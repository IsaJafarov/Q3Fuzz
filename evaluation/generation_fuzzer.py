import json
import networkx as nx
import sys
import ssl
import argparse
from collections import OrderedDict
from typing import List
from aioquic.quic.connection import *
from pyshark.packet.packet import Packet
from urllib.parse import urlparse

import util
from http_client import HttpClient
from aioquic.h3.connection import H3_ALPN
from dissector import *
from aioquic.quic.packet import QuicPreferredAddress
from util import QUIC_FRAME_ABBREVIATIONS, H3_FRAME_ABBREVIATIONS
from datetime import datetime
import time
import concurrent.futures
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn, SpinnerColumn
from rich.console import Console
from rich.table import Table
import warnings
import paramiko
from enum import Enum
from hypothesis import given, reproduce_failure, settings, Verbosity, Phase, strategies as st, HealthCheck
from hypothesis.database import DirectoryBasedExampleDatabase
import random
from rich.traceback import install
import functools


PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]

# largest values in varint encoding. https://www.rfc-editor.org/rfc/rfc9000.html#section-16
LARGEST_VARINT_LEN1 = 0x3F # length = 1. hex value is 2^4-1=63
LARGEST_VARINT_LEN2 = 0x3FFF # length = 2. hex value is 2^14-1=16383
LARGEST_VARINT_LEN4 = 0x3FFFFFFF # length = 4. hex value is 2^30-1=1073741823
LARGEST_VARINT_LEN8 = 0x3FFFFFFFFFFFFFFF # length = 8. hex value is 2^62-1=4611686018427387903
# Higher values throw "Integer is too big for a variable-length integer"
SAMPLE_VALUES_FOR_VARINT_VALUES = [0, 2**10, 2**18, 2**25, 2**40, 2**50, 997, 10**5, 10**10, LARGEST_VARINT_LEN1, LARGEST_VARINT_LEN2, LARGEST_VARINT_LEN4, LARGEST_VARINT_LEN8 ]
UNNCESESSARY_NODES = ['START', 'HANDSHAKING']
FIRST_STATE = "CONNECTED"
LAST_STATE = "FINISH"


class Fuzzer():
    def __init__(self, quic_conf:QuicConfiguration, hostname:str, keylog_file:str, mutations:int, 
                 parallel_requests:int, interval:int, duration:int, generation:int, verbose:bool, 
                 restart_server:bool, ssh_user:str, ssh_key_path:str, server_name:str, server_version:str, num_of_replays:int):
        self.quic_conf:QuicConfiguration = quic_conf
        self.hostname:str = hostname
        self.keylog_file:str = keylog_file
        self.graph:nx.DiGraph = nx.DiGraph()
        self.traffic_messages:list[Packet] = []
        self.mutations:int = mutations
        self.parallel_requests:int = parallel_requests
        self.interval:int = interval
        self.duration:int = duration
        self.generation:int = generation
        self.verbose = verbose
        self.restart_server = restart_server
        self.ssh_user = ssh_user
        self.ssh_key_path = ssh_key_path
        self.server_name = server_name
        self.server_version = server_version
        self.num_of_replays = num_of_replays
    
    def set_up_graph(self, sm_file_path:str, traffic_file_path:str):
        with open(sm_file_path, 'r') as f:
            data = json.load(f)

        for t in data['transitions']:
            
            source = t['source']
            destination = t['dest']
            
            if source in UNNCESESSARY_NODES: 
                continue

            trigger = t['trigger'].strip()
            packet_number = t['conditions'][0].split(":")[1] if 'conditions' in t else None
            self.graph.add_edge(source, destination, trigger=trigger, packet_number=packet_number)

        self.traffic_messages = util.h3msg_from_pcap(traffic_file_path, self.keylog_file, True)

    def print_info(self, transitions:List[Tuple]):
        table = Table(title="Fuzzing Configuration")
        table.add_column("Parameter")
        table.add_column("Value")

        table.add_row("Parallel Requests", "{}".format(self.parallel_requests))
        table.add_row("Interval", "{} sec.".format(self.interval) )
        table.add_row("Attack Duration for each mutation", "{} sec.".format(self.duration) )
        table.add_row("Number of generations for each transition", "{}".format(self.generation) )
        table.add_row("Number of mutations for each generated packet", "{}".format(self.mutations) )
        table.add_row("Fuzzing transitions", "Transport parameters, {}".format(", ".join(f"{i}->{j}" for i, j in transitions)))
        
        console = Console()
        console.print(table)


    def fuzz(self):
        """
        Extract all the transitions from the graph to fuzz
        """

        def get_triggering_msg_of_transition(source_node:str, target_node:str) -> QuicPacket:
            edge_to_fuzz = self.graph.get_edge_data(source_node, target_node)
            
            if edge_to_fuzz['packet_number'] is None: 
                return None
            triggering_msg_packet_num = int(edge_to_fuzz['packet_number'])
            packet = self._find_message_by_packet_number(triggering_msg_packet_num)
            return MSGDissector().dissect_msg( packet )

        # 1. Extract the transitions from the State Machine
        fuzzing_transitions = list(tuple())
        
        for node in self.graph.nodes():

            if node == FIRST_STATE:
                continue
            
            for predecessor in self.graph.predecessors(node):
                if get_triggering_msg_of_transition(predecessor, node): # the transition has a packet
                    fuzzing_transitions.append( (predecessor, node) )
        

        self.print_info(fuzzing_transitions)


        # 2. Fuzz individual messages
        for source_node, target_node in fuzzing_transitions:

            print("\n\nTransition: {} -> {}\n".format(source_node, target_node))

            moving_msgs_path = nx.shortest_path(self.graph, FIRST_STATE, source_node)
            moving_msgs = list()
            for i in range(len(moving_msgs_path)-1):
                moving_msgs.append( get_triggering_msg_of_transition(moving_msgs_path[i], moving_msgs_path[i+1]) )

            try:
                self.fuzz_msg_with_strategy(moving_msgs)
            except KeyboardInterrupt:
                pass # when interrupted, move to the next frame            


    def fuzz_msg_with_strategy(self, moving_msgs:List[QuicPacket] = []) -> None:
        """
        Apply the mutation strategy to the selected frame
        """
        
        # build a progress bar
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            SpinnerColumn()) as progress:

            bar1 = progress.add_task("Generation ", total=self.generation, visible=not self.verbose)

            for gen in range( self.generation ):

                available_quic_frame_types = [
                    QuicPadding, QuicPing, QuicAck, QuicResetStream, QuicStopSending, 
                    QuicCrypto, QuicNewTokenFrame, QuicStream, QuicMaxData, QuicMaxStreamData, 
                    QuicMaxStreams, QuicDataBlocked, QuicStreamDataBlocked, QuicStreamsBlocked, QuicNewConnectionId, 
                    QuicRetireConnectionId, QuicPathChallenge, QuicPathResponse, QuicConnectionClose, QuicHandshakeDone
                    ]
                
                # Give a higher priority to QuicStream, because it is more complex.
                weights = [
                    1,1,1,1,1,
                    1,1,10,1,1, 
                    1,1,1,1,1,
                    1,1,1,1,1
                ]


                if self.server_name == "neqo":
                    # Sending many PATH_CHALLENGE frames puts a lot of stress on the server and
                    # interestingly when the attack stops, it crashes the server.
                    # In order not to discover the same vulnerability, replace each QuicPathChallenge frame with something else.
                    weights[16] = 0 # QuicPathChallenge
                    # Do not rediscover existing vulnerability: https://github.com/mozilla/neqo/security/advisories/GHSA-56c6-rfrf-rh4r
                    weights[6] = 0 # QuicNewTokenFrame


                random_quic_frame_types = random.choices(available_quic_frame_types, weights=weights, k=5)

                if self.server_name == "h2o":
                    # Sending a STREAM or STOP_SENDING frame after CONNECTION_CLOSE crashes Quicly
                    # Prevent rediscovering the same vulnerability.
                    # If there is STREAM or STOP_SENDING frame in the list, replace the preceeding CONNECTION_CLOSE frames with something else
                    for i in range(4, -1, -1):
                        if random_quic_frame_types[i] in [QuicStream, QuicStopSending]:
                            for j in range(0, i):
                                if random_quic_frame_types[j] is QuicConnectionClose:
                                    random_quic_frame_types[j] = random.choice([x for x in available_quic_frame_types if x is not QuicConnectionClose])

                if self.server_name == "neqo":
                    # Sending a PATH_RESPONSE + STREAM frames crashes the Neqo server with 'Unreachable Code' error.
                    for i in range(4, 1, -1):
                        if random_quic_frame_types[i] is QuicStream:
                            for j in range(0, i):
                                if random_quic_frame_types[j] is QuicPathResponse:
                                    random_quic_frame_types[j] = random.choice([x for x in available_quic_frame_types if x is not QuicPathResponse])

                if self.server_name == "neqo":
                    # https://github.com/mozilla/neqo/security/advisories/GHSA-jfv6-x22w-grhf
                    for i in range(4, 1, -1):
                        if random_quic_frame_types[i] is QuicDataBlocked:
                            for j in range(0, i):
                                if random_quic_frame_types[j] is QuicResetStream:
                                    random_quic_frame_types[j] = random.choice([x for x in available_quic_frame_types if x is not QuicResetStream])

                
                if self.server_name == "neqo":
                    if moving_msgs and QuicStream in moving_msgs[-1]:
                        for i in range(5):
                            if random_quic_frame_types[i] is QuicDataBlocked:
                                # https://github.com/mozilla/neqo/security/advisories/GHSA-jfv6-x22w-grhf
                                random_quic_frame_types[i] = random.choice([x for x in available_quic_frame_types if x is not QuicDataBlocked])
                            if random_quic_frame_types[i] is QuicConnectionClose:
                                # https://github.com/IsaJafarov/Neqo-TransportInvalidStreamId-Crash-Exploit
                                random_quic_frame_types[i] = random.choice([x for x in available_quic_frame_types if x is not QuicConnectionClose])


                # build strategy for each frame
                strategies = []
                for quic_frame_type in random_quic_frame_types:
                    if quic_frame_type is QuicPadding:
                        strategies.append(self._build_padding_strategy())
                    elif quic_frame_type is QuicPing:
                        strategies.append(self._build_ping_strategy())
                    elif quic_frame_type is QuicAck:
                        strategies.append(self._build_ack_strategy())
                    elif quic_frame_type is QuicResetStream:
                        strategies.append(self._build_reset_stream_strategy())
                    elif quic_frame_type is QuicStopSending:
                        strategies.append(self._build_stop_sending_strategy())
                    elif quic_frame_type is QuicCrypto:
                        strategies.append(self._build_crypto_strategy())
                    elif quic_frame_type is QuicNewTokenFrame:
                        strategies.append(self._build_new_token_frame_strategy())
                    elif quic_frame_type is QuicStream:
                        strategies.append(self._build_stream_strategy())
                    elif quic_frame_type is QuicMaxData:
                        strategies.append(self._build_max_data_frame_strategy())
                    elif quic_frame_type is QuicMaxStreamData:
                        strategies.append(self._build_max_stream_data_frame_strategy())
                    elif quic_frame_type is QuicMaxStreams:
                        strategies.append(self._build_max_streams_frame_strategy())
                    elif quic_frame_type is QuicDataBlocked:
                        strategies.append(self._build_data_blocked_frame_strategy())
                    elif quic_frame_type is QuicStreamDataBlocked:
                        strategies.append(self._build_stream_data_blocked_frame_strategy())
                    elif quic_frame_type is QuicStreamsBlocked:
                        strategies.append(self._build_streams_blocked_frame_strategy())
                    elif quic_frame_type is QuicNewConnectionId:
                        strategies.append(self._build_new_connection_id_strategy())
                    elif quic_frame_type is QuicRetireConnectionId:
                        strategies.append(self._build_retire_connection_id_frame_strategy())
                    elif quic_frame_type is QuicPathChallenge:
                        strategies.append(self._build_path_challenge_frame_strategy())
                    elif quic_frame_type is QuicPathResponse:
                        strategies.append(self._build_path_response_frame_strategy())
                    elif quic_frame_type is QuicConnectionClose:
                        strategies.append(self._build_connection_close_frame_strategy())
                    elif quic_frame_type is QuicHandshakeDone:
                        strategies.append(self._build_handshake_done_frame_strategy())
                
                strategy = st.tuples(*strategies).map(list)
                
                
                if self.verbose:                    
                    print("\n\tGeneration #{}: {}".format( gen+1, list(map(lambda x: x.__name__, random_quic_frame_types)) ))
                self.outside( strategy, moving_msgs, progress)
                progress.update(bar1, advance=1)
                

                
    def outside(self, strategy:st.SearchStrategy, moving_msgs:List[QuicPacket], progress:Progress):

        
        def verify_hypothesis_failures():
            def decorator(test_func):
                @functools.wraps(test_func)
                def wrapper(*args, **kwargs):
                    try:
                        test_func(*args, **kwargs)
                    except Exception as original_error:
                        print(">>> Failed. Let's replay {} times.".format(self.num_of_replays) )
                        # Test failed - verify it's consistent
                        failures = 0
                        for _ in range(self.num_of_replays):
                            try:
                                time.sleep(5)    
                                self._restart_remote_server()
                                time.sleep(5)
                                test_func(*args, **kwargs)
                                print(">>> Passed this time :(")
                                return
                            except Exception:
                                print(">>> Failed again:)" )
                                failures += 1
                        # Only raise if it fails consistently
                        if failures == self.num_of_replays:
                            print(">>> Failed in all attempts!".format() )
                            raise original_error
                return wrapper
            return decorator

        num_of_mutation=1

        @given( strategy )
        @settings(deadline=None, verbosity=Verbosity.normal, print_blob=True, 
                  # Exclude the Shrinking phase. We want to see the first example that caused the error.
                  phases=[Phase.explicit , Phase.reuse, Phase.generate, Phase.target], 
                  max_examples=self.mutations,
                  database=DirectoryBasedExampleDatabase("/home/ubuntu/hypothesis-db"),
                  suppress_health_check=list(HealthCheck))
        @verify_hypothesis_failures()
        def fuzz_msg_with_strategy_inner(moving_msgs:List[QuicPacket], fuzzed_entity:QuicPacket):
            
            if self.verbose:
                nonlocal num_of_mutation
                print("\n\t\tMutation #{}: {}".format(num_of_mutation, fuzzed_entity))
                num_of_mutation += 1
            
            with concurrent.futures.ThreadPoolExecutor() as executor:

                if self.verbose:
                    print("\n\t\tSend {} requests in parallel for {} sec. with {} sec. interval"
                            .format( self.parallel_requests, self.duration, self.interval ))
                
                for _ in range(int(self.duration/self.interval)):

                    for __ in range(self.parallel_requests):

                        # Submit each iteration as a separate task
                        executor.submit(self.execute_attack, 
                                                    fuzzed_entity,
                                                    moving_msgs=moving_msgs)
                    time.sleep(self.interval)

            # check if we can establish a connection with the server.
            # if we can't, then the server is down
            self.check_server_liveness()

            self._restart_remote_server()
            
            progress.update(bar2, advance=1)
            

            if self.verbose:
                print("\n\n")


        bar2 = progress.add_task("Mutation ", total=self.mutations, visible=not self.verbose, transient=True)
        fuzz_msg_with_strategy_inner(moving_msgs)
        progress.remove_task(bar2)
            

    def check_server_liveness(self) -> None:
        """
        Check if the web server is available by initiating a connection with a new client.
        The server is up, if it responds with the HANDSHAKE_DONE frame
        """

        h3client = HttpClient(self.quic_conf, self.hostname)

        h3client.connect()
        res1 = h3client.read_from_buffer()  # Receive any response from the server

        # Complete the connection by sending handshake completion messages
        h3client.complete_connection()
        res2 = h3client.read_from_buffer()

        # print("res2 = {}".format(res2))

        if QUIC_FRAME_ABBREVIATIONS['HANDSHAKE_DONE'] not in res2:
            raise Exception("Server did not complete handshake")
        
        if self.verbose:
            print("\t\tServer is UP")


    def execute_attack(self, fuzzed_entity:QuicPacket, 
                       moving_msgs:List[QuicPacket]=[]) -> None:
        
        # Ignore errors during the attack.
        # Once the attack completes, we will check the server liveness. At that point, we will care about the connection errors.
        try: 
            h3client = HttpClient(self.quic_conf, self.hostname)

            # Connection Initialization
            h3client.connect()
            connect_response = h3client.read_from_buffer()  # Receive any response from the server
            if self.verbose:
                print("\t\tConnection: {}. Connection Response: {}".format(h3client.connection._host_cids[0].cid.hex(), connect_response) )
            if connect_response == "\u2298":
                return

            # Complete the connection by sending handshake completion messages
            h3client.complete_connection()
            completion_response = h3client.read_from_buffer()
            if self.verbose:
                print("\t\tConnection: {}. Handshake Response: {}".format(h3client.connection._host_cids[0].cid.hex(), completion_response) )
            if completion_response == "\u2298":
                return

            # Send Moving Messages
            for moving_msg in moving_msgs:
                moving_msg_response = h3client.send_frames(moving_msg)
                if moving_msg_response == "\u2298":
                    return

            # Send Test Input
            test_input_response = h3client.send_frames( fuzzed_entity, wait_for_respose=False )
            if self.verbose:
                print("\t\tConnection: {}. Fuzzed Transition Response: {}".format(h3client.connection._host_cids[0].cid.hex(), test_input_response))

        except Exception as e:
            if self.verbose:
                print(e)
        finally:
            h3client.close_local_socket()


    def _find_message_by_packet_number(self, packet_number:int) -> Packet:
        for msg in self.traffic_messages:
            
            # The same packet number can used in a short and long header quic frames. We only care about short header QUIC frames.
            if int(msg.quic.packet_number) == packet_number and int(msg.quic.header_form)==0:
                return msg
        raise Exception("Packet with packet_number {} does not exist!".format(packet_number)) 
        





    # Build QUIC frame strategies
    def _build_padding_strategy(self) -> st.SearchStrategy:
        """
        QuicPadding:
            pass
        """

        return st.builds(QuicPadding)

    def _build_ping_strategy(self) -> st.SearchStrategy:
        """
        QuicPing:
            pass
        """

        return st.builds(QuicPing)

    def _build_ack_strategy(self) -> st.SearchStrategy:
        """
        QuicAck:
            largest_acknowledged:int
            ack_delay:int
            ack_range_count:int
            ack_first_ack_range:int
            ack_ranges:List[Tuple[int,int]]
        """

        ack_largest_acknowledged_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        ack_delay_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**14+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        ack_range_count_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**8+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        ack_first_ack_range_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # tuple of variable-length integers
        ack_ranges_field_strategy = st.one_of(
            st.lists( 
                st.tuples( 
                    st.integers(min_value=0,max_value=255), 
                    st.integers(min_value=0,max_value=LARGEST_VARINT_LEN8) ) ),

            st.sampled_from( [ [(0, 5)], [(16, 5)], [(997, 5)], [(LARGEST_VARINT_LEN8, 5)], [(None, 5)], [(LARGEST_VARINT_LEN2, 5)],
                               [(5, 0)], [(5, 16)], [(5, 997)], [(5, LARGEST_VARINT_LEN8)], [(5, None)], [(5, LARGEST_VARINT_LEN2)] ] ),
        )

        
        return st.builds(QuicAck, 
                          ack_largest_acknowledged_field_strategy,
                          ack_delay_field_strategy,
                          ack_range_count_field_strategy,
                          ack_first_ack_range_field_strategy,
                          ack_ranges_field_strategy )
        
    def _build_reset_stream_strategy(self) -> st.SearchStrategy:
        """
        QuicResetStream:
            stream_id:int
            app_protocol_error_code:int
            final_size:int
        """

        stream_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        app_protocol_error_code_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # 8-bit unsigned integer
        final_size = st.one_of(
            st.integers(min_value=0, max_value=2**8+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        if self.server_name == "h2o":
            final_size = st.one_of(
                st.integers(min_value=0, max_value=0x3FFFFFFFFF000000-1), 
                st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
            )


        return st.builds(QuicResetStream, 
                          stream_id_field_strategy,
                          app_protocol_error_code_field_strategy,
                          final_size )

    def _build_stop_sending_strategy(self) -> st.SearchStrategy:
        """
        QuicStopSending:
            stream_id:int
            app_protocol_error_code:int
        """

        stream_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        app_protocol_error_code_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )


        return st.builds(QuicStopSending, 
                          stream_id_field_strategy,
                          app_protocol_error_code_field_strategy )

    def _build_crypto_strategy(self) -> st.SearchStrategy:
        """
        QuicCrypto:
            offset:int
            data:bytes
        """

        offset_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        data_field_strategy = st.binary()


        return st.builds(QuicCrypto, 
                          offset_field_strategy,
                          data_field_strategy )

    def _build_new_token_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicNewTokenFrame:
            token:bytes
        """

        token_field_strategy = st.binary()


        return st.builds(QuicNewTokenFrame, 
                        token_field_strategy )

    def _build_stream_strategy(self) -> st.SearchStrategy:
        """
        QuicStream:
            stream_id:int
            fin_bit:bool
            offset:int
            h3_frame:H3Frame
        """
        
        stream_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        fin_bit_field_strategy = st.booleans()

        # TODO: temp
        if self.server_name == "msquic-kestrel":
            # When you fuzz msquic, set fin_bit to False in order not to discover the same vulnerability over and over 
            fin_bit_field_strategy = st.just(False)

        offset_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        # choose HTTP/3 frame type randomly
        available_h3_frames_types = [H3Data, H3Headers, H3CancelPush, H3Settings, H3PushPromise, H3GoAway, H3MaxPushId, H3PriorityUpdate, QpackEncoder, QpackDecoder]
        random_h3_type = random.choice(available_h3_frames_types)
        
        h3_frame_strategy = st.none()
        if random_h3_type is H3Data:
            h3_frame_strategy = self._build_h3_data_strategy()
        elif random_h3_type is H3Headers:
            h3_frame_strategy = self._build_h3_headers_strategy()
        elif random_h3_type is H3CancelPush:
            h3_frame_strategy = self._build_h3_cancel_push_strategy()
        elif random_h3_type is H3Settings:
            h3_frame_strategy = self._build_h3_settings_strategy()
        elif random_h3_type is H3PushPromise:
            h3_frame_strategy = self._build_h3_push_promise_strategy()
        elif random_h3_type is H3GoAway:
            h3_frame_strategy = self._build_h3_goaway_strategy()
        elif random_h3_type is H3MaxPushId:
            h3_frame_strategy = self._build_h3_max_push_id_strategy()
        elif random_h3_type is H3PriorityUpdate:
            h3_frame_strategy = self._build_h3_priority_update_strategy()
        elif random_h3_type is QpackEncoder:
            h3_frame_strategy = self._build_h3_qpack_encoder_strategy()
        elif random_h3_type is QpackDecoder:
            h3_frame_strategy = self._build_h3_qpack_decoder_strategy()
        
        return st.builds(QuicStream, 
                          stream_id_field_strategy,
                          fin_bit_field_strategy,
                          offset_field_strategy,
                          h3_frame_strategy)
        
    def _build_max_data_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicMaxData:
            max_data:int
        """

        max_data_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        return st.builds(QuicMaxData, 
                        max_data_field_strategy )

    def _build_max_stream_data_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicMaxStreamData:
            stream_id:int
            max_stream_data:int
        """

        stream_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        max_stream_data_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        return st.builds(QuicMaxStreamData, 
                        stream_id_field_strategy,
                        max_stream_data_field_strategy )

    def _build_max_streams_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicMaxStreams:
            maximum_streams:int
        """

        maximum_streams_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        return st.builds(QuicMaxStreams, 
                        maximum_streams_field_strategy )
    
    def _build_data_blocked_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicDataBlocked:
            max_data:int
        """

        max_data_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        return st.builds(QuicDataBlocked, 
                        max_data_field_strategy )
    
    def _build_stream_data_blocked_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicStreamDataBlocked:
            stream_id:int
            max_stream_data:int
        """

        stream_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        max_stream_data_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        return st.builds(QuicStreamDataBlocked, 
                        stream_id_field_strategy,
                        max_stream_data_field_strategy )

    def _build_streams_blocked_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicStreamsBlocked:
            bidirectional:bool
            max_streams:int
        """

        bidirectional_field_strategy = st.booleans()

        max_streams_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        
        return st.builds(QuicStreamsBlocked, 
                        bidirectional_field_strategy,
                        max_streams_field_strategy )

    def _build_new_connection_id_strategy(self) -> st.SearchStrategy:
        """
        QuicNewConnectionId:
            sequence_number:int
            retire_prior_to:int
            connection_id:bytes
            stateless_reset_token:bytes
        """

        sequence_number_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        retire_prior_to_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # connection ID of the specified length
        connection_id_field_strategy = st.binary(min_size=0, max_size=2**8+1)

        # It is supposed to be 16 bytes. Try both normal size to avoid crafting a malformed frame and also random length to test edge cases
        stateless_reset_token_strategy = st.one_of(
            st.binary(min_size=16, max_size=16),
            st.binary()
        )
        
        
        return st.builds(QuicNewConnectionId, 
                          sequence_number_field_strategy,
                          retire_prior_to_field_strategy,
                          connection_id_field_strategy,
                          stateless_reset_token_strategy )

    def _build_retire_connection_id_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicRetireConnectionId:
            sequence_number:int
        """

        sequence_number_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # TODO: temp
        if self.server_name == "quiche":
            sequence_number_field_strategy = st.one_of(
            st.integers(min_value=1, max_value=LARGEST_VARINT_LEN8), # sequence_number=0 causes vulnerability in Quiche
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES[1:])
        )
        
        return st.builds(QuicRetireConnectionId, 
                        sequence_number_field_strategy )

    def _build_path_challenge_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicPathChallenge: 
            data:bytes
        """

        # It is supposed to be 8 bytes. Try both normal size to avoid crafting a malformed frame and also random length to test edge cases
        data_field_strategy = st.one_of(
            st.binary(min_size=8, max_size=8),
            st.binary()
        )
        
        
        return st.builds(QuicPathChallenge, 
                        data_field_strategy )
    
    def _build_path_response_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicPathResponse:
            data:bytes
        """

        # It is supposed to be 8 bytes. Try both normal size to avoid crafting a malformed frame and also random length to test edge cases
        data_field_strategy = st.one_of(
            st.binary(min_size=8, max_size=8),
            st.binary()
        )

        
        return st.builds(QuicPathResponse, 
                        data_field_strategy )
    
    def _build_connection_close_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicConnectionClose:
            transport_layer:bool
            error_code:int
            frame_type:int
            reason_phrase:bytes
        """

        transport_layer_field_strategy = st.booleans()


        error_code_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        frame_type_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        reason_phrase_field_strategy = st.binary()

        
        return st.builds(QuicConnectionClose, 
                        transport_layer_field_strategy,
                        error_code_field_strategy,
                        frame_type_field_strategy,
                        reason_phrase_field_strategy )

    def _build_handshake_done_frame_strategy(self) -> st.SearchStrategy:
        """
        QuicHandshakeDone:
            pass
        """

        return st.builds(QuicHandshakeDone)
    

    # Build HTTP/3 frame strategies
    def _build_h3_data_strategy(self) -> st.SearchStrategy:
        """
        H3Data:
            payload:bytes
        """

        payload_field_strategy = st.binary()


        return st.builds(H3Data, 
                        payload_field_strategy )

    def _build_h3_headers_strategy(self) -> st.SearchStrategy:
        """
        H3Headers:
            payload:bytes
        """

        payload_field_strategy = st.binary()


        return st.builds(H3Headers, 
                        payload_field_strategy )
    
    def _build_h3_cancel_push_strategy(self) -> st.SearchStrategy:
        """
        H3CancelPush:
            push_id:int
        """

        push_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )


        return st.builds(H3CancelPush, 
                        push_id_field_strategy )

    def _build_h3_settings_strategy(self) -> st.SearchStrategy:
        """
        H3Settings:
            max_table_capacity:int
            max_field_section_size:int
            blocked_streams:int
            h3_datagram:int
            webtransport:int
        """

        max_table_capacity_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**32+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        max_field_section_size_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**32+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        blocked_streams_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**32+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        h3_datagram_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**15+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        webtransport_strategy = st.one_of(
            st.integers(0, 100),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        return st.builds(H3Settings, 
                          max_table_capacity_field_strategy,
                          max_field_section_size_field_strategy,
                          blocked_streams_field_strategy,
                          h3_datagram_field_strategy,
                          webtransport_strategy )

    def _build_h3_push_promise_strategy(self) -> st.SearchStrategy:
        """
        H3PushPromise:
            push_id:int
            field_section:bytes
        """

        push_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        field_section_field_strategy = st.binary()

        return st.builds(H3PushPromise, 
                        push_id_field_strategy,
                        field_section_field_strategy )

    def _build_h3_goaway_strategy(self) -> st.SearchStrategy:
        """
        H3GoAway:
            stream_id:int
        """

        element_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        return st.builds(H3GoAway, 
                        element_id_field_strategy)
    
    def _build_h3_max_push_id_strategy(self) -> st.SearchStrategy:
        """
        H3MaxPushId:
            push_id:int
        """

        push_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        return st.builds(H3MaxPushId, 
                        push_id_field_strategy)

    def _build_h3_priority_update_strategy(self) -> st.SearchStrategy:
        """
        H3PriorityUpdate:
            element_id:int
            field_value:str
        """

        element_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=10),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        # ASCII string
        field_value_field_strategy = st.one_of(
            st.text(min_size=0, max_size=10), 
            st.sampled_from(["", "000000", "a"*20, "a"*200, "\u2298" ])
        )

        return st.builds(H3PriorityUpdate, 
                          element_id_field_strategy,
                          field_value_field_strategy )
    
    def _build_h3_qpack_encoder_strategy(self) -> st.SearchStrategy:
        """
        QpackEncoder:
            payload:bytes
        """

        payload_field_strategy = st.binary()

        return st.builds(QpackEncoder, 
                        payload_field_strategy )
    
    def _build_h3_qpack_decoder_strategy(self) -> st.SearchStrategy:
        """
        QpackDecoder:
            payload:bytes
        """

        payload_field_strategy = st.binary()

        return st.builds(QpackDecoder, 
                        payload_field_strategy )
    

    def _restart_remote_server(self):

        if not self.restart_server:
            return
        
        if self.verbose:
            print("\n\t\tRestarting the server...")

        def run_remote_tmux_command(ssh, command):
            stdin, stdout, stderr = ssh.exec_command(command)
            channel = stdout.channel

            while not channel.exit_status_ready():
                # the command has not finished, yet
                time.sleep(0.1)

            return stdout.read().decode(), stderr.read().decode()
        
        # Setup SSH connection
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        key = paramiko.Ed25519Key.from_private_key_file(self.ssh_key_path)
        client.connect(self.hostname, 22, self.ssh_user, pkey=key)
        
        # Kill running process
        cmd ="sudo pkill -9 -f autorun.py"
        run_remote_tmux_command(client, cmd)

        if self.server_name == "xquic":
            # Delete Xquic's log files
            cmd ="sudo rm /home/ubuntu/PRETT3/servers_setup/xquic/slog.log /home/ubuntu/PRETT3/servers_setup/xquic/skeys.log"
            run_remote_tmux_command(client, cmd)

        # Run the new process
        cmd = "tmux send-keys -t server 'sudo python3 autorun.py {} {}' Enter".format(self.server_name, self.server_version)
        run_remote_tmux_command(client, cmd)
        time.sleep(3)

        client.close()


if __name__ == "__main__":
    # install()

    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(description="HTTP/3 client")
    parser.add_argument(
        "url", type=str, help="the URL to query (must be HTTPS)"
    )
    parser.add_argument(
        "pcap", type=str, help="PATH to the QUIC/HTTP3 traffic (must be Wireshark-readable pcap)"
    )
    parser.add_argument(
        "state_machine", type=str, help="Path to the state machine json file"
    )
    parser.add_argument(
        "-dk",
        "--decrypt_keylog",
        default="./sample_traffics/secrets.keylog",
        type=str,
        help="SSLKEYLOG file to decrypt the traffic files (default ./sample_traffics/secrets.keylog)",
    )
    parser.add_argument(
        "-ok",
        "--output_keylog",
        type=str,
        help="File path to log new traffic secrets",
    )
    parser.add_argument(
        "-g",
        "--generation",
        type=int,
        default=10,
        help="The number of generations for each transition (default 10)"
    )
    parser.add_argument(
        "-m",
        "--mutations",
        type=int,
        default=100,
        help="The number of mutations to apply on generated packets (default 100)"
    )
    parser.add_argument(
        "-p",
        "--parallel_requests",
        type=int,
        default=20,
        help="The number of requests to send in parallel (default 20)"
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=1,
        help="Time to wait before sending the next parallel requests (in sec.) (default 1)"
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=60,
        help="The length of attack (in sec.) (default 60)"
    )
    parser.add_argument(
        "-rs", "--restart_server", action="store_true", help="After fuzzing for each mutation, connect to the target server and restart the QUIC server"
    )
    parser.add_argument(
        "-su",
        "--ssh_user",
        type=str,
        default="ubuntu",
        help="The SSH user on the server side to connect to (default: ubuntu)"
    )
    parser.add_argument(
        "-skp",
        "--ssh_key_path",
        type=str,
        default="/home/ubuntu/.ssh/id_ed25519",
        help="The SSH private key path to use to connect to the target server (default: /home/ubuntu/.ssh/id_ed25519)"
    )
    parser.add_argument(
        "-sn",
        "--server_name",
        type=str,
        default=None,
        help="Server name to use as input parameter while running autorun.py to restart QUIC server"
    )
    parser.add_argument(
        "-sv",
        "--server_version",
        type=str,
        default=None,
        help="Server name to use as input parameter while running autorun.py to restart QUIC server"
    )
    parser.add_argument(
        "-r",
        "--replay",
        type=int,
        default=2,
        help="Number of additional replays to confirm a finding (default 2)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    


    args = parser.parse_args()

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        original_version=1,
        verify_mode=ssl.CERT_NONE
    )

    if args.output_keylog:
        output_keylog_file = os.path.abspath(args.output_keylog) 
        configuration.secrets_log_file = open(output_keylog_file, "a")

    decrypt_keylog_file = os.path.abspath(args.decrypt_keylog)
    if not os.path.exists(decrypt_keylog_file):
        raise Exception("{} does not exist".format(decrypt_keylog_file))

    fuzzer = Fuzzer(
        configuration, 
        urlparse(args.url).netloc, 
        decrypt_keylog_file,
        mutations=args.mutations,
        parallel_requests=args.parallel_requests,
        interval=args.interval,
        duration=args.duration,
        generation=args.generation,
        verbose = args.verbose,
        restart_server=args.restart_server,
        ssh_user=args.ssh_user,
        ssh_key_path=args.ssh_key_path,
        server_name=args.server_name,
        server_version=args.server_version,
        num_of_replays=args.replay)
    
    fuzzer.set_up_graph(args.state_machine, args.pcap)

    print("Starting the fuzzer at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
    fuzzer.fuzz()
