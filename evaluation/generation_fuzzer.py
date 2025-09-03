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
from hypothesis import given, reproduce_failure, settings, Verbosity, Phase, strategies as st
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


"""
@dataclass
class QuicAck:
    largest_acknowledged:int=None
    ack_delay:int=None
    ack_range_count:int=None
    ack_first_ack_range:int=None
    ack_ranges:List[Tuple[int,int]] = field(default_factory=list) # [gap, ack_range]

@dataclass
class QuicNewConnectionId:
    sequence_number:int = None
    retire_prior_to:int = None
    length:int = None
    connection_id:bytes = None
    stateless_reset_token:bytes = None

@dataclass
class H3Settings:
    max_table_capacity:int = None
    max_field_section_size:int = None
    blocked_streams:int = None
    h3_datagram:int = None
    webtransport:int = None
    
@dataclass
class H3Headers:
    payload:bytes = None

@dataclass
class H3Data:
    payload:bytes = None
    
@dataclass
class H3PriorityUpdate:
    element_id:int = None
    field_value:str = None

@dataclass
class QpackEncoder:
    payload:bytes = None

@dataclass
class QpackDecoder:
    payload:bytes = None

@dataclass
class QuicStream:
    stream_id:int = None
    fin_bit:bool = None
    offset:int = None
    length:int = None
    h3_frame:Union[H3Settings, H3Headers, H3Data, H3PriorityUpdate, QpackEncoder, QpackDecoder] = None

@dataclass
class QuicMaxStreams(QuicH3Frame):
    maximum_streams:int = None

"""


class Fuzzer():
    def __init__(self, quic_conf:QuicConfiguration, hostname:str, keylog_file:str, mutations:int, 
                 parallel_requests:int, interval:int, duration:int, generation:int, verbose:bool, reproduce_failure:str, 
                 restart_server:bool, ssh_user:str, ssh_key_path:str, server_name:str, server_version:str):
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
        self.reproduce_failure = reproduce_failure
        self.restart_server = restart_server
        self.ssh_user = ssh_user
        self.ssh_key_path = ssh_key_path
        self.server_name = server_name
        self.server_version = server_version
    
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

        def get_triggering_msg_of_transition(source_node:str, target_node:str) -> QuicH3Packet:
            edge_to_fuzz = self.graph.get_edge_data(source_node, target_node)
            
            if edge_to_fuzz['packet_number'] is None: 
                return None
            triggering_msg_packet_num = int(edge_to_fuzz['packet_number'])
            packet = self.find_message_by_packet_number(triggering_msg_packet_num)
            return MSGDissector().dissect_msg( packet )

        # 1. Extract the transitions from the State Machine
        fuzzing_and_following_transitions = OrderedDict()
        # Keys: the list of transitions to fuzz in the form of (source_node, target_node) tuple. 
        # Values: the list of transitions that follow the target_node. We need this information, 
        # because after fuzzing the (source_node, target_node) transition, we will need to travel the following transition, too.
        for node in self.graph.nodes():

            if node == FIRST_STATE:
                continue

            successors = list()
            for successor in self.graph.successors(node):
                if get_triggering_msg_of_transition(node, successor): # the transition has a packet
                    successors.append( (node, successor) )
            
            # skip loop transitions
            for predecessor in self.graph.predecessors(node):
                if get_triggering_msg_of_transition(predecessor, node): # the transition has a packet
                    fuzzing_and_following_transitions[ (predecessor, node) ] = successors
        

        self.print_info(fuzzing_and_following_transitions.keys())


        # 3. Fuzz individual messages
        for source_node, target_node in fuzzing_and_following_transitions.keys():

            print("\n\nTransition: {} -> {}\n".format(source_node, target_node))

            moving_msgs_path = nx.shortest_path(self.graph, FIRST_STATE, source_node)
            moving_msgs = list()
            for i in range(len(moving_msgs_path)-1):
                moving_msgs.append( get_triggering_msg_of_transition(moving_msgs_path[i], moving_msgs_path[i+1]) )


            following_msgs = list()
            for target_node, following_node in fuzzing_and_following_transitions[ (source_node, target_node) ]:
                following_msgs.append( get_triggering_msg_of_transition(target_node, following_node))
            
            self.fuzz_msg_with_strategy(moving_msgs, following_msgs)

    def reach_source_state(self, h3client:HttpClient, moving_msgs:List[QuicH3Packet]) -> None:
        
        h3client.connect()
        connect_response = h3client.read_from_buffer()  # Receive any response from the server

        # Complete the connection by sending handshake completion messages
        h3client.complete_connection()
        handshake_response = h3client.read_from_buffer()        

        #print("\nMoving Messages:")
        for moving_msg in moving_msgs:
            response = h3client.send_frames(moving_msg)


    def fuzz_msg_with_strategy(self, 
                            moving_msgs:List[QuicH3Packet] = [],
                            following_msgs:List[QuicH3Packet] = []) -> None:
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

            for _ in range( self.generation ):

                available_quic_frame_types = [QuicAck, QuicNewConnectionId, QuicStream, QuicMaxStreams]
            
                num_of_quic_frames = random.randint(1, 5)
                random_quic_frame_types = random.choices(available_quic_frame_types, k=num_of_quic_frames)

                # build strategy for each frame
                strategies = []
                for quic_frame_type in random_quic_frame_types:
                    if quic_frame_type is QuicAck:
                        strategies.append(self.build_ack_strategy())
                    elif quic_frame_type is QuicNewConnectionId:
                        strategies.append(self.build_nci_strategy())
                    elif quic_frame_type is QuicStream:
                        strategies.append(self.build_stream_strategy())
                    elif quic_frame_type is QuicMaxStreams:
                        strategies.append(self.build_max_streams_strategy())
                
                strategy = st.tuples(*strategies).map(list)
                
                try:
                    if self.verbose:                    
                        print("\n\tGeneration: {}".format( list(map(lambda x: x.__name__, random_quic_frame_types)) ))
                    self.outside( strategy, moving_msgs, following_msgs, progress)
                    progress.update(bar1, advance=1)
                except KeyboardInterrupt:
                    pass # when interrupted, move to the next frame

                
    def outside(self, strategy, moving_msgs, following_msgs, progress:Progress):

        
        def verify_hypothesis_failures(retries=2):
            def decorator(test_func):
                @functools.wraps(test_func)
                def wrapper(*args, **kwargs):
                    try:
                        test_func(*args, **kwargs)
                    except Exception as original_error:
                        print(">>> Failed. Let's rerun twice." )
                        # Test failed - verify it's consistent
                        failures = 0
                        for _ in range(retries):
                            try:
                                time.sleep(10)
                                test_func(*args, **kwargs)
                                print(">>> Passed this time :(")
                                return
                            except Exception:
                                print(">>> Failed again!" )
                                failures += 1
                        # Only raise if it fails consistently
                        if failures == retries:
                            print(">>> Voila. Failed twice!".format() )
                            raise original_error
                return wrapper
            return decorator

        num=1

        reproduce_tag = None
        if self.reproduce_failure:
            hypothesis_version, test_string = self.reproduce_failure.split(",")
            reproduce_tag = reproduce_failure(hypothesis_version, test_string.encode())
        else:
            reproduce_tag = lambda f: f  # No-op decorator

        @given( strategy )
        @settings(deadline=None, verbosity=Verbosity.normal, print_blob=True, 
                  # Exclude the Shrinking phase. We want to see the first example that caused the error.
                  phases=[Phase.explicit , Phase.reuse, Phase.generate, Phase.target], 
                  max_examples=self.mutations,
                  database=DirectoryBasedExampleDatabase("/home/ubuntu/hypothesis-db"))
        @reproduce_tag
        @verify_hypothesis_failures()
        def fuzz_msg_with_strategy_inner(moving_msgs:List[QuicH3Packet], following_msgs:List[QuicH3Packet], fuzzed_entity):
            
            if self.verbose:
                nonlocal num
                print("\n\t\tMutation #{}: {}".format(num, fuzzed_entity))
                num += 1

            # if there is no following state, then still we need to fuzz this transition once
            for i in range(max(1, len(following_msgs))): 
                following_msg =  following_msgs[i] if i < len(following_msgs) else None
                
                with concurrent.futures.ThreadPoolExecutor() as executor:

                    if self.verbose:
                        print("\n\t\tSend {} requests in parallel for {} sec. with {} sec. interval with each of {} following messages"
                              .format( self.parallel_requests, self.duration, self.interval, len(following_msgs) ))
                    
                    for _ in range(int(self.duration/self.interval)):

                        for __ in range(self.parallel_requests):

                            # Submit each iteration as a separate task
                            executor.submit(self.execute_attack, 
                                                        fuzzed_entity,
                                                        moving_msgs=moving_msgs, 
                                                        following_msg=following_msg)
                        time.sleep(self.interval)

                # check if we can establish a connection with the server.
                # if we can't, then the server is down
                self.check_server_availability()

                if self.restart_server:
                    self.restart_remote_server()
            
            
            progress.update(bar2, advance=1)
            

            if self.verbose:
                print("\n\n")


        bar2 = progress.add_task("Mutation ", total=self.mutations, visible=not self.verbose, transient=True)
        fuzz_msg_with_strategy_inner(moving_msgs, following_msgs)
        progress.remove_task(bar2)
            

    def check_server_availability(self) -> None:
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

        if QUIC_FRAME_ABBREVIATIONS['HANDSHAKE_DONE'] not in res2:
            raise Exception("Server did not complete handshake")
        
        if self.verbose:
            print("\t\tServer is UP")


    def execute_attack(self, 
                       fuzzed_entity:Union[QuicH3Frame, QuicH3Packet], 
                       moving_msgs:List[QuicH3Packet]=[], 
                       preceding_quic_frames:List[QuicH3Frame]=[], 
                       succeeding_quic_frames:List[QuicH3Frame]=[],
                       following_msg:QuicH3Packet=[]) -> None:
        
        # Ignore errors during the attack.
        # Once the attack completes, we will check the server availability. At that point, we will care about the connection errors.
        try: 
            h3client = HttpClient(self.quic_conf, self.hostname)

            self.reach_source_state(h3client, moving_msgs)

            response = h3client.send_frames( fuzzed_entity if isinstance( fuzzed_entity, list ) else preceding_quic_frames + [fuzzed_entity] + succeeding_quic_frames )
            if self.verbose:
                print("\t\tConnection: {}. Fuzzed Transition Response: {}".format(h3client.connection._host_cids[0].cid.hex(), response))

            
            #h3client.replay_msg(following_msg) # TODO replay_msg() doesn't work. Don't make MSGDissector H3Client's object parameter
            response = h3client.send_frames( following_msg ) 
            if self.verbose:
                print("\t\tConnection: {}. Following Transition Response: {}".format(h3client.connection._host_cids[0].cid.hex(), response) )

        except Exception as e:
            if self.verbose:
                print(e)
        finally:
            h3client.close_local_socket()


    def find_message_by_packet_number(self, packet_number:int) -> Packet:
        for msg in self.traffic_messages:
            
            # The same packet number can used in a short and long header quic frames. We only care about short header QUIC frames.
            if int(msg.quic.packet_number) == packet_number and int(msg.quic.header_form)==0:
                return msg
        raise Exception("Packet with packet_number {} does not exist!".format(packet_number)) 
        

    def build_ack_strategy(self) -> st.SearchStrategy:
        """
        largest_acknowledged:int=None
        ack_delay:int=None
        ack_range_count:int=None
        ack_first_ack_range:int=None
        ack_ranges:List[Tuple[int,int]] = field(default_factory=list) # [gap, ack_range]
        """

        # variable-length integer
        ack_largest_acknowledged_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        ack_delay_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**14+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        ack_range_count_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**8+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
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
            st.sampled_from( [ (0, 5), (16, 5), (997, 5), (LARGEST_VARINT_LEN8, 5), (None, 5), (LARGEST_VARINT_LEN2, 5),
                               (5, 0), (5, 16), (5, 997), (5, LARGEST_VARINT_LEN8), (5, None), (5, LARGEST_VARINT_LEN2)] ),
        )

        
        return st.builds(QuicAck, 
                          ack_largest_acknowledged_field_strategy,
                          ack_delay_field_strategy,
                          ack_range_count_field_strategy,
                          ack_first_ack_range_field_strategy,
                          ack_ranges_field_strategy )
        
        
    def build_nci_strategy(self) -> st.SearchStrategy:
        """
        sequence_number:int = None
        retire_prior_to:int = None
        length:int = None
        connection_id:bytes = None
        stateless_reset_token:bytes = None
        """

        # variable-length integer
        sequence_number_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        retire_prior_to_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # 8-bit unsigned integer
        length_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**8+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # connection ID of the specified length
        connection_id_field_strategy = st.binary(min_size=0, max_size=2**8+1)

        # 128-bit (16 byte) value
        stateless_reset_token_strategy = st.binary(min_size=0, max_size=20)
        
        return st.builds(QuicNewConnectionId, 
                          sequence_number_field_strategy,
                          retire_prior_to_field_strategy,
                          length_field_strategy,
                          connection_id_field_strategy,
                          stateless_reset_token_strategy )

    def build_stream_strategy(self) -> st.SearchStrategy:
        """
        stream_id:int = None
        fin_bit:bool = None
        offset:int = None
        h3_frame:Union[H3Settings, H3Headers, H3Data, H3PriorityUpdate, QpackEncoder, QpackDecoder] = None
        """
        
        # variable-length integer
        stream_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**31+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        # variable-length integer
        fin_bit_field_strategy = st.booleans()

        # When you fuzz msquic, set fin_bit to False in order not to discover the same vulnerability over and over 
        # fin_bit_field_strategy = st.just(False)

        # variable-length integer
        offset_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        h3_frame_strategy = st.none()

        # choose H3 frame type randomly
        available_h3_frames_types = [H3Settings, H3Headers, H3Data, H3PriorityUpdate, QpackEncoder, QpackDecoder]
        random_h3_type = random.choice(available_h3_frames_types)
        
        if random_h3_type is H3Settings:
            h3_frame_strategy = self.build_h3_settings_strategy()
        elif random_h3_type is H3PriorityUpdate:
            h3_frame_strategy = self.build_h3_priority_update_strategy()
        # The strategies for the following HTTP/3 frames are quite simple
        elif random_h3_type is H3Headers:
            h3_frame_strategy = st.builds(H3Headers, payload=st.binary(min_size=0, max_size=1000))
        elif random_h3_type is H3Data:
            h3_frame_strategy = st.builds(H3Data, payload=st.binary(min_size=0, max_size=1000))
        elif random_h3_type is QpackEncoder:
            h3_frame_strategy = st.builds(QpackEncoder, payload=st.binary(min_size=0, max_size=1000))
        elif random_h3_type is QpackDecoder:
            h3_frame_strategy = st.builds(QpackDecoder, payload=st.binary(min_size=0, max_size=1000))
        
        return st.builds(QuicStream, 
                          stream_id_field_strategy,
                          fin_bit_field_strategy,
                          offset_field_strategy,
                          h3_frame_strategy)
        

    
    def build_max_streams_strategy(self) -> st.SearchStrategy:
        """
        maximum_streams:int = None
        """

        # variable-length integer
        max_streams_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        return st.builds(QuicMaxStreams, max_streams_field_strategy)


    def build_h3_settings_strategy(self) -> st.SearchStrategy:
        """
        max_table_capacity:int = None
        max_field_section_size:int = None
        blocked_streams:int = None
        h3_datagram:int = None
        webtransport:int = None
        """

        # variable-length integer
        max_table_capacity_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**32+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        # variable-length integer
        max_field_section_size_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**32+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        # variable-length integer
        blocked_streams_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**32+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        # variable-length integer
        h3_datagram_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**15+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        # variable-length integer
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

                                                      
    def build_h3_priority_update_strategy(self) -> st.SearchStrategy:
        """
        element_id:int = None
        field_value:str = None
        """

        # variable-length integer
        element_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**31+1),
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
    
    
    def extract_fuzzed_object_str_from_strategy(self, strategy:st.SearchStrategy) -> str:
        
        fuzzed_object_str = ""

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            example = strategy.example()
            if isinstance(example, QuicTransportParameters):
                fuzzed_object_str = "Transport Params"
            elif isinstance(example, QuicAck):
                fuzzed_object_str = "ACK"
            elif isinstance(example, QuicNewConnectionId):
                fuzzed_object_str = "NCI"
            elif isinstance(example, QuicStream):
                h3FrameName = ""
                if isinstance(example, H3Settings):
                    h3FrameName = H3_FRAME_ABBREVIATIONS["SETTINGS"]
                elif isinstance(example, H3Headers):
                    h3FrameName = H3_FRAME_ABBREVIATIONS["HEADERS"]
                elif isinstance(example, H3Data):
                    h3FrameName = H3_FRAME_ABBREVIATIONS["DATA"]
                elif isinstance(example, H3PriorityUpdate):
                    h3FrameName = H3_FRAME_ABBREVIATIONS["PRIORITY_UPDATE"]
                elif isinstance(example, QpackEncoder):
                    h3FrameName = "Enc"
                elif isinstance(example, QpackDecoder):
                    h3FrameName = "Dec"
                fuzzed_object_str = "Stream[{}]".format(h3FrameName)

        return fuzzed_object_str

    def restart_remote_server(self):

        def run_remote_tmux_command(ssh, command):
            stdin, stdout, stderr = ssh.exec_command(command)
            return stdout.read().decode(), stderr.read().decode()
        
        # Setup SSH connection
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        key = paramiko.Ed25519Key.from_private_key_file(self.ssh_key_path)
        client.connect(self.hostname, 22, self.ssh_user, pkey=key)
        
        # Kill running process
        cmd ="sudo pkill -9 -f autorun.py"
        run_remote_tmux_command(client, cmd)

        time.sleep(3)

        # Run the new process
        cmd = "tmux send-keys -t server 'sudo python3 autorun.py {} {}' Enter".format(self.server_name, self.server_version)
        run_remote_tmux_command(client, cmd)

        client.close()

if __name__ == "__main__":
    install()

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
        "-rf",
        "--reproduce_failure",
        type=str,
        default=None,
        help="Comma seperated hypothesis version and test case string to reproduce a specific case (e.g. 6.113.0,AAMBAw==) to build @reproduce_failure('6.113.0', b'AAMBAw==')"
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
        reproduce_failure=args.reproduce_failure,
        restart_server=args.restart_server,
        ssh_user=args.ssh_user,
        ssh_key_path=args.ssh_key_path,
        server_name=args.server_name,
        server_version=args.server_version)
    
    
    fuzzer.set_up_graph(args.state_machine, args.pcap)


    print("Starting the fuzzer at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
    fuzzer.fuzz()

    sys.exit()
