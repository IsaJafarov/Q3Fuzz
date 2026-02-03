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
from typing import Union

from libs import *
from libs.dissector import *
from libs.util import QUIC_FRAME_ABBREVIATIONS, H3_FRAME_ABBREVIATIONS
from libs.http_client import HttpClient

from aioquic.h3.connection import H3_ALPN
from aioquic.quic.packet import QuicPreferredAddress
from datetime import datetime
import time
import concurrent.futures
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn, SpinnerColumn
from rich.console import Console
from rich.table import Table
import warnings
import paramiko
from hypothesis import given, reproduce_failure, settings, Verbosity, Phase, strategies as st, HealthCheck
from hypothesis.database import DirectoryBasedExampleDatabase
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
                 parallel_requests:int, interval:int, duration:int, verbose:bool, no_response:bool,
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
        self.verbose = verbose
        self.restart_server = restart_server
        self.ssh_user = ssh_user
        self.ssh_key_path = ssh_key_path
        self.server_name = server_name
        self.server_version = server_version
        self.num_of_replays = num_of_replays
        self.no_response = no_response


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
        table.add_row("Number of mutations for each transition", "{}".format(self.mutations) )
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
        fuzzing_and_following_transitions = OrderedDict()
        # Keys: the list of transitions to fuzz in the form of (source_node, target_node) tuple. 
        # Values: the list of transitions that follow the target_node. We need this information, 
        # because after fuzzing the (source_node, target_node) transition, we will need to travel the following transition, too.
        for node in self.graph.nodes():

            if node == FIRST_STATE:
                continue

            successors = list()
            for successor in self.graph.successors(node):
                if get_triggering_msg_of_transition(node, successor): # the transition has a triggering message
                    successors.append( (node, successor) )
            
            for predecessor in self.graph.predecessors(node):
                if get_triggering_msg_of_transition(predecessor, node): # the transition has a triggering message
                    fuzzing_and_following_transitions[ (predecessor, node) ] = successors
        

        self.print_info(fuzzing_and_following_transitions.keys())

        # 2. Fuzz Transport Prameters
        if self.verbose:
            print("\n\nTransition: START -> {}\n".format(FIRST_STATE))
            print("\tFuzzing Transport Parameters" )
        transport_params_strategy = self._build_transport_params_strategy()

        following_msgs=list()
        for source_node, target_node in fuzzing_and_following_transitions.keys():
            if source_node==FIRST_STATE:
                following_msgs.append( get_triggering_msg_of_transition(FIRST_STATE, target_node) )

        try:
            self.fuzz_msg_with_strategy(transport_params_strategy, following_msgs=following_msgs)
        except KeyboardInterrupt:
            pass # When interrupted, stop fuzzing the transport params and move to frame fuzzing


        # 3. Fuzz individual messages
        for source_node, target_node in fuzzing_and_following_transitions.keys():

            print("\n\nTransition: {} -> {}\n".format(source_node, target_node))

            moving_msgs_path = nx.shortest_path(self.graph, FIRST_STATE, source_node)
            moving_msgs = list()
            for i in range(len(moving_msgs_path)-1):
                moving_msgs.append( get_triggering_msg_of_transition(moving_msgs_path[i], moving_msgs_path[i+1]) )

            triggering_msg = get_triggering_msg_of_transition(source_node, target_node)

            following_msgs = list()
            for target_node, following_node in fuzzing_and_following_transitions[ (source_node, target_node) ]:
                following_msgs.append( get_triggering_msg_of_transition(target_node, following_node))
            
            self.fuzz_state_transition(moving_msgs, triggering_msg, following_msgs)


    def fuzz_state_transition(self, moving_msgs:List[QuicPacket], triggering_msg:QuicPacket, following_msgs:List[QuicPacket]) -> None:
        """
        Dissect the triggering message into individual frames to fuzz them independently
        """

        if self.server_name == "mvfst":           
                     
            first_msg_found = False
            for mm in moving_msgs:
                if len(mm)==3 and isinstance(mm[0], QuicStream) and isinstance(mm[1], QuicStream) and isinstance(mm[2], QuicStream) and mm[0].stream_id==2 and mm[1].stream_id==6 and mm[2].stream_id==10:
                    first_msg_found = True
                if first_msg_found and len(mm)==2 and isinstance(mm[0], QuicStream) and isinstance(mm[1], QuicStream) and mm[0].stream_id==0 and mm[1].stream_id==6:
                    return
                    
        
        for i in range(len(triggering_msg)):
            quic_frame = triggering_msg[i]

            preceding_quic_frames = triggering_msg[:i]
            succeeding_quic_frames = triggering_msg[i+1:]

            strategy = None
            if isinstance(quic_frame, QuicAck):
                if self.verbose:
                    print("\tFuzzing ACK" )
                strategy = self._build_ack_strategy(quic_frame)
            elif isinstance(quic_frame, QuicNewConnectionId):
                if self.verbose:
                    print("\tFuzzing NCI" )
                strategy = self._build_new_connection_id_strategy(quic_frame)
            elif isinstance(quic_frame, QuicStream):
                if self.verbose:
                    print("\tFuzzing STREAM" )
                strategy = self._build_stream_strategy(quic_frame)
            elif isinstance(quic_frame, QuicMaxStreams):
                if self.verbose:
                    print("\tFuzzing QuicMaxStreams" )
                strategy = self._build_max_streams_strategy(quic_frame)
            else:
                raise Exception("[-] Unsupported QUIC Frame: {}".format(quic_frame))
            
            try:
                self.fuzz_msg_with_strategy(strategy, moving_msgs, preceding_quic_frames, succeeding_quic_frames, following_msgs)
            except KeyboardInterrupt:
                pass # when interrupted, move to the next frame

    def fuzz_msg_with_strategy(self, 
                            strategy:st.SearchStrategy,
                            moving_msgs:List[QuicPacket] = [], 
                            preceding_quic_frames:List[QuicFrame] = [], 
                            succeeding_quic_frames:List[QuicFrame] = [],
                            following_msgs:List[QuicPacket] = []) -> None:
        """
        Apply the mutation strategy to the selected frame
        """
        
        num=1

        def verify_hypothesis_failures():
            def decorator(test_func):
                @functools.wraps(test_func)
                def wrapper(*args, **kwargs):
                    try:
                        test_func(*args, **kwargs)
                    except Exception as original_error:
                        raise original_error
                        print("> Failed. Let's replay {} times.".format(self.num_of_replays) )
                        # Test failed - verify it's consistent
                        failures = 0
                        for _ in range(self.num_of_replays):
                            try:
                                time.sleep(5)    
                                self._restart_remote_server()
                                time.sleep(5)
                                test_func(*args, **kwargs)
                                print("> Passed this time :(")
                                return
                            except Exception:
                                print("> Failed again:)" )
                                failures += 1
                        # Only raise if it fails consistently
                        if failures == self.num_of_replays:
                            print("> Failed in all attempts!".format() )
                            raise original_error
                return wrapper
            return decorator

        @given( strategy )
        @settings(deadline=None, verbosity=Verbosity.normal, print_blob=False, 
                  # Exclude the Shrinking phase. We want to see the first example that caused the error.
                  phases=[Phase.explicit , Phase.reuse, Phase.generate, Phase.target], 
                  max_examples=self.mutations,
                  database=DirectoryBasedExampleDatabase("/home/ubuntu/hypothesis-db"),
                  suppress_health_check=list(HealthCheck))
        @verify_hypothesis_failures()
        def fuzz_msg_with_strategy_inner(moving_msgs:List[QuicPacket], 
                                          preceding_quic_frames:QuicPacket, 
                                          succeeding_quic_frames:List[QuicFrame], 
                                          following_msgs:List[QuicPacket],
                                          fuzzed_entity):
                
            if self.verbose:
                nonlocal num
                print("\n\t\tMutation #{}: {}".format(num, fuzzed_entity))
                num += 1
            
            # the following code is for reproducing Chatzoglou vulnerability
            # if isinstance(fuzzed_entity, QuicStream) and isinstance(fuzzed_entity.h3_frame, H3Settings):
            #         print("Fuzzzzzzzz that SETTINGS!")
            #         if fuzzed_entity.h3_frame.max_table_capacity < 20 and fuzzed_entity.h3_frame.blocked_streams < 5:
            #             print("Hellllllllllllllllllllllll Yeah. Found that MF")
            #             print(fuzzed_entity)

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
                                                        preceding_quic_frames=preceding_quic_frames,
                                                        succeeding_quic_frames=succeeding_quic_frames,
                                                        following_msg=following_msg)
                        time.sleep(self.interval)

                # check if we can establish a connection with the server.
                # if we can't, then the server is down
                self.check_server_liveness()
    
                self._restart_remote_server()

            
            progress.update(mutations_bar, advance=1)

            if self.verbose:
                print("\n\n")
            

        
        with Progress( # build a progress bar
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            SpinnerColumn()) as progress:

            mutations_bar = progress.add_task("Fuzz "+self._extract_fuzzed_object_str_from_strategy(strategy), total=self.mutations, visible=not self.verbose)

            fuzz_msg_with_strategy_inner(moving_msgs, preceding_quic_frames, succeeding_quic_frames, following_msgs)
            

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

        if QUIC_FRAME_ABBREVIATIONS['HANDSHAKE_DONE'] not in res2:
            raise Exception("Server did not complete handshake")
        
        if self.verbose:
            print("\t\tServer is UP")


    def execute_attack(self, 
                       fuzzed_entity:Union[QuicTransportParameters, QuicFrame], 
                       moving_msgs:List[QuicPacket]=[], 
                       preceding_quic_frames:List[QuicFrame]=[], 
                       succeeding_quic_frames:List[QuicFrame]=[],
                       following_msg:QuicPacket=[]) -> None:
        
        # Ignore errors during the attack.
        # Once the attack completes, we will check the server liveness. At that point, we will care about the connection errors.
        try: 
            h3client = HttpClient(self.quic_conf, self.hostname)

            if isinstance(fuzzed_entity, QuicTransportParameters):
                
                # we need to keeep the connection id as is, otherwise the client doesn't know which received packets correspond this connection
                fuzzed_entity.initial_source_connection_id = h3client.connection._host_cids[0].cid

                h3client.connect(fuzzed_entity)
                connect_response = h3client.read_from_buffer()
                if self.verbose:
                    print("\t\tConnection: {}. Connection Response: {}".format(h3client.connection._host_cids[0].cid.hex(), connect_response) )

                h3client.complete_connection()
                completion_response = h3client.read_from_buffer()
                if self.verbose:
                    print("\t\tConnection: {}. Handshake Response: {}".format(h3client.connection._host_cids[0].cid.hex(), completion_response) )
                
                following_trans_response = h3client.send_frames( following_msg, wait_for_response=(not self.no_response) )
                if self.verbose:
                    print("\t\tConnection: {}. Following Transition Response: {}".format(h3client.connection._host_cids[0].cid.hex(), following_trans_response) )

            else:

                # Connection Initialization
                h3client.connect()
                connect_response = h3client.read_from_buffer()  # Receive any response from the server
                if self.verbose:
                    print("\t\tConnection: {}. Connection Response: {}".format(h3client.connection._host_cids[0].cid.hex(), connect_response) )

                # Complete the connection by sending handshake completion messages
                h3client.complete_connection()
                completion_response = h3client.read_from_buffer()
                if self.verbose:
                    print("\t\tConnection: {}. Handshake Response: {}".format(h3client.connection._host_cids[0].cid.hex(), completion_response) )

                # Send Moving Messages
                for moving_msg in moving_msgs:
                    moving_msg_response = h3client.send_frames(moving_msg, wait_for_response=(not self.no_response) )
                    if self.verbose:
                        print("\t\tConnection: {}. Moving Msg Response: {}".format(h3client.connection._host_cids[0].cid.hex(), moving_msg_response) )

                test_input_response = h3client.send_frames( preceding_quic_frames + [fuzzed_entity] + succeeding_quic_frames, wait_for_response=(not self.no_response) )
                if self.verbose:
                    print("\t\tConnection: {}. Fuzzed Transition Response: {}".format(h3client.connection._host_cids[0].cid.hex(), test_input_response))

                #h3client.replay_msg(following_msg) # TODO replay_msg() doesn't work. Don't make MSGDissector H3Client's object parameter
                following_trans_response = h3client.send_frames( following_msg, wait_for_response=(not self.no_response) ) 
                if self.verbose:
                    print("\t\tConnection: {}. Following Transition Response: {}".format(h3client.connection._host_cids[0].cid.hex(), following_trans_response) )

        except Exception as e:
            raise e
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
        
    def _extract_fuzzed_object_str_from_strategy(self, strategy:st.SearchStrategy) -> str:
        
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


    # Build Transport Parameters strategy

    def _build_transport_params_strategy(self) -> st.SearchStrategy:
        """
        QuicTransportParameters:
            original_destination_connection_id: Optional[bytes]
            max_idle_timeout: Optional[int]
            stateless_reset_token: Optional[bytes]
            max_udp_payload_size: Optional[int]
            initial_max_data: Optional[int]
            initial_max_stream_data_bidi_local: Optional[int]
            initial_max_stream_data_bidi_remote: Optional[int]
            initial_max_stream_data_uni: Optional[int]
            initial_max_streams_bidi: Optional[int]
            initial_max_streams_uni: Optional[int]
            ack_delay_exponent: Optional[int]
            max_ack_delay: Optional[int]
            disable_active_migration: Optional[bool] = False
            preferred_address: Optional[QuicPreferredAddress]
            active_connection_id_limit: Optional[int]
            initial_source_connection_id: Optional[bytes]
            retry_source_connection_id: Optional[bytes]
            version_information: Optional[QuicVersionInformation]
            max_datagram_frame_size: Optional[int]
            quantum_readiness: Optional[bytes]                         
        """


        # variable length byte sequence. len<=20
        original_destination_connection_id_field_strategy = st.one_of(
            st.binary(min_size=0, max_size=21),
            st.sampled_from( [None] ),
        )

        # variable length integer
        max_idle_timeout_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # sequence of 16 bytes
        stateless_reset_token_field_strategy = st.one_of(
            st.binary(min_size=0, max_size=17),
            st.sampled_from( [None] ),
        )
        
        # should be <1200 is invalid
        max_udp_payload_size_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )
        
        initial_max_data_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        initial_max_stream_data_bidi_local_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        initial_max_stream_data_bidi_remote_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        initial_max_stream_data_uni_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        initial_max_streams_bidi_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        initial_max_streams_uni_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        ack_delay_exponent_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        max_ack_delay_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # 0 length. Either exists or not
        disable_active_migration_field_strategy = st.booleans()

        preferred_address_field_strategy = st.builds(QuicPreferredAddress, 
                                                     ipv4_address=st.tuples( st.ip_addresses(v=4).map(str), st.integers(min_value=0, max_value=2^16) ),
                                                     ipv6_address=st.tuples( st.ip_addresses(v=6).map(str), st.integers(min_value=0, max_value=2^16) ),
                                                     connection_id=st.binary(),
                                                     stateless_reset_token=st.binary())

        # <2 should result in connection close
        active_connection_id_limit_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )
        
        # variable length byte sequence. len<=20
        initial_source_connection_id_field_strategy = st.one_of(
            st.binary(min_size=0, max_size=21),
            st.sampled_from( [None] ),
        )

        # variable length byte sequence. len<=20. this should be sent only by the sever
        retry_source_connection_id_field_strategy = st.one_of(
            st.binary(min_size=0, max_size=21),
            st.sampled_from( [None] ),
        )
        
        version_information_chosen_version_field_strategy = st.builds(QuicVersionInformation,
            chosen_version = st.integers(min_value=1, max_value=1),
            available_versions = st.lists( st.integers(min_value=1, max_value=1), min_size=1, max_size=1 )
        )

        # RFC 9221
        max_datagram_frame_size_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        
        quantum_readiness_field_strategy = st.one_of(
            st.binary(min_size=0, max_size=2000),
            st.sampled_from( [None] ),
        )
        
        
        default_field_strategies = [
            st.just(3),  # ack_delay_exponent
            st.just(8), # active_connection_id_limit
            st.just(int(self.quic_conf.idle_timeout * 1000)), # max_idle_timeout
            st.just(None),
            st.just(self.quic_conf.max_data), # initial_max_data
            st.just(self.quic_conf.max_stream_data ), # initial_max_stream_data_bidi_local
            st.just(self.quic_conf.max_stream_data), # initial_max_stream_data_bidi_remote
            st.just(self.quic_conf.max_stream_data), # initial_max_stream_data_uni
            st.just(128), # initial_max_streams_bidi
            st.just(128), # initial_max_streams_uni
            #st.just(default_quic_conn._host_cids[0].cid), # initial_source_connection_id
            st.just(25), # max_ack_delay
            st.just(False), # disable_active_migration
            st.just(None), # preferred_address
            st.just(None), # retry_source_connection
            st.just(self.quic_conf.max_datagram_frame_size), # max_datagram_frame_size
            st.just(( b"Q" * SMALLEST_MAX_DATAGRAM_SIZE if self.quic_conf.quantum_readiness_test else None)), # quantum_readiness
            st.just(None), # stateless_reset_token
            st.just(QuicVersionInformation( chosen_version=self.quic_conf.original_version, available_versions=self.quic_conf.supported_versions)), # version_information            
        ]

        modifying_field_strategies = [
            ack_delay_exponent_field_strategy,
            active_connection_id_limit_field_strategy,
            max_idle_timeout_field_strategy,
            max_udp_payload_size_field_strategy,
            initial_max_data_field_strategy,
            initial_max_stream_data_bidi_local_field_strategy,
            initial_max_stream_data_bidi_remote_field_strategy,
            initial_max_stream_data_uni_field_strategy,
            initial_max_streams_bidi_field_strategy,
            initial_max_streams_uni_field_strategy,
            #initial_source_connection_id_field_strategy,
            max_ack_delay_field_strategy,
            disable_active_migration_field_strategy,
            preferred_address_field_strategy,
            retry_source_connection_id_field_strategy,
            max_datagram_frame_size_field_strategy,
            quantum_readiness_field_strategy,
            stateless_reset_token_field_strategy,
            version_information_chosen_version_field_strategy
        ]
        
        inter_field_strategies = self._build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(QuicTransportParameters, 
                        ack_delay_exponent = final_strategy[0],
                        active_connection_id_limit = final_strategy[1],
                        max_idle_timeout = final_strategy[2],
                        max_udp_payload_size = final_strategy[3],
                        initial_max_data = final_strategy[4],
                        initial_max_stream_data_bidi_local = final_strategy[5],
                        initial_max_stream_data_bidi_remote = final_strategy[6],
                        initial_max_stream_data_uni = final_strategy[7],
                        initial_max_streams_bidi = final_strategy[8],
                        initial_max_streams_uni = final_strategy[9],
                        #initial_source_connection_id = final_strategy[9],
                        max_ack_delay = final_strategy[10],
                        disable_active_migration = final_strategy[11],
                        preferred_address = final_strategy[12],
                        retry_source_connection_id = final_strategy[13],
                        max_datagram_frame_size = final_strategy[14],
                        quantum_readiness = final_strategy[15],
                        stateless_reset_token = final_strategy[16],
                        version_information = final_strategy[17])
            )

        return st.one_of(built_strategies)


    # Build QUIC frame strategies
    
    def _build_ack_strategy(self, ack_frame:QuicAck) -> st.SearchStrategy:
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
            st.sampled_from( [ [(0, 5)], [(16, 5)], [(997, 5)], [(LARGEST_VARINT_LEN8, 5)], [(LARGEST_VARINT_LEN2, 5)],
                               [(5, 0)], [(5, 16)], [(5, 997)], [(5, LARGEST_VARINT_LEN8)], [(5, LARGEST_VARINT_LEN2)] ] ),
        )
        
        
        default_field_strategies = [
            st.just(ack_frame.largest_acknowledged), 
            st.just(ack_frame.ack_delay), 
            st.just(ack_frame.ack_range_count), 
            st.just(ack_frame.ack_first_ack_range), 
            st.just(ack_frame.ack_ranges)
        ]

        modifying_field_strategies = [
            ack_largest_acknowledged_field_strategy,
            ack_delay_field_strategy,
            ack_range_count_field_strategy,
            ack_first_ack_range_field_strategy,
            ack_ranges_field_strategy
        ]
        
        inter_field_strategies = self._build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(QuicAck, 
                          final_strategy[0],
                          final_strategy[1],
                          final_strategy[2],
                          final_strategy[3],
                          final_strategy[4] )
            )

        return st.one_of(built_strategies)
    
    def _build_new_connection_id_strategy(self, nci_frame:QuicNewConnectionId) -> st.SearchStrategy:
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

        # 8-bit unsigned integer
        # length_field_strategy = st.one_of(
        #     st.integers(min_value=0, max_value=2**8+1), 
        #     st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        # )

        # connection ID of the specified length
        connection_id_field_strategy = st.binary(min_size=0, max_size=2**8+1)

        # 128-bit (16 byte) value
        stateless_reset_token_strategy = st.binary(min_size=0, max_size=20)
        
        
        default_field_strategies = [
            st.just(nci_frame.sequence_number), 
            st.just(nci_frame.retire_prior_to), 
            # st.just(nci_frame.length), 
            st.just(nci_frame.connection_id), 
            st.just(nci_frame.stateless_reset_token)
        ]

        modifying_field_strategies = [
            sequence_number_field_strategy,
            retire_prior_to_field_strategy,
            # length_field_strategy,
            connection_id_field_strategy,
            stateless_reset_token_strategy
        ]
        
        inter_field_strategies = self._build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(QuicNewConnectionId, 
                          final_strategy[0],
                          final_strategy[1],
                          final_strategy[2],
                          final_strategy[3])
            )

        return st.one_of(built_strategies)

    def _build_stream_strategy(self, stream_frame:QuicStream) -> st.SearchStrategy:
        """
        QuicStream:
            stream_id:int
            fin_bit:bool
            offset:int
            h3_frame:H3Frame
        """

        stream_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**31+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        fin_bit_field_strategy = st.booleans()

        
        if self.server_name == "msquic-kestrel":
            # Don't rediscover the same vulnerability that stems from fin_bit=True
            fin_bit_field_strategy = st.just(False)

        offset_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        h3_frame_strategy = st.none()
        if isinstance(stream_frame.h3_frame, H3Data):
            h3_frame_strategy = self._build_h3_data_strategy(stream_frame.h3_frame)
        elif isinstance(stream_frame.h3_frame, H3Headers):
            h3_frame_strategy = self._build_h3_headers_strategy(stream_frame.h3_frame)
        elif isinstance(stream_frame.h3_frame, H3Settings):
            h3_frame_strategy = self._build_h3_settings_strategy(stream_frame.h3_frame)
        elif isinstance(stream_frame.h3_frame, H3PriorityUpdate):
            h3_frame_strategy = self._build_h3_priority_update_strategy(stream_frame.h3_frame)        
        elif isinstance(stream_frame.h3_frame, QpackEncoder):
            h3_frame_strategy = self._build_h3_qpack_encoder_strategy(stream_frame.h3_frame)
        elif isinstance(stream_frame.h3_frame, QpackDecoder):
            h3_frame_strategy = self._build_h3_qpack_decoder_strategy(stream_frame.h3_frame)
        elif stream_frame.h3_frame is None:
            h3_frame_strategy = st.none() # stream doesn't have any application layer data
        else:
            raise Exception("[-] Unsupported Application Layer Data: {}".format(stream_frame.h3_frame))
        
        
        default_field_strategies = [
            st.just(stream_frame.stream_id), 
            st.just(stream_frame.fin_bit), 
            st.just(stream_frame.offset), 
            st.just(stream_frame.h3_frame)
        ]

        modifying_field_strategies = [
            stream_id_field_strategy,
            fin_bit_field_strategy,
            offset_field_strategy,
            h3_frame_strategy
        ]
        
        inter_field_strategies = self._build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(QuicStream, 
                          final_strategy[0],
                          final_strategy[1],
                          final_strategy[2],
                          final_strategy[3])
            )

        
        return st.one_of(built_strategies)
    
    def _build_max_streams_strategy(self, max_streams_frame:QuicMaxStreams) -> st.SearchStrategy:
        """
        QuicMaxStreams:
            maximum_streams:int
        """

        max_streams_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        default_field_strategies = [
            st.just(max_streams_frame.maximum_streams)
        ]

        modifying_field_strategies = [
            max_streams_field_strategy
        ]
        
        inter_field_strategies = self._build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(QuicMaxStreams, 
                          final_strategy[0])
            )

        return st.one_of(built_strategies)


    # Build HTTP/3 frame strategies

    def _build_h3_settings_strategy(self, settings_frame:H3Settings) -> st.SearchStrategy:
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
        
        
        default_field_strategies = [
            st.just(settings_frame.max_table_capacity), 
            st.just(settings_frame.max_field_section_size), 
            st.just(settings_frame.blocked_streams), 
            st.just(settings_frame.h3_datagram), 
            st.just(settings_frame.webtransport)
        ]

        modifying_field_strategies = [
            max_table_capacity_field_strategy,
            max_field_section_size_field_strategy,
            blocked_streams_field_strategy,
            h3_datagram_field_strategy,
            webtransport_strategy
        ]
        
        inter_field_strategies = self._build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(H3Settings, 
                          final_strategy[0],
                          final_strategy[1],
                          final_strategy[2],
                          final_strategy[3],
                          final_strategy[4] )
            )

        
        return st.one_of(built_strategies)
                                                      
    def _build_h3_priority_update_strategy(self, priority_update_frame:H3PriorityUpdate) -> st.SearchStrategy:
        """
        H3PriorityUpdate:
            element_id:int
            field_value:str
        """

        element_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**31+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES),
        )

        # ASCII string
        field_value_field_strategy = st.one_of(
            st.text(min_size=0, max_size=10), 
            st.sampled_from(["", "000000", "a"*20, "a"*200, "\u2298" ])
        )

       
        
        default_field_strategies = [
            st.just(priority_update_frame.element_id), 
            st.just(priority_update_frame.field_value)
        ]

        modifying_field_strategies = [
            element_id_field_strategy,
            field_value_field_strategy
        ]
        
        inter_field_strategies = self._build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(H3PriorityUpdate, 
                          final_strategy[0],
                          final_strategy[1] )
            )

        
        #print(st.one_of(built_strategies))

        return st.one_of(built_strategies)
    
    def _build_h3_data_strategy(self, data_frame:H3Data) -> st.SearchStrategy:
        """
        H3Data:
            payload:bytes
        """

        payload_field_strategy = st.binary()


        return st.builds(H3Data, 
                        payload_field_strategy )

    def _build_h3_headers_strategy(self, headers_frame:H3Headers) -> st.SearchStrategy:
        """
        H3Headers:
            payload:bytes
        """

        payload_field_strategy = st.binary()

        return st.builds(H3Headers, 
                        payload_field_strategy )
    
    def _build_h3_qpack_encoder_strategy(self, qpack_encoder:QpackEncoder) -> st.SearchStrategy:
        """
        QpackEncoder:
            payload:bytes
        """

        payload_field_strategy = st.binary()

        return st.builds(QpackEncoder, 
                        payload_field_strategy )
    
    def _build_h3_qpack_decoder_strategy(self, qpack_decoder:QpackDecoder) -> st.SearchStrategy:
        """
        QpackDecoder:
            payload:bytes
        """

        payload_field_strategy = st.binary()

        return st.builds(QpackDecoder, 
                        payload_field_strategy )

    def _build_inter_field_strategies(self, default_field_strategies:List[st.SearchStrategy], modifying_field_strategies:List[st.SearchStrategy]) -> List[List[st.SearchStrategy]]:
       
        inter_field_strategies:List[List[st.SearchStrategy]] = []

        # Modify a single field at a time, while keeping the other fields as is
        for i in range(len(modifying_field_strategies)):
            # copy the list, so that the change will not reflect on the original list
            default_values_strategy_copy = default_field_strategies.copy() 

            # replace default value of a single field, with corresponding modifying field
            default_values_strategy_copy[i] = modifying_field_strategies[i]

            # add it to the inter-field strategies
            inter_field_strategies.append(default_values_strategy_copy )


        # Additionally, modify all fileds at the same time
        # There are more possible test cases when we modify all fields at once than modifying each field
        # Therefore, we want the strategy that modifies all fields together has higher priority
        # Hypothesis does not allow giving weights to priorities, when we merge them with one_of() method
        # Through observation, we see that when multiple strategies are merged with one_of() method, the first one is used more for data generation
        # Thefore, insert modifying_field_strategies at the beginning of the list
        inter_field_strategies.insert(0, modifying_field_strategies )
        # P.S. adding the same strategy multiple times to one_of() does not increase its 'priority'
        
        #print(inter_field_strategies)

        return inter_field_strategies
    
   
if __name__ == "__main__":
    #install()

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
        "-m",
        "--mutations",
        type=int,
        default=100,
        help="The number of mutations to apply on each QUIC, HTTP/3 frame and Transport Params (default 100)"
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
        "-nr", "--no_response", action="store_true", help="Do not wait for the server to send back resonse for 1-RTT messages. \
        Transmitting messages without waiting can lead to abnormal server behaviour."
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
        verbose = args.verbose,
        no_response=args.no_response,
        restart_server=args.restart_server,
        ssh_user=args.ssh_user,
        ssh_key_path=args.ssh_key_path,
        server_name=args.server_name,
        server_version=args.server_version,
        num_of_replays=args.replay)
    
    
    fuzzer.set_up_graph(args.state_machine, args.pcap)


    print("Starting the fuzzer at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
    fuzzer.fuzz()

    sys.exit()
