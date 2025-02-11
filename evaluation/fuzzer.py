import json
import networkx as nx
import sys
import ssl
import argparse
from typing import List
from aioquic.quic.connection import *
from pyshark.packet.packet import Packet
from urllib.parse import urlparse

from aioquic.h3.connection import FrameType
from crafter import MSGCrafter
import util
from rich.traceback import install
from http_client import HttpClient
from aioquic.h3.connection import H3_ALPN
from aioquic.tls import Epoch
from pyshark.packet.layers.xml_layer import XmlLayer
from dissector import *
from aioquic.h3.connection import encode_frame
from util import QUIC_FRAME_ABBREVIATIONS, H3_FRAME_ABBREVIATIONS
from datetime import datetime
import time
import concurrent.futures
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn, SpinnerColumn
from rich.console import Console
from rich.table import Table
import warnings


from hypothesis import example, given, note, reproduce_failure, settings, Verbosity, Phase, strategies as st



PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]

# largest values in varint encoding. https://www.rfc-editor.org/rfc/rfc9000.html#section-16
LARGEST_VARINT_LEN1 = 0x3F # length = 1. hex value is 63
LARGEST_VARINT_LEN2 = 0x3FFF # length = 2. hex value is 16383
LARGEST_VARINT_LEN4 = 0x3FFFFFFF # length = 4. hex value is 1073741823
LARGEST_VARINT_LEN8 = 0x3FFFFFFFFFFFFFFF # length = 8. hex value is 4611686018427387903
# Higher values throw "Integer is too big for a variable-length integer"
SAMPLE_VALUES_FOR_VARINT_VALUES = [0, 16, 997, 10**5, 10**10, LARGEST_VARINT_LEN1, LARGEST_VARINT_LEN2, LARGEST_VARINT_LEN4, LARGEST_VARINT_LEN8 ]

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

"""


class Fuzzer():
    def __init__(self, quic_conf:QuicConfiguration, hostname:str, keylog_file:str, mutations:int, parallel_requests:int, interval:int, duration:int, verbose:bool):
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
    
    def set_up_graph(self, sm_file_path:str, traffic_file_path:str):
        with open(sm_file_path, 'r') as f:
            data = json.load(f)

        for t in data['transitions']:
            source = t['source']
            destination = t['dest']
            trigger = t['trigger'].strip()
            packet_number = t['conditions'][0].split(":")[1]
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
        
        def get_transitions_to_fuzz():
            transitions = []
            for node in self.graph.nodes():

                if node=="Init" or node=="Finish":
                    continue
                
                for pre in self.graph.predecessors(node):
                    if pre == node: 
                        continue
                    
                    transitions.append( (pre, node) )

            return transitions

        transitions_to_fuzz = get_transitions_to_fuzz()
        self.print_info(get_transitions_to_fuzz())


        # Fuzz Transport Prameters
        if self.verbose:
            print("Fuzzing Transport Parameters at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
        transport_params_strategy = self.build_transport_params_strategy()
        self.fuzz_msg_with_strategy(transport_params_strategy)

        # Fuzz individual messages
        for source_node, target_node in transitions_to_fuzz:
            
            print("\n\nTransition: {} -> {}\n".format(source_node, target_node))

            nodes_in_the_path = nx.shortest_path(self.graph, "Init", source_node)

            moving_msgs_packet_nums = []
            for i in range(len(nodes_in_the_path)-1):
                edge = self.graph.get_edge_data(nodes_in_the_path[i], nodes_in_the_path[i+1])
                trigger = edge['trigger']
                packet_number = int(edge['packet_number'])
                moving_msgs_packet_nums.append( packet_number )

            edge_to_fuzz = self.graph.get_edge_data(source_node, target_node)
            response = edge_to_fuzz['trigger'].split("=>")[1].strip()
            triggering_msg_packet_num = int(edge_to_fuzz['packet_number'])
            triggering_msg = self.find_message_by_packet_number(triggering_msg_packet_num)

            self.fuzz_state_transition(moving_msgs_packet_nums, triggering_msg)




                
                
                
    
    def reach_source_state(self, h3client:HttpClient, moving_msgs_packet_nums:List[int]) -> None:
        
        h3client.connect()
        h3client.read_from_buffer()  # Receive any response from the server

        # Complete the connection by sending handshake completion messages
        h3client.complete_connection()
        received_after_init = h3client.read_from_buffer()
        

        #print("\nMoving Messages:")
        for moving_msg_packet_num in moving_msgs_packet_nums:
            #print(moving_msg_packet_num)
            
            moving_msg = self.find_message_by_packet_number(moving_msg_packet_num)
            response = h3client.replay_msg(moving_msg)
            #print("{} => {}".format(util.h3msg_to_str(moving_msg), response))

    def fuzz_state_transition(self, moving_msgs_packet_nums:List[int], triggering_msg: Packet):
        
        msg_dissector = MSGDissector()
        quic_frames = msg_dissector.dissect_msg(triggering_msg)

        for i in range(len(quic_frames)):
            quic_frame = quic_frames[i]

            preceding_quic_frames = quic_frames[:i]
            succeeding_quic_frames = quic_frames[i+1:]

            strategy = None
            if type(quic_frame) == QuicAck:
                if self.verbose:
                    print("Fuzzing ACK at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
                strategy = self.build_ack_strategy(quic_frame)
                
            elif type(quic_frame) == QuicNewConnectionId:
                if self.verbose:
                    print("Fuzzing NCI at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
                strategy = self.build_nci_strategy(quic_frame)

            elif type(quic_frame) == QuicStream:
                if self.verbose:
                    print("Fuzzing STREAM at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
                strategy = self.build_stream_strategy(quic_frame)

            self.fuzz_msg_with_strategy(strategy, moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames)


    def fuzz_msg_with_strategy(self, 
                            strategy:st.SearchStrategy,
                            moving_msgs_packet_nums:List[int] = None, 
                            preceding_quic_frames:List[Union[QuicAck,QuicNewConnectionId,QuicStream]] = None, 
                            succeeding_quic_frames:List[Union[QuicAck,QuicNewConnectionId,QuicStream]] = None) -> None:
        
        num=1
        @given( strategy )
        @settings(deadline=None, verbosity=Verbosity.normal, print_blob=True, 
                  # Exclude the Shrinking phase. We want to see the first example that caused the error.
                  phases=[Phase.explicit , Phase.reuse, Phase.generate, Phase.target], 
                  max_examples=self.mutations)
        #@reproduce_failure('6.113.0', b'AAAAAAAAAAAAAQ==')
        def fuzz_msg_with_strategy_innner(moving_msgs_packet_nums:List[int], 
                                          preceding_quic_frames:List[Union[QuicAck,QuicNewConnectionId,QuicStream]], 
                                          succeeding_quic_frames:List[Union[QuicAck,QuicNewConnectionId,QuicStream]], 
                                          fuzzed_thing:Union[QuicTransportParameters,QuicAck,QuicNewConnectionId,QuicStream]):
            
            
            if self.verbose:
                nonlocal num
                print("\nMutation #{}: {}".format(num, fuzzed_thing))
                num += 1
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []

                if self.verbose:
                    print("\nSend {} requests in parallel for {} sec. with {} sec. interval".format( self.parallel_requests, self.duration, self.interval ))
                for i in range(int(self.duration/self.interval)):
                    
                    for j in range(self.parallel_requests):

                        # Submit each iteration as a separate task
                        futures.append(executor.submit(self.execute_attack, 
                                                       fuzzed_thing,
                                                       moving_msgs_packet_nums=moving_msgs_packet_nums, 
                                                       preceding_quic_frames=preceding_quic_frames,
                                                       succeeding_quic_frames=succeeding_quic_frames))
                    time.sleep(self.interval)

            fuzzer.check_server_availability()
            
            progress.update(mutations_bar, advance=1)

            if self.verbose:
                print("\n\n\n")
            

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            SpinnerColumn()) as progress:

            mutations_bar = progress.add_task("Fuzz "+self.extract_fuzzed_object_str_from_strategy(strategy), total=self.mutations, visible=not self.verbose)

            
            fuzz_msg_with_strategy_innner(moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames)
            

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
        res2 = received_after_init = h3client.read_from_buffer()

        if QUIC_FRAME_ABBREVIATIONS['HANDSHAKE_DONE'] not in res2:
            raise Exception("Server did not complete handshake")
        
        if self.verbose:
            print("Server is UP")
        

    def execute_attack(self, 
                       fuzzed_thing:Union[QuicTransportParameters,QuicAck,QuicNewConnectionId,QuicStream], 
                       moving_msgs_packet_nums:List[int]=None, 
                       preceding_quic_frames:List=None, 
                       succeeding_quic_frames:List=None) -> None:
        
        h3client = HttpClient(self.quic_conf, self.hostname)

        # Ignore errors during the attack.
        # Once the attack complets, we will check the server availability. At that point, we will care about the connection errors.
        try: 
            if type(fuzzed_thing) is QuicTransportParameters:

                # we need to keeep the connection id as is, otherwise the client doesn't know which received packets are for this connection
                fuzzed_thing.initial_source_connection_id = h3client.connection._host_cids[0].cid

                h3client.connect(fuzzed_thing)
                connect_response = h3client.read_from_buffer()
                if self.verbose:
                    print("\tConnection {}. Response 1: {}".format(h3client.connection._host_cids[0].cid.hex(), connect_response) )

                h3client.complete_connection()
                completion_response = h3client.read_from_buffer()
                if self.verbose:
                    print("\tConnection {}. Response 2: {}".format(h3client.connection._host_cids[0].cid.hex(), completion_response) )

            else:
                self.reach_source_state(h3client, moving_msgs_packet_nums)

                response = h3client.send_frames( preceding_quic_frames + [fuzzed_thing] + succeeding_quic_frames )

                if self.verbose:
                    print("\tResponse: {}".format(response) )
        except Exception as e:
            if self.verbose:
                print(e)
            else:
                pass

    def find_message_by_packet_number(self, packet_number:int) -> Packet:
        for msg in self.traffic_messages:
            if int(msg.quic.packet_number) == packet_number:
                #print(msg.quic)
                return msg
        raise Exception("Packet with packet_number {} does not exist!".format(packet_number)) 
        

    
    # Build strategies
    def build_transport_params_strategy(self) -> st.SearchStrategy:
        """
        class QuicTransportParameters:
            original_destination_connection_id: Optional[bytes] = None
            max_idle_timeout: Optional[int] = None
            stateless_reset_token: Optional[bytes] = None
            max_udp_payload_size: Optional[int] = None
            initial_max_data: Optional[int] = None
            initial_max_stream_data_bidi_local: Optional[int] = None
            initial_max_stream_data_bidi_remote: Optional[int] = None
            initial_max_stream_data_uni: Optional[int] = None
            initial_max_streams_bidi: Optional[int] = None
            initial_max_streams_uni: Optional[int] = None
            ack_delay_exponent: Optional[int] = None
            max_ack_delay: Optional[int] = None
            disable_active_migration: Optional[bool] = False
            preferred_address: Optional[QuicPreferredAddress] = None
            active_connection_id_limit: Optional[int] = None
            initial_source_connection_id: Optional[bytes] = None
            retry_source_connection_id: Optional[bytes] = None
            version_information: Optional[QuicVersionInformation] = None
            max_datagram_frame_size: Optional[int] = None
            quantum_readiness: Optional[bytes] = None                         
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
        
        # variable-length integer. <1200 is invalid
        max_udp_payload_size_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )
        
        # variable-length integer
        initial_max_data_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        initial_max_stream_data_bidi_local_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        initial_max_stream_data_bidi_remote_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        initial_max_stream_data_uni_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        initial_max_streams_bidi_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        initial_max_streams_uni_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        ack_delay_exponent_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        max_ack_delay_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # 0 length. Either exists or not TODO
        disable_active_migration_field_strategy = None

        
        preferred_address_field_strategy = None # TODO

        # variable-length integer. <2 should result in connection close
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

        # variable-length integer. RFC 9221
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
            st.just(self.quic_conf.max_data), # initial_max_data
            st.just(self.quic_conf.max_stream_data ), # initial_max_stream_data_bidi_local
            st.just(self.quic_conf.max_stream_data), # initial_max_stream_data_bidi_remote
            st.just(self.quic_conf.max_stream_data), # initial_max_stream_data_uni
            st.just(128), # initial_max_streams_bidi
            st.just(128), # initial_max_streams_uni
            #st.just(default_quic_conn._host_cids[0].cid), # initial_source_connection_id
            st.just(25), # max_ack_delay
            st.just(self.quic_conf.max_datagram_frame_size), # max_datagram_frame_size
            st.just(( b"Q" * SMALLEST_MAX_DATAGRAM_SIZE if self.quic_conf.quantum_readiness_test else None)), # quantum_readiness
            st.just(None), # stateless_reset_token
            st.just(QuicVersionInformation( chosen_version=self.quic_conf.original_version, available_versions=self.quic_conf.supported_versions)), # version_information            
        ]

        modifying_field_strategies = [
            ack_delay_exponent_field_strategy,
            active_connection_id_limit_field_strategy,
            max_idle_timeout_field_strategy,
            initial_max_data_field_strategy,
            initial_max_stream_data_bidi_local_field_strategy,
            initial_max_stream_data_bidi_remote_field_strategy,
            initial_max_stream_data_uni_field_strategy,
            initial_max_streams_bidi_field_strategy,
            initial_max_streams_uni_field_strategy,
            #initial_source_connection_id_field_strategy,
            max_ack_delay_field_strategy,
            max_datagram_frame_size_field_strategy,
            quantum_readiness_field_strategy,
            stateless_reset_token_field_strategy,
            version_information_chosen_version_field_strategy
        ]
        
        inter_field_strategies = self.build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(QuicTransportParameters, 
                        ack_delay_exponent = final_strategy[0],
                        active_connection_id_limit = final_strategy[1],
                        max_idle_timeout = final_strategy[2],
                        initial_max_data = final_strategy[3],
                        initial_max_stream_data_bidi_local = final_strategy[4],
                        initial_max_stream_data_bidi_remote = final_strategy[5],
                        initial_max_stream_data_uni = final_strategy[6],
                        initial_max_streams_bidi = final_strategy[7],
                        initial_max_streams_uni = final_strategy[8],
                        #initial_source_connection_id = final_strategy[9],
                        max_ack_delay = final_strategy[9],
                        max_datagram_frame_size = final_strategy[10],
                        quantum_readiness = final_strategy[11],
                        stateless_reset_token = final_strategy[12],
                        version_information = final_strategy[13]
                        )
            )

        
        #print(st.one_of(built_strategies))

        return st.one_of(built_strategies)

    def build_ack_strategy(self, ack_frame:QuicAck) -> st.SearchStrategy:
        """
        largest_acknowledged:int=None
        ack_delay:int=None
        ack_range_count:int=None
        ack_first_ack_range:int=None
        ack_ranges:List[Tuple[int,int]] = field(default_factory=list) # [gap, ack_range]
        """

        # variable-length integer
        ack_largest_acknowledged_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**62+1),
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
            st.integers(min_value=0, max_value=2**62+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # tuple of variable-length integers
        ack_ranges_field_strategy = st.one_of(
            st.lists( 
                st.tuples( 
                    st.integers(min_value=0,max_value=255), 
                    st.integers(min_value=0,max_value=2**62+1) ) ),
            st.sampled_from( [ (0, 5), (16, 5), (997, 5), (LARGEST_VARINT_LEN8, 5), (None, 5), (LARGEST_VARINT_LEN2, 5),
                               (5, 0), (5, 16), (5, 997), (5, LARGEST_VARINT_LEN8), (5, None), (5, LARGEST_VARINT_LEN2)] ),
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
        
        inter_field_strategies = self.build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


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

        
        #print(st.one_of(built_strategies))

        return st.one_of(built_strategies)
    
    def build_nci_strategy(self, nci_frame:QuicNewConnectionId) -> st.SearchStrategy:
        """
        sequence_number:int = None
        retire_prior_to:int = None
        length:int = None
        connection_id:bytes = None
        stateless_reset_token:bytes = None
        """

        # variable-length integer
        sequence_number_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**62+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        retire_prior_to_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**62+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # 8-bit unsigned integer
        length_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**8+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # connection ID of the specified length
        connection_id_field_strategy = st.one_of(
            st.binary(min_size=0, max_size=2**8+1),
            st.sampled_from( [0x00000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 
                              0x0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f, 0x0000000000000000FF00000000000000] )
        )

        # 128-bit (16 byte) value
        stateless_reset_token_strategy = st.one_of(
            st.binary(min_size=0, max_size=20),
            st.sampled_from( [0x00000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 
                              0x0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f, 0x0000000000000000FF00000000000000] )
        )
        
        
        default_field_strategies = [
            st.just(nci_frame.sequence_number), 
            st.just(nci_frame.retire_prior_to), 
            st.just(nci_frame.length), 
            st.just(nci_frame.connection_id), 
            st.just(nci_frame.stateless_reset_token)
        ]

        modifying_field_strategies = [
            sequence_number_field_strategy,
            retire_prior_to_field_strategy,
            length_field_strategy,
            connection_id_field_strategy,
            stateless_reset_token_strategy
        ]
        
        inter_field_strategies = self.build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(QuicNewConnectionId, 
                          final_strategy[0],
                          final_strategy[1],
                          final_strategy[2],
                          final_strategy[3],
                          final_strategy[4] )
            )

        
        #print(st.one_of(built_strategies))

        return st.one_of(built_strategies)

    def build_stream_strategy(self, stream_frame:QuicStream) -> st.SearchStrategy:
        """
        stream_id:int = None
        fin_bit:bool = None
        offset:int = None
        h3_frame:Union[H3Settings, H3Headers, H3Data, H3PriorityUpdate, QpackEncoder, QpackDecoder] = None
        """

        # variable-length integer
        stream_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**31+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        fin_bit_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        offset_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=LARGEST_VARINT_LEN8), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        h3_frame_strategy = None
        if type(stream_frame.h3_frame) == H3Settings:
            h3_frame_strategy = self.build_h3_settings_strategy(stream_frame.h3_frame)
        elif type(stream_frame.h3_frame) == H3PriorityUpdate:
            h3_frame_strategy = self.build_h3_priority_update_strategy(stream_frame.h3_frame)

        # TODO: build strategy for each properly
        elif type(stream_frame.h3_frame) == H3Headers:
            h3_frame_strategy = st.builds(H3Headers, st.binary())
        elif type(stream_frame.h3_frame) == H3Data:
            h3_frame_strategy = st.builds(H3Data, st.binary())
        elif type(stream_frame.h3_frame) == QpackEncoder:
            h3_frame_strategy = st.builds(QpackEncoder, st.binary())
        elif type(stream_frame.h3_frame) == QpackDecoder:
            h3_frame_strategy = st.builds(QpackDecoder, st.binary())
        
        
        
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
        
        inter_field_strategies = self.build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


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
    
    def build_h3_settings_strategy(self, settings_frame:H3Settings) -> st.SearchStrategy:
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
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        max_field_section_size_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**32+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        blocked_streams_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**32+1), 
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        h3_datagram_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**15+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
        )

        # variable-length integer
        webtransport_strategy = st.one_of(
            st.integers(0, 100),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
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
        
        inter_field_strategies = self.build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


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
                                                      
    def build_h3_priority_update_strategy(self, priority_update_frame:H3PriorityUpdate) -> st.SearchStrategy:
        """
        element_id:int = None
        field_value:str = None
        """

        # variable-length integer
        element_id_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**31+1),
            st.sampled_from(SAMPLE_VALUES_FOR_VARINT_VALUES)
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
        
        inter_field_strategies = self.build_inter_field_strategies(default_field_strategies, modifying_field_strategies)


        built_strategies = []
        for final_strategy in inter_field_strategies:
            built_strategies.append(
                st.builds(H3PriorityUpdate, 
                          final_strategy[0],
                          final_strategy[1] )
            )

        
        #print(st.one_of(built_strategies))

        return st.one_of(built_strategies)
    
    def build_inter_field_strategies(self, default_field_strategies:List[st.SearchStrategy], modifying_field_strategies:List[st.SearchStrategy]) -> List[List[st.SearchStrategy]]:
       
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
    
    def extract_fuzzed_object_str_from_strategy(self, strategy:st.SearchStrategy) -> str:
        
        fuzzed_object_str = ""

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            example = strategy.example()
            if type(example) == QuicTransportParameters:
                fuzzed_object_str = "Transport Params"
            elif type(example) == QuicAck:
                fuzzed_object_str = "ACK"
            elif type(example) == QuicNewConnectionId:
                fuzzed_object_str = "NCI"
            elif type(example) == QuicStream:
                h3FrameName = ""
                if type(example.h3_frame) == H3Settings:
                    h3FrameName = H3_FRAME_ABBREVIATIONS["SETTINGS"]
                elif type(example.h3_frame) == H3Headers:
                    h3FrameName = H3_FRAME_ABBREVIATIONS["HEADERS"]
                elif type(example.h3_frame) == H3Data:
                    h3FrameName = H3_FRAME_ABBREVIATIONS["DATA"]
                elif type(example.h3_frame) == H3PriorityUpdate:
                    h3FrameName = H3_FRAME_ABBREVIATIONS["PRIORITY_UPDATE"]
                elif type(example.h3_frame) == QpackEncoder:
                    h3FrameName = "Enc"
                elif type(example.h3_frame) == QpackDecoder:
                    h3FrameName = "Dec"
                fuzzed_object_str = "Stream[{}]".format(h3FrameName)

        return fuzzed_object_str


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
        "--parallel-requests",
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
        default=30,
        help="The length of attack (in sec.) (default 30)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    
    


    args = parser.parse_args()

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        original_version=1
    )

    configuration.verify_mode = ssl.CERT_NONE

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
        verbose = args.verbose)
    
    
    fuzzer.set_up_graph(args.state_machine, args.pcap)

    fuzzer.fuzz()
    

