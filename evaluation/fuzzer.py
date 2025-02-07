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

from hypothesis import example, given, note, reproduce_failure, strategies as st
from hypothesis import settings, Verbosity



PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]

# largest values in varint encoding. https://www.rfc-editor.org/rfc/rfc9000.html#section-16
LARGEST_VARINT_LEN1 = 0x3F # length = 1. 63 in hex
LARGEST_VARINT_LEN2 = 0x3FFF # length = 2. 16383 in hex
LARGEST_VARINT_LEN4 = 0x3FFFFFFF # length = 4. 1073741823 in hex
LARGEST_VARINT_LEN8 = 0x3FFFFFFFFFFFFFFF # length = 8. 4611686018427387903 in hex
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
    def __init__(self, quic_conf:QuicConfiguration, hostname:str, secrets_log:str):
        self.test_num = 0
        self.quic_conf:QuicConfiguration = quic_conf
        self.hostname:str = hostname
        self.secrets_log:str = secrets_log
        self.graph:nx.DiGraph = nx.DiGraph()
        self.traffic_messages:list[Packet] = []
        
    
    def set_up_graph(self, sm_file_path:str, traffic_file_path:str):
        with open(sm_file_path, 'r') as f:
            data = json.load(f)

        for t in data['transitions']:
            source = t['source']
            destination = t['dest']
            trigger = t['trigger'].strip()
            packet_number = t['conditions'][0].split(":")[1]
            self.graph.add_edge(source, destination, trigger=trigger, packet_number=packet_number)

        self.traffic_messages = util.h3msg_from_pcap(traffic_file_path, True)


    def fuzz(self):
        
        transport_params_strategy = self.build_transport_params_strategy()
        self.fuzz_transport_params(transport_params_strategy)
        sys.exit()

        for node in self.graph.nodes():

            if node=="Init" or node=="Finish":
                continue
            
            for pre in self.graph.predecessors(node):
                if pre == node: 
                    continue
                #print("----------------------------")
                print("\n{} -> {}".format(pre, node))
                
                nodes_in_the_path = nx.shortest_path(self.graph, "Init", pre)

                moving_msgs_packet_nums = []
                for i in range(len(nodes_in_the_path)-1):
                    source_node = nodes_in_the_path[i]
                    destination_node = nodes_in_the_path[i+1]
                    edge = self.graph.get_edge_data(source_node, destination_node)
                    trigger = edge['trigger']
                    packet_number = int(edge['packet_number'])

                    moving_msgs_packet_nums.append( packet_number )

                edge_to_fuzz = self.graph.get_edge_data(pre, node)
                response = edge_to_fuzz['trigger'].split("=>")[1].strip()
                triggering_msg_packet_num = int(edge_to_fuzz['packet_number'])
                triggering_msg = self.find_message_by_packet_number(triggering_msg_packet_num)

                self.fuzz_state_transition(moving_msgs_packet_nums, triggering_msg, response)
    
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


    def fuzz_state_transition(self, moving_msgs_packet_nums:List[int], triggering_msg: Packet, expected_response:str):
        
        msg_dissector = MSGDissector()
        quic_frames = msg_dissector.dissect_msg(triggering_msg)

        #print("triggering_msg: {}".format(util.h3msg_to_str(triggering_msg)))
        for i in range(len(quic_frames)):
            quic_frame = quic_frames[i]

            preceding_quic_frames = quic_frames[:i]
            succeeding_quic_frames = quic_frames[i+1:]

            if type(quic_frame) == QuicAck:
                print("Fuzzing ACK at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
                strategy = self.build_ack_strategy(quic_frame)
                self.fuzz_triggering_msg(moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames, expected_response, strategy)
            
            elif type(quic_frame) == QuicNewConnectionId:
                print("Fuzzing NCI at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
                strategy = self.build_nci_strategy(quic_frame)
                self.fuzz_triggering_msg(moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames, expected_response, strategy)

            elif type(quic_frame) == QuicStream:
                print("Fuzzing STREAM at {}".format( datetime.now().strftime("%Y-%m-%d %H:%M:%S") ) )
                strategy = self.build_stream_strategy(quic_frame)
                self.fuzz_triggering_msg(moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames, expected_response, strategy)


    
    def fuzz_triggering_msg(self, moving_msgs_packet_nums:List[int], preceding_quic_frames, succeeding_quic_frames, expected_response, strategy:st.SearchStrategy) -> None:
        
        i=0
        @given( strategy )
        @settings(deadline=None, verbosity=Verbosity.normal, print_blob=True, max_examples=100)
        #@reproduce_failure('6.113.0', b'AAAAAAAAAAAAAQ==')
        def fuzz_triggering_msg_innner(moving_msgs_packet_nums:List[int], preceding_quic_frames, succeeding_quic_frames, expected_response, quic_frame):
            nonlocal i
            #print(".", end="")
            sys.stdout.flush()
            
            print("{}. {}".format(i, quic_frame))
            i+=1

            
            h3client = HttpClient(self.quic_conf, self.hostname, self.secrets_log)

            #print("Reaching the source state")
            self.reach_source_state(h3client, moving_msgs_packet_nums)

            #print("Sending the triggering message")

            response = h3client.send_frames( preceding_quic_frames + [quic_frame] + succeeding_quic_frames )
            note("Actual Response: {}".format(response))
            #h3client.close_connection()

            fuzzer.check_server_availability()

            #if response != expected_response: raise Exception("Aye")
            
            
                

            
        
        fuzz_triggering_msg_innner(moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames, expected_response)
        print()


        
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
            st.sampled_from( [ (0, 5), (16, 5), (997, 5), (LARGEST_NUMBER_IN_VARINT_ENCODING, 5), (None, 5),
                               (5, 0), (5, 16), (5, 997), (5, LARGEST_NUMBER_IN_VARINT_ENCODING), (5, None)] ),
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
        elif type(stream_frame.h3_frame) in [H3Headers, H3Data, QpackEncoder, QpackDecoder]:
            h3_frame_strategy = st.just(stream_frame.h3_frame) # TODO: build strategy for each
        
        
        
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
                                                      
    def check_server_availability(self) -> None:
        """
        Check if the web server is available by initiating a connection with a new client.
        The server is up, if it responds with the HANDSHAKE_DONE frame
        """

        h3client = HttpClient(self.quic_conf, self.hostname, self.secrets_log)

        h3client.connect()
        res1 = h3client.read_from_buffer()  # Receive any response from the server

        # Complete the connection by sending handshake completion messages
        h3client.complete_connection()
        res2 = received_after_init = h3client.read_from_buffer()

        if QUIC_FRAME_ABBREVIATIONS['HANDSHAKE_DONE'] not in res2:
            raise Exception("Server is down")
            
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
            version_information: Optional[QuicVersionInformation] = None TODO
            max_datagram_frame_size: Optional[int] = None
            quantum_readiness: Optional[bytes] = None                         
        """

        """
        QuicTransportParameters(
            ack_delay_exponent=self._local_ack_delay_exponent,
            active_connection_id_limit=self._local_active_connection_id_limit,
            max_idle_timeout=int(self._configuration.idle_timeout * 1000),
            initial_max_data=self._local_max_data.value,
            initial_max_stream_data_bidi_local=self._local_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote=self._local_max_stream_data_bidi_remote,
            initial_max_stream_data_uni=self._local_max_stream_data_uni,
            initial_max_streams_bidi=self._local_max_streams_bidi.value,
            initial_max_streams_uni=self._local_max_streams_uni.value,
            initial_source_connection_id=self._local_initial_source_connection_id,
            max_ack_delay=25,
            max_datagram_frame_size=self._configuration.max_datagram_frame_size,
            quantum_readiness=(
                b"Q" * SMALLEST_MAX_DATAGRAM_SIZE
                if self._configuration.quantum_readiness_test
                else None
            ),
            stateless_reset_token=self._host_cids[0].stateless_reset_token,
            version_information=QuicVersionInformation(
                chosen_version=self._version,
                available_versions=self._configuration.supported_versions,
            ),
        )
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
        

        default_quic_conn = QuicConnection(configuration=self.quic_conf)
        
        default_field_strategies = [
            st.just(3),  # ack_delay_exponent
            st.just(8), # active_connection_id_limit
            st.just(int(default_quic_conn._configuration.idle_timeout * 1000)), # max_idle_timeout
            st.just(default_quic_conn.configuration.max_data), # initial_max_data
            st.just(default_quic_conn.configuration.max_stream_data ), # initial_max_stream_data_bidi_local
            st.just(default_quic_conn.configuration.max_stream_data), # initial_max_stream_data_bidi_remote
            st.just(default_quic_conn.configuration.max_stream_data), # initial_max_stream_data_uni
            st.just(128), # initial_max_streams_bidi
            st.just(128), # initial_max_streams_uni
            #st.just(default_quic_conn._host_cids[0].cid), # initial_source_connection_id
            st.just(25), # max_ack_delay
            st.just(default_quic_conn._configuration.max_datagram_frame_size), # max_datagram_frame_size
            st.just(( b"Q" * SMALLEST_MAX_DATAGRAM_SIZE if default_quic_conn._configuration.quantum_readiness_test else None)), # quantum_readiness
            st.just(default_quic_conn._host_cids[0].stateless_reset_token,), # stateless_reset_token
            st.just(QuicVersionInformation( chosen_version=default_quic_conn.configuration.original_version, available_versions=default_quic_conn._configuration.supported_versions)), # version_information            
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

        
    def fuzz_transport_params(self, strategy:st.SearchStrategy) -> None:
        
        i=0
        @given( strategy )
        @settings(deadline=None, verbosity=Verbosity.normal, print_blob=True, max_examples=100)
        #@reproduce_failure('6.113.0', b'AAAAAAAAAAAAAQ==')
        def fuzz_transport_params_inner(transport_params:QuicTransportParameters):
            nonlocal i
            #print(".", end="")
            #sys.stdout.flush()
            print("------------------------------------------------------")
            print("{}. {}".format(i, transport_params))
            i+=1

            
            h3client = HttpClient(self.quic_conf, self.hostname, self.secrets_log)

            # we need to keeep the connection id as is, otherwise the client doesn't know which received packets are for this connection
            transport_params.initial_source_connection_id = h3client.connection._host_cids[0].cid

            h3client.connect(transport_params)
            asas = h3client.read_from_buffer()  # Receive any response from the server
            print(asas)

            # Complete the connection by sending handshake completion messages
            h3client.complete_connection()
            asas = received_after_init = h3client.read_from_buffer()
            print(asas)
            
            
            #note("Actual Response: {}".format(response))
            #h3client.close_connection()

            fuzzer.check_server_availability()
            
        fuzz_transport_params_inner()
        print()



    def build_inter_field_strategies(self, default_field_strategies:List[st.SearchStrategy], modifying_field_strategies:List[st.SearchStrategy]) -> List[List[st.SearchStrategy]]:
       
        inter_field_strategies:List[List[st.SearchStrategy]] = []

        # Modify a single field at a time, while keeping the other fields as is
        for i in range(len(modifying_field_strategies)):
            # copy the list, so that the change will not reflect on the original list
            default_values_strategy_copy = default_field_strategies.copy() 

            # replace default value of a single field, with corresponding modifying field
            default_values_strategy_copy[i] = modifying_field_strategies[i]

            # add it to the inter-field strategies
            inter_field_strategies.append( default_values_strategy_copy )


        # Additionally, modify all fileds at the same time
        inter_field_strategies.append( modifying_field_strategies )

        #print(inter_field_strategies)

        return inter_field_strategies
    



    def find_message_by_packet_number(self, packet_number:int) -> Packet:
        for msg in self.traffic_messages:
            #print(msg.quic.field_names)
            if int(msg.quic.packet_number) == packet_number:
                #print(msg.quic)
                return msg
        raise Exception("Packet with packet_number {} does not exist!".format(packet_number)) 
            

    def isa(self):
        packet = self.find_message_by_packet_number(9)
        msgDissector = MSGDissector()
        frames = msgDissector.dissect_msg(packet)

        print(frames)

        #msgCrafter = MSGCrafter()
        #msgCrafter.craft_msg_from_frames(frames, )

        h3client = HttpClient(self.quic_conf, self.hostname, self.secrets_log)
        print( h3client.quic_conf )
        return
        h3client.connect()
        h3client.read_from_buffer()  # Receive any response from the server

        # Complete the connection by sending handshake completion messages
        h3client.complete_connection()
        received_after_init = h3client.read_from_buffer()

        h3client.send_frames(frames)

    



if __name__ == "__main__":
    #install()

    defaults = QuicConfiguration(is_client=True)
    keylog_file = None

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
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )



    args = parser.parse_args()

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        original_version=1
    )

    configuration.verify_mode = ssl.CERT_NONE
    if args.secrets_log:
        keylog_file = os.path.abspath(args.secrets_log) 
        configuration.secrets_log_file = open(keylog_file, "a")




    fuzzer = Fuzzer(configuration, urlparse(args.url).netloc, args.secrets_log)
    
    
    fuzzer.set_up_graph(args.state_machine, args.pcap)

    #fuzzer.hypo("isa")
    #sys.exit()

    fuzzer.fuzz()
    #fuzzer.isa()
    





