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

from hypothesis import example, given, note, reproduce_failure, strategies as st
from hypothesis import settings, Verbosity



PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]

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
        self.ack_strategy = None
        
    
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
                print("Fuzzing ACK")
                strategy = self.build_ack_strategy(quic_frame)
                self.fuzz_triggering_msg(moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames, expected_response, strategy)
            
            elif type(quic_frame) == QuicNewConnectionId:
                print("Fuzzing NCI")
                strategy = self.build_nci_strategy(quic_frame)
                self.fuzz_triggering_msg(moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames, expected_response, strategy)

            elif type(quic_frame) == QuicStream:
                print("Fuzzing STREAM")
                strategy = self.build_stream_strategy(quic_frame)
                self.fuzz_triggering_msg(moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames, expected_response, strategy)


        
    # this might work for all frames, not just ack
    def fuzz_triggering_msg(self, moving_msgs_packet_nums:List[int], preceding_quic_frames, succeeding_quic_frames, expected_response, strategy:st.SearchStrategy):
        
        i=0
        @given( strategy )
        @settings(deadline=2000, verbosity=Verbosity.normal, print_blob=True, max_examples=1000)
        #@reproduce_failure('6.113.0', b'AAAAAAAAAAAAAQ==')
        def fuzz_triggering_msg_innner(moving_msgs_packet_nums:List[int], preceding_quic_frames, succeeding_quic_frames, expected_response, quic_frame):
            #nonlocal i
            print(".", end="")
            sys.stdout.flush()
            
            #print("{}. {}".format(i, quic_frame))
            #i+=1

            
            
            
            h3client = HttpClient(self.quic_conf, self.hostname, self.secrets_log)

            #print("Reaching the source state")
            self.reach_source_state(h3client, moving_msgs_packet_nums)

            #print("Sending the triggering message")
            try:
                response = h3client.send_frames( preceding_quic_frames + [quic_frame] + succeeding_quic_frames )
                note("Actual Response: {}".format(response))
                h3client.close_connection()

                fuzzer.check_server_availability()

                #if response != expected_response: raise Exception("Aye")
            
            except ValueError as ve :
                #print( str(ve) )
                pass
            except AttributeError as ve :
                #print( str(ve) )
                pass
            except OverflowError as ve :
                #print( str(ve) )
                pass
            except TypeError as ve :
                #print( str(ve) )
                pass

            
            
                        
        

        fuzz_triggering_msg_innner(moving_msgs_packet_nums, preceding_quic_frames, succeeding_quic_frames, expected_response)
        
        #
        #self.reach_source_state(h3client, moving_msgs_packet_nums)
        #h3client.send_frames()

        
    def build_ack_strategy(self, ack_frame:QuicAck) -> st.SearchStrategy:
        """
        largest_acknowledged:int=None
        ack_delay:int=None
        ack_range_count:int=None
        ack_first_ack_range:int=None
        ack_ranges:List[Tuple[int,int]] = field(default_factory=list) # [gap, ack_range]
        """

        ack_largest_acknowledged_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**62+1),
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )


        ack_delay_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**14+1), 
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        ack_range_count_field_strategy = st.one_of(
            st.integers(min_value=0, max_value=2**8+1), 
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        ack_first_ack_range_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**62+1),
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        ack_ranges_field_strategy = st.one_of(
            st.lists( 
                st.tuples( 
                    st.integers(min_value=-1,max_value=255), 
                    st.integers(min_value=-1,max_value=2**62+1) ) ),
            st.sampled_from( [ (-10000, 5), (-1000, 5), (-1, 5), (-32768, 5), (0, 5), (16, 5), (997, 5), ('a', 5), ('!', 5), (10**20, 5), (None, 5),
                               (5, -10000), (5, -1000), (5, -1), (5, -32768), (5, 0), (5, 16), (5, 997), (5, 'a'), (5, '!'), (5, 10**20), (5, None)] ),
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

        sequence_number_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**62+1),
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )


        retire_prior_to_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**62+1), 
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        length_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**8+1), 
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        connection_id_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**8+1),
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        stateless_reset_token_strategy = st.one_of(
            st.binary(min_size=0, max_size=20),
            st.sampled_from( [0x00000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 
                              0x0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f, 0x0000000000000000FF00000000000000] ),
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

        stream_id_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**31+1),
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )


        fin_bit_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2), 
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        offset_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**64+1), 
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
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

        
        #print(st.one_of(built_strategies))

        return st.one_of(built_strategies)
    

    def build_h3_settings_strategy(self, settings_frame:H3Settings) -> st.SearchStrategy:
        """
        max_table_capacity:int = None
        max_field_section_size:int = None
        blocked_streams:int = None
        h3_datagram:int = None
        webtransport:int = None
        """

        max_table_capacity_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**32+1),
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )


        max_field_section_size_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**32+1), 
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        blocked_streams_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**32+1), 
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        h3_datagram_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**15+1),
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )

        webtransport_strategy = st.one_of(
            st.integers(-1, 100),
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
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

        
        #print(st.one_of(built_strategies))

        return st.one_of(built_strategies)
                                                      
    def build_h3_priority_update_strategy(self, priority_update_frame:H3PriorityUpdate) -> st.SearchStrategy:
        """
        element_id:int = None
        field_value:str = None
        """

        element_id_field_strategy = st.one_of(
            st.integers(min_value=-1, max_value=2**31+1),
            st.sampled_from([-10000, -1000, -1, -32768, 0, 16, 997, 'a', '!', 10**20, None ])
        )


        field_value_field_strategy = st.one_of(
            st.text(min_size=0, max_size=10), 
            st.sampled_from(["", "000000", "a"*20, "a"*200, "\u2298", None ])
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
    





