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


PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]


class Fuzzer():
    def __init__(self, quic_conf:QuicConfiguration, hostname:str, secrets_log:str):
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

               
                h3client = HttpClient(self.quic_conf, self.hostname, self.secrets_log)
                self.reach_source_state(h3client, moving_msgs_packet_nums)
                
                edge_to_fuzz = self.graph.get_edge_data(pre, node)
                response = edge_to_fuzz['trigger'].split("=>")[1].strip()
                triggering_msg_packet_num = int(edge_to_fuzz['packet_number'])
                triggering_msg = self.find_message_by_packet_number(triggering_msg_packet_num)
                self.fuzz_selected_state_transition(h3client, triggering_msg, response)


    
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


    
    def fuzz_selected_state_transition(self, h3client:HttpClient, triggering_msg:Packet, expected_response:str):
        
        #modified_triggering_msg = self.fuzz(triggering_msg)
        

        #builder = h3client.crafter.copy_msg(triggering_msg, h3client.get_builder(Epoch.ONE_RTT))

        #h3client.crafter.dissect_msg(triggering_msg)

        builder = h3client.get_builder(Epoch.ONE_RTT)
        h3client.crafter.copy_msg(triggering_msg, builder)


    
    def find_message_by_packet_number(self, packet_number:int):
        for msg in self.traffic_messages:
            #print(msg.quic.field_names)
            if int(msg.quic.packet_number) == packet_number:
                #print(msg.quic)
                return msg
        raise Exception("Packet with packet_number {} does not exist!".format(packet_number)) 
            
    def test_dissection(self):
        
        for packet in self.traffic_messages:
            print(packet)
            print()
            h3client = HttpClient(self.quic_conf, self.hostname, self.secrets_log)
            h3client.crafter.copy_msg(packet, None)


    def send_packets_in_custom_order(self):
        h3client = HttpClient(self.quic_conf, self.hostname, self.secrets_log)
        for i in [8,11]:
            h3client.replay_msg( self.find_message_by_packet_number(i) )
        pass

if __name__ == "__main__":
    install()

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
        #congestion_control_algorithm=args.congestion_control_algorithm,
        #max_datagram_size=args.max_datagram_size,
        original_version=1
    )

    configuration.verify_mode = ssl.CERT_NONE
    if args.secrets_log:
        keylog_file = os.path.abspath(args.secrets_log) 
        configuration.secrets_log_file = open(keylog_file, "a")



    

    

    fuzzer = Fuzzer(configuration, urlparse(args.url).netloc, args.secrets_log)
    
    
    fuzzer.set_up_graph(args.state_machine, args.pcap)
    fuzzer.test_dissection()
    sys.exit()
    fuzzer.fuzz()






