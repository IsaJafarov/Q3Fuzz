# -*- coding: UTF-8 -*-
# Modules for HTTP3
import pyshark
import re
import traceback
from typing import List, Union
from aioquic.buffer import Buffer
from aioquic.quic.packet import QuicFrameType, QuicPacketType
import pyshark.packet
import pyshark.packet.layers
from pyshark.packet.packet import Packet
from pyshark.packet.layers.xml_layer import XmlLayer
from dissector import *

# IETF specification
QUIC_LONGPACKETTYPE = ['INIT', '0-RTT', 'HANDSHAKE', 'RETRY']


QUIC_FRAME_ABBREVIATIONS = {
    # by frame byte
    0x00: "PAD", # Padding
    0x01: "PING",
    0x02: "ACK",
    0x03: "ACK",
    0x04: "RS", # Reset Stream
    0x05: "SS", # Stop Sending
    0x06: "CRY", # Crypto
    0x07: "NT", # New Tokwn
    0x08: "ST",
    0x09: "ST",
    0x0A: "ST",
    0x0B: "ST",
    0x0C: "ST",
    0x0D: "ST",
    0x0E: "ST",
    0x0F: "ST",
    0x10: "MD", # Max Data
    0x11: "MSD", # Max Stream Data
    0x12: "MS", # Max Streams
    0x13: "MS", # Max Streams
    0x14: "DB", # Data Blocked
    0x15: "SDB", # STREAM_DATA_BLOCKED
    0x16: "SB", # STREAMS_BLOCKED
    0x17: "SB", # STREAMS_BLOCKED
    0x18: "NCI", # NEW_CONNECTION_ID
    0x19: "RCI", # RETIRE_CONNECTION_ID
    0x1A: "PC", # PATH_CHALLENGE    
    0x1B: "PR", # PATH_RESPONSE
    0x1C: "CC", # CONNECTION_CLOSE
    0x1D: "CC", # CONNECTION_CLOSE
    0x1E: "HD", # HANDSHAKE_DONE
    0x1F: "IA", # IMMEDIATE_ACK
    0x30: "DT", # DATAGRAM
    0x31: "DT", # DATAGRAM
    0xaf: "ACKF", # ACK_FREQUENCY -  draft-ietf-quic-ack-frequency-10
    

    "PADDING": "PAD",
    "PING": "PING",
    "ACK": "ACK",
    "RESET_STREAM": "RS",
    "STOP_SENDING": "SS",
    "CRYPTO": "CRY",
    "NEW_TOKEN": "NT",
    "STREAM": "ST",
    "MAX_DATA": "MD",
    "MAX_STREAM_DATA": "MSD",
    "MAX_STREAMS": "MS",
    "DATA_BLOCKED": "DB",
    "STREAM_DATA_BLOCKED": "SDB",
    "STREAMS_BLOCKED": "SB",
    "NEW_CONNECTION_ID": "NCI",
    "RETIRE_CONNECTION_ID": "RCI",
    "PATH_CHALLENGE": "PC",
    "PATH_RESPONSE": "PR",
    "CONNECTION_CLOSE": "CC",
    "HANDSHAKE_DONE": "HD",
    "IMMEDIATE_ACK": "IA",
    "DATAGRAM": "DT", # DATAGRAM
    "ACK_FREQUENCY": "ACKF"
}


H3_FRAME_ABBREVIATIONS = {
    # by frame bytes
    0x00: "DA", # Data
    0x01: "HE", # Headers
    0x02: "RE", # Reserved
    0x03: "CP", # Cancel Push
    0x04: "SE", # Settings
    0x05: "PP", # Push Promise
    0x06: "RE", # Reserved
    0x07: "GO", # Goaway
    0x08: "RE", # Reserved
    0x09: "RE", # Reserved
    0x0a: "UN", # Unassigned
    0x0b: "UN", # Unassigned
    0x0c: "OR", # Origin
    0x0d: "MPI", # Max Push Id
    0x0e: "UN", # Unassigned
    0x4d: "MD", # Metadata
    0xf0700: "PU", # Priority Update - RFC 9218
    0xf0701: "PU", # Priority Update

    # by frame name
    "DATA": "DA",
    "HEADERS": "HE",
    "CANCEL_PUSH": "CP",
    "SETTINGS": "SE",
    "PUSH_PROMISE": "PP",
    "GOAWAY": "GO",
    "MAX_PUSH_ID": "MPI",
    "RESERVED": "RE",
    "PRIORITY_UPDATE": "PU"
}


############# GENERAL #############
class Tee(object):
    def __init__(self, *files):
        self.files = files

    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()  # If you want the output to be visible immediately

    def flush(self):
        for f in self.files:
            f.flush()


def cmp(a, b):
    return (a > b) - (a < b)


def compare_ordered_dict(dict1:dict, dict2:dict) -> bool:
    for i, j in zip(dict1.items(), dict2.items()):
        if cmp(i, j) != 0:
            return False
    # print("compare_ordered_dict(): Two dict is same")
    # print(dict1)
    # print("---")
    # print(dict2)
    return True

def get_frames_of_layer(layer:XmlLayer) -> List[str]:
    frame_names = []
    for field_line in layer._get_all_field_lines():
        if ':' in field_line:
            field_name, field_value = field_line.split(':', 1)

            if (layer.layer_name == 'quic' and field_name.strip() == 'Frame Type') :
                field_value = field_value.split()[0]
                frame_names.append( QUIC_FRAME_ABBREVIATIONS[ field_value.upper() ] )

            if (layer.layer_name == 'http3' and field_name.strip() == 'Type') :
                field_value = field_value.split()[0]
                frame_names.append( H3_FRAME_ABBREVIATIONS[ field_value.upper() ] )
    
    return frame_names


def h3msg_from_pcap(file_path:str, client_only:bool=False) -> List[Packet]: # for HTTP3
    """
    Extract all QUIC messages from pcapfile and return an array of http3 messages
    Now we only consider EXPORTED_PDU layer exported by wireshark instead of preserving data of UDP layer.

    Args:
        f (str): pcap file with QUIC or HTTP/3 messages
        client_only (bool, default=False): flag for extracting messages sent by client side. 
    Returns:
        quic_packet_list (FileCapture): QUIC or HTTP/3 messages that are seen in the pcap file.
    """
    client_ip = None   # Get ip to gather client message 
    raw_cap = pyshark.FileCapture(file_path)
    quic_cap = pyshark.FileCapture(file_path, display_filter='quic')
    quic_packet_list = []
    quic_cap_cnt = 0

    # print("============= List of QUIC packets in pcap =============")
    for packet in quic_cap:
        mark_client = " "
        quic_cap_cnt += 1
        if client_ip == None and packet.quic.header_form == "1" and packet.quic.long_packet_type == "0": # The first INITIAL packet type of QUIC
            if 'exported_pdu' in packet: 
                client_ip = packet.exported_pdu.ip_src
        if client_only:
            if 'exported_pdu' in packet and packet.exported_pdu.ip_src == client_ip:
                quic_packet_list.append(packet)
                mark_client = "*"
        else:
            quic_packet_list.append(packet)

    return quic_packet_list


def h3msg_to_str(h3msg:Union[list, Packet]) -> str:
    """
    Convert a QUIC or HTTP3 message in a human-readable format.
    args:
        h3msg: A QUIC / HTTP3 packet of type 'pyshark.packet.packet.Packet'
    return:
        msginfo: a string of a Q / H3 message with multiple layers and frames
    """
    
    msginfo = ''

    if type(h3msg) is list: # for moving messages
        for h3msg_sub in h3msg:
            msginfo += h3msg_to_str(h3msg_sub) + " => "
        if msginfo != '':
            msginfo = msginfo.rstrip(" => ")
    else:
        quic_layer = h3msg.quic
        
        if 'header_form' in quic_layer.field_names and quic_layer.header_form == "1":  # Long header type
            if msginfo:
                msginfo += ','
            msginfo += QUIC_LONGPACKETTYPE[int(quic_layer.long_packet_type)]
            return msginfo

        msg_dissector = MSGDissector()
        msg_dissector.dissect_msg(h3msg)    

        for quic_frame in msg_dissector.quic_frames:
            if type(quic_frame) == QuicAck:
                msginfo += QUIC_FRAME_ABBREVIATIONS['ACK']
            elif type(quic_frame) == QuicNewConnectionId:
                msginfo += QUIC_FRAME_ABBREVIATIONS['NEW_CONNECTION_ID']
            elif type(quic_frame) == QuicStream:
                h3_frame_str = ''

                if quic_frame is None:
                    h3_frame_str = "\u2298"
                elif type(quic_frame.h3_frame) == H3Settings:
                    h3_frame_str = H3_FRAME_ABBREVIATIONS['SETTINGS']
                elif type(quic_frame.h3_frame) == H3Headers:
                    h3_frame_str = H3_FRAME_ABBREVIATIONS['HEADERS']
                elif type(quic_frame.h3_frame) == H3Data:
                    h3_frame_str = H3_FRAME_ABBREVIATIONS['DATA'] 
                elif type(quic_frame.h3_frame) == H3PriorityUpdate:
                    h3_frame_str = H3_FRAME_ABBREVIATIONS['PRIORITY_UPDATE']
                elif type(quic_frame.h3_frame) == QpackEncoder:
                    h3_frame_str = 'Enc'
                elif type(quic_frame.h3_frame) == QpackDecoder:
                    h3_frame_str = 'Dec'
                
                else:
                    raise Exception("Unknown HTTP/3 frame")
            
                msginfo += "{}({})[{}]".format(QUIC_FRAME_ABBREVIATIONS['STREAM'], quic_frame.stream_id, h3_frame_str)
            else:
                raise Exception("Unknown QUIC frame")
            msginfo += ","

    return beautify_message_string(msginfo,True) 


def beautify_message_string(message:str, sent_by_client:bool) -> str:
    
    message = message\
        .replace(H3_FRAME_ABBREVIATIONS["RESERVED"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["PADDING"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["NEW_TOKEN"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["PING"]+",", "")

    if not sent_by_client:
        message = message\
        .replace(QUIC_FRAME_ABBREVIATIONS["NEW_CONNECTION_ID"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["MAX_STREAMS"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["MAX_STREAM_DATA"]+",", "")\

    message = message\
        .rstrip(",")    
    

    return message
