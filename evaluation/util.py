# -*- coding: UTF-8 -*-
# Modules for HTTP3
import pyshark
import re
import traceback
from typing import List
from aioquic.buffer import Buffer
from aioquic.quic.packet import QuicFrameType, QuicPacketType
import pyshark.packet
import pyshark.packet.layers
from pyshark.packet.packet import Packet
from pyshark.packet.layers.xml_layer import XmlLayer

# IETF specification
QUIC_LONGPACKETTYPE = ['INIT', '0-RTT', 'HANDSHAKE', 'RETRY']
QUIC_SHORTPACKETTYPE = "1-RTT" # short packet does not have a type. It corresponds to 1-RTT only.
QUIC_FRAMETYPE = ['PADDING', 'PING', 'ACK', 'ACK', 'RESET_STREAM', 'STOP_SENDING', 'CRYPTO', 'NEW_TOKEN', \
             'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', \
             'MAX_DATA', 'MAX_STREAM_DATA', 'MAX_STREAMS', 'MAX_STREAMS', 'DATA_BLOCKED', 'STREAM_DATA_BLOCKED', 'STREAMS_BLOCKED', 'STREAMS_BLOCKED',\
             'NEW_CONNECTION_ID', 'RETIRE_CONNECTION_ID', 'PATH_CHALLENGE', 'PATH_RESPONSE', 'CONNECTION_CLOSE', 'CONNECTION_CLOSE', 'HANDSHAKE_DONE', 'IMMEDIATE_ACK',\
             'DATAGRAM', 'DATAGRAM'] # ~0x21 frames so far

H3_STREAMTYPE = ['CONTROL_STREAM', 'PUSH_STREAM', 'QPACK_ENCODER_STREAM', 'QPACK_DECODER_STREAM']
H3_FRAMETYPE = ['DATA', 'HEADERS', 'RESERVED', 'CANCEL_PUSH', 'SETTINGS', 'PUSH_PROMISE', 'RESERVED', 'GOAWAY',\
                'RESERVED', 'RESERVED', 'UNASSIGNED', 'UNASSIGNED', 'ORIGIN', 'MAX_PUSH_ID'] # ~0x0d frames so far


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
            if (layer.layer_name == 'quic' and field_name.strip() == 'Frame Type') \
                or (layer.layer_name == 'http3' and field_name.strip() == 'Type') :
                frame_names.append( field_value.split()[0] )
    return frame_names

def h3msg_from_pcap(file_path:str, client_only:bool=False) -> List[Packet]: # for HTTP3
    """
    Extract all QUIC messages from pcapfile and return an array of http3 messages
    Now we only consider EXPORTED_PDU layer exported by wireshark instead of preserving data of UDP layer.

    Args:
        f (str): pcap file with QUIC or HTTP/3 messages
        client_only (bool, default=False): flag for extracting messages set by client side. 
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

def extract_quic_stream_frames(layer:XmlLayer) -> List[str]:
    """
    Extract all STREAM frame IDs from a QUIC layer.
    args:
        layer: A QUIC layer object from pyshark.
    return:
        stream_ids: A list of stream IDs from STREAM frames.
    """
    stream_ids = []

    # Iterate through all fields in the QUIC layer
    for frame in layer.frame.all_fields:
        if "STREAM" in frame.showname.upper():  # Check if this field represents a STREAM frame
            # Extract the stream_id directly from the showname
            stream_details = frame.showname
            for part in stream_details.split():
                if part.startswith("id="):
                    stream_id = part.split("=")[1]
                    stream_ids.append(stream_id)
                    break  # Only need the id, stop further parsing for this frame
    return stream_ids

def h3msg_to_str(h3msg:Packet) -> str:
    """
    Convert a QUIC or HTTP3 message in a human-readable format.
    args:
        h3msg: A QUIC / HTTP3 packet of type 'pyshark.packet.packet.Packet'
    return:
        msginfo: a string of a Q / H3 message with multiple layers and frames
    """

    msginfo = ''
    stream_frames = []  # A list to store stream IDs from QUIC STREAM frames

    if type(h3msg) is list:
        for h3msg_sub in h3msg:
            msginfo += h3msg_to_str(h3msg_sub) + " | "
        if msginfo != '':
            msginfo = msginfo.rstrip(" | ")
    else:
        http3_layer_idx = 0  # Index to track HTTP/3 layer processing
        for layer in h3msg.layers:
            if layer.layer_name == 'quic':
                # Handle QUIC Long Header
                if 'header_form' in dir(layer) and layer.header_form == "1":  # Long header type
                    if msginfo:
                        msginfo += ','
                    msginfo += QUIC_LONGPACKETTYPE[int(layer.long_packet_type)]
                    continue  # Skip further processing for long headers

                # Handle Short Header and frames
                if 'header_form' in dir(layer) and layer.header_form == "0":  # Short header type
                    # print(get_frames_of_layer(layer))
                    stream_frames = extract_quic_stream_frames(layer)
                    if len(stream_frames) == 0:
                        # Include non-STREAM frames directly in msginfo
                        for frame_name in get_frames_of_layer(layer):
                            if msginfo:
                                msginfo += ','
                            msginfo += frame_name.upper()

            elif layer.layer_name == "http3":
                # Match HTTP/3 layer to the corresponding QUIC STREAM frame
                if http3_layer_idx < len(stream_frames):
                    stream_id = stream_frames[http3_layer_idx]
                    http3_layer_idx += 1
                else:
                    raise ValueError("HTTP/3 layer count exceeds QUIC STREAM frames.")

                # Extract HTTP/3 frames
                tmp_frames = ''
                for frame_name in get_frames_of_layer(layer):
                    tmp_frames += frame_name.upper() + ","

               

                frame_info = None
                # the layer has HTTP3 frames
                if tmp_frames: 
                    frame_info = tmp_frames[:-1]
                # the layer has non-HTTP3 data (QPACK)
                else:
                    if 'QPACK Encoder' in layer.stream_uni or 'qpack_encoder' in layer.field_names: 
                        frame_info = "Enc" 
                    elif 'QPACK Decoder' in layer.stream_uni: 
                        frame_info = "Dec" 
                    else:
                        print(layer)
                        raise "Unknown Application Layer Data"
                if msginfo:
                    msginfo += ','
                msginfo += 'STREAM(%s)[%s]' % (stream_id, frame_info)
                ###
    
    return msginfo