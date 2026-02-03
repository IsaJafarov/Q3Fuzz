# -*- coding: UTF-8 -*-
# Modules for HTTP3
import pyshark
import difflib
import re
from termcolor import colored
from collections import OrderedDict
from typing import List, Union
from aioquic.buffer import Buffer
from aioquic.quic.packet import QuicFrameType, QuicPacketType
import pyshark.packet
import pyshark.packet.layers
from pyshark.packet.packet import Packet
from pyshark.packet.layers.xml_layer import XmlLayer
from .dissector import *

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
    
    # by frame name
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

GREASE_ABBREVIATION = "GR"


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

import re
from collections import OrderedDict

def compare_sr_pairs(state_name: str, dict1: OrderedDict, dict2: OrderedDict, mode: str = "nostrid") -> bool:
    """
    Compare two OrderedDicts containing SR input-output pairs.

    Parameters:
        state_name (str): Debug label
        dict1 (OrderedDict): Baseline state
        dict2 (OrderedDict): New state to compare
        mode (str): One of "strict", "nostrid", or "subset"

    Returns:
        bool: True if the states match under the given mode
    """

    def extract_frames(s: str) -> set:
        """
        Parse a string like 'ST(4)[HE],ACK,CC' into set of frame types: {'HE', 'ACK', 'CC'}
        """
        tokens = [t.strip() for t in s.split(',') if t.strip()]
        frames = set()
        for t in tokens:
            # Extract [TYPE] from ST(4)[TYPE]
            m = re.search(r'\[(.*?)\]', t)
            if m:
                frames.add(m.group(1))
            else:
                frames.add(t)  # Includes ACK, CC, etc.
        return frames

    subset = True

    for key in dict2:
        val2 = str(dict2[key])
        if key not in dict1:
            continue

        val1 = str(dict1[key])

        if mode == "strict":
            if val1 != val2:
                # print(f"[DEBUG][{state_name}] STRICT mismatch at key '{key}': '{val1}' != '{val2}'")
                subset = False

        elif mode == "nostrid":
            frames1 = extract_frames(val1)
            frames2 = extract_frames(val2)
            if frames1 != frames2:
                # print(f"[DEBUG][{state_name}] NOSTRID mismatch at key '{key}': {frames1} != {frames2}")
                subset = False

        elif mode == "subset":
            frames1 = extract_frames(val1)
            frames2 = extract_frames(val2)
            missing = frames2 - frames1
            if missing:
                # print(f"[DEBUG][{state_name}] SUBSET missing frames at key '{key}': {missing}")
                subset = False

        else:
            raise ValueError(f"Invalid comparison mode: {mode}")

    return subset

def highlight_differences(str1: str, str2: str) -> str:
    """Generate a visual diff highlighting changes between two strings."""
    diff = difflib.ndiff(str1.splitlines(), str2.splitlines())
    highlighted_diff = []
    for line in diff:
        if line.startswith('- '):
            highlighted_diff.append(colored(line, 'red'))  # Removed value
        elif line.startswith('+ '):
            highlighted_diff.append(colored(line, 'green'))  # Added value
        elif not line.startswith('? '):
            highlighted_diff.append(line)  # Unchanged value
    return "\n".join(highlighted_diff)

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

def extract_stop_sending_stream_ids(msg_rcvd_str: str) -> set:
    """
    Extract all stream IDs from STOP_SENDING (SS) frames in a message string.
    Example matches: "SS(2)", "SS(10)", etc.
    """
    return set(int(m.group(1)) for m in re.finditer(r'SS\((\d+)\)', msg_rcvd_str))

def extract_stream_ids_from_msg_str(msg_sent_str: str) -> set:
    """
    Extract all stream IDs from ST(x) patterns in a message string.
    """
    return set(int(m.group(1)) for m in re.finditer(r'ST\((\d+)\)', msg_sent_str))


def h3msg_from_pcap(file_path:str, keylog_file:str, client_only:bool=False) -> List[Packet]: # for HTTP3
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
    quic_cap = pyshark.FileCapture(file_path, display_filter='quic', override_prefs={"tls.keylog_file": keylog_file})
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


def h3msg_to_str(h3msg:Union[list, Packet], exclude_opt_client_frames:bool = False, exclude_opt_server_frames:bool = False) -> str:
    """
    Convert a QUIC or HTTP3 message in a human-readable format.
    args:
        h3msg: A QUIC / HTTP3 packet of type 'pyshark.packet.packet.Packet'
    return:
        msginfo: a string of a Q / H3 message with multiple layers and frames
    """
    
    msginfo = ''

    if isinstance(h3msg, list): # for moving messages
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
        quic_frames = msg_dissector.dissect_msg(h3msg)

        for quic_frame in quic_frames:

            if isinstance(quic_frame, QuicAck):
                msginfo += QUIC_FRAME_ABBREVIATIONS['ACK']
            elif isinstance(quic_frame, QuicNewConnectionId):
                msginfo += QUIC_FRAME_ABBREVIATIONS['NEW_CONNECTION_ID']
            elif isinstance(quic_frame, QuicMaxStreams):
                msginfo += QUIC_FRAME_ABBREVIATIONS['MAX_STREAMS']
            elif isinstance(quic_frame, QuicStream):
                h3_frame_str = ''
                
                if quic_frame.h3_frame is None:
                    h3_frame_str = "\u2298"
                elif isinstance(quic_frame.h3_frame, H3Settings):
                    h3_frame_str = H3_FRAME_ABBREVIATIONS['SETTINGS']
                elif isinstance(quic_frame.h3_frame, H3Headers):
                    h3_frame_str = H3_FRAME_ABBREVIATIONS['HEADERS']
                elif isinstance(quic_frame.h3_frame, H3Data):
                    h3_frame_str = H3_FRAME_ABBREVIATIONS['DATA'] 
                elif isinstance(quic_frame.h3_frame, H3PriorityUpdate):
                    h3_frame_str = H3_FRAME_ABBREVIATIONS['PRIORITY_UPDATE']
                elif isinstance(quic_frame.h3_frame, QpackEncoder):
                    h3_frame_str = 'Enc'
                elif isinstance(quic_frame.h3_frame, QpackDecoder):
                    h3_frame_str = 'Dec'
                else:
                    print(quic_frame)
                    raise Exception("Unknown HTTP/3 frame")
            
                msginfo += "{}({})[{}]".format(QUIC_FRAME_ABBREVIATIONS['STREAM'], quic_frame.stream_id, h3_frame_str)
            else:
                raise Exception("Unknown QUIC frame")
            msginfo += ","

    return beautify_message_string(msginfo, exclude_opt_client_frames=exclude_opt_client_frames, exclude_opt_server_frames=exclude_opt_server_frames) 


def beautify_message_string(message:str, exclude_opt_client_frames:bool = False, exclude_opt_server_frames:bool = False) -> str:
    
    message = message\
        .replace(H3_FRAME_ABBREVIATIONS["RESERVED"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["PADDING"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["NEW_TOKEN"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["PING"]+",", "")

    if exclude_opt_server_frames:
        message = message\
        .replace(QUIC_FRAME_ABBREVIATIONS["NEW_CONNECTION_ID"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["MAX_STREAMS"]+",", "")\
        .replace(QUIC_FRAME_ABBREVIATIONS["MAX_STREAM_DATA"]+",", "")
            
        # check if there are frames other than ACK
        if len( message.replace("ACK", "").replace(",", "") ) > 0:
            # print(">>> Turned {} into {}".format(
            #     message,
            #     message.replace(QUIC_FRAME_ABBREVIATIONS["ACK"]+",", "")
            # ))
            message = message.replace(QUIC_FRAME_ABBREVIATIONS["ACK"]+",", "")
    
    if exclude_opt_client_frames:
        message = message\
        .replace(QUIC_FRAME_ABBREVIATIONS["ACK"]+",", "")

    

    message = message\
        .rstrip(",")    
    

    return message
