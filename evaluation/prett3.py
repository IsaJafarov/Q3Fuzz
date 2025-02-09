#! /usr/bin/env python
# Common type modules
import aioquic.h3
import aioquic.h3.connection
import util
import os
import sys
import logging
import subprocess
import time
import pickle
import argparse
from datetime import datetime
from collections import deque
from typing import BinaryIO, Callable, Deque, Dict, List, Optional, Union, cast
from urllib.parse import urlparse

# HTTP/3 with aioquic modules
import aioquic.buffer
import asyncio
import ssl
import aioquic
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection, FrameType, StreamType, encode_frame, encode_settings
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.packet_builder import QuicPacketBuilder
from aioquic.quic.packet import QuicFrameType, QuicPacketType
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.connection import *
from aioquic.tls import CipherSuite, Epoch
import socket


logger = logging.getLogger("client")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
sock.settimeout(0.5)
network_path = QuicNetworkPath('prett3.com')
connect_v = None # temporary

class HttpClient():
    def __init__(self, quic_conf: QuicConfiguration, hostname: str) -> None:
        
        self.quic_conf = quic_conf
        self.quic_conf.original_version = 1
        self.quic_conf.server_name = "prett3.com"
        self._quic = QuicConnection(configuration=self.quic_conf)
        self._http = H3Connection(self._quic)
        self.hostname = hostname
        #self.host_cid = os.urandom(self.quic_conf.connection_id_length) # wireshark -> 
        # "[Failed to create decryption context: Decryption (checktag) failed: Checksum error]" TODO: find out why
        #self.host_cid = self._quic._peer_cid.cid

    def craft_sample_headers_frame(self):
        """
        Craft a sample HEADERS frame
        """

        stream_id = self._quic.get_next_available_stream_id()
        print("\nCrafting a sample HEADERS frame (stream_id : %s)" % stream_id)

        headers = [
                (b":method", "GET".encode()),
                (b":scheme", "HTTPS".encode()),
                (b":authority", self.hostname.encode()),
                (b":path", "/".encode()),
                (b"user-agent", "PRETT3 client".encode()),
            ]


        # frame_date = self._http._encode_headers(stream_id, headers)
        # self.sent_packets.append(("HEADERS", stream_id))

        frame_data =  self._http._encode_headers(stream_id, headers)

        return aioquic.h3.connection.encode_frame(FrameType.HEADERS, frame_data)

        #self._http._quic.send_stream_data(
        #    stream_id, aioquic.h3.connection.encode_frame(FrameType.HEADERS, frame_data), False)


    def get_builder(self, epoch: Epoch):
        builder = QuicPacketBuilder(
            host_cid=self._http._quic.host_cid,
            is_client=True,
            max_datagram_size=self._http._quic._max_datagram_size,
            peer_cid=self._http._quic._peer_cid.cid,
            version=self.quic_conf.original_version,

            packet_number=self._http._quic._packet_number,
            peer_token=self._http._quic._peer_token,
            quic_logger=self._http._quic._quic_logger,
            spin_bit=self._http._quic._spin_bit,
        )

        crypto_pair = self._quic._cryptos[epoch]
       
        quic_packet_type = None
        if epoch==Epoch.INITIAL: quic_packet_type = QuicPacketType.INITIAL
        elif epoch==Epoch.HANDSHAKE: quic_packet_type = QuicPacketType.HANDSHAKE
        elif epoch==Epoch.ONE_RTT: quic_packet_type = QuicPacketType.ONE_RTT

        #print(">>> prett3.get_builder. quic_packet_type={}, crypto_pair={}".format(quic_packet_type, crypto_pair))
        #print(">>> prett3.get_builder. crypto valid={}".format(crypto_pair.send.is_valid()))
        builder.start_packet(quic_packet_type, crypto_pair)

        self._http._quic._packet_number += 1

        return builder

    def send_quic_stream(self, frame_data):
        builder = self.get_builder(Epoch.ONE_RTT)

        buf = builder.start_frame(
                QuicFrameType.STREAM_BASE | 2,
                capacity=4, # not sure
                #handler=stream.sender.on_data_delivery,
                #handler_args=(frame.offset, frame.offset + len(frame.data), frame.fin),
            )
        buf.push_uint_var(0) # stream id
        #buf.push_uint_var(0) # offset
        '''
        QUIC RFC 19.8
        The OFF bit (0x04) in the frame type is set to indicate that there is an Offset field present. 
        When set to 1, the Offset field is present. 
        When set to 0, the Offset field is absent and the Stream Data starts at an offset of 0 
        (that is, the frame contains the first bytes of the stream, or the end of a stream that includes no data).
        '''
        buf.push_uint16(len(frame_data) | 0x4000) # length
        buf.push_bytes(frame_data) # data

        self.send_quic_frames_from_builder(builder)

        # pm.num_of_states += 1
        # cand_s = states.State(name=str(pm.num_of_states), level=pm.current_level + 1, parent_state=pm.current_state,
        #         msg_sent=matched_packet, msg_rcvd="|".join(received_packets_once))
        # sm.add_state(cand_s.name)
        # sm.add_transition(f"{cand_s.msg_sent}->{cand_s.msg_rcvd}", source=cand_s.parent_state, dest=cand_s.name)
        # pm.current_state = cand_s.name

        # # Last transition from the last state to finish state.
        # sm.add_transition(f"GOAWAY", source=pm.current_state, dest="finish")

        # graphname = "%s/diagram/level_" % "." + str(pm.current_level) + ".png"
        # sm.get_graph().draw(graphname, prog='dot')


    def send_quic_ack(self, acked_packet_num):
        
        builder = self.get_builder()

        buf = builder.start_frame(
                    QuicFrameType.ACK, # frame type
                    capacity=ACK_FRAME_CAPACITY,
                    #handler_args=(limit,),
                )
        
        buf.push_uint_var(acked_packet_num) # largest acknowledged
        buf.push_uint_var(106) # ack delay
        buf.push_uint_var(0) # ack range count
        buf.push_uint_var(0) # ack range

        self.send_quic_frames_from_builder(builder)


    def send_quic_frames_from_builder(self, builder:QuicPacketBuilder):
        datagrams, packets = builder.flush()

        for data in datagrams:
            print("\nSending message: len={}\n".format( len(data) ))
            sock.sendto(data, (self.hostname, 443))
    

    def connect(self):
        self._quic.connect(self.hostname, time.process_time())

        for data, addr in self._quic.datagrams_to_send(now=time.process_time()):
            print("\nSending message: len={}\n".format( len(data) ))
            sock.sendto(data, (self.hostname, 443))

    
    def complete_connection(self):
        print("\n>>> complete_connection: start")
        
        #self._quic._discard_epoch(tls.Epoch.INITIAL) # datagrams_to_send, if sent_handshake is True
 
        #self._quic._update_traffic_key(tls.Direction.ENCRYPT, Epoch.HANDSHAKE, tls.CipherSuite.AES_256_GCM_SHA384, ''.encode())
        
        builder = self.get_builder(Epoch.HANDSHAKE)
        self._quic._write_handshake(builder, Epoch.HANDSHAKE, time.process_time())
        self.send_quic_frames_from_builder(builder)
    

        """
        How aioquic creates/sends streams:
        1. _quic.send_stream_data
            - calls _quic._get_or_create_stream_for_send(), which creates the stream and appends to _quic._streams_queue
            - writes data to that stream.sender
        2. _quic.datagrams_to_send() passes builder to _quic._write_application(), which
            - gets the stream from _quic._streams_queue 
            - calls _quic._write_stream_frame to create the frame
        """
    

    def open_qpack_streams(self):
        """
        1. Crafting
        _http._init_connection()
            - gonna create 3 uni streams via _http._create_uni_stream()
        
        _http._create_uni_stream()
            - gonna create QUIC stream by calling _quic.send_stream_data() with stream id and encoded _http.StreamType

        _quic.send_stream_data()
            - gonna create the stream by calling _quic._get_or_create_stream_for_send()
            - appends to _quic._streams_queue list
            - writes data to that stream.sender
        
        _quic._get_or_create_stream_for_send()
            - creates QuicStream
        
            
        2. Sending
        _quic.datagrams_to_send() 
            - passes builder to _quic._write_application()

        _quic._write_application()
            - gets the stream from _quic._streams_queue list
            - gonna create the stream frame by passing builder to _quic._write_stream_frame

        _quic._write_stream_frame()
            - creates frame by calling stream.sender.get_frame()

        stream.sender.get_frame()
            - creates QuicStreamFrame
        """
        
        print(">>> open_qpack_streams: start")

        settings={
            aioquic.h3.connection.Setting.QPACK_MAX_TABLE_CAPACITY: 2323,# self._http._max_table_capacity,
            aioquic.h3.connection.Setting.QPACK_BLOCKED_STREAMS: self._http._blocked_streams,
            aioquic.h3.connection.Setting.ENABLE_CONNECT_PROTOCOL: 1,
            aioquic.h3.connection.Setting.DUMMY: 1
        }
        encoded_settings_frame = encode_frame(FrameType.SETTINGS, encode_settings(settings))
        stream2_frame = QuicStreamFrame(
            data=
             bytes( aioquic.buffer.encode_uint_var(StreamType.CONTROL) + encoded_settings_frame), #aioquic.buffer.encode_uint_var(StreamType.CONTROL),
            offset=0,
            fin=False
        )
       
        
        stream6_frame = QuicStreamFrame(
            data=aioquic.buffer.encode_uint_var(StreamType.QPACK_ENCODER),
            offset=0,
            fin=False
        )

        stream10_frame = QuicStreamFrame(
            data=aioquic.buffer.encode_uint_var(StreamType.QPACK_DECODER),
            offset=0,
            fin=False
        )


        builder = self.get_builder(Epoch.ONE_RTT)


        # Frame 1
        buf1 = builder.start_frame(
                QuicFrameType.STREAM_BASE | 2, 
                capacity=4, #checked
            )
        buf1.push_uint_var(2) # stream id
        #buf1.push_uint_var(0) # offset. IMPORTANT!!! _QUIC._write_stream_frame() does not set offset for these frames.
        buf1.push_uint16( len(stream2_frame.data) | 0x4000 ) #(16399) #(len(stream2_frame.data) | 0x4000) # length
        buf1.push_bytes(stream2_frame.data) # data
        
        
        # Frame 2
        buf2 = builder.start_frame(
                QuicFrameType.STREAM_BASE | 2,
                capacity=4, #checked
            )
        buf2.push_uint_var(6)
        #buf2.push_uint_var(0) # offset
        buf2.push_uint16( len(stream6_frame.data) | 0x4000 )  #(16385) #(len(stream6_frame.data) | 0x4000)
        buf2.push_bytes(stream6_frame.data)


        # Frame 3
        buf3 = builder.start_frame(
                QuicFrameType.STREAM_BASE | 2,
                capacity=4, #checked
            )
        buf3.push_uint_var(10)
        #buf3.push_uint_var(0) # offset
        buf3.push_uint16(len(stream10_frame.data) | 0x4000) #(16385) | 0x4000)
        buf3.push_bytes(stream10_frame.data)        

        self.send_quic_frames_from_builder(builder)


    def read_from_buffer(self):
        # receive server's response
        try:
            while True:
                data, addr = sock.recvfrom(2048) # 1024 causes problems
                print("\nReceived message: len={}\n".format(len(data)))
                self._quic.receive_datagram(data, addr=self.hostname, now=time.process_time())
        except socket.timeout: pass


def main(
    configuration: QuicConfiguration,
    url: str
) -> None:

    # Step 1: Initialize the HTTP/3 client with QUIC configuration
    h3client = HttpClient(configuration, urlparse(url).netloc)

    # Step 2: Establish the initial connection (handshake)
    print("\033[93m\n[Establishing connection via Crypto message...]\033[0m")
    h3client.connect()
    print("1. sending crypto validity: {}".format( h3client._quic._cryptos[Epoch.HANDSHAKE].send.is_valid() ))

    h3client.read_from_buffer()  # Receive any response from the server

    print("After connect, sending crypto validity: {}".format( h3client._quic._cryptos[Epoch.HANDSHAKE].send.is_valid() ))

    time.sleep(0.1)
    
    # Step 3: Complete the connection (finish handshake)
    print("\033[93m\n[Finishing handshake using Handshake message...]\033[0m")
    h3client.complete_connection()
    h3client.read_from_buffer()  # Receive any response from the server

    time.sleep(0.1)
    
    #sys.exit()
    headers_data = h3client.craft_sample_headers_frame()
    h3client.send_quic_stream(headers_data)
    h3client.read_from_buffer()
    

def init(args):
    print("\n[STEP 1] Initializing...")
    os.system("sudo rm -r __pycache__")
    SERVER_ADDR = args.url
    pcapfile = args.pcap
    print("  [+] Initializing done!\n    => pcap : %s, SERVER_ADDR : %s" % (pcapfile, SERVER_ADDR))
    return


if __name__ == "__main__":
    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(description="HTTP/3 client")
    parser.add_argument(
        "url", type=str, help="the URL to query (must be HTTPS)"
    )
    parser.add_argument(
        "pcap", type=str, help="the PATH of QUIC or HTTP/3 traffic (must be Wireshark-readable pcap)"
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument(
        "--cipher-suites",
        type=str,
        help=(
            "only advertise the given cipher suites, e.g. `AES_256_GCM_SHA384,"
            "CHACHA20_POLY1305_SHA256`"
        ),
    )
    parser.add_argument(
        "--congestion-control-algorithm",
        type=str,
        default="reno",
        help="use the specified congestion control algorithm",
    )
    parser.add_argument(
        "--max-data",
        type=int,
        help="connection-wide flow control limit (default: %d)" % defaults.max_data,
    )
    parser.add_argument(
        "--max-stream-data",
        type=int,
        help="per-stream flow control limit (default: %d)" % defaults.max_stream_data,
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
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
    parser.add_argument(
        "--local-port",
        type=int,
        default=0,
        help="local port to bind for connections",
    )
    parser.add_argument(
        "--max-datagram-size",
        type=int,
        default=defaults.max_datagram_size,
        help="maximum datagram size to send, excluding UDP or IP overhead",
    )
    parser.add_argument(
        "--zero-rtt", action="store_true", help="try to send requests using 0-RTT"
    )

    args = parser.parse_args()

    '''
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    '''

    

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        congestion_control_algorithm=args.congestion_control_algorithm,
        max_datagram_size=args.max_datagram_size,
        original_version=1
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.cipher_suites:
        configuration.cipher_suites = [
            CipherSuite[s] for s in args.cipher_suites.split(",")
        ]
    configuration.verify_mode = ssl.CERT_NONE
    if args.max_data:
        configuration.max_data = args.max_data
    if args.max_stream_data:
        configuration.max_stream_data = args.max_stream_data
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")

    """ aioquic's code till here """

    ### General setting ###
    #init(args)
    
    ### Extract initial state machine ###
    #http3_basic_messages = util.h3msg_from_pcap(args.pcap, client_only=True)
    main(
             configuration=configuration,
             url=args.url
    )
    
