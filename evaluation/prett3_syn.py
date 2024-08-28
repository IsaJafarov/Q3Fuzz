#! /usr/bin/env python
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

import asyncio
import ssl
import aioquic
import wsproto
import wsproto.events
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection, FrameType
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


class HttpClient():
    def __init__(self, quic_conf, hostname) -> None:
        
        self.quic_conf = quic_conf
        self._quic = QuicConnection(configuration=self.quic_conf)
        self._http = H3Connection(self._quic)
        self.hostname = hostname
    
    def craft_sample_headers_frame(self):
        """
        Craft a sample HEADERS frame
        """
        
        print("\nCrafting a sample HEADERS frame")
        stream_id = self._quic.get_next_available_stream_id()

        headers = [
                (b":method", "GET".encode()),
                (b":scheme", "HTTPS".encode()),
                (b":authority", self.hostname.encode()),
                (b":path", "/".encode()),
                (b"user-agent", "PRETT3 client".encode()),
            ]

        frame_data = self._http._encode_headers(stream_id, headers)

        #return frame_data

        self._http._quic.send_stream_data(
            stream_id, aioquic.h3.connection.encode_frame(FrameType.HEADERS, frame_data), False)


    def get_builder(self):
    
        builder = QuicPacketBuilder(
            host_cid=self._http._quic.host_cid,
            is_client=True,
            max_datagram_size=self._http._quic._max_datagram_size,
            peer_cid=self._http._quic._peer_cid.cid,
            version=self._http._quic._version,

            packet_number=self._http._quic._packet_number,
            peer_token=self._http._quic._peer_token,
            quic_logger=self._http._quic._quic_logger,
            spin_bit=self._http._quic._spin_bit,
            
        )
    
        epoch = Epoch.ONE_RTT # ZERO_RTT throws "Encryption key is not available" exception
        crypto = self._http._quic._cryptos[epoch]
        builder.start_packet(QuicPacketType.ONE_RTT, crypto)

        self._http._quic._packet_number += 1

        return builder

    def send_quic_stream(self, frame_data):

        builder = self.get_builder()

        buf = builder.start_frame(
                QuicFrameType.STREAM_BASE,
                capacity=1000,
                #handler=stream.sender.on_data_delivery,
                #handler_args=(frame.offset, frame.offset + len(frame.data), frame.fin),
            )
        buf.push_uint_var(0) # stream id
        buf.push_uint_var(0) # offset
        buf.push_uint16(100) # length
        buf.push_bytes(frame_data) # data

        self.send_quic_frames_from_builder(builder)

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
            sock.sendto(data, (self.hostname, 443))
    

    def connect(self):
        self._quic.connect(self.hostname, time.time())
        print("\n Transmitting:\n")

        for data, addr in self._quic.datagrams_to_send(now=time.time()):
            print(data)
            sock.sendto(data, (self.hostname, 443))
            

    
    


def main(
    configuration: QuicConfiguration,
    url: str
) -> None:
    
    h3client = HttpClient(configuration, urlparse(url).netloc)

    # connection initialization
    h3client.connect()

    # receive server's response
    try:
        while True:
            data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
            print("\nReceived message:\n%s" % data)
    except socket.timeout: pass


    # try to send a simple quic frame
    h3client.send_quic_ack(10)



def init(args):
    print("\n[STEP 1] Initializing...")
    os.system("sudo rm -r __pycache__")

    SERVER_ADDR = args.url
    pcapfile = args.pcap
    # outdir = setup_logger(pcapfile, 0)
    # _enable_capture()

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
    init(args)
    
    ### Extract initial state machine ###
    http3_basic_messages = util.h3msg_from_pcap(args.pcap, client_only=True)

    main(
            configuration=configuration,
            url=args.url
        )
    
    