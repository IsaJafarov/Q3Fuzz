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
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection, FrameType
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.tls import CipherSuite

logger = logging.getLogger("client")


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http = H3Connection(self._quic)
        self.received_packets: Deque[H3Event] = []


    def quic_event_received(self, event: QuicEvent) -> None:
        """
        Override the function of the parent class (QuicConnectionProtocol).
        
        The function is automatically called when a new quic event is received. The received events are saved in a list.
        """
        
        #print("RECEIVED EVENT",end=": ")
        #print( type(event) )

        self.received_packets.append(event)

    

    def craft_sample_headers_frame(self):
        """
        Craft a sample HEADERS frame
        """
        
        print("Crafting a sample HEADERS frame")
        stream_id = self._quic.get_next_available_stream_id()

        headers = [
                (b":method", "GET".encode()),
                (b":scheme", "HTTPS".encode()),
                (b":authority", "prett3.com".encode()),
                (b":path", "/".encode()),
                (b"user-agent", "PRETT3 client".encode()),
            ]

        frame_date = self._http._encode_headers(stream_id, headers)

        self._http._quic.send_stream_data(
            stream_id, aioquic.h3.connection.encode_frame(FrameType.HEADERS, frame_date), False)
    
    def craft_sample_data_frame(self):
        """
        Craft a sample DATA frame
        """
        
        print("Crafting a sample DATA frame")
        stream_id = self._quic.get_next_available_stream_id()

        frame_date = "ASASASASASASASASASASASASASASASASASASASASASASASASASASASASASASASASAS".encode()

        self._http._quic.send_stream_data(
            stream_id, aioquic.h3.connection.encode_frame(FrameType.DATA, frame_date), False)

    def craft_sample_settings_frame(self):
        """
        Craft a sample SETTINGS frame
        """
        
        print("Crafting a sample SETTINGS frame")

        stream_id = self._quic.get_next_available_stream_id()

        setting_params={
            1:1, # QPACK_MAX_TABLE_CAPACITY
            6:6, # MAX_FIELD_SECTION_SIZE
            7:7, # QPACK_BLOCKED_STREAMS
            8:8, # ENABLE_CONNECT_PROTOCOL
            33:33, # H3_DATAGRAM
            727725890:727725890, # ENABLE_WEBTRANSPORT
            21:21 # DUMMY
        }

        self._http._quic.send_stream_data(
            stream_id,
            aioquic.h3.connection.encode_frame(FrameType.SETTINGS, 
                                               aioquic.h3.connection.encode_settings(setting_params) 
                                               ), False
        )

    def craft_sample_goaway_frame(self):
        """
        Craft a sample GOAWAY frame
        """
            
        print("Crafting a sample GOAWAY frame")

        stream_id = self._quic.get_next_available_stream_id()

        self._http._quic.send_stream_data(
            stream_id,
            aioquic.h3.connection.encode_frame(FrameType.GOAWAY, 
                                               "".encode()
                                               ), False
        )

    def craft_packet_by_bytes(self, packet_bytes: bytes):
        """
        Craft a packet based on bytes. The bytes should contain all the data, including the Frame Type.

        :param packet_bytes: The bytes of the packet.
        """
        
        print("Crafting a packet by bytes")
        stream_id = self._quic.get_next_available_stream_id()

        self._http._quic.send_stream_data(
            stream_id, packet_bytes, False
        )

    async def send_and_receive_packets(self):
        """
        Send the crafted packet and wait for some time to receive the server's response. 
        """
        
        # remove the previously received packets from the list. We care about the ones that will be received from now on
        self.received_packets = []
            
        # send the packet
        self.transmit()

        # wait for 3 seconds to receive packets sent from the server
        print("\nWaiting for the server's response...")
        await asyncio.sleep(3) # waiting should be asynchronous. time.sleep() won't work.
        
        # the received packets
        quic_events = self.received_packets

        print("\n\n [+] Received Packets: \n")

        for i, quic_event in enumerate(quic_events):
            print("%d. QUIC EVENT: " % (i+1), end="")
            print(quic_event)

            http_events = self._http.handle_event(quic_event)

            for j, http_event in enumerate(http_events):
                print("\n\t%d. HTTP/3 EVENT: " % (j+1), end="")
                print( http_event )
            print()


async def perform_packet_transmission(
    client: HttpClient,
) -> None:

    print("\n\n [+] Packet Transmission: \n")

    client.craft_sample_headers_frame()

    #client.craft_sample_data_frame()

    #client.craft_sample_settings_frame()

    #client.craft_sample_goaway_frame()
    

    # Send packet bytes
    #packet = aioquic.h3.connection.encode_frame(FrameType.GOAWAY, "".encode()) # sample packet bytes
    #client.craft_packet_by_bytes( packet )

    await client.send_and_receive_packets()



async def main(
    configuration: QuicConfiguration,
    url: str,
    local_port: int,
    zero_rtt: bool,
) -> None:
    
    async with connect(
        urlparse(url).netloc,
        443,
        configuration=configuration,
        create_protocol=HttpClient,
        local_port=local_port,
        wait_connected=not zero_rtt,
    ) as client:
        client = cast(HttpClient, client)

        
        
        await perform_packet_transmission(
                    client=client
            )
        

        #client._quic.close(error_code=ErrorCode.H3_NO_ERROR)


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
    #init(args)
    
    ### Extract initial state machine ###
    #http3_basic_messages = util.h3msg_from_pcap(args.pcap, client_only=True)


    asyncio.run(
        main(
            configuration=configuration,
            url=args.url,
            local_port=args.local_port,
            zero_rtt=args.zero_rtt,
        )
    )
    