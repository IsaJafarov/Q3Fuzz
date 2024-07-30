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
from aioquic.tls import CipherSuite, SessionTicket

logger = logging.getLogger("client")
USER_AGENT = "aioquic/" + aioquic.__version__


class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)

        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme

class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}

        self.content = content
        self.headers = headers
        self.method = method
        self.url = url


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: H3Connection = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._http = H3Connection(self._quic)

    def http_event_received(self, event: H3Event) -> None:
        print("H3 event happened:")
        print( type(event) )
        print("")
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        #  pass event to the HTTP layer
        #print("QQQQQQQQQQQQQ")
        #print( type(event) )
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                
                self.http_event_received(http_event)

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path", request.url.full_path.encode()),
                (b"user-agent", USER_AGENT.encode()),
            ]
            + [(k.encode(), v.encode()) for (k, v) in request.headers.items()],
            end_stream=not request.content,
        )
        if request.content:
            self._http.send_data(
                stream_id=stream_id, data=request.content, end_stream=True
            )

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)


    async def send_sample_headers_frame(self):
        '''
        finishes normal. doesn't hang
        prints html and response headers
        print "Connection close sent (code 0x100, reason )"
        '''
        stream_id = self._quic.get_next_available_stream_id()

        headers = [
                (b":method", "GET".encode()),
                (b":scheme", "HTTPS".encode()),
                (b":authority", "prett3.com".encode()),
                (b":path", "/".encode()),
                (b"user-agent", USER_AGENT.encode()),
            ]

        frame_date = self._http._encode_headers(stream_id, headers)

        self._http._quic.send_stream_data(
            stream_id, aioquic.h3.connection.encode_frame(FrameType.HEADERS, frame_date), False)

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        # without it, you don't receive h3 packets
        return await asyncio.shield(waiter)
    
    async def send_sample_data_frame(self):
        '''
        sends the data frame and hangs
        doesn't receive any h3 packet
        prints "Connection close received (code 0x105, reason unexpected HTTP/3 frame sequence on stream 0)"
        '''
        stream_id = self._quic.get_next_available_stream_id()

        frame_date = "ASASASASASASASASASASASASASASASASASASASASASASASASASASASASASASASASAS".encode()

        self._http._quic.send_stream_data(
            stream_id, aioquic.h3.connection.encode_frame(FrameType.DATA, frame_date), True)

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)
    
    async def send_sample_settings_frame(self):
        '''
        sends settings frame and hangs
        doesn't receive any h3 packet
        logs "Connection close received (code 0x105, reason unexpected HTTP/3 frame sequence on stream 0)"
        '''
        stream_id = self._quic.get_next_available_stream_id()

        asyncio.sleep(2)

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


        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    async def send_sample_goaway_frame(self):
        '''
        
        '''
        stream_id = self._quic.get_next_available_stream_id()

        asyncio.sleep(2)

        self._http._quic.send_stream_data(
            stream_id,
            aioquic.h3.connection.encode_frame(FrameType.GOAWAY, 
                                               "".encode()
                                               ), False
        )


        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    async def send_packet_bytes(self, packet: bytes):
  
        stream_id = self._quic.get_next_available_stream_id()

        self._http._quic.send_stream_data(
            stream_id, packet, False
        )

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)


async def perform_packet_transmission(
    client: HttpClient,
) -> None:

    # Send DATA frame
    #http_events = await client.send_data_frame()
    #http_events = await client.send_sample_data_frame()

    # Send SETTINGS frame
    #await client.send_any_frame(FrameType.SETTINGS, "ASASAS".encode())
    #http_events = await client.send_sample_settings_frame()
    
    # Send HEADERS frame
    #await client.send_any_frame(FrameType.HEADERS,   "ASASAS".encode() )
    #http_events = await client.send_sample_headers_frame()

    # Send GOAWAY frame
    #http_events = await client.send_sample_goaway_frame()


    # Send packet bytes
    packet = aioquic.h3.connection.encode_frame(FrameType.GOAWAY, "".encode()) # sample packet bytes
    http_events = await client.send_packet_bytes( packet )


    # output response
    print_response(http_events=http_events)
    

def print_response( http_events: Deque[H3Event] ) -> None:
    for http_event in http_events:
        if isinstance(http_event, HeadersReceived):
            for k, v in http_event.headers:
                print(k.decode()+": "+v.decode())
            
        elif isinstance(http_event, DataReceived):
            print(http_event.data)


def save_session_ticket(ticket: SessionTicket) -> None:
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)



async def main(
    configuration: QuicConfiguration,
    url: str,
    data: Optional[str],
    local_port: int,
    zero_rtt: bool,
) -> None:
    
    async with connect(
        urlparse(url).netloc,
        443,
        configuration=configuration,
        create_protocol=HttpClient,
        session_ticket_handler=save_session_ticket,
        local_port=local_port,
        wait_connected=not zero_rtt,
    ) as client:
        client = cast(HttpClient, client)

        
        
        await perform_packet_transmission(
                    client=client
            )
        

        client._quic.close(error_code=ErrorCode.H3_NO_ERROR)


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
        "-d", "--data", type=str, help="send the specified data in a POST request"
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
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
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

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

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
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            pass

    """ aioquic's code till here """

    ### General setting ###
    init(args)
    
    ### Extract initial state machine ###
    http3_basic_messages = util.h3msg_from_pcap(args.pcap, client_only=True)


    asyncio.run(
        main(
            configuration=configuration,
            url=args.url,
            data=args.data,
            local_port=args.local_port,
            zero_rtt=args.zero_rtt,
        )
    )
    