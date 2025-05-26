#! /usr/bin/env python
import os
import argparse
import ssl
from pathlib import Path
from urllib.parse import urlparse
from rich.traceback import install

# aioquic module
import aioquic
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN, H3Connection, FrameType, encode_frame, encode_settings, StreamType
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet_builder import QuicPacketBuilder
from aioquic.quic.packet import QuicFrameType, QuicPacketType
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.connection import *
from aioquic.tls import CipherSuite, Epoch
from pyshark.packet.packet import Packet

# PRETT3 module
from handler import MSGHandler
from crafter import MSGCrafter
from http_client import HttpClient
import states
import util
import statemachine as stma

EVALUATION_DIR = Path(__file__).parent.resolve()

def init(args) -> Path:
    print("\n[STEP 1] Initializing...")

    # Remove __pycache__ directory if it exists
    pycache_dir = EVALUATION_DIR / "__pycache__"
    if pycache_dir.exists():
        import shutil
        shutil.rmtree(pycache_dir)

    SERVER_ADDR = args.url
    pcapfile = args.pcap

    print(f"  [+] Initializing done!\n    => pcap : {pcapfile}, SERVER_ADDR : {SERVER_ADDR}")
    return


if __name__ == "__main__":
    
    # for beautiful tracebacks
    install()

    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(
        description="Manual testing script for HTTP/3 commuincation. Send each packet in pcap file.")
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
        "-dk",
        "--decrypt_keylog",
        default=str(EVALUATION_DIR / "secrets.keylog"),
        type=str,
        help="Path to SSLKEYLOGFIEL to decrypt the input pcap (default: ./sample_traffics/secrets.keylog)",
    )
    parser.add_argument(
        "-ok",
        "--output_keylog",
        default=str(EVALUATION_DIR / "secrets.keylog"),
        type=str,
        help="Path to SSLKEYLOGFILE to decrypt the running conneciton (default=./secrets.keylog)",
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
    
    if args.output_keylog:
        output_keylog_file = os.path.abspath(args.output_keylog) 
        configuration.secrets_log_file = open(output_keylog_file, "a")

    decrypt_keylog_file = os.path.abspath(args.decrypt_keylog)
    if not os.path.exists(decrypt_keylog_file):
        raise Exception("{} does not exist".format(decrypt_keylog_file))

    
    ### General setting ###
    init(args)
    
    ### Extract initial state machine ###
    cnt = 1
    http3_basic_messages = util.h3msg_from_pcap(args.pcap, decrypt_keylog_file, client_only=True)
    h3client = HttpClient(configuration, urlparse(args.url).netloc)


    # ROUTINE 1: Connection Estalbishment Test.
    # - In case of Caddy 2.7.4, there is suspicious response ST(2),SE. Check with this routine.
    # -----------------------------------------------
    quicmsg_rcvd = stma.connect_initial(h3client)
    print(f"[RECORD\t{cnt}] INITIAL => {quicmsg_rcvd}")
    cnt += 1
    quicmsg_rcvd = stma.connect_handshake(h3client)
    print(f"[RECORD\t{cnt}] HANDSHAKE => {quicmsg_rcvd}")
    # -----------------------------------------------
    
    # ROUTINE 2: Pcap Message Test.
    # Filtering out connection, server-side, optional messages
    client_msgs = []
    for msg_sent in http3_basic_messages:
            msg_sent_str = util.h3msg_to_str(msg_sent, exclude_opt_client_frames=True)
            ## SKIP TEST 1 (connection establishment?)
            if 'INIT' in msg_sent_str or 'HANDSHAKE' in msg_sent_str or len(msg_sent_str)==0:
                continue
            client_msgs.append(msg_sent)

    print(f"Available Messages : {len(client_msgs)}")
    idx = 0
    for msg in client_msgs:
        print(f"{idx}\t: {util.h3msg_to_str(msg)}")
        idx += 1

    while(True):
        n = input("Message # (C/c for connection close): ")
        if n == "c" or n == "C":
            h3client.close_connection()
            print("Good Bye!")
            break
        else:
            n = int(n)
            h3msg_rcvd = h3client.replay_msg(client_msgs[n], exclude_ack=True)
            print(f"[RECORD\t{cnt}] {util.h3msg_to_str(client_msgs[n])} => {h3msg_rcvd}")
            cnt += 1