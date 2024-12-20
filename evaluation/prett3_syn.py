#! /usr/bin/env python
import os
import time
import socket
import argparse
import ssl
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

# pyshark module
import pyshark
from pyshark.packet.packet import Packet

# PRETT3 module
from handler import MSGHandler
from crafter import MSGCrafter
import util
import statemachine as stma

PRIORITY_UPDATE_FRAME_TYPE = 0x800f0700

class HttpClient():
    def __init__(self, quic_conf: QuicConfiguration, hostname: str, keylog_file: str) -> None:
        self.quic_conf = quic_conf
        self.quic_conf.original_version = 1
        self.hostname = hostname
        self.quic_conf.server_name = hostname # OLS requires. normally set in async module's connect()
        self.network_path = QuicNetworkPath(hostname)
        self.connection = QuicConnection(configuration=self.quic_conf)
        self._http = H3Connection(self.connection)
        self.sock = None
        self.handler = MSGHandler(qc = self.connection)
        self.crafter = MSGCrafter(qc = self.connection, client = self)
        os.environ['SSLKEYLOGFILE'] = keylog_file
        
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

        crypto_pair = self.connection._cryptos[epoch] 

        quic_packet_type = None
        if epoch==Epoch.INITIAL: quic_packet_type = QuicPacketType.INITIAL
        elif epoch==Epoch.HANDSHAKE: quic_packet_type = QuicPacketType.HANDSHAKE
        elif epoch==Epoch.ONE_RTT: quic_packet_type = QuicPacketType.ONE_RTT

        # print(">>> prett3.get_builder. quic_packet_type={}, crypto_pair={}".format(quic_packet_type, crypto_pair))
        
        builder.start_packet(quic_packet_type, crypto_pair)
        self._http._quic._packet_number += 1
        return builder

    def serialize_transport_parameters(self) -> bytes:
        quic_transport_parameters = QuicTransportParameters(
            ack_delay_exponent=3,
            active_connection_id_limit=8,
            max_idle_timeout=int(self.quic_conf.idle_timeout * 1000),
            initial_max_data=self.quic_conf.max_data,
            initial_max_stream_data_bidi_local=self.quic_conf.max_stream_data,
            initial_max_stream_data_bidi_remote=self.quic_conf.max_stream_data,
            initial_max_stream_data_uni=self.quic_conf.max_stream_data,
            initial_max_streams_bidi=128,
            initial_max_streams_uni=128,
            initial_source_connection_id=self.connection._host_cids[0].cid,
            max_ack_delay=25,
            max_datagram_frame_size=self.quic_conf.max_datagram_frame_size,
            quantum_readiness=(
                b"Q" * SMALLEST_MAX_DATAGRAM_SIZE
                if self.quic_conf.quantum_readiness_test
                else None
            ),
            stateless_reset_token=self.connection._host_cids[0].stateless_reset_token,
            version_information=QuicVersionInformation(
                chosen_version=self.quic_conf.original_version,
                available_versions=self.quic_conf.supported_versions,
            ),
        )
        # print(">>> prett3.serialize_transport_parameters. quic_transport_parameters={}".format(quic_transport_parameters))

        buf = Buffer(capacity=3 * self.connection._max_datagram_size)
        push_quic_transport_parameters(buf, quic_transport_parameters)
        return buf.data

    def get_tls(self) -> None:
        self.connection.tls = tls.Context(
            alpn_protocols=self.quic_conf.alpn_protocols,
            cadata=self.quic_conf.cadata,
            cafile=self.quic_conf.cafile,
            capath=self.quic_conf.capath,
            cipher_suites=self.quic_conf.cipher_suites,
            is_client=True,
            max_early_data=None, # None if self._is_client else MAX_EARLY_DATA
            server_name=self.quic_conf.server_name,
            verify_mode=self.quic_conf.verify_mode,
        )
        self.connection.tls.certificate = self.quic_conf.certificate
        self.connection.tls.certificate_chain = self.quic_conf.certificate_chain
        self.connection.tls.certificate_private_key = self.quic_conf.private_key
        self.connection.tls.handshake_extensions = [
            (
                tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS,
                self.serialize_transport_parameters(),
            )
        ]
    
        # TLS session resumption
        '''
        session_ticket = self.quic_conf.session_ticket
        if (
            session_ticket is not None
            and session_ticket.is_valid
            and session_ticket.server_name == self.quic_conf.server_name
        ):
            self.connection.tls.session_ticket = self.quic_conf.session_ticket
            
            # parse saved QUIC transport parameters - for 0-RTT
            if session_ticket.max_early_data_size == MAX_EARLY_DATA:
                for ext_type, ext_data in session_ticket.other_extensions:
                    if ext_type == tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS:
                        self.parse_transport_parameters(
                            ext_data, from_session_ticket=True
                        )
                        break
        '''
        
        # TLS callbacks
        self.connection.tls.alpn_cb = self.connection._alpn_handler 
        if self.connection._session_ticket_fetcher is not None:
            self.connection.tls.get_session_ticket_cb = self.connection._session_ticket_fetcher
        if self.connection._session_ticket_handler is not None:
            self.connection.tls.new_session_ticket_cb = self.connection._handle_session_ticket
        self.connection.tls.update_traffic_key_cb = self.connection._update_traffic_key# update_traffic_key
        
        # packet spaces
        def create_crypto_pair(epoch: tls.Epoch) -> CryptoPair:
            # print(">>> prett3.get_tls.create_crypto_pair: start. epoch={}".format(epoch))
            epoch_name = ["initial", "0rtt", "handshake", "1rtt"][epoch.value]
            
            recv_secret_name = "server_%s_secret" % epoch_name
            send_secret_name = "client_%s_secret" % epoch_name
            return CryptoPair(
                recv_setup_cb=partial(self.connection._log_key_updated, recv_secret_name),
                recv_teardown_cb=partial(self.connection._log_key_retired, recv_secret_name),
                send_setup_cb=partial(self.connection._log_key_updated, send_secret_name),
                send_teardown_cb=partial(self.connection._log_key_retired, send_secret_name),
            )

        # To enable version negotiation, setup encryption keys for all
        # our supported versions.
        self.connection._cryptos_initial = {}
        for version in self.quic_conf.supported_versions:
            pair = CryptoPair()
            pair.setup_initial(cid=self.connection._peer_cid.cid, is_client=True, version=version)
            self.connection._cryptos_initial[version] = pair

        self.connection._cryptos = dict(
            (epoch, create_crypto_pair(epoch))
            for epoch in (
                tls.Epoch.ZERO_RTT,
                tls.Epoch.HANDSHAKE,
                tls.Epoch.ONE_RTT,
            )
        )
        self.connection._cryptos[tls.Epoch.INITIAL] = self.connection._cryptos_initial[self.quic_conf.original_version]

        self.connection._crypto_buffers = {
            tls.Epoch.INITIAL: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.HANDSHAKE: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.ONE_RTT: Buffer(capacity=CRYPTO_BUFFER_SIZE),
        }
        self.connection._crypto_streams = {
            tls.Epoch.INITIAL: QuicStream(),
            tls.Epoch.HANDSHAKE: QuicStream(),
            tls.Epoch.ONE_RTT: QuicStream(),
        }
        self.connection._spaces = {
            tls.Epoch.INITIAL: QuicPacketSpace(),
            tls.Epoch.HANDSHAKE: QuicPacketSpace(),
            tls.Epoch.ONE_RTT: QuicPacketSpace(),
        }

        self.connection._loss.spaces = list(self.connection._spaces.values())
    
    def connect(self):
        """
        How aioquic's QuicConnection does it:
        initialize() sets up tls context
        handle_message() puts _client_send_hello message into the INITIAL's buffer in _crypto_buffers
        _push_crypto_data() writes data from the buffer to INITIAL's crypto stream in _crypto_streams
        datagrams_to_send() when called passes the builder to _write_handshake(), which adds the CRYPTO frame to it
        """

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        self.sock.settimeout(0.2)
        
        crypto_buf = Buffer(capacity=CRYPTO_BUFFER_SIZE)

        self.get_tls() # better to build tls myself to construct transport params myself
        
        self.connection.tls._client_send_hello(crypto_buf)
        
        builder = self.get_builder(Epoch.INITIAL)
        
        buf = builder.start_frame(
                QuicFrameType.CRYPTO,
                capacity=4, # based on logs
                #handler=stream.sender.on_data_delivery,
                #handler_args=(frame.offset, frame.offset + len(frame.data), False),
            )
        buf.push_uint_var(0) # offset. based on logs
        buf.push_uint16(len(crypto_buf.data) | 0x4000)
        buf.push_bytes(crypto_buf.data)
        
        self.send_quic_frames_from_builder(builder)

    def complete_connection(self):
        """
        How aioquic's QuicConnection does it:
        receive_datagram() calls _payload_received()
        _payload_received() calls _handle_crypto_frame() if the received frame is CRYPTO
        _handle_crypto_frame() passes event_data, and crypto_buffers to tls.handle_message()
        tls.handle_message() processes and puts data into HANDSHAKE's buffer

        _update_traffic_key() (when called automatically) calls _push_crypto_data() to write data from HANDSHAKE's full buffer to its stream
        """

        # print("\n>>> prett3.complete_connection: start")
        epoch = Epoch.HANDSHAKE

        crypto_pair = self.connection._cryptos[epoch]
        if not crypto_pair.send.is_valid():
            print("The Encoding crypto is not valid to send data")
            return
        
        builder = self.get_builder(epoch)

        # ACK
        # print(">>> prett3.complete_connection: start. Adding ACK frame to the builder")
        buf = builder.start_frame(
                    QuicFrameType.ACK,
                    capacity=ACK_FRAME_CAPACITY,
                )
        
        buf.push_uint_var(1) # largest acknowledged
        buf.push_uint_var(106) # ack delay
        buf.push_uint_var(0) # ack range count
        buf.push_uint_var(1) # ack range

        # CRYPTO
        # print(">>> prett3.complete_connection: Adding CRYPTO frame to the builder")
        strm_data = self.connection._crypto_streams[Epoch.HANDSHAKE].sender.get_frame(1135).data # TODO: calculate max_size dynamically instead of giving static number
        buf = builder.start_frame(
                QuicFrameType.CRYPTO,
                capacity=4, 
            )
        buf.push_uint_var(0) # offset 
        buf.push_uint16( len(strm_data) | 0x4000) # length
        buf.push_bytes(strm_data) # data

        self.send_quic_frames_from_builder(builder)

    def disconnect(self):
        # Send CONNECTION_CLOSE frame
        # Define the payload to include error_code and reason_phrase according to the QUIC specification.
        connection_close_payload = Buffer(capacity=256)
        connection_close_payload.push_uint_var(QuicErrorCode.NO_ERROR)  # Error code (NO_ERROR)
        connection_close_payload.push_uint_var(0)  # Frame type (0 since no specific frame is indicated)
        reason_phrase = "Normal connection closure after message replay"
        connection_close_payload.push_uint16(len(reason_phrase))
        connection_close_payload.push_bytes(reason_phrase.encode('utf-8'))
        
        # Send QUIC CC packet
        quic_payload = connection_close_payload.data
        builder = self.get_builder(Epoch.ONE_RTT)
        buf = builder.start_frame(QuicFrameType.APPLICATION_CLOSE, capacity=len(quic_payload))
        buf.push_bytes(quic_payload)
        self.send_quic_frames_from_builder(builder)

        # Explicitly close the QUIC connection using CONNECTION_CLOSE frame
        self.connection.close(
            error_code=QuicErrorCode.NO_ERROR,
            frame_type=QuicFrameType.APPLICATION_CLOSE,
            reason_phrase="Normal connection closure after message replay",
        )

        self.sock.close()

    def open_qpack_streams(self):
        """
        How aioquic does it
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

        settings={
            aioquic.h3.connection.Setting.QPACK_MAX_TABLE_CAPACITY: self._http._max_table_capacity,
            aioquic.h3.connection.Setting.QPACK_BLOCKED_STREAMS: self._http._blocked_streams,
            aioquic.h3.connection.Setting.ENABLE_CONNECT_PROTOCOL: 1,
            aioquic.h3.connection.Setting.DUMMY: 1
        }
        encoded_settings_frame = encode_frame(FrameType.SETTINGS, encode_settings(settings))

        # Control stream
        stream2_frame = QuicStreamFrame(
            data=
             bytes( aioquic.buffer.encode_uint_var(StreamType.CONTROL) + encoded_settings_frame), #aioquic.buffer.encode_uint_var(StreamType.CONTROL),
            offset=0,
            fin=False
        )
       
        # Encoder stream
        stream6_frame = QuicStreamFrame(
            data=aioquic.buffer.encode_uint_var(StreamType.QPACK_ENCODER),
            offset=0,
            fin=False
        )

        # Decoder stream
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
        #'''
        buf2 = builder.start_frame(
                QuicFrameType.STREAM_BASE | 2,
                capacity=4, #checked
            )
        buf2.push_uint_var(6)
        #buf2.push_uint_var(0) # offset
        buf2.push_uint16( len(stream6_frame.data) | 0x4000 )  #(16385) #(len(stream6_frame.data) | 0x4000)
        buf2.push_bytes(stream6_frame.data)
        #'''

        #'''
        # Frame 3
        buf3 = builder.start_frame(
                QuicFrameType.STREAM_BASE | 2,
                capacity=4, #checked
            )
        buf3.push_uint_var(10)
        #buf3.push_uint_var(0) # offset
        buf3.push_uint16(len(stream10_frame.data) | 0x4000) #(16385) | 0x4000)
        buf3.push_bytes(stream10_frame.data)        
        #'''
        self.send_quic_frames_from_builder(builder)

    def send_quic_stream(self, fin_bit:bool, stream_id:int, offset:int, h3_frame_data:bytes):
        """
        Send multiple HTTP/3 frames over the QUIC stream. Each frame is written into its own 
        QUIC stream frame within the same QUIC packet.
        """

        builder = self.get_builder(Epoch.ONE_RTT)

        # Determine Stream Type
        stream_type = QuicFrameType.STREAM_BASE | 2 # sets LEN bit (bit position is 1)
        if offset!=0:
            stream_type = stream_type | 4 # sets OFF bit (bit position is 2)
        if fin_bit:
            stream_type = stream_type | 1 # sets FIN bit (bit position is 0)

        buf = builder.start_frame(stream_type, capacity=4)

        # Push stream ID (encoded as varint)
        buf.push_uint_var(stream_id)

        # Push OffSet value. Push only when the offset bit in the type is set to 1
        if offset != 0:
            buf.push_uint_var(offset)

        # Push frame length (encoded as varint)
        frame_length = len(h3_frame_data)
        buf.push_uint_var(frame_length)

        # Push frame data (actual HTTP/3 frame bytes)
        buf.push_bytes(h3_frame_data)

        # print(f"Prepared QUIC frame for stream ID {stream_id} with length {frame_length}")

        # Send the combined frames in one QUIC stream message
        self.send_quic_frames_from_builder(builder)

        # print(f"\tsend_quic_stream(): Sending combined HTTP/3 frames over stream ID {stream_id}...")

    def send_quic_packet(self, quic_frame_type, quic_payload):
        """
        Send pure QUIC-level packets, such as ACK or PADDING frames.
        """
        # Ensure quic_frame_type is an integer
        if isinstance(quic_frame_type, str):
            quic_frame_type = int(quic_frame_type, 16)  # Convert hex string to int if needed
        
        # Start building a QUIC packet with the appropriate epoch (1-RTT)
        builder = self.get_builder(Epoch.ONE_RTT)

        # Handle None payload
        if quic_payload is None:
            quic_payload = b''

        # Start the frame
        buf = builder.start_frame(quic_frame_type, capacity=len(quic_payload))
        
        # Add the QUIC payload (for example, ACK payload)
        buf.push_bytes(quic_payload)

        # Send the packet
        self.send_quic_frames_from_builder(builder)

    def send_quic_frames_from_builder(self, builder:QuicPacketBuilder):
        datagrams, packets = builder.flush()

        for data in datagrams:
            # print("\tsend_quic_frames_from_builder(): Sending message: len={}".format( len(data) ))
            self.sock.sendto(data, (self.hostname, 443))

    def read_from_buffer(self):
        """
        Read QUIC/HTTP3 messages from the buffer, directly parsing decrypted payloads and saving into human-readable format.

        Returns:
            res: human-readable QUIC / HTTP3 message
        """
        res = ''

        try:
            while True:
                # Receive raw data from UDP socket
                data, addr = self.sock.recvfrom(2048)  # Adjust buffer size as needed
                # print("\tread_from_buffer(): Received message: len={}".format(len(data)))

                res_per_packet = self.receive_datagram(data, now=time.process_time())
                if res_per_packet != '':
                    res += res_per_packet
                    res += '|'

        except socket.timeout:
            # Return parsed packets after timeout
            res = res.rstrip('|')
            return res

    def receive_datagram(self, data: bytes, now: float) -> str:
        """
        Process a received QUIC datagram, decrypt and return any decrypted packet data.
        
        Args:
            data: Raw data from the UDP socket.
            now: Current time to use in QUIC processing.
            
        Returns:
            decrypted_payload: List of decrypted QUIC or HTTP/3 layer from processed packets.
        """
        res_per_packet = ''

        buf = Buffer(data=data)
        i=0
        while not buf.eof():
            i+=1
  
            # print("\tQUIC layer #{}".format(i),end=" ")

            start_off = buf.tell()

            try:
                header = pull_quic_header(buf, host_cid_length=self.quic_conf.connection_id_length)
            except ValueError:
                return
            #print("(Type: {})".format(header.packet_type.name))

            # Check destination CID matches.
            destination_cid_seq: Optional[int] = None
            for connection_id in self.connection._host_cids:
                if header.destination_cid == connection_id.cid:
                    destination_cid_seq = connection_id.sequence_number
                    break
            if destination_cid_seq is None:
                return

            # Handle version negotiation packet.
            if header.packet_type == QuicPacketType.VERSION_NEGOTIATION:
                self.connection._receive_version_negotiation_packet(header=header, now=now)
                return

            # Check long header packet protocol version.
            if (
                header.version is not None
                and header.version not in self.quic_conf.supported_versions
            ):
                return
            
            # Handle retry packet.
            if header.packet_type == QuicPacketType.RETRY:
                self.handler.handle_retry_packet(header=header,
                    packet_without_tag=buf.data_slice(
                        start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE
                    ))
                return


            crypto_frame_required = False

            # Determine crypto and packet space.
            epoch = get_epoch(header.packet_type)
            if epoch == tls.Epoch.INITIAL:
                crypto = self.connection._cryptos_initial[header.version]
            else:
                crypto = self.connection._cryptos[epoch]
            if epoch == tls.Epoch.ZERO_RTT:
                space = self.connection._spaces[tls.Epoch.ONE_RTT]
            else:
                space = self.connection._spaces[epoch]

            
            # decrypt packet
            encrypted_off = buf.tell() - start_off
            end_off = start_off + header.packet_length
            buf.seek(end_off)

            try:
                plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                        data[start_off:end_off], encrypted_off, space.expected_packet_number)
            except KeyUnavailableError as exc:
                # If a client receives HANDSHAKE or 1-RTT packets before it has
                # handshake keys, it can assume that the server's INITIAL was lost.
                if (
                    epoch in (tls.Epoch.HANDSHAKE, tls.Epoch.ONE_RTT)
                    and not self.connection._crypto_retransmitted
                ):
                    self.connection._loss.reschedule_data(now=now)
                    self.connection._crypto_retransmitted = True
                continue
            except CryptoError as exc:
                continue
            
            #print("Received packet: \n\tPacket Number={}\n\tPlain Header={}\n\tPlain Payload={}".format(packet_number, plain_header, plain_payload))
            
            # check reserved bits
            if header.packet_type == QuicPacketType.ONE_RTT:
                reserved_mask = 0x18
            else:
                reserved_mask = 0x0C
            if plain_header[0] & reserved_mask:
                self.connection.close(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=QuicFrameType.PADDING,
                    reason_phrase="Reserved bits must be zero",)
                return


            # raise expected packet number
            if packet_number > space.expected_packet_number:
                space.expected_packet_number = packet_number + 1

            # update state
            if self.connection._peer_cid.sequence_number is None:
                self.connection._peer_cid.cid = header.source_cid
                self.connection._peer_cid.sequence_number = 0

            if self.connection._state == QuicConnectionState.FIRSTFLIGHT:
                self.connection._remote_initial_source_connection_id = header.source_cid
                self.connection._set_state(QuicConnectionState.CONNECTED)

            # update spin bit
            if (header.packet_type == QuicPacketType.ONE_RTT
                and packet_number > self.connection._spin_highest_pn):
                
                spin_bit = get_spin_bit(plain_header[0])
                self._spin_bit = not spin_bit # for clients
                self._spin_highest_pn = packet_number
                
            # handle payload
            context = QuicReceiveContext(
                epoch=epoch,
                host_cid=header.destination_cid,
                network_path=self.network_path,
                quic_logger_frames=None, #quic_logger_frames,
                time=now,
                version=header.version,
            )
            
            try:
                #is_ack_eliciting, is_probing = \
                res_per_packet += self.handler.process_payload( context, plain_payload, crypto_frame_required=crypto_frame_required )
            except QuicConnectionError:
                pass

            if self.connection._state in END_STATES or self.connection._close_pending:
                return

            # update idle timeout
            self.connection._close_at = now + self.connection._idle_timeout()

        return res_per_packet
    

    def replay_msg(self, h3msg: Packet, is_moving: bool):
        """
        Replay QUIC and HTTP/3 packets by copying h3msg and capture responses.
        After capturing message, close 
        """

        builder = None

        # Build message by parsing h3msg
        builder = self.crafter.copy_msg(h3msg)
        self.send_quic_frames_from_builder(builder)

        response_packets = self.read_from_buffer()

        return response_packets

def main(
    configuration: QuicConfiguration,
    url: str,
    outdir: str,
    sample_msg: pyshark.FileCapture,
    keylog_file: str
) -> None:

    stma.modeller_h3(configuration, keylog_file, url, sample_msg, outdir)

def init(args):
    print("\n[STEP 1] Initializing...")
    os.system("sudo rm -r __pycache__")

    SERVER_ADDR = args.url
    pcapfile = args.pcap

    print("  [+] Initializing done!\n    => pcap : %s, SERVER_ADDR : %s" % (pcapfile, SERVER_ADDR))
    return


if __name__ == "__main__":
    install() # for beautiful tracebacks

    defaults = QuicConfiguration(is_client=True)
    keylog_file = None

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
        keylog_file = os.path.abspath(args.secrets_log) 
        configuration.secrets_log_file = open(keylog_file, "a")

    ### General setting ###
    init(args)
    
    ### Extract initial state machine ###
    http3_basic_messages = util.h3msg_from_pcap(args.pcap, client_only=True)

    main(
            configuration=configuration,
            url=args.url,
            outdir="./result",
            sample_msg = http3_basic_messages,
            keylog_file = keylog_file
        )
    
    