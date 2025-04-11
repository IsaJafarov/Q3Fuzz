import os
import sys
import time
import socket
import argparse
import ssl
import pyshark.packet
import pyshark.packet.fields
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
from pyshark.packet.layers.xml_layer import XmlLayer

# PRETT3 module
from handler import MSGHandler
from crafter import MSGCrafter
import util

class HttpClient():
    def __init__(self, quic_conf: QuicConfiguration, hostname: str) -> None:
        self.quic_conf = quic_conf
        self.quic_conf.original_version = 1
        self.quic_conf.server_name = hostname # OLS requires. normally set in async module's connect()
        self.hostname = hostname
        self.network_path = QuicNetworkPath(hostname)
        self.connection = QuicConnection(configuration=self.quic_conf)
        self._http = H3Connection(self.connection)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        self.sock.settimeout(0.1)
        self.handler = MSGHandler(qc = self.connection)
        self.msg_crafter = MSGCrafter(http_client=self)
        self.received_packet_numbers = set()
        self.ack_needed = True  # Flag to determine if an ACK should be sent against specific QUIC messages   TODO
        
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

        crypto_pair = self._http._quic._cryptos[epoch]

        quic_packet_type = None
        if epoch==Epoch.INITIAL: quic_packet_type = QuicPacketType.INITIAL
        elif epoch==Epoch.HANDSHAKE: quic_packet_type = QuicPacketType.HANDSHAKE
        elif epoch==Epoch.ONE_RTT: quic_packet_type = QuicPacketType.ONE_RTT
        
        builder.start_packet(quic_packet_type, crypto_pair) 
        self._http._quic._packet_number += 1
        return builder

    def serialize_transport_parameters(self, quic_transport_parameters:QuicTransportParameters=None) -> bytes:
        
        if quic_transport_parameters is None:
            # use default transport parameters
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
                initial_source_connection_id=self._http._quic._host_cids[0].cid,
                max_ack_delay=25,
                max_datagram_frame_size=self.quic_conf.max_datagram_frame_size,
                quantum_readiness=(
                    b"Q" * SMALLEST_MAX_DATAGRAM_SIZE
                    if self.quic_conf.quantum_readiness_test
                    else None
                ),
                stateless_reset_token=self._http._quic._host_cids[0].stateless_reset_token,
                version_information=QuicVersionInformation(
                    chosen_version=self.quic_conf.original_version,
                    available_versions=self.quic_conf.supported_versions,
                ),
            )
            
        buf = Buffer(capacity=3 * self._http._quic._max_datagram_size)
        push_quic_transport_parameters(buf, quic_transport_parameters)
        return buf.data

    def set_up_tls(self, transport_params:QuicTransportParameters=None) -> None:
        self._http._quic.tls = tls.Context(
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
        self._http._quic.tls.certificate = self.quic_conf.certificate
        self._http._quic.tls.certificate_chain = self.quic_conf.certificate_chain
        self._http._quic.tls.certificate_private_key = self.quic_conf.private_key
        self._http._quic.tls.handshake_extensions = [
            (
                tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS,
                self.serialize_transport_parameters(transport_params)
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
            self._http._quic.tls.session_ticket = self.quic_conf.session_ticket
            
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
        self._http._quic.tls.alpn_cb = self._http._quic._alpn_handler 
        if self._http._quic._session_ticket_fetcher is not None:
            self._http._quic.tls.get_session_ticket_cb = self._http._quic._session_ticket_fetcher
        if self._http._quic._session_ticket_handler is not None:
            self._http._quic.tls.new_session_ticket_cb = self._http._quic._handle_session_ticket
        self._http._quic.tls.update_traffic_key_cb = self._http._quic._update_traffic_key# update_traffic_key
        
        # packet spaces
        def create_crypto_pair(epoch: tls.Epoch) -> CryptoPair:
            
            epoch_name = ["initial", "0rtt", "handshake", "1rtt"][epoch.value]
            
            recv_secret_name = "server_%s_secret" % epoch_name
            send_secret_name = "client_%s_secret" % epoch_name
            return CryptoPair(
                recv_setup_cb=partial(self._http._quic._log_key_updated, recv_secret_name),
                recv_teardown_cb=partial(self._http._quic._log_key_retired, recv_secret_name),
                send_setup_cb=partial(self._http._quic._log_key_updated, send_secret_name),
                send_teardown_cb=partial(self._http._quic._log_key_retired, send_secret_name),
            )

        # To enable version negotiation, setup encryption keys for all
        # our supported versions.
        self._http._quic._cryptos_initial = {}
        for version in self.quic_conf.supported_versions:
            pair = CryptoPair()
            pair.setup_initial(cid=self._http._quic._peer_cid.cid, is_client=True, version=version)
            self._http._quic._cryptos_initial[version] = pair

        self._http._quic._cryptos = dict(
            (epoch, create_crypto_pair(epoch))
            for epoch in (
                tls.Epoch.ZERO_RTT,
                tls.Epoch.HANDSHAKE,
                tls.Epoch.ONE_RTT,
            )
        )
        self._http._quic._cryptos[tls.Epoch.INITIAL] = self._http._quic._cryptos_initial[self.quic_conf.original_version]

        self._http._quic._crypto_buffers = {
            tls.Epoch.INITIAL: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.HANDSHAKE: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.ONE_RTT: Buffer(capacity=CRYPTO_BUFFER_SIZE),
        }
        self._http._quic._crypto_streams = {
            tls.Epoch.INITIAL: QuicStream(),
            tls.Epoch.HANDSHAKE: QuicStream(),
            tls.Epoch.ONE_RTT: QuicStream(),
        }
        self._http._quic._spaces = {
            tls.Epoch.INITIAL: QuicPacketSpace(),
            tls.Epoch.HANDSHAKE: QuicPacketSpace(),
            tls.Epoch.ONE_RTT: QuicPacketSpace(),
        }

        self._http._quic._loss.spaces = list(self._http._quic._spaces.values())
    
    def connect(self, transport_params:QuicTransportParameters=None) -> None:
        """
        How aioquic's QuicConnection does it:
        initialize() sets up tls context
        handle_message() puts _client_send_hello message into the INITIAL's buffer in _crypto_buffers
        _push_crypto_data() writes data from the buffer to INITIAL's crypto stream in _crypto_streams
        datagrams_to_send() when called passes the builder to _write_handshake(), which adds the CRYPTO frame to it
        """

        crypto_buf = Buffer(capacity=CRYPTO_BUFFER_SIZE)

        self.set_up_tls(transport_params) # better to build tls myself to construct transport params myself
        
        self._http._quic.tls._client_send_hello(crypto_buf)
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

        epoch = Epoch.HANDSHAKE

        crypto_pair = self._http._quic._cryptos[epoch]
        if not crypto_pair.send.is_valid():
            self.close_local_socket()
            raise Exception("The Encoding crypto is not valid to send data. Is your server up?")
        
        builder = self.get_builder(epoch)

        # CRYPTO
        crypto_streams = self._http._quic._crypto_streams[Epoch.HANDSHAKE]
        
        crypto_frame = None
        # Wait till the server finishes sending all the CRYPTO data
        for i in range(30):
            crypto_frame = crypto_streams.sender.get_frame(1135)  # TODO: calculate max_size dynamically instead of giving static number
            if crypto_frame is not None: 
                break
            # time.sleep(0.1)
        else:
            self.close_local_socket()
            raise Exception("The Server did not send crypto data. Try again.")


        strm_data = crypto_frame.data
        buf = builder.start_frame(
                QuicFrameType.CRYPTO,
                capacity=4, 
            )
        buf.push_uint_var(0) # offset 
        buf.push_uint16( len(strm_data) | 0x4000) # length
        buf.push_bytes(strm_data) # data

        self.send_quic_frames_from_builder(builder)


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

    def send_quic_frames_from_builder(self, builder:QuicPacketBuilder) -> None:
        datagrams, packets = builder.flush()

        for data in datagrams:
            #print("Sending message: len={}".format( len(data) ))
            self.sock.sendto(data, (self.hostname, 443))

    def read_from_buffer(self) -> str:
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
                
                # print("Received message length: len={}".format(len(data)))

                res_per_packet = self.receive_datagram(data, now=time.process_time())
                #print()
                if res_per_packet and res_per_packet != '':
                    res += res_per_packet
                    res += ','
                    # res += '|'

        except socket.timeout:
            # Return parsed packets after timeout
            if res:
                res = res.rstrip(',')
                # res = res.rstrip('|')
            else:
                res="\u2298"
            return res

    def receive_datagram(self, data: bytes, now: float) -> str:
        """
        Process a received QUIC packet datagram and return any decrypted packet data.
        Also determines whether to send an ACK frame.

        Args:
            data: Raw data from the UDP socket.
            now: Current time to use in QUIC processing.

        Returns:
            decrypted_payload: List of decrypted QUIC or HTTP/3 layer from processed packets.
        """
        res_per_packet = ''
        buf = Buffer(data=data)
        packet_number = None  # Track the packet number for ACK
        context = None  # Track the last valid context

        while not buf.eof():
            start_off = buf.tell()

            # Step 1: Extract QUIC Header
            try:
                header = pull_quic_header(buf, host_cid_length=self.quic_conf.connection_id_length)
            except ValueError:
                return

            # Step 2: Handle special QUIC packets
            if header.packet_type == QuicPacketType.VERSION_NEGOTIATION:
                self._http._quic._receive_version_negotiation_packet(header=header, now=now)
                return

            if header.version is not None and header.version not in self.quic_conf.supported_versions:
                return

            if header.packet_type == QuicPacketType.RETRY:
                self.handle_retry_packet(header=header,
                    packet_without_tag=buf.data_slice(start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE))
                return

            # Step 3: Determine crypto and packet space
            epoch = get_epoch(header.packet_type)
            if epoch == tls.Epoch.INITIAL:
                crypto = self._http._quic._cryptos_initial[header.version]
            else:
                crypto = self._http._quic._cryptos[epoch]

            space = self._http._quic._spaces[epoch]  # FIXED: Keep 0-RTT separate

            # Step 4: Decrypt packet
            encrypted_off = buf.tell() - start_off
            end_off = start_off + header.packet_length
            buf.seek(end_off)

            try:
                plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                    data[start_off:end_off], encrypted_off, space.expected_packet_number
                )

            except KeyUnavailableError:
                if epoch in (tls.Epoch.HANDSHAKE, tls.Epoch.ONE_RTT) and not self._http._quic._crypto_retransmitted:
                    self._http._quic._loss.reschedule_data(now=now)
                    self._http._quic._crypto_retransmitted = True
                continue
            except CryptoError:
                continue

            # Step 5: Check reserved bits
            if header.packet_type == QuicPacketType.ONE_RTT:
                reserved_mask = 0x18
            else:
                reserved_mask = 0x0C
            if plain_header[0] & reserved_mask:
                self._http._quic.close(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=QuicFrameType.PADDING,
                    reason_phrase="Reserved bits must be zero",
                )
                return

            # Step 6: Validate Packet Number
            # if packet_number in self.received_packet_numbers:
            #     return  # Ignore duplicate packet

            self.received_packet_numbers.add(packet_number)  # Store received packet

            # Ensure expected_packet_number increases correctly
            if packet_number >= space.expected_packet_number:
                space.expected_packet_number = packet_number + 1

            # Step 7: Ensure correct connection state
            if self._http._quic._peer_cid.sequence_number is None:
                self._http._quic._peer_cid.cid = header.source_cid
                self._http._quic._peer_cid.sequence_number = 0

            if self._http._quic._state == QuicConnectionState.FIRSTFLIGHT:
                self._http._quic._remote_initial_source_connection_id = header.source_cid
                self._http._quic._set_state(QuicConnectionState.CONNECTED)

            # Step 8: Update spin bit 
            if header.packet_type == QuicPacketType.ONE_RTT and packet_number > self._http._quic._spin_highest_pn:
                spin_bit = get_spin_bit(plain_header[0])
                self._spin_bit = not spin_bit  # Toggle spin bit for clients
                self._spin_highest_pn = packet_number

            # Step 9: Process QUIC Payload
            context = QuicReceiveContext(
                epoch=epoch,
                host_cid=header.destination_cid,
                network_path=self.network_path,
                quic_logger_frames=None,  # Optional logging
                time=now,
                version=header.version,
            )

            try:
                res_per_packet += self.handler.process_quic_payload(context, plain_payload, crypto_frame_required=False) + ","
            except QuicConnectionError:
                pass

            if self._http._quic._state in END_STATES or self._http._quic._close_pending:
                return
            
            # Step 10: Determine if ACK should be sent based on `res_per_packet` and `self.ack_needed`
            # QUIC ACK should be sent in response to STREAM and CRYPTO
            if self.ack_needed and (epoch == tls.Epoch.ONE_RTT or epoch == tls.Epoch.HANDSHAKE):
                # If "ST" or "CRY" is present, trigger ACK
                if "ST" in res_per_packet or "CRY" in res_per_packet or "HD" in res_per_packet:
                    self.send_ack_frame(context, packet_number)

        return util.beautify_message_string(res_per_packet, exclude_opt_server_frames=True)

    def handle_retry_packet(self, header: QuicHeader, packet_without_tag: bytes) -> None:
        """
        Reinitialize connection, when the server sends RETRY type packet
        Caddy old does it.
        """
        #print("Reinitialize connection, because RETRY packet is received!")
    
        # The following line is from Aioquic's QuicConnection, but it causes a problem.
        # When it is uncommented, the Destination ID in the INITIAL packet changes, which is supposed to stay the same.
        # As a result, the server acks weird and the generated keylog file cannot decrypt the traffic.
        #self._http._quic._peer_cid.cid = header.source_cid
        self._http._quic._peer_token = header.token
        self._http._quic._retry_count += 1
        self._http._quic._retry_source_connection_id = header.source_cid

        self.connect()
        

    def set_ack_enabled(self, flag: bool) -> None:
        """
        Switch for en-/disabling auto-ack response per HttpClient.
        For state machine construction, the self.ack_needed is set to be True as default.
        For fuzzing, we may choose to either 
        - 'True' to follow the same transition as SM construciton) 
        - 'False' to ignore auto-ack for the special use.
        !!! This function MUST BE CALLED EVERY TIME we create HttpClient instance to DISABLE.
        """
        self.ack_needed = flag

    def send_ack_frame(self, context: QuicReceiveContext, largest_acknowledged: int) -> None:
        """Constructs and sends an ACK frame in response to received QUIC packets."""
        
        # Get the builder using existing get_builder() function
        builder = self.get_builder(context.epoch)
        buf = builder.start_frame(QuicFrameType.ACK, capacity=16)

        # Add ACK information
        buf.push_uint_var(largest_acknowledged)  # Largest acknowledged packet number
        buf.push_uint_var(0)  # ACK delay (set to 0 for now)
        buf.push_uint_var(0)  # ACK range count (assuming no gaps)
        buf.push_uint_var(0)  # First ACK range

        # Send the ACK frame using existing send_quic_frames_from_builder()
        self.send_quic_frames_from_builder(builder)

    # def receive_datagram(self, data:bytes, now:float) -> str:
    #     """
    #     Process a received QUIC datagram, decrypt and return any decrypted packet data.
        
    #     Args:
    #         data: Raw data from the UDP socket.
    #         now: Current time to use in QUIC processing.
            
    #     Returns:
    #         decrypted_payload: List of decrypted QUIC or HTTP/3 layer from processed packets.
    #     """
    #     res_per_packet = ''

    #     buf = Buffer(data=data)
        
    #     while not buf.eof():
  
    #         # print("\tQUIC layer #{}".format(i),end=" ")

    #         start_off = buf.tell()

    #         try:
    #             header = pull_quic_header(buf, host_cid_length=self.quic_conf.connection_id_length)
    #         except ValueError:
    #             return
    #         #print("(Type: {})".format(header.packet_type.name))

    #         ''' 
    #         This aioquic check causes a problem, when we send NEW_CONNECTIONS_ID frame in the test message 
    #         and the server responds to that new destination ID

    #         # Check destination CID matches.
    #         destination_cid_seq: Optional[int] = None
    #         for connection_id in self._http._quic._host_cids:
    #             if header.destination_cid == connection_id.cid:
    #                 destination_cid_seq = connection_id.sequence_number
    #                 break
    #         if destination_cid_seq is None:
    #             print("asas")
    #             return 
    #         '''

    #         # Handle version negotiation packet.
    #         if header.packet_type == QuicPacketType.VERSION_NEGOTIATION:
    #             self._http._quic._receive_version_negotiation_packet(header=header, now=now)
    #             return
            
    #         # Check long header packet protocol version.
    #         if (
    #             header.version is not None
    #             and header.version not in self.quic_conf.supported_versions
    #         ):
    #             return
            
    #         # Handle retry packet.
    #         if header.packet_type == QuicPacketType.RETRY:
    #             self.handler.handle_retry_packet(header=header,
    #                 packet_without_tag=buf.data_slice(
    #                     start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE
    #                 ))
    #             return

            
    #         crypto_frame_required = False

    #         # Determine crypto and packet space.
    #         epoch = get_epoch(header.packet_type)
    #         if epoch == tls.Epoch.INITIAL:
    #             crypto = self._http._quic._cryptos_initial[header.version]
    #         else:
    #             crypto = self._http._quic._cryptos[epoch]
    #         if epoch == tls.Epoch.ZERO_RTT:
    #             space = self._http._quic._spaces[tls.Epoch.ZERO_RTT]  # Keep separate space
    #         else:
    #             space = self._http._quic._spaces[epoch] # Keep separate space


    #         # decrypt packet
    #         encrypted_off = buf.tell() - start_off
    #         end_off = start_off + header.packet_length
    #         buf.seek(end_off)

    #         try:
    #             plain_header, plain_payload, packet_number = crypto.decrypt_packet(
    #                     data[start_off:end_off], encrypted_off, space.expected_packet_number)

    #         except KeyUnavailableError as exc:
    #             # If a client receives HANDSHAKE or 1-RTT packets before it has
    #             # handshake keys, it can assume that the server's INITIAL was lost.
    #             if (
    #                 epoch in (tls.Epoch.HANDSHAKE, tls.Epoch.ONE_RTT)
    #                 and not self._http._quic._crypto_retransmitted
    #             ):
    #                 self._http._quic._loss.reschedule_data(now=now)
    #                 self._http._quic._crypto_retransmitted = True
    #             continue
    #         except CryptoError as exc:
    #             continue
            
    #         #print("Received packet: \n\tPacket Number={}\n\tPlain Header={}\n\tPlain Payload={}".format(packet_number, plain_header, plain_payload))
            
    #         # check reserved bits
    #         if header.packet_type == QuicPacketType.ONE_RTT:
    #             reserved_mask = 0x18
    #         else:
    #             reserved_mask = 0x0C
    #         if plain_header[0] & reserved_mask:
    #             self._http._quic.close(
    #                 error_code=QuicErrorCode.PROTOCOL_VIOLATION,
    #                 frame_type=QuicFrameType.PADDING,
    #                 reason_phrase="Reserved bits must be zero",)
    #             return


    #         # raise expected packet number
    #         if packet_number > space.expected_packet_number:
    #             space.expected_packet_number = packet_number + 1

    #         # update state
    #         if self._http._quic._peer_cid.sequence_number is None:
    #             self._http._quic._peer_cid.cid = header.source_cid
    #             self._http._quic._peer_cid.sequence_number = 0

    #         if self._http._quic._state == QuicConnectionState.FIRSTFLIGHT:
    #             self._http._quic._remote_initial_source_connection_id = header.source_cid
    #             self._http._quic._set_state(QuicConnectionState.CONNECTED)

    #         # update spin bit
    #         if (header.packet_type == QuicPacketType.ONE_RTT
    #             and packet_number > self._http._quic._spin_highest_pn):
                
    #             spin_bit = get_spin_bit(plain_header[0])
    #             self._spin_bit = not spin_bit # for clients
    #             self._spin_highest_pn = packet_number
                
    #         # handle payload
    #         context = QuicReceiveContext(
    #             epoch=epoch,
    #             host_cid=header.destination_cid,
    #             network_path=self.network_path,
    #             quic_logger_frames=None, #quic_logger_frames,
    #             time=now,
    #             version=header.version,
    #         )
            
    #         try:
    #             res_per_packet += self.handler.process_quic_payload( context, plain_payload, crypto_frame_required=crypto_frame_required )+","
    #         except QuicConnectionError:
    #             pass

    #         if self._http._quic._state in END_STATES or self._http._quic._close_pending:
    #             return

    #         # update idle timeout
    #         self._http._quic._close_at = now + self._http._quic._idle_timeout()

    #     return util.beautify_message_string(res_per_packet, False)

    def replay_msg(self, h3msg:Packet, exclude_ack:bool = False) -> str:
        """
        Replay QUIC and HTTP/3 packets by copying h3msg and capture responses.
        """
        
        # Build message by parsing h3msg
        builder = self.get_builder(Epoch.ONE_RTT)
        self.msg_crafter.copy_msg(h3msg, builder, exclude_ack)
        self.send_quic_frames_from_builder(builder)

        response_packets = self.read_from_buffer()

        return response_packets
    
    def send_frames(self, quic_frames:List) -> str:
        """
        Send the QUIC and HTTP/3 frames in a packet and capture responses.
        """
        
        # Build message by parsing h3msg
        builder = self.get_builder(Epoch.ONE_RTT)
        self.msg_crafter.craft_msg_from_frames(quic_frames, builder)
        self.send_quic_frames_from_builder(builder)

        response_packets = self.read_from_buffer()
        #print("Received response: {}".format(response_packets))

        return response_packets

    def close_connection(self) -> None:

        builder = self.get_builder(Epoch.ONE_RTT)

        reason = "closed by prett3".encode("utf8")

        buf = builder.start_frame(
            QuicFrameType.TRANSPORT_CLOSE,
            capacity=TRANSPORT_CLOSE_FRAME_CAPACITY + len(reason),
        )
        buf.push_uint_var(QuicErrorCode.APPLICATION_ERROR)
        buf.push_uint_var(QuicFrameType.PADDING)
        buf.push_uint_var(len(reason))
        buf.push_bytes(reason)

        self.send_quic_frames_from_builder(builder=builder)
        #self.read_from_buffer()
        
        self.close_local_socket()
        self.received_packet_numbers.clear()

    def close_local_socket(self) -> None:

        self.sock.close()
        
