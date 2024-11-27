#! /usr/bin/env python
import os
import time
import socket
import logging
import argparse
import ssl
import io
import traceback

import aioquic.quic
import aioquic.quic.rangeset
import pyshark
import asyncio
import aioquic
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN, H3Connection, FrameType, encode_frame, encode_settings, StreamType
from aioquic.h3.events import DataReceived, HeadersReceived, H3Event, PushPromiseReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.packet_builder import QuicPacketBuilder
from aioquic.quic.packet import QuicFrameType, QuicPacketType
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.connection import QuicConnection, QuicNetworkPath
from aioquic.quic.rangeset import RangeSet
from aioquic.tls import CipherSuite, Epoch

# PRETT3 project module
import util  
from states import StateList, State
import statemachine as stma
from transitions.extensions import GraphMachine as Machine
from aioquic.quic.connection import *
from rich.traceback import install

PRIORITY_UPDATE_FRAME_TYPE = 0x800f0700

class HttpClient():
    def __init__(self, quic_conf: QuicConfiguration, hostname: str, keylog_file: str) -> None:
        self.quic_conf = quic_conf
        self.quic_conf.original_version = 1
        self.hostname = hostname
        self.quic_conf.server_name = hostname # OLS requires. normally set in async module's connect()
        self.network_path = QuicNetworkPath(hostname)
        self._quic = QuicConnection(configuration=self.quic_conf)
        self._http = H3Connection(self._quic)
        self.sock = None
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

        
        crypto_pair = self._quic._cryptos[epoch] 

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
            initial_source_connection_id=self._quic._host_cids[0].cid,
            max_ack_delay=25,
            max_datagram_frame_size=self.quic_conf.max_datagram_frame_size,
            quantum_readiness=(
                b"Q" * SMALLEST_MAX_DATAGRAM_SIZE
                if self.quic_conf.quantum_readiness_test
                else None
            ),
            stateless_reset_token=self._quic._host_cids[0].stateless_reset_token,
            version_information=QuicVersionInformation(
                chosen_version=self.quic_conf.original_version,
                available_versions=self.quic_conf.supported_versions,
            ),
        )
        # print(">>> prett3.serialize_transport_parameters. quic_transport_parameters={}".format(quic_transport_parameters))

        buf = Buffer(capacity=3 * self._quic._max_datagram_size)
        push_quic_transport_parameters(buf, quic_transport_parameters)
        return buf.data

    def get_tls(self) -> None:
        # TLS
        self._quic.tls = tls.Context(
            alpn_protocols=self.quic_conf.alpn_protocols,
            cadata=self.quic_conf.cadata,
            cafile=self.quic_conf.cafile,
            capath=self.quic_conf.capath,
            cipher_suites=self.quic_conf.cipher_suites,
            is_client=True,
            #logger=self._logger,
            max_early_data=None, # None if self._is_client else MAX_EARLY_DATA
            server_name=self.quic_conf.server_name,
            verify_mode=self.quic_conf.verify_mode,
        )
        self._quic.tls.certificate = self.quic_conf.certificate
        self._quic.tls.certificate_chain = self.quic_conf.certificate_chain
        self._quic.tls.certificate_private_key = self.quic_conf.private_key
        self._quic.tls.handshake_extensions = [
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
            self._quic.tls.session_ticket = self.quic_conf.session_ticket
            
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
        self._quic.tls.alpn_cb = self._quic._alpn_handler 
        if self._quic._session_ticket_fetcher is not None:
            self._quic.tls.get_session_ticket_cb = self._quic._session_ticket_fetcher
        if self._quic._session_ticket_handler is not None:
            self._quic.tls.new_session_ticket_cb = self._quic._handle_session_ticket
        self._quic.tls.update_traffic_key_cb = self._quic._update_traffic_key# update_traffic_key
        

        # packet spaces
        def create_crypto_pair(epoch: tls.Epoch) -> CryptoPair:
            # print(">>> prett3.get_tls.create_crypto_pair: start. epoch={}".format(epoch))
            epoch_name = ["initial", "0rtt", "handshake", "1rtt"][epoch.value]
            
            recv_secret_name = "server_%s_secret" % epoch_name
            send_secret_name = "client_%s_secret" % epoch_name
            return CryptoPair(
                recv_setup_cb=partial(self._quic._log_key_updated, recv_secret_name),
                recv_teardown_cb=partial(self._quic._log_key_retired, recv_secret_name),
                send_setup_cb=partial(self._quic._log_key_updated, send_secret_name),
                send_teardown_cb=partial(self._quic._log_key_retired, send_secret_name),
            )

        # To enable version negotiation, setup encryption keys for all
        # our supported versions.
        self._quic._cryptos_initial = {}
        for version in self.quic_conf.supported_versions:
            pair = CryptoPair()
            pair.setup_initial(cid=self._quic._peer_cid.cid, is_client=True, version=version)
            self._quic._cryptos_initial[version] = pair

        self._quic._cryptos = dict(
            (epoch, create_crypto_pair(epoch))
            for epoch in (
                tls.Epoch.ZERO_RTT,
                tls.Epoch.HANDSHAKE,
                tls.Epoch.ONE_RTT,
            )
        )
        self._quic._cryptos[tls.Epoch.INITIAL] = self._quic._cryptos_initial[self.quic_conf.original_version]

        self._quic._crypto_buffers = {
            tls.Epoch.INITIAL: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.HANDSHAKE: Buffer(capacity=CRYPTO_BUFFER_SIZE),
            tls.Epoch.ONE_RTT: Buffer(capacity=CRYPTO_BUFFER_SIZE),
        }
        self._quic._crypto_streams = {
            tls.Epoch.INITIAL: QuicStream(),
            tls.Epoch.HANDSHAKE: QuicStream(),
            tls.Epoch.ONE_RTT: QuicStream(),
        }
        self._quic._spaces = {
            tls.Epoch.INITIAL: QuicPacketSpace(),
            tls.Epoch.HANDSHAKE: QuicPacketSpace(),
            tls.Epoch.ONE_RTT: QuicPacketSpace(),
        }

        self._quic._loss.spaces = list(self._quic._spaces.values())
    
    def connect(self):
        """
        How aioquic's QuicConnection does it:
        initialize() sets up tls context
        handle_message() puts _client_send_hello message into the INITIAL's buffer in _crypto_buffers
        _push_crypto_data() writes data from the buffer to INITIAL's crypto stream in _crypto_streams
        datagrams_to_send() when called passes the builder to _write_handshake(), which adds the CRYPTO frame to it
        """

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        self.sock.settimeout(0.4)
        
        crypto_buf = Buffer(capacity=CRYPTO_BUFFER_SIZE)

        self.get_tls() # better to build tls myself to construct transport params myself
        
        self._quic.tls._client_send_hello(crypto_buf)
        
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

    def craft_sample_headers_frame(self):
        """
        Craft a sample HEADERS frame
        """
        
        #print("\nCrafting a sample HEADERS frame")
        stream_id = self._quic.get_next_available_stream_id()

        headers = [
                (b":method", "GET".encode()),
                (b":scheme", "HTTPS".encode()),
                (b":authority", self.hostname.encode()),
                (b":path", "/".encode()),
                (b"user-agent", "PRETT3 Client".encode()),
                (b"accept", "AAA".encode())
            ]

        frame_data =  self._http._encode_headers(stream_id, headers)

        return stream_id, aioquic.h3.connection.encode_frame(FrameType.HEADERS, frame_data)

    def handle_crypto(self, context: QuicReceiveContext, frame_type: int, buf:Buffer):

        offset = buf.pull_uint_var()
        length = buf.pull_uint_var()
        data = buf.pull_bytes(length)
        print(("\033[31mCRYPTO frame received. " +
                  "Offset={}, " +
                  "Length={}, " +
                  "Crypto Data={} \033[0m")
            .format(offset, length, data ))
        
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError( error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=frame_type, reason_phrase="offset + length cannot exceed 2^62 - 1")
        frame = QuicStreamFrame(offset=offset, data=data)
        
        stream = self._quic._crypto_streams[context.epoch]
        pending = offset + length - stream.receiver.starting_offset()
        if pending > MAX_PENDING_CRYPTO:
            raise QuicConnectionError(
                error_code=QuicErrorCode.CRYPTO_BUFFER_EXCEEDED,
                frame_type=frame_type,
                reason_phrase="too much crypto buffering",
            )
        
        event = stream.receiver.handle_frame(frame)
        if event is not None:
            # Pass data to TLS layer, which may cause calls to:
            # - _alpn_handler
            # - _update_traffic_key
            self._quic._crypto_frame_type = frame_type
            self._quic._crypto_packet_version = context.version
            try:
                self._quic.tls.handle_message(event.data, self._quic._crypto_buffers)
                self._quic._push_crypto_data()
            except tls.Alert as exc:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.CRYPTO_ERROR + int(exc.description),
                    frame_type=frame_type,
                    reason_phrase=str(exc),
                )

            # Update the current epoch.
            if not self._quic._handshake_complete and self._quic.tls.state in [
                tls.State.CLIENT_POST_HANDSHAKE,
                tls.State.SERVER_POST_HANDSHAKE,
            ]:
                self._quic._handshake_complete = True

                # for servers, the handshake is now confirmed
                self._quic._replenish_connection_ids()
                self._quic._events.append(
                    events.HandshakeCompleted(
                        alpn_protocol=self._quic.tls.alpn_negotiated,
                        early_data_accepted=self._quic.tls.early_data_accepted,
                        session_resumed=self._quic.tls.session_resumed,
                    )
                )
                self._quic._unblock_streams(is_unidirectional=False)
                self._quic._unblock_streams(is_unidirectional=True)
                self._quic._logger.info(
                    "ALPN negotiated protocol %s", self._quic.tls.alpn_negotiated
                )

    def handle_padding_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PADDING frame.
        """
        print("\033[31m\nPADDING frame received\033[0m".format())

        """
        # consume padding
        pos = buf.tell()
        for byte in buf.data_slice(pos, buf.capacity):
            if byte:
                break
            pos += 1
        buf.seek(pos)
        """

    def handle_ping_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PING frame.
        """
        print("\033[31m\nPING frame received\033[0m".format())

    def handle_ack_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle an ACK frame.
        """

        def pull_ack_frame(buf: Buffer) -> Tuple[RangeSet, int]:
            rangeset = RangeSet()
            end = buf.pull_uint_var()  # largest acknowledged
            delay = buf.pull_uint_var()
            ack_range_count = buf.pull_uint_var()
            ack_count = buf.pull_uint_var()  # first ack range
            rangeset.add(end - ack_count, end + 1)
            
            print(("\033[31m\nACK frame received. " +
                  "Largest Acknowledged={}, " +
                  "Ack Delay={}, " +
                  "Ack Range Count={}, " +
                  "First Ack Range={} \033[0m")
            .format(end, delay, ack_range_count, ack_count ))
            
            end -= ack_count
            for _ in range(ack_range_count):
                end -= buf.pull_uint_var() + 2
                ack_count = buf.pull_uint_var()
                rangeset.add(end - ack_count, end + 1)
                end -= ack_count
            
            
            return rangeset, delay

        ack_rangeset, ack_delay_encoded = pull_ack_frame(buf)
        if frame_type == QuicFrameType.ACK_ECN:
            buf.pull_uint_var()
            buf.pull_uint_var()
            buf.pull_uint_var()
        ack_delay = (ack_delay_encoded << self._quic._remote_ack_delay_exponent) / 1000000


        
        
        '''
        # check whether peer completed address validation
        if not self._quic._loss.peer_completed_address_validation and context.epoch in (
            tls.Epoch.HANDSHAKE,
            tls.Epoch.ONE_RTT,
        ):
            self._quic._loss.peer_completed_address_validation = True

        self._quic._loss.on_ack_received(
            ack_rangeset=ack_rangeset,
            ack_delay=ack_delay,
            now=context.time,
            space=self._quic._spaces[context.epoch],
        )
        '''

    def handle_reset_stream_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RESET_STREAM frame.
        """
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()
        final_size = buf.pull_uint_var()

        print("\033[31m\nRESET_STREAM frame received. Stream ID={}, Error Code={}, Final Size={}\033[0m"
              .format(stream_id, error_code, final_size))

        """
        # check stream direction
        self._quic._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._quic._get_or_create_stream(frame_type, stream_id)
        if final_size > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, final_size - stream.receiver.highest_offset)
        if self._quic._local_max_data.used + newly_received > self._quic._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        try:
            event = stream.receiver.handle_reset(
                error_code=error_code, final_size=final_size
            )
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._quic._events.append(event)
        self._quic._local_max_data.used += newly_received
        """

    def handle_stop_sending_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STOP_SENDING frame.
        """
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()  # application error code

        print("\033[31m\nSTOP_SENDING frame received. Stream ID={}, Error Code={}\033[0m"
              .format(stream_id, error_code))

        """
        # check stream direction
        self._quic._assert_stream_can_send(frame_type, stream_id)

        # reset the stream
        stream = self._quic._get_or_create_stream(frame_type, stream_id)
        stream.sender.reset(error_code=QuicErrorCode.NO_ERROR)

        self._quic._events.append(
            events.StopSendingReceived(error_code=error_code, stream_id=stream_id)
        )
        """

    def handle_new_token_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_TOKEN frame.
        """
        length = buf.pull_uint_var()
        token = buf.pull_bytes(length)

        print("\033[31m\nRESET_STREAM frame received. Length={}, Token={}\033[0m"
              .format(length, token))

        """
        if not self._quic._is_client:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Clients must not send NEW_TOKEN frames",
            )

        if self._quic._token_handler is not None:
            self._quic._token_handler(token)
        """

    def handle_stream_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM frame.
        """
        stream_id = buf.pull_uint_var()
        if frame_type & 4:
            offset = buf.pull_uint_var()
        else:
            offset = 0
        if frame_type & 2:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - buf.tell()
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="offset + length cannot exceed 2^62 - 1",
            )
        data=buf.pull_bytes(length)
        frame = QuicStreamFrame(
            offset=offset, data=data, fin=bool(frame_type & 1)
        )
        
        print("\033[31m\nSTREAM frame received. Stream ID={}, Offset={}, Length={}, Stream Data={}\033[0m"
              .format(stream_id, offset, length, data))
        
        """
        # check stream direction
        self._quic._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._quic._get_or_create_stream(frame_type, stream_id)
        if offset + length > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, offset + length - stream.receiver.highest_offset)
        if self._quic._local_max_data.used + newly_received > self._quic._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        # process data
        try:
            event = stream.receiver.handle_frame(frame)
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._quic._events.append(event)
        self._quic._local_max_data.used += newly_received
        """

    def handle_max_data_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_DATA frame.

        This adjusts the total amount of we can send to the peer.
        """
        max_data = buf.pull_uint_var()
        
        print("\033[31m\nMAX_DATA frame received. MAX DATA={}\033[0m"
              .format(max_data))

        """
        if max_data > self._remote_max_data:
            self._remote_max_data = max_data
        """

    def handle_max_stream_data_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAM_DATA frame.

        This adjusts the amount of data we can send on a specific stream.
        """
        stream_id = buf.pull_uint_var()
        max_stream_data = buf.pull_uint_var()

        print("\033[31m\nMAX_STREAM_DATA frame received. Stream ID={}, Max Stream Data={}\033[0m"
              .format(stream_id, max_stream_data))

        """
        # check stream direction
        self._quic._assert_stream_can_send(frame_type, stream_id)

        stream = self._quic._get_or_create_stream(frame_type, stream_id)
        if max_stream_data > stream.max_stream_data_remote:
            stream.max_stream_data_remote = max_stream_data
        """

    def handle_max_streams_bidi_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_BIDI frame.

        This raises number of bidirectional streams we can initiate to the peer.
        """
        max_streams = buf.pull_uint_var()
        if max_streams > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        print("\033[31m\nSTREAM frame received. Stream ID={}, Offset={}, Length={}, Stream Data={}\033[0m"
              .format(stream_id, offset, length, data))

        """
        if max_streams > self._remote_max_streams_bidi:
            self._remote_max_streams_bidi = max_streams
            self._quic._unblock_streams(is_unidirectional=False)
        """

    def handle_max_streams_uni_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_UNI frame.

        This raises number of unidirectional streams we can initiate to the peer.
        """
        max_streams = buf.pull_uint_var()
        if max_streams > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        """
        if max_streams > self._remote_max_streams_uni:
            self._remote_max_streams_uni = max_streams
            self._quic._unblock_streams(is_unidirectional=True)
        """

    def handle_data_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATA_BLOCKED frame.
        """
        limit = buf.pull_uint_var()

        print("\033[31m\nDATA_BLOCKED  frame received. Limit={}\033[0m"
              .format(limit))

    def handle_stream_data_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM_DATA_BLOCKED frame.
        """
        stream_id = buf.pull_uint_var()
        limit = buf.pull_uint_var()

        print("\033[31m\nSTREAM_DATA_BLOCKED frame received. Stream ID={}, Limit={}\033[0m"
              .format(stream_id, limit))
        
        """
        # check stream direction
        self._quic._assert_stream_can_receive(frame_type, stream_id)

        self._quic._get_or_create_stream(frame_type, stream_id)
        """

    def handle_streams_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAMS_BLOCKED frame.
        """
        limit = buf.pull_uint_var()

        print("\033[31m\nSTREAMS_BLOCKED frame received. Limit={}\033[0m"
              .format(limit))
        
        """
        if limit > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )
        """
    
    def handle_new_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_CONNECTION_ID frame.
        """
        sequence_number = buf.pull_uint_var()
        retire_prior_to = buf.pull_uint_var()
        length = buf.pull_uint8()
        connection_id = buf.pull_bytes(length)
        stateless_reset_token = buf.pull_bytes(STATELESS_RESET_TOKEN_SIZE)
        
        print("\033[31m\nNEW_CONNECTION_ID frame received. Sequence Number={}, Retire Prior To={}, Length={}, Connection Id={}, stateless Reset Token\033[0m"
              .format(sequence_number, retire_prior_to, length, connection_id, stateless_reset_token))

        """
        if not connection_id or len(connection_id) > CONNECTION_ID_MAX_SIZE:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Length must be greater than 0 and less than 20",
            )


        # sanity check
        if retire_prior_to > sequence_number:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Retire Prior To is greater than Sequence Number",
            )

        # only accept retire_prior_to if it is bigger than the one we know
        self._quic._peer_retire_prior_to = max(retire_prior_to, self._quic._peer_retire_prior_to)

        # determine which CIDs to retire
        change_cid = False
        retire = [
            cid
            for cid in self._quic._peer_cid_available
            if cid.sequence_number < self._quic._peer_retire_prior_to
        ]
        if self._quic._peer_cid.sequence_number < self._quic._peer_retire_prior_to:
            change_cid = True
            retire.insert(0, self._peer_cid)

        # update available CIDs
        self._quic._peer_cid_available = [
            cid
            for cid in self._quic._peer_cid_available
            if cid.sequence_number >= self._quic._peer_retire_prior_to
        ]
        if (
            sequence_number >= self._quic._peer_retire_prior_to
            and sequence_number not in self._quic._peer_cid_sequence_numbers
        ):
            self._quic._peer_cid_available.append(
                QuicConnectionId(
                    cid=connection_id,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )
            self._quic._peer_cid_sequence_numbers.add(sequence_number)

        # retire previous CIDs
        for quic_connection_id in retire:
            self._quic._retire_peer_cid(quic_connection_id)

        # assign new CID if we retired the active one
        if change_cid:
            self._quic._consume_peer_cid()

        # check number of active connection IDs, including the selected one
        if 1 + len(self._quic._peer_cid_available) > self._quic._local_active_connection_id_limit:
            raise QuicConnectionError(
                error_code=QuicErrorCode.CONNECTION_ID_LIMIT_ERROR,
                frame_type=frame_type,
                reason_phrase="Too many active connection IDs",
            )

        # Check the number of retired connection IDs pending, though with a safer limit
        # than the 2x recommended in section 5.1.2 of the RFC.  Note that we are doing
        # the check here and not in _retire_peer_cid() because we know the frame type to
        # use here, and because it is the new connection id path that is potentially
        # dangerous.  We may transiently go a bit over the limit due to unacked frames
        # getting added back to the list, but that's ok as it is bounded.
        if len(self._quic._retire_connection_ids) > min(
            self._quic._local_active_connection_id_limit * 4, MAX_PENDING_RETIRES
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.CONNECTION_ID_LIMIT_ERROR,
                frame_type=frame_type,
                reason_phrase="Too many pending retired connection IDs",
            )
        """

    def handle_retire_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RETIRE_CONNECTION_ID frame.
        """
        sequence_number = buf.pull_uint_var()
        
        print("\033[31m\nRETIRE_CONNECTION_ID frame received. Sequence Number={}\033[0m"
              .format(sequence_number))

        """
        if sequence_number >= self._quic._host_cid_seq:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Cannot retire unknown connection ID",
            )

        # find the connection ID by sequence number
        for index, connection_id in enumerate(self._quic._host_cids):
            if connection_id.sequence_number == sequence_number:
                if connection_id.cid == context.host_cid:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                        frame_type=frame_type,
                        reason_phrase="Cannot retire current connection ID",
                    )
                del self._quic._host_cids[index]
                self._quic._events.append(
                    events.ConnectionIdRetired(connection_id=connection_id.cid)
                )
                break

        # issue a new connection ID
        self._quic._replenish_connection_ids()
        """

    def handle_path_challenge_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_CHALLENGE frame.
        """
        data = buf.pull_bytes(8)

        print("\033[31m\nPATH_CHALLENGE frame received. Data={}\033[0m"
              .format(data))

        """
        context.network_path.remote_challenges.append(data)
        """

    def handle_path_response_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_RESPONSE frame.
        """
        data = buf.pull_bytes(8)

        print("\033[31m\nSTREAM frame received. Data={}\033[0m"
              .format(data))

        """
        try:
            network_path = self._quic._local_challenges.pop(data)
        except KeyError:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Response does not match challenge",
            )
        network_path.is_validated = True
        """

    def handle_connection_close_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a CONNECTION_CLOSE frame.
        """
        error_code = buf.pull_uint_var()
        if frame_type == QuicFrameType.TRANSPORT_CLOSE:
            frame_type = buf.pull_uint_var()
        else:
            frame_type = None
        reason_length = buf.pull_uint_var()
        try:
            reason_phrase = buf.pull_bytes(reason_length).decode("utf8")
        except UnicodeDecodeError:
            reason_phrase = ""

        print("\033[31m\nCONNECTION_CLOSE frame received. Error Code={}, Frame Type={}, Reason Phrase Length={}, Reason Phrase={}\033[0m"
              .format(error_code, frame_type, reason_length, reason_phrase))

        """
        if self._quic._close_event is None:
            self._quic._close_event = events.ConnectionTerminated(
                error_code=error_code,
                frame_type=frame_type,
                reason_phrase=reason_phrase,
            )
            self._quic._close_begin(is_initiator=False, now=context.time)
        """

    def handle_handshake_done_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a HANDSHAKE_DONE frame.
        """
        print("\033[31m\nHANDSHAKE DONE frame received\033[0m"
              .format())
        """
        # for clients, the handshake is now confirmed
        if not self._quic._handshake_confirmed:
            self._quic._discard_epoch(tls.Epoch.HANDSHAKE)
            self._quic._handshake_confirmed = True
            self._quic._loss.peer_completed_address_validation = True
        """

    def handle_datagram_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATAGRAM frame.
        """
        start = buf.tell()
        if frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - start
        data = buf.pull_bytes(length)

        print("\033[31m\nDATAGRAM frame received. Length={}, Data={}\033[0m"
              .format(length, data))

        """
        # check frame is allowed
        if (
            self._quic._configuration.max_datagram_frame_size is None
            or buf.tell() - start >= self._quic._configuration.max_datagram_frame_size
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Unexpected DATAGRAM frame",
            )

        self._quic._events.append(events.DatagramFrameReceived(data=data))
        """

    def process_payload(self, context: QuicReceiveContext, plain: bytes, crypto_frame_required: bool = False) -> Tuple[bool, bool]:
        
        buf = Buffer(data=plain)

        crypto_frame_found = False
        frame_found = False
        is_ack_eliciting = False
        is_probing = None
        i=0
        while not buf.eof():
            i+=1
            #print("\t\tFrame #{}".format(i))

            # get frame type
            try:
                frame_type = buf.pull_uint_var()
            except BufferReadError:
                raise QuicConnectionError( error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=None, reason_phrase="Malformed frame type")
            #print(">>> prett3.process_payload: frame #{}, type={}".format(i, frame_type))

            # handle the frame
            
            try:
                # a condition for each frame type can be added
                if frame_type==0x00: # PADDING frame
                    continue
                elif frame_type==0x01:
                    self.handle_ping_frame(context, frame_type, buf)

                elif frame_type in [0x02, 0x03]:
                    self.handle_ack_frame(context, frame_type, buf)

                elif frame_type==0x04:
                    self.handle_reset_stream_frame(context, frame_type, buf)
                
                elif frame_type==0x05:
                    self.handle_stop_sending_frame(context, frame_type, buf)

                elif frame_type==0x06: # CRYPTO frame
                    self.handle_crypto(context, frame_type, buf)

                elif frame_type==0x07:
                    self.handle_new_token_frame(context, frame_type, buf)
                
                elif frame_type >= 0x08 and frame_type <= 0x0F: # STREAM frame
                    self.handle_stream_frame(context, frame_type, buf)
                
                elif frame_type==0x10:
                    self.handle_max_data_frame(context, frame_type, buf)
                
                elif frame_type==0x11:
                    self.handle_max_stream_data_frame(context, frame_type, buf)

                elif frame_type==0x12:
                    self.handle_max_streams_bidi_frame(context, frame_type, buf)

                elif frame_type==0x13:
                    self.handle_max_streams_uni_frame(context, frame_type, buf)

                elif frame_type==0x14:
                    self.handle_data_blocked_frame(context, frame_type, buf)

                elif frame_type==0x15:
                    self.handle_stream_data_blocked_frame(context, frame_type, buf)

                elif frame_type in [0x16, 0x17]:
                    self.handle_streams_blocked_frame(context, frame_type, buf)

                elif frame_type==0x18:
                    self.handle_new_connection_id_frame(context, frame_type, buf)
                
                elif frame_type==0x19:
                    self.handle_retire_connection_id_frame(context, frame_type, buf)

                elif frame_type==0x1A:
                    self.handle_path_challenge_frame(context, frame_type, buf)

                elif frame_type==0x1B:
                    self.handle_path_response_frame(context, frame_type, buf)

                elif frame_type==0x1C:
                    self.handle_connection_close_frame(context, frame_type, buf)

                elif frame_type==0x1E:
                    self.handle_handshake_done_frame(context, frame_type, buf)

                elif frame_type in [0x30, 0x31]:
                    self.handle_datagram_frame(context, frame_type, buf)


                elif frame_type>0x31:
                    raise QuicConnectionError(error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=frame_type, reason_phrase="Unknown frame type")
            except BufferReadError:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Failed to parse frame",
                )
            except StreamFinishedError:
                # we lack the state for the stream, ignore the frame
                pass
            

            # update ACK only / probing flags
            frame_found = True

            if frame_type == QuicFrameType.CRYPTO:
                crypto_frame_found = True

            if frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
                is_ack_eliciting = True

            if frame_type not in PROBING_FRAME_TYPES:
                is_probing = False
            elif is_probing is None:
                is_probing = True
        
        return is_ack_eliciting, bool(is_probing)

    def handle_retry_packet(self, header: QuicHeader, packet_without_tag: bytes) -> None:
        """
        Reinitialize connection, when the server sends RETRY type packet
        Caddy old does it.
        """
        #print("Reinitialize connection, because RETRY packet is received!")
        self._quic._peer_cid.cid = header.source_cid
        self._quic._peer_token = header.token
        self._quic._retry_count += 1
        self._quic._retry_source_connection_id = header.source_cid
        self.connect()

    def receive_datagram(self, data: bytes, now: float) -> None:

        buf = Buffer(data=data)
        i=0
        while not buf.eof():
            i+=1
            #print("\tQUIC layer #{}".format(i),end=" ")

            start_off = buf.tell()

            try:
                header = pull_quic_header(buf, host_cid_length=self.quic_conf.connection_id_length)
            except ValueError:
                return
            #print("(Type: {})".format(header.packet_type.name))

            # Check destination CID matches.
            destination_cid_seq: Optional[int] = None
            for connection_id in self._quic._host_cids:
                if header.destination_cid == connection_id.cid:
                    destination_cid_seq = connection_id.sequence_number
                    break
            if destination_cid_seq is None:
                return

            # Handle version negotiation packet.
            if header.packet_type == QuicPacketType.VERSION_NEGOTIATION:
                self._quic._receive_version_negotiation_packet(header=header, now=now)
                return

            # Check long header packet protocol version.
            if (
                header.version is not None
                and header.version not in self.quic_conf.supported_versions
            ):
                return
            
            # Handle retry packet.
            if header.packet_type == QuicPacketType.RETRY:
                self.handle_retry_packet(header=header,
                    packet_without_tag=buf.data_slice(
                        start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE
                    ))
                return


            crypto_frame_required = False

            # Determine crypto and packet space.
            epoch = get_epoch(header.packet_type)
            if epoch == tls.Epoch.INITIAL:
                crypto = self._quic._cryptos_initial[header.version]
            else:
                crypto = self._quic._cryptos[epoch]
            if epoch == tls.Epoch.ZERO_RTT:
                space = self._quic._spaces[tls.Epoch.ONE_RTT]
            else:
                space = self._quic._spaces[epoch]

            
            # decrypt packet
            encrypted_off = buf.tell() - start_off
            end_off = start_off + header.packet_length
            buf.seek(end_off)

            
            # print(">>> prett3.receive_datagram. Decrypting the packet...")
            try:
                plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                        data[start_off:end_off], encrypted_off, space.expected_packet_number)
            except KeyUnavailableError as exc:
                # If a client receives HANDSHAKE or 1-RTT packets before it has
                # handshake keys, it can assume that the server's INITIAL was lost.
                if (
                    epoch in (tls.Epoch.HANDSHAKE, tls.Epoch.ONE_RTT)
                    and not self._quic._crypto_retransmitted
                ):
                    self._quic._loss.reschedule_data(now=now)
                    self._quic._crypto_retransmitted = True
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
                self._quic.close(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=QuicFrameType.PADDING,
                    reason_phrase="Reserved bits must be zero",)
                return


            # raise expected packet number
            if packet_number > space.expected_packet_number:
                space.expected_packet_number = packet_number + 1

            # update state
            if self._quic._peer_cid.sequence_number is None:
                self._quic._peer_cid.cid = header.source_cid
                self._quic._peer_cid.sequence_number = 0

            if self._quic._state == QuicConnectionState.FIRSTFLIGHT:
                self._quic._remote_initial_source_connection_id = header.source_cid
                self._quic._set_state(QuicConnectionState.CONNECTED)

            # update spin bit
            if (header.packet_type == QuicPacketType.ONE_RTT
                and packet_number > self._quic._spin_highest_pn):
                
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
                self.process_payload( context, plain_payload, crypto_frame_required=crypto_frame_required )
            except QuicConnectionError:
                pass

            if self._quic._state in END_STATES or self._quic._close_pending:
                return

            # update idle timeout
            self._quic._close_at = now + self._quic._idle_timeout()

            '''
            # update network path
            if not network_path.is_validated and epoch == tls.Epoch.HANDSHAKE:
                network_path.is_validated = True
            if network_path not in self._quic._network_paths:
                self._quic._network_paths.append(network_path)
            idx = self._quic._network_paths.index(network_path)
            if idx and not is_probing and packet_number > space.largest_received_packet:
                self._quic._network_paths.pop(idx)
                self._quic._network_paths.insert(0, network_path)
            
            # record packet as received
            if not space.discarded:
                if packet_number > space.largest_received_packet:
                    space.largest_received_packet = packet_number
                    space.largest_received_time = now
                space.ack_queue.add(packet_number)
                if is_ack_eliciting and space.ack_at is None:
                    space.ack_at = now + self._quic._ack_delay
            '''

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

        crypto_pair = self._quic._cryptos[epoch]
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
        strm_data = self._quic._crypto_streams[Epoch.HANDSHAKE].sender.get_frame(1135).data # TODO: calculate max_size dynamically instead of giving static number
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
            aioquic.h3.connection.Setting.QPACK_MAX_TABLE_CAPACITY: 2323,# self._http._max_table_capacity,
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

    #### FOR SENDING PACKETS ####
    def build_h3_settings_frame(self, h3_layer):
        """
        Builds and returns a SETTINGS frame for the H3 layer.
        SETTINGS frame is sent over the control stream (Uni Stream Type 0x00).
        """
        settings = {
            # Define HTTP/3 settings here (example settings)
            aioquic.h3.connection.Setting.QPACK_MAX_TABLE_CAPACITY: 1024,
            aioquic.h3.connection.Setting.QPACK_BLOCKED_STREAMS: 16,
            aioquic.h3.connection.Setting.ENABLE_CONNECT_PROTOCOL: 1
        }

        try:
            # Create SETTINGS frame payload
            if hasattr(h3_layer, 'frame_payload') and hasattr(h3_layer.frame_payload, 'raw_value'):
                settings_data = bytes.fromhex(h3_layer.frame_payload.raw_value)
            else:
                print("No valid payload found for SETTINGS frame, using default payload.")
                settings_data = encode_settings(settings)

            # Encode the SETTINGS frame
            frame_data = aioquic.h3.connection.encode_frame(FrameType.SETTINGS, settings_data)

            # Prepend Uni Stream Type (0x00) to the SETTINGS frame data for control stream
            stream_type = aioquic.buffer.encode_uint_var(0x00)  # Uni Stream Type for control stream
            final_frame_data = stream_type + frame_data  # Combine stream type and frame data

            return final_frame_data  # Return the combined frame data with stream type

        except Exception as e:
            print(f"Error encoding SETTINGS frame: {e}")
            return b''  # Return empty payload in case of error

    def build_h3_priority_update_frame(self, h3_layer):
        """
        Builds and returns a PRIORITY_UPDATE frame for the H3 layer.
        """
        # If the PRIORITY_UPDATE frame payload is not available, create a default one
        if hasattr(h3_layer, 'frame_payload') and hasattr(h3_layer.frame_payload, 'raw_value'):
            priority_data = bytes.fromhex(h3_layer.frame_payload.raw_value)
        else:
            print("No valid payload found for PRIORITY_UPDATE frame, using default payload.")
            priority_data = b'\x00\x01\x02'  # Example priority payload

        return aioquic.h3.connection.encode_frame(0x000f0700, priority_data)

    def build_h3_headers_frame(self, h3_layer):
        """
        Builds and returns a HEADERS frame for the H3 layer
        """
        # Extract the HEADERS payload
        if hasattr(h3_layer, 'frame_payload') and hasattr(h3_layer.frame_payload, 'raw_value'):
            headers_data = bytes.fromhex(h3_layer.frame_payload.raw_value)
        else:
            print("No valid payload found for HEADERS frame, using default payload.")
            headers_data = b'\x82\x84\x41\x85\x86'  # Example headers (this should be replaced with real headers)

        return aioquic.h3.connection.encode_frame(FrameType.HEADERS, headers_data)

    def send_quic_stream(self, frames, stream_id):
        """
        Send multiple HTTP/3 frames over the QUIC stream. Each frame is written into its own 
        QUIC stream frame within the same QUIC packet.
        """
        builder = self.get_builder(Epoch.ONE_RTT)

        # For each HTTP/3 frame, we start a new frame in the QUIC stream
        for frame in frames:
            frame_length = len(frame)
            
            # Start the frame for the QUIC stream
            buf = builder.start_frame(QuicFrameType.STREAM_BASE | 2, capacity=4)

            # Push stream ID (encoded as varint)
            buf.push_uint_var(stream_id)

            # Push frame length (encoded as varint)
            buf.push_uint_var(frame_length)

            # Push frame data (actual HTTP/3 frame bytes)
            buf.push_bytes(frame)

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

                res += '|'.join(self.receive_datagram(data, now=time.process_time()))
                res += '||'

        except socket.timeout:
            # Return parsed packets after timeout
            res = res.rstrip('||')
            return res

    def receive_datagram(self, data: bytes, now: float) -> list:
        """
        Process a received QUIC datagram, decrypt and return any decrypted packet data.
        
        Args:
            data: Raw data from the UDP socket.
            now: Current time to use in QUIC processing.
            
        Returns:
            decrypted_payload: List of decrypted QUIC or HTTP/3 layer from processed packets.
        """
        decrypted_payload = []

        buf = Buffer(data=data)
        i=0
        while not buf.eof():
            i+=1
            msg_per_layer = ''
            # print("\tQUIC layer #{}".format(i),end=" ")

            start_off = buf.tell()

            try:
                header = pull_quic_header(buf, host_cid_length=self.quic_conf.connection_id_length)
            except ValueError:
                return
            #print("(Type: {})".format(header.packet_type.name))

            # Check destination CID matches.
            destination_cid_seq: Optional[int] = None
            for connection_id in self._quic._host_cids:
                if header.destination_cid == connection_id.cid:
                    destination_cid_seq = connection_id.sequence_number
                    break
            if destination_cid_seq is None:
                return

            # Handle version negotiation packet.
            if header.packet_type == QuicPacketType.VERSION_NEGOTIATION:
                self._quic._receive_version_negotiation_packet(header=header, now=now)
                return

            # Check long header packet protocol version.
            if (
                header.version is not None
                and header.version not in self.quic_conf.supported_versions
            ):
                return
            
            # Handle retry packet.
            if header.packet_type == QuicPacketType.RETRY:
                self.handle_retry_packet(header=header,
                    packet_without_tag=buf.data_slice(
                        start_off, buf.tell() - RETRY_INTEGRITY_TAG_SIZE
                    ))
                return


            crypto_frame_required = False

            # Determine crypto and packet space.
            epoch = get_epoch(header.packet_type)
            if epoch == tls.Epoch.INITIAL:
                crypto = self._quic._cryptos_initial[header.version]
            else:
                crypto = self._quic._cryptos[epoch]
            if epoch == tls.Epoch.ZERO_RTT:
                space = self._quic._spaces[tls.Epoch.ONE_RTT]
            else:
                space = self._quic._spaces[epoch]

            
            # decrypt packet
            encrypted_off = buf.tell() - start_off
            end_off = start_off + header.packet_length
            buf.seek(end_off)

            
            # print(">>> prett3.receive_datagram. Decrypting the packet...")
            try:
                plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                        data[start_off:end_off], encrypted_off, space.expected_packet_number)
            except KeyUnavailableError as exc:
                # If a client receives HANDSHAKE or 1-RTT packets before it has
                # handshake keys, it can assume that the server's INITIAL was lost.
                if (
                    epoch in (tls.Epoch.HANDSHAKE, tls.Epoch.ONE_RTT)
                    and not self._quic._crypto_retransmitted
                ):
                    self._quic._loss.reschedule_data(now=now)
                    self._quic._crypto_retransmitted = True
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
                self._quic.close(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=QuicFrameType.PADDING,
                    reason_phrase="Reserved bits must be zero",)
                return


            # raise expected packet number
            if packet_number > space.expected_packet_number:
                space.expected_packet_number = packet_number + 1

            # update state
            if self._quic._peer_cid.sequence_number is None:
                self._quic._peer_cid.cid = header.source_cid
                self._quic._peer_cid.sequence_number = 0

            if self._quic._state == QuicConnectionState.FIRSTFLIGHT:
                self._quic._remote_initial_source_connection_id = header.source_cid
                self._quic._set_state(QuicConnectionState.CONNECTED)

            # update spin bit
            if (header.packet_type == QuicPacketType.ONE_RTT
                and packet_number > self._quic._spin_highest_pn):
                
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
                msg_per_layer += self.process_payload( context, plain_payload, crypto_frame_required=crypto_frame_required )
            except QuicConnectionError:
                pass

            decrypted_payload.append(msg_per_layer)

            if self._quic._state in END_STATES or self._quic._close_pending:
                return

            # update idle timeout
            self._quic._close_at = now + self._quic._idle_timeout()

        return decrypted_payload

    #### FOR HANDLING PACKETS ####
    def is_http3_stream(self, stream_id: int) -> bool:
        """
        Determine if the given stream ID corresponds to an HTTP/3 stream.
        
        Args:
            stream_id: The stream ID to check.
            
        Returns:
            bool: True if the stream is an HTTP/3 stream, otherwise False.
        """
        # In HTTP/3, client-initiated bidirectional streams are typically used.
        return stream_id % 4 == 0 or stream_id % 4 == 3

    def process_payload(self, context: QuicReceiveContext, plain: bytes, crypto_frame_required: bool = False) -> Tuple[bool, bool]:
        
        buf = Buffer(data=plain)
        msg_per_layer = ''

        crypto_frame_found = False
        frame_found = False
        is_ack_eliciting = False
        is_probing = None
        i=0
        while not buf.eof():
            i+=1
            #print("\t\tFrame #{}".format(i))

            # get frame type
            try:
                frame_type = buf.pull_uint_var()
            except BufferReadError:
                raise QuicConnectionError( error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=None, reason_phrase="Malformed frame type")

            # handle the frame
            try:
                # a condition for each frame type can be added
                if frame_type==0x00: # PADDING frame
                    continue
                elif frame_type==0x01:
                    self.handle_ping_frame(context, frame_type, buf)

                elif frame_type in [0x02, 0x03]:
                    self.handle_ack_frame(context, frame_type, buf)
                    msg_per_layer += 'ACK,'

                elif frame_type==0x04:
                    self.handle_reset_stream_frame(context, frame_type, buf)
                    msg_per_layer += 'RESET,'
                
                elif frame_type==0x05:
                    self.handle_stop_sending_frame(context, frame_type, buf)
                    msg_per_layer += 'STOP,'

                elif frame_type==0x06: # CRYPTO frame
                    self.handle_crypto(context, frame_type, buf)
                    msg_per_layer += 'CRYPTO,'

                elif frame_type==0x07:
                    self.handle_new_token_frame(context, frame_type, buf)
                    msg_per_layer += 'NEWTOKEN,'
                
                elif frame_type >= 0x08 and frame_type <= 0x0F: # STREAM frame
                    stream_id, stream_data = self.handle_stream_frame(context, frame_type, buf)
                    msg_per_layer += f'STREAM({stream_id})'
                    if self.is_http3_stream(stream_id):
                        http3_stream_msg = self.process_http3_payload(stream_data)
                        if http3_stream_msg != '':
                            msg_per_layer += f'[{self.process_http3_payload(stream_data)}],'
                        else:
                            msg_per_layer += ','
                    # print(msg_per_layer)
                
                elif frame_type==0x10:
                    self.handle_max_data_frame(context, frame_type, buf)
                
                elif frame_type==0x11:
                    self.handle_max_stream_data_frame(context, frame_type, buf)

                elif frame_type==0x12:
                    self.handle_max_streams_bidi_frame(context, frame_type, buf)

                elif frame_type==0x13:
                    self.handle_max_streams_uni_frame(context, frame_type, buf)

                elif frame_type==0x14:
                    self.handle_data_blocked_frame(context, frame_type, buf)

                elif frame_type==0x15:
                    self.handle_stream_data_blocked_frame(context, frame_type, buf)

                elif frame_type in [0x16, 0x17]:
                    self.handle_streams_blocked_frame(context, frame_type, buf)

                elif frame_type==0x18:
                    self.handle_new_connection_id_frame(context, frame_type, buf)
                    msg_per_layer += 'NCI,'
                
                elif frame_type==0x19:
                    self.handle_retire_connection_id_frame(context, frame_type, buf)

                elif frame_type==0x1A:
                    self.handle_path_challenge_frame(context, frame_type, buf)

                elif frame_type==0x1B:
                    self.handle_path_response_frame(context, frame_type, buf)

                elif frame_type==0x1C:
                    self.handle_connection_close_frame(context, frame_type, buf)
                    msg_per_layer += 'CLOSE,'

                elif frame_type==0x1E:
                    self.handle_handshake_done_frame(context, frame_type, buf)
                    msg_per_layer += 'DONE,'

                elif frame_type in [0x30, 0x31]:
                    self.handle_datagram_frame(context, frame_type, buf)
                    msg_per_layer += 'DATA,'

                elif frame_type>0x31:
                    raise QuicConnectionError(error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=frame_type, reason_phrase="Unknown frame type")
            except BufferReadError:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                    frame_type=frame_type,
                    reason_phrase="Failed to parse frame",
                )
            except StreamFinishedError:
                # we lack the state for the stream, ignore the frame
                pass
            

            # update ACK only / probing flags
            frame_found = True

            if frame_type == QuicFrameType.CRYPTO:
                crypto_frame_found = True

            if frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
                is_ack_eliciting = True

            if frame_type not in PROBING_FRAME_TYPES:
                is_probing = False
            elif is_probing is None:
                is_probing = True
        
        return msg_per_layer.rstrip(",")
        # return is_ack_eliciting, bool(is_probing)
    
    def process_http3_payload(self, stream_data: bytes) -> str:
        """
        Process HTTP/3 frames within a stream's data and return a human-readable summary.

        Args:
            stream_data: The data contained within the stream.

        Returns:
            msg_http3: A string summarizing the processed HTTP/3 frames.
        """
        buf_http3 = Buffer(data=stream_data)
        msg_http3 = ''

        # Determine stream type by inspecting the first bytes of the stream data
        try:
            stream_type = buf_http3.pull_uint_var()
            # print("[DEBUG] stream_type : 0x%02x" % stream_type)
        except BufferReadError:
            print("Invalid stream data: unable to determine stream type.")
            return

        # if stream_type == 0x00:
        #     msg_http3 += "Control Stream"
        # elif stream_type == 0x02:
        #     msg_http3 += "QPACK Encoder Stream"
        # elif stream_type == 0x03:
        #     msg_http3 += "QPACK Decoder Stream"
        # else:
        #     msg_http3 += "Uni Stream"

        # Process each frame in the stream data based on the identified stream type
        while not buf_http3.eof():
            try:
                if stream_type in [0x01, 0x04]:
                    #0x01 : Request stream.
                    if stream_type == 0x01:
                        msg_http3 += ', HEADERS'
                        break
                    #0x04 : Usually conveys SETTINGS.
                    elif stream_type == 0x04:
                        msg_http3 += ', SETTINGS'
                        break

                frame_type = buf_http3.pull_uint_var()
                # print("[DEBUG] stream_type : 0x%02x | frame type : 0x%02x" % (stream_type, frame_type))

                # Control Stream frames
                if stream_type == 0x00:
                    if frame_type == FrameType.SETTINGS:
                        msg_http3 += ', SETTINGS'
                        break
                    elif frame_type == FrameType.PRIORITY_UPDATE:
                        msg_http3 += ', PRIORITY_UPDATE'
                        break
                    else:
                        msg_http3 += f', UNKNOWN_CONTROL_FRAME(type={frame_type})'
                        break
                

                # QPACK Streams frames (both Encoder and Decoder)
                elif stream_type in [0x02, 0x03]:
                    msg_http3 += f', QPACK_FRAME(type={frame_type})'

                # Uni Stream frames
                else:
                    if frame_type == FrameType.HEADERS:
                        msg_http3 += ', HEADERS'
                        break
                    elif frame_type == FrameType.DATA:
                        data_length = buf_http3.pull_uint_var()
                        buf_http3.pull_bytes(data_length) 
                        msg_http3 += f', DATA(len={data_length})'
                        break
                    if frame_type == 0x0f0700:
                        length = buf_http3.pull_uint_var()
                        buf_http3.pull_bytes(length)
                        msg_http3 += f', PRIORITY_UPDATE(len={length})'
                        break
                    else:
                        msg_http3 += f', UNKNOWN_REQUEST_RESPONSE_FRAME(type={frame_type})'
                        break

            except BufferReadError:
                print("Buffer read error while processing HTTP/3 stream. Skipping rest of stream.")
                break

        # Remove any leading/trailing whitespace if necessary
        msg_http3 = msg_http3.strip(', ')

        return msg_http3

    def handle_datagram_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATAGRAM frame.
        """
        start = buf.tell()
        if frame_type == QuicFrameType.DATAGRAM_WITH_LENGTH:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - start
        data = buf.pull_bytes(length)

        print("\033[31m\nDATAGRAM frame received. Length={}, Data={}\033[0m"
              .format(length, data))

        """
        # check frame is allowed
        if (
            self._quic._configuration.max_datagram_frame_size is None
            or buf.tell() - start >= self._quic._configuration.max_datagram_frame_size
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Unexpected DATAGRAM frame",
            )

        self._quic._events.append(events.DatagramFrameReceived(data=data))
        """

    def handle_crypto(self, context: QuicReceiveContext, frame_type: int, buf:Buffer):

        offset = buf.pull_uint_var()
        length = buf.pull_uint_var()
        data = buf.pull_bytes(length)
        # print(("\033[31mCRYPTO frame received. " +
        #           "Offset={}, " +
        #           "Length={}, " +
        #           "Crypto Data={}... \033[0m")
        #     .format(offset, length, data[:10] ))
        
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError( error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=frame_type, reason_phrase="offset + length cannot exceed 2^62 - 1")
        frame = QuicStreamFrame(offset=offset, data=data)
        
        stream = self._quic._crypto_streams[context.epoch]
        pending = offset + length - stream.receiver.starting_offset()
        if pending > MAX_PENDING_CRYPTO:
            raise QuicConnectionError(
                error_code=QuicErrorCode.CRYPTO_BUFFER_EXCEEDED,
                frame_type=frame_type,
                reason_phrase="too much crypto buffering",
            )
        
        event = stream.receiver.handle_frame(frame)
        if event is not None:
            # Pass data to TLS layer, which may cause calls to:
            # - _alpn_handler
            # - _update_traffic_key
            self._quic._crypto_frame_type = frame_type
            self._quic._crypto_packet_version = context.version
            try:
                self._quic.tls.handle_message(event.data, self._quic._crypto_buffers)
                self._quic._push_crypto_data()
            except tls.Alert as exc:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.CRYPTO_ERROR + int(exc.description),
                    frame_type=frame_type,
                    reason_phrase=str(exc),
                )

            # Update the current epoch.
            if not self._quic._handshake_complete and self._quic.tls.state in [
                tls.State.CLIENT_POST_HANDSHAKE,
                tls.State.SERVER_POST_HANDSHAKE,
            ]:
                self._quic._handshake_complete = True

                # for servers, the handshake is now confirmed
                self._quic._replenish_connection_ids()
                self._quic._events.append(
                    events.HandshakeCompleted(
                        alpn_protocol=self._quic.tls.alpn_negotiated,
                        early_data_accepted=self._quic.tls.early_data_accepted,
                        session_resumed=self._quic.tls.session_resumed,
                    )
                )
                self._quic._unblock_streams(is_unidirectional=False)
                self._quic._unblock_streams(is_unidirectional=True)
                self._quic._logger.info(
                    "ALPN negotiated protocol %s", self._quic.tls.alpn_negotiated
                )

    def handle_padding_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PADDING frame.
        """
        # print("\033[31m\nPADDING frame received\033[0m".format())
        pass
        """
        # consume padding
        pos = buf.tell()
        for byte in buf.data_slice(pos, buf.capacity):
            if byte:
                break
            pos += 1
        buf.seek(pos)
        """

    def handle_ping_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PING frame.
        """
        # print("\033[31m\nPING frame received\033[0m".format())
        pass

    def handle_ack_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle an ACK frame.
        """

        def pull_ack_frame(buf: Buffer) -> Tuple[RangeSet, int]:
            rangeset = RangeSet()
            end = buf.pull_uint_var()  # largest acknowledged
            delay = buf.pull_uint_var()
            ack_range_count = buf.pull_uint_var()
            ack_count = buf.pull_uint_var()  # first ack range
            rangeset.add(end - ack_count, end + 1)
            
            # print(("\033[31m\nACK frame received. " +
            #       "Largest Acknowledged={}, " +
            #       "Ack Delay={}, " +
            #       "Ack Range Count={}, " +
            #       "First Ack Range={} \033[0m")
            # .format(end, delay, ack_range_count, ack_count ))
            
            end -= ack_count
            for _ in range(ack_range_count):
                end -= buf.pull_uint_var() + 2
                ack_count = buf.pull_uint_var()
                rangeset.add(end - ack_count, end + 1)
                end -= ack_count
            
            
            return rangeset, delay

        ack_rangeset, ack_delay_encoded = pull_ack_frame(buf)
        if frame_type == QuicFrameType.ACK_ECN:
            buf.pull_uint_var()
            buf.pull_uint_var()
            buf.pull_uint_var()
        ack_delay = (ack_delay_encoded << self._quic._remote_ack_delay_exponent) / 1000000

        '''
        # check whether peer completed address validation
        if not self._quic._loss.peer_completed_address_validation and context.epoch in (
            tls.Epoch.HANDSHAKE,
            tls.Epoch.ONE_RTT,
        ):
            self._quic._loss.peer_completed_address_validation = True

        self._quic._loss.on_ack_received(
            ack_rangeset=ack_rangeset,
            ack_delay=ack_delay,
            now=context.time,
            space=self._quic._spaces[context.epoch],
        )
        '''

    def handle_reset_stream_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RESET_STREAM frame.
        """
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()
        final_size = buf.pull_uint_var()

        print("\033[31m\nRESET_STREAM frame received. Stream ID={}, Error Code={}, Final Size={}\033[0m"
              .format(stream_id, error_code, final_size))

        """
        # check stream direction
        self._quic._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._quic._get_or_create_stream(frame_type, stream_id)
        if final_size > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, final_size - stream.receiver.highest_offset)
        if self._quic._local_max_data.used + newly_received > self._quic._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        try:
            event = stream.receiver.handle_reset(
                error_code=error_code, final_size=final_size
            )
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._quic._events.append(event)
        self._quic._local_max_data.used += newly_received
        """

    def handle_stop_sending_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STOP_SENDING frame.
        """
        stream_id = buf.pull_uint_var()
        error_code = buf.pull_uint_var()  # application error code

        print("\033[31m\nSTOP_SENDING frame received. Stream ID={}, Error Code={}\033[0m"
              .format(stream_id, error_code))

        """
        # check stream direction
        self._quic._assert_stream_can_send(frame_type, stream_id)

        # reset the stream
        stream = self._quic._get_or_create_stream(frame_type, stream_id)
        stream.sender.reset(error_code=QuicErrorCode.NO_ERROR)

        self._quic._events.append(
            events.StopSendingReceived(error_code=error_code, stream_id=stream_id)
        )
        """

    def handle_new_token_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_TOKEN frame.
        """
        length = buf.pull_uint_var()
        token = buf.pull_bytes(length)

        print("\033[31m\nRESET_STREAM frame received. Length={}, Token={}\033[0m"
              .format(length, token))

        """
        if not self._quic._is_client:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Clients must not send NEW_TOKEN frames",
            )

        if self._quic._token_handler is not None:
            self._quic._token_handler(token)
        """

    def handle_stream_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM frame.
        """
        stream_id = buf.pull_uint_var()
        if frame_type & 4:
            offset = buf.pull_uint_var()
        else:
            offset = 0
        if frame_type & 2:
            length = buf.pull_uint_var()
        else:
            length = buf.capacity - buf.tell()
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="offset + length cannot exceed 2^62 - 1",
            )

        # Pull the stream data from the buffer

        stream_data = buf.pull_bytes(length)
        # print("\033[31m\nSTREAM frame received. Stream ID={}, Offset={}, Length={}, Stream Data={}\033[0m"
        #       .format(stream_id, offset, length, stream_data))

        return stream_id, stream_data


        """
        data=buf.pull_bytes(length)
        frame = QuicStreamFrame(
            offset=offset, data=data, fin=bool(frame_type & 1)
        )
        
        print("\033[31m\nSTREAM frame received. Stream ID={}, Offset={}, Length={}, Stream Data={}\033[0m"
              .format(stream_id, offset, length, data))
        
        
        # check stream direction
        self._quic._assert_stream_can_receive(frame_type, stream_id)

        # check flow-control limits
        stream = self._quic._get_or_create_stream(frame_type, stream_id)
        if offset + length > stream.max_stream_data_local:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over stream data limit",
            )
        newly_received = max(0, offset + length - stream.receiver.highest_offset)
        if self._quic._local_max_data.used + newly_received > self._quic._local_max_data.value:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FLOW_CONTROL_ERROR,
                frame_type=frame_type,
                reason_phrase="Over connection data limit",
            )

        # process data
        try:
            event = stream.receiver.handle_frame(frame)
        except FinalSizeError as exc:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FINAL_SIZE_ERROR,
                frame_type=frame_type,
                reason_phrase=str(exc),
            )
        if event is not None:
            self._quic._events.append(event)
        self._quic._local_max_data.used += newly_received
        """

        return stream_id, data

    def handle_max_data_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_DATA frame.

        This adjusts the total amount of we can send to the peer.
        """
        max_data = buf.pull_uint_var()
        
        print("\033[31m\nMAX_DATA frame received. MAX DATA={}\033[0m"
              .format(max_data))

        """
        if max_data > self._remote_max_data:
            self._remote_max_data = max_data
        """

    def handle_max_stream_data_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAM_DATA frame.

        This adjusts the amount of data we can send on a specific stream.
        """
        stream_id = buf.pull_uint_var()
        max_stream_data = buf.pull_uint_var()

        print("\033[31m\nMAX_STREAM_DATA frame received. Stream ID={}, Max Stream Data={}\033[0m"
              .format(stream_id, max_stream_data))

        """
        # check stream direction
        self._quic._assert_stream_can_send(frame_type, stream_id)

        stream = self._quic._get_or_create_stream(frame_type, stream_id)
        if max_stream_data > stream.max_stream_data_remote:
            stream.max_stream_data_remote = max_stream_data
        """

    def handle_max_streams_bidi_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_BIDI frame.

        This raises number of bidirectional streams we can initiate to the peer.
        """
        max_streams = buf.pull_uint_var()
        if max_streams > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        """
        if max_streams > self._remote_max_streams_bidi:
            self._remote_max_streams_bidi = max_streams
            self._quic._unblock_streams(is_unidirectional=False)
        """

    def handle_max_streams_uni_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a MAX_STREAMS_UNI frame.

        This raises number of unidirectional streams we can initiate to the peer.
        """
        max_streams = buf.pull_uint_var()
        if max_streams > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )

        """
        if max_streams > self._remote_max_streams_uni:
            self._remote_max_streams_uni = max_streams
            self._quic._unblock_streams(is_unidirectional=True)
        """

    def handle_data_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a DATA_BLOCKED frame.
        """
        limit = buf.pull_uint_var()

        print("\033[31m\nDATA_BLOCKED  frame received. Limit={}\033[0m"
              .format(limit))

    def handle_stream_data_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAM_DATA_BLOCKED frame.
        """
        stream_id = buf.pull_uint_var()
        limit = buf.pull_uint_var()

        print("\033[31m\nSTREAM_DATA_BLOCKED frame received. Stream ID={}, Limit={}\033[0m"
              .format(stream_id, limit))
        
        """
        # check stream direction
        self._quic._assert_stream_can_receive(frame_type, stream_id)

        self._quic._get_or_create_stream(frame_type, stream_id)
        """

    def handle_streams_blocked_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a STREAMS_BLOCKED frame.
        """
        limit = buf.pull_uint_var()

        print("\033[31m\nSTREAMS_BLOCKED frame received. Limit={}\033[0m"
              .format(limit))
        
        """
        if limit > STREAM_COUNT_MAX:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Maximum Streams cannot exceed 2^60",
            )
        """
    
    def handle_new_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a NEW_CONNECTION_ID frame.
        """
        sequence_number = buf.pull_uint_var()
        retire_prior_to = buf.pull_uint_var()
        length = buf.pull_uint8()
        connection_id = buf.pull_bytes(length)
        stateless_reset_token = buf.pull_bytes(STATELESS_RESET_TOKEN_SIZE)
        
        # print("\033[31m\nNEW_CONNECTION_ID frame received. Sequence Number={}, Retire Prior To={}, Length={}, Connection Id={}, stateless Reset Token\033[0m"
        #       .format(sequence_number, retire_prior_to, length, "Suppressed", stateless_reset_token))

        """
        if not connection_id or len(connection_id) > CONNECTION_ID_MAX_SIZE:
            raise QuicConnectionError(
                error_code=QuicErrorCode.FRAME_ENCODING_ERROR,
                frame_type=frame_type,
                reason_phrase="Length must be greater than 0 and less than 20",
            )


        # sanity check
        if retire_prior_to > sequence_number:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Retire Prior To is greater than Sequence Number",
            )

        # only accept retire_prior_to if it is bigger than the one we know
        self._quic._peer_retire_prior_to = max(retire_prior_to, self._quic._peer_retire_prior_to)

        # determine which CIDs to retire
        change_cid = False
        retire = [
            cid
            for cid in self._quic._peer_cid_available
            if cid.sequence_number < self._quic._peer_retire_prior_to
        ]
        if self._quic._peer_cid.sequence_number < self._quic._peer_retire_prior_to:
            change_cid = True
            retire.insert(0, self._peer_cid)

        # update available CIDs
        self._quic._peer_cid_available = [
            cid
            for cid in self._quic._peer_cid_available
            if cid.sequence_number >= self._quic._peer_retire_prior_to
        ]
        if (
            sequence_number >= self._quic._peer_retire_prior_to
            and sequence_number not in self._quic._peer_cid_sequence_numbers
        ):
            self._quic._peer_cid_available.append(
                QuicConnectionId(
                    cid=connection_id,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )
            self._quic._peer_cid_sequence_numbers.add(sequence_number)

        # retire previous CIDs
        for quic_connection_id in retire:
            self._quic._retire_peer_cid(quic_connection_id)

        # assign new CID if we retired the active one
        if change_cid:
            self._quic._consume_peer_cid()

        # check number of active connection IDs, including the selected one
        if 1 + len(self._quic._peer_cid_available) > self._quic._local_active_connection_id_limit:
            raise QuicConnectionError(
                error_code=QuicErrorCode.CONNECTION_ID_LIMIT_ERROR,
                frame_type=frame_type,
                reason_phrase="Too many active connection IDs",
            )

        # Check the number of retired connection IDs pending, though with a safer limit
        # than the 2x recommended in section 5.1.2 of the RFC.  Note that we are doing
        # the check here and not in _retire_peer_cid() because we know the frame type to
        # use here, and because it is the new connection id path that is potentially
        # dangerous.  We may transiently go a bit over the limit due to unacked frames
        # getting added back to the list, but that's ok as it is bounded.
        if len(self._quic._retire_connection_ids) > min(
            self._quic._local_active_connection_id_limit * 4, MAX_PENDING_RETIRES
        ):
            raise QuicConnectionError(
                error_code=QuicErrorCode.CONNECTION_ID_LIMIT_ERROR,
                frame_type=frame_type,
                reason_phrase="Too many pending retired connection IDs",
            )
        """

    def handle_retire_connection_id_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a RETIRE_CONNECTION_ID frame.
        """
        sequence_number = buf.pull_uint_var()
        
        print("\033[31m\nRETIRE_CONNECTION_ID frame received. Sequence Number={}\033[0m"
              .format(sequence_number))

        """
        if sequence_number >= self._quic._host_cid_seq:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Cannot retire unknown connection ID",
            )

        # find the connection ID by sequence number
        for index, connection_id in enumerate(self._quic._host_cids):
            if connection_id.sequence_number == sequence_number:
                if connection_id.cid == context.host_cid:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                        frame_type=frame_type,
                        reason_phrase="Cannot retire current connection ID",
                    )
                del self._quic._host_cids[index]
                self._quic._events.append(
                    events.ConnectionIdRetired(connection_id=connection_id.cid)
                )
                break

        # issue a new connection ID
        self._quic._replenish_connection_ids()
        """

    def handle_path_challenge_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_CHALLENGE frame.
        """
        data = buf.pull_bytes(8)

        print("\033[31m\nPATH_CHALLENGE frame received. Data={}\033[0m"
              .format(data))

        """
        context.network_path.remote_challenges.append(data)
        """

    def handle_path_response_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PATH_RESPONSE frame.
        """
        data = buf.pull_bytes(8)

        print("\033[31m\nSTREAM frame received. Data={}\033[0m"
              .format(data))

        """
        try:
            network_path = self._quic._local_challenges.pop(data)
        except KeyError:
            raise QuicConnectionError(
                error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                frame_type=frame_type,
                reason_phrase="Response does not match challenge",
            )
        network_path.is_validated = True
        """

    def handle_connection_close_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a CONNECTION_CLOSE frame.
        """
        error_code = buf.pull_uint_var()
        if frame_type == QuicFrameType.TRANSPORT_CLOSE:
            frame_type = buf.pull_uint_var()
        else:
            frame_type = None
        reason_length = buf.pull_uint_var()
        try:
            reason_phrase = buf.pull_bytes(reason_length).decode("utf8")
        except UnicodeDecodeError:
            reason_phrase = ""

        # print("\033[31m\nCONNECTION_CLOSE frame received. Error Code={}, Frame Type={}, Reason Phrase Length={}, Reason Phrase={}\033[0m"
            #   .format(error_code, frame_type, reason_length, reason_phrase))

        """
        if self._quic._close_event is None:
            self._quic._close_event = events.ConnectionTerminated(
                error_code=error_code,
                frame_type=frame_type,
                reason_phrase=reason_phrase,
            )
            self._quic._close_begin(is_initiator=False, now=context.time)
        """

    def handle_handshake_done_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a HANDSHAKE_DONE frame.
        """
        # print("\033[31m\nHANDSHAKE DONE frame received\033[0m"
        #       .format())
        """
        # for clients, the handshake is now confirmed
        if not self._quic._handshake_confirmed:
            self._quic._discard_epoch(tls.Epoch.HANDSHAKE)
            self._quic._handshake_confirmed = True
            self._quic._loss.peer_completed_address_validation = True
        """

    def replay_sample_msg(self, h3msg):
        """
        Replay QUIC and HTTP/3 packets from h3msg and capture responses.
        """
        stream_id = 0
        h3_frames = []
        quic_frame_type_hex = None
        quic_payload = None

        ### Send the test message (QUIC or HTTP/3) ###
        for layer in h3msg.layers:
            if layer.layer_name == 'quic':
                quic_frame_type_hex = layer.get_field_value("quic.frame_type", raw=True)
                # Extract stream ID and payload from QUIC layer
                for field in layer.frame.fields:
                    if 'STREAM' in str(field):  
                        stream_id_info = field.showname  
                        if 'id=' in stream_id_info:
                            stream_id = int(stream_id_info.split('id=')[1].split()[0])
                    # Extract QUIC payload
                    if hasattr(layer, 'payload'):
                        quic_payload = layer.payload.raw_value

            elif layer.layer_name == 'http3':
                h3_field_type_hex = layer.get_field_value("http3.frame_type", raw=True)
                if h3_field_type_hex is not None:
                    h3_field_type = int(h3_field_type_hex, 16)

                    if h3_field_type == FrameType.SETTINGS:
                        h3_frames.append(self.build_h3_settings_frame(layer))
                    elif h3_field_type == PRIORITY_UPDATE_FRAME_TYPE:
                        h3_frames.append(self.build_h3_priority_update_frame(layer))
                    elif h3_field_type == FrameType.HEADERS:
                        h3_frames.append(self.build_h3_headers_frame(layer))
        if h3_frames:
            self.send_quic_stream(h3_frames, stream_id) # If HTTP/3 frames are found, send them over QUIC stream
        else:
            self.send_quic_packet(quic_frame_type_hex, quic_payload)

        response_packets = self.read_from_buffer()

        # Explicitly close the QUIC connection using CONNECTION_CLOSE frame
        self._quic.close(
            error_code=QuicErrorCode.NO_ERROR,
            frame_type=QuicFrameType.APPLICATION_CLOSE,
            reason_phrase="Normal connection closure after message replay",
        )

        # Send CONNECTION_CLOSE frame using send_quic_packet
        # Define the payload to include error_code and reason_phrase according to the QUIC specification.
        connection_close_payload = Buffer(capacity=256)
        connection_close_payload.push_uint_var(QuicErrorCode.NO_ERROR)  # Error code (NO_ERROR)
        connection_close_payload.push_uint_var(0)  # Frame type (0 since no specific frame is indicated)
        reason_phrase = "Normal connection closure after message replay"
        connection_close_payload.push_uint16(len(reason_phrase))
        connection_close_payload.push_bytes(reason_phrase.encode('utf-8'))

        self.send_quic_packet(
            quic_frame_type=QuicFrameType.APPLICATION_CLOSE,  # Use APPLICATION_CLOSE for QUIC-level closure
            quic_payload=connection_close_payload.data  # Include the correctly formatted payload
        )

        self.sock.close()

        return response_packets

    def draw_state_machine_graph(self, sm):
        """
        상태 머신을 그래프로 그리는 함수. Machine의 get_graph() 메소드를 사용합니다.
        """
        # 상태 머신 그래프를 파일로 저장
        graph = sm.get_graph()
        graph_name = "state_machine_graph.png"

        # 세로로 긴 그래프를 그리도록 설정 ('dot' 프로그래프에 rankdir=TB를 추가)
        graph.draw(graph_name, prog='dot', args='-Grankdir=TB')  # 'TB'는 Top to Bottom, 세로 방향

        print(f"[+] Graph saved as {graph_name}")

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
    install()

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
    
    