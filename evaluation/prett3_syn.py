#! /usr/bin/env python
import aioquic.h3
import aioquic.h3.connection
import util
import pyshark
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
import aioquic.buffer
import asyncio
import ssl
import aioquic
import wsproto
import wsproto.events
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


class HttpClient():
    def __init__(self, quic_conf: QuicConfiguration, hostname: str) -> None:
        
        self.quic_conf = quic_conf
        self.quic_conf.original_version = 1
        self._quic = QuicConnection(configuration=self.quic_conf)
        self._http = H3Connection(self._quic)
        self.hostname = hostname
        #self.host_cid = os.urandom(self.quic_conf.connection_id_length) # wireshark -> 
        # "[Failed to create decryption context: Decryption (checktag) failed: Checksum error]" TODO: find out why
        #self.host_cid = self._quic._peer_cid.cid
    

    def replicate_sample_msg(self, h3msg):
        for layer in h3msg.layers:
            if layer.layer_name == 'quic':
                continue
            elif layer.layer_name == 'http3':
                h3_field_type = int(layer.get_field_value("http3.frame_type", raw=True))
                print(h3_field_type)
                h3_field_payload = bytes(layer.get_field_value("http3.frame_payload", raw=True), "utf-8")
                frame_data = aioquic.h3.connection.encode_frame(h3_field_type, h3_field_payload)
                print("done")

                # frames = util.get_frames_of_layer(layer)
                # for frame in frames:
                #     print(frame)
                #     print(FrameType.HEADERS)
                # frame_data = aioquic.h3.connection.encode_frame(FrameType.HEADERS, frame_data)


    
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

        print(">>> prett3.get_builder. quic_packet_type={}, crypto_pair={}".format(quic_packet_type, crypto_pair))
        
        builder.start_packet(quic_packet_type, crypto_pair)

        self._http._quic._packet_number += 1

        return builder

    def send_quic_stream(self, frame_data):

        builder = self.get_builder(Epoch.ONE_RTT)

        buf = builder.start_frame(
                QuicFrameType.STREAM_BASE | 2,
                capacity=4, # TODO why is capacity always 4?
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

    # sample
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
    
    # TODO: do we really need to implement this method ourselves?
    def parse_transport_parameters(
        self, data: bytes, from_session_ticket: bool = False
    ) -> None:
        """
        Parse and apply remote transport parameters.

        `from_session_ticket` is `True` when restoring saved transport parameters,
        and `False` when handling received transport parameters.
        """

        try:
            quic_transport_parameters = pull_quic_transport_parameters(
                Buffer(data=data)
            )
        except ValueError:
            raise QuicConnectionError(
                error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                frame_type=QuicFrameType.CRYPTO,
                reason_phrase="Could not parse QUIC transport parameters",
            )

        if not from_session_ticket:
            if (
                quic_transport_parameters.initial_source_connection_id
                != self._remote_initial_source_connection_id
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="initial_source_connection_id does not match",
                )
            if self._is_client and (
                quic_transport_parameters.original_destination_connection_id
                != self._original_destination_connection_id
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="original_destination_connection_id does not match",
                )
            if self._is_client and (
                quic_transport_parameters.retry_source_connection_id
                != self._retry_source_connection_id
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="retry_source_connection_id does not match",
                )
            if (
                quic_transport_parameters.active_connection_id_limit is not None
                and quic_transport_parameters.active_connection_id_limit < 2
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="active_connection_id_limit must be no less than 2",
                )
            if (
                quic_transport_parameters.ack_delay_exponent is not None
                and quic_transport_parameters.ack_delay_exponent > 20
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="ack_delay_exponent must be <= 20",
                )
            if (
                quic_transport_parameters.max_ack_delay is not None
                and quic_transport_parameters.max_ack_delay >= 2**14
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase="max_ack_delay must be < 2^14",
                )
            if quic_transport_parameters.max_udp_payload_size is not None and (
                quic_transport_parameters.max_udp_payload_size
                < SMALLEST_MAX_DATAGRAM_SIZE
            ):
                raise QuicConnectionError(
                    error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                    frame_type=QuicFrameType.CRYPTO,
                    reason_phrase=(
                        f"max_udp_payload_size must be >= {SMALLEST_MAX_DATAGRAM_SIZE}"
                    ),
                )

            # Validate Version Information extension.
            #
            # https://datatracker.ietf.org/doc/html/rfc9368#section-4
            if quic_transport_parameters.version_information is not None:
                version_information = quic_transport_parameters.version_information

                # If a server receives Version Information where the Chosen Version
                # is not included in Available Versions, it MUST treat is as a
                # parsing failure.
                if (
                    not self._is_client
                    and version_information.chosen_version
                    not in version_information.available_versions
                ):
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.TRANSPORT_PARAMETER_ERROR,
                        frame_type=QuicFrameType.CRYPTO,
                        reason_phrase=(
                            "version_information's chosen_version is not included "
                            "in available_versions"
                        ),
                    )

                # Validate that the Chosen Version matches the version in use for the
                # connection.
                if version_information.chosen_version != self._crypto_packet_version:
                    raise QuicConnectionError(
                        error_code=QuicErrorCode.VERSION_NEGOTIATION_ERROR,
                        frame_type=QuicFrameType.CRYPTO,
                        reason_phrase=(
                            "version_information's chosen_version does not match "
                            "the version in use"
                        ),
                    )

        
        # Store remote parameters.
        '''
        if not from_session_ticket:
            if quic_transport_parameters.ack_delay_exponent is not None:
                self._remote_ack_delay_exponent = self._remote_ack_delay_exponent
            if quic_transport_parameters.max_ack_delay is not None:
                self._loss.max_ack_delay = (
                    quic_transport_parameters.max_ack_delay / 1000.0
                )
            if (
                self._peer_cid.sequence_number == 0
                and quic_transport_parameters.stateless_reset_token is not None
            ):
                self._peer_cid.stateless_reset_token = (
                    quic_transport_parameters.stateless_reset_token
                )
            self._remote_version_information = (
                quic_transport_parameters.version_information
            )
        '''
        if quic_transport_parameters.active_connection_id_limit is not None:
            self._remote_active_connection_id_limit = (
                quic_transport_parameters.active_connection_id_limit
            )
        if quic_transport_parameters.max_idle_timeout is not None:
            
            self._remote_max_idle_timeout = (
                quic_transport_parameters.max_idle_timeout / 1000.0
            )
        self._remote_max_datagram_frame_size = (
            quic_transport_parameters.max_datagram_frame_size
        )
        for param in [
            "max_data",
            "max_stream_data_bidi_local",
            "max_stream_data_bidi_remote",
            "max_stream_data_uni",
            "max_streams_bidi",
            "max_streams_uni",
        ]:
            value = getattr(quic_transport_parameters, "initial_" + param)
            if value is not None:
                setattr(self, "_remote_" + param, value)

    # we need to implement this method to be able to play with transport params
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
        print(">>> prett3.serialize_transport_parameters. quic_transport_parameters={}".format(quic_transport_parameters))

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
        self._quic.tls.alpn_cb = self.alpn_callback
        if self._quic._session_ticket_fetcher is not None:
            self._quic.tls.get_session_ticket_cb = self._quic._session_ticket_fetcher
        if self._quic._session_ticket_handler is not None:
            self._quic.tls.new_session_ticket_cb = self._quic._handle_session_ticket
        self._quic.tls.update_traffic_key_cb = self.update_traffic_key
        

        # packet spaces
        def create_crypto_pair(epoch: tls.Epoch) -> CryptoPair:
            print(">>> prett3.get_tls.create_crypto_pair: start. epoch={}".format(epoch))
            epoch_name = ["initial", "0rtt", "handshake", "1rtt"][epoch.value]
            
            recv_secret_name = "server_%s_secret" % epoch_name
            send_secret_name = "client_%s_secret" % epoch_name
            return CryptoPair(
                recv_setup_cb=partial(self.log_key_updated, recv_secret_name),
                recv_teardown_cb=partial(self.log_key_retired, recv_secret_name),
                send_setup_cb=partial(self.log_key_updated, send_secret_name),
                send_teardown_cb=partial(self.log_key_retired, send_secret_name),
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

    def log_key_updated(self, key_type: str, trigger: str) -> None:
        #print("LOG KEY UPDATED!!!!!!!!!!!!")
        pass

    def log_key_retired(self):
        #print("LOG KEY RETIRED!!!!!!!!!!!!")
        pass
    
    # TODO: do we really need to implement this method ourselves?
    def update_traffic_key( self, direction: tls.Direction, epoch: tls.Epoch, cipher_suite: tls.CipherSuite, secret: bytes,
    ) -> None:
        print(">>> prett3.update_traffic_key: starts: direction={}, epoch={}, cipher_suite={}, secret={}".format(direction.name, epoch.name, cipher_suite.name, secret) )

        if (
            self._quic._crypto_packet_version is not None
            and not self._quic._version_negotiated_compatible
        ):
            self._quic._version = self._quic._crypto_packet_version
            self._quic._version_negotiated_compatible = True

        secrets_log_file = self._quic._configuration.secrets_log_file
        if secrets_log_file is not None:
            label_row = True == (direction == tls.Direction.DECRYPT)
            print(">>> prett3.update_traffic_key: label_row={}".format(label_row))
            label = SECRETS_LABELS[label_row][epoch.value]
            secrets_log_file.write(
                "%s %s %s\n" % (label, self._quic.tls.client_random.hex(), secret.hex())
            )
            secrets_log_file.flush()

        crypto = self._quic._cryptos[epoch]
        if direction == tls.Direction.ENCRYPT:
            print(">>> prett3._update_traffic_key: setting up outgoing crypto")
            crypto.send.setup(
                cipher_suite=cipher_suite, secret=secret, version=self._quic._version
            )
        else:
            print(">>> prett3._update_traffic_key: setting up incoming crypto")
            crypto.recv.setup(
                cipher_suite=cipher_suite, secret=secret, version=self._quic._version
            )

    def alpn_callback(self, alpn_protocol: str) -> None:
        #print("ALPN CALLED BACK!!!!!!!!!!!!!!")
        pass

    def connect(self):
        """
        How aioquic's QuicConnection does it:
        initialize() sets up tls context
        handle_message() puts _client_send_hello message into the INITIAL's buffer in _crypto_buffers
        _push_crypto_data() writes data from the buffer to INITIAL's crypto stream in _crypto_streams
        datagrams_to_send() when called passes the builder to _write_handshake(), which adds the CRYPTO frame to it
        """

        crypto_buf = Buffer(capacity=CRYPTO_BUFFER_SIZE)

        self.get_tls() # better to build tls myself to contruct transport params myself
        
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


    def handle_crypto(self, context: QuicReceiveContext, frame_type: int, buf:Buffer):

        print(">>> prett3.handle_crypto: start: frame_type={}, buf={}".format(frame_type, buf.data) )
        offset = buf.pull_uint_var()
        length = buf.pull_uint_var()
        if offset + length > UINT_VAR_MAX:
            raise QuicConnectionError( error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=frame_type, reason_phrase="offset + length cannot exceed 2^62 - 1")
        frame = QuicStreamFrame(offset=offset, data=buf.pull_bytes(length))
        
        print(">>> prett3.handle_crypto: epoch={}".format(context.epoch) )
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
            self._crypto_frame_type = frame_type
            
            self._crypto_packet_version = context.version
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

    def process_payload(self, context: QuicReceiveContext, plain: bytes, crypto_frame_required: bool = False) -> Tuple[bool, bool]:

        print(">>> prett3.process_payload: start")
        
        buf = Buffer(data=plain)

        crypto_frame_found = False
        frame_found = False
        is_ack_eliciting = False
        is_probing = None
        i=0
        while not buf.eof():
            i+=1

            # get frame type
            try:
                frame_type = buf.pull_uint_var()
            except BufferReadError:
                raise QuicConnectionError( error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=None, reason_phrase="Malformed frame type")

            # check frame type is known
            '''
            try:
                print(">>> frame type={}".format(frame_type))
                frame_handler = self.__frame_handlers[frame_type]
                print(">>> frame handler={}".format(frame_handler))
            except KeyError:
                raise QuicConnectionError(error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=frame_type, reason_phrase="Unknown frame type")
            
            # check frame type is allowed for the epoch
            if context.epoch not in frame_epochs:
                raise QuicConnectionError(
                    error_code=QuicErrorCode.PROTOCOL_VIOLATION,
                    frame_type=frame_type,
                    reason_phrase="Unexpected frame type",
                )
            '''

            # handle the frame
            
            try:
                # a condition for each frame type can be added
                if frame_type==0: # PADDING frame
                    continue
                elif frame_type==2: # ACK frame
                    continue
                elif frame_type==6: # CRYPTO frame
                    self.handle_crypto(context, frame_type, buf)
                elif frame_type>48:
                    raise QuicConnectionError(error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=frame_type, reason_phrase="Unknown frame type")
                print(">>> prett3.process_payload: frame #{}, type={}".format(i, frame_type))
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


    def receive_datagram(self, data: bytes, now: float) -> None:

        print(">>> prett3.receive_datagram: start. data_length={}".format(len(data)) )

        buf = Buffer(data=data)
        i=1
        while not buf.eof():
            print(">>> prett3.receive_datagram: layer #{}".format(i))
            i+=1

            start_off = buf.tell()

            try:
                header = pull_quic_header(buf, host_cid_length=self.quic_conf.connection_id_length)
                print(">>> prett3.receive_datagram: quic_header={}".format(header))
            except ValueError:
                return

            # Handle version negotiation packet.
            if header.packet_type == QuicPacketType.VERSION_NEGOTIATION:
                self._quic._receive_version_negotiation_packet(header=header, now=now)
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

            
            print(">>> prett3.receive_datagram. Decrypting the packet...")
            plain_header, plain_payload, packet_number = crypto.decrypt_packet(
                data[start_off:end_off], encrypted_off, space.expected_packet_number)

            print(">>> prett3.receive_datagram. \n\tPacket Number={}\n\tPlain Header={}\n\tPlain Payload={}".format(packet_number, plain_header, plain_payload))
                
            
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
                self._remote_initial_source_connection_id = header.source_cid
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
                network_path=network_path,
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

        print("\n>>> prett3.complete_connection: start")
        
        builder = self.get_builder(Epoch.HANDSHAKE)

        print(">>> prett3.complete_connection: start. Adding ACK frame to the builder")
        buf = builder.start_frame(
                    QuicFrameType.ACK,
                    capacity=ACK_FRAME_CAPACITY,
                )
        
        buf.push_uint_var(1) # largest acknowledged
        buf.push_uint_var(106) # ack delay
        buf.push_uint_var(0) # ack range count
        buf.push_uint_var(1) # ack range

        # CRYPTO
        print(">>> prett3.complete_connection: Adding CRYPTO frame to the builder")
        str_data = self._quic._crypto_streams[Epoch.HANDSHAKE].sender.get_frame(1135).data # TODO: calculate max_size dynamically instead of giving static number
        buf = builder.start_frame(
                QuicFrameType.CRYPTO,
                capacity=4, 
            )
        buf.push_uint_var(0) # offset 
        buf.push_uint16( len(str_data) | 0x4000) # length
        buf.push_bytes(str_data) # data

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
        
        print(">>> open_qpack_streams: start")

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

    def read_from_buffer(self):
        # receive server's response
        try:
            while True:
                data, addr = sock.recvfrom(2048) # 1024 causes problems
                print("\nReceived message: len={}\n".format(len(data)))
                self.receive_datagram(data, now=time.process_time())
        except socket.timeout: pass

def main(
    configuration: QuicConfiguration,
    url: str,
    sample_msg: pyshark.FileCapture
) -> None:

    h3client = HttpClient(configuration, urlparse(url).netloc)

    h3client.connect()
    h3client.read_from_buffer()


    time.sleep(0.1)


    h3client.complete_connection()
    h3client.read_from_buffer()
    

    time.sleep(0.1)


    h3client.open_qpack_streams()
    h3client.read_from_buffer()


    time.sleep(0.1)

    for msg in sample_msg:
        h3_data = h3client.replicate_sample_msg(msg)


    # headers_data = h3client.craft_sample_headers_frame()
    # print(type(headers_data))
    # # h3client.send_quic_stream(headers_data)
    # # h3client.read_from_buffer()
    


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
    http3_basic_messages = util.h3msg_from_pcap(args.pcap, client_only=True)

    main(
            configuration=configuration,
            url=args.url,
            sample_msg = http3_basic_messages
        )
    
    