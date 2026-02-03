
from aioquic.quic.connection import *
from aioquic.h3.connection import FrameType, StreamType, encode_settings, encode_frame
from aioquic.buffer import encode_uint_var
from typing import List
from .dissector import *

PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]

class MSGCrafter():
    def __init__(self, http_client=None):
        self.quic_frames:list = []
        self.http_client = http_client
        self.stream_offsets = dict()
        self.opened_uni_streams = set()
        

    def craft_msg_from_frames(self, quic_frames:List[QuicFrame], builder:QuicPacketBuilder) -> None:
        for quic_frame in quic_frames:
            self.add_dissected_frames_to_builder(quic_frame, builder)

    def add_dissected_frames_to_builder(self, quic_frame, builder:QuicPacketBuilder):

        if isinstance(quic_frame, QuicPadding):
            self._add_padding_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicPing):
            self._add_ping_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicAck):
            self._add_ack_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicResetStream):
            self._add_reset_streams_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicStopSending):
            self._add_stop_sending_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicCrypto):
            self._add_crypto_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicNewTokenFrame):
            self._add_new_token_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicStream):
            self._add_stream_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicMaxData):
            self._add_max_data_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicMaxStreamData):
            self._add_max_stream_data_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicMaxStreams):
            self._add_max_streams_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicDataBlocked):
            self._add_data_blocked_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicStreamDataBlocked):
            self._add_stream_data_blocked_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicStreamsBlocked):
            self._add_streams_blocked_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicNewConnectionId):
            self._add_nci_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicRetireConnectionId):
            self._add_retire_connection_id_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicPathChallenge):
            self._add_path_challenge_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicPathResponse):
            self._add_path_response_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicConnectionClose):
            self._add_connection_close_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicHandshakeDone):
            self._add_handshake_done_frame(quic_frame, builder)
        elif isinstance(quic_frame, QuicDatagram):
            self._add_datagram_frame(quic_frame, builder)
        else:
            raise Exception("Unexpected QUIC frame {}. Add it here.".format(quic_frame))



    def _generate_h3_data_frame(self, h3_frame:H3Data) -> bytes:

        return encode_frame(FrameType.DATA, h3_frame.payload)

    def _generate_h3_headers_frame(self, h3_frame:H3Headers) -> bytes:

        return encode_frame(FrameType.HEADERS, h3_frame.payload)

    def _generate_cancel_push_frame(self, h3_frame:H3CancelPush) -> bytes:
        """
        H3CancelPush:
            push_id:int
        """

        data_payload = b""
        # data_payload += encode_uint_var(h3_frame.length)
        data_payload += encode_uint_var(h3_frame.push_id)
        
        # Add the Frame Type
        frame_data = encode_frame(FrameType.CANCEL_PUSH, data_payload )
        
        return frame_data
    
    def _generate_h3_settings_frame(self, h3_frame:H3Settings) -> bytes:
        """
        H3Settings
            max_table_capacity:int
            max_field_section_size:int
            blocked_streams:int
            h3_datagram:bool
            webtransport:bool
        """
        settings = {}

        if h3_frame.max_table_capacity is not None:
            settings[0x01] = h3_frame.max_table_capacity

        if h3_frame.max_field_section_size is not None:
            settings[0x06] = h3_frame.max_field_section_size

        if h3_frame.blocked_streams is not None:
            settings[0x07] = h3_frame.blocked_streams

        if h3_frame.h3_datagram is not None:
            settings[0x33] = 1 if h3_frame.h3_datagram else 0

        if h3_frame.webtransport is not None:
            settings[0x2B603742] = 1 if h3_frame.webtransport else 0

        # Encode the settings into SETTINGS frame payload
        settings_data = encode_settings(settings)

        # Encode the SETTINGS frame
        frame_data = encode_frame(FrameType.SETTINGS, settings_data)

        return frame_data
    
    def _generate_push_promise_frame(self, h3_frame:H3PushPromise) -> bytes:
        """
        H3PushPromise:
            push_id:int
            field_section:bytes
        """

        data_payload = b""
        # data_payload += encode_uint_var(h3_frame.length)
        data_payload += encode_uint_var(h3_frame.push_id)
        data_payload += h3_frame.field_section
        
        # Add the Frame Type
        frame_data = encode_frame(FrameType.PUSH_PROMISE, data_payload )
        
        return frame_data
    
    def _generate_goaway_frame(self, h3_frame:H3GoAway) -> bytes:
        """
        H3GoAway:
            stream_id:int
        """

        data_payload = b""
        data_payload += encode_uint_var(h3_frame.stream_id)

        
        # Add the Frame Type
        frame_data = encode_frame(FrameType.GOAWAY, data_payload )
        
        return frame_data
    
    def _generate_max_push_id_frame(self, h3_frame:H3MaxPushId) -> bytes:
        """
        H3MaxPushId:
            push_id:int
        """

        data_payload = b""
        data_payload += encode_uint_var(h3_frame.push_id)

        
        # Add the Frame Type
        frame_data = encode_frame(FrameType.MAX_PUSH_ID, data_payload )
        
        return frame_data
 
    def _generate_h3_priority_update_frame(self, h3_frame:H3PriorityUpdate) -> bytes:
        """
        H3PriorityUpdate
            element_id:int
            field_value:str
        """

        data_payload = b""
        data_payload += encode_uint_var(h3_frame.element_id)  
        data_payload += h3_frame.field_value.encode()
        
        # Add the Frame Type
        frame_data = encode_frame(PRIORITY_UPDATE_FRAME_IDS[0], data_payload )
        
        return frame_data
    
    def _generate_h3_origin_frame(self, h3_frame:H3Origin) -> bytes:
        """
        H3Origin:
            entries:List[str]
        """

        data_payload = b""
        for entry in h3_frame.entries:
            data_payload += len(entry).to_bytes(2, byteorder='big', signed=False)
            data_payload += entry.encode()
        
        frame_data = encode_frame(0xC, data_payload)

        return frame_data


    def _generate_qpack_encoder(self, h3_frame:QpackEncoder, include_stream_type:bool=True) -> bytes:
        
        if include_stream_type:
            return h3_frame.payload
        else:
            return h3_frame.payload
    
    def _generate_qpack_decoder(self, h3_frame:QpackDecoder, include_stream_type:bool=True) -> bytes:
        
        if include_stream_type:
            return h3_frame.payload
        else:
            return h3_frame.payload



    def _add_padding_frame(self, quic_frame:QuicPadding, builder:QuicPacketBuilder) -> None:
        """
        QuicPadding:
            pass
        """
        buf = builder.start_frame(
            QuicFrameType.PADDING,
            # capacity=PADDING
        )

    def _add_ping_frame(self, quic_frame:QuicPing, builder:QuicPacketBuilder) -> None:
        """
        QuicPing:
            pass
        """
        buf = builder.start_frame(
            QuicFrameType.PING,
            capacity=PING_FRAME_CAPACITY
        )

    def _add_ack_frame(self, quic_frame:QuicAck, builder:QuicPacketBuilder) -> None:
        """
        QuicAck:
            largest_acknowledged:int
            ack_delay:int
            ack_range_count:int
            ack_first_ack_range:int
            ack_ranges:List[Tuple[int,int]]
        """

        # Start the ACK frame in the builder
        buf = builder.start_frame(frame_type=QuicFrameType.ACK, capacity=16)
        largest_acknowledged = quic_frame.largest_acknowledged
        # For every ACK to be sent, we update largest_ack to the latest packet to avoid a server from thinking packet loss
        if self.http_client is not None and len(self.http_client.received_packet_numbers):
            largest_acknowledged = max(self.http_client.received_packet_numbers)
            # print("largest_acknowledged is updated to %d" % largest_acknowledged)
        buf.push_uint_var(largest_acknowledged)
        buf.push_uint_var(quic_frame.ack_delay)
        buf.push_uint_var(quic_frame.ack_range_count)
        buf.push_uint_var(quic_frame.ack_first_ack_range)
        

        for gap, ack_range in quic_frame.ack_ranges:
            buf.push_uint_var(gap)
            buf.push_uint_var(ack_range)

    def _add_reset_streams_frame(self, quic_frame:QuicResetStream, builder:QuicPacketBuilder) -> None:
        """
        QuicResetStream:
            stream_id:int
            app_protocol_error_code:int
            final_size:int
        """
        buf = builder.start_frame(
            QuicFrameType.RESET_STREAM,
            capacity=RESET_STREAM_FRAME_CAPACITY
        )
        buf.push_uint_var( quic_frame.stream_id ) # Stream ID
        buf.push_uint_var( quic_frame.app_protocol_error_code ) # Application Protocol Error Code
        buf.push_uint_var( quic_frame.final_size ) # Final Size

    def _add_stop_sending_frame(self, quic_frame:QuicStopSending, builder:QuicPacketBuilder) -> None:
        """
        QuicStopSending:
            stream_id:int
            app_protocol_error_code:int
        """

        buf = builder.start_frame(
            QuicFrameType.STOP_SENDING,
            capacity=STOP_SENDING_FRAME_CAPACITY
        )
        buf.push_uint_var( quic_frame.stream_id ) # Stream ID
        buf.push_uint_var( quic_frame.app_protocol_error_code ) # Application Protocol Error Code
    
    def _add_crypto_frame(self, quic_frame:QuicCrypto, builder:QuicPacketBuilder) -> None:
        """
        QuicCrypto:
            offset:int
            data:bytes
        """

        buf = builder.start_frame(
            QuicFrameType.CRYPTO,
            # capacity=CRYPTO_BUFFER_SIZE
        )
        buf.push_uint_var( quic_frame.offset ) # Offset
        buf.push_uint_var( len( quic_frame.data ) ) # Length
        buf.push_bytes( quic_frame.data ) # Crypto Data

    def _add_new_token_frame(self, quic_frame:QuicNewTokenFrame, builder:QuicPacketBuilder) -> None:
        """
        QuicNewTokenFrame:
            token:bytes
        """

        buf = builder.start_frame(
            QuicFrameType.NEW_TOKEN,
            # capacity=NEW_TOKE
        )
        buf.push_uint_var( len(quic_frame.token) ) # Token Length
        buf.push_bytes( quic_frame.token ) # Token
    
    def _add_stream_frame(self, quic_frame:QuicStream, builder:QuicPacketBuilder) -> None:
        """
        QuicStream:
            stream_id:int
            fin_bit:bool
            offset:int
            h3_frame:int
        """

        current_offset = self.stream_offsets.get(quic_frame.stream_id, 0)
        
        stream_type = QuicFrameType.STREAM_BASE | 2  # Include LEN bit
        if current_offset > 0:# quic_frame.offset != 0:
            stream_type |= 4  # Include OFF bit
        

        # Comment out below so that one stream frame will not close the stream and all stream frames will freely carry data.
        # (NOTE) In case of H2O, the unset fin_bit makes the server answer no HEADER or DATA to HEADER request.
        if quic_frame.fin_bit:
           stream_type |= 1  # Include FIN bit
        

        # Combine all HTTP/3 frames into a single payload
        h3_frame_payload = None
        if isinstance(quic_frame.h3_frame, H3Data):
            h3_frame_payload = self._generate_h3_data_frame(quic_frame.h3_frame)
        elif isinstance(quic_frame.h3_frame, H3Headers):
            h3_frame_payload = self._generate_h3_headers_frame(quic_frame.h3_frame)
        elif isinstance(quic_frame.h3_frame, H3CancelPush):
            h3_frame_payload = self._generate_cancel_push_frame(quic_frame.h3_frame)
        elif isinstance(quic_frame.h3_frame, H3Settings):
            h3_frame_payload = self._generate_h3_settings_frame(quic_frame.h3_frame)
        elif isinstance(quic_frame.h3_frame, H3PushPromise):
            h3_frame_payload = self._generate_push_promise_frame(quic_frame.h3_frame)
        elif isinstance(quic_frame.h3_frame, H3GoAway):
            h3_frame_payload = self._generate_goaway_frame(quic_frame.h3_frame)
        elif isinstance(quic_frame.h3_frame, H3MaxPushId):
            h3_frame_payload = self._generate_max_push_id_frame(quic_frame.h3_frame)
        elif isinstance(quic_frame.h3_frame, H3PriorityUpdate):
            h3_frame_payload = self._generate_h3_priority_update_frame(quic_frame.h3_frame)
        elif isinstance(quic_frame.h3_frame, H3Origin):
            h3_frame_payload = self._generate_h3_origin_frame(quic_frame.h3_frame)
        elif isinstance(quic_frame.h3_frame, QpackEncoder):
            h3_frame_payload = self._generate_qpack_encoder(quic_frame.h3_frame, quic_frame.offset==0)
        elif isinstance(quic_frame.h3_frame, QpackDecoder):
            h3_frame_payload = self._generate_qpack_decoder(quic_frame.h3_frame, quic_frame.offset==0)
        elif quic_frame.h3_frame is None:
            h3_frame_payload = b'' # the stream does not have an application layer data
        else:
            raise Exception("Unexpected HTTP/3 frame {}. Add it here...".format(quic_frame.h3_frame))
        
        

        # If unidirection stream has already been created by previously sent STREAM frames, then do not prepend the HTTP/3 stream type.
        # Otherwise, prepend the corresponding stream type.
        if quic_frame.stream_id % 4 == 2 and quic_frame.stream_id not in self.opened_uni_streams:
            if quic_frame.stream_id==2:
                h3_frame_payload = encode_uint_var(StreamType.CONTROL) + h3_frame_payload
            elif isinstance(quic_frame.h3_frame, QpackEncoder):
                h3_frame_payload = encode_uint_var(StreamType.QPACK_ENCODER) + h3_frame_payload 
            elif isinstance(quic_frame.h3_frame, QpackDecoder):
                h3_frame_payload = encode_uint_var(StreamType.QPACK_DECODER) + h3_frame_payload
            self.opened_uni_streams.add(quic_frame.stream_id)
            
        
        # TODO TEMPORARY
        # h3_frame_payload = b'' # the stream does not have an application layer data

        
        buf = builder.start_frame(stream_type, capacity=len(h3_frame_payload) + 8)
        buf.push_uint_var(quic_frame.stream_id)  # Push stream ID
        if current_offset > 0:
            buf.push_uint_var( current_offset ) # (quic_frame.offset)  # Push offset
        buf.push_uint_var(len(h3_frame_payload))  # Push total length
        
        buf.push_bytes(h3_frame_payload)  # Push combined payload

        self.stream_offsets[quic_frame.stream_id] = current_offset + len(h3_frame_payload)

    def _add_max_data_frame(self, quic_frame:QuicMaxData, builder:QuicPacketBuilder) -> None:
        """
        QuicMaxData:
            max_data:int
        """

        buf = builder.start_frame(
            QuicFrameType.MAX_DATA,
            # capacity=MAX_DATA
        )
        buf.push_uint_var( quic_frame.max_data ) # Maximum Data
    
    def _add_max_stream_data_frame(self, quic_frame:QuicMaxStreamData, builder:QuicPacketBuilder) -> None:
        """
        QuicMaxStreamData:
            stream_id:int
            max_stream_data:int
        """

        buf = builder.start_frame(
            QuicFrameType.MAX_STREAM_DATA,
            capacity=MAX_STREAM_DATA_FRAME_CAPACITY
        )
        buf.push_uint_var( quic_frame.stream_id ) # Stream ID
        buf.push_uint_var( quic_frame.max_stream_data ) # Maximum Stream Data

    def _add_max_streams_frame(self, quic_frame:QuicMaxStreams, builder:QuicPacketBuilder) -> None:
        '''
         QuicMaxStreams:
            maximum_streams:int
        '''
        buf = builder.start_frame(
            QuicFrameType.MAX_STREAMS_UNI,
            capacity=MAX_STREAM_DATA_FRAME_CAPACITY
        )
        buf.push_uint_var( quic_frame.maximum_streams ) # Maximum Streams
    
    def _add_data_blocked_frame(self, quic_frame:QuicDataBlocked, builder:QuicPacketBuilder) -> None:
        """
        QuicDataBlocked:
            max_data:int
        """

        buf = builder.start_frame(
            QuicFrameType.DATA_BLOCKED,
            # capacity=DATA_BLOCKED
        )
        buf.push_uint_var( quic_frame.max_data ) # Maximum Data

    def _add_stream_data_blocked_frame(self, quic_frame:QuicStreamDataBlocked, builder:QuicPacketBuilder) -> None:
        """
        QuicStreamDataBlocked:
            stream_id:int
            max_stream_data:int
        """

        buf = builder.start_frame(
            QuicFrameType.STREAM_DATA_BLOCKED,
            # capacity=STREAm_da
        )
        buf.push_uint_var( quic_frame.stream_id ) # Stream ID
        buf.push_uint_var( quic_frame.max_stream_data ) # Maximum Stream Data

    def _add_streams_blocked_frame(self, quic_frame:QuicStreamsBlocked, builder:QuicPacketBuilder) -> None:
        """
        QuicStreamsBlocked:
            bidirectional:bool
            max_streams:int
        """

        buf = builder.start_frame(
            QuicFrameType.STREAMS_BLOCKED_BIDI if quic_frame.bidirectional else QuicFrameType.STREAMS_BLOCKED_UNI,
            capacity=STREAMS_BLOCKED_CAPACITY
        )
        buf.push_uint_var( quic_frame.max_streams ) # Maximum Streams

    def _add_nci_frame(self, quic_frame:QuicNewConnectionId, builder:QuicPacketBuilder) -> None:
        """
        QuicNewConnectionId:
            sequence_number:int
            retire_prior_to:int
            connection_id:bytes
            stateless_reset_token:bytes
        """

        buf = builder.start_frame(
            QuicFrameType.NEW_CONNECTION_ID,
            capacity=NEW_CONNECTION_ID_FRAME_CAPACITY
        )
        buf.push_uint_var( quic_frame.sequence_number ) # Sequence Number
        buf.push_uint_var( quic_frame.retire_prior_to ) # Retire Prior To
        buf.push_uint8( len(quic_frame.connection_id) ) # Length
        buf.push_bytes( quic_frame.connection_id ) # Connection ID
        buf.push_bytes( quic_frame.stateless_reset_token  ) # Stateless Reset Token

    def _add_retire_connection_id_frame(self, quic_frame:QuicRetireConnectionId, builder:QuicPacketBuilder) -> None:
        """
        QuicRetireConnectionId:
            sequence_number:int
        """

        buf = builder.start_frame(
            QuicFrameType.RETIRE_CONNECTION_ID,
            capacity=RETIRE_CONNECTION_ID_CAPACITY
        )
        buf.push_uint_var( quic_frame.sequence_number ) # Sequence Number

    def _add_path_challenge_frame(self, quic_frame:QuicPathChallenge, builder:QuicPacketBuilder) -> None:
        """
        QuicPathChallenge:
            data:bytes
        """

        buf = builder.start_frame(
            QuicFrameType.PATH_CHALLENGE,
            capacity=PATH_CHALLENGE_FRAME_CAPACITY
        )
        buf.push_bytes( quic_frame.data ) # Data

    def _add_path_response_frame(self, quic_frame:QuicPathResponse, builder:QuicPacketBuilder) -> None:
        """
        QuicPathResponse:
            data:bytes
        """

        buf = builder.start_frame(
            QuicFrameType.PATH_RESPONSE,
            capacity=PATH_RESPONSE_FRAME_CAPACITY
        )
        buf.push_bytes( quic_frame.data ) # Data

    def _add_connection_close_frame(self, quic_frame:QuicConnectionClose, builder:QuicPacketBuilder) -> None:
        """
        QuicConnectionClose:
            error_code:int
            frame_type:int
            reason_phrase:bytes
        """

        buf = builder.start_frame(
            QuicFrameType.TRANSPORT_CLOSE if quic_frame.transport_layer else QuicFrameType.APPLICATION_CLOSE,
            capacity = TRANSPORT_CLOSE_FRAME_CAPACITY if quic_frame.transport_layer else APPLICATION_CLOSE_FRAME_CAPACITY
        )

        buf.push_uint_var( quic_frame.error_code ) # Error Code
        buf.push_uint_var( quic_frame.frame_type ) # Frame Type
        buf.push_uint_var( len( quic_frame.reason_phrase ) ) # Reason Phrase Length
        buf.push_bytes( quic_frame.reason_phrase ) # Reason Phrase

    def _add_handshake_done_frame(self, quic_frame:QuicHandshakeDone, builder:QuicPacketBuilder) -> None:
        """
        QuicHandshakeDone:
            pass
        """

        buf = builder.start_frame(
            QuicFrameType.HANDSHAKE_DONE,
            capacity = HANDSHAKE_DONE_FRAME_CAPACITY
        )

    def _add_datagram_frame(self, quic_frame:QuicDatagram, builder:QuicPacketBuilder) -> None:
        """
        QuicDatagram
            h3_datagram:H3Datagram
        """

        application_layer_payload = encode_uint_var(quic_frame.h3_datagram.quarter_stream_id) + quic_frame.h3_datagram.payload

        buf = builder.start_frame(
            QuicFrameType.DATAGRAM_WITH_LENGTH,
        )
        buf.push_uint_var( len(application_layer_payload) )
        buf.push_bytes( application_layer_payload )