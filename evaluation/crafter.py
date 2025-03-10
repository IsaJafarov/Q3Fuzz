import sys

import aioquic
from aioquic.quic.connection import *
from aioquic.h3.connection import FrameType, StreamType, encode_settings, encode_frame
from aioquic.buffer import encode_uint_var
from aioquic.tls import Epoch
from pyshark.packet.packet import Packet
from pyshark.packet.layers.xml_layer import XmlLayer
from dataclasses import dataclass, field
from typing import List, Union
from dissector import *

PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]



class MSGCrafter():

    def __init__(self):
        self.quic_frames:list = []
        self.stream_offsets = dict()
        self.opened_uni_streams = set()

    def copy_msg(self, h3msg:Packet, builder:QuicPacketBuilder, exclude_ack:bool = False) -> None:
        msg_dissector = MSGDissector()
        quic_frames = msg_dissector.dissect_msg(h3msg)

        for quic_frame in quic_frames:

            if exclude_ack and type(quic_frame) is QuicAck:
                continue
            self.add_dissected_frames_to_builder(quic_frame, builder)

    def craft_msg_from_frames(self, quic_frames:List, builder:QuicPacketBuilder) -> None:
        for quic_frame in quic_frames:
            self.add_dissected_frames_to_builder(quic_frame, builder)


    def add_dissected_frames_to_builder(self, quic_frame, builder:QuicPacketBuilder):
        if type(quic_frame) == QuicAck:
            self.add_ack_frame(quic_frame, builder)
        elif type(quic_frame) == QuicNewConnectionId:
            self.add_nci_frame(quic_frame, builder)
        elif type(quic_frame) == QuicStream:
            self.add_stream_frame(quic_frame, builder)
        else:
            raise Exception("Unexpected QUIC frame {}. Add it here.".format(quic_frame))
        
    def add_ack_frame(self, quic_frame:QuicAck, builder:QuicPacketBuilder) -> None:
        """
        class QuicAck:
        largest_acknowledged:int=None
        ack_delay:int=None
        ack_range_count:int=None
        ack_first_ack_range:int=None
        ack_ranges:List[Tuple[int,int]] = field(default_factory=list)
        """

        # Start the ACK frame in the builder
        buf = builder.start_frame(frame_type=QuicFrameType.ACK, capacity=16)

        buf.push_uint_var(quic_frame.largest_acknowledged)
        buf.push_uint_var(quic_frame.ack_delay)
        buf.push_uint_var(quic_frame.ack_range_count)
        buf.push_uint_var(quic_frame.ack_first_ack_range)
        

        for gap, ack_range in quic_frame.ack_ranges:
            buf.push_uint_var(gap)
            buf.push_uint_var(ack_range)

    def add_nci_frame(self, quic_frame:QuicNewConnectionId, builder:QuicPacketBuilder) -> None:
        """
        class QuicNewConnectionId:
        sequence_number:int = None
        retire_prior_to:int = None
        length:int = None
        connection_id:bytes = None
        stateless_reset_token:bytes = None
        """

        buf = builder.start_frame(
            QuicFrameType.NEW_CONNECTION_ID,
            capacity=NEW_CONNECTION_ID_FRAME_CAPACITY
        )
        buf.push_uint_var( quic_frame.sequence_number ) # Sequence Number
        buf.push_uint_var( quic_frame.retire_prior_to ) # Retire Prior To
        buf.push_uint8( quic_frame.length ) # Length
        buf.push_bytes( quic_frame.connection_id ) # Connection ID
        buf.push_bytes( quic_frame.stateless_reset_token  ) # Stateless Reset Token

    def add_stream_frame(self, quic_frame:QuicStream, builder:QuicPacketBuilder) -> None:
        """
        @dataclass
        class QuicStream:
        stream_id:int = None
        fin_bit:bool = None
        offset:int = None
        length:int = None
        h3_frame:int = None
        """

        current_offset = self.stream_offsets.get(quic_frame.stream_id, 0)
        
        stream_type = QuicFrameType.STREAM_BASE | 2  # Include LEN bit
        if current_offset > 0:# quic_frame.offset != 0:
            stream_type |= 4  # Include OFF bit
        

        # During SM generation, we will not include the FIN. So that one stream frame will not close the stream and all stream frames will freely carry data.
        #if quic_frame.fin_bit:
        #    stream_type |= 1  # Include FIN bit

        # Combine all HTTP/3 frames into a single payload
        h3_frame_payload = None
        if type(quic_frame.h3_frame) == H3Settings:
            h3_frame_payload = self.generate_h3_settings_frame(quic_frame.h3_frame)
        elif type(quic_frame.h3_frame) == H3Headers:
            h3_frame_payload = self.generate_h3_headers_frame(quic_frame.h3_frame)
        elif type(quic_frame.h3_frame) == H3Data:
            h3_frame_payload = self.generate_h3_data_frame(quic_frame.h3_frame)
        elif type(quic_frame.h3_frame) == H3PriorityUpdate:
            h3_frame_payload = self.generate_h3_priority_update_frame(quic_frame.h3_frame)
        elif type(quic_frame.h3_frame) == QpackEncoder:
            h3_frame_payload = self.generate_qpack_encoder(quic_frame.h3_frame, quic_frame.offset==0)
        elif type(quic_frame.h3_frame) == QpackDecoder:
            h3_frame_payload = self.generate_qpack_decoder(quic_frame.h3_frame, quic_frame.offset==0)
        elif quic_frame.h3_frame is None:
            h3_frame_payload = b'' # the stream does not have an application layer data
        else:
            raise Exception("Unexpected HTTP/3 frame {}. Add it here...".format(quic_frame.h3_frame))

        # If unidirection stream has already been created by previously sent STREAM frames, then do not prepend the HTTP/3 stream type.
        # Otherwise, prepend the corresponding stream type.
        if quic_frame.stream_id % 4 == 2 and quic_frame.stream_id not in self.opened_uni_streams:
            if quic_frame.stream_id==2:
                h3_frame_payload = encode_uint_var(StreamType.CONTROL) + h3_frame_payload
            elif type(quic_frame.h3_frame) == QpackEncoder:
                h3_frame_payload = encode_uint_var(StreamType.QPACK_ENCODER) + h3_frame_payload 
            elif type(quic_frame.h3_frame) == QpackDecoder:
                h3_frame_payload = encode_uint_var(StreamType.QPACK_DECODER) + h3_frame_payload
            self.opened_uni_streams.add(quic_frame.stream_id)

        
        buf = builder.start_frame(stream_type, capacity=len(h3_frame_payload) + 8)
        buf.push_uint_var(quic_frame.stream_id)  # Push stream ID
        if current_offset > 0:
            buf.push_uint_var( current_offset ) # (quic_frame.offset)  # Push offset
        buf.push_uint_var(len(h3_frame_payload))  # Push total length
        
        buf.push_bytes(h3_frame_payload)  # Push combined payload

        self.stream_offsets[quic_frame.stream_id] = current_offset + len(h3_frame_payload)

        

    def generate_h3_settings_frame(self, h3_frame:H3Settings) -> bytes:
        """
        max_table_capacity:int = None
        max_field_section_size:int = None
        blocked_streams:int = None
        h3_datagram:int = None
        webtransport:int = None
        """
        settings = {}

        if h3_frame.max_table_capacity is not None:
            settings[0x01] = h3_frame.max_table_capacity

        if h3_frame.max_field_section_size is not None:
            settings[0x06] = h3_frame.max_field_section_size

        if h3_frame.blocked_streams is not None:
            settings[0x07] = h3_frame.blocked_streams

        if h3_frame.h3_datagram is not None:
            settings[0x33] = h3_frame.h3_datagram

        if h3_frame.webtransport is not None:
            settings[0x2B603742] = h3_frame.webtransport

        # Encode the settings into SETTINGS frame payload
        settings_data = encode_settings(settings)

        # Encode the SETTINGS frame
        frame_data = encode_frame(FrameType.SETTINGS, settings_data)

        return frame_data
    
    def generate_h3_headers_frame(self, h3_frame:H3Headers) -> bytes:

        return encode_frame(FrameType.HEADERS, h3_frame.payload)

    def generate_h3_data_frame(self, h3_frame:H3Data) -> bytes:

        return encode_frame(FrameType.DATA, h3_frame.payload)

    def generate_h3_priority_update_frame(self, h3_frame:H3PriorityUpdate) -> bytes:
        """
        element_id:int = None
        field_value:str = None
        """

        data_payload = b""
        data_payload += encode_uint_var(h3_frame.element_id)  
        data_payload += h3_frame.field_value.encode()
        
        # Encode the PRIORITY_UPDATE frame
        frame_data = encode_frame(PRIORITY_UPDATE_FRAME_IDS[0], data_payload )
        
        return frame_data
    
    def generate_qpack_encoder(self, h3_frame:QpackEncoder, include_stream_type:bool=True) -> bytes:
        
        if include_stream_type:
            return h3_frame.payload
        else:
            return h3_frame.payload
    
    def generate_qpack_decoder(self, h3_frame:QpackDecoder, include_stream_type:bool=True) -> bytes:
        
        if include_stream_type:
            return h3_frame.payload
        else:
            return h3_frame.payload



    
