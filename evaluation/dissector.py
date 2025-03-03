import sys

from aioquic.quic.connection import *
from aioquic.h3.connection import FrameType, StreamType, encode_settings, encode_frame
from aioquic.buffer import encode_uint_var
from aioquic.tls import Epoch
from pyshark.packet.packet import Packet
from pyshark.packet.layers.xml_layer import XmlLayer
from dataclasses import dataclass, field
from typing import List, Union

PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]


@dataclass
class QuicAck:
    largest_acknowledged:int=None
    ack_delay:int=None
    ack_range_count:int=None
    ack_first_ack_range:int=None
    ack_ranges:List[Tuple[int,int]] = field(default_factory=list) # [gap, ack_range]

@dataclass
class QuicNewConnectionId:
    sequence_number:int = None
    retire_prior_to:int = None
    length:int = None
    connection_id:bytes = None
    stateless_reset_token:bytes = None

@dataclass
class H3Settings:
    max_table_capacity:int = None
    max_field_section_size:int = None
    blocked_streams:int = None
    h3_datagram:int = None
    webtransport:int = None
    
@dataclass
class H3Headers:
    payload:bytes = None

@dataclass
class H3Data:
    payload:bytes = None
    
@dataclass
class H3PriorityUpdate:
    element_id:int = None
    field_value:str = None

@dataclass
class QpackEncoder:
    payload:bytes = None

@dataclass
class QpackDecoder:
    payload:bytes = None

@dataclass
class QuicStream:
    stream_id:int = None
    fin_bit:bool = None
    offset:int = None
    # No need to play with the length field. We calculate length dynamically. Otherwise, the stream frame will be malformed most of the time.
    # length:int = None
    h3_frame:Union[H3Settings, H3Headers, H3Data, H3PriorityUpdate, QpackEncoder, QpackDecoder] = None


class MSGDissector():
    def __init__(self):
        self.quic_frames:list = []

    def dissect_msg(self, message:Packet) -> List:
        
        h3_frames = []

        # Parse layers in the h3msg
        for layer in message.layers:
            if layer.layer_name == 'quic':
                #print(layer)
                for field in layer.frame.fields:

                    if 'STREAM' in field.showname:
                        self.quic_frames.append( self._dissect_stream_frame(field.showname) )
                    elif 'ACK' in field.showname:
                        self.quic_frames.append( self._dissect_ack_frame(layer) )
                    elif 'NEW_CONNECTION_ID' in field.showname:
                        self.quic_frames.append( self._dissect_nci_frame(layer) )
                    elif 'PADDING' in field.showname:
                        pass
                    elif 'CRYPTO' in field.showname or 'PING' in field.showname:
                        return
                    else:
                        print(field)
                        raise Exception("[-] Unsupported QUIC Frame: {}".format(field.showname))
                    
            
            elif layer.layer_name == 'http3':
                #print(layer)
                #print(layer.stream_uni)
                #print(layer.stream_uni_type)

                # This HTTP/3 layer has HTTP/3 frames
                if layer.has_field("frame_type"):
                    # Obtain safe value of frame type.
                    frame_type_value = layer.frame_type.strip()
                    try:
                        # Check if the value is hexadecimal
                        if frame_type_value.startswith("0x"):
                            h3_field_type = int(frame_type_value, 16)
                        else:
                            h3_field_type = int(frame_type_value)  # Assume decimal
                    except ValueError:
                        raise ValueError(f"Invalid frame_type value: {frame_type_value}")

                    if h3_field_type == FrameType.SETTINGS:
                        h3_frames.append(self._dissect_h3_settings_frame(layer))
                    elif h3_field_type == FrameType.HEADERS:
                        h3_frames.append(self._dissect_h3_headers_frame(layer))
                    elif h3_field_type == FrameType.DATA:
                        h3_frames.append(self._dissect_h3_data_frame(layer))
                    elif h3_field_type in PRIORITY_UPDATE_FRAME_IDS:  # PRIORITY_UPDATE_FRAME_TYPE
                        h3_frames.append(self._dissect_h3_priority_update_frame(layer))
                    else:
                        print(layer)
                        raise Exception("[-] Unsupported Application Layer Data: {}".format(field.showname)) 
                
                # This HTTP/3 layer has non-HTTP/3 data (QPACK)                
                else: 
                    if 'QPACK Encoder' in layer.stream_uni or 'qpack_encoder' in layer.field_names: 
                        h3_frames.append( self._dissect_qpack_encoder_frame(layer) )
                    elif 'QPACK Decoder' in layer.stream_uni: 
                        h3_frames.append( self._dissect_qpack_decoder_frame(layer) )
                    elif len(layer.field_names)==1 and layer.field_names[0]=='stream_uni':
                        # this is an empty unidirectional stream
                        h3_frames.append(None)
                    else:
                        print(layer)
                        raise Exception("[-] Unsupported Application Layer Data")
        
        # Put application layer data into the corresponding quic stream frame
        quic_stream_frames = [qf for qf in self.quic_frames if type(qf) == QuicStream]
        for quic_stream_frame, h3_frame in zip(quic_stream_frames, h3_frames):
            quic_stream_frame.h3_frame = h3_frame
        
        return self.quic_frames

    def _dissect_stream_frame(self, showname:str) -> QuicStream:
        quic_stream = QuicStream()

        quic_stream.stream_id = int(showname.split('id=')[1].split()[0])
        quic_stream.fin_bit = int(showname.split('fin=')[1].split()[0])
        quic_stream.offset = int(showname.split('off=')[1].split()[0])
        #quic_stream.length = int(showname.split('len=')[1].split()[0])

        return quic_stream

    def _dissect_ack_frame(self, layer: XmlLayer) -> QuicAck:

        ack_contents = QuicAck()

        # Extract ACK frame details from the layer
        ack_contents.largest_acknowledged = int(layer.ack_largest_acknowledged)
        ack_contents.ack_delay = int(layer.ack_ack_delay)
        ack_contents.ack_range_count = int(layer.ack_ack_range_count)
        ack_contents.ack_first_ack_range = int(layer.ack_first_ack_range)
        ack_contents.ack_ranges = []
        
        # Extract ACK ranges if present
        for i in range(ack_contents.ack_range_count):
            # if there are more than one ranges, pyshark gives only the first range
            gap = layer.ack_gap
            ack_range = layer.ack_ack_range
            ack_contents.ack_ranges.append((int(gap), int(ack_range)))

        return ack_contents

    def _dissect_nci_frame(self, layer:XmlLayer) -> QuicNewConnectionId:
        
        nci_contents = QuicNewConnectionId()

        nci_contents.sequence_number = int(layer.nci_sequence)
        nci_contents.retire_prior_to = int(layer.nci_retire_prior_to)
        nci_contents.length = int(layer.nci_connection_id_length)
        nci_contents.connection_id = bytes(int(part, 16) for part in layer.nci_connection_id.split(":"))
        nci_contents.stateless_reset_token = bytes(int(part, 16) for part in layer.nci_stateless_reset_token.split(":"))

        return nci_contents
    
    def _dissect_h3_settings_frame(self, layer:XmlLayer) -> H3Settings:
        """
        Generate an HTTP/3 SETTINGS frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 SETTINGS frame data.
        """
        
        h3_settings = H3Settings()

        # Extract SETTINGS fields from the HTTP/3 layer
        fields = layer._all_fields
        for key, value in fields.items():
            #print("{}: {}".format(key, value))
            # ignore layer fields that are not setting identifiers
            if not key.startswith("http3.settings."):
                continue
            
            # ignore unnecessary fields
            if key in ["http3.settings.id", "http3.settings.value"]:
                continue
            
            # read settings fields
            if key == "http3.settings.qpack.max_table_capacity":
                h3_settings.max_table_capacity = int(value)

            elif key == "http3.settings.max_field_section_size":
                h3_settings.max_field_section_size = int(value)
                
            elif key == "http3.settings.qpack.blocked_streams":
                h3_settings.blocked_streams = int(value)

            elif key == "http3.settings.h3_datagram":
                h3_settings.h3_datagram = int(value)
                
            elif key == "http3.settings.webtransport":
                h3_settings.webtransport = int(value)
                
            else:
                raise Exception("Unexpected SETTINGS Identifier: {}. Add it here...".format(key))

        return h3_settings

    def _dissect_h3_headers_frame(self, layer:XmlLayer) -> H3Headers:
        """
        Generate an HTTP/3 HEADERS frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 HEADERS frame data.
        """
        h3_headers = H3Headers()

        if hasattr(layer, "frame_payload"):
            h3_headers.payload = bytes.fromhex(layer.frame_payload.raw_value) 
        else:
            raise ValueError("HEADERS frame payload not found or is empty")

        return h3_headers

    def _dissect_h3_data_frame(self, layer:XmlLayer) -> H3Data:
        """
        Generate an HTTP/3 DATA frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 DATA frame data.
        """

        h3_data_contents = H3Data()

        # Extract raw payload for data
        if hasattr(layer, "payload") and layer.payload.raw_value:
            h3_data_contents.payload = bytes.fromhex(layer.frame_payload.raw_value) 
        else:
            raise ValueError("DATA frame payload not found")

        
        return h3_data_contents

    def _dissect_h3_priority_update_frame(self, layer:XmlLayer) -> bytes:
        """
        Generate an HTTP/3 PRIORITY_UPDATE frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 PRIORITY_UPDATE frame data.
        """

        priority_update = H3PriorityUpdate()
        priority_update.element_id = int(layer.priority_update_element_id)
        priority_update.field_value = str(layer.priority_update_field_value)
        
        return priority_update

    def _dissect_qpack_encoder_frame(self, layer:XmlLayer) -> QpackEncoder:

        qpack_encoder = QpackEncoder()

        if 'qpack_encoder' in layer.field_names and layer.qpack_encoder.raw_value is not None:
            qpack_encoder.payload = bytes.fromhex(layer.qpack_encoder.raw_value)
        else:
            qpack_encoder.payload = b''

        return qpack_encoder

    def _dissect_qpack_decoder_frame(self, layer:XmlLayer) -> QpackDecoder:

        qpack_decoder = QpackDecoder()

        if len( layer.field_names) == 2:
            # the decoder does not have any data
            qpack_decoder.payload = b''
        else:
            print(layer)
            print(layer.field_names)
            # in our traffic, all decoder streams are empty. Therefore, we are not sure what fields there would be, if there was real data.
            # we suppose it will be layer.qpack_decoder, just like qpack encoder. If it is wrong, modify the field name below.
            qpack_decoder.payload = bytes.fromhex(layer.qpack_decoder.raw_value)

        return qpack_decoder

