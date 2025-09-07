
from aioquic.quic.connection import *
from aioquic.h3.connection import FrameType
from pyshark.packet.packet import Packet
from pyshark.packet.layers.xml_layer import XmlLayer
from dataclasses import dataclass, field
from typing import List

PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]

@dataclass
class H3Frame:
    pass

@dataclass
class H3Data(H3Frame):
    payload:bytes = None

@dataclass
class H3Headers(H3Frame):
    payload:bytes = None

@dataclass
class H3CancelPush(H3Frame):
    push_id:int = None

@dataclass
class H3Settings(H3Frame):
    max_table_capacity:int = None
    max_field_section_size:int = None
    blocked_streams:int = None
    h3_datagram:int = None
    webtransport:int = None

@dataclass
class H3PushPromise(H3Frame):
    push_id:int = None
    field_section:bytes = None

@dataclass
class H3GoAway(H3Frame):
    stream_id:int = None

@dataclass
class H3MaxPushId(H3Frame):
    push_id:int = None

@dataclass
class H3PriorityUpdate(H3Frame):
    element_id:int = None
    field_value:str = None

@dataclass
class QpackEncoder(H3Frame):
    payload:bytes = None

@dataclass
class QpackDecoder(H3Frame):
    payload:bytes = None


@dataclass
class QuicFrame:
    pass

@dataclass
class QuicPadding(QuicFrame):
    pass

@dataclass
class QuicPing(QuicFrame):
    pass

@dataclass
class QuicAck(QuicFrame):
    largest_acknowledged:int=None
    ack_delay:int=None
    ack_range_count:int=None
    ack_first_ack_range:int=None
    ack_ranges:List[Tuple[int,int]] = field(default_factory=list) # [gap, ack_range]

@dataclass
class QuicResetStream(QuicFrame):
    stream_id:int = None
    app_protocol_error_code:int = None
    final_size:int = None

@dataclass
class QuicStopSending(QuicFrame):
    stream_id:int = None
    app_protocol_error_code:int = None

@dataclass
class QuicCrypto(QuicFrame):
    offset:int = None
    # length:int = None
    data:bytes = None # offset, length and the length of data should match. Otherwise, it is malformed

@dataclass
class QuicNewTokenFrame(QuicFrame):
    # length:int = None
    token:bytes = None

@dataclass
class QuicStream(QuicFrame):
    stream_id:int = None
    fin_bit:bool = None
    # No need to play with the length field. We calculate length dynamically. Otherwise, the stream frame will be malformed most of the time.
    # length:int = None
    offset:int = None
    h3_frame:H3Frame = None

@dataclass
class QuicMaxData(QuicFrame):
    max_data:int = None

@dataclass
class QuicMaxStreamData(QuicFrame):
    stream_id:int = None
    max_stream_data:int = None

@dataclass
class QuicMaxStreams(QuicFrame):
    maximum_streams:int = None

@dataclass
class QuicDataBlocked(QuicFrame):
    max_data:int = None

@dataclass
class QuicStreamDataBlocked(QuicFrame):
    stream_id:int = None
    max_stream_data:int = None

@dataclass
class QuicStreamsBlocked(QuicFrame):
    bidirectional:bool = None
    max_streams:int = None

@dataclass
class QuicNewConnectionId(QuicFrame):
    sequence_number:int = None
    retire_prior_to:int = None
    # length:int = None
    connection_id:bytes = None
    stateless_reset_token:bytes = None # it should be 16 byte. Otherwise, the frame is malformed

@dataclass
class QuicRetireConnectionId(QuicFrame):
    sequence_number:int = None

@dataclass
class QuicPathChallenge(QuicFrame): 
    data:bytes = None  # should be 8 bytes or it is malformed

@dataclass
class QuicPathResponse(QuicFrame):
    data:bytes = None # should be 8 bytes or it is malformed

@dataclass
class QuicConnectionClose(QuicFrame):
    transport_layer:bool = None
    error_code:int = None
    frame_type:int = None
    # reason_phrase_length:int = None # reason_phrase_length should match the length of reason_phrase. Otherwise it is malformed
    reason_phrase:bytes = None

@dataclass
class QuicHandshakeDone(QuicFrame):
    pass




QuicPacket = List[QuicFrame] # A QUIC packet is basically a few Quic Frames sent together

class MSGDissector():
    def __init__(self):
        self.quic_frames:list = []

    def dissect_msg(self, message:Packet) -> List[QuicFrame]:
        h3_frames = []
        # Parse layers in the h3msg
        for layer in message.layers:
            if layer.layer_name == 'quic':
                for field in layer.frame.fields:
                    
                    if 'MAX_STREAMS' in field.showname:
                        self.quic_frames.append( self._dissect_max_streams_frame(layer) )
                    elif 'STREAM' in field.showname:
                        self.quic_frames.append( self._dissect_stream_frame(field.showname) )
                    elif 'ACK' in field.showname:
                        self.quic_frames.append( self._dissect_ack_frame(layer) )
                    elif 'NEW_CONNECTION_ID' in field.showname:
                        self.quic_frames.append( self._dissect_nci_frame(layer) )
                    elif 'PADDING' in field.showname:
                        pass
                    elif 'CRYPTO' in field.showname or 'PING' in field.showname:
                        pass
                    elif 'CONNECTION_CLOSE' in field.showname:
                        pass
                    else:
                        print(field)
                        raise Exception("[-] Unsupported QUIC Frame: {}".format(field.showname))
                    
            elif layer.layer_name == 'http3':
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
        quic_stream_frames = [qf for qf in self.quic_frames if isinstance(qf, QuicStream)]
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

    def _dissect_max_streams_frame(self, layer:XmlLayer) -> QuicMaxStreams:
        
        max_streams = QuicMaxStreams()
        
        max_streams.maximum_streams = layer.ms_max_streams
        
        return max_streams