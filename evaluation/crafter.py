import sys

import aioquic
from aioquic.quic.connection import *
from aioquic.h3.connection import FrameType, StreamType, encode_settings, encode_frame
from aioquic.buffer import encode_uint_var
from aioquic.tls import Epoch
from pyshark.packet.packet import Packet
from pyshark.packet.layers.xml_layer import XmlLayer

PRIORITY_UPDATE_FRAME_IDS = [0xf0700, 0xf0701]

class MSGCrafter():
    def __init__(self, qc: QuicConnection, client):
        self.connection = qc
        self.client = client

    def copy_msg(self, h3msg: Packet) -> QuicPacketBuilder:
        """
        Build a QuicPacketBuilder with multiple frames in one QUIC packet.

        Args:
            h3msg: The parsed QUIC/HTTP3 packet.

        Returns:
            builder: A QuicPacketBuilder instance with all frames added.
        """
        builder = self.client.get_builder(Epoch.ONE_RTT)

        # Containers to hold QUIC stream and HTTP/3 frame information
        quic_streams = []

        # Helper dataclass for stream metadata
        @dataclass
        class QuicStreamInfo:
            fin_bit: bool = False
            stream_id: int = 0
            offset: int = 0

        # Parse layers in the h3msg
        for layer in h3msg.layers:
            if layer.layer_name == 'quic':
                for field in layer.frame.fields:
                    if 'STREAM' in field.showname:
                        stream_info = QuicStreamInfo()
                        stream_showname = field.showname
                        stream_info.stream_id = int(stream_showname.split('id=')[1].split()[0])
                        stream_info.offset = int(stream_showname.split('off=')[1].split()[0])
                        stream_info.fin_bit = int(stream_showname.split('fin=')[1].split()[0])
                        quic_streams.append(stream_info)
                    elif 'ACK' in field.showname:
                        self.add_ack_frame(builder, layer)
                    elif 'NEW_CONNECTION_ID' in field.showname:
                        self.add_nci_frame(builder, layer)
                    elif 'PADDING' in field.showname:
                        pass
                    else:
                        print(field)
                        raise "[-] Unsupported QUIC Frame"
                    
            elif layer.layer_name == 'http3':
                
                # This HTTP/3 layer has HTTP/3 frames
                if layer.has_field("frame_type"):
                    
                    h3_field_type = int(layer.frame_type)

                    if h3_field_type == FrameType.SETTINGS:
                        frame_data = self.generate_h3_settings_frame(layer)
                    elif h3_field_type == FrameType.HEADERS:
                        frame_data = self.generate_h3_headers_frame(layer) 
                    elif h3_field_type == FrameType.DATA:
                        frame_data = self.generate_h3_data_frame(layer)
                    elif h3_field_type in PRIORITY_UPDATE_FRAME_IDS:  # PRIORITY_UPDATE_FRAME_TYPE
                        frame_data = self.generate_h3_priority_update_frame(layer)
                    else:
                        print(layer)
                        raise "[-] Unsupported Application Layer Data"
    
                # This HTTP/3 layer has non-HTTP/3 frames (QPACK)
                else: 
                    if 'QPACK Encoder' in layer.stream_uni or 'qpack_encoder' in layer.field_names: 
                        frame_data = aioquic.buffer.encode_uint_var(StreamType.QPACK_ENCODER)
                    elif 'QPACK Decoder' in layer.stream_uni: 
                        frame_data = aioquic.buffer.encode_uint_var(StreamType.QPACK_DECODER)
                    else:
                        print(layer)
                        raise "[-] Unsupported Application Layer Data"
                
                # Put application layer data into the corresponding quic stream frame
                quic_stream = quic_streams.pop(0)
                self.add_stream_frame(builder, quic_stream, frame_data)

        return builder

    def add_ack_frame(self, builder: QuicPacketBuilder, layer: XmlLayer):
        """
        Add an ACK frame to the builder.

        Args:
            builder: The QuicPacketBuilder instance.
            layer: The QUIC layer from Pyshark.
        """

        # Extract ACK frame details from the layer
        largest_acknowledged = int(layer.ack_largest_acknowledged)
        ack_delay = int(layer.ack_ack_delay)
        ack_range_count = int(layer.ack_ack_range_count)
        ack_first_ack_range = int(layer.ack_first_ack_range)
        ack_ranges = []

        # Extract ACK ranges if present
        for i in range(ack_range_count):
            # if there are more than one ranges, pyshark gives only the first range
            gap = layer.ack_gap
            ack_range = layer.ack_ack_range
            ack_ranges.append((int(gap), int(ack_range)))

        # Start the ACK frame in the builder
        buf = builder.start_frame(frame_type=QuicFrameType.ACK, capacity=16)

        # Add largest acknowledged and ACK delay
        buf.push_uint_var(largest_acknowledged)
        buf.push_uint_var(ack_delay)
        buf.push_uint_var(ack_range_count)
        buf.push_uint_var(ack_first_ack_range)
        

        for gap, ack_range in ack_ranges:
            buf.push_uint_var(gap)
            buf.push_uint_var(ack_range)

    def add_nci_frame(self, builder:QuicPacketBuilder, layer:XmlLayer) -> None:
        
        buf = builder.start_frame(
            QuicFrameType.NEW_CONNECTION_ID,
            capacity=NEW_CONNECTION_ID_FRAME_CAPACITY
        )
        buf.push_uint_var( int(layer.nci_sequence) ) # Sequence Number
        buf.push_uint_var( int(layer.nci_retire_prior_to) ) # Retire Prior To
        buf.push_uint8( int(layer.nci_connection_id_length) ) # Length
        buf.push_bytes( bytes(int(part, 16) for part in layer.nci_connection_id.split(":")) ) # Connection ID
        buf.push_bytes( bytes(int(part, 16) for part in layer.nci_stateless_reset_token.split(":"))  ) # Stateless Reset Token
    
    def add_stream_frame(self, builder:QuicPacketBuilder, stream_info, h3_frame_payload):
        """
        Add multiple HTTP/3 frames to a single STREAM frame in the builder.

        Args:
            builder: The QuicPacketBuilder instance.
            stream_info: Metadata about the QUIC stream (stream_id, offset, fin_bit).
            h3_frame_payload: HTTP/3 frame data to include in the STREAM frame.
        """
        
        stream_type = QuicFrameType.STREAM_BASE | 2  # Include LEN bit
        if stream_info.offset != 0:
            stream_type |= 4  # Include OFF bit
        if stream_info.fin_bit:
            stream_type |= 1  # Include FIN bit

        # Combine all HTTP/3 frames into a single payload

        buf = builder.start_frame(stream_type, capacity=len(h3_frame_payload) + 8)
        buf.push_uint_var(stream_info.stream_id)  # Push stream ID
        if stream_info.offset != 0:
            buf.push_uint_var(stream_info.offset)  # Push offset
        buf.push_uint_var(len(h3_frame_payload))  # Push total length
        buf.push_bytes(h3_frame_payload)  # Push combined payload

    def generate_h3_settings_frame(self, layer:XmlLayer) -> bytes:
        """
        Generate an HTTP/3 SETTINGS frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 SETTINGS frame data.
        """
        settings = {}

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
                settings[0x01] = int(value)

            elif key == "http3.settings.max_field_section_size":
                settings[0x06] = int(value)

            elif key == "http3.settings.qpack.blocked_streams":
                settings[0x07] = int(value)

            elif key == "http3.settings.h3_datagram":
                settings[0x33] = int(value)

            elif key == "http3.settings.webtransport":
                settings[0x2B603742] = int(value)

            else:
                raise "Unexpected SETTINGS Identifier: {}. Add it here...".format(key)

        # Encode the settings into SETTINGS frame payload
        settings_data = encode_settings(settings)

        # Encode the SETTINGS frame
        frame_data = encode_frame(FrameType.SETTINGS, settings_data)

        # Prepend the Uni Stream Type for control stream
        stream_type = encode_uint_var(0x00)  # Control Stream Type
        h3_frame_data = stream_type + frame_data

        return h3_frame_data

    def generate_h3_headers_frame(self, layer:XmlLayer) -> bytes:
        """
        Generate an HTTP/3 HEADERS frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 HEADERS frame data.
        """
        
        headers_data = None
        if hasattr(layer, "frame_payload"):
            headers_data = layer.frame_payload.raw_value
        else:
            raise ValueError("HEADERS frame payload not found or is empty")

        # Encode the HEADERS frame
        frame_data = encode_frame(FrameType.HEADERS, bytes.fromhex(headers_data))

        return frame_data

    def generate_h3_data_frame(self, layer:XmlLayer) -> bytes:
        """
        Generate an HTTP/3 DATA frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 DATA frame data.
        """

        # Extract raw payload for data
        if hasattr(layer, "payload") and layer.payload.raw_value:
            data_payload = layer.payload.raw_value
        else:
            raise ValueError("DATA frame payload not found")

        # Encode the DATA frame
        frame_data = encode_frame(FrameType.DATA, data_payload)
        return frame_data

    def generate_h3_priority_update_frame(self, layer:XmlLayer) -> bytes:
        """
        Generate an HTTP/3 PRIORITY_UPDATE frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 PRIORITY_UPDATE frame data.
        """

        data_payload = ""
        data_payload += layer.priority_update_element_id.raw_value
        data_payload += layer.priority_update_field_value.raw_value

        #print("data_payload: {}".format( data_payload ))
        #print("data_payload: {}".format( bytes.fromhex(data_payload) ))

        # Encode the PRIORITY_UPDATE frame
        frame_data = encode_frame(PRIORITY_UPDATE_FRAME_IDS[0], bytes.fromhex(data_payload))
        
        return frame_data