import sys

import aioquic
from aioquic.quic.connection import *
from aioquic.h3.connection import FrameType, StreamType, encode_settings, encode_frame
from aioquic.buffer import encode_uint_var
from aioquic.tls import Epoch
from pyshark.packet.packet import Packet

class MSGCrafter():
    def __init__(self, qc: QuicConnection, client):
        self.connection = qc
        self.client = client

    def copy_msg(self, h3msg: Packet):
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
                    else:
                        print(field)
                        raise "[-] Unsupported QUIC Frame"
                    
            elif layer.layer_name == 'http3':
                h3_field_type_hex = layer.get_field_value("http3.frame_type", raw=True)

                # This HTTP/3 layer has HTTP/3 frames
                if h3_field_type_hex is not None:
                    h3_field_type = int(h3_field_type_hex, 16)
                    if h3_field_type == FrameType.SETTINGS:
                        frame_data = self.add_h3_settings_frame(layer)
                    elif h3_field_type == FrameType.HEADERS:
                        frame_data = self.add_h3_headers_frame(layer) 
                    elif h3_field_type == FrameType.DATA:
                        frame_data = self.add_h3_data_frame(layer)
                    elif h3_field_type >= 0x800F0000 and h3_field_type <= 0X800FFFFF:  # PRIORITY_UPDATE_FRAME_TYPE
                        frame_data = self.add_h3_priority_update_frame(layer)
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

    def add_ack_frame(self, builder, layer):
        """
        Add an ACK frame to the builder.

        Args:
            builder: The QuicPacketBuilder instance.
            layer: The QUIC layer from Pyshark.
        """
        # Extract ACK frame details from the layer
        largest_acknowledged = int(layer.get_field_value("ack_largest_acknowledged", raw=True), 16)
        ack_delay = int(layer.get_field_value("ack_ack_delay", raw=True), 16)
        ack_range_count = int(layer.get_field_value("ack_ack_range_count", raw=True), 16)
        ack_ranges = []

        # Extract ACK ranges if present
        for i in range(ack_range_count):
            range_start = layer.get_field_value(f"ack_range_start[{i}]", raw=True)
            range_end = layer.get_field_value(f"ack_range_end[{i}]", raw=True)
            if range_start is None or range_end is None:
                continue  # Skip invalid ranges
            ack_ranges.append((int(range_start, 16), int(range_end, 16)))

        # Start the ACK frame in the builder
        buf = builder.start_frame(frame_type=QuicFrameType.ACK, capacity=16)

        # Add largest acknowledged and ACK delay
        buf.push_uint_var(largest_acknowledged)
        buf.push_uint_var(ack_delay)

        # Add ACK ranges
        buf.push_uint_var(len(ack_ranges))
        for start, end in ack_ranges:
            buf.push_uint_var(start)
            buf.push_uint_var(end - start)

    def add_nci_frame(self, builder:QuicPacketBuilder, layer) -> None:
        
        buf = builder.start_frame(
            QuicFrameType.NEW_CONNECTION_ID,
            capacity=NEW_CONNECTION_ID_FRAME_CAPACITY
        )
        buf.push_uint_var(1) # Sequence Number
        buf.push_uint_var(0) # Retire Prior To
        buf.push_uint8(3) # Length
        buf.push_bytes(os.urandom(3)) # Connection ID
        buf.push_bytes(os.urandom(16)) # Stateless Reset Token

    def add_stream_frame(self, builder, stream_info, h3_frame_payload):
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

    def add_h3_settings_frame(self, layer):
        """
        Generate an HTTP/3 SETTINGS frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 SETTINGS frame data.
        """
        settings = {}

        # Extract SETTINGS fields from the HTTP/3 layer
        if hasattr(layer, "_all_fields"):
            fields = layer._all_fields
            for key, value in fields.items():
                if key.startswith("http3.settings.") and key not in ["http3.settings"]:
                    try:
                        # Parse setting ID and value
                        setting_id = int(key.split(".")[-1], 16) if "id" in key else None
                        setting_value = int(value) if setting_id is not None else None
                        if setting_id is not None and setting_value is not None:
                            settings[setting_id] = setting_value
                    except ValueError:
                        continue

        # Encode the settings into SETTINGS frame payload
        settings_data = encode_settings(settings)

        # Encode the SETTINGS frame
        frame_data = encode_frame(FrameType.SETTINGS, settings_data)

        # Prepend the Uni Stream Type for control stream
        stream_type = encode_uint_var(0x00)  # Control Stream Type
        h3_frame_data = stream_type + frame_data

        return h3_frame_data

    def add_h3_headers_frame(self, layer):
        """
        Generate an HTTP/3 HEADERS frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 HEADERS frame data.
        """
        headers_data = b""

        # Attempt to extract headers payload from the layer
        if hasattr(layer, "_all_fields") and "http3.frame_payload" in layer._all_fields:
            # Extract payload as hexadecimal string and convert to bytes
            raw_payload = layer._all_fields["http3.frame_payload"]
            headers_data = bytes.fromhex(raw_payload.replace(":", ""))
        elif hasattr(layer, "payload") and hasattr(layer.payload, "raw_value"):
            # Fallback: use raw payload if available
            headers_data = layer.payload.raw_value
        else:
            raise ValueError("HEADERS frame payload not found or is empty")

        # Encode the HEADERS frame
        frame_data = encode_frame(FrameType.HEADERS, headers_data)
        return frame_data

    def add_h3_data_frame(self, layer):
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

    def add_h3_priority_update_frame(self, layer):
        """
        Generate an HTTP/3 PRIORITY_UPDATE frame.

        Args:
            layer: The HTTP/3 layer from Pyshark.

        Returns:
            Encoded HTTP/3 PRIORITY_UPDATE frame data.
        """
        # Extract priority update details
        if hasattr(layer, "_all_fields"):
            fields = layer._all_fields
            stream_id = int(fields.get("http3.priority_update.stream_id", "0"), 16)
            priority_value = int(fields.get("http3.priority_update.priority", "0"), 16)
        else:
            raise ValueError("PRIORITY_UPDATE frame details not found")

        # Build priority update payload
        priority_update_payload = (
            encode_uint_var(stream_id) + encode_uint_var(priority_value)
        )

        # Encode the PRIORITY_UPDATE frame
        frame_data = encode_frame(0x800f0700, priority_update_payload)
        return frame_data