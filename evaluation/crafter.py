import sys

import aioquic
from aioquic.quic.connection import *
from aioquic.h3.connection import FrameType, encode_settings, encode_frame
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
        h3_frames = []  # Store HTTP/3 frame data sequentially

        # Helper dataclass for stream metadata
        @dataclass
        class QuicStreamInfo:
            fin_bit: bool = False
            stream_id: int = 0
            offset: int = 0

        # Parse layers in the h3msg
        for layer in h3msg.layers:
            if layer.layer_name == 'quic':
                quic_frame_type_hex = layer.get_field_value("quic.frame_type", raw=True)
                if quic_frame_type_hex:
                    quic_frame_type = int(quic_frame_type_hex, 16)

                    if quic_frame_type == QuicFrameType.STREAM_BASE:
                        stream_info = QuicStreamInfo()
                        stream_info.stream_id = int(layer.get_field_value("quic.stream.stream_id", raw=True))
                        stream_info.offset = int(layer.get_field_value("quic.stream.off", raw=True)) if layer.get_field_value("quic.stream.off", raw=True) != "False" else 0
                        stream_info.fin_bit = layer.get_field_value("quic.stream.fin", raw=True).lower() == "true"
                        quic_streams.append(stream_info)

            elif layer.layer_name == 'http3':
                h3_field_type_hex = layer.get_field_value("http3.frame_type", raw=True)

                if h3_field_type_hex:
                    h3_field_type = int(h3_field_type_hex, 16)

                    if h3_field_type == FrameType.SETTINGS:
                        frame_data = self.add_h3_settings_frame(layer)
                        h3_frames.append(frame_data)
                    elif h3_field_type == FrameType.HEADERS:
                        frame_data = self.add_h3_headers_frame(layer)
                        h3_frames.append(frame_data)
                    elif h3_field_type == FrameType.DATA:
                        frame_data = self.add_h3_data_frame(layer)
                        h3_frames.append(frame_data)
                    elif h3_field_type == 0x800f0700:  # PRIORITY_UPDATE_FRAME_TYPE
                        frame_data = self.add_h3_priority_update_frame(layer)
                        h3_frames.append(frame_data)

        # Add HTTP/3 frames to QUIC streams
        for quic_stream, h3_frame in zip(quic_streams, h3_frames):
            self.add_stream_frame(builder, quic_stream, [h3_frame])

        return builder

    def add_ack_frame(self, builder, layer):
        """
        Add an ACK frame to the builder.

        Args:
            builder: The QuicPacketBuilder instance.
            layer: The QUIC layer from Pyshark.
        """
        # Extract ACK frame details from the layer
        largest_acknowledged = int(layer.get_field_value("quic.ack.largest", raw=True))
        ack_delay = int(layer.get_field_value("quic.ack.delay", raw=True))
        ack_range_count = int(layer.get_field_value("quic.ack.range_count", raw=True))
        ack_ranges = []

        # Extract ACK ranges
        for i in range(ack_range_count):
            range_start = int(layer.get_field_value(f"quic.ack.range_start[{i}]", raw=True))
            range_end = int(layer.get_field_value(f"quic.ack.range_end[{i}]", raw=True))
            ack_ranges.append((range_start, range_end))

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

    def add_stream_frame(self, builder, stream_info, h3_frames):
        """
        Add multiple HTTP/3 frames to a single STREAM frame in the builder.

        Args:
            builder: The QuicPacketBuilder instance.
            stream_info: Metadata about the QUIC stream (stream_id, offset, fin_bit).
            h3_frames: List of HTTP/3 frame data to include in the STREAM frame.
        """
        stream_type = QuicFrameType.STREAM_BASE | 2  # Include LEN bit
        if stream_info.offset != 0:
            stream_type |= 4  # Include OFF bit
        if stream_info.fin_bit:
            stream_type |= 1  # Include FIN bit

        # Combine all HTTP/3 frames into a single payload
        combined_payload = b"".join(h3_frames)

        buf = builder.start_frame(stream_type, capacity=len(combined_payload) + 8)
        buf.push_uint_var(stream_info.stream_id)  # Push stream ID
        if stream_info.offset != 0:
            buf.push_uint_var(stream_info.offset)  # Push offset
        buf.push_uint_var(len(combined_payload))  # Push total length
        buf.push_bytes(combined_payload)  # Push combined payload

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



    """
    def process_stream_frame(self, builder, layer):
        # Default values for STREAM frame fields
        frame_type = None
        stream_id = None
        offset = 0
        fin_bit = False
        data = b""

        # Parse the STREAM frame fields
        if hasattr(layer, "_all_fields"):
            fields = layer._all_fields
            if "quic.frame_type" in fields:
                frame_type = int(fields["quic.frame_type"], 16) # STREAM frame may vary
                # print(frame_type)
            if "quic.stream.stream_id" in fields:
                stream_id = int(fields["quic.stream.stream_id"])  # Stream ID
                # print(stream_id)
            if "quic.stream.off" in fields:
                offset = int(fields["quic.stream.off"]) if fields["quic.stream.off"] != "False" else 0  # Offset
                # print(offset)
            if "quic.stream.fin" in fields:
                fin_bit = fields["quic.stream.fin"].lower() == "true"  # FIN flag
                # print(fin_bit)
            if "quic.stream_data" in fields:
                # Convert stream_data from hex string with colons to bytes
                data = bytes.fromhex(fields["quic.stream_data"].replace(":", ""))
                # print(data)

        # If stream_id is not found, raise an error
        if stream_id is None:
            raise ValueError("Stream ID not found in STREAM frame")

        buf = builder.start_frame(
            frame_type=frame_type,  # STREAM frame type
            capacity=len(data),
        )
        buf.push_uint_var(stream_id)  # Stream ID
        buf.push_uint_var(offset)    # Offset
        buf.push_bytes(data)         # Data payload
        if fin_bit:
            buf.push_uint8(1)  # FIN flag

        # Store stream metadata for later HTTP/3 frame matching
        self.store_stream_metadata(layer)

        return builder
    """
    """
    def process_crypto_frame(self, builder, layer):
        offset = int(layer.get_field_value("quic.crypto.offset", default=0))
        data = layer.payload.raw_value if hasattr(layer, 'payload') else b""

        buf = builder.start_frame(
            frame_type=0x06,  # CRYPTO frame type
            capacity=len(data),
        )
        buf.push_uint_var(offset)  # Offset
        buf.push_bytes(data)       # Data payload

        return builder

    def process_ack_frame(self, builder, layer):
        largest_acknowledged = int(layer.get_field_value("quic.ack.largest", default=0))
        ack_delay = int(layer.get_field_value("quic.ack.delay", default=0))
        ack_ranges = [(0, 0)]  # Default range, update if needed

        buf = builder.start_frame(
            frame_type=0x02,  # ACK frame type
            capacity=16,
        )
        buf.push_uint_var(largest_acknowledged)  # Largest acknowledged
        buf.push_uint_var(ack_delay)            # ACK delay
        buf.push_uint_var(len(ack_ranges))      # Number of ranges
        for start, end in ack_ranges:
            buf.push_uint_var(start)
            buf.push_uint_var(end - start)

        return builder
    """
    """
    def store_stream_metadata(self, layer):
        metadata = {}
        if hasattr(layer, "_all_fields"):
            fields = layer._all_fields
            if "quic.stream.stream_id" in fields:
                metadata['stream_id'] = int(fields["quic.stream.stream_id"])
            if "quic.stream.off" in fields:
                metadata['offset'] = int(fields["quic.stream.off"]) if fields["quic.stream.off"] != "False" else 0
            if "quic.stream.fin" in fields:
                metadata['fin_bit'] = fields["quic.stream.fin"].lower() == "true"

        self.stream_metadata.append(metadata)
    """
    
    # def process_http3_frame(self, builder, layer):
    #     """
    #     Process HTTP/3 frames based on their type and add them to the QUIC packet builder.

    #     Args:
    #         builder: The QuicPacketBuilder instance.
    #         layer: The HTTP/3 layer from Pyshark.

    #     Returns:
    #         Updated builder with the HTTP/3 frame added.
    #     """
    #     h3_field_type_hex = layer.get_field_value("http3.frame_type", raw=True)
    #     if h3_field_type_hex is None:
    #         raise ValueError("HTTP/3 frame type not found")

    #     # Convert frame type from hex string to integer
    #     h3_field_type = int(h3_field_type_hex, 16)
    #     payload = layer.payload.raw_value if hasattr(layer, 'payload') else b""

    #     if h3_field_type == FrameType.SETTINGS:
    #         builder = self.process_h3_settings_frame(builder, layer)
    #     elif h3_field_type == FrameType.HEADERS:
    #         builder = self.process_h3_headers_frame(builder, layer)
    #     elif h3_field_type == FrameType.DATA:
    #         builder = self.process_h3_data_frame(builder, layer)
    #     elif h3_field_type == 0x800f0700: # PRIORITY_UPDATE_FRAME_TYPE
    #         builder = self.process_h3_priority_update_frame(builder, layer)
    #     else:
    #         # Generic processing for unknown or unhandled frame types
    #         builder = self.process_generic_h3_frame(builder, h3_field_type, layer)

    #     return builder
    
    
    # def process_h3_settings_frame(self, builder, layer, stream_id=0):
    #     """
    #     Process an HTTP/3 SETTINGS frame and add it to the builder.

    #     Args:
    #         builder: The QuicPacketBuilder instance.
    #         layer: The HTTP/3 layer from Pyshark.
    #         stream_id: The QUIC stream ID to use for the SETTINGS frame (default is 0 for control stream).

    #     Returns:
    #         Updated builder.
    #     """
    #     # Extract SETTINGS fields from the layer
    #     settings = {}
    #     if hasattr(layer, "_all_fields"):
    #         fields = layer._all_fields
    #         for key, value in fields.items():
    #             if key.startswith("http3.settings.") and key not in ["http3.settings"]:
    #                 try:
    #                     setting_id = int(key.split(".")[-1], 16)
    #                     setting_value = int(value)
    #                     settings[setting_id] = setting_value
    #                 except ValueError:
    #                     continue

    #     # Encode SETTINGS frame using aioquic
    #     try:
    #         settings_data = encode_settings(settings)  # Create SETTINGS frame payload
    #         frame_data = encode_frame(FrameType.SETTINGS, settings_data)  # Encode SETTINGS frame
    #         stream_type = encode_uint_var(0x00)  # Control Stream Type
    #         h3_frame_data = stream_type + frame_data  # Combine stream type and frame data
    #     except Exception as e:
    #         print(f"Error encoding SETTINGS frame: {e}")
    #         return builder

    #     # Add the SETTINGS frame to the QUIC stream
    #     try:
    #         # Calculate stream type
    #         stream_type = QuicFrameType.STREAM_BASE | 2  # Include LEN bit
    #         offset = 0  # No offset for SETTINGS
    #         fin_bit = False  # SETTINGS frame does not finish the stream

    #         buf = builder.start_frame(stream_type, capacity=len(h3_frame_data) + 4)

    #         # Push stream ID
    #         buf.push_uint_var(stream_id)

    #         # Push frame length
    #         buf.push_uint_var(len(h3_frame_data))

    #         # Push frame data
    #         buf.push_bytes(h3_frame_data)
    #     except Exception as e:
    #         print(f"Error adding SETTINGS frame to QUIC stream: {e}")

    #     return builder

    # def build_h3_settings_frame(self, h3_layer):
    #     """
    #     Builds and returns a SETTINGS frame for the H3 layer.
    #     SETTINGS frame is sent over the control stream (Uni Stream Type 0x00).
    #     """
    #     settings = {
    #         # Define HTTP/3 settings here (example settings)
    #         aioquic.h3.connection.Setting.QPACK_MAX_TABLE_CAPACITY: 1024,
    #         aioquic.h3.connection.Setting.QPACK_BLOCKED_STREAMS: 16,
    #         aioquic.h3.connection.Setting.ENABLE_CONNECT_PROTOCOL: 1
    #     }

    #     try:
    #         # Create SETTINGS frame payload
    #         if hasattr(h3_layer, 'frame_payload') and hasattr(h3_layer.frame_payload, 'raw_value'):
    #             settings_data = bytes.fromhex(h3_layer.frame_payload.raw_value)
    #         else:
    #             print("No valid payload found for SETTINGS frame, using default payload.")
    #             settings_data = encode_settings(settings)

    #         # Encode the SETTINGS frame
    #         frame_data = aioquic.h3.connection.encode_frame(FrameType.SETTINGS, settings_data)

    #         # Prepend Uni Stream Type (0x00) to the SETTINGS frame data for control stream
    #         stream_type = aioquic.buffer.encode_uint_var(0x00)  # Uni Stream Type for control stream
    #         final_frame_data = stream_type + frame_data  # Combine stream type and frame data

    #         return final_frame_data  # Return the combined frame data with stream type

    #     except Exception as e:
    #         print(f"Error encoding SETTINGS frame: {e}")
    #         return b''  # Return empty payload in case of error

    # def build_h3_priority_update_frame(self, h3_layer):
    #     """
    #     Builds and returns a PRIORITY_UPDATE frame for the H3 layer.
    #     """
    #     # If the PRIORITY_UPDATE frame payload is not available, create a default one
    #     if hasattr(h3_layer, 'frame_payload') and hasattr(h3_layer.frame_payload, 'raw_value'):
    #         priority_data = bytes.fromhex(h3_layer.frame_payload.raw_value)
    #     else:
    #         print("No valid payload found for PRIORITY_UPDATE frame, using default payload.")
    #         priority_data = b'\x00\x01\x02'  # Example priority payload

    #     return aioquic.h3.connection.encode_frame(0x000f0700, priority_data)

    # def build_h3_headers_frame(self, h3_layer):
    #     """
    #     Builds and returns a HEADERS frame for the H3 layer
    #     """
    #     # Extract the HEADERS payload
    #     if hasattr(h3_layer, 'frame_payload') and hasattr(h3_layer.frame_payload, 'raw_value'):
    #         headers_data = bytes.fromhex(h3_layer.frame_payload.raw_value)
    #     else:
    #         print("No valid payload found for HEADERS frame, using default payload.")
    #         headers_data = b'\x82\x84\x41\x85\x86'  # Example headers (this should be replaced with real headers)

    #     return aioquic.h3.connection.encode_frame(FrameType.HEADERS, headers_data)

