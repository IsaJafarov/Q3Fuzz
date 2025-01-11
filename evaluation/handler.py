#! /usr/bin/env python
import sys
from aioquic.quic.connection import *
from aioquic.h3.connection import FrameType, StreamType
from aioquic.quic.rangeset import RangeSet
from aioquic.buffer import Buffer
import util
from util import QUIC_FRAME_ABBREVIATIONS, H3_FRAME_ABBREVIATIONS

class Stream():
    def __init__(self):
        self.stream_id:int = None
        self.finish:bool = False
        self.offset:int = None
        self.length:int = None
        self.data:int = None
        self.uni_stream_type:StreamType = None # types of server-initiated unidirectional streams
        # if data that the server sends is too long to fit in a singe frame, some of its contents is sent in the subsequent stream frames
        self.unfinished_frame_type:FrameType = None # type of the H3 frame, which has been received partially
        self.unfinished_frame_len_to_read:int = None # length of the rest of the H3 frame, which is expected to be received in the subsequent frame
        

class MSGHandler():
    def __init__(self, qc: QuicConnection):
        self._quic = qc
        self.streams = {int:Stream}


    def process_quic_payload(self, context: QuicReceiveContext, plain: bytes, crypto_frame_required: bool = False) -> Tuple[bool, bool]:
        buf = Buffer(data=plain)
        
        msg_per_layer = ''

        while not buf.eof():

            # get frame type
            try:
                frame_type = buf.pull_uint_var()
                #print("\nframe_type: {}".format(frame_type))
            except BufferReadError:
                raise QuicConnectionError( error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=None, reason_phrase="Malformed frame type")


            if frame_type < 0x08 or frame_type > 0x0F: # not STREAM frame
                msg_per_layer += QUIC_FRAME_ABBREVIATIONS[frame_type]+","
           
            # a condition for each frame type can be added
            if frame_type==0x00: # PADDING frame
                self.handle_padding_frame(context, frame_type, buf)
                
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
                stream = self.handle_stream_frame(context, frame_type, buf)
                
                msg_per_layer += f'{QUIC_FRAME_ABBREVIATIONS[frame_type]}({stream.stream_id})'
                
                http3_stream_msg = self.process_http3_payload(stream)    
                msg_per_layer += "[{}],".format(http3_stream_msg)
                #print(">>> {}".format(http3_stream_msg))
                
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
                
            elif frame_type==0x1C or frame_type==0x1D:
                self.handle_connection_close_frame(context, frame_type, buf)
               
            elif frame_type==0x1E:
                self.handle_handshake_done_frame(context, frame_type, buf)
                
            elif frame_type in [0x30, 0x31]:
                self.handle_datagram_frame(context, frame_type, buf)
                
            elif frame_type>0x31:
                raise QuicConnectionError(error_code=QuicErrorCode.FRAME_ENCODING_ERROR, frame_type=frame_type, reason_phrase="Unknown frame type")
            
        
        for stream_id in self.streams:
            self.streams[stream_id].uni_stream_type = None

        return util.beautify_message_string(msg_per_layer)
    

    def process_http3_payload( self, stream:Stream ) -> str:
        buf = Buffer(data=stream.data)
        msg_http3 = ''
        
        #print("\nstream_id: {}".format( stream.stream_id ))
        #print("stream_fin: {}".format( stream.finish ))
        #print("stream_off: {}".format( stream.offset ))
        #print("stream_len: {}".format( stream.length )) # same as len(stream.data) and buf.capacity()
        #print("stream_data = {}".format( stream.data ))

        # Check if the stream is server-initiated unidirectional stream
        # In unidirectional streams, the first byte indicates stream type (control, push, QPACK... )
        # if stream has already been initiated, when the server sends STREAM, it does not send the stream type as the first byte
        # Therefore, check if the strem has previously been initiated. If so, do not read the first byte.
        if stream.stream_id % 4 == 3:

            if stream.uni_stream_type is None:
                stream.uni_stream_type = buf.pull_uint_var()
            
            #print("uni_stream_type = {}".format( stream.uni_stream_type ))

            if stream.uni_stream_type == StreamType.QPACK_ENCODER:
                msg_http3 += "Enc,"
                return util.beautify_message_string(msg_http3)
            elif stream.uni_stream_type == StreamType.QPACK_DECODER:
                msg_http3 += "Dec,"
                return util.beautify_message_string(msg_http3)
            

        # read HTTP3 frames
        while ( not buf.eof() ):
            
            if stream.unfinished_frame_type is None:
                frame_type = buf.pull_uint_var()
                frame_len = buf.pull_uint_var()    
            else:
                frame_type = stream.unfinished_frame_type
                frame_len = stream.unfinished_frame_len_to_read
            
            #print("frame_type: {}".format( frame_type ))
            #print("frame_len: {}".format( frame_len ))

            msg_http3 += H3_FRAME_ABBREVIATIONS[frame_type]+","

            
            
            if len(buf.data) + frame_len <= stream.length:
                frame_data = buf.pull_bytes(frame_len)
            else:
                left_data = len(stream.data) - len(buf.data)
                #print("oops we can only read {} byte frame data".format( left_data ))
                frame_data = buf.pull_bytes( left_data )
                stream.unfinished_frame_type = frame_type
                stream.unfinished_frame_len_to_read = frame_len - left_data
                #print("Frame data length to read in the next stream {}".format( stream.unfinished_frame_len_to_read ))
                
            #print("frame_data = {}".format( frame_data ))
            #print("buf data len: {}".format( len(buf.data) ))
            

        return util.beautify_message_string(msg_http3)
      
  

    def handle_padding_frame(
        self, context: QuicReceiveContext, frame_type: int, buf: Buffer
    ) -> None:
        """
        Handle a PADDING frame.
        """
        # consume padding
        pos = buf.tell()
        for byte in buf.data_slice(pos, buf.capacity):
            if byte:
                break
            pos += 1
        buf.seek(pos)

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
            
            '''
            print(("\033[31m\nACK frame received. " +
                   "Largest Acknowledged={}, " +
                   "Ack Delay={}, " +
                   "Ack Range Count={}, " +
                   "First Ack Range={} \033[0m")
            .format(end, delay, ack_range_count, ack_count ))
            '''

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

        # print("\033[31m\nRESET_STREAM frame received. Stream ID={}, Error Code={}, Final Size={}\033[0m"
        #   .format(stream_id, error_code, final_size))

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

        # print("\033[31m\nSTOP_SENDING frame received. Stream ID={}, Error Code={}\033[0m"
        #       .format(stream_id, error_code))

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

        #print("\033[31m\nRESET_STREAM frame received. Length={}, Token={}\033[0m"
        #      .format(length, token))

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
    ) -> Stream:
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
        frame = QuicStreamFrame(
            offset=offset, data=stream_data, fin=bool(frame_type & 1)
        )
        # print("\033[31m\nSTREAM frame received. Stream ID={}, Offset={}, Length={}, Stream Data={}\033[0m"
        #       .format(stream_id, offset, length, stream_data))

        #stream = self._quic._get_or_create_stream(frame_type, stream_id)
        #event = stream.receiver.handle_frame(frame)

        if stream_id in self.streams:
            stream = self.streams[stream_id]
        else:
            stream = Stream()
            self.streams[stream_id] = stream
            stream.stream_id = stream_id
        
        stream.finish = bool(frame_type & 1)
        stream.offset = offset
        stream.length = length
        stream.data = stream_data

        return stream


        """
        
        
        
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