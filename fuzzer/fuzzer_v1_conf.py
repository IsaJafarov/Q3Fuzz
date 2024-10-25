import random
from pprint import pprint

class FuzzingConf():
    def __init__(self) -> None:
        # transport params
        self.ack_delay_exponent = random.randint(-0, 25) # 3, no negative, RFC says <=20 integer
        self.active_connection_id_limit = random.randint(0, 50) # 8 no negative
        self.max_idle_timeout = random.randint(0, 10000) # 6000 no negative
        self.initial_max_data = random.randint(-1000, 2000000) # 1048576
        self.initial_max_stream_data_bidi_local = random.randint(-100, 2000000) # 1048576
        self.initial_max_stream_data_bidi_remote = random.randint(-100, 2000000) # 1048576
        self.initial_max_stream_data_uni = random.randint(-100, 2000000) # 1048576
        self.initial_max_streams_bidi = random.randint(0, 300) #128 no  negative
        self.initial_max_streams_uni = random.randint(-1, 300) # 128
        self.max_ack_delay = random.randint(0, 100) #25 no negative
        self.max_datagram_frame_size = random.randint(-1000, 2000000) # doesn't exist
        self.quic_version = random.randint(0, 4)

        # complete connection
        self.largest_acknowledged = random.randint(0, 100) # no negative
        self.ack_delay = random.randint(0, 200) # 106 no negative
        self.ack_range_count = random.randint(0, 5) #0
        self.ack_range = random.randint(0, 50) # 1 no negative

        # open qpack streams
        self.qpack_max_table_capacity = random.randint(-100, 100000) # 4096
        self.qpack_blocked_streams = random.randint(0, 200)# 16
        self.enable_connect = random.randint(0, 2) # 1
        self.dummy = random.randint(0, 100)# 1 no negative

        self.control_stream_id = random.randint(0, 4) # 2
        self.encoder_stream_id = random.randint(0, 8) # 6 no negative
        self.decoder_stream_id = random.randint(0, 11) # 10 no negative

        # headers frame
        self.request_stream_id = random.randint(-1, 4) # 0
        self.method_header = random.choice( ['GET']*7 + ['POST', 'PUT', 'DELETE', 'HEAD', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH', 'ASAS'])
        self.path_header = random.choice(['/100k.html', '/600k.html'])
        self.user_agent_length = random.randint(0, 2000)


        pprint(vars(self))

