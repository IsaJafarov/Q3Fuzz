import random
from pprint import pprint
import json, ast

class FuzzingConf():
    def __init__(self, config_file: str) -> None:

        if config_file is None:
            self.assign_random_values()
        else:
            self.assign_values_from_file(config_file)
        
        print( json.dumps(self.__dict__, indent=1) )

    def assign_random_values(self):

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

        

    def assign_values_from_file(self, config_file):

        print("Reading parameter values from {}".format(config_file))

        with open(config_file, 'r') as file:
            config = json.load(file)

        # transport params
        self.ack_delay_exponent = config['ack_delay_exponent']
        self.active_connection_id_limit = config['active_connection_id_limit']
        self.max_idle_timeout = config['max_idle_timeout']
        self.initial_max_data = config['initial_max_data']
        self.initial_max_stream_data_bidi_local = config['initial_max_stream_data_bidi_local']
        self.initial_max_stream_data_bidi_remote = config['initial_max_stream_data_bidi_remote']
        self.initial_max_stream_data_uni = config['initial_max_stream_data_uni']
        self.initial_max_streams_bidi = config['initial_max_streams_bidi']
        self.initial_max_streams_uni = config['initial_max_streams_uni']
        self.max_ack_delay = config['max_ack_delay']
        self.max_datagram_frame_size = config['max_datagram_frame_size']
        self.quic_version = config['quic_version']

        # complete connection
        self.largest_acknowledged = config['largest_acknowledged']
        self.ack_delay = config['ack_delay']
        self.ack_range_count = config['ack_range_count']
        self.ack_range = config['ack_range']

        # open qpack streams
        self.qpack_max_table_capacity = config['qpack_max_table_capacity']
        self.qpack_blocked_streams = config['qpack_blocked_streams']
        self.enable_connect = config['enable_connect']
        self.dummy = config['dummy']

        self.control_stream_id = config['control_stream_id']
        self.encoder_stream_id = config['encoder_stream_id']
        self.decoder_stream_id = config['decoder_stream_id']

        # headers frame
        self.request_stream_id = config['request_stream_id']
        self.method_header = config['method_header']
        self.path_header = config['path_header']
        self.user_agent_length = config['user_agent_length']
 