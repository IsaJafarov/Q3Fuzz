import random
from pprint import pprint
import json, ast

class FuzzingConf():
    def __init__(self, config_file: str) -> None:

        if config_file is None:
            self.assign_random_values()
        else:
            self.assign_values_from_file(config_file)


    def assign_random_values(self):

        def choose_size():
            return random.choice( list(range(-1000, 10000, 100)) + list(range(10000, 100000, 5000)) + list(range(1000000, 2000000, 10000)) )
        
        # transport params
        self.ack_delay_exponent = random.choice( list(range(0, 10)) + list(range(10, 25, 5)) ) #  3, no negative, RFC says <=20 integer
        self.active_connection_id_limit = random.choice( list(range(0, 10)) + list(range(10, 50, 5)) ) # 8 no negative
        self.max_idle_timeout = random.choice( list(range(0, 10000, 100 )) ) # 6000 no negative
        self.initial_max_data = choose_size() # 1048576
        self.initial_max_stream_data_bidi_local = choose_size() # 1048576
        self.initial_max_stream_data_bidi_remote = choose_size() # 1048576
        self.initial_max_stream_data_uni = choose_size() # 1048576
        self.initial_max_streams_bidi = random.choice( range(0, 300, 5)) #128 no  negative
        self.initial_max_streams_uni = random.choice( range(0, 300, 5)) # 128
        self.max_ack_delay = random.choice( range(0, 100, 5) ) #25 no negative
        self.max_datagram_frame_size = choose_size() # doesn't exist
        self.quic_version = random.randint(0, 4)

        # random.choice( list(range()) + list(range()) )

        # complete connection
        self.largest_acknowledged = random.choice( list(range(0, 20)) + list(range(20, 100, 10)) ) # no negative
        self.ack_delay = random.choice( range(0, 200, 5) ) # 106 no negative
        self.ack_range_count = random.randint(0, 5) #0
        self.ack_range = random.choice( range(0, 50, 5) ) # 1 no negative

        # open qpack streams
        self.qpack_max_table_capacity = random.choice( list(range(-100, 10000, 200)) + list(range(10000, 100000, 5000)) ) # 4096
        self.qpack_blocked_streams = random.choice( list(range(0, 20)) + list(range(20, 200, 10)) ) # 16
        self.enable_connect = random.randint(0, 2) # 1
        self.dummy = random.choice( list(range(0, 5)) + list(range(5, 100, 5)) ) # 1 no negative

        self.control_stream_id = random.randint(0, 4) # 2
        self.encoder_stream_id = random.randint(0, 8) # 6 no negative
        self.decoder_stream_id = random.randint(0, 11) # 10 no negative

        # headers frame
        self.request_stream_id = random.randint(-1, 4) # 0
        self.method_header = random.choice( ['GET']*7 + ['POST', 'PUT', 'DELETE', 'HEAD', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH', 'ASAS'])
        self.path_header = random.choice(['/100k.html', '/300k.html', '/600k.html'])
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
 
    def __str__(self):
        return json.dumps(self.__dict__, indent=1)