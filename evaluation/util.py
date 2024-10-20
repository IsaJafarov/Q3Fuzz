# -*- coding: UTF-8 -*-
# Modules for HTTP3
import pyshark 
#import nest_asyncio

#nest_asyncio.apply()

# IETF specification
QUIC_LONGPACKETTYPE = ['INIT', '0-RTT', 'HANDSHAKE', 'RETRY']
QUIC_SHORTPACKETTYPE = "1-RTT" # short packet does not have a type. It corresponds to 1-RTT only.
QUIC_FRAMETYPE = ['PADDING', 'PING', 'ACK', 'ACK', 'RESET_STREAM', 'STOP_SENDING', 'CRYPTO', 'NEW_TOKEN', \
             'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', \
             'MAX_DATA', 'MAX_STREAM_DATA', 'MAX_STREAMS', 'MAX_STREAMS', 'DATA_BLOCKED', 'STREAM_DATA_BLOCKED', 'STREAMS_BLOCKED', 'STREAMS_BLOCKED',\
             'NEW_CONNECTION_ID', 'RETIRE_CONNECTION_ID', 'PATH_CHALLENGE', 'PATH_RESPONSE', 'CONNECTION_CLOSE', 'CONNECTION_CLOSE', 'HANDSHAKE_DONE', 'IMMEDIATE_ACK',\
             'DATAGRAM', 'DATAGRAM'] # ~0x21 frames so far

H3_STREAMTYPE = ['CONTROL_STREAM', 'PUSH_STREAM', 'QPACK_ENCODER_STREAM', 'QPACK_DECODER_STREAM']
H3_FRAMETYPE = ['DATA', 'HEADERS', 'RESERVED', 'CANCEL_PUSH', 'SETTINGS', 'PUSH_PROMISE', 'RESERVED', 'GOAWAY',\
                'RESERVED', 'RESERVED', 'UNASSIGNED', 'UNASSIGNED', 'ORIGIN', 'MAX_PUSH_ID'] # ~0x0d frames so far


############# GENERAL #############
class Tee(object):
    def __init__(self, *files):
        self.files = files

    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()  # If you want the output to be visible immediately

    def flush(self):
        for f in self.files:
            f.flush()


def cmp(a, b):
    return (a > b) - (a < b)


def compare_ordered_dict(dict1, dict2):
    for i, j in zip(dict1.items(), dict2.items()):
        if cmp(i, j) != 0:
            return False
    # print("compare_ordered_dict(): Two dict is same")
    # print(dict1)
    # print("---")
    # print(dict2)
    return True


def ip_checker(string):
    # ex) https://www.geeksforgeeks.org/python-check-url-string/
    # determines if string is ip address
    regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    # regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex, string)
    if len(url) == 0:
        return False  # non-ip address
    else:
        return True  # ip adress

def get_frames_of_layer(layer):
   
    frame_names = []
    for field_line in layer._get_all_field_lines():
        if ':' in field_line:
            field_name, field_value = field_line.split(':', 1)
            if (layer.layer_name == 'quic' and field_name.strip() == 'Frame Type') \
                or (layer.layer_name == 'http3' and field_name.strip() == 'Type') :
                frame_names.append( field_value.split()[0] )
    return frame_names

def h3msg_from_pcap(f, client_only=False): # for HTTP3
    """
    Extract all QUIC messages from pcapfile and return an array of http3 messages
    Now we only consider EXPORTED_PDU layer exported by wireshark instead of preserving data of UDP layer.

    Args:
        f (str): pcap file with QUIC or HTTP/3 messages
        client_only (bool, default=False): flag for extracting messages set by client side. 
    Returns:
        quic_packet_list (FileCapture): QUIC or HTTP/3 messages that are seen in the pcap file.
    """
    # print("\n[STEP 2] Parsing QUIC messages from pcapfile %s ..." % f)
    client_ip = None   # Get ip to gather client message 
    raw_cap = pyshark.FileCapture(f)
    quic_cap = pyshark.FileCapture(f, display_filter='quic')
    quic_packet_list = []
    quic_cap_cnt = 0

    # print("============= List of QUIC packets in pcap =============")
    for packet in quic_cap:
        #print(packet)
        mark_client = " "
        quic_cap_cnt += 1
        if client_ip == None and packet.quic.header_form == "1" and packet.quic.long_packet_type == "0": # The first INITIAL packet type of QUIC
            if 'exported_pdu' in packet: 
                client_ip = packet.exported_pdu.ip_src
        if client_only:
            if 'exported_pdu' in packet and packet.exported_pdu.ip_src == client_ip:
                quic_packet_list.append(packet)
                mark_client = "*"
        else:
            quic_packet_list.append(packet)
        # print("  [%d%s] %s" % (quic_cap_cnt, mark_client, packet.layers))

    # print("  [+] Parsing done! (Extracted %d client messages out of all %d QUIC messages.)" % (len(quic_packet_list), quic_cap_cnt))

    """
    quic_packet_cnt = 0
    print("\n  [DBG] Extracted messages")
    for quic_packet in quic_packet_list:
        quic_packet_cnt += 1
        # A packet may have multile layers
        print("  <PKT %d>---------------" % quic_packet_cnt)
        msginfo = h3msg_to_str(quic_packet)
        print(msginfo)
    """

    return quic_packet_list

def h3msg_to_str(h3msg):
    """
    Convert a QUIC or HTTP3 message in a human-readable format.
    args:
        h3msg: A QUIC / HTTP3 packet of type 'pyshark.packet.packet.Packet'
    return:
        msginfo: a string of a Q / H3 message with multiple layers and frames
    """
    msginfo = ''
    # h3msg.show()
    if type(h3msg) is type([]):
        msginfo = ""
    else:
        quic_layer_cnt = 0
        for layer in h3msg.layers:
            if layer.layer_name == 'quic':
                if quic_layer_cnt != 0:
                    msginfo += ' '
                quic_layer_cnt += 1
                if 'header_form' in dir(layer) and layer.header_form == "1": #long header type (Initial | 0-RTT | Handshake | Retry)
                    msginfo += '[%s]%s' % ('Q', QUIC_LONGPACKETTYPE[int(layer.long_packet_type)]) 
                    # print("     (Layer %d) [%s] PKT_TYPE: %s" % (quic_layer_cnt, 'QUIC', QUIC_LONGPACKETTYPE[int(layer.long_packet_type)]))
                elif 'coalesced_padding_data' in dir(layer):
                    msginfo += '[%s]%s' % ('Q', QUIC_FRAMETYPE[0]) 
                    # print("     (Layer %d) [%s] PKT_TYPE: Random_padding" % (quic_layer_cnt, 'QUIC'))
                else: # short header type (1-RTT)
                    msginfo += '[%s]%s' % ('Q', QUIC_SHORTPACKETTYPE) 
                    # print("     (Layer %d) [%s] PKT_TYPE: %s" % (quic_layer_cnt, 'QUIC', QUIC_SHORTPACKETTYPE))

                tmp_frames = ''
                for frame_name in get_frames_of_layer(layer):
                    tmp_frames += frame_name+","
                if len(tmp_frames) > 0:
                    msginfo += '(%s)' % tmp_frames[:-1]         
                    # print("     \t\t- frame: %s" % frame_name )


            elif layer.layer_name == "http3":
                if quic_layer_cnt != 0:
                    msginfo += ' '
                quic_layer_cnt += 1
                # 1. Check stream type
                if 'stream_type' in dir(layer): # always false????
                    msginfo += '[%s]%s' % ('H3', H3_STREAMTYPE[int(layer.stream_type)]) 
                    # print("     (Layer %d) [%s] STREAM_TYPE: %s" % (quic_layer_cnt, 'HTTP3', H3_STREAMTYPE[int(layer.stream_type)]))
                else:
                    msginfo += '[%s]%s' % ('H3', 'NONE') 
                    # print("     (Layer %d) [%s] STREAM_TYPE: %s" % (quic_layer_cnt, 'HTTP3', "NONE"))
                # 2. Check the frame type
                tmp_frames = ''
                for frame_name in get_frames_of_layer(layer):
                    tmp_frames += frame_name.upper()+","
                if len(tmp_frames) > 0:
                    msginfo += '(%s)' % tmp_frames[:-1]         
                    # print("     \t\t- frame: %s" % frame_name )
                # for frame_name in get_frames_of_layer(layer):
                #     print("     \t\t- frame: %s" % frame_name )

    return msginfo

    # Case 1: h3msg is list of HTTP/2 Frame Sequence in Scapy (multiplexed message sequence)
    # if type(h3msg) is type([]):
    #     for h3msg_in_list in h3msg:
    #         for h2frame in h3msg_in_list.frames:
    #             frame_len = 0xdeadbeef # frame with deadbeef is malformed frame!
    #             if h2frame.len is not None: # handle malformed frame
    #                 frame_len = h2frame.len
    #             if hasattr(h2frame, 'type') and hasattr(h2frame, 'len'):
    #                 frameStr += (frameShortInfoArr[h2frame.type] + '(%x)' % frame_len + '-')
    #         frameStr = frameStr[:-1]
    #         frameStr += ' | '
    #     frameStr = frameStr[:-3]
    # # Case 2: h3msg is HTTP/2 Frame Sequence in Scapy
    # else:
    #     for h2frame in h3msg.frames:
    #         frame_len = 0xdeadbeef # frame with deadbeef is malformed frame!
    #         if h2frame.len is not None: # handle malformed frame
    #             frame_len = h2frame.len
    #         if hasattr(h2frame, 'type'):
    #             frameStr += (frameShortInfoArr[h2frame.type] + '(%x)' % frame_len + '-')
    #     frameStr = frameStr[:-1]
    # return frameStr


def h2frame_from_sniff(packet):
    sniff_frame = h2.H2Frame(str(packet))
    return sniff_frame


def framestr_to_h2seq(frameStrBuf):
    global dst_ip
    # move_state_msg_arr: ['HE-SE-SE', DE-PE, ....]
    # send_frame_seq: 'HE-DE'
    frameDashStrArr = []
    if (str(type(frameStrBuf)) == "<type 'str'>"):
        frameDashStrArr.append(frameStrBuf)
    else:
        frameDashStrArr.extend(frameStrBuf)

    frameStrArr = []
    for frameEachSeq in frameDashStrArr:
        splitFrameEachSeq = frameEachSeq.split('-')
        for splitFrameEach in splitFrameEachSeq:
            frameStrArr.append(splitFrameEach)

    # frameArr = []
    srv_max_frm_sz = 1 << 14
    srv_hdr_tbl_sz = 4096
    srv_max_hdr_tbl_sz = 0
    srv_global_window = 1 << 14
    srv_max_hdr_lst_sz = 0

    h2seq = h2.H2Seq()
    # H2DataFrame
    # H2HeadersFrame
    # H2SettingsFrame
    # H2PushPromiseFrame
    # H2PingFrame
    # H2PriorityFrame
    # H2ResetFrame
    # H2GoAwayFrame
    # H2WindowUpdateFrame
    # H2ContinuationFrame

    for frameValue in frameStrArr:
        if frameValue == 'DA':
            dataFrameBuf = h2.H2Frame() / h2.H2DataFrame()
            dataFrameBuf.stream_id = 1
            h2seq.frames.append(dataFrameBuf)

        elif frameValue == 'HE':
            msg = "GET"
            args = "/index.html"

            headerArgs = ":method " + msg + "\n\
			:path " + args + "\n\
			:authority " + dst_ip + "\n\
			:scheme https\n\
			accept-encoding: gzip, deflate\n\
			accept-language: ko-KR\n\
			accept: text/html\n\
			user-agent: Scapy HTTP/2 Module\n"

            tblhdr = h2.HPackHdrTable()
            qry_frontpage = tblhdr.parse_txt_hdrs(
                headerArgs,
                stream_id=1,
                max_frm_sz=srv_max_frm_sz,
                max_hdr_lst_sz=srv_max_hdr_lst_sz,
                is_sensitive=lambda hdr_name, hdr_val: hdr_name in ['cookie'],
                should_index=lambda x: x in [
                    'x-requested-with',
                    'user-agent',
                    'accept-language',
                    ':authority',
                    'accept',
                ]
            )
            h2seq.frames.append(qry_frontpage.frames[0])

        elif frameValue == 'SE':
            settingFrameBuf = h2.H2Frame() / h2.H2SettingsFrame()
            max_frm_sz = (1 << 24) - 1
            max_hdr_tbl_sz = (1 << 16) - 1
            win_sz = (1 << 31) - 1
            settingFrameBuf.settings = [
                h2.H2Setting(id=h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
                h2.H2Setting(id=h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=win_sz),
                h2.H2Setting(id=h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=max_hdr_tbl_sz),
                h2.H2Setting(id=h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=max_frm_sz),
            ]
            h2seq.frames.append(settingFrameBuf)
        elif frameValue == 'PU':
            h2seq.frames.append(h2.H2Frame() / h2.H2PushPromiseFrame())

        elif frameValue == 'PI':
            h2seq.frames.append(h2.H2Frame() / h2.H2PingFrame())

        elif frameValue == 'PR':
            h2seq.frames.append(h2.H2Frame() / h2.H2PriorityFrame())

        elif frameValue == 'RS':
            h2seq.frames.append(h2.H2Frame() / h2.H2ResetFrame())

        elif frameValue == 'GO':
            h2seq.frames.append(h2.H2Frame() / h2.H2GoAwayFrame())

        elif frameValue == 'WI':
            h2seq.frames.append(h2.H2Frame() / h2.H2WindowUpdateFrame())

        elif frameValue == 'CO':
            h2seq.frames.append(h2.H2Frame() / h2.H2ContinuationFrame())

    return h2seq




def check_h2_response(ans, msg=None):
    # Check if h2 message received from sr.

    # Detailed information about ans
    # ans is a list of QueryAnswer tuple
    # therefore, a Queryanswer is (Query (s), Answer (r))
    check = False
    # print(ans)
    # FUNCTION 1: checking h2 message presence
    if msg is None:
        for a in ans:
            # print("-----")
            # print(a)
            # print("-----")
            r = a[1] # received packet
            if r.haslayer(h2.H2Seq):
                check = True
    # FUNCTION 2 : checking specific message
    else:           
        for a in ans:
            # print("-----")
            # print(a)
            # print("-----")
            r = a[1] # received packet
            if msg in h3msg_to_str(r):
                check = True
    return check