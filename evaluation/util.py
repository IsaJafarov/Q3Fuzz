# -*- coding: UTF-8 -*-
# Modules for HTTP3
import pyshark 

# IETF specification
QUIC_LONGPACKETTYPE = ['Initial', '0-RTT', 'Handshake', 'Retry']
QUIC_SHORTPACKETTYPE = "1-RTT" # short packet does not have a type. It corresponds to 1-RTT only.
QUIC_FRAMETYPE = ['PADDING', 'PING', 'ACK', 'ACK', 'RESET_STREAM', 'STOP_SENDING', 'CRYPTO', 'NEW_TOKEN', \
             'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', 'STREAM', \
             'MAX_DATA', 'MAX_STREAM_DATA', 'MAX_STREAMS', 'MAX_STREAMS', 'DATA_BLOCKED', 'STREAM_DATA_BLOCKED', 'STREAMS_BLOCKED', 'STREAMS_BLOCKED',\
             'NEW_CONNECTION_ID', 'RETIRE_CONNECTION_ID', 'PATH_CHALLENGE', 'PATH_RESPONSE', 'CONNECTION_CLOSE', 'CONNECTION_CLOSE', 'HANDSHAKE_DONE', 'IMMEDIATE_ACK',\
             'DATAGRAM', 'DATAGRAM'] # ~0x21 frames so far

H3_STREAMTYPE = ['Control Stream', 'Push Stream', 'QPACK Encoder Stream', 'QPACK Decoder Stream']
H3_FRAMETYPE = ['DATA', 'HEADERS', 'Reserved', 'CANCEL_PUSH', 'SETTINGS', 'PUSH_PROMISE', 'Reserved', 'GOAWAY',\
                'Reserved', 'Reserved', 'Unassigned', 'Unassigned', 'ORIGIN', 'MAX_PUSH_ID'] # ~0x0d frames so far


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


def h3msg_from_pcap(f): # for HTTP3
    # Extract all QUIC messages from pcapfile and return an array of http3 messages
    # Now we only consider EXPORTED_PDU layer instead of UDP
    print("\n[STEP 2] Parsing QUIC messages from pcapfile %s ..." % f)
    client_ip = None   # Get ip to gather client message 
    raw_cap = pyshark.FileCapture(f)
    quic_cap = pyshark.FileCapture(f, display_filter='quic')
    quic_packet_list = []
    quic_cap_cnt = 0

    print("============= List of QUIC packets in pcap =============")
    for packet in quic_cap:
        client_flag = " "
        quic_cap_cnt += 1
        if client_ip == None and packet.quic.header_form == "1" and packet.quic.long_packet_type == "0": # The first INITIAL packet type of QUIC
            if 'exported_pdu' in packet: 
                client_ip = packet.exported_pdu.ip_src
        # if 'exported_pdu' in packet and packet.exported_pdu.ip_src == client_ip:
        if 'exported_pdu' in packet:
            quic_packet_list.append(packet)
            client_flag = "*"
        print("  [%d%s] %s" % (quic_cap_cnt, client_flag, packet.layers))

    print("  [+] Parsing done! (Extracted %d client messages out of all %d QUIC messages.)" % (len(quic_packet_list), quic_cap_cnt))

    quic_packet_cnt = 0
    print("\n  [DBG] Extracted messages")
    for quic_packet in quic_packet_list:
        quic_packet_cnt += 1
        # A pacekt may have multile layers
        print("  <PKT %d>---------------" % quic_packet_cnt)
        quic_layer_cnt = 0
        for layer in quic_packet.layers:

            if layer.layer_name == 'quic':
                quic_layer_cnt += 1
                if 'header_form' in dir(layer) and layer.header_form == "1": #long header type (Initial | 0-RTT | Handshake | Retry)
                    print("     (Layer %d) [%s] PKT_TYPE: %s" % (quic_layer_cnt, 'QUIC', QUIC_LONGPACKETTYPE[int(layer.long_packet_type)]))
                    print("     \t\t- frame (first-only): %s" % QUIC_FRAMETYPE[int(layer.frame_type)])
                elif 'coalesced_padding_data' in dir(layer):
                    print("     (Layer %d) [%s] PKT_TYPE: Random_padding" % (quic_layer_cnt, 'QUIC'))
                else: # short header type (1-RTT)
                    print("     (Layer %d) [%s] PKT_TYPE: %s" % (quic_layer_cnt, 'QUIC', QUIC_SHORTPACKETTYPE))
                    print("     \t\t- frame (first-only): %s" % QUIC_FRAMETYPE[int(layer.frame_type)])
                    # IMPORTANT ISSUE:
                    # It is unable to access multiple frames/streams of a pyshark layer,
                    # even if print(layer) shows multiple frames or streams in a QUIC layer.
                    # Thus we only consider the topmost frames and use pyshark's own printing method
                    # for debugging transmitted packets.  
                    # print(layer)
            elif layer.layer_name == "http3":
                quic_layer_cnt += 1
                # 1. Check stream type
                if 'stream_type' in dir(layer):
                    print("     (Layer %d) [%s] STREAM_TYPE: %s" % (quic_layer_cnt, 'HTTP3', H3_STREAMTYPE[int(layer.stream_type)]))
                else:
                    print("     (Layer %d) [%s] STREAM_TYPE: %s" % (quic_layer_cnt, 'HTTP3', "NONE"))
                # 2. Check the frame type
                if 'frame_type' in dir(layer):
                    print("     \t\t- frame (first-only): %s" % H3_FRAMETYPE[int(layer.frame_type)])


                
                # IMPORTANT ISSUE:
                # Same as QUIC, it is unable to access multiple frames/streams of a pyshark layer (i.e. HEADER),
                # even if print(layer) shows multiple frames in a HTTP3 layer (i.e., HEADER DATA).
                # Thus we only consider the topmost frames and use pyshark's own printing method
                # for debugging transmitted packets.  
                # Below is the packet number that shows the example.
                # if quic_packet_cnt == 16:
                #     print(dir(layer))
                #     print(layer)

    return quic_packet_list


def h2msg_from_pcap(f):
    # Extract all http2 messages from pcapfile and return an array of http2 messages in scapy form
    print("\n[STEP 2] Parsing http3 messages from pcapfile %s ..." % f)
    # Get ip to gather client message 
    client_ip = None
    with open(f, 'rb') as f_pre:
        pcapng = rdpcap(f_pre)
        for buf in pcapng:
            http2raw = buf.load[64:]
            # Got client's message
            if http2raw[:24] == b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a':
                client_ip = buf.load[16:20]
                break

    h2msg_arr = []
    with open(f, 'rb') as f:
        pcapng = rdpcap(f)
        frameid = 1
        for buf in pcapng:  # for each http2 message
            if buf.load[16:20] != client_ip:
                continue

            http2raw = buf.load[64:]
            # handle magic
            if http2raw[:24] == b'\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a':
                http2raw = http2raw[24:] 
            tmpseq = h2.H2Seq(http2raw)
            h2msg_arr.append(tmpseq)
            frameid += 1
    print("  [+] Parsing done! (Total %s messages.)" % len(h2msg_arr))

    msgid = 1
    # Debugging http2 messages frame by frame
    # print("  [DBG] messages (shortened)")
    for h2msg in h2msg_arr:
        h2msg_str = h2msg_to_str(h2msg)
        print("    - h2msg %d: %s" % (msgid, h2msg_str))
        msgid += 1

    # [NOTE] An HTTP2 message is a sequence of frames.
    return h2msg_arr


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


def h2msg_to_str(h2msg):
    frameStr = ''
    # h2msg.show()
    # Case 1: h2msg is list of HTTP/2 Frame Sequence in Scapy (multiplexed message sequence)
    if type(h2msg) is type([]):
        for h2msg_in_list in h2msg:
            for h2frame in h2msg_in_list.frames:
                frame_len = 0xdeadbeef # frame with deadbeef is malformed frame!
                if h2frame.len is not None: # handle malformed frame
                    frame_len = h2frame.len
                if hasattr(h2frame, 'type') and hasattr(h2frame, 'len'):
                    frameStr += (frameShortInfoArr[h2frame.type] + '(%x)' % frame_len + '-')
            frameStr = frameStr[:-1]
            frameStr += ' | '
        frameStr = frameStr[:-3]
    # Case 2: h2msg is HTTP/2 Frame Sequence in Scapy
    else:
        for h2frame in h2msg.frames:
            frame_len = 0xdeadbeef # frame with deadbeef is malformed frame!
            if h2frame.len is not None: # handle malformed frame
                frame_len = h2frame.len
            if hasattr(h2frame, 'type'):
                frameStr += (frameShortInfoArr[h2frame.type] + '(%x)' % frame_len + '-')
        frameStr = frameStr[:-1]
    return frameStr

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
            if msg in h2msg_to_str(r):
                check = True
    return check