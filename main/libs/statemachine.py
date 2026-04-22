from .states import *
from transitions.extensions import GraphMachine
from libs.http_client import HttpClient

from .util import *
import json
import time
import sys
from typing import List
from collections import OrderedDict
import copy
from urllib.parse import urlparse
from pyshark.packet.packet import Packet
from aioquic.quic.configuration import QuicConfiguration


class MergeData():
    def __init__(self):
        self.src_s = None
        self.dst_s = None
        self.t_label = None
        
class TrafficModeller(object):
    def __init__(self, name: str, testmsgs:List[Packet], url:str, conf:QuicConfiguration, outdir:str):
        self.name = name

        # For HTTP/3 communication
        self.configuration:QuicConfiguration = conf

        # overall status
        self.is_pruning:bool = False
        self.current_level:int = 1
        self.dst_ip:str = url

        # State searching information
        self.current_state = 0
        self.num_of_states = 0
        self.state_list = StateList(state_list=[State('CONNECTED', 1)])  # basic state in level 1
        self.candidate_state_list = StateList(state_list=[])

        # Transition information
        # trigger as key (string) : [src_state (string), dest_state (string), cnt]
        self.transition_info:dict = {}
        self.testmsgs:List[Packet] = testmsgs
        
        self.sm = GraphMachine(states=['START', 'FINISH'], initial='START', auto_transitions=False)

        self.outdir:str = outdir
        
        # TEMP
        self.sent_received = dict() 
        
        self.nondeter_sent_msg_sequence = set()
        # key: packet number of client message
        # value: string representation
        self.client_msg_str_dict = dict()
        
        self.set_up_client_msg_str_dict()
        

    def set_up_client_msg_str_dict(self):
        for sample_msg in self.testmsgs:

            sample_msg_str = h3msg_to_str(sample_msg, exclude_opt_client_frames=True)
            
            if not sample_msg_str:
                continue
            # multiple messages might correspond to the same string representation.
            # therefore, we add subscript to distinguish them
            if sample_msg_str not in self.client_msg_str_dict.values():
                self.client_msg_str_dict[sample_msg.frame_info.number] = sample_msg_str
            elif sample_msg_str + "\u2082" not in self.client_msg_str_dict.values():
                self.client_msg_str_dict[sample_msg.frame_info.number] = sample_msg_str + "\u2082"
            elif sample_msg_str + "\u2083" not in self.client_msg_str_dict.values():
                self.client_msg_str_dict[sample_msg.frame_info.number] = sample_msg_str + "\u2083"
            elif sample_msg_str + "\u2084" not in self.client_msg_str_dict.values():
                self.client_msg_str_dict[sample_msg.frame_info.number] = sample_msg_str + "\u2084"
            elif sample_msg_str + "\u2085" not in self.client_msg_str_dict.values():
                self.client_msg_str_dict[sample_msg.frame_info.number] = sample_msg_str + "\u2085"

        print("\n\tExtracted client messages: ")
        for k,v in self.client_msg_str_dict.items():
            print("\t{}: {}".format(k,v))
        
    def client_msg_to_str(self, h3msg:Union[list,Packet]):
        
        if isinstance(h3msg, list): # moving messages
            msginfo = ''
            for h3msg_sub in h3msg:
                msginfo += self.client_msg_to_str(h3msg_sub) + " => "
            if msginfo != '':
                msginfo = msginfo.rstrip(" => ")
            return msginfo
        else: # single message
            return self.client_msg_str_dict.get(h3msg.frame_info.number, '')
    
    def get_move_state_h3msgs(self, target_state:State) -> List[Packet]:
        # Get state moving message to reach current state
        # Return list of QUIC / HTTP3 messages
        state_moving_msgs = []
        move_state_num = 0
        while True:
            parent_state = target_state.parent_state
            if parent_state is not None:  # non-root node
                parent_msg = copy.deepcopy(target_state.msg_sent)
                # parent_msg.frames.reverse()
                state_moving_msgs.append(parent_msg)
                move_state_num = move_state_num + 1
                target_state = parent_state
                continue
            else:  # root node
                break

        state_moving_msgs.reverse()
        
        return state_moving_msgs


    def modeller_h3(self) -> None:
        
        g_start_time = time.time()
        print("\n[STEP 3] Modeling started at %s" % time.ctime(g_start_time))
        
        ### Record 0-RTT INIT and HANDSHAKE ###
        h3client = HttpClient(self.configuration, urlparse(self.dst_ip).netloc)
        quicmsg_rcvd = h3client.connect()
        self.sm.add_state('HANDSHAKING')
        self.sm.add_transition('INITIAL => '+quicmsg_rcvd, source='START', dest='HANDSHAKING') # We skip recording condition; it is just a simple transition before connection
        quicmsg_rcvd = h3client.complete_connection()
        self.sm.add_state('CONNECTED')
        self.sm.add_transition('HANDSHAKE => '+quicmsg_rcvd, source='HANDSHAKING', dest='CONNECTED') # We skip recording condition; it is just a simple transition before connection
        h3client.close_connection()

        for _ in range(10):
            ### Expand candidate states in this level ###
            print("\033[31m[LEVEL %d] STATE MACHINE EXPANSION started at %s\033[0m" % (self.current_level, time.ctime(time.time())))
            self.is_pruning = False
            # Retrieve valid states of previous level (unique states in prev. level so far) (for level 1, it is the initial state '0')
            leaf_states = self.state_list.get_states_by_level(self.current_level)
            self.expand_sm(leaf_states)
            print("\033[31m[LEVEL %d] STATE MACHINE EXPANSION ended at %s\033[0m" % (self.current_level, time.ctime(time.time())))

            self.state_list.print_state_list()
            self.candidate_state_list.print_state_list()

            ### Prune candidate states in this level ###
            print("\033[31m[LEVEL %d] STATE MACHINE MINIMIZATION started at %s\033[0m" % (self.current_level, time.ctime(time.time())))
            self.is_pruning = True
            self.minimize_sm()
            print("\033[31m[LEVEL %d] STATE MACHINE MINIMIZATION ended at %s\033[0m" % (self.current_level, time.ctime(time.time())))

            ### Wrap up this level ###
            self.candidate_state_list.state_list = []  # clear candidate state list

            print("[LEVEL %d] Elapsed time for this level: %s" % (self.current_level, time.time() - g_start_time))

            ### Graph drawing ###
            graphname = "%s/level_" % self.outdir + str(self.current_level)

            graph = self.sm.get_graph()
            
            # Style setting on the entire graph
            graph.graph_attr.update(
                {
                    'ranksep': '2.5'
                })
            # Style setting on nodes
            for node in graph.nodes():
                node.attr.update({
                    'shape': 'ellipse',
                    'fontname': 'DejaVu Sans',
                    'fontsize': '14',
                    'label': node.name
                })
            # Style setting on edges
            for edge in graph.edges():
                # edge.attr['xlabel'] = edge.attr['label']
                # del edge.attr['label']
                edge.attr.update({
                    'fontname': 'DejaVu Sans',
                    'fontsize': '12'
                })

            # draw with default resolutions
            graph.draw(graphname+".png", format="png", prog='dot') # format can be "svg" for clear visualization when zoomed in

            with open(graphname+".json", "w") as jsonfile:
                json.dump(self.sm.markup, jsonfile, indent=2)

            print("\033[31m[+] STATE MACHINE until Level %d saved to {%s.png, %s.json}\033[0m" % (self.current_level, graphname, graphname))


            if len(self.state_list.get_states_by_level(self.current_level+1)) == 0: # Jobs finished
                break

            self.current_level = self.current_level + 1
            
            print("\n================Nondeterminism================") # TEMP
            print("The server returned different different responses to the following {} client message sequences".format(len(self.nondeter_sent_msg_sequence)))
            for sent_msg_sequence in self.nondeter_sent_msg_sequence:
                print(sent_msg_sequence)
            self.nondeter_sent_msg_sequence.clear()
        else:
            print("\033[31m 10 layers of State Machine is generated. Stopping the process. \033[0m")
            print("\033[31m There might be State Space Expansion. See if the server acts too nondeterministic. \033[0m")

        
        print ("[+] All jobs done. Total elapsed time is ", round(time.time() - g_start_time, 2))
        


    def send_receive_http3(self, h3client:HttpClient, mov_msg_list:List[Packet], h3msg_sent:Packet) -> str:
        h3msg_rcvd = ''
        
        h3client.connect()
        h3client.complete_connection()
        
        ### SENDING STATE MOVING MESSAGES ###
        for mov_msg in mov_msg_list:
            # print(f"  [+] Sending state-moving message: {h3msg_to_str(mov_msg, exclude_opt_client_frames=True)}")
            state_msg = h3client.replay_msg(mov_msg)  # Send HTTP/3 state-moving message
            if state_msg:
                # print(f"  [+] Received state-moving response: {state_msg}")
                pass
                
        ### SENDING TARGET MSG ###
        # print("  [+] Sending testing message...")
        # print(f"  [+] Sending target message: {h3msg_to_str(h3msg_sent, exclude_opt_client_frames=True)}")
        # h3msg_sent.show()
        h3msg_rcvd = h3client.replay_msg(h3msg_sent)  # Send HTTP/3 target message
        
        h3client.close_connection()

        print("\033[92m  [SUMMARY]\tSent: (%s) => %s \n\t\tReceived: %s\033[0m" % (
        self.client_msg_to_str(mov_msg_list), self.client_msg_to_str(h3msg_sent), h3msg_rcvd))        
        
        sent_msg_sequence = "(%s) => %s" % (self.client_msg_to_str(mov_msg_list), self.client_msg_to_str(h3msg_sent))

        if sent_msg_sequence in self.sent_received: # TEMP
            if self.sent_received[sent_msg_sequence] != h3msg_rcvd:
                self.nondeter_sent_msg_sequence.add( sent_msg_sequence )
        else:
            self.sent_received[sent_msg_sequence] = h3msg_rcvd
        
        return h3msg_rcvd

    def update_candidates(self, msg_sent:Packet, msg_rcvd:str) -> None:
        """
        Update candidate node (expanded in the current level) in pm and sm.
        args:
            msg_sent: A QUIC layer object from pyshark that is sent from its parent.
            msg_rcvd: String of response to the msg_sent
        return:
            stream_ids: A list of stream IDs from STREAM frames.
        """

        # No valid state found yet. Add candidate states in protocol model first.
        self.num_of_states += 1
        cand_s = State(name=str(self.num_of_states), level=self.current_level + 1, parent_state=self.current_state,
                            msg_sent=msg_sent, msg_rcvd_str=msg_rcvd)
        self.candidate_state_list.add_state(cand_s)
        print("  [+] Candidate state %s added (%s -> %s)" % (cand_s.name, cand_s.parent_state.name, cand_s.name))

    def check_dupstate(self, md:MergeData, cand_s:State, mode:str) -> bool:
        if mode == 'p':
            # Case 1. Parent:
            # Compare its SR dict with that of its parent
            target_state = cand_s.parent_state.name + " (its parent)"
            if compare_sr_pairs(target_state, cand_s.parent_state.child_sr_dict, cand_s.child_sr_dict):
                md.src_s = cand_s.parent_state
                md.dst_s = cand_s.parent_state
                return True
            else:
                return False

        elif mode == 's':
            # STEP 2. Sibling:
            # Compare its child dict with that of states whose parent is same.
            for state_v in self.state_list.state_list:  # check all states that are valid till now
                if state_v.parent_state is not None and state_v.parent_state.name == cand_s.parent_state.name:  #
                    # siblings; same parent
                    target_state = state_v.name + " (its sibling)"
                    if compare_sr_pairs(target_state, state_v.child_sr_dict, cand_s.child_sr_dict):
                        md.src_s = cand_s.parent_state
                        md.dst_s = state_v
                        return True
            return False

        elif mode == 'r':
            # Step 3. Relatives:
            # Compare its child dict with that of the other states
            for state_v in self.state_list.state_list:  # check all states that are valid till now
                if state_v.name == cand_s.parent_state.name:
                    continue
                if state_v.parent_state is None or state_v.parent_state.name != cand_s.parent_state.name:  # relative; different parent or ancestor
                    target_state = state_v.name + " (its relative)"
                    if compare_sr_pairs(target_state, state_v.child_sr_dict, cand_s.child_sr_dict):
                        md.src_s = cand_s.parent_state
                        md.dst_s = state_v
                        return True
            return False

        else:
            print("[ERROR] (check_dupstate()) Invalid mode.")
            sys.exit()


    def update_sm(self, cand_s:State, md:MergeData) -> None:
        # Mergable
        if md.src_s is not None and md.dst_s is not None:
            # if len(self.sm.get_transitions(trigger=md.t_label + "\n", source=md.src_s.name, dest=md.dst_s.name)) > 0:
            #     return
            self.sm.add_transition(md.t_label + "\n", source=md.src_s.name, dest=md.dst_s.name, conditions="packet_number:{}".format(cand_s.msg_sent.quic.packet_number))
        # Unique
        else:
            # Finished
            if cand_s.msg_rcvd_str.find("CC") >= 0:
                print("  [lv.%d-MINIMIZATION-STATE %s] It is finishing state!" % (self.current_level, cand_s.name))
                if len(self.sm.get_transitions(trigger=md.t_label + "\n", source=cand_s.parent_state.name, dest='FINISH')) > 0:
                    return
                self.sm.add_transition(md.t_label + "\n", source=cand_s.parent_state.name, dest='FINISH', conditions="packet_number:{}".format(cand_s.msg_sent.quic.packet_number))
            # Non-finished
            else:
                if cand_s.msg_rcvd_str:
                    ss_stream_ids = extract_stop_sending_stream_ids(cand_s.msg_rcvd_str)
                    for ss_id in ss_stream_ids:
                        cand_s.blocked_stream_ids.add(ss_id)
                        print(f"\033[31m[DEBUG] Unique state {cand_s.name}: Detected STOP_SENDING for stream {ss_id}, now blocked in this state.\033[0m")

                self.state_list.add_state(cand_s)
                self.sm.add_state(cand_s.name)
                self.sm.add_transition(md.t_label + "\n", source=cand_s.parent_state.name, dest=cand_s.name, conditions="packet_number:{}".format(cand_s.msg_sent.quic.packet_number))
                # Explicitly add finishing transition
                self.sm.add_transition("CC", source=cand_s.name, dest='FINISH')

    def expand_sm(self, leaf_states:List[State]) -> None:
        # Find candidate states in the next level from leaf states found in the current level.
        leafstate_num = 1
        for leaf_state in leaf_states:
            sr_dict = OrderedDict()

            print("    [LV %d | EXP | LEAF %d/%d] Expanding leaf state \'%s\'..." % (self.current_level, leafstate_num, len(leaf_states),
                    leaf_state.name))

            state_moving_msgs_list = []

            message_num = 1
            self.current_state = leaf_state
            skipped_messages = 0
            for msg_sent in self.testmsgs:
                # print(msg_sent)
                # print(h3msg_to_str(msg_sent))
                msg_sent_str = self.client_msg_to_str(msg_sent)
                # print(msg_sent.quic)
                ## SKIP TEST 1 (connection establishment?)
                if 'INIT' in msg_sent_str or 'HANDSHAKE' in msg_sent_str or len(msg_sent_str)==0:
                    skipped_messages += 1
                    continue

                ## SKIP TEST 2 (blocked stream ID?)
                # Extract stream IDs from the test message string
                stream_ids_in_msg = extract_stream_ids_from_msg_str(msg_sent_str)
                # If any stream ID in the message is blocked for the current state, skip this test message
                if any(sid in leaf_state.blocked_stream_ids for sid in stream_ids_in_msg):
                    print(f"\033[31m[SKIP] Testmsg for state '{leaf_state.name}' contains blocked stream ID(s): {stream_ids_in_msg & leaf_state.blocked_stream_ids}\033[0m")
                    skipped_messages += 1
                    continue

                h3client = HttpClient(self.configuration, urlparse(self.dst_ip).netloc)
                state_moving_msgs_list = self.get_move_state_h3msgs(leaf_state)

                print("┌────────────────────────────────────────────────────────────────────────────────────")
                print("│    [LV %d | EXP | LEAF %d/%d | State '%s' | MSG %d/%d]         " %
                    (self.current_level, leafstate_num, len(leaf_states), leaf_state.name, message_num, len(self.testmsgs)-skipped_messages))
                print("│    - Moving MSG: %s                                            " % 
                    self.client_msg_to_str(state_moving_msgs_list))
                print("│    - Test MSG  : %s                                            " % 
                    self.client_msg_to_str(msg_sent))
                print("└────────────────────────────────────────────────────────────────────────────────────")

                msg_rcvd_str = self.send_receive_http3(h3client, state_moving_msgs_list, msg_sent)

                message_num += 1
                msg_sent_str = self.client_msg_to_str(msg_sent)

                self.update_candidates(msg_sent, msg_rcvd_str)

                sr_dict[msg_sent_str] = msg_rcvd_str
            leafstate_num += 1
            self.current_state.child_sr_dict = sr_dict

    def minimize_sm(self) -> None:
        # Among candidate states in the next level, unique states in current level are determined via pruning.
        cand_s_list = self.candidate_state_list.state_list
        if len(cand_s_list) == 0:
            print("  [+] No more candidate states ...")
            return

        print("  [INFO] Test %d candidate states in level %d" % (len(cand_s_list), self.current_level))
        for cand_s in cand_s_list:
            md = MergeData()
            msg_sent_str = self.client_msg_to_str(cand_s.msg_sent)
            msg_rcvd_str = cand_s.msg_rcvd_str
            # print("msg_rcvd_str: {}".format( msg_rcvd_str ))
            sr_msg = "%s => %s" % (msg_sent_str, msg_rcvd_str)
            md.t_label = sr_msg

            ######## Filter out quick-disconnected (finishing) state #######
            if msg_rcvd_str.find("CC") >= 0:
                pass

            ######## Retrieve cand_s SR info ########
            else: # cand_sr_dict: messages from cand_s to and its child node (Do the same test as parent).
                print('  [lv.%d-MINIMIZATION-STATE %s] Retrieving its SR dict' % (self.current_level, cand_s.name))
                cand_sr_dict = OrderedDict()
                state_moving_msgs_list = self.get_move_state_h3msgs(cand_s)

                for msg_sent in self.testmsgs:
                    msg_sent_str = self.client_msg_to_str(msg_sent)

                    ## SKIP TEST 1 (connection establishment?)
                    if 'INIT' in msg_sent_str or 'HANDSHAKE' in msg_sent_str or len(msg_sent_str)==0:
                        continue

                    ## SKIP TEST 2 (blocked stream ID?)
                    # Extract stream IDs from the test message string
                    stream_ids_in_msg = extract_stream_ids_from_msg_str(msg_sent_str)
                    # If any stream ID in the message is blocked for the current candidate state, skip this test message
                    if any(sid in cand_s.blocked_stream_ids for sid in stream_ids_in_msg):
                        print(f"\033[31m[SKIP] Testmsg for state '{cand_s.name}' contains blocked stream ID(s): {stream_ids_in_msg & cand_s.blocked_stream_ids}\033[0m")
                        continue

                    h3client = HttpClient(self.configuration, urlparse(self.dst_ip).netloc)
                    msg_rcvd_str = self.send_receive_http3(h3client, state_moving_msgs_list, msg_sent)
                    
                    msg_sent_str = self.client_msg_to_str(msg_sent)
                    cand_sr_dict[msg_sent_str] = msg_rcvd_str

                cand_s.child_sr_dict = cand_sr_dict

                ######## Check duplication of cand_s in 3 ways ########
                if self.check_dupstate(md, cand_s, 'p'):
                    print("  [lv.%d-MINIMIZATION-STATE %s] Same as parent state %s. Merge with its parent" % (self.current_level, 
                        cand_s.name, md.dst_s.name))
                elif self.check_dupstate(md, cand_s, 's'):
                    print("  [lv.%d-MINIMIZATION-STATE %s] Same as sibling state %s. Merge with its sibling" % (self.current_level,
                        cand_s.name, md.dst_s.name))
                elif self.check_dupstate(md, cand_s, 'r'):
                    print("  [lv.%d-MINIMIZATION-STATE %s] Same as relative state %s. Merge with its relative" % (self.current_level,
                        cand_s.name, md.dst_s.name))
                else:
                    # no dup state found.
                    print("  [lv.%d-MINIMIZATION-STATE %s] -> **** Unique state %s found ****" % (self.current_level, cand_s.name, cand_s.name))
            
                # Add the triggering message's packet number to SM
                # It will be used during fuzzing
            
            self.update_sm(cand_s, md)

