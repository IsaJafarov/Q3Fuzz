import states
from transitions.extensions import GraphMachine
from prett3_syn import HttpClient

import util
import json
import time
import logging
import sys
from typing import List
from collections import OrderedDict
import copy
import traceback
from urllib.parse import urlparse
from pyshark.packet.packet import Packet
from pyshark import FileCapture
from aioquic.quic.configuration import QuicConfiguration

class ProtoModel(object):
    def __init__(self, name: str):
        self.name = name

        # For HTTP/3 communication
        self.configuration = None
        self.keylog = None

        # overall status
        self.is_pruning = False
        self.current_level = 1
        self.dst_ip = None
        self.timeout = 10

        # State searching information
        self.current_state = 0
        self.num_of_states = 0
        self.state_list = states.StateList(state_list=[states.State('Init', 1)])  # basic state '0' in level 1
        self.candidate_state_list = states.StateList(state_list=[])

        # Transition information
        # trigger as key (string) : [src_state (string), dest_state (string), cnt]
        self.transition_info = {}
        self.testmsgs = None


class MergeData():
    def __init__(self):
        self.src_s = None
        self.dst_s = None
        self.t_label = None


def generate_sm():
    pm = ProtoModel("HTTP/3 State Machine")
    sm = GraphMachine(model=pm, states=['Init', 'Finish'], initial='Init', auto_transitions=False)
    return pm, sm

def get_move_state_h3msgs(pm:ProtoModel, target_state:states.State) -> List[Packet]:
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

def modeller_h3(conf:QuicConfiguration, keylog:str, url:str, sample_msgs:List[Packet], outdir:str) -> None:
    global expand_sm, minimize_sm
    g_start_time = time.time()
    print("\n[STEP 3] Modeling started at %s" % time.ctime(g_start_time))
    # pm : modeling status, 
    # sm : state machine data structure using Machines package 
    pm, sm = generate_sm()
    pm.testmsgs = sample_msgs
    pm.dst_ip = url
    pm.configuration = conf
    pm.keylog = keylog

    while True:
        ### Expand candidate states in this level ###
        print("\033[31m[LEVEL %d] STATE MACHINE EXPANSION started at %s\033[0m" % (pm.current_level, time.ctime(time.time())))
        pm.is_pruning = False
        # Retrieve valid states of previous level (unique states in prev. level so far) (for level 1, it is the initial state '0')
        leaf_states = pm.state_list.get_states_by_level(pm.current_level)
        expand_sm(pm, sm, leaf_states)
        print("\033[31m[LEVEL %d] STATE MACHINE EXPANSION ended at %s\033[0m" % (pm.current_level, time.ctime(time.time())))

        pm.state_list.print_state_list()
        pm.candidate_state_list.print_state_list()

        ### Prune candidate states in this level ###
        print("\033[31m[LEVEL %d] STATE MACHINE MINIMIZATION started at %s\033[0m" % (pm.current_level, time.ctime(time.time())))
        is_pruning = True
        minimize_sm(pm, sm)
        print("\033[31m[LEVEL %d] STATE MACHINE MINIMIZATION ended at %s\033[0m" % (pm.current_level, time.ctime(time.time())))

        ### Wrap up this level ###
        elapsed_time = time.time() - g_start_time
        pm.candidate_state_list.state_list = []  # clear candidate state list

        print("[LEVEL %d] Elapsed time for this level: %s" % (pm.current_level, elapsed_time))

        ### Graph drawing ###
        graphname = "%s/level_" % outdir + str(pm.current_level)

        graph = sm.get_graph()
        
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

        # draw with 16x9 resolution
        graph.graph_attr.update({
            "ratio": "fill",   # Adjust graph to fill aspect ratio
            "size": "16,9!",   # Force 16:9 aspect ratio
            "dpi": "300"       # Set resolution to 300 DPI
        })
        graph.draw(graphname+"_16x9.png", format="png", prog='dot')
        


        with open(graphname+".json", "w") as jsonfile:
            json.dump(sm.markup, jsonfile, indent=2)

        print("\033[31m[+] STATE MACHINE until Level %d saved to {%s.png, %s.json}\033[0m" % 
        (pm.current_level, graphname, graphname))


        if len(pm.state_list.get_states_by_level(pm.current_level+1)) == 0: # Jobs finished
            break

        pm.current_level = pm.current_level + 1

    elapsed_time = time.time() - g_start_time
    print ("[+] All jobs done. Total elapsed time is ", elapsed_time)

    ### Final graph drawing ###
    # graphname = "%s/level_" % outdir + str(pm.current_level-1) + "(fin).png"
    # sm.get_graph().draw(graphname, prog='dot')
    # with open(graphname.replace(".png", ".json"), "w") as jsonfile:
    #     json.dump(sm.markup, jsonfile, indent=2)
    sys.exit()


def send_receive_http3(pm:ProtoModel, h3client:HttpClient, mov_msg_list:List[Packet], h3msg_sent:Packet) -> str:
    h3msg_rcvd = ''
    
    is_already_closed = False
    
    ### INITIAL CONNECTION ###
    # Establish initial connection by sending handshake messages
    h3client.connect()
    h3client.read_from_buffer()  # Receive any response from the server

    # Complete the connection by sending handshake completion messages
    h3client.complete_connection()
    received_after_init = h3client.read_from_buffer()  # Receive any response from the server
    print("received_after_init = {}".format(received_after_init))

    ### SENDING STATE MOVING MESSAGES ###
    for mov_msg in mov_msg_list:
        print(f"  [+] Sending state-moving message: {util.h3msg_to_str(mov_msg)}")
        state_msg = h3client.replay_msg(mov_msg, is_moving=True)  # Send HTTP/3 state-moving message
        if state_msg:
            print(f"  [+] Received state-moving response: {state_msg}")
            # h3msg_rcvd.append(state_msg)
            
    ### SENDING TARGET MSG ###
    if is_already_closed is False: # check for goaway in state moving (TODO)
        print("  [+] Sending testing message...")
        print(f"  [+] Sending target message: {util.h3msg_to_str(h3msg_sent)}")
        # h3msg_sent.show()
        h3msg_rcvd = h3client.replay_msg(h3msg_sent, is_moving=False)  # Send HTTP/3 target message
    
    h3client.close_connection()


    print("\033[92m  [SUMMARY] (%s) => %s => %s\033[0m" % (
    util.h3msg_to_str(mov_msg_list), util.h3msg_to_str(h3msg_sent), h3msg_rcvd))
    
    

    return h3msg_rcvd

def update_candidates(pm:ProtoModel, sm:GraphMachine, msg_sent:Packet, msg_rcvd:str) -> None:
    """
    Update candidate node (expanded in the current level) in pm and sm.
    args:
        msg_sent: A QUIC layer object from pyshark that is sent from its parent.
        msg_rcvd: String of response to the msg_sent
    return:
        stream_ids: A list of stream IDs from STREAM frames.
    """

    # No valid state found yet. Add candidate states in protocol model first.
    pm.num_of_states += 1
    cand_s = states.State(name=str(pm.num_of_states), level=pm.current_level + 1, parent_state=pm.current_state,
                          msg_sent=msg_sent, msg_rcvd_str=msg_rcvd)
    pm.candidate_state_list.add_state(cand_s)
    print("  [+] Candidate state %s added (%s -> %s)" % (cand_s.name, cand_s.parent_state.name, cand_s.name))

def check_dupstate(pm:ProtoModel, md:MergeData, cand_s:states.State, mode:str) -> bool:
    if mode == 'p':
        # Case 1. Parent:
        # Compare its SR dict with that of its parent
        if util.compare_ordered_dict(cand_s.parent_state.child_sr_dict, cand_s.child_sr_dict):
            md.src_s = cand_s.parent_state
            md.dst_s = cand_s.parent_state
            return True
        else:
            return False

    elif mode == 's':
        # STEP 2. Sibling:
        # Compare its child dict with that of states whose parent is same.
        for state_v in pm.state_list.state_list:  # check all states that are valid till now
            if state_v.parent_state is not None and state_v.parent_state.name == cand_s.parent_state.name:  #
                # siblings; same parent
                # print("Compare state %s with sibling state %s" % (cand_s.name, state_v.name))
                if util.compare_ordered_dict(state_v.child_sr_dict, cand_s.child_sr_dict):
                    md.src_s = cand_s.parent_state
                    md.dst_s = state_v
                    return True
        return False

    elif mode == 'r':
        # Step 3. Relatives:
        # Compare its child dict with that of the other states
        for state_v in pm.state_list.state_list:  # check all states that are valid till now
            if state_v.name == cand_s.parent_state.name:
                # print("Relative of state %s is same as its parent state %s" % (cand_s.name, state_v.name))
                continue
            if state_v.parent_state is None or state_v.parent_state.name != cand_s.parent_state.name:  # relative; different parent or ancestor
                # print("Comparing state %s with its relative state %s" % (cand_s.name, state_v.name))
                if util.compare_ordered_dict(state_v.child_sr_dict, cand_s.child_sr_dict):
                    md.src_s = cand_s.parent_state
                    md.dst_s = state_v
                    return True
        return False

    else:
        print("[ERROR] (check_dupstate()) Invalid mode.")
        sys.exit()


def update_sm(pm:ProtoModel, sm:GraphMachine, cand_s:states.State, md:MergeData) -> None:
    # Mergable
    if md.src_s is not None and md.dst_s is not None:
        if len(sm.get_transitions(trigger=md.t_label + "\n", source=md.src_s.name, dest=md.dst_s.name)) > 0:
            return
        sm.add_transition(md.t_label + "\n", source=md.src_s.name, dest=md.dst_s.name)
    # Unique
    else:
        # Finished
        if cand_s.msg_rcvd_str.find("CC") >= 0:
            print("  [lv.%d-MINIMIZATION-STATE %s] It is finishing state!" % (pm.current_level, cand_s.name))
            if len(sm.get_transitions(trigger=md.t_label + "\n", source=cand_s.parent_state.name, dest='Finish')) > 0:
                return
            sm.add_transition(md.t_label + "\n", source=cand_s.parent_state.name, dest='Finish')
        # Non-finished
        else:
            pm.state_list.add_state(cand_s)
            sm.add_state(cand_s.name)
            sm.add_transition(md.t_label + "\n", source=cand_s.parent_state.name, dest=cand_s.name)


def expand_sm(pm:ProtoModel, sm:GraphMachine, leaf_states:List[states.State]) -> None:
    # Find candidate states in the next level from leaf states found in the current level.
    leafstate_num = 1
    for leaf_state in leaf_states:
        sr_dict = OrderedDict()

        print("    [LV %d | EXP | LEAF %d/%d] Expanding leaf state \'%s\'..." % (pm.current_level, leafstate_num, len(leaf_states),
                leaf_state.name))

        state_moving_msgs_list = []

        message_num = 1
        pm.current_state = leaf_state
        skipped_messages = 0
        for msg_sent in pm.testmsgs:
            if 'INIT' in util.h3msg_to_str(msg_sent) or 'HANDSHAKE' in util.h3msg_to_str(msg_sent):
                skipped_messages += 1
                continue

            h3client = HttpClient(pm.configuration, urlparse(pm.dst_ip).netloc, pm.keylog)
            state_moving_msgs_list = get_move_state_h3msgs(pm, leaf_state)

            print("┌────────────────────────────────────────────────────────────────────────────────────")
            print("│    [LV %d | EXP | LEAF %d/%d | State '%s' | MSG %d/%d]         " %
                (pm.current_level, leafstate_num, len(leaf_states), leaf_state.name, message_num, len(pm.testmsgs)-skipped_messages))
            print("│    - Moving MSG: %s                                            " % 
                util.h3msg_to_str(state_moving_msgs_list))
            print("│    - Test MSG  : %s                                            " % 
                util.h3msg_to_str(msg_sent))
            print("└────────────────────────────────────────────────────────────────────────────────────")
            #print(msg_sent)
            msg_rcvd_str = send_receive_http3(pm, h3client, state_moving_msgs_list, msg_sent)


            message_num += 1
            msg_sent_str = util.h3msg_to_str(msg_sent)

            update_candidates(pm, sm, msg_sent, msg_rcvd_str)
            sr_dict[msg_sent_str] = msg_rcvd_str
        leafstate_num += 1
        pm.current_state.child_sr_dict = sr_dict

def minimize_sm(pm:ProtoModel, sm:GraphMachine) -> None:
    # Among candidate states in the next level, unique states in current level are determined via pruning.
    cand_s_list = pm.candidate_state_list.state_list
    if len(cand_s_list) == 0:
        print("  [+] No more candidate states ...")
        return

    print("  [INFO] Test %d candidate states in level %d" % (len(cand_s_list), pm.current_level))
    for cand_s in cand_s_list:
        md = MergeData()
        msg_sent_str = util.h3msg_to_str(cand_s.msg_sent)
        msg_rcvd_str = cand_s.msg_rcvd_str
        sr_msg = "%s => %s" % (msg_sent_str, msg_rcvd_str)
        md.t_label = sr_msg

        ######## Filter out quick-disconnected (finishing) state #######
        if msg_rcvd_str.find("CC") >= 0:
            pass

        ######## Retrieve cand_s SR info ########
        else: # cand_sr_dict: messages from cand_s to and its child node (Do the same test as parent).
            print('  [lv.%d-MINIMIZATION-STATE %s] Retrieving its SR dict' % (pm.current_level, cand_s.name))
            cand_sr_dict = OrderedDict()
            state_moving_msgs_list = get_move_state_h3msgs(pm, cand_s)

            skipped_messages = 0
            for msg_sent in pm.testmsgs:
                if 'INIT' in util.h3msg_to_str(msg_sent) or 'HANDSHAKE' in util.h3msg_to_str(msg_sent):
                    skipped_messages += 1
                    continue

                h3client = HttpClient(pm.configuration, urlparse(pm.dst_ip).netloc, pm.keylog)
                msg_rcvd_str = send_receive_http3(pm, h3client, state_moving_msgs_list, msg_sent)
                msg_sent_str = util.h3msg_to_str(msg_sent)
                cand_sr_dict[msg_sent_str] = msg_rcvd_str

            cand_s.child_sr_dict = cand_sr_dict

            ######## Check duplication of cand_s in 3 ways ########
            if check_dupstate(pm, md, cand_s, 'p'):
                print("  [lv.%d-MINIMIZATION-STATE %s] Same as parent state %s. Merge with its parent" % (pm.current_level, 
                    cand_s.name, md.dst_s.name))
            elif check_dupstate(pm, md, cand_s, 's'):
                print("  [lv.%d-MINIMIZATION-STATE %s] Same as sibling state %s. Merge with its sibling" % (pm.current_level,
                    cand_s.name, md.dst_s.name))
            elif check_dupstate(pm, md, cand_s, 'r'):
                print("  [lv.%d-MINIMIZATION-STATE %s] Same as relative state %s. Merge with its relative" % (pm.current_level,
                    cand_s.name, md.dst_s.name))
            else:
                # no dup state found.
                print("  [lv.%d-MINIMIZATION-STATE %s] -> **** Unique state %s found ****" % (pm.current_level, cand_s.name, cand_s.name))

        update_sm(pm, sm, cand_s, md)