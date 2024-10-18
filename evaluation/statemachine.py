import states
import smbuilder
from transitions.extensions import GraphMachine as Machine
import util
import time
import logging
import sys
from collections import OrderedDict
import copy

class ProtoModel(object):
    def __init__(self, name):
        self.name = name

        # overall status
        self.is_pruning = False
        self.current_level = 1
        self.dst_ip = None
        self.timeout = 10

        # State searching information
        self.current_state = 0
        self.num_of_states = 0
        self.state_list = states.StateList(state_list=[states.State('connected', 1)])  # basic state '0' in level 1
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
    sm = Machine(model=pm, states=['connected', 'finish'], initial='connected', auto_transitions=False)
    return pm, sm

"""
******* TODO - update to http3 *******
def get_move_state_h3msgs(pm, target_state):
    # Get state moving message to reach current state
    # Return list of H2 messages
    move_state_h2msgs = []
    move_state_num = 0
    while True:
        parent_state = target_state.parent_state
        if parent_state is not None:  # non-root node
            parent_h2msg = copy.deepcopy(target_state.h2msg_sent)
            # parent_h2msg.frames.reverse()
            move_state_h2msgs.append(parent_h2msg)
            move_state_num = move_state_num + 1
            target_state = parent_state
            continue
        else:  # root node
            break

    move_state_h2msgs.reverse()
    return move_state_h2msgs
"""


def update_candidates(pm, sm, h2msg_sent, h2msg_rcvd, elapsedTime):
    # sm : state machine, current_state : current state,
    # spyld_str : send h2 frame sequence in string, h2msg_sent : send h2 frame sequence,
    # rpyld_str : response h2 frame sequence in string, h2msg_rcvd : response h2 frame sequence
    # elapsedTime : elapsed time for response of h2msg_rcvd to h2msg_sent
    # Build and fix a state machine based on the response

    # No valid state found yet. Add candidate states in protocol model first.
    pm.num_of_states += 1
    cand_s = states.State(name=str(pm.num_of_states), level=pm.current_level + 1, parent_state=pm.current_state,
                          h2msg_sent=h2msg_sent, h2msg_rcvd=h2msg_rcvd, elapsedTime=elapsedTime)
    pm.candidate_state_list.add_state(cand_s)
    print("    [+] Candidate state %s added (%s -> %s)" % (cand_s.name, cand_s.parent_state.name, cand_s.name))
    logger.info("    [+] Candidate state %s added (%s -> %s)" % (cand_s.name, cand_s.parent_state.name, cand_s.name))


def check_dupstate(pm, md, cand_s, mode):
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
        logger.info("[ERROR] (check_dupstate()) Invalid mode.")
        sys.exit()


def update_sm(pm, sm, cand_s, md):
    # Mergable
    if md.src_s is not None and md.dst_s is not None:
        if len(sm.get_transitions(trigger=md.t_label + "\n", source=md.src_s.name, dest=md.dst_s.name)) > 0:
            return
        sm.add_transition(md.t_label + "\n", source=md.src_s.name, dest=md.dst_s.name)
    # Unique
    else:
        # Finished
        if int(cand_s.elapsedTime) == 0:
            print("  [lv.%d-MINIMIZATION-STATE %s] It is finishing state!" % (pm.current_level, cand_s.name))
            logger.info("  [lv.%d-MINIMIZATION-STATE %s] It is finishing state!" % (pm.current_level, cand_s.name))
            if len(sm.get_transitions(trigger=md.t_label + "\n", source=cand_s.parent_state.name, dest='fin')) > 0:
                return
            sm.add_transition(md.t_label + "\n", source=cand_s.parent_state.name, dest='fin')
        # Non-finished
        else:
            pm.state_list.add_state(cand_s)
            sm.add_state(cand_s.name)
            sm.add_transition(md.t_label + "\n", source=cand_s.parent_state.name, dest=cand_s.name)


def expand_sm(pm, sm, leaf_states):
    # Find candidate states in the next level from leaf states found in the current level.
    leafstate_num = 1
    for leaf_state in leaf_states:
        sr_dict = OrderedDict()
        try:
            print("  [lv.%d-EXPANSION-LEAF] Expanding leaf state %s (%d/%d leaves)" % (pm.current_level,
                leaf_state.name, leafstate_num, len(leaf_states)))
            # logger.info("  [lv.%d-EXPANSION-LEAF] Expanding leaf state %s (%d/%d leaves)" % (pm.current_level,
                # leaf_state.name, leafstate_num, len(leaf_states)))
        except Exception as e:
            print(e)
            print(leaf_state)


        # TODO - update to HTTP/3
        # move_state_h3msgs_list = get_move_state_h3msgs(pm, leaf_state)
        move_state_h3msgs_list = []

        message_num = 1
        pm.current_state = leaf_state
        parent_elapsed_time = leaf_state.elapsedTime
        for h3msg_sent in pm.testmsgs:
            print("    [lv.%d-EXPANSION-STATE-\'%s\'] move Frame: %s, send Frame: %s (%d/%d msgs)" % (pm.current_level,
                leaf_state.name, util.h3msg_to_str(move_state_h3msgs_list), util.h3msg_to_str(h3msg_sent), message_num,
                len(pm.testmsgs)))
            # logger.info("    [lv.%d-EXPANSION-STATE-\'%s\'] move Frame: %s, send Frame: %s (%d/%d msgs)" % (pm.current_level,
                # leaf_state.name, util.h3msg_to_str(move_state_h3msgs_list), util.h3msg_to_str(h3msg_sent), message_num,
                # len(pm.testmsgs)))
            h3msg_rcvd, elapsedTime = smbuilder.send_receive_http3(pm, move_state_h3msgs_list, h3msg_sent,
                                                                     parent_elapsed_time)
            update_candidates(pm, sm, h3msg_sent, h3msg_rcvd, elapsedTime)
            message_num += 1
            h3msg_sent_str = util.h3msg_to_str(h3msg_sent)
            h3msg_rcvd_str = util.h3msg_to_str(h3msg_rcvd)
            sr_dict[h3msg_sent_str] = h2msg_rcvd_str + " (%s)" % str(int(elapsedTime))
        leafstate_num += 1
        pm.current_state.child_sr_dict = sr_dict


## if Elapsed time is 0, it means end state
def minimize_sm(pm, sm):
    # Among candidate states in the next level, unique states in current level are determined in minimize_sm() via pruning.
    cand_s_list = pm.candidate_state_list.state_list
    if len(cand_s_list) == 0:
        print("  [+] No more candidate states ...")
        return

    print("  [INFO] Test %d candidate states in level %d" % (len(cand_s_list), pm.current_level))
    for cand_s in cand_s_list:
        md = MergeData()
        h2msg_sent_str = util.h3msg_to_str(cand_s.h2msg_sent)
        h2msg_rcvd_str = util.h3msg_to_str(cand_s.h2msg_rcvd)
        sr_msg = "%s => %s (%s)" % (h2msg_sent_str, h2msg_rcvd_str, str(int(cand_s.elapsedTime)))
        md.t_label = sr_msg

        ######## Filter out quick-disconnected (finishing) state #######
        if int(cand_s.elapsedTime) == 0 and h2msg_rcvd_str.find("GO") >= 0:
            pass

        ######## Retrieve cand_s SR info ########
        else: # cand_sr_dict: messages from cand_s to and its child node (Do the same test as parent).
            print('  [lv.%d-MINIMIZATION-STATE %s] Retrieving its SR dict' % (pm.current_level, cand_s.name))
            cand_sr_dict = OrderedDict()
            move_state_h3msgs_list = get_move_state_h3msgs(pm, cand_s)
            move_state_h2msgs_str = util.h3msg_to_str(move_state_h3msgs_list)

            for h2msg_sent in pm.testmsgs:
                h2msg_rcvd, elapsedTime = modeller_h2.send_receive_http2(pm, move_state_h3msgs_list, h2msg_sent,
                                                                         cand_s.elapsedTime)
                h2msg_sent_str = util.h3msg_to_str(h2msg_sent)
                h2msg_rcvd_str = util.h3msg_to_str(h2msg_rcvd)
                cand_sr_dict[h2msg_sent_str] = h2msg_rcvd_str + " (%s)" % str(int(elapsedTime))

            cand_s.child_sr_dict = cand_sr_dict

            ######## Check duplication of cand_s in 3 ways ########
            if check_dupstate(pm, md, cand_s, 'p'):
                print("  [lv.%d-MINIMIZATION-STATE %s] Same as parent state %s. Merge with its parent" % (pm.current_level, 
                    cand_s.name, md.dst_s.name))
                logger.debug(
                    "  [lv.%d-MINIMIZATION-STATE %s] Same as parent state %s. Merge with its parent" % (pm.current_level,
                        cand_s.name, md.dst_s.name))
            elif check_dupstate(pm, md, cand_s, 's'):
                print("  [lv.%d-MINIMIZATION-STATE %s] Same as sibling state %s. Merge with its sibling" % (pm.current_level,
                    cand_s.name, md.dst_s.name))
                logger.debug(
                    "  [lv.%d-MINIMIZATION-STATE %s] Same as sibling state %s. Merge with its sibling" % (pm.current_level,
                        cand_s.name, md.dst_s.name))
            elif check_dupstate(pm, md, cand_s, 'r'):
                print("  [lv.%d-MINIMIZATION-STATE %s] Same as relative state %s. Merge with its relative" % (pm.current_level,
                    cand_s.name, md.dst_s.name))
                logger.debug(
                    "  [lv.%d-MINIMIZATION-STATE %s] Same as relative state %s. Merge with its relative" % (pm.current_level,
                        cand_s.name, md.dst_s.name))
            else:
                # no dup state found.
                print("  [lv.%d-MINIMIZATION-STATE %s] -> **** Unique state %s found ****" % (pm.current_level, cand_s.name, cand_s.name))
                logger.info("  [lv.%d-MINIMIZATION-STATE %s] -> **** Unique state %s found ****" % (pm.current_level, cand_s.name, cand_s.name))

        update_sm(pm, sm, cand_s, md)
