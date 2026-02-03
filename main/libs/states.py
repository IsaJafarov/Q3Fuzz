from pyshark.packet.packet import Packet
from typing import List

class State:
	def __init__(self, name:str, level:int, parent_state:"State"=None, msg_sent:Packet=None, msg_rcvd_str:str=None,
	 child_sr_dict=None, is_abnormal=False):
		self.name:str = name
		self.level:int = level
		self.parent_state = parent_state
		self.msg_sent:Packet = msg_sent # Pyshark packet: Requested QUIC and HTTP/3 message to reach this state from its parent
		self.msg_rcvd_str:str = msg_rcvd_str # Str: Responsed QUIC and HTTP/3 message to reach this state from its parent
		self.child_sr_dict:dict = child_sr_dict
		self.blocked_stream_ids:set = set()

	def is_stream_id_blocked(self, stream_id: int) -> bool:
		return stream_id in self.blocked_stream_ids

class StateList:
	def __init__(self, state_list:List[State]=[]):
		self.state_list = state_list

	def add_state(self, state:State) -> None:
		self.state_list.append(state)

	def remove_state(self, state:State) -> None:
		self.state_list.remove(state)

	def get_state_by_name(self, name:str) -> State:
		for state in self.state_list:
			if state.name == name:
				return state

	def get_states_by_level(self, level:int) -> List[State]:
		states_list = []
		for state in self.state_list:
			if state.level == level:
				states_list.append(state)
		return states_list

	def print_state_list(self) -> None:
		tmplist = []
		print("state list length : " + str(len(self.state_list)))
		for s in self.state_list:
			tmplist.append(s.name)
		print(tmplist)

	def print_payloadPair(self) -> None:
		print("State list length : " + str(len(self.state_list)))
		for state in self.state_list:
			print("State name : %s" % state.name)
			print("Sent payload : " + str(state.spyld))
			print ("Receive payload : "+str(state.rpyld))

