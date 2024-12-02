class State:
	def __init__(self, name, level, parent_state=None, msg_sent=None, msg_rcvd_str=None,
	 child_sr_dict=None, is_abnormal=False):
		self.name = name
		self.level = level
		self.parent_state = parent_state
		self.msg_sent = msg_sent # Pyshark packet: Requested QUIC and HTTP/3 message to reach this state from its parent
		self.msg_rcvd_str = msg_rcvd_str # Str: Responsed QUIC and HTTP/3 message to reach this state from its parent
		self.child_sr_dict = child_sr_dict

class StateList:
	def __init__(self, state_list=[]):
		self.state_list = state_list

	def add_state(self, state):
		self.state_list.append(state)

	def remove_state(self, state):
		self.state_list.remove(state)

	def get_state_by_name(self, name):
		for state in self.state_list:
			if state.name == name:
				return state

	def get_states_by_level(self, level):
		states_list = []
		for state in self.state_list:
			if state.level == level:
				states_list.append(state)
		return states_list

	def print_state_list(self):
		tmplist = []
		print("state list length : " + str(len(self.state_list)))
		for s in self.state_list:
			tmplist.append(s.name)
		print(tmplist)

	def print_payloadPair(self):
		print("State list length : " + str(len(self.state_list)))
		for state in self.state_list:
			print("State name : %s" % state.name)
			print("Sent payload : " + str(state.spyld))
			print ("Receive payload : "+str(state.rpyld))

