import struct
from scapy import all as scapy_all

# How do you know if the layer is a request or a response?
# Where do you put exception codes in the layers?
# NOTE: for modbus the TCP layer has the PSH, ACK flags set.
#


class Modbus_MBAP(scapy_all.Packet):
	"""Modbus TCP base packet layer. This represents the Modbus application protocol header (MBAP)"""
	name = "Modbus_MBAP"
	fields_desc = [
		scapy_all.ShortField("transaction_id", generate_unique_id(self)), # A simple implementation of this is to use the tcp sequence number, and increment by 1 for each packet
		scapy_all.ShortField("protocol_id", 0), # I believe for Modbus TCP this is always 0
		scapy_all.ShortField("length", None),   # Is the length inherited from the child layers? If so, it'll need to be calculated. I'm sure there is a function for this!
		scapy_all.ByteField("unit_id", None),
	]

	def is_request(self):
		"""Function to determine if the packet is a request or response
		There is nothing explicit in the protocol to delineate each, so we must
		infer it from other things.

		returns True if 'this' packet is a request, false if a response"""

		if self[TCP].sport != 502 and self[TCP].dport == 502:
			return True
		elif self[TCP].sport == 502 and self[TCP].dport != 502:
			return False
		elif self[TCP].sport == self[TCP].dport == 502:
			return guess_request_response(self) # Define another function to guess
		else: # None of the ports are 502
			return False # Default value

		#What do we do if both ports are 502?
		# Can return a default Value
		# Could return exception?
		# Could try and use some other method using sequence numbers
		# Can we use TCP flags?

	def guess_request_response(self):
		# TODO: implement
		return False

	def generate_unique_id(self):
		# should check that this layer is associated with a tcp sequence number, as when it is instantiated it might not be
		if TCP in self:
			return self[TCP].seq # Just being lazy and using tcp sequence num for this
		else:
			return 1 # Boring default value


	def extract_padding(self, p): # Will there be any padding? This is supposed to return the length
		return p[:self.length], p[self.length:]

	def default_payload_class(self): # In case we want to overload a default payload class with our own
		return Modbus_PDU #

	def post_build(self, p, pay):
		# Post build is used to calculate the length of fields
		if self.length is None and pay:
			l = len(pay)
			p = p[:4] + struct.pack(">H", l) + p[6:] # This is due to the structure of the frame
		return p + pay

	def answers(self, other):
		# This needs adjusting!
		# Can base this on whether the packet is a request or response
		return isinstance(other, Modbus_MBAP)

class Modbus_PDU(scapy_all.Packet):

	FUNCTION_CODES = {
	# Data functions
		2 : "READ_DISCRETE_INPUTS",
		1 : "READ_COILS",
		5 : "WRITE_SINGLE_COIL",
		15 : "WRITE_MULTIPLE_COILS",
		4 : "READ_INPUT_REGISTER",
		3 : "READ_HOLDING_REGISTERS",
		6 : "WRITE_SINGLE_REGISTER",
		16 : "WRITE_MULTIPLE_REGISTERS",
		23 : "READ_WRITE_MULTIPLE_REGISTERS",
		22 : "MASK_WRITE_REGISTERS",
		24 : "READ_FIFO_QUEUE",
		20 : "WRITE_FILE_RECORD",
		21 : "READ_FILE_RECORD",

	# Diagnostic functions
		7 : "READ_EXCEPTION_STATUS",
		8 : "DIAGNOSTIC",            # Note: Needs sub code (00-18, 20)
		11 : "GET_COM_EVENT_COUNTER",
		12 : "GET_COM_EVENT_LOG",
		17 : "REPORT_SLAVE_ID",
		43 : "READ_DEVICE_IDENTIFICATION", # Sub code 14

	# "Other" function
		43 : "ENCAPSULATED_INTERFACE_TRANSPORT" # sub codes 13,14
	}

	fields_desc =[
		scapy_all.ByteEnumField("function_code", None, FUNCTION_CODES)
	]

	def guess_payload_class(self, payload):
		"""Used do find out what the payload is, here we will use the function code.
		scapy should be able to find out which packets are requests v answers by the tcp stream"""
		is_request = True if self[TCP].sport=502 else False
		if self.function_code in FUNCTION_CODES: # Valid code



class Modbus_ExceptionCode(scapy_all.Packet):

	EXCEPTION_CODES = {
		0x01 : "ILLEGAL_FUNCTION",
		0x02 : "ILLEGAL_DATA_ADDRESS",
		0x03 : "ILLEGAL_DATA_VALUE",
		0x04 : "SLAVE_DEVICE_FAILURE",
		0x05 : "ACKNOWLEDGE",
		0x06 : "SLAVE_DEVICE_BUSY",
		0x08 : "MEMORY_PARITY_ERROR",
		0x0A : "GATEWAY_PATH_UNAVAILABLE",
		0x0B : "GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND"
	}

	fields_desc = [
		scapy_all.XByteField("exception_code", None)
	]

# Do I need separate layers for both requests and responses?

class Modbus_ReadCoilsReq(scapy_all.Packet):
	"""Layer for Read coils request packet"""
	fields_desc =[
		scapy_all.XShortField("starting_address", 0x0000),
		scapy_all.XShortField("quantity_coils", 0x0000)
	]

class Modbus_ReadCoilsResp(scapy_all.Packet):
	"""Layer for Read coils response packet"""
	fields_desc = [
		scapy_all.FieldLenField("byte_count", 0, length_of="coil_status"),
		scapy_all.StrLenField("coil_status", "", length_from= lambda x:x.length)
	]

	def extract_padding(self, p):
		return p[:self.length], p[self.length:]


#class Modbus_ReadDiscreteInputsReq(scapy_all.Packet):
	"""Layer for read discrete inputs request"""

#class Modbus_ReadDiscreteInputsResp(scapy_all.Packet):
	"""Layer for read discrete inputs response"""

#class Modbus_WriteSingleCoilReq(scapy_all.Packet):
	"""Layer for write single coil request"""

#class Modbus_WriteSingleCoilResp(scapy_all.Packet):
	"""Layer for write single coil response"""

#class Modbus_WriteMultipleCoilsReq(scapy_all.packet):
	"""Layer for write multiple coils request"""

#class Modbus_WriteMultipleCoilsResp(scapy_all.packet):
	"""Layer for wite multiple coils response"""

#class Modbus_ReportSlaveIdReq(scapy_all.Packet): # The request only has the function code: 0x11 so no need for this layer
	"""Layer for report slave id request"""


class Modbus_ReportSlaveIdResp(scapy_all.Packet):
	"""Layer for report slave ID response"""
	fields_desc = [
		scapy_all.FieldLenField("byte_count", 0, length_of="slave_id"),
		scapy_all.StrLenField("slave_id", "", length_from=lambda x:x.length),
		scapy_all.XByteField("run_status", 0x00)
	]

	"""
	def post_build(self, p, pay):
		# Post build is used to calculate the length of fields
		if self.length is None and pay:
			l = len(pay)
			p = p[:4] + struct.pack(">H", l) + p[6:] # This is due to the structure of the frame
		return p + pay
		"""

	def extract_padding(self, p):
		return "", p


# Modbus is defined as using TCP port 502
scapy_all.bind_layers(scapy_all.TCP, Modbus_MBAP, dport=502) # Request packet
scapy_all.bind_layers(scapy_all.TCP, Modbus_MBAP, sport=502) # Response packet
scapy_all.bind_layers(Modbus_MBAP, Modbus_PDU)

# Shouldn't need 'bind_layers' functions for each function code as we are using the
# 'guess_payload_class' function

"""
bind_layers(Modbus_PDU, Modbus_ReadDiscreteInputsReq, function_code=2)
bind_layers(Modbus_PDU, Modbus_ReadDiscreteInputsResp, function_code=2)

scapy_all.bind_layers(scapy_all.TCP, Modbus_ReadCoilsReq, dport=502)
scapy_all.bind_layers(Modbus_PDU, Modbus_ReadCoilsReq, function_code=1)
scapy_all.bind_layers(Modbus_PDU, Modbus_ReadCoilsResp, function_code=1)
scapy_all.bind_layers(Modbus_ReadCoilsReq, Modbus_ReadCoilsResp)

bind_layers(Modbus_PDU, Modbus_WriteSingleCoilReq, function_code=5)
bind_layers(Modbus_PDU, Modbus_WriteSingleCoilResp, function_code=5)
bind_layers(Modbus_PDU, Modbus_WriteMultipleCoilsReq, function_code=15)
bind_layers(Modbus_PDU, Modbus_WriteMultipleCoilsResp, function_code=15)
bind_layers(Modbus_PDU, Modbus_ReportSlaveIdReq, function_code=17)
"""
#scapy_all.bind_layers(Modbus_PDU, Modbus_ReportSlaveIdResp, function_code=0x11)


if __name__ == "__main__":
	scapy_all.interact(mydict=globals(), mybanner="SCAPY MODBUS ADDON V0.01")
