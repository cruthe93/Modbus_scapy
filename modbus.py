import struct
from scapy import all as scapy_all

# How do you know if the layer is a request or a response?
# Where do you put exception codes in the layers?
# NOTE: for modbus the TCP layer has the PSH, ACK flags set.

class Modbus_TCP(scapy_all.Packet):
    """Modbus TCP base packet layer. All Modbus TCP packets have these fields"""
    name = "Modbus_TCP"
    fields_desc = [
        scapy_all.ShortField("transaction_id", None), # A simple implementation of this is to use the tcp sequence number, and increment by 1 for each packet
        scapy_all.ShortField("protocol_id", 0),
        scapy_all.ShortField("length", None),   # Is the length inherited from the child layers? If so, it'll need to be calculated
        scapy_all.ByteField("unit_id", None),
    ]

    def extract_padding(self, p): # Will there be any padding?
        return "", p

    def post_build(self, p, pay):
        # Post build is used to calculate the length of fields
        if self.length is None and pay:
            l = len(pay)
            p = p[:4] + struct.pack(">H", l) + p[6:] # This is due to the structure of the frame
        return p + pay

    def answers(self, other):
        # This may need adjusting
        return isinstance(other, Modbus_TCP)

class Modbus(scapy_all.Packet):

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
        8 : "DIAGNOSTIC",            # Note: Needs sub code
        11 : "GET_COM_EVENT_COUNTER",
        12 : "GET_COM_EVENT_LOG",
        17 : "REPORT_SLAVE_ID",
        43 : "READ_DEVICE_IDENTIFICATION",

    # "Other" function
        43 : "ENCAPSULATED_INTERFACE_TRANSPORT"
    }

    fields_desc =[
        scapy_all.ByteEnumField("function_code", None, FUNCTION_CODES)
    ]

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

#class Modbus_ReportSlaveIdReq(scapy_all.Packet):
    """Layer for report slave id request"""


class Modbus_ReportSlaveIdResp(scapy_all.Packet):
    """Layer for report slave ID response"""
    fields_desc = [
        scapy_all.FieldLenField("byte_count", 0, length_of="slave_id"),
        scapy_all.StrLenField("slave_id", "", length_from=lambda x:x.length),
        scapy_all.XByteField("run_status", 0x00)
    ]



# Modbus is defined as using TCP port 502
scapy_all.bind_layers(scapy_all.TCP, Modbus_TCP, dport=502)
scapy_all.bind_layers(scapy_all.TCP, Modbus_TCP, sport=502)
scapy_all.bind_layers(Modbus_TCP, Modbus)
"""
bind_layers(Modbus, Modbus_ReadDiscreteInputsReq, function_code=2)
bind_layers(Modbus, Modbus_ReadDiscreteInputsResp, function_code=2)
"""
scapy_all.bind_layers(scapy_all.TCP, Modbus_ReadCoilsReq, dport=502)
scapy_all.bind_layers(Modbus, Modbus_ReadCoilsReq, function_code=1)
scapy_all.bind_layers(Modbus, Modbus_ReadCoilsResp, function_code=1)
"""
bind_layers(Modbus, Modbus_WriteSingleCoilReq, function_code=5)
bind_layers(Modbus, Modbus_WriteSingleCoilResp, function_code=5)
bind_layers(Modbus, Modbus_WriteMultipleCoilsReq, function_code=15)
bind_layers(Modbus, Modbus_WriteMultipleCoilsResp, function_code=15)
bind_layers(Modbus, Modbus_ReportSlaveIdReq, function_code=17)
"""
scapy_all.bind_layers(Modbus, Modbus_ReportSlaveIdResp, function_code=17)


if __name__ == "__main__":
    scapy_all.interact(mydict=globals(), mybanner="SCAPY MODBUS ADDON V0.01")
