import struct
from scapy import all

# How do you know if the layer is a request or a response?
# Where do you put exception codes in the layers?

class Modbus_TCP(scapy.all.Packet):
    """Modbus TCP Packet Layer"""
    name = "Modbus_TCP"
    fields_desc = [
        scapy.all.ShortField("transaction_id", None),
        scapy.all.ShortField("protocol_id", 0),
        scapy.all.ShortField("length", None),   # Is the length inherited from the child layers?
        scapy.all.ByteField("unit_id", None),
    ]

    def extract_padding(self, p): # Will there be any padding?
        return "", p

    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:4] + struct.pack("<H", l) + p[7:]
        return p + pay

class Modbus(scapy.all.Packet):

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
        scapy.all.ByteEnumField("function_code", None, FUNCTION_CODES)
    ]

# Do I need separate layers for both requests and responses?

class Modbus_ReadCoilsReq(scapy.all.Packet):
    """Layer for Read coils request packet"""
    fields_desc =[
        scapy.all.XShortField("starting_address", 0x0000),
        scapy.all.XShortField("quantity_coils", 0x0000)
    ]

class Modbus_ReadCoilsResp(scapy.all.Packet):
    """Layer for Read coils response packet"""
    fields_desc = [
        scapy.all.FieldLenField("byte_count", 0, length_of="coil_status"),
        scapy.all.StrLenField("coil_status", "", length_from= lambda x:x.length)
    ]


#class Modbus_ReadDiscreteInputsReq(scapy.all.Packet):
    """Layer for read discrete inputs request"""

#class Modbus_ReadDiscreteInputsResp(scapy.all.Packet):
    """Layer for read discrete inputs response"""

#class Modbus_WriteSingleCoilReq(scapy.all.Packet):
    """Layer for write single coil request"""

#class Modbus_WriteSingleCoilResp(scapy.all.Packet):
    """Layer for write single coil response"""

#class Modbus_WriteMultipleCoilsReq(scapy.all.packet):
    """Layer for write multiple coils request"""

#class Modbus_WriteMultipleCoilsResp(scapy.all.packet):
    """Layer for wite multiple coils response"""

#class Modbus_ReportSlaveIdReq(scapy.all.Packet):
    """Layer for report slave id request"""


class Modbus_ReportSlaveIdResp(scapy.all.Packet):
    """Layer for report slave ID response"""
    fields_desc = [
        scapy.all.FieldLenField("byte_count", 0, length_of="slave_id"),
        scapy.all.StrLenField("slave_id", "", length_from=lambda x:x.length),
        scapy.all.XByteField("run_status", 0x00)
    ]




bind_layers(scapy.all.UDP, Modbus_TCP)
bind_layers(Modbus_TCP, Modbus)
"""
bind_layers(Modbus, Modbus_ReadDiscreteInputsReq, function_code=2)
bind_layers(Modbus, Modbus_ReadDiscreteInputsResp, function_code=2)
"""
bind_layers(Modbus, Modbus_ReadCoilsReq, function_code=1)
bind_layers(Modbus, Modbus_ReadCoilsResp, function_code=1)
"""
bind_layers(Modbus, Modbus_WriteSingleCoilReq, function_code=5)
bind_layers(Modbus, Modbus_WriteSingleCoilResp, function_code=5)
bind_layers(Modbus, Modbus_WriteMultipleCoilsReq, function_code=15)
bind_layers(Modbus, Modbus_WriteMultipleCoilsResp, function_code=15)
bind_layers(Modbus, Modbus_ReportSlaveIdReq, function_code=17)
"""
bind_layers(Modbus, Modbus_ReportSlaveIdResp, function_code=17)
