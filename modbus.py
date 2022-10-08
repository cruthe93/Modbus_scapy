import struct

from scapy.main import interact
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP
from scapy.fields import ShortField, ByteField, ByteEnumField, XByteField, XShortField, FieldLenField, StrLenField


class Modbus_MBAP(Packet):
    """Modbus TCP base packet layer. This represents the Modbus application protocol header (MBAP)"""
    name = "Modbus_MBAP"

    fields_desc = [
        ShortField("transaction_id", 0),
        # A simple implementation of this is to use the tcp sequence number, and increment by 1 for each packet
        ShortField("protocol_id", 0),  # I believe for Modbus TCP this is always 0
        ShortField("length", None),
        # Is the length inherited from the child layers? If so, it'll need to be calculated. I'm sure there is a function for this!
        ByteField("unit_id", None),
    ]

    @classmethod
    def generate_unique_id(self):
        # should check that this layer is associated with a tcp sequence number, as when it is instantiated it might not be
        if TCP in self:
            return self[TCP].seq  # Just being lazy and using tcp sequence num for this
        else:
            return 1  # Boring default value

    @classmethod
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
            return self.guess_request_response  # Define another function to guess
        else:  # None of the ports are 502
            return False  # Default value

    # What do we do if both ports are 502?
    # Can return a default Value
    # Could return exception?
    # Could try and use some other method using sequence numbers
    # Can we use TCP flags?

    @classmethod
    def is_response(cls):
        # Added for code readability
        return not cls.is_request

    def extract_padding(self, p):  # Will there be any padding? This is supposed to return the length
        return p[:self.length], p[self.length:]

    def default_payload_class(self, payload):  # In case we want to overload a default payload class with our own
        return Modbus_PDU  #

    def post_build(self, p, pay):
        # Post build is used to calculate the length of fields
        if self.length is None and pay:
            l = len(pay)
            p = p[:4] + struct.pack(">H", l) + p[6:]  # This is due to the structure of the frame
        return p + pay

    def answers(self, other):
        # This needs adjusting!
        # Can base this on whether the packet is a request or response
        return isinstance(other, Modbus_MBAP)


class Modbus_PDU(Packet):
    FUNCTION_CODES = {
        # Data functions
        2: "READ_DISCRETE_INPUTS",
        1: "READ_COILS",
        5: "WRITE_SINGLE_COIL",
        15: "WRITE_MULTIPLE_COILS",
        4: "READ_INPUT_REGISTER",
        3: "READ_HOLDING_REGISTERS",
        6: "WRITE_SINGLE_REGISTER",
        16: "WRITE_MULTIPLE_REGISTERS",
        23: "READ_WRITE_MULTIPLE_REGISTERS",
        22: "MASK_WRITE_REGISTERS",
        24: "READ_FIFO_QUEUE",
        20: "WRITE_FILE_RECORD",
        21: "READ_FILE_RECORD",

        # Diagnostic functions
        7: "READ_EXCEPTION_STATUS",
        8: "DIAGNOSTIC",  # Note: Needs sub code (00-18, 20)
        11: "GET_COM_EVENT_COUNTER",
        12: "GET_COM_EVENT_LOG",
        17: "REPORT_SLAVE_ID",
        43: "READ_DEVICE_IDENTIFICATION",  # Sub code 14

        # "Other" function
        43: "ENCAPSULATED_INTERFACE_TRANSPORT"  # sub codes 13,14
    }

    fields_desc = [
        ByteEnumField("function_code", None, FUNCTION_CODES)
    ]

    def guess_payload_class(self, payload):
        """Used do find out what the payload is, here we will use the function code.
        scapy should be able to find out which packets are requests v answers by the tcp stream"""

        if self.function_code in self.FUNCTION_CODES:  # Valid code
            if self.is_request:  # Now look at code to determine payload class
                return modbus_classes_requests[self.function_code]
            elif self.is_response:
                return modbus_classes_responses[self.function_code]
        else:  # if we can't figure it out, then let scapy attempt to handle it
            return self.guess_payload_class(payload)


class ModbusExceptionCode(Packet):
    EXCEPTION_CODES = {
        0x01: "ILLEGAL_FUNCTION",
        0x02: "ILLEGAL_DATA_ADDRESS",
        0x03: "ILLEGAL_DATA_VALUE",
        0x04: "SLAVE_DEVICE_FAILURE",
        0x05: "ACKNOWLEDGE",
        0x06: "SLAVE_DEVICE_BUSY",
        0x08: "MEMORY_PARITY_ERROR",
        0x0A: "GATEWAY_PATH_UNAVAILABLE",
        0x0B: "GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND"
    }

    fields_desc = [
        XByteField("exception_code", None)
    ]


# Do I need separate layers for both requests and responses?

class ModbusReadCoilsReq(Packet):
    """Layer for Read coils request packet"""
    fields_desc = [
        XShortField("starting_address", 0x0000),
        XShortField("quantity_coils", 0x0000)
    ]


class ModbusReadCoilsResp(Packet):
    """Layer for Read coils response packet"""
    fields_desc = [
        FieldLenField("byte_count", 0, length_of="coil_status"),
        StrLenField("coil_status", "", length_from=lambda x: x.length)
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]


class ModbusReadDiscreteInputsReq(Packet):
    """Layer for read discrete inputs request"""
    pass


class ModbusReadDiscreteInputsResp(Packet):
    """Layer for read discrete inputs response"""
    pass


class ModbusWriteSingleCoilReq(Packet):
    """Layer for write single coil request"""
    pass


class ModbusWriteSingleCoilResp(Packet):
    """Layer for write single coil response"""
    pass


class ModbusWriteMultipleCoilsReq(Packet):
    """Layer for write multiple coils request"""
    pass


class ModbusWriteMultipleCoilsResp(Packet):
    """Layer for write multiple coils response"""
    pass


class ModbusReadInputRegisterReq(Packet):
    pass


class ModbusReadInputRegisterResp(Packet):
    pass


class ModbusReadHoldingRegistersReq(Packet):
    pass


class ModbusReadHoldingRegistersResp(Packet):
    pass


class ModbusWriteSingleRegisterReq(Packet):
    pass


class ModbusWriteSingleRegisterResp(Packet):
    pass


class ModbusWriteMultipleRegistersReq(Packet):
    pass


class ModbusWriteMultipleRegistersResp(Packet):
    pass


class ModbusReadWriteMultipleRegistersReq(Packet):
    pass


class ModbusReadWriteMultipleRegistersResp(Packet):
    pass


class ModbusMaskWriteRegistersReq(Packet):
    pass


class ModbusMaskWriteRegistersResp(Packet):
    pass


class ModbusReadFIFOQueueReq(Packet):
    pass


class ModbusReadFIFOQueueResp(Packet):
    pass


class ModbusWriteFileRecordReq(Packet):
    pass


class ModbusWriteFileRecordResp(Packet):
    pass


class ModbusReadFileRecordReq(Packet):
    pass


class ModbusReadFileRecordResp(Packet):
    pass

# Diagnostic functions


class ModbusReadExceptionStatusReq(Packet):
    pass


class ModbusReadExceptionStatusResp(Packet):
    pass


class ModbusDiagnosticReq(Packet):
    pass


class ModbusDiagnosticResp(Packet):
    pass


class ModbusGetComEventCounterReq(Packet):
    pass


class ModbusGetComEventCounterResp(Packet):
    pass


class ModbusGetComEventLogReq(Packet):
    pass


class ModbusGetComEventLogResp(Packet):
    pass


class ModbusReportSlaveIdReq(Packet):  # The request only has the function code: 0x11 so no need for this layer
    """Layer for report slave id request"""
    pass


class ModbusReportSlaveIdResp(Packet):
    """Layer for report slave ID response"""
    fields_desc = [
        FieldLenField("byte_count", 0, length_of="slave_id"),
        StrLenField("slave_id", "", length_from=lambda x: x.length),
        XByteField("run_status", 0x00)
    ]

    """
    def post_build(self, p, pay):
        # Post build is used to calculate the length of fields
        if self.length is None and pay:
            l = len(pay)
            p = p[:4] + struct.pack(">H", l) + p[6:] # This is due to the structure of the frame
        return p + pay
        """


# def extract_padding(self, p):
#    return "", p

class ModbusReadDeviceIDReq(Packet):
    pass


class ModbusReadDeviceIDResp(Packet):
    pass


# "Other" function
class ModbusEncapsulatedInterfaceTransportReq(Packet):
    pass


class ModbusEncapsulatedInterfaceTransportResp(Packet):
    pass


modbus_classes_requests = {
    # Data functions
    2: ModbusReadDiscreteInputsReq,
    1: ModbusReadCoilsReq,
    5: ModbusWriteSingleCoilReq,
    15: ModbusWriteMultipleCoilsReq,
    4: ModbusReadInputRegisterReq,
    3: ModbusReadHoldingRegistersReq,
    6: ModbusWriteSingleRegisterReq,
    16: ModbusWriteMultipleRegistersReq,
    23: ModbusReadWriteMultipleRegistersReq,
    22: ModbusMaskWriteRegistersReq,
    24: ModbusReadFIFOQueueReq,
    20: ModbusWriteFileRecordReq,
    21: ModbusReadFileRecordReq,

    # Diagnostic functions
    7: ModbusReadExceptionStatusReq,
    8: ModbusDiagnosticReq,  # Note: Needs sub code (00-18, 20)
    11: ModbusGetComEventCounterReq,
    12: ModbusGetComEventLogReq,
    17: ModbusReportSlaveIdReq,
    43: ModbusReadDeviceIDReq,  # Sub code 14

    # "Other" function
    43: ModbusEncapsulatedInterfaceTransportResp  # sub codes 13,14
}

modbus_classes_responses = {
    # Data functions
    2: ModbusReadDiscreteInputsResp,
    1: ModbusReadCoilsResp,
    5: ModbusWriteSingleCoilResp,
    15: ModbusWriteMultipleCoilsResp,
    4: ModbusReadInputRegisterResp,
    3: ModbusReadHoldingRegistersResp,
    6: ModbusWriteSingleRegisterResp,
    16: ModbusWriteMultipleRegistersResp,
    23: ModbusReadWriteMultipleRegistersResp,
    22: ModbusMaskWriteRegistersResp,
    24: ModbusReadFIFOQueueResp,
    20: ModbusWriteFileRecordResp,
    21: ModbusReadFileRecordResp,

    # Diagnostic functions
    7: ModbusReadExceptionStatusResp,
    8: ModbusDiagnosticResp,  # Note: Needs sub code (00-18, 20)
    11: ModbusGetComEventCounterResp,
    12: ModbusGetComEventLogResp,
    17: ModbusReportSlaveIdResp,
    43: ModbusReadDeviceIDResp,  # Sub code 14

    # "Other" function
    43: ModbusEncapsulatedInterfaceTransportResp  # sub codes 13,14
}

# Modbus is defined as using TCP port 502
bind_layers(TCP, Modbus_MBAP, dport=502)  # Request packet
bind_layers(TCP, Modbus_MBAP, sport=502)  # Response packet
bind_layers(Modbus_MBAP, Modbus_PDU)

# Shouldn't need 'bind_layers' functions for each function code as we are using the
# 'guess_payload_class' function
# There are too many request and response types to bother with binding layers


if __name__ == "__main__":
    interact(mydict=globals(), mybanner="SCAPY MODBUS ADDON V0.01")
