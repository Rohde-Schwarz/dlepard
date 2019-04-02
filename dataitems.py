# SPDX-License-Identifier: MIT

import logging
import socket
import struct
from enum import IntEnum

from helperfunctions import *

log = logging.getLogger("myLog")
PROG_NAME = "DLEP_ROUTER"


class SessionState(IntEnum):
    """
    Defines all the DLEP session states according to the RFC8175
    """
    PEER_DISCOVERY = 0
    SESSION_INITIALISATION = 1
    IN_SESSION = 2
    SESSION_TERMINATION = 3
    SESSION_RESET = 4


class SignalType(IntEnum):
    """
    Defines all the DLEP signal types according to the RFC8175
    """
    RESERVED = 0
    PEER_DISCOVERY_SIGNAL = 1
    PEER_OFFER_SIGNAL = 2


class MessageType(IntEnum):
    """
    Defines all the DLEP message types according to the RFC8175
    """
    RESERVED = 0
    SESSION_INITIALISATION_MESSAGE = 1
    SESSION_INITIALISATION_RESPONSE_MESSAGE = 2
    SESSION_UPDATE_MESSAGE = 3
    SESSION_UPDATE_RESPONSE_MESSAGE = 4
    SESSION_TERMINATION_MESSAGE = 5
    SESSION_TERMINATION_RESPONSE_MESSAGE = 6
    DESTINATION_UP_MESSAGE = 7
    DESTINATION_UP_RESPONSE_MESSAGE = 8
    DESTINATION_ANNOUNCE_MESSAGE = 9
    DESTINATION_ANNOUNCE_RESPONSE_MESSAGE = 10
    DESTINATION_DOWN_MESSAGE = 11
    DESTINATION_DOWN_RESPONSE_MESSAGE = 12
    DESTINATION_UPDATE_MESSAGE = 13
    LINK_CHARACTERISTICS_REQUEST_MESSAGE = 14
    LINK_CHARACTERISTICS_RESPONSE_MESSAGE = 15
    HEARTBEAT_MESSAGE = 16


class DataItemType(IntEnum):
    """
    Defines all the DLEP data item types according to the RFC8175
    """
    STATUS = 1
    IPV4_CONNECTION_POINT = 2
    IPV6_CONNECTION_POINT = 3
    PEER_TYPE = 4
    HEARTBEAT_INTERVAL = 5
    EXTENSIONS_SUPPORTED = 6
    MAC_ADDRESS = 7
    IPV4_ADDRESS = 8
    IPV6_ADDRESS = 9
    IPV4_ATTACHED_SUBNET = 10
    IPV6_ATTACHED_SUBNET = 11
    MAXIMUM_DATA_RATE_RX = 12
    MAXIMUM_DATA_RATE_TX = 13
    CURRENT_DATA_RATE_RX = 14
    CURRENT_DATA_RATE_TX = 15
    LATENCY = 16
    RESOURCES = 17
    RELATIVE_LINK_QUALITY_RX = 18
    RELATIVE_LINK_QUALITY_TX = 19
    MAXIMUM_TRANSMISSION_UNIT = 20
    LOSS_RATE = 65408


class StatusCode(IntEnum):
    """
    Defines all the DLEP status codes according to the RFC8175
    """
    SUCCESS = 0
    NOT_INTERESTED = 1
    REQUEST_DENIED = 2
    INCONSISTENT_DATA = 3
    UNKNOWN_MESSAGE = 128
    UNEXPECTED_MESSAGE = 129
    INVALID_DATA = 130
    INVALID_DESTINATION = 131
    TIMED_OUT = 132
    SHUTTING_DOWN = 255


################################################################################
#  Signal Header
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |      'D'      |      'L'      |      'E'      |      'P'      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  | Signal Type                   | Length                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# The minimum length of an SignalPdu
MINIMUM_SIGNAL_LEN = 0
SIGNAL_HEADER_SIZE = 8


class SignalPdu:
    def __init__(self, signaltype: SignalType = SignalType.RESERVED):
        self.type = signaltype  # The type of the PDU
        self.len = 0            # The length of the PDU in bytes
        self.data_items = []    # List of data items included in the signal

    def from_buffer(self, buffer):
        if len(buffer) < SIGNAL_HEADER_SIZE:
            log.error('SignalPdu.from_buffer() FAILED with: Message too small')
            return 0

        unpacked_data = struct.unpack('!ccccHH', buffer)
        # check if its a valid DLEP signal
        if unpacked_data[0] == b'D' \
                and unpacked_data[1] == b'L'\
                and unpacked_data[2] == b'E' \
                and unpacked_data[3] == b'P':
            self.type = SignalType(unpacked_data[4])
            self.len = int(unpacked_data[5])
            log.debug("Received Signal Pdu with len {}".format(self.len))
            return self.len

        log.error("RX: SignalPdu.from_buffer() FAILED with:"
                  " no valid DLEP header")
        return -1

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack("!ccccHH",
                                  'D'.encode('ascii'),
                                  'L'.encode('ascii'),
                                  'E'.encode('ascii'),
                                  'P'.encode('ascii'),
                                  int(self.type),  # 0: Data Item Type
                                  self.len,        # 1: Length
                                  ))

        for item in self.data_items:
            packet += item.to_buffer()

        return packet


################################################################################
#  Message Header
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Message Type                  | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

MESSAGE_HEADER_LENGTH = 4


class MessagePdu:
    def __init__(self, messagetype=MessageType.RESERVED):
        self.type = messagetype
        self.len = MESSAGE_HEADER_LENGTH
        self.data_items = []

    def from_buffer(self, buffer):
        if len(buffer) < MESSAGE_HEADER_LENGTH:
            log.error('MessagePdu.from_buffer() FAILED with: Message too small')
            return 0

        unpacked_data = struct.unpack('!HH', buffer)
        self.type = MessageType(unpacked_data[0])
        self.len = unpacked_data[1]
        return self.len

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack('!HH',
                                  int(self.type),
                                  self.len
                                  ))
        for item in self.data_items:
            packet += item.to_buffer()

        return packet


################################################################################
#  IPv4 Connection Point
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  | Data Item Type                | Length                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |   Flags       |               IPv4 Address...                 :
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  :  ...cont.     |   TCP Port Number (optional)  |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# The minimum length of an IPV4 Connection Point Message
DATA_ITEM_IP4_CONN_PT_LEN = 5


class DataItemIp4ConnPt:
    # TODO: tcp port is optional...??
    def __init__(self):
        self.type = int(DataItemType.IPV4_CONNECTION_POINT)
        self.len = DATA_ITEM_IP4_CONN_PT_LEN
        self.flags = 0
        self.ipaddr = ''
        self.tcp_port = 0

    def log_rx(self):
        log.debug('-> DATA_ITEM_Ip4_Conn_Pt -'
                  ' ipaddr {} - tcp-port: {}'.format(self.ipaddr, self.tcp_port))

    def to_buffer(self):
        ipid = int_from_bytes(socket.inet_aton(self.ipaddr))
        packet = bytearray()
        packet.extend(struct.pack("!HHbIH",
                                  int(self.type),  # 0: Data Item Type
                                  self.len,        # 1: Length
                                  self.flags,      # 2: Flags
                                  ipid,            # 3: Modem IP-Address
                                  self.tcp_port    # 4: Modem TCP Port
                                  ))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < DATA_ITEM_IP4_CONN_PT_LEN:
            log.error("RX: DataItemIp4ConnPt.from_buffer() FAILED with:"
                      " Message to small")
            return 0

        unpacked_data = struct.unpack('!HHbIH', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        if self.len < DATA_ITEM_IP4_CONN_PT_LEN:
            log.error("RX: DataItemIp4ConnPt.from_buffer() FAILED with:"
                      " Message length is invalid")
            return 0
        self.flags = unpacked_data[2]
        self.ipaddr = socket.inet_ntoa(int_to_bytes(unpacked_data[3]))
        self.tcp_port = unpacked_data[4]
        self.log_rx()

        return self.len


################################################################################
#  Heartbeat Interval
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  | Data Item Type                | Length                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                       Heartbeat Interval                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

HEARTBEAT_INTERVAL_LEN = 4


class HeartbeatInterval:
    def __init__(self, interval=60000):
        self.type = DataItemType.HEARTBEAT_INTERVAL
        self.len = HEARTBEAT_INTERVAL_LEN
        self.heartbeatInterval = interval  # default: 60 seconds

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack("!HHI",
                                  int(self.type),
                                  self.len,
                                  self.heartbeatInterval
                                  ))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < HEARTBEAT_INTERVAL_LEN:
            log.error("RX: DataItemHeartbeatInterval.from_buffer() FAILED with:"
                      " Message too small")
            return 0

        unpacked_data = struct.unpack('!HHI', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        self.heartbeatInterval = unpacked_data[2]
        log.debug("RX: DataItem HeartbeatInterval with"
                  " {} ms".format(self.heartbeatInterval))
        return HEARTBEAT_INTERVAL_LEN


################################################################################
#  Peer Type
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Flags         | Description...                                :
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

MINIMUM_LEN_PEER_TYPE = 1


class PeerType:
    def __init__(self, description=""):
        self.type = DataItemType.PEER_TYPE
        self.flags = 0
        self.description = description
        self.length = 1 + len(description)

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack("!HHb{}s".format(len(self.description)),
                                  int(self.type),
                                  self.length,
                                  self.flags,
                                  self.description.encode()))

        return packet

    def from_buffer(self, buffer):
        if len(buffer) < MINIMUM_LEN_PEER_TYPE:
            log.error("RX: DataItemPeerType.from_buffer() FAILED with:"
                      " Message too small")
            return -1

        unpacked_data = struct.unpack('!HHb{}s'.format(len(buffer) - 5), buffer)
        self.type = DataItemType(unpacked_data[0])
        self.length = unpacked_data[1]
        self.flags = unpacked_data[2]
        self.description = unpacked_data[3]
        log.debug("RX: DataItem PeerType with description"
                  " {} SUCCESS".format(self.description))

        return 0


################################################################################
#  Status
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Status Code   | Text...                                       :
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

MINIMUM_LEN_STATUS = 1


class Status:
    def __init__(self, code=StatusCode.SUCCESS, text=""):
        self.type = DataItemType.STATUS
        self.status_code = code
        self.text = text
        self.length = 1 + len(text)

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack('!HHB{}s'.format(len(self.text)),
                                  int(self.type),
                                  self.length,
                                  int(self.status_code),
                                  self.text.encode()))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < MINIMUM_LEN_PEER_TYPE:
            log.error("RX: DataItemStatus.from_buffer() FAILED with:"
                      " Message too small")
            return -1

        unpacked_data = struct.unpack('!HHb{}s'.format(len(buffer) - 5), buffer)
        self.type = DataItemType(unpacked_data[0])
        self.length = unpacked_data[1]
        self.status_code = StatusCode(unpacked_data[2])
        self.text = unpacked_data[3]
        log.debug("RX: DataItem Status with text {} SUCCESS".format(self.text))

        return 0


################################################################################
#  Maximum Data Rate Receive
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        MDRR (bps)                             :
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# :                        MDRR (bps)                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class MaximumDatarateReceive:
    def __init__(self, bps=0):
        self.type = DataItemType.MAXIMUM_DATA_RATE_RX
        self.len = 8
        self.datarate = bps

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack('!HHQ',
                                  int(self.type),
                                  self.len,
                                  self.datarate))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < 8:
            log.error("RX: DataItemMDRR.from_buffer() FAILED with:"
                      " Message too small")
            return -1

        unpacked_data = struct.unpack('!HHQ', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        self.datarate = unpacked_data[2]
        log.debug("RX: DataItem MDRR with {} bps".format(self.datarate))

        return 0


################################################################################
#  Maximum Data Rate Transmit
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        MDRT (bps)                             :
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# :                        MDRT (bps)                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class MaximumDatarateTransmit:
    def __init__(self, bps=0):
        self.type = DataItemType.MAXIMUM_DATA_RATE_TX
        self.len = 8
        self.datarate = bps

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack('!HHQ',
                                  int(self.type),
                                  self.len,
                                  self.datarate))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < 8:
            log.error("RX: DataItemMDRT.from_buffer() FAILED with:"
                      " Message too small")
            return -1

        unpacked_data = struct.unpack('!HHQ', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        self.datarate = unpacked_data[2]
        log.debug("RX: DataItem MDRT with {} bps".format(self.datarate))

        return 0


################################################################################
#  Current Data Rate Receive
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        CDRR (bps)                             :
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# :                        CDRR (bps)                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class CurrentDatarateReceive:
    def __init__(self, bps=0):
        self.type = DataItemType.CURRENT_DATA_RATE_RX
        self.len = 8
        self.datarate = bps

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack('!HHQ',
                                  int(self.type),
                                  self.len,
                                  self.datarate))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < 8:
            log.error("RX: DataItemCDRR.from_buffer() FAILED with:"
                      " Message too small")
            return -1

        unpacked_data = struct.unpack('!HHQ', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        self.datarate = unpacked_data[2]
        log.debug("RX: DataItem CDRR with {} bps".format(self.datarate))

        return 0


################################################################################
#  Current Data Rate Transmit
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        CDRT (bps)                             :
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# :                        CDRT (bps)                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class CurrentDatarateTransmit:
    def __init__(self, bps=0):
        self.type = DataItemType.CURRENT_DATA_RATE_TX
        self.len = 8
        self.datarate = bps

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack('!HHQ',
                                  int(self.type),
                                  self.len,
                                  self.datarate))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < 8:
            log.error("RX: DataItemCDRT.from_buffer() FAILED with:"
                      " Message too small")
            return -1

        unpacked_data = struct.unpack('!HHQ', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        self.datarate = unpacked_data[2]
        log.debug("RX: DataItem CDRT with {} bps".format(self.datarate))

        return 0



################################################################################
#  Latency
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Latency                                :
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# :                        Latency                                |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class Latency:
    def __init__(self, latency=0):
        self.type = DataItemType.LATENCY
        self.len = 8
        self.latency = latency

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack('!HHQ',
                                  int(self.type),
                                  self.len,
                                  self.latency))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < 8:
            log.error("RX: DataItemLatency.from_buffer() FAILED with:"
                      " Message too small")
            return -1

        unpacked_data = struct.unpack('!HHQ', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        self.latency = unpacked_data[2]
        log.debug("RX: DataItem Latency with {} us".format(self.latency))

        return 0


################################################################################
#  MAC Address
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                      MAC Address                              :
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# :                MAC Address    :     (if EUI-64 used)          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class MacAddress:
    def __init__(self, adr=""):
        self.type = DataItemType.MAC_ADDRESS
        self.len = 6
        self.adr = adr

    def to_buffer(self):
        packet = bytearray()
        iary = mac_str_to_int_array(self.adr)

        packet.extend(struct.pack('!HHIH',
                                  self.type,
                                  self.len,
                                  int.from_bytes(iary[0:4], 'big'),
                                  int.from_bytes(iary[4:6], 'big')))

        return packet

    def from_buffer(self, buffer):
        if len(buffer) < 6:
            log.error("RX: DataItemMacAddress.from_buffer() FAILED with:"
                      " Message too small")
            return -1

        unpacked_data = struct.unpack('!HHIH', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        self.adr = mac_itoa((unpacked_data[2] << 16) + unpacked_data[3])
        log.debug("RX: Data Item MAC Address with address {}".format(self.adr))

        return self.len


################################################################################
#  IPv4 Address
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Flags         | IPv4 Address                                  :
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# :    ...cont.   |
# +-+-+-+-+-+-+-+-+


class IPv4Address:
    def __init__(self, adr=""):
        self.type = int(DataItemType.IPV4_ADDRESS)
        self.len = 5
        self.flags = 1
        self.ipaddr = adr

    def to_buffer(self):
        ipid = int_from_bytes(socket.inet_aton(self.ipaddr))
        packet = bytearray()
        packet.extend(struct.pack("!HHbI",
                                  int(self.type),  # 0: Data Item Type
                                  self.len,        # 1: Length
                                  self.flags,      # 2: Flags
                                  ipid,            # 3: Modem IP-Address
                                  ))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < 5:
            log.error("RX: DataItemIp4Address.from_buffer() FAILED with:"
                      " Message to small")
            return 0

        unpacked_data = struct.unpack('!HHbI', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        self.flags = unpacked_data[2]
        self.ipaddr = socket.inet_ntoa(int_to_bytes(unpacked_data[3]))
        log.debug("RX: DataItemIPv4Address {}".format(self.ipaddr))

        return self.len


################################################################################
#  Loss Rate

#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Data Item Type                | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     LOSS      |
# +-+-+-+-+-+-+-+-+

class LossRate:
    def __init__(self, adr=""):
        self.ipaddr = adr
        self.type = int(DataItemType.IPV4_ADDRESS)
        self.len = 1
        self.loss = 0

    def to_buffer(self):
        ipid = int_from_bytes(socket.inet_aton(self.ipaddr))
        packet = bytearray()
        packet.extend(struct.pack("!HHb",
                                  int(self.type),  # 0: Data Item Type
                                  self.len,        # 1: Length
                                  self.loss,       # 2: Flags
                                  ))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < 1:
            log.error("RX: DataItemLossRate.from_buffer() FAILED with:"
                      " Message to small")
            return 0

        unpacked_data = struct.unpack('!HHb', buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
        self.loss = unpacked_data[2]
        log.debug("RX: DataItemLossRate {}".format(self.loss))

        return self.len
