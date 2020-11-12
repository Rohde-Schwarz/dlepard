# SPDX-License-Identifier: MIT

import logging
import socket
import struct
from enum import IntEnum

from helperfunctions import *

log = logging.getLogger("myLog")
PROG_NAME = "DLEP_ROUTER"


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


class DataItem:

    HEADER_SIZE = 4

    def __init__(self, item_type, item_len):
        self.type = item_type
        self.len = item_len


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


class DataItemIp4ConnPt(DataItem):
    # TODO: tcp port is optional...??
    def __init__(self):
        super().__init__(
                int(DataItemType.IPV4_CONNECTION_POINT),
                DATA_ITEM_IP4_CONN_PT_LEN
        )
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


class HeartbeatInterval(DataItem):
    def __init__(self, interval=60000):
        super().__init__(
                DataItemType.HEARTBEAT_INTERVAL,
                HEARTBEAT_INTERVAL_LEN
        )
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


class PeerType(DataItem):
    def __init__(self, description=""):
        super().__init__(
                DataItemType.PEER_TYPE,
                1 + len(description)
        )
        self.flags = 0
        self.description = description

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack("!HHb{}s".format(len(self.description)),
                                  int(self.type),
                                  self.len,
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
        self.len = unpacked_data[1]
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


class Status(DataItem):
    def __init__(self, code=StatusCode.SUCCESS, text=""):
        super().__init__(
                DataItemType.STATUS,
                1 + len(text)
        )
        self.status_code = code
        self.text = text

    def to_buffer(self):
        packet = bytearray()
        packet.extend(struct.pack('!HHB{}s'.format(len(self.text)),
                                  int(self.type),
                                  self.len,
                                  int(self.status_code),
                                  self.text.encode()))
        return packet

    def from_buffer(self, buffer):
        if len(buffer) < MINIMUM_LEN_PEER_TYPE:
            log.error("RX: DataItemStatus.from_buffer() FAILED with:"
                      " Message too small")
            return -1

        unpacked_data = struct.unpack('!HHB{}s'.format(len(buffer) - 5), buffer)
        self.type = DataItemType(unpacked_data[0])
        self.len = unpacked_data[1]
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


class MaximumDatarateReceive(DataItem):
    def __init__(self, bps=0):
        super().__init__(
                DataItemType.MAXIMUM_DATA_RATE_RX,
                8
        )
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


class MaximumDatarateTransmit(DataItem):
    def __init__(self, bps=0):
        super().__init__(
                DataItemType.MAXIMUM_DATA_RATE_TX,
                8
        )
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


class CurrentDatarateReceive(DataItem):
    def __init__(self, bps=0):
        super().__init__(
                DataItemType.CURRENT_DATA_RATE_RX,
                8
        )
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


class CurrentDatarateTransmit(DataItem):
    def __init__(self, bps=0):
        super().__init__(
                DataItemType.CURRENT_DATA_RATE_TX,
                8
        )
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


class Latency(DataItem):
    def __init__(self, latency=0):
        super().__init__(
                DataItemType.LATENCY,
                8
        )
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


class MacAddress(DataItem):
    def __init__(self, adr=""):
        super().__init__(
                DataItemType.MAC_ADDRESS,
                6
        )
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


class IPv4Address(DataItem):
    def __init__(self, adr=""):
        super().__init__(
                int(DataItemType.IPV4_ADDRESS),
                5
        )
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

class LossRate(DataItem):
    def __init__(self, adr=""):
        super().__init__(
                int(DataItemType.IPV4_ADDRESS),
                1
        )
        self.ipaddr = adr
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
