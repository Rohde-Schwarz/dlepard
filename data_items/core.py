"""Definition of Data Item structures."""
import ipaddress
import logging
import socket
import struct
from typing import List, Optional, Union

from . import DataItem, DataItemType, ExtensionType, StatusCode
from ._helpers import bytes_to_int, int_to_bytes, mac_int_to_str, mac_str_to_int_array

log = logging.getLogger(__name__)


class Ip4ConnPt(DataItem):
    """IPv4 Connection Point.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Flags       |               IPv4 Address...                 :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :  ...cont.     |   TCP Port Number (optional)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Todo:
        TCP port is optional ... ??

    """

    type = DataItemType.IPV4_CONNECTION_POINT
    _len = 5

    def __init__(self):
        super().__init__()
        self.flags = 0
        self.ipaddr = ""
        self.tcp_port = 0

    def to_buffer(self) -> bytearray:
        self._log_writing()
        ipid = bytes_to_int(socket.inet_aton(self.ipaddr))
        packet = bytearray()
        if self.tcp_port != 0:
            packet.extend(
                struct.pack(
                    "!HHbIH",
                    int(self.type),  # 0: Data Item Type
                    self.len,  # 1: Length
                    self.flags,  # 2: Flags
                    ipid,  # 3: Modem IP-Address
                    self.tcp_port,  # 4: Modem TCP Port
                )
            )
        else:
            packet.extend(
                struct.pack(
                    "!HHbI",
                    int(self.type),  # 0: Data Item Type
                    self.len,  # 1: Length
                    self.flags,  # 2: Flags
                    ipid,  # 3: Modem IP-Address
                )
            )
        return packet

    def _payload_from_buffer(self, buffer):
        if self.len == 7:
            unpacked_data = struct.unpack("!HHbIH", buffer)
        else:
            unpacked_data = struct.unpack("!HHbI", buffer)
        self.flags = unpacked_data[2]
        self.ipaddr = socket.inet_ntoa(int_to_bytes(unpacked_data[3]))
        if self.len == 7:
            self.tcp_port = unpacked_data[4]


class HeartbeatInterval(DataItem):
    """Heartbeat Interval.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Heartbeat Interval                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.HEARTBEAT_INTERVAL
    _len = 4

    def __init__(self, interval: int = 60000):
        super().__init__()
        self.heartbeatInterval = interval  # default: 60 seconds

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        packet.extend(
            struct.pack("!HHI", int(self.type), self.len, self.heartbeatInterval)
        )
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHI", buffer)
        self.heartbeatInterval = unpacked_data[2]


class PeerType(DataItem):
    """Peer Type.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Flags         | Description...                                :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.PEER_TYPE
    _len = 1

    def __init__(self, description: str = ""):
        super().__init__(self._len + len(description))
        self.flags = 0
        self._description = description

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, description):
        self._description = description
        self.len = self._len + len(description)

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        packet.extend(
            struct.pack(
                "!HHb{}s".format(len(self._description)),
                int(self.type),
                self.len,
                self.flags,
                self._description.encode(),
            )
        )
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHb{}s".format(len(buffer) - 5), buffer)
        self.flags = unpacked_data[2]
        self._description = unpacked_data[3].decode()


class Status(DataItem):
    """Status.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Status Code   | Text...                                       :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.STATUS
    _len = 1

    def __init__(self, code=StatusCode.SUCCESS, text: str = ""):
        super().__init__(self._len + len(text))
        self.status_code = code
        self._text = text

    @property
    def text(self) -> str:
        return self._text

    @text.setter
    def text(self, text: str):
        self._text = text
        self.len = self._len + len(text)

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        packet.extend(
            struct.pack(
                "!HHB{}s".format(len(self._text)),
                int(self.type),
                self.len,
                int(self.status_code),
                self._text.encode(),
            )
        )
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHB{}s".format(len(buffer) - 5), buffer)
        self.status_code = StatusCode(unpacked_data[2])
        self._text = unpacked_data[3].decode()


class MaximumDatarateReceive(DataItem):
    """Maximum Data Rate Receive.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        MDRR (bps)                             :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :                        MDRR (bps)                             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.MAXIMUM_DATA_RATE_RX
    _len = 8

    def __init__(self, bps: int = 0):
        super().__init__()
        self.datarate = bps

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        packet.extend(struct.pack("!HHQ", int(self.type), self.len, self.datarate))
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHQ", buffer)
        self.datarate = unpacked_data[2]


class MaximumDatarateTransmit(DataItem):
    """Maximum Data Rate Transmit.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        MDRT (bps)                             :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :                        MDRT (bps)                             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.MAXIMUM_DATA_RATE_TX
    _len = 8

    def __init__(self, bps: int = 0):
        super().__init__()
        self.datarate = bps

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        packet.extend(struct.pack("!HHQ", int(self.type), self.len, self.datarate))
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHQ", buffer)
        self.datarate = unpacked_data[2]


class CurrentDatarateReceive(DataItem):
    """Current Data Rate Receive.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        CDRR (bps)                             :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :                        CDRR (bps)                             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.CURRENT_DATA_RATE_RX
    _len = 8

    def __init__(self, bps: int = 0):
        super().__init__()
        self.datarate = bps

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        packet.extend(struct.pack("!HHQ", int(self.type), self.len, self.datarate))
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHQ", buffer)
        self.datarate = unpacked_data[2]


class CurrentDatarateTransmit(DataItem):
    """Current Data Rate Transmit.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        CDRT (bps)                             :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :                        CDRT (bps)                             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.CURRENT_DATA_RATE_TX
    _len = 8

    def __init__(self, bps: int = 0):
        super().__init__()
        self.datarate = bps

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        packet.extend(struct.pack("!HHQ", int(self.type), self.len, self.datarate))
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHQ", buffer)
        self.datarate = unpacked_data[2]


class Latency(DataItem):
    """Latency.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Latency                                :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :                        Latency                                |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.LATENCY
    _len = 8

    def __init__(self, latency: int = 0):
        super().__init__()
        self.latency = latency

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        packet.extend(struct.pack("!HHQ", int(self.type), self.len, self.latency))
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHQ", buffer)
        self.latency = unpacked_data[2]


class MacAddress(DataItem):
    """MAC Address.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                      MAC Address                              :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :                MAC Address    :     (if EUI-64 used)          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.MAC_ADDRESS
    _len = 6

    def __init__(self, addr: str = ""):
        super().__init__()
        self.addr = addr

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        iary = mac_str_to_int_array(self.addr)

        packet.extend(
            struct.pack(
                "!HHIH",
                self.type,
                self.len,
                int.from_bytes(iary[0:4], "big"),
                int.from_bytes(iary[4:6], "big"),
            )
        )

        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHIH", buffer)
        self.addr = mac_int_to_str((unpacked_data[2] << 16) + unpacked_data[3])


class IPv4Address(DataItem):
    """IPv4 Address.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Flags         | IPv4 Address                                  :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        :    ...cont.   |
        +-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.IPV4_ADDRESS
    _len = 5

    def __init__(self, addr: Optional[Union[ipaddress.IPv4Address, str]] = None):
        super().__init__()
        self.flags = 1
        self._ipaddr: Optional[ipaddress.IPv4Address] = None
        if addr is not None:
            self.ipaddr = addr

    @property
    def ipaddr(self) -> Optional[Union[ipaddress.IPv4Address, str]]:
        return self._ipaddr

    @ipaddr.setter
    def ipaddr(self, value: Union[ipaddress.IPv4Address, str]):
        if isinstance(value, ipaddress.IPv4Address):
            self._ipaddr = value
        else:
            self._ipaddr = ipaddress.IPv4Address(value)

    def to_buffer(self) -> bytearray:
        if self._ipaddr is None:
            return bytearray()
        self._log_writing()
        packet = bytearray()
        packet.extend(
            struct.pack(
                "!HHbI",
                int(self.type),  # 0: Data Item Type
                self.len,  # 1: Length
                self.flags,  # 2: Flags
                int(self._ipaddr),  # 3: Modem IP-Address
            )
        )
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHbI", buffer)
        self.flags = unpacked_data[2]
        self._ipaddr = ipaddress.IPv4Address(unpacked_data[3])


class IPv4AttachedSubnet(DataItem):
    """IPv4 Attached Subnet.

    The DLEP IPv4 Attached Subnet Data Item contains the following
    fields::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Flags         | IPv4 Attached Subnet                          :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        : ...cont.      | Prefix Length |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.IPV4_ATTACHED_SUBNET
    _len = 6

    def __init__(self, subnet: Optional[Union[ipaddress.IPv4Network, str]] = None):
        super().__init__()
        self.flags = 1
        self._subnet: Optional[ipaddress.IPv4Network] = None
        if subnet:
            self.subnet = subnet

    @property
    def subnet(self) -> Optional[Union[ipaddress.IPv4Network, str]]:
        return self._subnet

    @subnet.setter
    def subnet(self, value: Union[ipaddress.IPv4Network, str]):
        if isinstance(value, ipaddress.IPv4Network):
            self._subnet = value
        else:
            self._subnet = ipaddress.IPv4Network(value)

    def to_buffer(self) -> bytearray:
        if self._subnet is None:
            return bytearray()
        self._log_writing()
        packet = bytearray()
        packet.extend(
            struct.pack(
                "!HHbIb",
                int(self.type),
                self.len,
                self.flags,
                int(self._subnet.network_address),
                self._subnet.prefixlen,
            )
        )
        return packet

    def _payload_from_buffer(self, buffer: bytes):
        unpacked_data = struct.unpack("!HHbIb", buffer)
        self.flags = unpacked_data[2]
        self._subnet = ipaddress.IPv4Network((unpacked_data[3], unpacked_data[4]))


class LossRate(DataItem):
    """Loss Rate.

    ::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     LOSS      |
        +-+-+-+-+-+-+-+-+

    """

    type: DataItemType = DataItemType.LOSS_RATE
    _len = 1

    def __init__(self, loss: int = 0):
        super().__init__()
        self.loss = loss

    def to_buffer(self) -> bytearray:
        self._log_writing()
        packet = bytearray()
        packet.extend(
            struct.pack(
                "!HHb",
                int(self.type),  # 0: Data Item Type
                self.len,  # 1: Length
                self.loss,  # 2: Flags
            )
        )
        return packet

    def _payload_from_buffer(self, buffer):
        unpacked_data = struct.unpack("!HHb", buffer)
        self.loss = unpacked_data[2]


class ExtensionsSupported(DataItem):
    """Extensions Supported.

    The Extensions Supported Data Item is used by the router and modem to
    negotiate additional optional functionality they are willing to
    support.

    The Extensions Supported Data Item contains the following fields::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Extensions List...                                            :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type = DataItemType.EXTENSIONS_SUPPORTED
    _len = 0

    def __init__(self, ext_list: Optional[List[int]] = None):
        self._ext = ext_list if ext_list is not None else []
        super().__init__(2 * len(self._ext))

    @property
    def ext_list(self) -> list:
        return self._ext

    def append(self, value: ExtensionType):
        self._ext.append(int(value))
        self.len = 2 * len(self._ext)

    def clear(self):
        self._ext = []
        self.len = 0

    def _payload_to_buffer(self) -> bytearray:
        fmt = "!{}H".format(len(self._ext))
        packet = bytearray(struct.pack(fmt, *self._ext))
        return packet

    def _payload_from_buffer(self, _buffer: bytes):
        buffer = _buffer[self.HEADER_SIZE :]
        fmt = "!{}H".format(self.len // 2)
        self._ext = list(struct.unpack(fmt, buffer))
