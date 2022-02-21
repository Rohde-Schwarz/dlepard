import abc
import logging
import struct
from enum import IntEnum
from typing import Dict, Optional, Type

log = logging.getLogger(__name__)


class DataItemType(IntEnum):
    """Defines all the DLEP data item types according to the RFC 8175."""

    RESERVED = 0
    STATUS = 1
    IPV4_CONNECTION_POINT = 2
    # IPV6_CONNECTION_POINT = 3
    PEER_TYPE = 4
    HEARTBEAT_INTERVAL = 5
    EXTENSIONS_SUPPORTED = 6
    MAC_ADDRESS = 7
    IPV4_ADDRESS = 8
    # IPV6_ADDRESS = 9
    IPV4_ATTACHED_SUBNET = 10
    # IPV6_ATTACHED_SUBNET = 11
    MAXIMUM_DATA_RATE_RX = 12
    MAXIMUM_DATA_RATE_TX = 13
    CURRENT_DATA_RATE_RX = 14
    CURRENT_DATA_RATE_TX = 15
    LATENCY = 16
    # RESOURCES = 17
    # RELATIVE_LINK_QUALITY_RX = 18
    # RELATIVE_LINK_QUALITY_TX = 19
    # MAXIMUM_TRANSMISSION_UNIT = 20
    LOSS_RATE = 65408


class StatusCode(IntEnum):
    """Defines all the DLEP status codes according to the RFC8175."""

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


class ExtensionType(IntEnum):
    """Contains all supported DLEP extension type values as defined by IANA."""

    LINK_IDENTIFIER = 3


class DataItem:
    """Base class for all Data Items.

    Data Item header::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Attributes:
        len (int): Value for the length field of the message header.

    """

    HEADER_SIZE = 4
    """Size of the Data Item header without payload."""
    type: IntEnum = DataItemType.RESERVED
    """Value for the type field of the header."""
    _len = 0
    """int: The minimum payload length; used for sanity checks."""
    _types: Dict[int, Type["DataItem"]] = dict()
    """Lookup table for all Data Item types that have subclass implementations."""

    def __init__(self, item_len: Optional[int] = None):
        """Contructor."""
        self.len = item_len if item_len is not None else self._len

    def __init_subclass__(cls, **kwargs):
        cls._types[int(cls.type)] = cls

    @property
    def size(self):
        """Size of the whole item including header in bytes."""
        return self.len + DataItem.HEADER_SIZE

    def _log_writing(self):
        log.debug("TX: Writing data item {} len {}".format(self.type, self.len))

    def _payload_to_buffer(self) -> bytearray:
        return bytearray()

    def to_buffer(self) -> bytearray:
        """Converts the data item representation to a packed bytearray."""
        packet = bytearray(struct.pack("!HH", int(self.type), self.len))
        packet += self._payload_to_buffer()
        return packet

    @abc.abstractmethod
    def _payload_from_buffer(self, buffer: bytes):
        ...

    @classmethod
    def from_buffer(cls, buffer: bytes):
        """Unpacks bytes and sets the instance attributes."""
        if len(buffer) < cls._len + cls.HEADER_SIZE:
            log.error("Item buffer too small")
            return None
        item_type, item_len = struct.unpack("!HH", buffer[:4])
        if item_type not in cls._types:
            log.error("Unknown message type {}".format(item_type))
            return None
        item = cls._types[item_type]()  # type DataItem
        item.len = item_len
        log.debug("RX: Reading data item {}".format(item.type))
        try:
            item._payload_from_buffer(buffer)
        except ValueError as e:
            log.error(f"Data Item {item_type}: " + str(e))
            return None
        log.debug("RX: {}".format(vars(item)))
        return item
