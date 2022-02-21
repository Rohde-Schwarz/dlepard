import logging
import struct
from enum import IntEnum
from typing import Optional

from ._interface import HeaderInterface, PduInterface

log = logging.getLogger(__name__)


class SignalType(IntEnum):
    """Defines all the DLEP signal types according to the RFC 8175."""

    RESERVED = 0
    PEER_DISCOVERY_SIGNAL = 1
    PEER_OFFER_SIGNAL = 2


class SignalHeader(HeaderInterface):
    """Comprises type and length header fields.

    Signal Header::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      'D'      |      'L'      |      'E'      |      'P'      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Signal Type                   | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    SIZE = 8
    """Size of the signal header without payload."""

    def __init__(self, sig_type: SignalType = SignalType.RESERVED, sig_len: int = 0):
        super().__init__(sig_type, sig_len)

    @classmethod
    def from_buffer(cls, buffer: bytes):
        """Unpacks bytes and sets the instance attributes."""
        if len(buffer) < cls.SIZE:
            return None
        unpacked = struct.unpack("!ccccHH", buffer[: cls.SIZE])
        if unpacked[:4] != (b"D", b"L", b"E", b"P"):
            log.error("No valid DLEP header found")
            return None
        return cls(SignalType(unpacked[4]), unpacked[5])

    def to_buffer(self) -> bytearray:
        """Converts the message representation to a packed bytearray."""
        packet = bytearray()
        packet.extend(
            struct.pack(
                "!ccccHH",
                "D".encode("ascii"),
                "L".encode("ascii"),
                "E".encode("ascii"),
                "P".encode("ascii"),
                int(self.type),
                self.len,
            )
        )
        return packet


class SignalPdu(PduInterface):
    """Comprises signal header and *DataItem* payload.

    Attributes:
        header: The header fields for the PDU.

    """

    def __init__(
        self,
        sig_type: SignalType = SignalType.RESERVED,
        header: Optional[SignalHeader] = None,
    ):
        if header is None:
            header = SignalHeader(sig_type, 0)
        super().__init__(header)

    @classmethod
    def from_buffer(cls, buffer: bytes):
        """Unpacks bytes and sets the instance attributes."""
        header = SignalHeader.from_buffer(buffer)
        if header is None:
            return None
        self = cls(header=header)
        log.debug(
            "Received Signal PDU {} with len {}".format(
                self.header.type, self.header.len
            )
        )
        self.items_from_buffer(buffer)
        return self
