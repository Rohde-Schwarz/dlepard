import logging
import struct
from enum import IntEnum
from typing import Optional

from ._interface import HeaderInterface, PduInterface

log = logging.getLogger(__name__)


class MessageType(IntEnum):
    """Defines all the DLEP message types according to the RFC 8175."""

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


class MessageHeader(HeaderInterface):
    """Comprises type and length header fields.

    Message Header::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Message Type                  | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Attributes:
        type: The type of the PDU.
        msg_len: The length of the PDU in bytes.

    """

    SIZE = 4
    """Size of the message header without payload."""

    def __init__(self, msg_type=MessageType.RESERVED, msg_len: int = 0):
        super().__init__(msg_type, msg_len)

    @classmethod
    def from_buffer(cls, buffer: bytes):
        """Unpacks bytes and sets the instance attributes."""
        if len(buffer) < cls.SIZE:
            return None
        msg_type, msg_len = struct.unpack("!HH", buffer[: cls.SIZE])
        return cls(MessageType(msg_type), msg_len)

    def to_buffer(self) -> bytearray:
        """Converts the message representation to a packed bytearray."""
        packet = bytearray()
        packet.extend(struct.pack("!HH", int(self.type), self.len))
        return packet


class MessagePdu(PduInterface):
    """Comprises message header and *DataItem* payload.

    Attributes:
        header: The header fields for the PDU.

    """

    def __init__(
        self, msg_type=MessageType.RESERVED, header: Optional[MessageHeader] = None
    ):
        """Constructs a message PDU representation without payload.

        Args:
            msg_type: Use this type value in the header.
            header: Use this header. *msg_type* will be ignored.
        """
        if header is None:
            header = MessageHeader(msg_type, 0)
        super().__init__(header)

    @classmethod
    def from_buffer(cls, buffer: bytes):
        header = MessageHeader.from_buffer(buffer)
        if header is None:
            return None
        self = cls(header=header)
        log.debug(
            "Received Message PDU {} with len {}".format(
                self.header.type, self.header.len
            )
        )
        self.items_from_buffer(buffer)
        return self
