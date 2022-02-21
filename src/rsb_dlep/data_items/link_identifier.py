"""Defines Data Items from RCF 8703."""
import logging
import struct
from enum import IntEnum

from . import DataItem

log = logging.getLogger(__name__)


class LinkIdentifierItemType(IntEnum):
    """Defines additional data item types from RCF 8703."""

    LINK_IDENTIFIER_LENGTH = 26
    LINK_IDENTIFIER = 27


class LinkIdentifierLength(DataItem):
    """Link Identifier Length Data Item.

    The Link Identifier Length Data Item is used by a DLEP modem implementation to
    specify the length of Link Identifier Data Items.

    Header::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Link Identifier Length        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type = LinkIdentifierItemType.LINK_IDENTIFIER_LENGTH
    _len = 2
    _format = "!H"

    def __init__(self, lid_len: int = 4):
        super().__init__()
        self.lid_len = lid_len

    def _payload_to_buffer(self) -> bytearray:
        packet = bytearray(struct.pack(self._format, self.lid_len))
        return packet

    def _payload_from_buffer(self, buffer: bytes):
        unpacked = struct.unpack(self._format, buffer[self.HEADER_SIZE :])
        self.lid_len = unpacked[0]


class LinkIdentifier(DataItem):
    """Link Identifier Data Item.

    The Link Identifier Data Item MAY be used wherever a MAC Address Data Item is
    defined as usable in core DLEP.

    Header::

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Data Item Type                | Length                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Link Identifier...                                            :
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    type = LinkIdentifierItemType.LINK_IDENTIFIER
    _len = 4

    def __init__(self, lid: bytes = b"\x00\x00\x00\x00"):
        super().__init__(item_len=len(lid))
        self._lid = lid

    @property
    def lid(self) -> bytes:
        return self._lid

    @lid.setter
    def lid(self, value: bytes):
        self._lid = value
        self.len = len(value)

    def _payload_to_buffer(self) -> bytearray:
        return bytearray(self.lid)

    def _payload_from_buffer(self, buffer: bytes):
        self.lid = buffer[self.HEADER_SIZE :]
