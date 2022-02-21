import abc
from enum import IntEnum
from typing import List

from .data_items import DataItem
from .data_items._helpers import extract_all_dataitems


class HeaderInterface(abc.ABC):

    SIZE = 0

    def __init__(self, pdu_type: IntEnum, payload_len: int):
        self.type = pdu_type
        self.len = payload_len

    @classmethod
    @abc.abstractmethod
    def from_buffer(cls, buffer: bytes):
        ...

    @abc.abstractmethod
    def to_buffer(self) -> bytearray:
        ...


class PduInterface(abc.ABC):
    def __init__(self, header: HeaderInterface):
        self.header = header
        self._data_items: List[DataItem] = []

    @property
    def type(self) -> IntEnum:
        """Value of the *type* header field."""
        return self.header.type

    @property
    def len(self) -> int:
        """Value of the *length* header field."""
        return self.header.len

    @property
    def data_items(self) -> List[DataItem]:
        """Returns the payload."""
        return self._data_items

    def append_data_item(self, item: DataItem):
        """Appends a new data item and updates the *len* attribute."""
        self._data_items.append(item)
        self.header.len += item.size

    def items_from_buffer(self, buffer: bytes):
        """Unpacks data items and sets the instance attributes."""
        self._data_items = extract_all_dataitems(buffer[self.header.SIZE :])

    def to_buffer(self) -> bytearray:
        """Converts the message representation to a packed bytearray."""
        packet = self.header.to_buffer()
        for item in self._data_items:
            packet += item.to_buffer()
        return packet
