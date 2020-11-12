# SPDX-License-Identifier: MIT

from enum import IntEnum
import logging
import struct

from dataitems import DataItem

log = logging.getLogger("myLog")


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
MINIMUM_SIGNAL_LEN = 0  # The minimum len of an SignalPdu
SIGNAL_HEADER_SIZE = 8

################################################################################
#  Message Header
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Message Type                  | Length                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
MESSAGE_HEADER_LENGTH = 4


class SignalPdu:
    def __init__(self, signaltype: SignalType = SignalType.RESERVED):
        self.type = signaltype  # The type of the PDU
        self.len = 0            # The length of the PDU in bytes
        self._data_items = []   # List of data items included in the signal

    @property
    def data_items(self):
        return self._data_items

    def append_data_item(self, item):
        self._data_items.append(item)
        self.len += item.len + DataItem.HEADER_SIZE

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

        for item in self._data_items:
            packet += item.to_buffer()

        return packet


class MessagePdu:
    def __init__(self, messagetype=MessageType.RESERVED):
        self.type = messagetype
        self.len = 0
        self._data_items = []

    @property
    def data_items(self):
        return self._data_items

    def append_data_item(self, item):
        self._data_items.append(item)
        self.len += item.len + DataItem.HEADER_SIZE

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
        for item in self._data_items:
            packet += item.to_buffer()

        return packet
