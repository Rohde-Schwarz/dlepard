import binascii
import logging
import struct
from typing import List

from . import DataItem

log = logging.getLogger(__name__)


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def bytes_to_int(x: bytes) -> int:
    return int.from_bytes(x, "big")


def mac_str_to_int_array(x: str) -> List[int]:
    return [int(_x, 16) for _x in (x.split(":"))]


def mac_int_to_str(x: int) -> str:
    hexstr = binascii.hexlify(int.to_bytes(x, 6, "big")).decode()
    return "{}:{}:{}:{}:{}:{}".format(
        hexstr[0:2], hexstr[2:4], hexstr[4:6], hexstr[6:8], hexstr[8:10], hexstr[10:12]
    )


def extract_all_dataitems(buffer: bytes) -> list:
    total_size = len(buffer)
    processed_bytes = 0
    result: List[DataItem] = []

    while processed_bytes < total_size:
        cur_buffer = buffer[processed_bytes:]
        cur_type, cur_len = struct.unpack("!HH", cur_buffer[:4])
        log.debug("Extracting data item: type {}, len {}".format(cur_type, cur_len))
        cur_size = cur_len + DataItem.HEADER_SIZE

        if (processed_bytes + cur_size) > total_size:
            log.error("Length of Data Item exceeded total buffer size")
            return result

        item = DataItem.from_buffer(cur_buffer[:cur_size])
        result.append(item)

        processed_bytes += cur_size

    return result
