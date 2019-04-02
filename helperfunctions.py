# SPDX-License-Identifier: MIT

import binascii
from datetime import datetime, timedelta


def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7)//8, 'big')


def int_from_bytes(xbytes):
    return int.from_bytes(xbytes, 'big')


def milli_to_date(milli):
    if milli is None:
        return None
    elif milli < 0:
        return datetime.utcfromtimestamp(0) + timedelta(seconds=(milli/1000))
    else:
        return datetime.utcfromtimestamp(milli/1000)


def date_to_milli(date):
    if not isinstance(date, datetime):
        return None
    epoch = datetime.utcfromtimestamp(0)
    return round((date - epoch).total_seconds() * 1000.0)


def timedelta_milli(td):
    return td.days*86400000 + td.seconds*1000 + td.microseconds/1000


def mac_str_to_int_array(macadr: str):
    return [int(x, 16) for x in (macadr.split(":"))]


def mac_atoi(macadr: str):
    return int.from_bytes(mac_str_to_int_array(macadr), 'big')


def mac_itoa(macadr: int):
    hexstr = binascii.hexlify(int.to_bytes(macadr, 6, 'big')).decode()
    return "{}:{}:{}:{}:{}:{}".format(hexstr[0:2], hexstr[2:4],
                                      hexstr[4:6], hexstr[6:8],
                                      hexstr[8:10], hexstr[10:12])
