# tools.py
#
# Utility functions

import struct


def EncodeString(str):
    if len(str)>253:
        raise ValueError, "Can only encode strings of <= 253 characters"

    return str


def EncodeAddress(addr):
    if not isinstance(addr, basestring):
        raise TypeError, "Address has to be a string"
    (a,b,c,d)=map(int, addr.split("."))
    return struct.pack("BBBB", a, b, c, d)


def EncodeInteger(num):
    if not isinstance(num, (int,long)):
        raise TypeError, "Can not encode non-integer as integer"
    return struct.pack("!I", num)


def EncodeDate(num):
    if not isinstance(num, int):
        raise TypeError, "Can not encode non-integer as date"
    return struct.pack("!I", num)


def DecodeString(str):
    return str


def DecodeAddress(addr):
    return ".".join(map(str, struct.unpack("BBBB", addr)))


def DecodeInteger(num):
    return (struct.unpack("!I", num))[0]


def DecodeDate(num):
    return (struct.unpack("!I", num))[0]


def EncodeAttr(datatype, value):
    if datatype in ("string", "octets", "byte", "short"):
        return EncodeString(value)
    elif datatype=="ipaddr":
        return EncodeAddress(value)
    elif datatype=="integer":
        return EncodeInteger(value)
    elif datatype=="date":
        return EncodeDate(value)
    else:
        raise ValueError, "Unknown attribute type %s" % datatype


def DecodeAttr(datatype, value):
    if datatype in ("string", "octets"):
        return DecodeString(value)
    elif datatype=="ipaddr":
        return DecodeAddress(value)
    elif datatype=="integer":
        return DecodeInteger(value)
    elif datatype=="date":
        return DecodeDate(value)
    else:
        raise ValueError, "Unknown attribute type %s" % datatype


