#===============================================================================
# Copyright 2014 NetApp, Inc. All Rights Reserved,
# contribution by Jorge Mora <mora@netapp.com>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#===============================================================================
"""
Pktt utilities module

The Packet trace utilities module has classes which augment functionality
of basic data types like displaying integers as their hex equivalent.
It also includes an Enum base class which displays the integer as its
string representation given by a mapping dictionary. There is also a
class to be used as a base class for an RPC payload object.
This module also includes some module variables to change how certain
objects are displayed.
"""
import nfstest_config as c
from baseobj import BaseObj, fstrobj

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.2"

# RPC type constants
RPC_CALL  = 0
RPC_REPLY = 1
rpc_type = {RPC_CALL:'call', RPC_REPLY:'reply'}

# Module variables that change the way an RPC packet is displayed
RPC_type = True  # Display RPC type, e.g., call or reply
RPC_load = True  # Display RPC load name, e.g., NFS, etc.
RPC_ver  = True  # Display RPC load version, e.g., v3, v4, etc.
RPC_xid  = True  # Display RPC xid

# Module variables that change the way an RPC payload is displayed
NFS_mainop = False # Display only the main operation in an NFS COMPOUND
LOAD_body  = True  # Display the body of layer/procedure/operation

# Module variables for Enum
ENUM_CHECK = False

class IntHex(int):
    """Integer object which is displayed in hex"""
    def __str__(self):
        return "{0:#010x}".format(self)

class LongHex(long):
    """Long integer object which is displayed in hex"""
    def __str__(self):
        return "{0:#018x}".format(self)

class DateStr(float):
    """Floating point object which is displayed as a date"""
    _strfmt = "{0:date}"
    def __str__(self):
        return repr(fstrobj.format(self._strfmt, self))

class StrHex(str):
    """String object which is displayed in hex"""
    def __str__(self):
        return "0x" + self.encode("hex")

class EnumInval(Exception):
    """Exception for an invalid enum value"""
    pass

class Enum(int):
    """Enum base object
       This should only be used as a base class where the class attributes
       should be initialized
    """
    _offset = 0    # Strip the first bytes from the string name after conversion
    _enumdict = {} # Enum mapping dictionary to convert integer to string name

    def __new__(cls, unpack):
        """Constructor which checks if integer is a valid enum value"""
        if isinstance(unpack, int):
            # Value is given as an integer
            value = unpack
        else:
            # Unpack integer
            value = unpack.unpack_int()
        # Instantiate base class (integer class)
        obj = super(Enum, cls).__new__(cls, value)
        if ENUM_CHECK and obj._enumdict.get(value) is None:
            raise EnumInval, "value=%s not in enum '%s'" % (value, obj.__class__.__name__)
        return obj

    def __str__(self):
        """Informal string representation, display value using the mapping
           dictionary provided as a class attribute
        """
        value = self._enumdict.get(self)
        if value is None:
            return super(Enum, self).__str__()
        else:
            return value[self._offset:]

class BitmapInval(Exception):
    """Exception for an invalid bit number"""
    pass

def bitmap_dict(unpack, bitmap, func_map, name_map=None):
    """Returns a dictionary where the key is the bit number given by bitmap
       and the value is the decoded value by evaluating the function used
       for that specific bit number

       unpack:
           Unpack object
       bitmap:
           Unsigned integer where a value must be decoded for every bit that
           is set, starting from the least significant bit
       func_map:
           Dictionary which maps a bit number to the function to be used for
           decoding the value for that bit number. The function must have
           the "unpack" object as the only argument
       name_map:
           Dictionary which maps a bit number to a bit name. If this is given
           the resulting dictionary will have a bit name for a key instead
           of the bit number
    """
    ret = {}
    bitnum = 0
    while bitmap > 0:
        # Check if bit is set
        if bitmap & 0x01 == 1:
            # Get decoding function for this bit number
            func = func_map.get(bitnum)
            if func is None:
                raise BitmapInval, "decoding function not found for bit number %d" % bitnum
            else:
                if name_map:
                    # Use the bit number name instead of the bit number
                    # for the key
                    ret[name_map.get(bitnum, bitnum)] = func(unpack)
                else:
                    ret[bitnum] = func(unpack)
        bitmap = bitmap >> 1
        bitnum += 1
    return ret

class RPCload(BaseObj):
    """RPC load base object
       This is used as a base class for an RPC payload object
    """
    # Class attributes
    _pindex  = 0    # Discard this number of characters from the procedure name
    _strname = None # Name to display in object's debug representation level=1

    def rpc_str(self, name=None):
        """Display RPC string"""
        out = ""
        rpc = self._rpc
        if name is None:
            self._strname = self.__class__.__name__
            name = self._strname
        if RPC_load:
            out += "%-5s " % name
        if RPC_ver:
            mvstr = ""
            minorversion = getattr(self, 'minorversion', 0)
            if minorversion > 0:
                mvstr = ".%d" % minorversion
            vers = "v%d%s" % (rpc.version, mvstr)
            out += "%-4s " % vers
        if RPC_type:
            out += "%-5s " % rpc_type.get(rpc.type)
        if RPC_xid:
            out += "xid:0x%08x " % rpc.xid
        return out

    def __str__(self):
        """Informal string representation"""
        rdebug = self.debug_repr()
        if rdebug == 1:
            out = self.rpc_str(self._strname)
            out += "%-10s" % str(self.procedure)[self._pindex:]
            if LOAD_body and getattr(self, "switch", None) is not None:
                itemstr = str(self.switch)
                if len(itemstr):
                    out += " " + itemstr

            rpc = self._rpc
            if rpc.type and getattr(self, "status", 0) != 0:
                # Display the status of the packet only if it is an error
                out += " %s" % self.status
            return out
        else:
            return BaseObj.__str__(self)
