#===============================================================================
# Copyright 2012 NetApp, Inc. All Rights Reserved,
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
Unpack module

Provides the object for managing and unpacking raw data from a working buffer.
"""
import struct
import nfstest_config as c

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "2.4"

# Module variables
UNPACK_ERROR = False  # Raise unpack error when True

class Unpack(object):
    """Unpack object

       Usage:
           from packet.unpack import Unpack

           x = Unpack(buffer)

           # Get 32 bytes from the working buffer and move the offset pointer
           data = x.read(32)

           # Get all the unprocessed bytes from the working buffer
           # (all bytes starting from the offset pointer)
           # Do not move the offset pointer
           data = x.getbytes()

           # Get all bytes from the working buffer from the given offset
           # Do not move the offset pointer
           data = x.getbytes(offset)

           # Return the number of unprocessed bytes left in the working buffer
           size = x.size()
           size = len(x)

           # Get the offset pointer
           offset = x.tell()

           # Set the offset pointer
           x.seek(offset)

           # Append the given data to the working buffer
           x.append(data)

           # Insert the given data to the working buffer right before the
           # offset pointer. This resets the working buffer completely
           # and the offset pointer is initialized to zero. It is like
           # re-instantiating the object like:
           #   x = Unpack(data + x.getbytes())
           x.insert(data)

           # Save state
           sid = x.save_state()

           # Restore state
           x.restore_state(sid)

           # Unpack an 'unsigned short' (2 bytes in network order)
           short_int = x.unpack(2, '!H')[0]

           # Unpack different basic types
           char      = x.unpack_char()
           uchar     = x.unpack_uchar()
           short     = x.unpack_short()
           ushort    = x.unpack_ushort()
           int       = x.unpack_int()
           uint      = x.unpack_uint()
           int64     = x.unpack_int64()
           uint64    = x.unpack_uint64()
           data1     = x.unpack_opaque()
           data2     = x.unpack_opaque(64)  # Length of opaque must be <= 64
           data3     = x.unpack_fopaque(32)

           # Get string where length is given as an unsigned integer
           buffer = x.unpack_string()
           # Get string of fixed length
           buffer = x.unpack_string(32)
           # Get string where length is given as a short integer
           buffer = x.unpack_string(Unpack.unpack_short)
           buffer = x.unpack_string(ltype=Unpack.unpack_short)
           # Get string padded to a 4 byte boundary, discard padding bytes
           buffer = x.unpack_string(pad=4)

           # Get an array of unsigned integers
           alist = x.unpack_array()
           # Get a fixed length array of unsigned integers
           alist = x.unpack_array(ltype=10)
           # Get an array of short integers
           alist = x.unpack_array(Unpack.unpack_short)
           # Get an array of strings, the length of the array is given
           # by a short integer
           alist = x.unpack_array(Unpack.unpack_string, Unpack.unpack_short)
           # Get an array of strings, the length of each string is given by
           # a short integer and each string is padded to a 4 byte boundary
           alist = x.unpack_array(Unpack.unpack_string, uargs={'ltype':Unpack.unpack_short, 'pad':4})
           # Get an array of objects decoded by item_obj where the first
           # argument to item_obj is the unpack object, e.g., item = item_obj(x)
           alist = x.unpack_array(item_obj)

           # Get a list of unsigned integers
           alist = x.unpack_list()
           # Get a list of short integers
           alist = x.unpack_list(Unpack.unpack_short)
           # Get a list of strings, the next item flag is given
           # by a short integer
           alist = x.unpack_list(Unpack.unpack_string, Unpack.unpack_short)
           # Get a list of strings, the length of each string is given by
           # a short integer and each string is padded to a 4 byte boundary
           alist = x.unpack_list(Unpack.unpack_string, uargs={'ltype':Unpack.unpack_short, 'pad':4})

           # Unpack a conditional, it unpacks a conditional flag first and
           # if it is true it unpacks the item given and returns it. If the
           # conditional flag decoded is false, the method returns None
           buffer = x.unpack_conditional(Unpack.unpack_opaque)

           # Unpack an array of unsigned integers and convert array into
           # a single long integer
           bitmask = unpack_bitmap()
    """
    def __init__(self, data):
        """Constructor

           Initialize object's private data.

           data:
               Raw packet data
        """
        self._offset = 0
        self._data = data
        self._state = []

    def _get_ltype(self, ltype):
        """Get length of element"""
        if isinstance(ltype, int):
            # An integer is given, just return it
            return ltype
        else:
            # A function is given, return output of function
            return ltype(self)

    def size(self):
        """Return the number of unprocessed bytes left in the working buffer"""
        return len(self._data) - self._offset
    __len__ = size

    def tell(self):
        """Get the offset pointer."""
        return self._offset

    def seek(self, offset):
        """Set the offset pointer."""
        slen = len(self._data)
        if offset > slen:
            offset = slen
        self._offset = offset

    def append(self, data):
        """Append data to the working buffer."""
        self._data += data

    def insert(self, data):
        """Insert data to the beginning of the current working buffer."""
        if len(self._state):
            # Save working buffer in the saved state since the buffer
            # will be overwritten
            state = self._state[-1]
            if len(state) == 2:
                state.append(self._data)
        self._data = data + self._data[self._offset:]
        self._offset = 0

    def save_state(self):
        """Save state and return the state id"""
        sid = len(self._state)
        self._state.append([sid, self._offset])
        return sid

    def restore_state(self, sid):
        """Restore state given by the state id"""
        max = len(self._state)
        while sid < len(self._state):
            state = self._state.pop()
            self._offset = state[1]
            if len(state) == 3:
                self._data = state[2]

    def getbytes(self, offset=None):
        """Get the number of bytes given from the working buffer.
           Do not move the offset pointer.

           offset:
               Starting offset of data to return [default: current offset]
        """
        if offset is None:
            return self._data[self._offset:]
        return self._data[offset:]

    def read(self, size, pad=0):
        """Get the number of bytes given from the working buffer.
           Move the offset pointer.

           size:
               Length of data to get
           pad:
               Get and discard padding bytes [default: 0]
               If given, data is padded to this byte boundary
        """
        buf = self._data[self._offset:self._offset+size]
        if pad > 0:
            # Discard padding bytes
            size += (size+pad-1)/pad*pad - size
        self._offset += size
        dlen = len(self._data)
        if self._offset > dlen:
            self._offset = dlen
        return buf

    def unpack(self, size, fmt):
        """Get the number of bytes given from the working buffer and process
           it according to the given format.
           Return a tuple of unpack items, see struct.unpack.

           size:
               Length of data to process
           fmt:
               Format string on how to process data
        """
        return struct.unpack(fmt, self.read(size))

    def unpack_char(self):
        """Get a signed char"""
        return self.unpack(1, '!b')[0]

    def unpack_uchar(self):
        """Get an unsigned char"""
        return self.unpack(1, '!B')[0]

    def unpack_short(self):
        """Get a signed short integer"""
        return self.unpack(2, '!h')[0]

    def unpack_ushort(self):
        """Get an unsigned short integer"""
        return self.unpack(2, '!H')[0]

    def unpack_int(self):
        """Get a signed integer"""
        return self.unpack(4, '!i')[0]

    def unpack_uint(self):
        """Get an unsigned integer"""
        return self.unpack(4, '!I')[0]

    def unpack_int64(self):
        """Get a signed 64 bit integer"""
        return self.unpack(8, '!q')[0]

    def unpack_uint64(self):
        """Get an unsigned 64 bit integer"""
        return self.unpack(8, '!Q')[0]

    def unpack_opaque(self, maxcount=0):
        """Get a variable length opaque up to a maximum length of maxcount"""
        size = self.unpack_uint()
        if maxcount > 0 and size > maxcount:
            raise Exception, "Opaque exceeds maximum length"
        return self.read(size, pad=4)

    def unpack_fopaque(self, size):
        """Get a fixed length opaque"""
        return self.read(size, pad=4)

    def unpack_string(self, ltype=unpack_uint, pad=0, maxcount=0):
        """Get a variable length string

           ltype:
               Function to decode length of string [default: unpack_uint]
               Could also be given as an integer to have a fixed length string
           pad:
               Get and discard padding bytes [default: 0]
               If given, string is padded to this byte boundary
           maxcount:
               Maximum length of string [default: any length]
        """
        slen = self._get_ltype(ltype)
        if maxcount > 0 and slen > maxcount:
            raise Exception, "String exceeds maximum length"
        return self.read(slen, pad)

    def unpack_array(self, unpack_item=unpack_uint, ltype=unpack_uint, uargs={}, maxcount=0, islist=False):
        """Get a variable length array, the type of objects in the array
           is given by the unpacking function unpack_item and the type
           to decode the length of the array is given by ltype

           unpack_item:
               Unpack function for each item in the array [default: unpack_uint]
           ltype:
               Function to decode length of array [default: unpack_uint]
               Could also be given as an integer to have a fixed length array
           uargs:
               Named arguments to pass to unpack_item function [default: {}]
           maxcount:
               Maximum length of array [default: any length]
        """
        ret = []
        # Get length of array
        slen = self._get_ltype(ltype)
        if maxcount > 0 and slen > maxcount:
            raise Exception, "Array exceeds maximum length"
        while slen > 0:
            try:
                # Unpack each item in the array
                ret.append(unpack_item(self, **uargs))
                if islist:
                    slen = self._get_ltype(ltype)
                else:
                    slen -= 1
            except:
                if UNPACK_ERROR:
                    raise
                break
        return ret

    def unpack_list(self, *kwts, **kwds):
        """Get an indeterminate size list, the type of objects in the list
           is given by the unpacking function unpack_item and the type
           to decode the next item flag is given by ltype

           unpack_item:
               Unpack function for each item in the list [default: unpack_uint]
           ltype:
               Function to decode the next item flag [default: unpack_uint]
           uargs:
               Named arguments to pass to unpack_item function [default: {}]
        """
        kwds['islist'] = True
        return self.unpack_array(*kwts, **kwds)

    def unpack_conditional(self, unpack_item=unpack_uint, ltype=unpack_uint, uargs={}):
        """Get an item if condition flag given by ltype is true, if condition
           flag is false then return None

           unpack_item:
               Unpack function for item if condition is true [default: unpack_uint]
           ltype:
               Function to decode the condition flag [default: unpack_uint]
           uargs:
               Named arguments to pass to unpack_item function [default: {}]
        """
        # Get condition flag
        if self._get_ltype(ltype):
            # Unpack item if condition is true
            return unpack_item(self, **uargs)
        return None

    def unpack_bitmap(self):
        """Unpack an array of unsigned integers and convert array into
           a single long integer
        """
        bitmask = 0
        nshift = 0
        # Unpack array of uint32
        blist = self.unpack_array()
        for bint in blist:
            bitmask += bint << nshift
            nshift += 32
        return bitmask
