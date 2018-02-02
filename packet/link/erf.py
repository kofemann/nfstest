#===============================================================================
# Copyright 2017 NetApp, Inc. All Rights Reserved,
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
ERF module

Decode Extensible Record Format layer
Reference: ERF Types Reference Guide, EDM11-01 - Version 21
"""
import time
import nfstest_config as c
from baseobj import BaseObj

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2017 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

# ERF types
ERF_type = {
    21: "InfiniBand",
}

class ERF_TS(long):
    """ERF Time Stamp"""
    def __str__(self):
        sec = (self >> 32)
        usec = int(round(1000000*float(self&0xFFFFFFFF)/0x100000000))
        if usec >= 1000000:
            usec -= 1000000
            sec += 1
        return "%s.%06d" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sec)), usec)

class ERF(BaseObj):
    """Extensible record format object

       Usage:
           from packet.link.erf import ERF

           x = ERF(pktt)

       Object definition:

       ERF(
           timestamp = int64,  # The time of arrival, an ERF 64-bit timestamp
           rtype     = int,    # ERF type
           flags     = int,    # ERF flags
           rlen      = int,    # Record length
           lctr      = int,    # Loss counter/color field
           wlen      = int,    # Wire length
       )
    """
    # Class attributes
    _attrlist = ("timestamp", "rtype", "flags", "rlen", "lctr", "wlen")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        unpack = pktt.unpack
        self.timestamp = ERF_TS(unpack.unpack(8, "<Q")[0]) # Little-endian timestamp
        ulist = unpack.unpack(8, "!2B3H")
        self.rtype = ulist[0] & 0x7F
        self.flags = ulist[1]
        self.rlen  = ulist[2]
        self.lctr  = ulist[3]
        self.wlen  = ulist[4]

        # Do not decode the extension headers just consume the bytes
        while (ulist[0] >> 7) and len(unpack) > 0:
            if len(unpack) >= 8:
                ulist = unpack.unpack(8, "!B7s")
            else:
                unpack.read(8)
                break

        pktt.pkt.erf = self

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed:
               'rtype=21 rlen=312 wlen=290 '

           If set to 2 the representation of the object also includes the type
           of payload:
               'rtype: 21(InfiniBand), rlen: 312, wlen: 290 '
        """
        rdebug = self.debug_repr()
        if rdebug == 1:
            out = "rtype=%s rlen=%d wlen=%d " % (self.rtype, self.rlen, self.wlen)
        elif rdebug == 2:
            rtype = ERF_type.get(self.rtype, None)
            rtype = self.rtype if rtype is None else "%s(%s)" % (self.rtype, rtype)
            out = "rtype: %s, rlen: %d, wlen: %d" % (rtype, self.rlen, self.wlen)
        else:
            out = BaseObj.__str__(self)
        return out
