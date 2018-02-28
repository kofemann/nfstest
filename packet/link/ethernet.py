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
ETHERNET module

Decode ethernet layer (RFC 894) Ethernet II.
"""
import nfstest_config as c
from baseobj import BaseObj
from macaddr import MacAddr
from ethernet_const import *
from packet.internet.ipv4 import IPv4
from packet.internet.ipv6 import IPv6
from packet.link.vlan import vlan_layers
from packet.internet.arp import ARP,RARP

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.3"

class ETHERNET(BaseObj):
    """Ethernet object

       Usage:
           from packet.link.ethernet import ETHERNET

           x = ETHERNET(pktt)

       Object definition:

       ETHERNET(
           dst   = MacAddr(),  # destination MAC address
           src   = MacAddr(),  # source MAC address
           type  = int,        # payload type
           data  = string,     # raw data of payload if type is not supported
       )
    """
    # Class attributes
    _attrlist = ("dst", "src", "type", "data")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        unpack = pktt.unpack
        ulist = unpack.unpack(14, "!6s6sH")
        self.dst  = MacAddr(ulist[0].encode('hex'))
        self.src  = MacAddr(ulist[1].encode('hex'))
        self.type = ulist[2]
        pktt.pkt.add_layer("ethernet", self)

        etype = self.type
        if etype == 0x8100:
            # Decode VLAN 802.1Q packet
            vlan_layers(pktt)
            if pktt.pkt.vlan:
                # VLAN has the etype for next layer
                etype = pktt.pkt.vlan.etype

        if etype == 0x0800:
            # Decode IPv4 packet
            IPv4(pktt)
        elif etype == 0x86dd:
            # Decode IPv6 packet
            IPv6(pktt)
        elif etype == 0x0806:
            # Decode ARP packet
            ARP(pktt)
        elif etype == 0x8035:
            # Decode RARP packet
            RARP(pktt)
        elif pktt.pkt.vlan:
            # Add rest of the data to the VLAN layer
            pktt.pkt.vlan.data = unpack.getbytes()
        else:
            self.data = unpack.getbytes()

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed:
               '00:0c:29:54:09:ef -> 60:33:4b:29:6e:9d '

           If set to 2 the representation of the object also includes the type
           of payload:
               '00:0c:29:54:09:ef -> 60:33:4b:29:6e:9d, type: 0x800(IPv4)'
        """
        rdebug = self.debug_repr()
        if rdebug == 1:
            out = "%s -> %s " % (self.src, self.dst)
            if self._pkt.get_layers()[-1] == "ethernet":
                etype = ETHERTYPES.get(self.type)
                etype = "" if etype is None else "(%s)" % etype
                out += " ETHERNET  type: 0x%04x%s" % (self.type, etype)
        elif rdebug == 2:
            etype = ETHERTYPES.get(self.type)
            etype = "" if etype is None else "(%s)" % etype
            out = "%s -> %s, type: 0x%04x%s" % (self.src, self.dst, self.type, etype)
        else:
            out = BaseObj.__str__(self)
        return out
