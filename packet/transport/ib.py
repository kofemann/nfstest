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
InfiniBand module

Decode InfiniBand layer.
Reference: IB Specification Vol 1-Release-1.3-2015-03-03.pdf
"""
import nfstest_config as c
from packet.utils import *
from baseobj import BaseObj
from packet.unpack import Unpack
from packet.application.rpc import RPC
from packet.internet.ipv6addr import IPv6Addr
from packet.application.rpcordma import RPCoRDMA
import packet.application.rpcordma_const as rdma

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2017 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

# Operation Code Transport Services (3 most significant bits)
ib_transport_services = {
    0b00000000 : "RC",  # Reliable Connection
    0b00100000 : "UC",  # Unreliable Connection
    0b01000000 : "RD",  # Reliable Datagram
    0b01100000 : "UD",  # Unreliable Datagram
    0b10000000 : "CNP", # Congestion Notification Packet
    0b10100000 : "XRC", # Extended Reliable Connection
}

# Create Operation Code type constants
for (key, value) in ib_transport_services.items():
    exec("%s = %d" % (value, key))

# Operation Code (5 least significant bits)
ib_op_codes = {
    0b00000 : "SEND_First",
    0b00001 : "SEND_Middle",
    0b00010 : "SEND_Last",
    0b00011 : "SEND_Last_Immediate",
    0b00100 : "SEND_Only",
    0b00101 : "SEND_Only_Immediate",
    0b00110 : "RDMA_WRITE_First",
    0b00111 : "RDMA_WRITE_Middle",
    0b01000 : "RDMA_WRITE_Last",
    0b01001 : "RDMA_WRITE_Last_Immediate",
    0b01010 : "RDMA_WRITE_Only",
    0b01011 : "RDMA_WRITE_Only_Immediate",
    0b01100 : "RDMA_READ_Request",
    0b01101 : "RDMA_READ_Response_First",
    0b01110 : "RDMA_READ_Response_Middle",
    0b01111 : "RDMA_READ_Response_Last",
    0b10000 : "RDMA_READ_Response_Only",
    0b10001 : "Acknowledge",
    0b10010 : "ATOMIC_Acknowledge",
    0b10011 : "CmpSwap",
    0b10100 : "FetchAdd",
    0b10101 : "RESYNC",
    0b10110 : "SEND_Last_Invalidate",
    0b10111 : "SEND_Only_Invalidate",
}

# Create Operation Code constants
for (key, value) in ib_op_codes.items():
    exec("%s = %d" % (value, key))

class OpCode(int):
    """OpCode object, this is an integer in which its informal
       string representation is given as the OpCode name
    """
    def __str__(self):
        group = ib_transport_services.get(self & 0b11100000)
        if group is not None:
            code  = ib_op_codes.get(self & 0b00011111)
            if code is not None:
                return group + "_" + code
        return super(OpCode, self).__str__()

class LRH(BaseObj):
    """LOCAL ROUTE HEADER (LRH) - 8 BYTES

       The Local Routing Header contains fields used for local routing
       by switches within a IBA subnet.

       LRH(
           vl   = int, # Virtual Lane that the packet is using
           lver = int, # Link Version of LRH
           sl   = int, # Service Level the packet is requesting within the subnet
           lnh  = int, # Link Next Header identifies the headers following the LRH
           dlid = int, # Destination Local ID identifies the destination port
                       # and path (data sink) on the local subnet
           plen = int, # Packet Length identifies the size of the packet in
                       # four-byte words. This field includes the first byte of
                       # LRH to the last byte before the variant CRC
           slid = int, # Source Local ID identifies the source port
                       # (injection point) on the local subnet
       )
    """
    # Class attributes
    _attrlist = ("vl", "lver", "sl", "lnh", "dlid", "plen", "slid")
    _strfmt1 = "LID:{6:<5d} -> LID:{4:<6d}"
    _strfmt2 = "LID:{6} -> LID:{4}"

    def __init__(self, unpack):
        offset = unpack.tell()
        ulist  = unpack.unpack(8, "!4H")
        self.vl   = (ulist[0] >> 12)
        self.lver = (ulist[0] >> 8) & 0x0F
        self.sl   = (ulist[0] >> 4) & 0x0F
        self.lnh  = ulist[0] & 0x03
        self.dlid = ulist[1]
        self.plen = ulist[2] & 0x07FF
        self.slid = ulist[3]

        # Calculate where the Variant CRC starts
        self._vcrc_offset = offset + 4*self.plen

class GRH(BaseObj):
    """GLOBAL ROUTE HEADER (GRH) - 40 BYTES

       Global Route Header contains fields for routing the packet between
       subnets. The presence of the GRH is indicated by the Link Next
       Header (LNH) field in the LRH. The layout of the GRH is the same as
       the IPv6 Header defined in RFC 2460. Note, however, that IBA does not
       define a relationship between a device GID and IPv6 address
       (i.e., there is no defined mapping between GID and IPv6 address for
       any IB device or port).

       GRH(
           ipver  = int,      # IP Version indicates version of the GRH
           tclass = int,      # Traffic Class is used by IBA to communicate
                              # global service level
           flabel = int,      # Flow Label identifies sequences of packets
                              # requiring special handling
           paylen = int,      # Payload length specifies the number of bytes
                              # starting from the first byte after the GRH,
                              # up to and including the last byte of the ICRC
           nxthdr = int,      # Next Header identifies the header following the
                              # GRH. This field is included for compatibility with
                              # IPV6 headers. It should indicate IBA transport
           hoplmt = int,      # Hop Limit sets a strict bound on the number of
                              # hops between subnets a packet can make before
                              # being discarded. This is enforced only by routers
           sgid   = IPv6Addr, # Source GID identifies the Global Identifier
                              # (GID) for the port which injected the packet
                              # into the network
           dgid   = IPv6Addr, # Destination GID identifies the GID for the port
                              # which will consume the packet from the network
       )
    """
    # Class attributes
    _attrlist = ("ipver", "tclass", "flabel", "paylen", "nxthdr", "hoplmt",
                 "sgid", "dgid")
    _strfmt1 = "{6} -> {7}"
    _strfmt2 = _strfmt1

    def __init__(self, unpack):
        ulist  = unpack.unpack(40, "!IHBB16s16s")
        self.ipver  = (ulist[0] >> 28)
        self.tclass = (ulist[0] >> 20) & 0x0FF
        self.flabel = ulist[0] & 0x0FFFFF
        self.paylen = ulist[1]
        self.nxthdr = ulist[2]
        self.hoplmt = ulist[3]
        self.sgid   = IPv6Addr(ulist[4].encode('hex'))
        self.dgid   = IPv6Addr(ulist[5].encode('hex'))

        # Calculate where the Invariant CRC starts
        self._icrc_offset = unpack.tell() + self.paylen - 4

class BTH(BaseObj):
    """BASE TRANSPORT HEADER (BTH) - 12 BYTES

       Base Transport Header contains the fields for IBA transports.
       The presence of BTH is indicated by the Next Header field of
       the last previous header (i.e., either LRH:lnh or GRH:nxthdr
       depending on which was the last previous header).

       BTH(
           opcode = int, # OpCode indicates the IBA packet type. It also
                         # specifies which extension headers follow the BTH
           se     = int, # Solicited Event, this bit indicates that an event
                         # should be generated by the responder
           migreq = int, # This bit is used to communicate migration state
           padcnt = int, # Pad Count indicates how many extra bytes are added
                         # to the payload to align to a 4 byte boundary
           tver   = int, # Transport Header Version indicates the version of
                         # the IBA Transport Headers
           pkey   = int, # Partition Key indicates which logical Partition is
                         # associated with this packet
           destqp = int, # Destination QP indicates the Work Queue Pair Number
                         # (QP) at the destination
           ackreq = int, # Acknowledge Request, this bit is used to indicate
                         # that an acknowledge (for this packet) should be
                         # scheduled by the responder
           psn    = int, # Packet Sequence Number is used to detect a missing
                         # or duplicate Packet
       )
    """
    # Class attributes
    _attrlist = ("opcode", "se", "migreq", "padcnt", "tver",
                 "pkey", "destqp", "ackreq", "psn")
    _strfmt1 = "{0} QP={6} PSN={8}"
    _strfmt2  = "{0}, Pkey: {5}, QP: {6}, PSN: {8}"

    def __init__(self, unpack):
        ulist = unpack.unpack(12, "!2BH2I")
        self.opcode = OpCode(ulist[0])
        self.se     = (ulist[1] >> 7) & 0x01
        self.migreq = (ulist[1] >> 6) & 0x01
        self.padcnt = (ulist[1] >> 4) & 0x03
        self.tver   = ulist[1] & 0x0f
        self.pkey   = ShortHex(ulist[2])
        self.destqp = ShortHex(ulist[3] & 0x00ffffff)
        self.ackreq = (ulist[4] >> 31) & 0x01
        self.psn    = ulist[4] & 0x00ffffff

# Extended Transport Headers -- Start
class RDETH(BaseObj):
    """RELIABLE DATAGRAM EXTENDED TRANSPORT HEADER (RDETH) - 4 BYTES

       Reliable Datagram Extended Transport Header contains the additional
       transport fields for reliable datagram service. The RDETH is only
       in Reliable Datagram packets as indicated by the Base Transport Header
       OpCode field.

       RDETH(
           ee_context = int, # EE-Context indicates which End-to-End Context
                             # should be used for this Reliable Datagram packet
       )
    """
    def __init__(self, unpack):
        # End-to-End Context identifier
        self.ee_context = unpack.unpack(4, "!I")[0] & 0x00ffffff

class DETH(BaseObj):
    """DATAGRAM EXTENDED TRANSPORT HEADER (DETH) - 8 BYTES

       Datagram Extended Transport Header contains the additional transport
       fields for datagram service. The DETH is only in datagram packets if
       indicated by the Base Transport Header OpCode field.

       DETH(
           q_key  = int, # Queue Key is required to authorize access to the
                         # receive queue
           src_qp = int, # Source QP indicates the Work Queue Pair Number (QP)
                         # at the source.
       )
    """
    # Class attributes
    _attrlist = ("q_key", "src_qp")

    def __init__(self, unpack):
        ulist = unpack.unpack(8, "!2I")
        self.q_key = ulist[0]
        self.src_qp    = ulist[1] & 0x00ffffff

class XRCETH(BaseObj):
    """XRC EXTENDED TRANSPORT HEADER (XRCETH)

       XRC Extended Transport Header contains the Destination XRC SRQ
       identifier.
       XRCETH(
           xrcsrq = int, # XRC Shared Receive Queue indicates the XRC Shared
                         # Receive Queue number to be used by the responder
                         # for this packet
       )
    """
    def __init__(self, unpack):
        self.xrcsrq = unpack.unpack(4, "!I")[0] & 0x00ffffff

class RETH(BaseObj):
    """RDMA EXTENDED TRANSPORT HEADER (RETH) - 16 BYTES

       RDMA Extended Transport Header contains the additional transport fields
       for RDMA operations. The RETH is present in only the first (or only)
       packet of an RDMA Request as indicated by the Base Transport Header
       OpCode field.

       RETH(
           va      = int, # Virtual Address of the RDMA operation
           r_key   = int, # Remote Key that authorizes access for the RDMA
                          # operation
           dma_len = int, # DMA Length indicates the length (in Bytes) of
                          # the DMA operation.
       )
    """
    # Class attributes
    _attrlist = ("va", "r_key", "dma_len")
    _strfmt1  = "dma_len: {2}"

    def __init__(self, unpack):
        ulist = unpack.unpack(16, "!Q2I")
        self.va      = ulist[0]
        self.r_key   = IntHex(ulist[1])
        self.dma_len = ulist[2]

class AtomicETH(BaseObj):
    """ATOMIC EXTENDED TRANSPORT HEADER (ATOMICETH) - 28 BYTES

       Atomic Extended Transport Header contains the additional transport
       fields for Atomic packets. The AtomicETH is only in Atomic packets
       as indicated by the Base Transport Header OpCode field.

       AtomicETH(
           va      = int, # Virtual Address: the remote virtual address
           r_key   = int, # Remote Key that authorizes access to the remote
                          # virtual address
           swap_dt = int, # Swap/Add Data is an operand in atomic operations
           cmp_dt  = int, # Compare Data is an operand in CmpSwap atomic
                          # operation
       )
    """
    # Class attributes
    _attrlist = ("va", "r_key", "swap_dt", "cmp_dt")

    def __init__(self, unpack):
        ulist = unpack.unpack(28, "!QI2Q")
        self.va      = ulist[0]
        self.r_key   = IntHex(ulist[1])
        self.swap_dt = ulist[2]
        self.cmp_dt  = ulist[3]

class AETH(BaseObj):
    """ACK EXTENDED TRANSPORT HEADER (AETH) - 4 BYTES

       ACK Extended Transport Header contains the additional transport fields
       for ACK packets. The AETH is only in Acknowledge, RDMA READ Response
       First, RDMA READ Response Last, and RDMA READ Response Only packets
       as indicated by the Base Transport Header OpCode field.

       AETH(
           syndrome = int, # Syndrome indicates if this is an ACK or NAK
                           # packet plus additional information about the
                           # ACK or NAK
           msn      = int, # Message Sequence Number indicates the sequence
                           # number of the last message completed at the
                           # responder
       )
    """
    # Class attributes
    _attrlist = ("syndrome", "msn")

    def __init__(self, unpack):
        # End-to-End Context identifier
        data = unpack.unpack(4, "!I")[0]
        self.syndrome = data >> 24
        self.msn      = data & 0x00ffffff

class AtomicAckETH(BaseObj):
    """ATOMIC ACKNOWLEDGE EXTENDED TRANSPORT HEADER (ATOMICACKETH) - 8 BYTES

       Atomic ACK Extended Transport Header contains the additional transport
       fields for AtomicACK packets. The AtomicAckETH is only in Atomic
       Acknowledge packets as indicated by the Base Transport Header OpCode
       field.

       AtomicAckETH(
           orig_rem_dt = int, # Original Remote Data is the return operand
                              # in atomic operations and contains the data
                              # in the remote memory location before the
                              # atomic operation
       )
    """
    def __init__(self, unpack):
        self.orig_rem_dt = unpack.unpack(8, "!Q")[0]

class ImmDt(BaseObj):
    """IMMEDIATE DATA EXTENDED TRANSPORT HEADER (IMMDT) - 4 BYTES

       Immediate DataExtended Transport Header contains the additional data
       that is placed in the receive Completion Queue Element (CQE).
       The ImmDt is only in Send or RDMA-Write packets with Immediate Data
       if indicated by the Base Transport Header OpCode.

       Note, the terms Immediate Data Extended Transport Header and Immediate
       Data Header are used synonymously in the specification.

       ImmDt(
           imm_dt = int, # Immediate Data contains data that is placed in the
                         # receive Completion Queue Element (CQE). The ImmDt is
                         # only allowed in SEND or RDMA WRITE packets with
                         # Immediate Data
       )
    """
    def __init__(self, unpack):
        self.imm_dt = unpack.unpack(4, "!I")[0]

class IETH(BaseObj):
    """INVALIDATE EXTENDED TRANSPORT HEADER (IETH) - 4 BYTES

       The Invalidate Extended Transport Header contains an R_Key field which
       is used by the responder to invalidate a memory region or memory window
       once it receives and executes the SEND with Invalidate request.

       IETH(
           r_key = int, # The SEND with Invalidate operation carries with it
                        # an R_Key field. This R_Key is used by the responder
                        # to invalidate a memory region or memory window once
                        # it receives and executes the SEND with Invalidate
                        # request
       )
    """
    def __init__(self, unpack):
        self.r_key = IntHex(unpack.unpack(4, "!I")[0])
# Extended Transport Headers -- End

# Extended Transport Headers Map table (IB: Table 38)
# The OpCode defines the interpretation of the remaining header
# and payload bytes. The following table maps the OpCode with the
# list of headers expected after the BTH. The list of headers is
# given in the order in which they should follow the BTH.
# Only the OpCodes which have at least a header after the BTH are
# listed.
ETH_map = {
    # Reliable Connection (RC)
    RC+SEND_Last_Immediate        : (ImmDt,),
    RC+SEND_Only_Immediate        : (ImmDt,),
    RC+RDMA_WRITE_First           : (RETH,),
    RC+RDMA_WRITE_Last_Immediate  : (ImmDt,),
    RC+RDMA_WRITE_Only            : (RETH,),
    RC+RDMA_WRITE_Only_Immediate  : (RETH, ImmDt),
    RC+RDMA_READ_Request          : (RETH,),
    RC+RDMA_READ_Response_First   : (AETH,),
    RC+RDMA_READ_Response_Last    : (AETH,),
    RC+RDMA_READ_Response_Only    : (AETH,),
    RC+Acknowledge                : (AETH,),
    RC+ATOMIC_Acknowledge         : (AETH, AtomicAckETH),
    RC+CmpSwap                    : (AtomicETH,),
    RC+FetchAdd                   : (AtomicETH,),
    RC+SEND_Last_Invalidate       : (IETH,),
    RC+SEND_Only_Invalidate       : (IETH,),

    # Unreliable Connection "(UC)"
    UC+SEND_Last_Immediate        : (ImmDt,),
    UC+SEND_Only_Immediate        : (ImmDt,),
    UC+RDMA_WRITE_First           : (RETH,),
    UC+RDMA_WRITE_Last_Immediate  : (ImmDt,),
    UC+RDMA_WRITE_Only            : (RETH,),
    UC+RDMA_WRITE_Only_Immediate  : (RETH, ImmDt),

    # Reliable Datagram "(RD)"
    RD+SEND_First                 : (RDETH, DETH),
    RD+SEND_Middle                : (RDETH, DETH),
    RD+SEND_Last                  : (RDETH, DETH),
    RD+SEND_Last_Immediate        : (RDETH, DETH, ImmDt),
    RD+SEND_Only                  : (RDETH, DETH),
    RD+SEND_Only_Immediate        : (RDETH, DETH, ImmDt),
    RD+RDMA_WRITE_First           : (RDETH, DETH, RETH),
    RD+RDMA_WRITE_Middle          : (RDETH, DETH),
    RD+RDMA_WRITE_Last            : (RDETH, DETH),
    RD+RDMA_WRITE_Last_Immediate  : (RDETH, DETH, ImmDt),
    RD+RDMA_WRITE_Only            : (RDETH, DETH, RETH),
    RD+RDMA_WRITE_Only_Immediate  : (RDETH, DETH, RETH, ImmDt),
    RD+RDMA_READ_Request          : (RDETH, DETH, RETH),
    RD+RDMA_READ_Response_First   : (RDETH, AETH),
    RD+RDMA_READ_Response_Middle  : (RDETH,),
    RD+RDMA_READ_Response_Last    : (RDETH, AETH),
    RD+RDMA_READ_Response_Only    : (RDETH, AETH),
    RD+Acknowledge                : (RDETH, AETH),
    RD+ATOMIC_Acknowledge         : (RDETH, AETH, AtomicAckETH),
    RD+CmpSwap                    : (RDETH, DETH, AtomicETH),
    RD+FetchAdd                   : (RDETH, DETH, AtomicETH),
    RD+RESYNC                     : (RDETH, DETH),

    # Unreliable Datagram "(UD)"
    UD+SEND_Only                  : (DETH,),
    UD+SEND_Only_Immediate        : (DETH, ImmDt),

    # Extended Reliable Connection "(XRC)"
    XRC+SEND_First                : (XRCETH,),
    XRC+SEND_Middle               : (XRCETH,),
    XRC+SEND_Last                 : (XRCETH,),
    XRC+SEND_Last_Immediate       : (XRCETH, ImmDt),
    XRC+SEND_Only                 : (XRCETH,),
    XRC+SEND_Only_Immediate       : (XRCETH, ImmDt),
    XRC+RDMA_WRITE_First          : (XRCETH, RETH),
    XRC+RDMA_WRITE_Middle         : (XRCETH,),
    XRC+RDMA_WRITE_Last           : (XRCETH,),
    XRC+RDMA_WRITE_Last_Immediate : (XRCETH, ImmDt),
    XRC+RDMA_WRITE_Only           : (XRCETH, RETH),
    XRC+RDMA_WRITE_Only_Immediate : (XRCETH, RETH, ImmDt),
    XRC+RDMA_READ_Request         : (XRCETH, RETH),
    XRC+RDMA_READ_Response_First  : (AETH,),
    XRC+RDMA_READ_Response_Last   : (AETH,),
    XRC+RDMA_READ_Response_Only   : (AETH,),
    XRC+Acknowledge               : (AETH,),
    XRC+ATOMIC_Acknowledge        : (AETH, AtomicAckETH),
    XRC+CmpSwap                   : (XRCETH, AtomicETH),
    XRC+FetchAdd                  : (XRCETH, AtomicETH),
    XRC+SEND_Last_Invalidate      : (XRCETH, IETH),
    XRC+SEND_Only_Invalidate      : (XRCETH, IETH),
}

class RDMAseg(object):
    """RDMA sub-segment object

       The sub-segment is created for each RDMA_WRITE_First, RDMA_WRITE_Only
       or RDMA_READ_Request and each sub-segment belongs to a list in the
       RDMAsegment object so there is no segment identifier or handle.

       Reassembly for each sub-segment is done using the PSN or packet
       sequence number in each of the data fragments. Therefore, a range
       of PSN numbers define this object which is given by the spsn and
       epsn attributes (first and last PSN respectively).
    """
    def __init__(self, spsn, epsn, dmalen):
        self.spsn     = spsn   # First PSN in sub-segment
        self.epsn     = epsn   # Last PSN in sub-segment
        self.dmalen   = dmalen # DMA length in sub-segment
        self.fraglist = []     # List of data fragments

    def insert_data(self, psn, data):
        """Insert data at correct position given by the psn"""
        # Make sure fragment belongs to this sub-segment
        if psn >= self.spsn and psn <= self.epsn:
            # Normalize psn with respect to first PSN
            index = psn - self.spsn
            fraglist = self.fraglist
            nlen = len(fraglist)
            if index < nlen:
                # This is an out-of-order fragment,
                # replace fragment data at index
                fraglist[index] = data
            else:
                # Some fragments may be missing
                for i in xrange(index - nlen):
                    # Use an empty string for missing fragments
                    # These may come later as out-of-order fragments
                    fraglist.append("")
                fraglist.append(data)
            return True
        return False

    def get_data(self, padding=True):
        """Return sub-segment data"""
        data = ""
        # Get data from all fragments
        for fragdata in self.fraglist:
            data += fragdata
        if not padding and len(data) > self.dmalen:
            return data[:self.dmalen-len(data)]
        return data

    def get_size(self):
        """Return sub-segment data size"""
        size = 0
        # Get the size from all fragments
        for fragdata in self.fraglist:
            size += len(fragdata)
        return size

class RDMAsegment(object):
    """RDMA segment object

       Each segment is identified by its handle. The segment information
       comes from the RPC-over-RDMA protocol layer so the length attribute
       gives the total DMA length of the segment.
    """
    def __init__(self, handle, length, xdrpos, rpcrdma):
        self.handle  = handle
        self.length  = length
        self.xdrpos  = xdrpos  # RDMA read chunk XDR position
        self.rpcrdma = rpcrdma # RPC-over-RDMA object used for RDMA reads

        # List of sub-segments (RDMAseg)
        # When the RDMA segment's length (DMA length) is large it could be
        # broken into multiple sub-segments. This is accomplished by sending
        # multiple Write First (or Read Request) packets where the RETH
        # specifies the same RKey(or handle) for all sub-segments and the
        # DMA length for the sub-segment.
        self.seglist = []

    def valid_psn(self, psn):
        """True if given psn is valid for this segment"""
        # Search all sub-segments
        for seg in self.seglist:
            if psn >= seg.spsn and psn <= seg.epsn:
                # Correct sub-segment found
                return True
        return False

    def add_sub_segment(self, psn, dmalen, only=False, iosize=0):
        """Add RDMA sub-segment PSN information"""
        seg = None
        # Find if sub-segment already exists
        for item in self.seglist:
            if psn == item.spsn:
                seg = item
                break
        if seg:
            # Sub-segment already exists, just update epsn
            if only:
                seg.epsn = psn
            else:
                dmalen = seg.dmalen
                seg.epsn = psn + dmalen/iosize - 1 + (1 if dmalen%iosize else 0)
        else:
            # Sub-segment does not exist, add it to the list
            if only:
                # Only one fragment thus epsn == spsn
                epsn = psn
            else:
                # Multiple fragments, calculate epsn if iosize is nonzero
                if iosize == 0:
                    # The iosize is not known for a Read Request which gives all
                    # information for the segment but does not have any data,
                    # thus the iosize is zero. The epsn will be updated in the
                    # RDMA Read First for this case.
                    # The last PSN is not known so set it to spsn so at
                    # least this PSN is valid for the sub-segment
                    epsn = psn
                else:
                    epsn = psn + dmalen/iosize - 1 + (1 if dmalen%iosize else 0)
            seg = RDMAseg(psn, epsn, dmalen)
            self.seglist.append(seg)
        return seg

    def add_data(self, psn, data):
        """Add fragment data"""
        # Search for correct sub-segment
        for seg in self.seglist:
            if seg.insert_data(psn, data):
                # The insert_data method returns True on correct
                # sub-segment for given psn
                return

    def get_data(self, padding=True):
        """Return segment data"""
        data = ""
        # Get data from all sub-segments
        for seg in self.seglist:
            data += seg.get_data(padding)
        return data

    def get_size(self):
        """Return segment data"""
        size = 0
        # Get the size from all sub-segments
        for seg in self.seglist:
            size += seg.get_size()
        return size

class RDMAinfo(object):
    """RDMA info object used for reassembly

       The reassembled message consists of one or multiple chunks and
       each chunk in turn could be composed of multiple segments. Also,
       each segment could be composed of multiple sub-segments and each
       sub-segment could be composed of multiple fragments.
       The protocol only defines segments but if the segment length is
       large, it is split into multiple sub-segments in which each
       sub-segment is specified by RDMA_WRITE_First or RDMA_READ_Request
       packets. The handle is the same for each of these packets but with
       a shorter DMA length.

       Thus in order to reassemble all fragments for a single message,
       a list of segments is created where each segment is identified
       by its handle or RKey and the message is reassembled according
       to the chuck lists specified by the RPC-over-RDMA layer.
    """
    def __init__(self):
        # RDMA Reads/Writes/Reply segments {key: handle, value: RDMAsegment}
        self._rdma_segments = {}

    def get_rdma_segment(self, handle):
        """Return RDMA segment identified by the given handle"""
        return self._rdma_segments.get(handle)

    def add_rdma_segment(self, handle, length, xdrpos=0, rpcrdma=None):
        """Add RDMA segment information and if the information already
           exists just update the length and return the segment
        """
        rsegment = self._rdma_segments.get(handle)
        if rsegment:
            # Update segment's length and return the segment
            rsegment.length = length
        else:
            # Add segment information
            self._rdma_segments[handle] = RDMAsegment(handle, length, xdrpos, rpcrdma)
        return rsegment

    def add_rdma_data(self, psn, unpack, reth=None, only=False, read=False):
        """Add RDMA fragment data"""
        if reth:
            # The RETH object header is given which is the case for an OpCode
            # like *Only or *First, use the RETH RKey(or handle) to get the
            # correct segment where this fragment should be inserted
            rsegment = self.get_rdma_segment(reth.r_key)
            if rsegment:
                size = len(unpack)
                seg = rsegment.add_sub_segment(psn, reth.dma_len, only=only, iosize=size)
                if size > 0:
                    seg.insert_data(psn, unpack.read(size))
            return rsegment
        else:
            # The RETH object header is not given, find the correct segment
            # where this fragment should be inserted
            for rsegment in self._rdma_segments.itervalues():
                if rsegment.valid_psn(psn):
                    size = len(unpack)
                    if read:
                        # Modify sub-segment for RDMA read (first or only)
                        # The sub-segment is added in the read request where
                        # RETH is given but the request does not have any
                        # data to correctly calculate the epsn
                        seg = rsegment.add_sub_segment(psn, 0, only=only, iosize=size)
                        seg.insert_data(psn, unpack.read(size))
                    else:
                        rsegment.add_data(psn, unpack.read(size))
                    return rsegment

    def reassemble_rdma_reads(self, psn, unpack):
        """Reassemble RDMA read chunks
           The RDMA read chunks are reassembled in the read last operation
        """
        # Payload data in the reduced message (e.g., two chunks)
        # where each chunk data is sent separately using RDMA:
        # +----------------+----------------+----------------+
        # |    xdrdata1    |    xdrdata2    |    xdrdata3    |
        # +----------------+----------------+----------------+
        #    chunk data1 --^  chunk data2 --^
        #
        # Reassembled message should look like the following in which
        # the xdrpos specifies where the chunk data must be inserted.
        # The xdrpos is relative to the reassembled message and NOT
        # relative to the reduced message:
        # +----------+-------------+----------+-------------+----------+
        # | xdrdata1 | chunk data1 | xdrdata2 | chunk data2 | xdrdata3 |
        # +----------+-------------+----------+-------------+----------+
        # xdrpos1 ---^              xdrpos2 --^

        # Add RDMA read fragment
        rsegment = self.add_rdma_data(psn, unpack)
        if rsegment is None:
            return

        # Get saved RPCoRDMA object to know how to reassemble the RDMA
        # read chunks and the data sent on the RDMA_MSG which has the
        # reduced message data
        rpcrdma = rsegment.rpcrdma
        if rpcrdma:
            # Get reduced data
            reduced_data = rpcrdma.data
            read_chunks = {}
            # Check if all segments are done
            for seg in rpcrdma.reads:
                rsegment = self._rdma_segments.get(seg.handle)
                if rsegment is None or rsegment.get_size() < rsegment.length:
                    # Not all data has been accounted for this segment
                    return
                # The RPC-over-RDMA protocol does not have a read chunk
                # list but instead it has a list of segments so arrange
                # the segments into chunks by using the XDR position.
                slist = read_chunks.setdefault(rsegment.xdrpos, [])
                slist.append(rsegment)

            data = ""
            offset = 0  # Current offset of reduced message
            # Reassemble the whole message
            for xdrpos in sorted(read_chunks.keys()):
                # Check if there is data from the reduced message which
                # should be inserted before this chunk
                if xdrpos > len(data):
                    # Insert data from the reduced message
                    size = xdrpos - len(data)
                    data += reduced_data[offset:size]
                    offset = size
                # Add all data from chunk
                for rsegment in read_chunks[xdrpos]:
                    # Get the bytes for the segment including the padding
                    # bytes because this is part of the message that will
                    # be dissected and the opaque needs a 4-byte boundary
                    data += rsegment.get_data(padding=True)
            if len(reduced_data) > offset:
                # Add last fragment from the reduced message
                data += reduced_data[offset:]
            return data

    def process_rdma_segments(self, rpcrdma):
        """Process the RPC-over-RDMA chunks

           When this method is called on an RPC call, it adds the
           information of all the segments to the list of segments.
           When this method is called on an RPC reply, the segments
           should already exist so just update the segment's DMA length
           as returned by the reply.

           RPCoRDMA reads attribute is a list of read segments
           Read segment is a plain segment plus an XDR position
           A read chunk is the collection of all read segments
           with the same XDR position

           RPCoRDMA reply is just a single write chunk if it exists.
           Return the reply chunk data
        """
        # Reassembly is done on the last read response of the last segment.
        # Process the rdma list to set up the expected read chunks and
        # their respective segments.
        # - Used for a large RPC call which has at least one
        #   large opaque, e.g., NFS WRITE
        # - The RPC call packet is used only to set up the RDMA read
        #   chunk list. It also has the reduced message data which
        #   includes the first fragment (XDR data up to and including
        #   the opaque length), but it could also have fragments which
        #   belong between each read chunk, and possibly a fragment after
        #   the last read chunk data.
        # - The opaque data is transferred via RDMA reads, once all
        #   fragments are accounted for they are reassembled and the
        #   whole RPC call is dissected in the last read response, so
        #   there is no RPCoRDMA layer
        #
        # - Packet sent order, the reduced RPC call is sent first, then the
        #   RDMA reads, e.g., showing only for a single chunk:
        #   +----------------+-------------+-----------+-----------+-----+-----------+
        #   | WRITE call XDR | opaque size |  GETATTR  | RDMA read | ... | RDMA read |
        #   +----------------+-------------+-----------+-----------+-----+-----------+
        #   |<-------------- First frame ------------->|<-------- chunk data ------->|
        #   Each RDMA read could be a single RDMA_READ_Response_Only or a series of
        #   RDMA_READ_Response_First, RDMA_READ_Response_Middle, ...,
        #   RDMA_READ_Response_Last
        #
        # - NFS WRITE call, this is how it should be reassembled:
        #   +----------------+-------------+-----------+-----+-----------+-----------+
        #   | WRITE call XDR | opaque size | RDMA read | ... | RDMA read |  GETATTR  |
        #   +----------------+-------------+-----------+-----+-----------+-----------+
        #                                  |<--- opaque (chunk) data --->|
        if rpcrdma.reads:
            # Add all segments in the RDMA read chunk list
            for rdma_seg in rpcrdma.reads:
                self.add_rdma_segment(rdma_seg.handle, rdma_seg.length, rdma_seg.position, rpcrdma)

        # Reassembly is done on the reply message with proc=RDMA_NOMSG.
        # The RDMA list is processed on the call message to set up the
        # reply chunk and its respective segments expected by the reply
        # - The reply chunk is used for a large RPC reply which does not
        #   fit into a single SEND operation and does not have a single
        #   large opaque, e.g., NFS READDIR
        # - The RPC call packet is used only to set up the RDMA reply chunk
        # - The whole RPC reply is transferred via RDMA writes
        # - The RPC reply packet has no data (RDMA_NOMSG) but fragments are
        #   then reassembled and the whole RPC reply is dissected
        #
        # - Packet sent order, this is the whole XDR data for the RPC reply:
        #   +--------------------------+------------------+--------------------------+
        #   |        RDMA write        |       ...        |        RDMA write        |
        #   +--------------------------+------------------+--------------------------+
        #   Each RDMA write could be a single RDMA_WRITE_Only or a series of
        #   RDMA_WRITE_First, RDMA_WRITE_Middle, ..., RDMA_WRITE_Last
        replydata = ""
        if rpcrdma.reply:
            # Process all segments in the RDMA reply chunk
            for rdma_seg in rpcrdma.reply.target:
                rsegment = self.add_rdma_segment(rdma_seg.handle, rdma_seg.length)
                if rsegment:
                    # Get the bytes for the segment including the padding
                    # bytes because this is part of the message that will
                    # be dissected and the opaque needs a 4-byte boundary
                    replydata += rsegment.get_data(padding=True)
        return replydata

class IB(BaseObj):
    """InfiniBand (IB) object

       Usage:
           from packet.transport.ib import IB

           x = IB(pktt)

       Object definition:

       IB(
           lrh          = LRH,          # Local Route Header
           grh          = GRH,          # Global Route Header
           bth          = BTH,          # Base Transport Header
           rdeth        = RDETH,        # Reliable Datagram Extended Transport Header
           deth         = DETH,         # Datagram Extended Transport Header
           xrceth       = XRCETH,       # XRC Extended Transport Header
           reth         = RETH,         # RDMA Extended Transport Header
           atomiceth    = AtomicETH,    # Atomic Extended Transport Header
           aeth         = AETH,         # ACK Extended Transport Header
           atomicacketh = AtomicAckETH, # Atomic Acknowledge Extended Transport Header
           immdt        = ImmDt,        # Immediate Extended Transport Header
           ieth         = IETH,         # Invalidate Extended Transport Header
           icrc         = int,          # Invariant CRC
           vcrc         = int,          # Variant CRC
       )
    """
    # Class attributes
    _attrlist = ("lrh", "grh", "bth", "rdeth", "deth", "xrceth", "reth",
                 "atomiceth", "aeth", "atomicacketh", "immdt", "ieth",
                 "icrc", "vcrc")
    _fattrs   = ("bth",)
    _strname  = "IB" # Layer name (IB, RoCE or RRoCE) to display

    # The following is a class attribute which can be modified and shared
    # by all IB packets:
    _rdma_info = RDMAinfo()

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        self.lrh    = None
        self.grh    = None
        self._ib    = False  # This object is valid when True
        icrc_offset = None
        vcrc_offset = None
        crc_bytes   = 0

        pkt = pktt.pkt
        unpack = pktt.unpack

        if pkt.ethernet:
            if pkt.ip:
                # RoCE v2 or Routable RoCE
                self._strname = "RRoCE"
            else:
                # RoCE v1
                self._strname = "RoCE"
                # Decode the IB GRH layer header
                self.grh = GRH(unpack)
                if self.grh is None:
                    # This is not a IB packet
                    return
            self._strfmt1 = "%-5s {0} {2}" % self._strname
            self._strfmt2 = "{2}"
        else:
            self._strfmt1 = "{0} %-5s {2}" % self._strname
            self._strfmt2 = "{0} {2}"

            # Decode the IB LRH layer header
            self.lrh = LRH(unpack)

            if self.lrh is None:
                # This is not a IB packet
                return
            elif self.lrh.lnh == 0x03:
                # Decode the IB GRH layer header
                self.grh = GRH(unpack)
                if self.grh is None:
                    # This is not a IB packet
                    return
            # This deals with truncated packets
            d_offset = unpack.tell() + unpack.size() - self.lrh._vcrc_offset
            if d_offset == 2:
                vcrc_offset = self.lrh._vcrc_offset
                crc_bytes += 2

        if self.grh:
            # The GRH payload length includes the ICRC
            self._strfmt1 = "{1} %-5s {2}" % self._strname
            self._strfmt2 = "{1} {2}"

        if ((self.lrh is None and self.grh is None) or
            (self.lrh and self.lrh.lnh == 0x02) or
            (self.grh and self.grh.nxthdr == 0x1B)):
            # Only BTH (RRoCEv2 or LRG.lnh=0x02 or GRH.nxthdr=0x1B) is supported
            # Decode the IB BTH layer header
            self.bth = BTH(unpack)

            # InfiniBand layer is valid
            self._ib = True
            pkt.add_layer("ib", self)
        else:
            return

        # Get Extended Transport Headers if any
        for eth in ETH_map.get(self.opcode, []):
            setattr(self, eth.__name__.lower(), eth(unpack))

        if self.bth:
            # All packets except raw packets (not supported) have an ICRC
            # The icrc_offset is not set here only if packet is truncated
            if self.grh:
                # The GRH paylen includes the ICRC
                d_offset = unpack.tell() + unpack.size() - self.grh._icrc_offset
                if d_offset >= 4:
                    icrc_offset = self.grh._icrc_offset
            elif pkt.record.length_inc == pkt.record.length_orig:
                # Non-truncated packet
                if vcrc_offset is None:
                    # Last four bytes of packets
                    icrc_offset = unpack.tell() + unpack.size() - 4
                else:
                    # Four bytes before the VCRC
                    icrc_offset = vcrc_offset - 4

        if icrc_offset is not None:
            crc_bytes += 4

        if crc_bytes > 0:
            # Get the Invariant/Variant CRCs
            offset = unpack.tell()
            crcoff = offset + unpack.size() - crc_bytes
            unpack.seek(crcoff)
            if icrc_offset is not None and len(unpack) >= 4:
                self.icrc = IntHex(unpack.unpack_uint())
            if vcrc_offset is not None and len(unpack) >= 2:
                self.vcrc = ShortHex(unpack.unpack_ushort())
            # Remove CRC bytes from unpack buffer
            data = unpack.getbytes(offset)
            if len(data) > crc_bytes:
                unpack = Unpack(data[:-crc_bytes])
                pktt.unpack = unpack

        # Decode InfiniBand payload
        offset = unpack.tell()
        out = self._decode_payload(pktt)

        if out and unpack.tell() > offset:
            # Payload was processed so set STRFMT1 to display either the
            # IB link or network layer
            if self.grh:
                # Display InfiniBand network layer
                self._strfmt1 = "{1} "
            elif self.lrh:
                # Display InfiniBand link layer
                self._strfmt1 = "{0} "
            else:
                self._strfmt1 = ""

    def __nonzero__(self):
        """Truth value testing for the built-in operation bool()"""
        return self._ib

    def _decode_payload(self, pktt):
        """Decode InfiniBand payload
           Return True if the next layer has been dissected
        """
        pkt    = pktt.pkt
        unpack = pktt.unpack
        offset = unpack.tell()

        if self.opcode in (RC + SEND_Only, RC + SEND_Only_Invalidate):
            rpcordma = RPCoRDMA(unpack)
            if rpcordma and rpcordma.vers == 1 and rdma.rdma_proc.get(rpcordma.proc):
                pkt.add_layer("rpcordma", rpcordma)
                if rpcordma.reads:
                    # Save RDMA read first fragment
                    rpcordma.data = unpack.read(len(unpack))
                # RPCoRDMA is valid so process the RDMA chunk lists
                replydata = self._rdma_info.process_rdma_segments(rpcordma)
                if rpcordma.proc == rdma.RDMA_MSG and not rpcordma.reads:
                    # Decode RPC layer except for an RPC call with
                    # RDMA read chunks in which the data has been reduced
                    RPC(pktt, proto=17)
                elif rpcordma.proc == rdma.RDMA_NOMSG and replydata:
                    # This is a no-msg packet but the reply has already been
                    # sent using RDMA writes so just add the RDMA reply chunk
                    # data to the working buffer and decode the RPC layer
                    unpack.insert(replydata)
                    # Decode RPC layer
                    RPC(pktt, proto=17)
                return True
            else:
                # RPCoRDMA is not valid so rewind Unpack object
                unpack.seek(offset)
        elif self.opcode in (RC+RDMA_WRITE_Only, RC+RDMA_WRITE_Only_Immediate):
            self._rdma_info.add_rdma_data(self.bth.psn, unpack, self.reth, True)
        elif self.opcode == RC+RDMA_WRITE_First:
            self._rdma_info.add_rdma_data(self.bth.psn, unpack, self.reth, False)
        elif self.opcode in (RC+RDMA_WRITE_Middle, RC+RDMA_WRITE_Last):
            self._rdma_info.add_rdma_data(self.bth.psn, unpack)
        elif self.opcode == RC+RDMA_READ_Request:
            self._rdma_info.add_rdma_data(self.bth.psn, unpack, self.reth, False)
        elif self.opcode == RC+RDMA_READ_Response_Only:
            self._rdma_info.add_rdma_data(self.bth.psn, unpack, only=True, read=True)
        elif self.opcode == RC+RDMA_READ_Response_First:
            self._rdma_info.add_rdma_data(self.bth.psn, unpack, only=False, read=True)
        elif self.opcode == RC+RDMA_READ_Response_Middle:
            self._rdma_info.add_rdma_data(self.bth.psn, unpack)
        elif self.opcode == RC+RDMA_READ_Response_Last:
            # The RDMA read chunks are reassembled in the read last operation
            data = self._rdma_info.reassemble_rdma_reads(self.bth.psn, unpack)
            if data is not None:
                # Decode RPC layer
                pktt.unpack = Unpack(data)
                RPC(pktt, proto=17)
                return True
        return False
