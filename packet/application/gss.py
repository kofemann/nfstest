#===============================================================================
# Copyright 2013 NetApp, Inc. All Rights Reserved,
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
GSS module

Decode GSS layers.

RFC 2203 RPCSEC_GSS Protocol Specification
RFC 5403 RPCSEC_GSS Version 2
RFC 1964 The Kerberos Version 5 GSS-API Mechanism

NOTE:
  Procedure RPCSEC_GSS_BIND_CHANNEL is not supported
"""
import krb5
import rpc_const
import gss_const as const
from packet.utils import *
import nfstest_config as c
from baseobj import BaseObj
from packet.derunpack import DERunpack

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2013 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "2.0"

# Token Identifier TOK_ID
KRB_AP_REQ            = 0x0100
KRB_AP_REP            = 0x0200
KRB_ERROR             = 0x0300
KRB_TOKEN_GETMIC      = 0x0101
KRB_TOKEN_CFX_GETMIC  = 0x0404

# Integrity algorithm indicator
class gss_sgn_alg(Enum):
    """enum gss_sgn_alg"""
    _enumdict = const.gss_sgn_alg

# GSS Major Status Codes
class gss_major_status(Enum):
    """enum gss_major_status"""
    _enumdict = const.gss_major_status

# GSS Minor Status Codes
class gss_minor_status(Enum):
    """enum gss_minor_status"""
    _enumdict = const.gss_minor_status

class GetMIC(BaseObj):
    """struct GSS_GetMIC {
           unsigned short      sgn_alg;      /* Integrity algorithm indicator */
           opaque              filler[4];    /* Filler bytes: 0xffffffff */
           unsigned long long  snd_seq;      /* Sequence number field */
           opaque              sgn_cksum[8]; /* Checksum of "to-be-signed data" */
       };
    """
    # Class attributes
    _strfmt2  = "GetMIC({0}, snd_seq:{1}, sgn_cksum:{2})"
    _attrlist = ("sgn_alg", "snd_seq", "sgn_cksum")

    def __init__(self, unpack):
        ulist = unpack.unpack(22, "!H4sQ8s")
        self.sgn_alg   = gss_sgn_alg(ulist[0])
        self.filler    = ulist[1]
        self.snd_seq   = LongHex(ulist[2])
        self.sgn_cksum = StrHex(ulist[3])

class GetCfxMIC(BaseObj):
    """struct GSS_GetCfxMIC {
           unsigned char       flags;        /* Attributes field */
           opaque              filler[5];    /* Filler bytes: 0xffffffffff */
           unsigned long long  snd_seq;      /* Sequence number field */
           unsigned char       sgn_cksum[];  /* Checksum of "to-be-signed data" */
       };
    """
    # Class attributes
    _strfmt2  = "GetCfxMIC(flags:{0:#02x}, snd_seq:{1}, sgn_cksum:{2})"
    _attrlist = ("flags", "snd_seq", "sgn_cksum")

    def __init__(self, unpack):
        ulist = unpack.unpack(14, "!B5sQ")
        self.flags     = ulist[0]
        self.filler    = ulist[1]
        self.snd_seq   = LongHex(ulist[2])
        self.sgn_cksum = StrHex(unpack.getbytes())

class GSS_API(BaseObj):
    """GSS-API DEFINITIONS ::=

       BEGIN

       MechType ::= OBJECT IDENTIFIER
       -- representing Kerberos V5 mechanism

       GSSAPI-Token ::=
       -- option indication (delegation, etc.) indicated within
       -- mechanism-specific token
       [APPLICATION 0] IMPLICIT SEQUENCE {
               thisMech MechType,
               innerToken ANY DEFINED BY thisMech
                  -- contents mechanism-specific
                  -- ASN.1 structure not required
               }

       END
    """
    # Class attributes
    _strfmt2  = "GSS_API({2})"
    _attrlist = ("oid", "tok_id", "krb5")

    def __init__(self, data):
        krbobj = None
        has_oid = False
        self._valid = False
        derunpack = DERunpack(data)
        # Get the Kerberos 5 OID only -- from application 0
        if data[0] == "\x60":
            has_oid = True
            krbobj = derunpack.get_item(oid="1.2.840.113554.1.2.2").get(0)
        if (krbobj is not None and len(krbobj) > 0) or not has_oid:
            if has_oid:
                self.oid = krbobj.get(0)
            else:
                self.oid = None
            self.tok_id = ShortHex(derunpack.unpack_ushort())
            self.krb5   = None

            try:
                if self.tok_id == KRB_AP_REQ:
                    krbobj = derunpack.get_item()
                    self.krb5 = krb5.AP_REQ(krbobj)
                    self.krb5.set_strfmt(2, "{1}, opts:{2}, Ticket({3})")
                    self.krb5.ticket.set_strfmt(2, "{2}@{1}({2.ntype}), {3.etype}")
                    self.krb5.ticket.sname.set_strfmt(2, "{1:/:}")
                elif self.tok_id == KRB_AP_REP:
                    krbobj = derunpack.get_item()
                    self.krb5 = krb5.AP_REP(krbobj)
                    self.krb5.set_strfmt(2, "{1}, {2.etype}")
                elif self.tok_id == KRB_ERROR:
                    krbobj = derunpack.get_item()
                    self.krb5 = krb5.KRB_ERROR(krbobj.get(30))
                elif self.tok_id == KRB_TOKEN_GETMIC:
                    self.krb5 = GetMIC(derunpack)
                elif self.tok_id == KRB_TOKEN_CFX_GETMIC:
                    self.krb5 = GetCfxMIC(derunpack)
            except:
                pass

            if self.krb5 is None:
                self.krb5 = StrHex(derunpack.getbytes())
            self._valid = True

    def __nonzero__(self):
        """Truth value testing for the built-in operation bool()"""
        return self._valid

class rgss_init_arg(BaseObj):
    """struct rpc_gss_init_arg {
           opaque token<>;
       };
    """
    # Class attributes
    _strfmt2  = "token: {0:#x:.32}..."
    _attrlist = ("token",)

    def __init__(self, unpack):
        self.token = unpack.unpack_opaque()
        krb = GSS_API(self.token)
        if krb:
            self.token = krb
            self.set_strfmt(2, "{0}")

class rgss_init_res(BaseObj):
    """struct rgss_init_res {
           opaque       context<>;
           unsigned int major;
           unsigned int minor;
           unsigned int seq_window;
           opaque       token<>;
       };
    """
    # Class attributes
    _strfmt2  = "context: {0}, token: {4:#x:.16}..."
    _attrlist = ("context", "major", "minor", "seq_window", "token")

    def __init__(self, unpack):
        self.context    = StrHex(unpack.unpack_opaque())
        self.major      = gss_major_status(unpack)
        self.minor      = gss_minor_status(unpack)
        self.seq_window = unpack.unpack_uint()
        self.token      = unpack.unpack_opaque()
        if self.major not in (const.GSS_S_COMPLETE, const.GSS_S_CONTINUE_NEEDED):
            # Display major and minor codes on error
            self.set_strfmt(2, "major: {1}, minor: {2}")
        else:
            # Try to decode the token
            krb = GSS_API(self.token)
            if krb:
                # Replace token attribute with the decoded object
                self.token = krb
                self.set_strfmt(2, "context: {0}, {4}")

class rgss_data(BaseObj):
    """struct rgss_data {
           unsigned int length;
           unsigned int seq_num;
       };
    """
    # Class attributes
    _strfmt2  = "length: {0}, seq_num: {1}"
    _attrlist = ("length", "seq_num")

    def __init__(self, unpack):
        self.length  = unpack.unpack_uint()
        self.seq_num = unpack.unpack_uint()

class rgss_checksum(rgss_init_arg): pass

class rgss_priv_data(BaseObj):
    """struct rgss_priv_data {
           opaque data<>;
       };
    """
    # Class attributes
    _strfmt2  = "length: {0}"
    _attrlist = ("length", "data")

    def __init__(self, unpack):
        self.length = unpack.unpack_uint()
        self.data   = unpack.unpack_fopaque(self.length)

class GSS(BaseObj):
    """GSS Data object

       This is a base object and should not be instantiated.
       It gives the following methods:
           # Decode data preceding the RPC payload when flavor is RPCSEC_GSS
           x.decode_gss_data()

           # Decode data following the RPC payload when flavor is RPCSEC_GSS
           x.decode_gss_checksum()
    """
    def decode_gss_data(self):
        """Decode GSS data"""
        try:
            gss = None
            pktt = self._pktt
            unpack = pktt.unpack
            if unpack.size() < 4:
                # Not a GSS encoded packet
                return
            if self.type == rpc_const.CALL:
                cred = self.credential
            else:
                cred = self.verifier
            gssproc = getattr(cred, "gssproc", None)
            if cred.flavor != rpc_const.RPCSEC_GSS or gssproc is None:
                # Not a GSS encoded packet
                return
            if gssproc == const.RPCSEC_GSS_DATA:
                if cred.service == const.rpc_gss_svc_integrity:
                    gss = rgss_data(unpack)
                elif cred.service == const.rpc_gss_svc_privacy:
                    gss = rgss_priv_data(unpack)
            elif gssproc in (const.RPCSEC_GSS_INIT, const.RPCSEC_GSS_CONTINUE_INIT):
                if self.type == rpc_const.CALL:
                    gss = rgss_init_arg(unpack)
                else:
                    gss = rgss_init_res(unpack)

            if gss is not None:
                pktt.pkt.add_layer("gssd", gss)
        except:
            pass

    def decode_gss_checksum(self):
        """Decode GSS checksum"""
        try:
            pktt = self._pktt
            unpack = pktt.unpack
            if unpack.size() < 4:
                # Not a GSS encoded packet
                return
            if self.type == rpc_const.CALL:
                cred = self.credential
            else:
                cred = self.verifier
            if cred.flavor == rpc_const.RPCSEC_GSS and cred.gssproc == const.RPCSEC_GSS_DATA:
                if cred.service == const.rpc_gss_svc_integrity:
                    pktt.pkt.add_layer("gssc", rgss_checksum(unpack))
        except:
            pass
