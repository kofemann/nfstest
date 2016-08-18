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

NOTE:
  Only procedures RPCSEC_GSS_INIT and RPCSEC_GSS_DATA are supported
"""
import rpc_const
import gss_const as const
from packet.utils import *
import nfstest_config as c
from baseobj import BaseObj

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2013 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.3"

# GSS Major Status Codes
class gss_major_status(Enum):
    """enum gss_major_status"""
    _enumdict = const.gss_major_status

class gss_minor_status(Enum):
    """enum gss_minor_status"""
    _enumdict = const.gss_minor_status

class GSS_init_arg(BaseObj):
    """struct rpc_gss_init_arg {
           opaque  gss_token<>;
       };
    """
    # Class attributes
    _strfmt2  = "token: {0:#x:.32}..."
    _attrlist = ("token",)

    def __init__(self, unpack):
        self.token = unpack.unpack_opaque()

class GSS_init_res(BaseObj):
    """struct rpc_gss_init_res {
           opaque        handle<>;
           unsigned int  gss_major;
           unsigned int  gss_minor;
           unsigned int  seq_window;
           opaque        gss_token<>;
       };
    """
    # Class attributes
    _strfmt2  = "major: {1}, minor: {2}, seq_window: {3}, context: {0:#x}, token: {0:#x:.16}..."
    _attrlist = ("context", "major", "minor", "seq_window", "token")

    def __init__(self, unpack):
        self.context    = unpack.unpack_opaque()
        self.major      = gss_major_status(unpack.unpack_uint())
        self.minor      = gss_minor_status(unpack.unpack_int())
        self.seq_window = unpack.unpack_uint()
        self.token      = unpack.unpack_opaque()
        if self.major not in (const.GSS_S_COMPLETE, const.GSS_S_CONTINUE_NEEDED):
            self.set_strfmt(2, "major: {1}, minor: {2}")

class GSS_data(BaseObj):
    """struct rpc_gss_data_t {
           unsigned int    seq_num;
           proc_req_arg_t  arg;
       };
    """
    # Class attributes
    _strfmt2  = "length: {0}, seq_num: {1}"
    _attrlist = ("length", "seq_num")

    def __init__(self, unpack):
        self.length  = unpack.unpack_uint()
        self.seq_num = unpack.unpack_uint()

class GSS_checksum(GSS_init_arg): pass

class GSS(BaseObj):
    """GSS Data object

       This is a base object and should not be instantiated.
       It gives the following methods:
           # Decode data preceding the RPC payload when flavor is RPCSEC_GSS
           x.decode_gss_data()

           # Decode data following the RPC payload when flavor is RPCSEC_GSS
           x.decode_gss_checksum()
    """
    def _gss_data_call(self):
        """Internal method to decode GSS data on a CALL"""
        if self.credential.flavor != rpc_const.RPCSEC_GSS:
            # Not a GSS encoded packet
            return
        unpack = self._pktt.unpack
        if self.credential.gss_proc == const.RPCSEC_GSS_DATA:
            if self.credential.gss_service == const.rpc_gss_svc_integrity:
                return GSS_data(unpack)
        elif self.credential.gss_proc == const.RPCSEC_GSS_INIT:
            return GSS_init_arg(unpack)

    def _gss_data_reply(self):
        """Internal method to decode GSS data on a REPLY"""
        if self.verifier.flavor != rpc_const.RPCSEC_GSS and not hasattr(self.verifier, 'gss_proc'):
            # Not a GSS encoded packet
            return
        unpack = self._pktt.unpack
        if self.verifier.gss_proc == const.RPCSEC_GSS_DATA:
            if self.verifier.gss_service == const.rpc_gss_svc_integrity:
                return GSS_data(unpack)
        elif self.verifier.gss_proc == const.RPCSEC_GSS_INIT:
            return GSS_init_res(unpack)

    def decode_gss_data(self):
        """Decode GSS data"""
        try:
            pktt = self._pktt
            if pktt.unpack.size() < 4:
                # Not a GSS encoded packet
                return
            if self.type == rpc_const.CALL:
                gss = self._gss_data_call()
            else:
                gss = self._gss_data_reply()
            if gss is not None:
                pktt.pkt.gssd = gss
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
            gss = None
            if self.type == rpc_const.CALL:
                cred = self.credential
            else:
                cred = self.verifier
            if cred.flavor == rpc_const.RPCSEC_GSS and cred.gss_proc == const.RPCSEC_GSS_DATA:
                if cred.gss_service == const.rpc_gss_svc_integrity:
                    gss = GSS_checksum(unpack)
            if gss is not None:
                pktt.pkt.gssc = gss
        except:
            pass
