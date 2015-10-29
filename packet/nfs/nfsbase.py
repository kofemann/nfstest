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
NFS Base module

Base class for an NFS object
"""
import nfstest_config as c
from baseobj import BaseObj
import packet.utils as utils
import packet.nfs.nfs4_const as const4

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.3"

# NFSv4 operation priority for displaying purposes
NFSpriority = {
    const4.OP_EXCHANGE_ID          : 95,
    const4.OP_CREATE_SESSION       : 95,
    const4.OP_DESTROY_SESSION      : 95,
    const4.OP_SETCLIENTID          : 95,
    const4.OP_SETCLIENTID_CONFIRM  : 95,
    const4.OP_DESTROY_CLIENTID     : 95,
    const4.OP_RENEW                : 92,
    const4.OP_OPEN                 : 90,
    const4.OP_OPEN_DOWNGRADE       : 90,
    const4.OP_OPENATTR             : 90,
    const4.OP_OPEN_CONFIRM         : 90,
    const4.OP_CLOSE                : 90,
    const4.OP_CREATE               : 90,
    const4.OP_LAYOUTGET            : 85,
    const4.OP_LAYOUTRETURN         : 85,
    const4.OP_LAYOUTCOMMIT         : 85,
    const4.OP_LAYOUTERROR          : 85,
    const4.OP_LAYOUTSTATS          : 85,
    const4.OP_GETDEVICEINFO        : 84,
    const4.OP_GETDEVICELIST        : 83,
    const4.OP_OFFLOAD_STATUS       : 83,
    const4.OP_OFFLOAD_CANCEL       : 83,
    const4.OP_CLONE                : 82,
    const4.OP_COPY                 : 82,
    const4.OP_COPY_NOTIFY          : 82,
    const4.OP_READ                 : 80,
    const4.OP_WRITE                : 80,
    const4.OP_READ_PLUS            : 80,
    const4.OP_WRITE_SAME           : 80,
    const4.OP_COMMIT               : 80,
    const4.OP_SEEK                 : 75,
    const4.OP_LOCK                 : 70,
    const4.OP_LOCKT                : 70,
    const4.OP_LOCKU                : 70,
    const4.OP_RELEASE_LOCKOWNER    : 70,
    const4.OP_ALLOCATE             : 65,
    const4.OP_DEALLOCATE           : 65,
    const4.OP_IO_ADVISE            : 65,
    const4.OP_DELEGRETURN          : 65,
    const4.OP_DELEGPURGE           : 65,
    const4.OP_GET_DIR_DELEGATION   : 63,
    const4.OP_WANT_DELEGATION      : 62,
    const4.OP_LOOKUPP              : 60,
    const4.OP_LOOKUP               : 60,
    const4.OP_READDIR              : 55,
    const4.OP_RENAME               : 50,
    const4.OP_REMOVE               : 50,
    const4.OP_LINK                 : 45,
    const4.OP_SETATTR              : 44,
    const4.OP_READLINK             : 40,
    const4.OP_TEST_STATEID         : 36,
    const4.OP_FREE_STATEID         : 35,
    const4.OP_RECLAIM_COMPLETE     : 34,
    const4.OP_BACKCHANNEL_CTL      : 33,
    const4.OP_BIND_CONN_TO_SESSION : 32,
    const4.OP_PUTROOTFH            : 30,
    const4.OP_PUTPUBFH             : 30,
    const4.OP_ACCESS               : 25,
    const4.OP_SECINFO              : 22,
    const4.OP_SECINFO_NO_NAME      : 22,
    const4.OP_GETATTR              : 20,
    const4.OP_GETFH                : 10,
    const4.OP_SET_SSV              :  7,
    const4.OP_VERIFY               :  0,
    const4.OP_NVERIFY              :  0,
    const4.OP_PUTFH                :  0,
    const4.OP_RESTOREFH            :  0,
    const4.OP_SAVEFH               :  0,
    const4.OP_SEQUENCE             :  0,
    const4.OP_ILLEGAL              :  0,
}

CBpriority = {
    const4.OP_CB_RECALL               : 90,
    const4.OP_CB_LAYOUTRECALL         : 90,
    const4.OP_CB_NOTIFY               : 80,
    const4.OP_CB_OFFLOAD              : 80,
    const4.OP_CB_PUSH_DELEG           : 70,
    const4.OP_CB_RECALL_ANY           : 60,
    const4.OP_CB_RECALLABLE_OBJ_AVAIL : 60,
    const4.OP_CB_RECALL_SLOT          : 50,
    const4.OP_CB_WANTS_CANCELLED      : 40,
    const4.OP_CB_NOTIFY_LOCK          : 30,
    const4.OP_CB_NOTIFY_DEVICEID      : 20,
    const4.OP_CB_GETATTR              : 10,
    const4.OP_CB_SEQUENCE             : 0,
    const4.OP_CB_ILLEGAL              : 0,
}

class NFSbase(utils.RPCload):
    """NFS Base object

       This should only be used as a base class for an NFS object
    """
    def __str__(self):
        """Informal string representation of object"""
        rpc = self._rpc
        rdebug = self.debug_repr()
        if rdebug == 1:
            # String format for verbose level 1
            out = self.rpc_str("NFS")
            if rpc.program >= 0x40000000 and rpc.program < 0x60000000:
                cb_flag  = True
                priority = CBpriority
            else:
                cb_flag  = False
                priority = NFSpriority
            if rpc.procedure == 0:
                # NULL procedure
                out += self.__class__.__name__
                return out
            elif rpc.version == 4 or cb_flag:
                # NFS version 4.x
                if not utils.NFS_mainop:
                    # Display all NFS operation names in the compound
                    oplist = [str(x.op)[3:] for x in self.array]
                    out += "%-25s" % ";".join(oplist)
                if utils.LOAD_body or utils.NFS_mainop:
                    # Order operations by their priority
                    item_list = sorted(self.array, key=lambda x: priority.get(x.op ,0))
                    if utils.NFS_mainop:
                        # Display only the highest priority operation name
                        out += "%-10s" % str(item_list[-1].op)[3:]
                    if utils.LOAD_body:
                        # Get the highest priority operation body to display
                        display_op = None
                        while item_list:
                            item = item_list.pop()
                            if priority.get(item.op, 0) == 0:
                                # Ignore operations with no priority
                                continue
                            itemstr = str(item)
                            if (display_op is None and len(itemstr)) or item.op == display_op:
                                out += " " + itemstr
                                # Check if there is another operation to display
                                display_op = getattr(item, "_opdisp", None)
                                if display_op is None:
                                    break

            if rpc.type and getattr(self, "status", 0) != 0:
                # Display the status of the NFS packet only if it is an error
                out += " %s" % self.status
            return out
        else:
            return BaseObj.__str__(self)

class NULL(NFSbase):
    """NFS NULL object"""
    pass

class CB_NULL(NFSbase):
    """NFS CB_NULL object"""
    pass
