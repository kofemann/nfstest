#===============================================================================
# Copyright 2018 NetApp, Inc. All Rights Reserved,
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
ETHERNET constants module
"""
import nfstest_config as c

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2018 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

ETHERTYPES = {
    0x0800: "IPv4",
    0x86dd: "IPv6",
    0x0806: "ARP",
    0x8035: "RARP",
    0x8100: "802.1Q VLAN",
}
