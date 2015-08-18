/*
 * Copyright (C) The Internet Society (2003).  All Rights Reserved.
 *
 * This document and translations of it may be copied and furnished to
 * others, and derivative works that comment on or otherwise explain it
 * or assist in its implementation may be prepared, copied, published
 * and distributed, in whole or in part, without restriction of any
 * kind, provided that the above copyright notice and this paragraph are
 * included on all such copies and derivative works.  However, this
 * document itself may not be modified in any way, such as by removing
 * the copyright notice or references to the Internet Society or other
 * Internet organizations, except as needed for the purpose of
 * developing Internet standards in which case the procedures for
 * copyrights defined in the Internet Standards process must be
 * followed, or as required to translate it into languages other than
 * English.
 *
 * The limited permissions granted above are perpetual and will not be
 * revoked by the Internet Society or its successors or assigns.
 *
 * This document and the information contained herein is provided on an
 * "AS IS" basis and THE INTERNET SOCIETY AND THE INTERNET ENGINEERING
 * TASK FORCE DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION
 * HEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Network File System (NFS) version 4 Protocol (RFC 3530)
 *
 *=====================================================================
 * This Document was changed to add directives for converting
 * it to python code. Also the name of some variables were
 * changed to be consistent throughout this document and to
 * have a similar interface with earlier versions of NFS.
 *=====================================================================
 */

/* COPYRIGHT: 2014 */

/*
 * Constants
 */
enum bool {
    FALSE = 0,
    TRUE  = 1
};

/*
 * Sizes
 */
const NFS4_FHSIZE               = 128;
const NFS4_VERIFIER_SIZE        = 8;
const NFS4_OPAQUE_LIMIT         = 1024;
const NFS4_OTHER_SIZE           = 12;

/*
 * File types
 */
enum nfs_ftype4 {
    NF4REG         = 1,    /* Regular File */
    NF4DIR         = 2,    /* Directory */
    NF4BLK         = 3,    /* Special File - block device */
    NF4CHR         = 4,    /* Special File - character device */
    NF4LNK         = 5,    /* Symbolic Link */
    NF4SOCK        = 6,    /* Special File - socket */
    NF4FIFO        = 7,    /* Special File - fifo */
    NF4ATTRDIR     = 8,    /* Attribute Directory */
    NF4NAMEDATTR   = 9     /* Named Attribute */
};

/*
 * Error status
 */
enum nfsstat4 {
    NFS4_OK                            = 0,    /* everything is okay      */
    NFS4ERR_PERM                       = 1,    /* caller not privileged   */
    NFS4ERR_NOENT                      = 2,    /* no such file/directory  */
    NFS4ERR_IO                         = 5,    /* hard I/O error          */
    NFS4ERR_NXIO                       = 6,    /* no such device          */
    NFS4ERR_ACCESS                     = 13,   /* access denied           */
    NFS4ERR_EXIST                      = 17,   /* file already exists     */
    NFS4ERR_XDEV                       = 18,   /* different filesystems   */
    /* Unused/reserved                   19 */
    NFS4ERR_NOTDIR                     = 20,   /* should be a directory   */
    NFS4ERR_ISDIR                      = 21,   /* should not be directory */
    NFS4ERR_INVAL                      = 22,   /* invalid argument        */
    NFS4ERR_FBIG                       = 27,   /* file exceeds server max */
    NFS4ERR_NOSPC                      = 28,   /* no space on filesystem  */
    NFS4ERR_ROFS                       = 30,   /* read-only filesystem    */
    NFS4ERR_MLINK                      = 31,   /* too many hard links     */
    NFS4ERR_NAMETOOLONG                = 63,   /* name exceeds server max */
    NFS4ERR_NOTEMPTY                   = 66,   /* directory not empty     */
    NFS4ERR_DQUOT                      = 69,   /* hard quota limit reached*/
    NFS4ERR_STALE                      = 70,   /* file no longer exists   */
    NFS4ERR_BADHANDLE                  = 10001,/* Illegal filehandle      */
    NFS4ERR_BAD_COOKIE                 = 10003,/* READDIR cookie is stale */
    NFS4ERR_NOTSUPP                    = 10004,/* operation not supported */
    NFS4ERR_TOOSMALL                   = 10005,/* response limit exceeded */
    NFS4ERR_SERVERFAULT                = 10006,/* undefined server error  */
    NFS4ERR_BADTYPE                    = 10007,/* type invalid for CREATE */
    NFS4ERR_DELAY                      = 10008,/* file "busy" - retry     */
    NFS4ERR_SAME                       = 10009,/* nverify says attrs same */
    NFS4ERR_DENIED                     = 10010,/* lock unavailable        */
    NFS4ERR_EXPIRED                    = 10011,/* lock lease expired      */
    NFS4ERR_LOCKED                     = 10012,/* I/O failed due to lock  */
    NFS4ERR_GRACE                      = 10013,/* in grace period         */
    NFS4ERR_FHEXPIRED                  = 10014,/* filehandle expired      */
    NFS4ERR_SHARE_DENIED               = 10015,/* share reserve denied    */
    NFS4ERR_WRONGSEC                   = 10016,/* wrong security flavor   */
    NFS4ERR_CLID_INUSE                 = 10017,/* clientid in use         */
    NFS4ERR_RESOURCE                   = 10018,/* resource exhaustion     */
    NFS4ERR_MOVED                      = 10019,/* filesystem relocated    */
    NFS4ERR_NOFILEHANDLE               = 10020,/* current FH is not set   */
    NFS4ERR_MINOR_VERS_MISMATCH        = 10021,/* minor vers not supp     */
    NFS4ERR_STALE_CLIENTID             = 10022,/* server has rebooted     */
    NFS4ERR_STALE_STATEID              = 10023,/* server has rebooted     */
    NFS4ERR_OLD_STATEID                = 10024,/* state is out of sync    */
    NFS4ERR_BAD_STATEID                = 10025,/* incorrect stateid       */
    NFS4ERR_BAD_SEQID                  = 10026,/* request is out of seq.  */
    NFS4ERR_NOT_SAME                   = 10027,/* verify - attrs not same */
    NFS4ERR_LOCK_RANGE                 = 10028,/* overlapping lock range  */
    NFS4ERR_SYMLINK                    = 10029,/* should be file/directory*/
    NFS4ERR_RESTOREFH                  = 10030,/* no saved filehandle     */
    NFS4ERR_LEASE_MOVED                = 10031,/* some filesystem moved   */
    NFS4ERR_ATTRNOTSUPP                = 10032,/* recommended attr not sup*/
    NFS4ERR_NO_GRACE                   = 10033,/* reclaim outside of grace*/
    NFS4ERR_RECLAIM_BAD                = 10034,/* reclaim error at server */
    NFS4ERR_RECLAIM_CONFLICT           = 10035,/* conflict on reclaim     */
    NFS4ERR_BADXDR                     = 10036,/* XDR decode failed       */
    NFS4ERR_LOCKS_HELD                 = 10037,/* file locks held at CLOSE*/
    NFS4ERR_OPENMODE                   = 10038,/* conflict in OPEN and I/O*/
    NFS4ERR_BADOWNER                   = 10039,/* owner translation bad   */
    NFS4ERR_BADCHAR                    = 10040,/* utf-8 char not supported*/
    NFS4ERR_BADNAME                    = 10041,/* name not supported      */
    NFS4ERR_BAD_RANGE                  = 10042,/* lock range not supported*/
    NFS4ERR_LOCK_NOTSUPP               = 10043,/* no atomic up/downgrade  */
    NFS4ERR_OP_ILLEGAL                 = 10044,/* undefined operation     */
    NFS4ERR_DEADLOCK                   = 10045,/* file locking deadlock   */
    NFS4ERR_FILE_OPEN                  = 10046,/* open file blocks op.    */
    NFS4ERR_ADMIN_REVOKED              = 10047,/* lockowner state revoked */
    NFS4ERR_CB_PATH_DOWN               = 10048,/* callback path down      */
};

/*
 * Basic typedefs for RFC 1832 data type definitions
 */
typedef int             int32_t;
typedef unsigned int    uint32_t;
typedef hyper           int64_t;
typedef unsigned hyper  uint64_t;

/*
 * Basic data types
 */
typedef opaque                  attrlist4<>;
/* BITMAP:1 */
typedef uint32_t                bitmap4<>; /* STRHEX:1 */
typedef uint64_t                changeid4; /* STRHEX:1 */
typedef uint64_t                clientid4; /* STRHEX:1 */
typedef uint64_t                offset4;
typedef uint32_t                count4;
typedef uint64_t                length4;
typedef uint32_t                mode4;
typedef uint64_t                nfs_cookie4;
typedef opaque                  nfs_fh4<NFS4_FHSIZE>; /* STRHEX:1 */
typedef uint32_t                nfs_lease4;
typedef uint32_t                qop4;
typedef opaque                  sec_oid4<>; /* STRHEX:1 */
typedef uint32_t                seqid4;
typedef opaque                  utf8string<>;
typedef utf8string              utf8str_cis;
typedef utf8string              utf8str_cs;
typedef utf8string              utf8str_mixed;
typedef utf8str_cs              component4;
typedef utf8str_cs              linktext4;
typedef utf8string              ascii_REQUIRED4;
typedef component4              pathname4<>;
typedef opaque                  verifier4[NFS4_VERIFIER_SIZE]; /* STRHEX:1 */
typedef uint32_t                acetype4; /* STRHEX:1 */
typedef uint32_t                aceflag4; /* STRHEX:1 */
typedef uint32_t                acemask4; /* STRHEX:1 */
typedef uint32_t                access4;

/*
 * Timeval
 */
/* STRFMT1: {0}.{1:09} */
struct nfstime4 {
    int64_t   seconds;
    uint32_t  nseconds;
};

enum time_how4 {
    SET_TO_SERVER_TIME4 = 0,
    SET_TO_CLIENT_TIME4 = 1
};

union settime4 switch (time_how4 set_it) {
    case SET_TO_CLIENT_TIME4:
        nfstime4  time;
    default:
        void;
};

/*
 * File attribute definitions
 */

/*
 * FSID structure for major/minor
 */
/* STRFMT1: {0},{1} */
struct fsid4 {
    uint64_t  major;
    uint64_t  minor;
};

/*
 * Filesystem locations attribute for relocation/migration
 */
/* STRFMT1: server:{0} rootpath:{1:/:} */
struct fs_location4 {
    utf8str_cis  server<>;
    pathname4    root;
};

/* STRFMT1: root:{1:/:} */
struct fs_locations4 {
    pathname4     root;
    fs_location4  locations<>;
};

/*
 * Various Access Control Entry definitions
 */

/*
 * Mask that indicates which Access Control Entries are supported.
 * Values for the fattr4_aclsupport attribute.
 */
const ACL4_SUPPORT_ALLOW_ACL    = 0x00000001;
const ACL4_SUPPORT_DENY_ACL     = 0x00000002;
const ACL4_SUPPORT_AUDIT_ACL    = 0x00000004;
const ACL4_SUPPORT_ALARM_ACL    = 0x00000008;

/*
 * acetype4 values, others can be added as needed.
 */
const ACE4_ACCESS_ALLOWED_ACE_TYPE      = 0x00000000;
const ACE4_ACCESS_DENIED_ACE_TYPE       = 0x00000001;
const ACE4_SYSTEM_AUDIT_ACE_TYPE        = 0x00000002;
const ACE4_SYSTEM_ALARM_ACE_TYPE        = 0x00000003;

/*
 * ACE flag values
 */
const ACE4_FILE_INHERIT_ACE             = 0x00000001;
const ACE4_DIRECTORY_INHERIT_ACE        = 0x00000002;
const ACE4_NO_PROPAGATE_INHERIT_ACE     = 0x00000004;
const ACE4_INHERIT_ONLY_ACE             = 0x00000008;
const ACE4_SUCCESSFUL_ACCESS_ACE_FLAG   = 0x00000010;
const ACE4_FAILED_ACCESS_ACE_FLAG       = 0x00000020;
const ACE4_IDENTIFIER_GROUP             = 0x00000040;

/*
 * ACE mask values
 */
const ACE4_READ_DATA            = 0x00000001;
const ACE4_LIST_DIRECTORY       = 0x00000001;
const ACE4_WRITE_DATA           = 0x00000002;
const ACE4_ADD_FILE             = 0x00000002;
const ACE4_APPEND_DATA          = 0x00000004;
const ACE4_ADD_SUBDIRECTORY     = 0x00000004;
const ACE4_READ_NAMED_ATTRS     = 0x00000008;
const ACE4_WRITE_NAMED_ATTRS    = 0x00000010;
const ACE4_EXECUTE              = 0x00000020;
const ACE4_DELETE_CHILD         = 0x00000040;
const ACE4_READ_ATTRIBUTES      = 0x00000080;
const ACE4_WRITE_ATTRIBUTES     = 0x00000100;

const ACE4_DELETE               = 0x00010000;
const ACE4_READ_ACL             = 0x00020000;
const ACE4_WRITE_ACL            = 0x00040000;
const ACE4_WRITE_OWNER          = 0x00080000;
const ACE4_SYNCHRONIZE          = 0x00100000;

/*
 * ACE4_GENERIC_READ -- defined as combination of
 *      ACE4_READ_ACL |
 *      ACE4_READ_DATA |
 *      ACE4_READ_ATTRIBUTES |
 *      ACE4_SYNCHRONIZE
 */
const ACE4_GENERIC_READ = 0x00120081;

/*
 * ACE4_GENERIC_WRITE -- defined as combination of
 *      ACE4_READ_ACL |
 *      ACE4_WRITE_DATA |
 *      ACE4_WRITE_ATTRIBUTES |
 *      ACE4_WRITE_ACL |
 *      ACE4_APPEND_DATA |
 *      ACE4_SYNCHRONIZE
 */
const ACE4_GENERIC_WRITE = 0x00160106;

/*
 * ACE4_GENERIC_EXECUTE -- defined as combination of
 *      ACE4_READ_ACL
 *      ACE4_READ_ATTRIBUTES
 *      ACE4_EXECUTE
 *      ACE4_SYNCHRONIZE
 */
const ACE4_GENERIC_EXECUTE = 0x001200A0;

/*
 * Access Control Entry definition
 */
struct nfsace4 {
    acetype4       type;
    aceflag4       flag;
    acemask4       mask;
    utf8str_mixed  who;
};

/*
 * Field definitions for the fattr4_mode attribute
 */
const MODE4_SUID = 0x800;  /* set user id on execution */
const MODE4_SGID = 0x400;  /* set group id on execution */
const MODE4_SVTX = 0x200;  /* save text even after use */
const MODE4_RUSR = 0x100;  /* read permission: owner */
const MODE4_WUSR = 0x080;  /* write permission: owner */
const MODE4_XUSR = 0x040;  /* execute permission: owner */
const MODE4_RGRP = 0x020;  /* read permission: group */
const MODE4_WGRP = 0x010;  /* write permission: group */
const MODE4_XGRP = 0x008;  /* execute permission: group */
const MODE4_ROTH = 0x004;  /* read permission: other */
const MODE4_WOTH = 0x002;  /* write permission: other */
const MODE4_XOTH = 0x001;  /* execute permission: other */

/*
 * Special data/attribute associated with
 * file types NF4BLK and NF4CHR.
 */
/* STRFMT1: major:{0} minor:{1} */
struct specdata4 {
    uint32_t  specdata1; /* major device number */
    uint32_t  specdata2; /* minor device number */
};

/*
 * Stateid
 */
/* EQATTR: other */
/* STRFMT1: {0},{1:crc16} */
struct stateid4 {
    uint32_t  seqid;
    opaque    other[NFS4_OTHER_SIZE]; /* STRHEX:1 */
};

enum stable_how4 {
    UNSTABLE4       = 0,
    DATA_SYNC4      = 1,
    FILE_SYNC4      = 2
};

/* STRFMT1: netid:{0} addr:{1} */
struct clientaddr4 {
    /* See struct rpcb in RFC 1833 */
    string  netid<>;    /* network id */
    string  addr<>;     /* universal address */
};

typedef clientaddr4 netaddr4;

/*
 * Values for fattr4_fh_expire_type
 */
const FH4_PERSISTENT          = 0x00000000;
const FH4_NOEXPIRE_WITH_OPEN  = 0x00000001;
const FH4_VOLATILE_ANY        = 0x00000002;
const FH4_VOL_MIGRATION       = 0x00000004;
const FH4_VOL_RENAME          = 0x00000008;

/*
 * Attributes
 */
typedef bitmap4                 fattr4_supported_attrs;
typedef nfs_ftype4              fattr4_type;
typedef uint32_t                fattr4_fh_expire_type;
typedef changeid4               fattr4_change;
typedef uint64_t                fattr4_size;
typedef bool                    fattr4_link_support;
typedef bool                    fattr4_symlink_support;
typedef bool                    fattr4_named_attr;
typedef fsid4                   fattr4_fsid;
typedef bool                    fattr4_unique_handles;
typedef nfs_lease4              fattr4_lease_time;
typedef nfsstat4                fattr4_rdattr_error;
typedef nfsace4                 fattr4_acl<>;
typedef uint32_t                fattr4_aclsupport;
typedef bool                    fattr4_archive;
typedef bool                    fattr4_cansettime;
typedef bool                    fattr4_case_insensitive;
typedef bool                    fattr4_case_preserving;
typedef bool                    fattr4_chown_restricted;
typedef uint64_t                fattr4_fileid;
typedef uint64_t                fattr4_files_avail;
typedef nfs_fh4                 fattr4_filehandle;
typedef uint64_t                fattr4_files_free;
typedef uint64_t                fattr4_files_total;
typedef fs_locations4           fattr4_fs_locations;
typedef bool                    fattr4_hidden;
typedef bool                    fattr4_homogeneous;
typedef uint64_t                fattr4_maxfilesize;
typedef uint32_t                fattr4_maxlink;
typedef uint32_t                fattr4_maxname;
typedef uint64_t                fattr4_maxread;
typedef uint64_t                fattr4_maxwrite;
typedef ascii_REQUIRED4         fattr4_mimetype;
typedef mode4                   fattr4_mode;
typedef uint64_t                fattr4_mounted_on_fileid;
typedef bool                    fattr4_no_trunc;
typedef uint32_t                fattr4_numlinks;
typedef utf8str_mixed           fattr4_owner;
typedef utf8str_mixed           fattr4_owner_group;
typedef uint64_t                fattr4_quota_avail_hard;
typedef uint64_t                fattr4_quota_avail_soft;
typedef uint64_t                fattr4_quota_used;
typedef specdata4               fattr4_rawdev;
typedef uint64_t                fattr4_space_avail;
typedef uint64_t                fattr4_space_free;
typedef uint64_t                fattr4_space_total;
typedef uint64_t                fattr4_space_used;
typedef bool                    fattr4_system;
typedef nfstime4                fattr4_time_access;
typedef settime4                fattr4_time_access_set;
typedef nfstime4                fattr4_time_backup;
typedef nfstime4                fattr4_time_create;
typedef nfstime4                fattr4_time_delta;
typedef nfstime4                fattr4_time_metadata;
typedef nfstime4                fattr4_time_modify;
typedef settime4                fattr4_time_modify_set;

/* FMAP:1 */
enum nfs_fattr4 {
    /*
     * Mandatory Attributes
     */
    FATTR4_SUPPORTED_ATTRS    = 0,
    FATTR4_TYPE               = 1,
    FATTR4_FH_EXPIRE_TYPE     = 2,
    FATTR4_CHANGE             = 3,
    FATTR4_SIZE               = 4,
    FATTR4_LINK_SUPPORT       = 5,
    FATTR4_SYMLINK_SUPPORT    = 6,
    FATTR4_NAMED_ATTR         = 7,
    FATTR4_FSID               = 8,
    FATTR4_UNIQUE_HANDLES     = 9,
    FATTR4_LEASE_TIME         = 10,
    FATTR4_RDATTR_ERROR       = 11,
    FATTR4_FILEHANDLE         = 19,

    /*
     * Recommended Attributes
     */
    FATTR4_ACL                = 12,
    FATTR4_ACLSUPPORT         = 13,
    FATTR4_ARCHIVE            = 14,
    FATTR4_CANSETTIME         = 15,
    FATTR4_CASE_INSENSITIVE   = 16,
    FATTR4_CASE_PRESERVING    = 17,
    FATTR4_CHOWN_RESTRICTED   = 18,
    FATTR4_FILEID             = 20,
    FATTR4_FILES_AVAIL        = 21,
    FATTR4_FILES_FREE         = 22,
    FATTR4_FILES_TOTAL        = 23,
    FATTR4_FS_LOCATIONS       = 24,
    FATTR4_HIDDEN             = 25,
    FATTR4_HOMOGENEOUS        = 26,
    FATTR4_MAXFILESIZE        = 27,
    FATTR4_MAXLINK            = 28,
    FATTR4_MAXNAME            = 29,
    FATTR4_MAXREAD            = 30,
    FATTR4_MAXWRITE           = 31,
    FATTR4_MIMETYPE           = 32,
    FATTR4_MODE               = 33,
    FATTR4_NO_TRUNC           = 34,
    FATTR4_NUMLINKS           = 35,
    FATTR4_OWNER              = 36,
    FATTR4_OWNER_GROUP        = 37,
    FATTR4_QUOTA_AVAIL_HARD   = 38,
    FATTR4_QUOTA_AVAIL_SOFT   = 39,
    FATTR4_QUOTA_USED         = 40,
    FATTR4_RAWDEV             = 41,
    FATTR4_SPACE_AVAIL        = 42,
    FATTR4_SPACE_FREE         = 43,
    FATTR4_SPACE_TOTAL        = 44,
    FATTR4_SPACE_USED         = 45,
    FATTR4_SYSTEM             = 46,
    FATTR4_TIME_ACCESS        = 47,
    FATTR4_TIME_ACCESS_SET    = 48,
    FATTR4_TIME_BACKUP        = 49,
    FATTR4_TIME_CREATE        = 50,
    FATTR4_TIME_DELTA         = 51,
    FATTR4_TIME_METADATA      = 52,
    FATTR4_TIME_MODIFY        = 53,
    FATTR4_TIME_MODIFY_SET    = 54,
    FATTR4_MOUNTED_ON_FILEID  = 55,
};

/*
 * File attribute container
 */
/* BITDICT: nfs_fattr4 */
struct fattr4 {
    bitmap4    mask;
    attrlist4  values;
};

/*
 * Change info for the client
 */
struct change_info4 {
    bool       atomic;
    changeid4  before;
    changeid4  after;
};

struct state_owner4 {
    clientid4  clientid;
    opaque     owner<NFS4_OPAQUE_LIMIT>; /* STRHEX:1 */
};

typedef state_owner4 open_owner4;
typedef state_owner4 lock_owner4;

/*
 * ======================================================================
 * NFSv4 Operation Definitions
 * ======================================================================
 */

/*
 * Operation array
 */
enum nfs_opnum4 {
    OP_ACCESS              = 3,
    OP_CLOSE               = 4,
    OP_COMMIT              = 5,
    OP_CREATE              = 6,
    OP_DELEGPURGE          = 7,
    OP_DELEGRETURN         = 8,
    OP_GETATTR             = 9,
    OP_GETFH               = 10,
    OP_LINK                = 11,
    OP_LOCK                = 12,
    OP_LOCKT               = 13,
    OP_LOCKU               = 14,
    OP_LOOKUP              = 15,
    OP_LOOKUPP             = 16,
    OP_NVERIFY             = 17,
    OP_OPEN                = 18,
    OP_OPENATTR            = 19,
    OP_OPEN_CONFIRM        = 20,
    OP_OPEN_DOWNGRADE      = 21,
    OP_PUTFH               = 22,
    OP_PUTPUBFH            = 23,
    OP_PUTROOTFH           = 24,
    OP_READ                = 25,
    OP_READDIR             = 26,
    OP_READLINK            = 27,
    OP_REMOVE              = 28,
    OP_RENAME              = 29,
    OP_RENEW               = 30,
    OP_RESTOREFH           = 31,
    OP_SAVEFH              = 32,
    OP_SECINFO             = 33,
    OP_SETATTR             = 34,
    OP_SETCLIENTID         = 35,
    OP_SETCLIENTID_CONFIRM = 36,
    OP_VERIFY              = 37,
    OP_WRITE               = 38,
    OP_RELEASE_LOCKOWNER   = 39,
    /* Illegal operation */
    OP_ILLEGAL             = 10044
};

const ACCESS4_READ      = 0x00000001;
const ACCESS4_LOOKUP    = 0x00000002;
const ACCESS4_MODIFY    = 0x00000004;
const ACCESS4_EXTEND    = 0x00000008;
const ACCESS4_DELETE    = 0x00000010;
const ACCESS4_EXECUTE   = 0x00000020;

/*
 * ACCESS: Check Access Rights
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} acc:{0:#04x} */
struct ACCESS4args {
    /* CURRENT_FH: object */
    access4        access;
};

/* STRFMT1: supported:{0:#04x} acc:{1:#04x} */
struct ACCESS4resok {
    access4        supported;
    access4        access;
};

/* STRFMT1: {1} */
union ACCESS4res switch (nfsstat4 status) {
    case NFS4_OK:
        ACCESS4resok   resok;
    default:
        void;
};

/*
 * CLOSE: Close a File and Release Share Reservations
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{1} */
struct CLOSE4args {
    /* CURRENT_FH: object */
    seqid4          seqid;
    stateid4        stateid;
};

/* STRFMT1: stid:{1} */
union CLOSE4res switch (nfsstat4 status) {
    case NFS4_OK:
        stateid4       stateid;
    default:
        void;
};

/*
 * COMMIT: Commit Cached Data on Server to Stable Storage
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} off:{0:umax64} len:{1:umax32} */
struct COMMIT4args {
    /* CURRENT_FH: file */
    offset4         offset;
    count4          count;
};

/* STRFMT1: verf:{0} */
struct COMMIT4resok {
    verifier4       verifier;
};

/* STRFMT1: {1} */
union COMMIT4res switch (nfsstat4 status) {
    case NFS4_OK:
        COMMIT4resok   resok;
    default:
        void;
};

/*
 * CREATE: Create a Non-Regular File Object
 * ======================================================================
 */
/* STRFMT1: "" */
union createtype4 switch (nfs_ftype4 type) {
    case NF4LNK:
        /* STRFMT1: -> {1} */
        linktext4 linkdata;
    case NF4BLK:
    case NF4CHR:
        /* STRFMT1: {1} */
        specdata4 devdata;
    case NF4SOCK:
    case NF4FIFO:
    case NF4DIR:
        void;
    default:
        void;  /* server should return NFS4ERR_BADTYPE */
};

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: {0.type} DH:{fh:crc32}/{1} {0} */
struct CREATE4args {
    /* CURRENT_FH: directory for creation */
    createtype4     type;
    component4      name;
    fattr4          attributes;
};

struct CREATE4resok {
    change_info4    cinfo;
    bitmap4         attrset;        /* attributes set */
};

/* STRFMT1: "" */
union CREATE4res switch (nfsstat4 status) {
    case NFS4_OK:
        /* new CURRENTFH: created object */
        CREATE4resok resok;
    default:
        void;
};

/*
 * DELEGPURGE: Purge Delegations Awaiting Recovery
 * ======================================================================
 */
/* STRFMT1: clientid:{0} */
struct DELEGPURGE4args {
    clientid4       clientid;
};

struct DELEGPURGE4res {
    nfsstat4        status;
};

/*
 * DELEGRETURN: Return Delegation
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} */
struct DELEGRETURN4args {
    /* CURRENT_FH: delegated object */
    stateid4        stateid;
};

/* STRFMT1: "" */
struct DELEGRETURN4res {
    nfsstat4        status;
};

/*
 * GETATTR: Get File Attributes
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} request:{0} */
struct GETATTR4args {
    /* CURRENT_FH: object */
    bitmap4         request;
};

struct GETATTR4resok {
    fattr4          attributes;
};

/* STRFMT1: "" */
union GETATTR4res switch (nfsstat4 status) {
    case NFS4_OK:
        GETATTR4resok  resok;
    default:
        void;
};

/*
 * GETFH: Get Current Filehandle
 * ======================================================================
 */
/* GLOBAL: nfs4_fh=fh */
/* STRFMT1: FH:{0:crc32} */
struct GETFH4resok {
    nfs_fh4         fh;
};

/* STRFMT1: {1} */
union GETFH4res switch (nfsstat4 status) {
    case NFS4_OK:
        GETFH4resok     resok;
    default:
        void;
};

/*
 * LINK: Create Link to an Object
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh,sfh=self.nfs4_sfh */
/* STRFMT1: DH:{fh:crc32}/{0} -> FH:{sfh:crc32} */
struct LINK4args {
    /* SAVED_FH: source object */
    /* CURRENT_FH: target directory */
    component4      name;
};

struct LINK4resok {
    change_info4    cinfo;
};

/* STRFMT1: "" */
union LINK4res switch (nfsstat4 status) {
    case NFS4_OK:
        LINK4resok resok;
    default:
        void;
};

/*
 * LOCK/LOCKT/LOCKU: Record Lock Management
 */
enum nfs_lock_type4 {
    READ_LT         = 1,
    WRITE_LT        = 2,
    READW_LT        = 3,    /* blocking read */
    WRITEW_LT       = 4     /* blocking write */
};

/*
 * For LOCK, transition from open_stateid and lock_owner
 * to a lock stateid.
 */
/* STRFMT1: open(stid:{1}, seqid:{0}) seqid:{2} */
struct open_to_lock_owner4 {
    seqid4          seqid;
    stateid4        stateid;
    seqid4          lock_seqid;
    lock_owner4     lock_owner;
};

/*
 * For LOCK, existing lock stateid continues to request new
 * file lock for the same lock_owner and open_stateid.
 */
/* STRFMT1: stid:{0} seqid:{1} */
struct exist_lock_owner4 {
    stateid4        stateid;
    seqid4          seqid;
};

/* STRFMT1: {1} */
union locker4 switch (bool new_lock_owner) {
    case TRUE:
        open_to_lock_owner4     open_owner;
    case FALSE:
        exist_lock_owner4       lock_owner;
};

/*
 * LOCK: Create Lock
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} {0} off:{2:umax64} len:{3:umax64} {4} */
struct LOCK4args {
    /* CURRENT_FH: file */
    nfs_lock_type4  locktype;
    bool            reclaim;
    offset4         offset;
    length4         length;
    locker4         locker;
};

/* STRFMT1: {2} off:{0:umax64} len:{1:umax64} */
struct LOCK4denied {
    offset4         offset;
    length4         length;
    nfs_lock_type4  locktype;
    lock_owner4     owner;
};

/* STRFMT1: stid:{0} */
struct LOCK4resok {
    stateid4        stateid;
};

/* STRFMT1: {1} */
union LOCK4res switch (nfsstat4 status) {
    case NFS4_OK:
        LOCK4resok     resok;
    case NFS4ERR_DENIED:
        LOCK4denied    denied;
    default:
        void;
};

/*
 * LOCKT: Test For Lock
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} {0} off:{1:umax64} len:{2:umax64} */
struct LOCKT4args {
    /* CURRENT_FH: file */
    nfs_lock_type4  locktype;
    offset4         offset;
    length4         length;
    lock_owner4     owner;
};

/* STRFMT1: {1} */
union LOCKT4res switch (nfsstat4 status) {
    case NFS4ERR_DENIED:
        LOCK4denied    denied;
    case NFS4_OK:
        void;
    default:
        void;
};

/*
 * LOCKU: Unlock File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} {0} off:{3:umax64} len:{4:umax64} stid:{2} */
struct LOCKU4args {
    /* CURRENT_FH: file */
    nfs_lock_type4  locktype;
    seqid4          seqid;
    stateid4        stateid;
    offset4         offset;
    length4         length;
};

/* STRFMT1: stid:{1} */
union LOCKU4res switch (nfsstat4 status) {
    case NFS4_OK:
        stateid4       stateid;
    default:
        /* STRFMT1: "" */
        void;
};

/*
 * LOOKUP: Lookup Filename
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: DH:{fh:crc32}/{0} */
struct LOOKUP4args {
    /* CURRENT_FH: directory */
    component4      name;
};

/* STRFMT1: "" */
struct LOOKUP4res {
    /* New CURRENT_FH: object */
    nfsstat4        status;
};

/*
 * LOOKUPP: Lookup Parent Directory
 * ======================================================================
 */
struct LOOKUPP4res {
    /* new CURRENT_FH: parent directory */
    nfsstat4        status;
};

/*
 * NVERIFY: Verify Difference in Attributes
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
struct NVERIFY4args {
    /* CURRENT_FH: object */
    fattr4          attributes;
};

struct NVERIFY4res {
    nfsstat4        status;
};

/*
 * Various definitions for OPEN
 */
enum createmode4 {
    UNCHECKED4      = 0,
    GUARDED4        = 1,
    EXCLUSIVE4      = 2,
};

struct creatverfattr {
    verifier4      verifier;
    fattr4         attrs;
};

union createhow4 switch (createmode4 mode) {
    case UNCHECKED4:
    case GUARDED4:
        fattr4         attributes;
    case EXCLUSIVE4:
        verifier4      verifier;
    case EXCLUSIVE4_1:
        creatverfattr  createboth;
};

enum opentype4 {
    OPEN4_NOCREATE  = 0,
    OPEN4_CREATE    = 1
};

union openflag4 switch (opentype4 opentype) {
    case OPEN4_CREATE:
        createhow4     how;
    default:
        void;
};

/* Next definitions used for OPEN delegation */
enum limit_by4 {
    NFS_LIMIT_SIZE          = 1,
    NFS_LIMIT_BLOCKS        = 2
    /* others as needed */
};

struct nfs_modified_limit4 {
    uint32_t        num_blocks;
    uint32_t        bytes_per_block;
};

union nfs_space_limit4 switch (limit_by4 limitby) {
    /* limit specified as file size */
    case NFS_LIMIT_SIZE:
        uint64_t               filesize;
    /* limit specified by number of blocks */
    case NFS_LIMIT_BLOCKS:
        nfs_modified_limit4    mod_blocks;
};

/*
 * Share Access and Deny constants for open argument
 */
const OPEN4_SHARE_ACCESS_READ   = 0x00000001;
const OPEN4_SHARE_ACCESS_WRITE  = 0x00000002;
const OPEN4_SHARE_ACCESS_BOTH   = 0x00000003;

const OPEN4_SHARE_DENY_NONE     = 0x00000000;
const OPEN4_SHARE_DENY_READ     = 0x00000001;
const OPEN4_SHARE_DENY_WRITE    = 0x00000002;
const OPEN4_SHARE_DENY_BOTH     = 0x00000003;

/* New flags for share_access field of OPEN4args */
const OPEN4_SHARE_ACCESS_WANT_DELEG_MASK        = 0xFF00;
const OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE     = 0x0000;
const OPEN4_SHARE_ACCESS_WANT_READ_DELEG        = 0x0100;
const OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG       = 0x0200;
const OPEN4_SHARE_ACCESS_WANT_ANY_DELEG         = 0x0300;
const OPEN4_SHARE_ACCESS_WANT_NO_DELEG          = 0x0400;
const OPEN4_SHARE_ACCESS_WANT_CANCEL            = 0x0500;

const OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL = 0x10000;
const OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED = 0x20000;

enum open_delegation_type4 {
    OPEN_DELEGATE_NONE      = 0,
    OPEN_DELEGATE_READ      = 1,
    OPEN_DELEGATE_WRITE     = 2,
};

enum open_claim_type4 {
    /*
     * Not a reclaim.
     */
    CLAIM_NULL              = 0,

    CLAIM_PREVIOUS          = 1,
    CLAIM_DELEGATE_CUR      = 2,
    CLAIM_DELEGATE_PREV     = 3,
};

/* STRFMT1: {1} stid:{0} */
struct open_claim_delegate_cur4 {
    stateid4        stateid;
    component4      name;
};

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: DH:{fh:crc32}/{1} */
union open_claim4 switch (open_claim_type4 claim) {
    /*
     * No special rights to file.
     * Ordinary OPEN of the specified file.
     */
    case CLAIM_NULL:
        /* CURRENT_FH: directory */
        component4      name;

    /*
     * Right to the file established by an
     * open previous to server reboot. File
     * identified by filehandle obtained at
     * that time rather than by name.
     */
    case CLAIM_PREVIOUS:
        /* CURRENT_FH: file being reclaimed */
        /* STRFMT1: {0}:{fh:crc32} {1} */
        open_delegation_type4   deleg_type;

    /*
     * Right to file based on a delegation
     * granted by the server. File is
     * specified by name.
     */
    case CLAIM_DELEGATE_CUR:
        /* CURRENT_FH: directory */
        /* STRFMT1: {0} DH:{fh:crc32}/{1} */
        open_claim_delegate_cur4  deleg_info;

    /*
     * Right to file based on a delegation
     * granted to a previous boot instance
     * of the client.  File is specified by name.
     */
    case CLAIM_DELEGATE_PREV:
        /* CURRENT_FH: directory */
        /* STRFMT1: {0} DH:{fh:crc32}/{1} */
        component4      name;
};

/*
 * OPEN: Open a Regular File, Potentially Receiving an Open Delegation
 * ======================================================================
 */
/* STRFMT1: {5} acc:{1:#04x} deny:{2:#04x} */
struct OPEN4args {
    seqid4          seqid;
    uint32_t        access;
    uint32_t        deny;
    open_owner4     owner;
    openflag4       openhow;
    open_claim4     claim; /* FLATATTR:1 */
};

/* STRFMT1: rd_deleg_stid:{0} */
struct open_read_delegation4 {
    stateid4 stateid;    /* Stateid for delegation*/
    bool     recall;     /* Pre-recalled flag for delegations obtained by reclaim (CLAIM_PREVIOUS) */

    nfsace4 permissions; /* Defines users who don't need an ACCESS call to open for read */
};

/* STRFMT1: wr_deleg_stid:{0} */
struct open_write_delegation4 {
    stateid4 stateid;      /* Stateid for delegation */
    bool     recall;       /* Pre-recalled flag for delegations obtained by reclaim (CLAIM_PREVIOUS) */
    nfs_space_limit4 space_limit; /* Defines condition that the client must check to determine whether the file needs to be flushed to the server on close.  */
    nfsace4   permissions; /* Defines users who don't need an ACCESS call as part of a delegated open. */
};

/* STRFMT1: {1} */
union open_delegation4 switch (open_delegation_type4 deleg_type) {
        case OPEN_DELEGATE_NONE:
                void;
        case OPEN_DELEGATE_READ:
                open_read_delegation4 read;
        case OPEN_DELEGATE_WRITE:
                open_write_delegation4 write;
};

/*
 * Result flags
 */
/* Client must confirm open */
const OPEN4_RESULT_CONFIRM           = 0x00000002;
/* Type of file locking behavior at the server */
const OPEN4_RESULT_LOCKTYPE_POSIX    = 0x00000004;

/* STRFMT1: stid:{0} {4} */
/* CLASSATTR: _opdisp=const.OP_GETFH */
struct OPEN4resok {
    stateid4       stateid;      /* Stateid for open */
    change_info4   cinfo;        /* Directory Change Info */
    uint32_t       rflags;       /* Result flags */
    bitmap4        attrset;      /* attribute set for create*/
    open_delegation4 delegation; /* Info on any open delegation */
};

/* STRFMT1: {1} */
union OPEN4res switch (nfsstat4 status) {
    case NFS4_OK:
        /* New CURRENT_FH: opened file */
        OPEN4resok      resok;
    default:
        void;
};

/*
 * OPENATTR: Open Named Attributes Directory
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
struct OPENATTR4args {
    /* CURRENT_FH: object */
    bool    createdir;
};

struct OPENATTR4res {
    /*
     * If status is NFS4_OK,
     *   new CURRENT_FH: named attribute directory
     */
    nfsstat4        status;
};

/*
 * OPEN_CONFIRM: Confirm the Open
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
struct OPEN_CONFIRM4args {
    /* CURRENT_FH: opened file */
    stateid4        stateid;
    seqid4          seqid;
};

struct OPEN_CONFIRM4resok {
    stateid4        stateid;
};

union OPEN_CONFIRM4res switch (nfsstat4 status) {
    case NFS4_OK:
        OPEN_CONFIRM4resok     resok;
    default:
        void;
};

/*
 * OPEN_DOWNGRADE: Reduce Open File Access
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} acc:{2:#04x} deny:{3:#04x} */
struct OPEN_DOWNGRADE4args {
    /* CURRENT_FH: opened file */
    stateid4        stateid;
    seqid4          seqid;
    uint32_t        access;
    uint32_t        deny;
};

/* STRFMT1: stid:{0} */
struct OPEN_DOWNGRADE4resok {
    stateid4        stateid;
};

/* STRFMT1: {1} */
union OPEN_DOWNGRADE4res switch(nfsstat4 status) {
    case NFS4_OK:
        OPEN_DOWNGRADE4resok    resok;
    default:
        void;
};

/*
 * PUTFH: Set Current Filehandle
 * ======================================================================
 */
/* GLOBAL: nfs4_fh=fh */
struct PUTFH4args {
    nfs_fh4         fh;
};

struct PUTFH4res {
    /*
     * If status is NFS4_OK,
     *    new CURRENT_FH: argument to PUTFH
     */
    nfsstat4        status;
};

/*
 * PUTPUBFH: Set Public Filehandle
 * ======================================================================
 */
/* STRFMT1: "" */
struct PUTPUBFH4res {
    /*
     * If status is NFS4_OK,
     *   new CURRENT_FH: public fh
     */
    nfsstat4        status;
};

/*
 * PUTROOTFH: Set Root Filehandle
 * ======================================================================
 */
/* STRFMT1: "" */
struct PUTROOTFH4res {
    /*
     * If status is NFS4_OK,
     *   new CURRENT_FH: root fh
     */
    nfsstat4        status;
};

/*
 * READ: Read From File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} off:{1:umax64} len:{2:umax32} */
struct READ4args {
    /* CURRENT_FH: file */
    stateid4        stateid;
    offset4         offset;
    count4          count;
};

/* STRFMT1: eof:{0} count:{1:umax32} */
struct READ4resok {
    bool            eof;
    opaque          data<>; /* FOPAQUE:count */
};

/* STRFMT1: {1} */
union READ4res switch (nfsstat4 status) {
    case NFS4_OK:
        READ4resok     resok;
    default:
        void;
};

/*
 * READDIR: Read Directory
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: DH:{fh:crc32} cookie:{0} verf:{1} count:{2:umax32} */
struct READDIR4args {
    /* CURRENT_FH: directory */
    nfs_cookie4     cookie;
    verifier4       verifier;
    count4          dircount;
    count4          maxcount;
    bitmap4         request;
};

struct entry4 {
    nfs_cookie4     cookie;
    component4      name;
    fattr4          attrs;
    entry4          *nextentry;
};

/* TRY: 1 */
/* STRFMT1: eof:{1} */
struct dirlist4 {
    entry4          *entries;
    bool            eof;
};

/* STRFMT1: verf:{0} {1} */
struct READDIR4resok {
    verifier4       verifier;
    dirlist4        reply;
};

/* STRFMT1: {1} */
union READDIR4res switch (nfsstat4 status) {
    case NFS4_OK:
        READDIR4resok  resok;
    default:
        void;
};

/*
 * READLINK: Read Symbolic Link
 * ======================================================================
 */
/* STRFMT1: {0} */
struct READLINK4resok {
    linktext4       link;
};

/* STRFMT1: {1} */
union READLINK4res switch (nfsstat4 status) {
    case NFS4_OK:
        READLINK4resok resok;
    default:
        void;
};

/*
 * REMOVE: Remove Filesystem Object
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: DH:{fh:crc32}/{0} */
struct REMOVE4args {
    /* CURRENT_FH: directory */
    component4      name;
};

struct REMOVE4resok {
    change_info4    cinfo;
};

/* STRFMT1: "" */
union REMOVE4res switch (nfsstat4 status) {
    case NFS4_OK:
        REMOVE4resok   resok;
    default:
        void;
};

/*
 * RENAME: Rename Directory Entry
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh,sfh=self.nfs4_sfh */
/* STRFMT1: {sfh:crc32}/{0} -> {fh:crc32}/{1} */
struct RENAME4args {
    /* SAVED_FH: source directory */
    component4      name;
    /* CURRENT_FH: target directory */
    component4      newname;
};

/* STRFMT1: "" */
struct RENAME4resok {
    change_info4    source;
    change_info4    target;
};

/* STRFMT1: {1} */
union RENAME4res switch (nfsstat4 status) {
    case NFS4_OK:
        RENAME4resok    resok;
    default:
        void;
};

/*
 * RENEW: Renew a Lease
 * ======================================================================
 */
/* STRFMT1: clientid:{0} */
struct RENEW4args {
    clientid4       clientid;
};

struct RENEW4res {
    nfsstat4        status;
};

/*
 * RESTOREFH: Restore Saved Filehandle
 * ======================================================================
 */
struct RESTOREFH4res {
    /*
     * If status is NFS4_OK,
     *     new CURRENT_FH: value of saved fh
     */
    nfsstat4        status;
};

/*
 * SAVEFH: Save Current Filehandle
 * ======================================================================
 */
struct SAVEFH4res {
    /*
     * If status is NFS4_OK,
     *    new SAVED_FH: value of current fh
     */
    nfsstat4        status;
};

/*
 * SECINFO: Obtain Available Security Mechanisms
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: {fh:crc32}/{0} */
struct SECINFO4args {
    /* CURRENT_FH: directory */
    component4      name;
};

enum nfs_secflavor4 {
    AUTH_NONE  = 0;
    AUTH_SYS   = 1;
    RPCSEC_GSS = 6;
};

/*
 * From RFC 2203
 */
enum rpc_gss_svc_t {
    RPC_GSS_SVC_NONE        = 1,
    RPC_GSS_SVC_INTEGRITY   = 2,
    RPC_GSS_SVC_PRIVACY     = 3
};

struct rpcsec_gss_info {
    sec_oid4        oid;
    qop4            qop;
    rpc_gss_svc_t   service;
};

/* RPCSEC_GSS has a value of '6' - See RFC 2203 */
/* STRFMT1: {0} */
union secinfo4 switch (nfs_secflavor4 flavor) {
    case RPCSEC_GSS:
        rpcsec_gss_info  info;
    default:
        void;
};

typedef secinfo4 SECINFO4resok<>;

/* STRFMT1: {1} */
union SECINFO4res switch (nfsstat4 status) {
    case NFS4_OK:
        /* CURRENTFH: consumed */
        SECINFO4resok resok;
    default:
        void;
};

/*
 * SETATTR: Set Attributes
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} */
struct SETATTR4args {
    /* CURRENT_FH: target object */
    stateid4        stateid;
    fattr4          attributes;
};

/* STRFMT1: attrset:{1} */
struct SETATTR4res {
    nfsstat4        status;
    bitmap4         attrset;
};

/*
 * Client ID
 */
struct nfs_client_id4 {
    verifier4  verifier;
    opaque     id<NFS4_OPAQUE_LIMIT>;
};

/*
 * Callback program info as provided by the client
 */
struct cb_client4 {
    uint32_t  cb_program;
    netaddr4  cb_location;
};

/*
 * SETCLIENTID: Negotiate Clientid
 * ======================================================================
 */
/* STRFMT1: "" */
struct SETCLIENTID4args {
    nfs_client_id4  client;
    cb_client4      callback;
    uint32_t        callback_ident;
};

/* STRFMT1: clientid:{0} */
struct SETCLIENTID4resok {
    clientid4       clientid;
    verifier4       verifier;
};

/* STRFMT1: {1} */
union SETCLIENTID4res switch (nfsstat4 status) {
    case NFS4_OK:
        SETCLIENTID4resok resok;
    case NFS4ERR_CLID_INUSE:
        /* STRFMT1: "" */
        clientaddr4       client;
    default:
        void;
};

/*
 * SETCLIENTID_CONFIRM: Confirm Clientid
 * ======================================================================
*/
/* STRFMT1: clientid:{0} */
struct SETCLIENTID_CONFIRM4args {
    clientid4       clientid;
    verifier4       verifier;
};

struct SETCLIENTID_CONFIRM4res {
    nfsstat4        status;
};

/*
 * VERIFY: Verify Same Attributes
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
struct VERIFY4args {
    /* CURRENT_FH: object */
    fattr4          attributes;
};

struct VERIFY4res {
    nfsstat4        status;
};

/*
 * WRITE: Write to File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} off:{1:umax64} len:{3:umax32} {2} */
struct WRITE4args {
    /* CURRENT_FH: file */
    stateid4        stateid;
    offset4         offset;
    stable_how4     stable;
    opaque          data<>; /* FOPAQUE:count */
};

/* STRFMT1: count:{0:umax32} verf:{2} {1} */
struct WRITE4resok {
    count4          count;
    stable_how4     committed;
    verifier4       verifier;
};

/* STRFMT1: {1} */
union WRITE4res switch (nfsstat4 status) {
    case NFS4_OK:
        WRITE4resok    resok;
    default:
        void;
};

/*
 * RELEASE_LOCKOWNER: Notify Server to Release Lockowner State
 * ======================================================================
 */
struct RELEASE_LOCKOWNER4args {
    lock_owner4     owner;
};

struct RELEASE_LOCKOWNER4res {
    nfsstat4        status;
};

/*
 * ILLEGAL: Response for Illegal Operation Numbers
 * ======================================================================
 */
struct ILLEGAL4res {
    nfsstat4        status;
};

/* OBJATTR: op=argop */
/* STRFMT1: {1} */
/* STRFMT2: {1} */
union nfs_argop4 switch (nfs_opnum4 argop) {
    case OP_ACCESS:
        ACCESS4args opaccess;
    case OP_CLOSE:
        CLOSE4args opclose;
    case OP_COMMIT:
        COMMIT4args opcommit;
    case OP_CREATE:
        CREATE4args opcreate;
    case OP_DELEGPURGE:
        DELEGPURGE4args opdelegpurge;
    case OP_DELEGRETURN:
        DELEGRETURN4args opdelegreturn;
    case OP_GETATTR:
        GETATTR4args opgetattr;
    case OP_GETFH:
        /* STRFMT2: GETFH4args() */
        void;
    case OP_LINK:
        LINK4args oplink;
    case OP_LOCK:
        LOCK4args oplock;
    case OP_LOCKT:
        LOCKT4args oplockt;
    case OP_LOCKU:
        LOCKU4args oplocku;
    case OP_LOOKUP:
        LOOKUP4args oplookup;
    case OP_LOOKUPP:
        /* STRFMT2: LOOKUPP4args() */
        void;
    case OP_NVERIFY:
        NVERIFY4args opnverify;
    case OP_OPEN:
        OPEN4args opopen;
    case OP_OPENATTR:
        OPENATTR4args opopenattr;
    case OP_OPEN_CONFIRM:
        OPEN_CONFIRM4args opopen_confirm;
    case OP_OPEN_DOWNGRADE:
        OPEN_DOWNGRADE4args opopen_downgrade;
    case OP_PUTFH:
        PUTFH4args opputfh;
    case OP_PUTPUBFH:
        /* STRFMT2: PUTPUBFH4args() */
        void;
    case OP_PUTROOTFH:
        /* STRFMT2: PUTROOTFH4args() */
        void;
    case OP_READ:
        READ4args opread;
    case OP_READDIR:
        READDIR4args opreaddir;
    case OP_READLINK:
        /* OBJATTR: fh=self.nfs4_fh */
        /* STRFMT1: FH:{fh:crc32} */
        /* STRFMT2: READLINK4args() */
        void;
    case OP_REMOVE:
        REMOVE4args opremove;
    case OP_RENAME:
        RENAME4args oprename;
    case OP_RENEW:
        RENEW4args oprenew;
    case OP_RESTOREFH:
        /* GLOBAL: nfs4_fh=self.nfs4_sfh */
        /* STRFMT2: RESTOREFH4args() */
        void;
    case OP_SAVEFH:
        /* GLOBAL: nfs4_sfh=self.nfs4_fh */
        /* STRFMT2: SAVEFH4args() */
        void;
    case OP_SECINFO:
        SECINFO4args opsecinfo;
    case OP_SETATTR:
        SETATTR4args opsetattr;
    case OP_SETCLIENTID:
        SETCLIENTID4args opsetclientid;
    case OP_SETCLIENTID_CONFIRM:
        SETCLIENTID_CONFIRM4args opsetclientid_confirm;
    case OP_VERIFY:
        VERIFY4args opverify;
    case OP_WRITE:
        WRITE4args opwrite;
    case OP_RELEASE_LOCKOWNER:
        RELEASE_LOCKOWNER4args oprelease_lockowner;
    case OP_ILLEGAL:
        /* Illegal operation */
        /* STRFMT2: ILLEGAL4args() */
        void;
};

/* OBJATTR: op=resop */
/* STRFMT1: {1} */
/* STRFMT2: {1} */
union nfs_resop4 switch (nfs_opnum4 resop){
    case OP_ACCESS:
        ACCESS4res opaccess;
    case OP_CLOSE:
        CLOSE4res opclose;
    case OP_COMMIT:
        COMMIT4res opcommit;
    case OP_CREATE:
        CREATE4res opcreate;
    case OP_DELEGPURGE:
        DELEGPURGE4res opdelegpurge;
    case OP_DELEGRETURN:
        DELEGRETURN4res opdelegreturn;
    case OP_GETATTR:
        GETATTR4res opgetattr;
    case OP_GETFH:
        GETFH4res opgetfh;
    case OP_LINK:
        LINK4res oplink;
    case OP_LOCK:
        LOCK4res oplock;
    case OP_LOCKT:
        LOCKT4res oplockt;
    case OP_LOCKU:
        LOCKU4res oplocku;
    case OP_LOOKUP:
        LOOKUP4res oplookup;
    case OP_LOOKUPP:
        LOOKUPP4res oplookupp;
    case OP_NVERIFY:
        NVERIFY4res opnverify;
    case OP_OPEN:
        OPEN4res opopen;
    case OP_OPENATTR:
        OPENATTR4res opopenattr;
    case OP_OPEN_CONFIRM:
        OPEN_CONFIRM4res opopen_confirm;
    case OP_OPEN_DOWNGRADE:
        OPEN_DOWNGRADE4res opopen_downgrade;
    case OP_PUTFH:
        PUTFH4res opputfh;
    case OP_PUTPUBFH:
        PUTPUBFH4res opputpubfh;
    case OP_PUTROOTFH:
        PUTROOTFH4res opputrootfh;
    case OP_READ:
        READ4res opread;
    case OP_READDIR:
        READDIR4res opreaddir;
    case OP_READLINK:
        READLINK4res opreadlink;
    case OP_REMOVE:
        REMOVE4res opremove;
    case OP_RENAME:
        RENAME4res oprename;
    case OP_RENEW:
        RENEW4res oprenew;
    case OP_RESTOREFH:
        RESTOREFH4res oprestorefh;
    case OP_SAVEFH:
        SAVEFH4res opsavefh;
    case OP_SECINFO:
        SECINFO4res opsecinfo;
    case OP_SETATTR:
        SETATTR4res opsetattr;
    case OP_SETCLIENTID:
        SETCLIENTID4res opsetclientid;
    case OP_SETCLIENTID_CONFIRM:
        SETCLIENTID_CONFIRM4res opsetclientid_confirm;
    case OP_VERIFY:
        VERIFY4res opverify;
    case OP_WRITE:
        WRITE4res opwrite;
    case OP_RELEASE_LOCKOWNER:
        RELEASE_LOCKOWNER4res oprelease_lockowner;
    case OP_ILLEGAL:
        /* Illegal operation */
        ILLEGAL4res opillegal;
};

/* INHERIT: packet.nfs.nfsbase.NFSbase */
/* GLOBAL: nfs4_fh=None */
/* STRFMT2: COMPOUND4 tag={0!r}, minorversion={1}, array={2} */
struct COMPOUND4args {
    utf8str_cs      tag;
    uint32_t        minorversion;
    nfs_argop4      array<>;
};

/* INHERIT: packet.nfs.nfsbase.NFSbase */
/* GLOBAL: nfs4_fh=None */
/* XARG: minorversion */
/* STRFMT2: COMPOUND4 status={0}, tag={1!r}, array={2} */
struct COMPOUND4res {
    nfsstat4        status;
    utf8str_cs      tag;
    nfs_resop4      array<>;
};

/*
 * ======================================================================
 * NFS4 Callback Operation Definitions
 * ======================================================================
 */

/*
 * Callback operation array
 */
enum nfs_cb_opnum4 {
    OP_CB_GETATTR               = 3,
    OP_CB_RECALL                = 4,
    /* Illegal callback operation */
    OP_CB_ILLEGAL               = 10044
};

/*
 * CB_GETATTR: Get Attributes of a File That Has Been Write Delegated
 * ======================================================================
 */
/* STRFMT1: FH:{0:crc32} request:{1} */
struct CB_GETATTR4args {
    nfs_fh4 fh;
    bitmap4 request;
};

struct CB_GETATTR4resok {
    fattr4  attributes;
};

/* STRFMT1: "" */
union CB_GETATTR4res switch (nfsstat4 status) {
    case NFS4_OK:
        CB_GETATTR4resok       resok;
    default:
        void;
};

/*
 * CB_RECALL: Recall an Open Delegation
 * ======================================================================
 */
/* STRFMT1: FH:{2:crc32} stid:{0} trunc:{1} */
struct CB_RECALL4args {
    stateid4        stateid;
    bool            truncate;
    nfs_fh4         fh;
};

/* STRFMT1: "" */
struct CB_RECALL4res {
    nfsstat4        status;
};

/*
 * CB_ILLEGAL: Response for illegal operation numbers
 * ======================================================================
 */
struct CB_ILLEGAL4res {
    nfsstat4        status;
};

/* OBJATTR: op=argop */
/* STRFMT1: {1} */
/* STRFMT2: {1} */
union nfs_cb_argop4 switch (nfs_cb_opnum4 argop) {
    case OP_CB_GETATTR:
        CB_GETATTR4args opcbgetattr;
    case OP_CB_RECALL:
        CB_RECALL4args opcbrecall;
    case OP_CB_ILLEGAL:
        /* Illegal callback operation */
        void;
};

/* OBJATTR: op=resop */
/* STRFMT1: {1} */
/* STRFMT2: {1} */
union nfs_cb_resop4 switch (nfs_cb_opnum4 resop){
    case OP_CB_GETATTR:
        CB_GETATTR4res opcbgetattr;
    case OP_CB_RECALL:
        CB_RECALL4res opcbrecall;
    case OP_CB_ILLEGAL:
        /* Illegal callback operation */
        CB_ILLEGAL4res opcbillegal;
};

/* INHERIT: packet.nfs.nfsbase.NFSbase */
/* GLOBAL: nfs4_fh=None */
/* STRFMT2: CB_COMPOUND4 tag={0!r}, minorversion={1}, callback_ident={2:#010x}, array={3} */
struct CB_COMPOUND4args {
    utf8str_cs      tag;
    uint32_t        minorversion;
    uint32_t        callback_ident;
    nfs_cb_argop4   array<>;
};

/* INHERIT: packet.nfs.nfsbase.NFSbase */
/* GLOBAL: nfs4_fh=None */
/* XARG: minorversion */
/* STRFMT2: CB_COMPOUND4 status={0}, tag={1!r}, array={2} */
struct CB_COMPOUND4res {
    nfsstat4 status;
    utf8str_cs      tag;
    nfs_cb_resop4   array<>;
};
