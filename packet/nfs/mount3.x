/*
 * Copyright (c) 1995
 *
 * MOUNT Version 3 Protocol Specification
 * The document authors are identified in RFC 1813
 *
 *=====================================================================
 * This Document was changed to add directives for converting
 * it to python code. Also the name of some variables were
 * changed to be consistent throughout this document and to
 * have a similar interface with other protocols.
 *=====================================================================
 */
/* COPYRIGHT: 2014 */

/*
 * Sizes
 */
const MNTPATHLEN = 1024;  /* Maximum bytes in a path name */
const MNTNAMLEN  = 255;   /* Maximum bytes in a name */
const FHSIZE3    = 64;    /* Maximum bytes in a V3 file handle */

/*
 * Basic Data Types
 */
typedef opaque fhandle3<FHSIZE3>; /* STRHEX:1 */
typedef string dirpath3<MNTPATHLEN>;
typedef string name3<MNTNAMLEN>;

enum mountstat3 {
    MNT3_OK = 0,                 /* no error */
    MNT3ERR_PERM = 1,            /* Not owner */
    MNT3ERR_NOENT = 2,           /* No such file or directory */
    MNT3ERR_IO = 5,              /* I/O error */
    MNT3ERR_ACCES = 13,          /* Permission denied */
    MNT3ERR_NOTDIR = 20,         /* Not a directory */
    MNT3ERR_INVAL = 22,          /* Invalid argument */
    MNT3ERR_NAMETOOLONG = 63,    /* Filename too long */
    MNT3ERR_NOTSUPP = 10004,     /* Operation not supported */
    MNT3ERR_SERVERFAULT = 10006  /* A failure on the server */
};

enum rpc_auth_flavors {
    AUTH_NULL  = 0,
    AUTH_UNIX  = 1,
    AUTH_SHORT = 2,
    AUTH_DES   = 3,
    AUTH_KRB   = 4,
    AUTH_GSS   = 6,
    AUTH_MAXFLAVOR = 8,
    /* pseudoflavors: */
    AUTH_GSS_KRB5  = 390003,
    AUTH_GSS_KRB5I = 390004,
    AUTH_GSS_KRB5P = 390005,
    AUTH_GSS_LKEY  = 390006,
    AUTH_GSS_LKEYI = 390007,
    AUTH_GSS_LKEYP = 390008,
    AUTH_GSS_SPKM  = 390009,
    AUTH_GSS_SPKMI = 390010,
    AUTH_GSS_SPKMP = 390011,
};

/*
 * MNT3res MOUNTPROC3_MNT(dirpath3) = 1;
 */
/* STRFMT1: {0} */
struct MNT3args {
    dirpath3 path;
};

/* STRFMT1: FH:{0:crc32} auth_flavors:{1} */
struct MNT3resok {
    fhandle3    fh;
    rpc_auth_flavors auth_flavors<>;
};

/* STRFMT1: {1} */
union MNT3res switch (mountstat3 status) {
    case MNT3_OK:
        MNT3resok  mountinfo;
    default:
        void;
};

/*
 * mountlist MOUNTPROC3_DUMP(void) = 2;
 */
struct mountentry {
    name3       hostname;
    dirpath3    directory;
    mountentry  *next;
};

/* STRFMT1: "" */
struct DUMP3res {
    mountentry *mountlist;
};

/*
 * void MOUNTPROC3_UMNT(dirpath3) = 3;
 */
/* STRFMT1: {0} */
struct UMNT3args {
    dirpath3 path;
};

/*
 * void MOUNTPROC3_UMNTALL(void) = 4;
 */

/*
 * EXPORT3res MOUNTPROC3_EXPORT(void) = 5;
 */
struct exportnode3 {
    dirpath3    dir;
    name3       *groups;
    exportnode3 *next;
};

/* STRFMT1: "" */
struct EXPORT3res {
    exportnode3 *exports;
};

/* Procedures */
enum mount_proc3 {
    MOUNTPROC3_NULL    = 0,
    MOUNTPROC3_MNT     = 1,
    MOUNTPROC3_DUMP    = 2,
    MOUNTPROC3_UMNT    = 3,
    MOUNTPROC3_UMNTALL = 4,
    MOUNTPROC3_EXPORT  = 5,
};

/*
 * Version 3 of the mount protocol used with
 * version 3 of the NFS protocol.
 */
/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _pindex=11,_strname="MOUNT" */
/* OBJATTR: argop=procedure,op=procedure */
union MOUNT3args switch (mount_proc3 procedure) {
    case MOUNTPROC3_NULL:    void; /* STRFMT2: NULL() */
    case MOUNTPROC3_MNT:     MNT3args opmnt;
    case MOUNTPROC3_DUMP:    void; /* STRFMT2: DUMP3args() */
    case MOUNTPROC3_UMNT:    UMNT3args opumnt;
    case MOUNTPROC3_UMNTALL: void; /* STRFMT2: UMNTALL3args() */
    case MOUNTPROC3_EXPORT:  void; /* STRFMT2: EXPORT3args() */
};

/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _pindex=11,_strname="MOUNT" */
/* OBJATTR: resop=procedure,op=procedure */
union MOUNT3res switch (mount_proc3 procedure) {
    case MOUNTPROC3_NULL:    void; /* STRFMT2: NULL() */
    case MOUNTPROC3_MNT:     MNT3res    opmnt;
    case MOUNTPROC3_DUMP:    DUMP3res   opdump;
    case MOUNTPROC3_UMNT:    void; /* STRFMT2: UMNT3res() */
    case MOUNTPROC3_UMNTALL: void; /* STRFMT2: UMNTALL3res() */
    case MOUNTPROC3_EXPORT:  EXPORT3res opexport;
};

program MOUNT_PROGRAM {
    /*
     * Version 3 of the mount protocol used with
     * version 3 of the NFS protocol.
     */
    version MOUNT {
        void       MOUNTPROC3_NULL(void)      = 0;
        MNT3res    MOUNTPROC3_MNT(MNT3args)   = 1;
        DUMP3res   MOUNTPROC3_DUMP(void)      = 2;
        void       MOUNTPROC3_UMNT(UMNT3args) = 3;
        void       MOUNTPROC3_UMNTALL(void)   = 4;
        EXPORT3res MOUNTPROC3_EXPORT(void)    = 5;
    } = 3;
} = 100005;
