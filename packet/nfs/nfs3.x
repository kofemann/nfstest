/*
 * Copyright (c) 1995
 *
 * NFS Version 3 Protocol Specification
 * The document authors are identified in RFC 1813
 *
 *=====================================================================
 * This Document was changed to add directives for converting
 * it to python code. Also the name of some variables were
 * changed to be consistent throughout this document and to
 * have a similar interface with other versions of NFS.
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
const NFS3_FHSIZE         = 64;
const NFS3_COOKIEVERFSIZE = 8;
const NFS3_CREATEVERFSIZE = 8;
const NFS3_WRITEVERFSIZE  = 8;

/*
 * Basic data types
 */
typedef unsigned hyper uint64;
typedef hyper          int64;
typedef unsigned int   uint32;
typedef int            int32;
typedef string         filename3<>;
typedef string         nfspath3<>;
typedef uint64         fileid3;
typedef uint64         cookie3;
typedef opaque         cookieverf3[NFS3_COOKIEVERFSIZE]; /* STRHEX:1 */
typedef opaque         createverf3[NFS3_CREATEVERFSIZE]; /* STRHEX:1 */
typedef opaque         writeverf3[NFS3_WRITEVERFSIZE];   /* STRHEX:1 */
typedef uint32         uid3;
typedef uint32         gid3;
typedef uint64         size3;
typedef uint64         offset3;
typedef uint32         mode3;
typedef uint32         count3;
typedef opaque         nfs_fh3<NFS3_FHSIZE>; /* STRHEX:1 */
typedef uint32         access3;

/*
 * Error status
 */
enum nfsstat3 {
        NFS3_OK             = 0,
        NFS3ERR_PERM        = 1,
        NFS3ERR_NOENT       = 2,
        NFS3ERR_IO          = 5,
        NFS3ERR_NXIO        = 6,
        NFS3ERR_ACCES       = 13,
        NFS3ERR_EXIST       = 17,
        NFS3ERR_XDEV        = 18,
        NFS3ERR_NODEV       = 19,
        NFS3ERR_NOTDIR      = 20,
        NFS3ERR_ISDIR       = 21,
        NFS3ERR_INVAL       = 22,
        NFS3ERR_FBIG        = 27,
        NFS3ERR_NOSPC       = 28,
        NFS3ERR_ROFS        = 30,
        NFS3ERR_MLINK       = 31,
        NFS3ERR_NAMETOOLONG = 63,
        NFS3ERR_NOTEMPTY    = 66,
        NFS3ERR_DQUOT       = 69,
        NFS3ERR_STALE       = 70,
        NFS3ERR_REMOTE      = 71,
        NFS3ERR_BADHANDLE   = 10001,
        NFS3ERR_NOT_SYNC    = 10002,
        NFS3ERR_BAD_COOKIE  = 10003,
        NFS3ERR_NOTSUPP     = 10004,
        NFS3ERR_TOOSMALL    = 10005,
        NFS3ERR_SERVERFAULT = 10006,
        NFS3ERR_BADTYPE     = 10007,
        NFS3ERR_JUKEBOX     = 10008
};

enum ftype3 {
        NF3REG   = 1,
        NF3DIR   = 2,
        NF3BLK   = 3,
        NF3CHR   = 4,
        NF3LNK   = 5,
        NF3SOCK  = 6,
        NF3FIFO  = 7
};

/* STRFMT1: major:{0} minor:{1} */
struct specdata3 {
        uint32  specdata1;
        uint32  specdata2;
};

/* STRFMT1: {0}.{1:09} */
struct nfstime3 {
        uint32  seconds;
        uint32  nseconds;
};

/* STRFMT1: {0} mode:{1:04o} nlink:{2} uid:{3} gid:{4} size:{5} fileid:{9} */
struct fattr3 {
        ftype3     type;
        mode3      mode;
        uint32     nlink;
        uid3       uid;
        gid3       gid;
        size3      size;
        size3      used;
        specdata3  rdev;
        uint64     fsid;
        fileid3    fileid;
        nfstime3   atime;
        nfstime3   mtime;
        nfstime3   ctime;
};

union post_op_attr switch (bool attributes_follow) {
    case TRUE:
        fattr3  attributes;
    case FALSE:
        void;
};

struct wcc_attr {
        size3     size;
        nfstime3  mtime;
        nfstime3  ctime;
};

union pre_op_attr switch (bool attributes_follow) {
    case TRUE:
        wcc_attr  attributes;
    case FALSE:
        void;
};

struct wcc_data {
        pre_op_attr   before;
        post_op_attr  after;
};

/* STRFMT1: FH:{1:crc32} */
union post_op_fh3 switch (bool handle_follows) {
    case TRUE:
        nfs_fh3  fh;
    case FALSE:
        /* STRFMT1: "" */
        void;
};

enum time_how {
        DONT_CHANGE        = 0,
        SET_TO_SERVER_TIME = 1,
        SET_TO_CLIENT_TIME = 2
};

/* STRFMT1: mode:{1:04o}\x20 */
union set_mode3 switch (bool set_it) {
    case TRUE:
        mode3  mode;
    default:
        /* STRFMT1: "" */
        void;
};

/* STRFMT1: uid:{1}\x20 */
union set_uid3 switch (bool set_it) {
    case TRUE:
        uid3  uid;
    default:
        /* STRFMT1: "" */
        void;
};

/* STRFMT1: gid:{1}\x20 */
union set_gid3 switch (bool set_it) {
    case TRUE:
        gid3  gid;
    default:
        /* STRFMT1: "" */
        void;
};

/* STRFMT1: size:{1}\x20 */
union set_size3 switch (bool set_it) {
    case TRUE:
        size3  size;
    default:
        /* STRFMT1: "" */
        void;
};

/* STRFMT1: atime:{1}\x20 */
union set_atime switch (time_how set_it) {
    case SET_TO_CLIENT_TIME:
        nfstime3  atime;
    default:
        /* STRFMT1: "" */
        void;
};

/* STRFMT1: mtime:{1}\x20 */
union set_mtime switch (time_how set_it) {
    case SET_TO_CLIENT_TIME:
        nfstime3  mtime;
    default:
        /* STRFMT1: "" */
        void;
};

/* STRFMT1: {0}{1}{2}{3} */
struct sattr3 {
        set_mode3  mode;
        set_uid3   uid;
        set_gid3   gid;
        set_size3  size;
        set_atime  atime;
        set_mtime  mtime;
};

/* STRFMT1: DH:{0:crc32}/{1} */
struct diropargs3 {
        nfs_fh3    fh;
        filename3  name;
};

/*
 * GETATTR3res NFSPROC3_GETATTR(GETATTR3args) = 1;
 */
/* STRFMT1: FH:{0:crc32} */
struct GETATTR3args {
        nfs_fh3  fh;
};

/* STRFMT1: {0} */
struct GETATTR3resok {
        fattr3  attributes;
};

/* STRFMT1: {1} */
union GETATTR3res switch (nfsstat3 status) {
    case NFS3_OK:
        GETATTR3resok  resok;
    default:
        void;
};

/*
 * SETATTR3res NFSPROC3_SETATTR(SETATTR3args) = 2;
 */
union sattrguard3 switch (bool check) {
    case TRUE:
        nfstime3  ctime;
    case FALSE:
        void;
};

/* STRFMT1: FH:{0:crc32} {1} */
struct SETATTR3args {
        nfs_fh3      fh;
        sattr3       attributes;
        sattrguard3  guard;
};

struct SETATTR3resok {
        wcc_data  wcc;
};

struct SETATTR3resfail {
        wcc_data  wcc;
};

/* STRFMT1: "" */
union SETATTR3res switch (nfsstat3 status) {
    case NFS3_OK:
        SETATTR3resok   resok;
    default:
        SETATTR3resfail resfail;
};

/*
 * LOOKUP3res NFSPROC3_LOOKUP(LOOKUP3args) = 3;
 */
/* STRFMT1: {0} */
struct LOOKUP3args {
        diropargs3  what; /* FLATATTR:1 */
};

/* STRFMT1: FH:{0:crc32} */
struct LOOKUP3resok {
        nfs_fh3       fh;
        post_op_attr  attributes;
        post_op_attr  dir_attributes;
};

struct LOOKUP3resfail {
        post_op_attr  dir_attributes;
};

/* STRFMT1: {1} */
union LOOKUP3res switch (nfsstat3 status) {
    case NFS3_OK:
        LOOKUP3resok    resok;
    default:
        /* STRFMT1: "" */
        LOOKUP3resfail  resfail;
};

/*
 * ACCESS3res NFSPROC3_ACCESS(ACCESS3args) = 4;
 */
const ACCESS3_READ    = 0x0001;
const ACCESS3_LOOKUP  = 0x0002;
const ACCESS3_MODIFY  = 0x0004;
const ACCESS3_EXTEND  = 0x0008;
const ACCESS3_DELETE  = 0x0010;
const ACCESS3_EXECUTE = 0x0020;

/* STRFMT1: FH:{0:crc32} acc:{1:#04x} */
struct ACCESS3args {
        nfs_fh3  fh;
        access3  access;
};

/* STRFMT1: acc:{1:#04x} */
struct ACCESS3resok {
        post_op_attr  attributes;
        access3       access;
};

struct ACCESS3resfail {
        post_op_attr  attributes;
};

/* STRFMT1: {1} */
union ACCESS3res switch (nfsstat3 status) {
    case NFS3_OK:
        ACCESS3resok   resok;
    default:
        /* STRFMT1: "" */
        ACCESS3resfail resfail;
};

/*
 * READLINK3res NFSPROC3_READLINK(READLINK3args) = 5;
 */
/* STRFMT1: FH:{0:crc32} */
struct READLINK3args {
        nfs_fh3  fh;
};

/* STRFMT1: {1} */
struct READLINK3resok {
        post_op_attr  attributes;
        nfspath3      link;
};

struct READLINK3resfail {
        post_op_attr  attributes;
};

/* STRFMT1: {1} */
union READLINK3res switch (nfsstat3 status) {
    case NFS3_OK:
        READLINK3resok   resok;
    default:
        /* STRFMT1: "" */
        READLINK3resfail resfail;
};

/*
 * READ3res NFSPROC3_READ(READ3args) = 6;
 */
/* STRFMT1: FH:{0:crc32} off:{1:umax64} len:{2:umax32} */
struct READ3args {
        nfs_fh3  fh;
        offset3  offset;
        count3   count;
};

/* STRFMT1: eof:{2} count:{1:umax32} */
struct READ3resok {
        post_op_attr  attributes;
        count3        count;
        bool          eof;
        opaque        data<>;
};

struct READ3resfail {
        post_op_attr  file_attributes;
};

/* STRFMT1: {1} */
union READ3res switch (nfsstat3 status) {
    case NFS3_OK:
        READ3resok   resok;
    default:
        /* STRFMT1: "" */
        READ3resfail resfail;
};

/*
 * WRITE3res NFSPROC3_WRITE(WRITE3args) = 7;
 */
enum stable_how {
        UNSTABLE  = 0,
        DATA_SYNC = 1,
        FILE_SYNC = 2
};

/* STRFMT1: FH:{0:crc32} off:{1:umax64} len:{2:umax32} {3} */
struct WRITE3args {
        nfs_fh3     fh;
        offset3     offset;
        count3      count;
        stable_how  stable;
        opaque      data<>;
};

/* STRFMT1: count:{1:umax32} verf:{3} {2} */
struct WRITE3resok {
        wcc_data    wcc;
        count3      count;
        stable_how  committed;
        writeverf3  verifier;
};

struct WRITE3resfail {
        wcc_data  wcc;
};

/* STRFMT1: {1} */
union WRITE3res switch (nfsstat3 status) {
    case NFS3_OK:
        WRITE3resok    resok;
    default:
        /* STRFMT1: "" */
        WRITE3resfail  resfail;
};

/*
 * CREATE3res NFSPROC3_CREATE(CREATE3args) = 8;
 */
enum createmode3 {
        UNCHECKED = 0,
        GUARDED   = 1,
        EXCLUSIVE = 2
};

/* STRFMT1: {0} */
union createhow3 switch (createmode3 mode) {
    case UNCHECKED:
    case GUARDED:
        sattr3  attributes;
    case EXCLUSIVE:
        createverf3  verifier;
};

/* STRFMT1: {0} {1} */
struct CREATE3args {
        diropargs3  where; /* FLATATTR:1 */
        createhow3  how;
};

/* STRFMT1: {0} */
struct CREATE3resok {
        post_op_fh3   obj; /* FLATATTR:1 */
        post_op_attr  attributes;
        wcc_data      wcc;
};

struct CREATE3resfail {
        wcc_data  wcc;
};

/* STRFMT1: {1} */
union CREATE3res switch (nfsstat3 status) {
    case NFS3_OK:
        CREATE3resok    resok;
    default:
        /* STRFMT1: "" */
        CREATE3resfail  resfail;
};

/*
 * MKDIR3res NFSPROC3_MKDIR(MKDIR3args) = 9;
 */
/* STRFMT1: {0} {1} */
struct MKDIR3args {
        diropargs3  where; /* FLATATTR:1 */
        sattr3      attributes;
};

/* STRFMT1: {0} */
struct MKDIR3resok {
        post_op_fh3   obj; /* FLATATTR:1 */
        post_op_attr  attributes;
        wcc_data      wcc;
};

struct MKDIR3resfail {
        wcc_data  wcc;
};

/* STRFMT1: {1} */
union MKDIR3res switch (nfsstat3 status) {
    case NFS3_OK:
        MKDIR3resok   resok;
    default:
        /* STRFMT1: "" */
        MKDIR3resfail resfail;
};

/*
 * SYMLINK3res NFSPROC3_SYMLINK(SYMLINK3args) = 10;
 */
/* STRFMT1: {1} {0} */
struct symlinkdata3 {
        sattr3    attributes;
        nfspath3  linkdata;
};

/* STRFMT1: {0} -> {1} */
struct SYMLINK3args {
        diropargs3    where; /* FLATATTR:1 */
        symlinkdata3  symlink;
};

/* STRFMT1: {0} */
struct SYMLINK3resok {
        post_op_fh3   obj; /* FLATATTR:1 */
        post_op_attr  attributes;
        wcc_data      wcc;
};

struct SYMLINK3resfail {
        wcc_data  dir_wcc;
};

/* STRFMT1: {1} */
union SYMLINK3res switch (nfsstat3 status) {
    case NFS3_OK:
        SYMLINK3resok   resok;
    default:
        /* STRFMT1: "" */
        SYMLINK3resfail resfail;
};

/*
 * MKNOD3res NFSPROC3_MKNOD(MKNOD3args) = 11;
 */
/* STRFMT1: {0} {1} */
struct devicedata3 {
        sattr3     attributes;
        specdata3  spec;
};

/* STRFMT1: "" */
union mknoddata3 switch (ftype3 type) {
    case NF3CHR:
    case NF3BLK:
        /* STRFMT1: {1} */
        devicedata3  device;
    case NF3SOCK:
    case NF3FIFO:
        sattr3       attributes;
    default:
        void;
};

/* STRFMT1: {1.type} {0} {1} */
struct MKNOD3args {
        diropargs3  where; /* FLATATTR:1 */
        mknoddata3  what;
};

/* STRFMT1: {0} */
struct MKNOD3resok {
        post_op_fh3   obj; /* FLATATTR:1 */
        post_op_attr  attributes;
        wcc_data      wcc;
};

struct MKNOD3resfail {
        wcc_data  wcc;
};

/* STRFMT1: {1} */
union MKNOD3res switch (nfsstat3 status) {
    case NFS3_OK:
        MKNOD3resok   resok;
    default:
        /* STRFMT1: "" */
        MKNOD3resfail resfail;
};

/*
 * REMOVE3res NFSPROC3_REMOVE(REMOVE3args) = 12;
 */
/* STRFMT1: {0} */
struct REMOVE3args {
        diropargs3  object; /* FLATATTR:1 */
};

struct REMOVE3resok {
        wcc_data  wcc;
};

struct REMOVE3resfail {
        wcc_data  wcc;
};

/* STRFMT1: "" */
union REMOVE3res switch (nfsstat3 status) {
    case NFS3_OK:
        REMOVE3resok   resok;
    default:
        REMOVE3resfail resfail;
};

/*
 * RMDIR3res NFSPROC3_RMDIR(RMDIR3args) = 13;
 */
/* STRFMT1: {0} */
struct RMDIR3args {
        diropargs3  object; /* FLATATTR:1 */
};

struct RMDIR3resok {
        wcc_data  wcc;
};

struct RMDIR3resfail {
        wcc_data  wcc;
};

/* STRFMT1: "" */
union RMDIR3res switch (nfsstat3 status) {
    case NFS3_OK:
        RMDIR3resok   resok;
    default:
        RMDIR3resfail resfail;
};

/*
 * RENAME3res NFSPROC3_RENAME(RENAME3args) = 14;
 */
/* OBJATTR: newname=self.nto.name */
/* STRFMT1: {0} -> {1} */
struct RENAME3args {
        diropargs3  nfrom; /* FLATATTR:1 */
        diropargs3  nto;
};

struct RENAME3resok {
        wcc_data  fromdir_wcc;
        wcc_data  todir_wcc;
};

struct RENAME3resfail {
        wcc_data  fromdir_wcc;
        wcc_data  todir_wcc;
};

/* STRFMT1: "" */
union RENAME3res switch (nfsstat3 status) {
    case NFS3_OK:
        RENAME3resok   resok;
    default:
        RENAME3resfail resfail;
};

/*
 * LINK3res NFSPROC3_LINK(LINK3args) = 15;
 */
/* STRFMT1: {1} -> FH:{0:crc32} */
struct LINK3args {
        nfs_fh3     fh;
        diropargs3  link; /* FLATATTR:1 */
};

struct LINK3resok {
        post_op_attr  attributes;
        wcc_data      wcc;
};

struct LINK3resfail {
        post_op_attr  attributes;
        wcc_data      wcc;
};

/* STRFMT1: "" */
union LINK3res switch (nfsstat3 status) {
    case NFS3_OK:
        LINK3resok    resok;
    default:
        LINK3resfail  resfail;
};

/*
 * READDIR3res NFSPROC3_READDIR(READDIR3args) = 16;
 */
/* STRFMT1: DH:{0:crc32} cookie:{1} verf:{2} count:{3:umax32} */
struct READDIR3args {
        nfs_fh3      fh;
        cookie3      cookie;
        cookieverf3  verifier;
        count3       count;
};

struct entry3 {
        fileid3    fileid;
        filename3  name;
        cookie3    cookie;
        entry3     *nextentry;
};

/* TRY: 1 */
/* STRFMT1: eof:{1} */
struct dirlist3 {
        entry3  *entries;
        bool    eof;
};

/* STRFMT1: verf:{1} {2} */
struct READDIR3resok {
        post_op_attr  attributes;
        cookieverf3   verifier;
        dirlist3      reply; /* FLATATTR:1 */
};

struct READDIR3resfail {
        post_op_attr  attributes;
};

/* STRFMT1: {1} */
union READDIR3res switch (nfsstat3 status) {
    case NFS3_OK:
        READDIR3resok   resok;
    default:
        /* STRFMT1: "" */
        READDIR3resfail resfail;
};

/*
 * READDIRPLUS3res NFSPROC3_READDIRPLUS(READDIRPLUS3args) = 17;
 */
/* STRFMT1: DH:{0:crc32} cookie:{1} verf:{2} count:{3:umax32} */
struct READDIRPLUS3args {
        nfs_fh3      fh;
        cookie3      cookie;
        cookieverf3  verifier;
        count3       dircount;
        count3       maxcount;
};

struct entryplus3 {
        fileid3      fileid;
        filename3    name;
        cookie3      cookie;
        post_op_attr attributes;
        post_op_fh3  obj; /* FLATATTR:1 */
        entryplus3   *nextentry;
};

/* TRY: 1 */
/* STRFMT1: eof:{1} */
struct dirlistplus3 {
        entryplus3  *entries;
        bool        eof;
};

/* STRFMT1: verf:{1} {2} */
struct READDIRPLUS3resok {
        post_op_attr  attributes;
        cookieverf3   verifier;
        dirlistplus3  reply; /* FLATATTR:1 */
};

struct READDIRPLUS3resfail {
        post_op_attr  attributes;
};

/* STRFMT1: {1} */
union READDIRPLUS3res switch (nfsstat3 status) {
    case NFS3_OK:
        READDIRPLUS3resok   resok;
    default:
        /* STRFMT1: "" */
        READDIRPLUS3resfail resfail;
};

/*
 * FSSTAT3res NFSPROC3_FSSTAT(FSSTAT3args) = 18;
 */
/* STRFMT1: FH:{0:crc32} */
struct FSSTAT3args {
        nfs_fh3  fh;
};

struct FSSTAT3resok {
        post_op_attr attributes;
        size3        tbytes;
        size3        fbytes;
        size3        abytes;
        size3        tfiles;
        size3        ffiles;
        size3        afiles;
        uint32       invarsec;
};

struct FSSTAT3resfail {
        post_op_attr attributes;
};

/* STRFMT1: "" */
union FSSTAT3res switch (nfsstat3 status) {
    case NFS3_OK:
        FSSTAT3resok   resok;
    default:
        FSSTAT3resfail resfail;
};

/*
 * FSINFO3res NFSPROC3_FSINFO(FSINFO3args) = 19;
 */
const FSF3_LINK        = 0x0001;
const FSF3_SYMLINK     = 0x0002;
const FSF3_HOMOGENEOUS = 0x0008;
const FSF3_CANSETTIME  = 0x0010;

/* STRFMT1: FH:{0:crc32} */
struct FSINFO3args {
        nfs_fh3  fh;
};

struct FSINFO3resok {
        post_op_attr attributes;
        uint32       rtmax;
        uint32       rtpref;
        uint32       rtmult;
        uint32       wtmax;
        uint32       wtpref;
        uint32       wtmult;
        uint32       dtpref;
        size3        maxfilesize;
        nfstime3     time_delta;
        uint32       properties;
};

struct FSINFO3resfail {
        post_op_attr attributes;
};

/* STRFMT1: "" */
union FSINFO3res switch (nfsstat3 status) {
    case NFS3_OK:
        FSINFO3resok   resok;
    default:
        FSINFO3resfail resfail;
};

/*
 * PATHCONF3res NFSPROC3_PATHCONF(PATHCONF3args) = 20;
 */
/* STRFMT1: FH:{0:crc32} */
struct PATHCONF3args {
        nfs_fh3  fh;
};

struct PATHCONF3resok {
        post_op_attr attributes;
        uint32       linkmax;
        uint32       name_max;
        bool         no_trunc;
        bool         chown_restricted;
        bool         case_insensitive;
        bool         case_preserving;
};

struct PATHCONF3resfail {
        post_op_attr attributes;
};

/* STRFMT1: "" */
union PATHCONF3res switch (nfsstat3 status) {
    case NFS3_OK:
        PATHCONF3resok   resok;
    default:
        PATHCONF3resfail resfail;
};

/*
 * COMMIT3res NFSPROC3_COMMIT(COMMIT3args) = 21;
 */
/* STRFMT1: FH:{0:crc32} off:{1:umax64} len:{2:umax32} */
struct COMMIT3args {
        nfs_fh3  fh;
        offset3  offset;
        count3   count;
};

/* STRFMT1: verf:{1} */
struct COMMIT3resok {
        wcc_data   wcc;
        writeverf3 verifier;
};

struct COMMIT3resfail {
        wcc_data  wcc;
};

/* STRFMT1: {1} */
union COMMIT3res switch (nfsstat3 status) {
    case NFS3_OK:
        COMMIT3resok   resok;
    default:
        /* STRFMT1: "" */
        COMMIT3resfail resfail;
};

/* Procedures */
enum nfs_proc3 {
    NFSPROC3_NULL        = 0,
    NFSPROC3_GETATTR     = 1,
    NFSPROC3_SETATTR     = 2,
    NFSPROC3_LOOKUP      = 3,
    NFSPROC3_ACCESS      = 4,
    NFSPROC3_READLINK    = 5,
    NFSPROC3_READ        = 6,
    NFSPROC3_WRITE       = 7,
    NFSPROC3_CREATE      = 8,
    NFSPROC3_MKDIR       = 9,
    NFSPROC3_SYMLINK     = 10,
    NFSPROC3_MKNOD       = 11,
    NFSPROC3_REMOVE      = 12,
    NFSPROC3_RMDIR       = 13,
    NFSPROC3_RENAME      = 14,
    NFSPROC3_LINK        = 15,
    NFSPROC3_READDIR     = 16,
    NFSPROC3_READDIRPLUS = 17,
    NFSPROC3_FSSTAT      = 18,
    NFSPROC3_FSINFO      = 19,
    NFSPROC3_PATHCONF    = 20,
    NFSPROC3_COMMIT      = 21
};

/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _pindex=9,_strname="NFS" */
/* OBJATTR: argop=procedure,op=procedure */
union NFS3args switch (nfs_proc3 procedure) {
    case NFSPROC3_NULL:        void;
    case NFSPROC3_GETATTR:     GETATTR3args     opgetattr;
    case NFSPROC3_SETATTR:     SETATTR3args     opsetattr;
    case NFSPROC3_LOOKUP:      LOOKUP3args      oplookup;
    case NFSPROC3_ACCESS:      ACCESS3args      opaccess;
    case NFSPROC3_READLINK:    READLINK3args    opreadlink;
    case NFSPROC3_READ:        READ3args        opread;
    case NFSPROC3_WRITE:       WRITE3args       opwrite;
    case NFSPROC3_CREATE:      CREATE3args      opcreate;
    case NFSPROC3_MKDIR:       MKDIR3args       opmkdir;
    case NFSPROC3_SYMLINK:     SYMLINK3args     opsymlink;
    case NFSPROC3_MKNOD:       MKNOD3args       opmknod;
    case NFSPROC3_REMOVE:      REMOVE3args      opremove;
    case NFSPROC3_RMDIR:       RMDIR3args       oprmdir;
    case NFSPROC3_RENAME:      RENAME3args      oprename;
    case NFSPROC3_LINK:        LINK3args        oplink;
    case NFSPROC3_READDIR:     READDIR3args     opreaddir;
    case NFSPROC3_READDIRPLUS: READDIRPLUS3args opreaddirplus;
    case NFSPROC3_FSSTAT:      FSSTAT3args      opfsstat;
    case NFSPROC3_FSINFO:      FSINFO3args      opfsinfo;
    case NFSPROC3_PATHCONF:    PATHCONF3args    oppathconf;
    case NFSPROC3_COMMIT:      COMMIT3args      opcommit;
};

/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _pindex=9,_strname="NFS" */
/* OBJATTR: resop=procedure,op=procedure */
union NFS3res switch (nfs_proc3 procedure) {
    case NFSPROC3_NULL:        void;
    case NFSPROC3_GETATTR:     GETATTR3res     opgetattr;
    case NFSPROC3_SETATTR:     SETATTR3res     opsetattr;
    case NFSPROC3_LOOKUP:      LOOKUP3res      oplookup;
    case NFSPROC3_ACCESS:      ACCESS3res      opaccess;
    case NFSPROC3_READLINK:    READLINK3res    opreadlink;
    case NFSPROC3_READ:        READ3res        opread;
    case NFSPROC3_WRITE:       WRITE3res       opwrite;
    case NFSPROC3_CREATE:      CREATE3res      opcreate;
    case NFSPROC3_MKDIR:       MKDIR3res       opmkdir;
    case NFSPROC3_SYMLINK:     SYMLINK3res     opsymlink;
    case NFSPROC3_MKNOD:       MKNOD3res       opmknod;
    case NFSPROC3_REMOVE:      REMOVE3res      opremove;
    case NFSPROC3_RMDIR:       RMDIR3res       oprmdir;
    case NFSPROC3_RENAME:      RENAME3res      oprename;
    case NFSPROC3_LINK:        LINK3res        oplink;
    case NFSPROC3_READDIR:     READDIR3res     opreaddir;
    case NFSPROC3_READDIRPLUS: READDIRPLUS3res opreaddirplus;
    case NFSPROC3_FSSTAT:      FSSTAT3res      opfsstat;
    case NFSPROC3_FSINFO:      FSINFO3res      opfsinfo;
    case NFSPROC3_PATHCONF:    PATHCONF3res    oppathconf;
    case NFSPROC3_COMMIT:      COMMIT3res      opcommit;
};
