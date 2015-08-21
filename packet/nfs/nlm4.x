/*
 * Copyright (c) 1995
 *
 * NLM Version 4 Protocol Specification
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
 * Constants
 */
enum bool {
    FALSE = 0,
    TRUE  = 1
};

/*
 * Sizes
 */
const LM_MAXSTRLEN = 1024;
const MAXNAMELEN   = 1025;  /* LM_MAXSTRLEN + 1 */
const MAXNETOBJ_SZ = 1024;

/*
 * Basic data types
 */
typedef unsigned hyper uint64;
typedef hyper          int64;
typedef unsigned int   uint32;
typedef int            int32;
typedef opaque         nlm_fh<MAXNETOBJ_SZ>; /* STRHEX:1 */
typedef opaque         netobj<MAXNETOBJ_SZ>; /* STRHEX:1 */
typedef opaque         strobj<MAXNETOBJ_SZ>;

enum nlm4_stats {
    NLM4_GRANTED             = 0,
    NLM4_DENIED              = 1,
    NLM4_DENIED_NOLOCKS      = 2,
    NLM4_BLOCKED             = 3,
    NLM4_DENIED_GRACE_PERIOD = 4,
    NLM4_DEADLCK             = 5,
    NLM4_ROFS                = 6,
    NLM4_STALE_FH            = 7,
    NLM4_FBIG                = 8,
    NLM4_FAILED              = 9
};

enum fsh4_mode {
    fsm_DN  = 0,
    fsm_DR  = 1,
    fsm_DW  = 2,
    fsm_DRW = 3,
};

enum fsh4_access {
    fsa_NONE = 0,
    fsa_R    = 1,
    fsa_W    = 2,
    fsa_RW   = 3,
};

/* STRFMT1: off:{3:umax64} len:{4:umax64} excl:{0} */
struct nlm4_holder {
    bool     exclusive;
    int32    svid;
    strobj   oh;
    uint64   offset;
    uint64   length;
};

/* STRFMT1: FH:{1:crc32} off:{4:umax64} len:{5:umax64} */
struct nlm4_lock {
    string   owner<LM_MAXSTRLEN>;
    nlm_fh   fh;
    strobj   oh;
    int32    svid;
    uint64   offset;
    uint64   length;
};

/* STRFMT1: FH:{1:crc32} owner:{0} */
struct nlm4_share {
    string       owner<LM_MAXSTRLEN>;
    nlm_fh       fh;
    strobj       oh;
    fsh4_mode    mode;
    fsh4_access  access;
};

/* STRFMT1: {2} excl:{1} */
struct nlm4_testargs {
    netobj     cookie;
    bool       exclusive;
    nlm4_lock  locker;
};

typedef nlm4_testargs TEST4args;        /* INHERIT:1 */
typedef nlm4_testargs TEST_MSG4args;    /* INHERIT:1 */
typedef nlm4_testargs GRANTED4args;     /* INHERIT:1 */
typedef nlm4_testargs GRANTED_MSG4args; /* INHERIT:1 */

/* STRFMT1: {0} {1} */
union nlm4_testrply switch (nlm4_stats status) {
    case NLM4_DENIED:
        nlm4_holder denied;
    default:
        void;
};

/* STRFMT1: {1} */
struct nlm4_testres {
    netobj         cookie;
    nlm4_testrply  stat; /* FLATATTR:1 */
};

typedef nlm4_testres TEST_RES4args; /* INHERIT:1 */
typedef nlm4_testres TEST4res;      /* INHERIT:1 */

/* STRFMT1: {3} excl:{2} block:{1}*/
struct nlm4_lockargs {
    netobj     cookie;
    bool       block;
    bool       exclusive;
    nlm4_lock  locker;
    bool       reclaim;  /* used for recovering locks */
    int        state;    /* specify local status monitor state */
};

typedef nlm4_lockargs LOCK4args;     /* INHERIT:1 */
typedef nlm4_lockargs LOCK_MSG4args; /* INHERIT:1 */
typedef nlm4_lockargs NM_LOCK4args;  /* INHERIT:1 */

/* STRFMT1: {1} */
struct nlm4_res {
    netobj      cookie;
    nlm4_stats  status;
};

typedef nlm4_res LOCK_RES4args;    /* INHERIT:1 */
typedef nlm4_res CANCEL_RES4args;  /* INHERIT:1 */
typedef nlm4_res UNLOCK_RES4args;  /* INHERIT:1 */
typedef nlm4_res GRANTED_RES4args; /* INHERIT:1 */
typedef nlm4_res LOCK4res;         /* INHERIT:1 */
typedef nlm4_res CANCEL4res;       /* INHERIT:1 */
typedef nlm4_res UNLOCK4res;       /* INHERIT:1 */
typedef nlm4_res GRANTED4res;      /* INHERIT:1 */
typedef nlm4_res NM_LOCK4res;      /* INHERIT:1 */

struct nlm4_cancargs {
    netobj     cookie;
    bool       block;
    bool       exclusive;
    nlm4_lock  locker;
};

typedef nlm4_cancargs CANCEL4args;     /* INHERIT:1 */
typedef nlm4_cancargs CANCEL_MSG4args; /* INHERIT:1 */

/* STRFMT1: {1} */
struct nlm4_unlockargs {
    netobj     cookie;
    nlm4_lock  locker;
};

typedef nlm4_unlockargs UNLOCK4args;     /* INHERIT:1 */
typedef nlm4_unlockargs UNLOCK_MSG4args; /* INHERIT:1 */

struct nlm4_shareargs {
    netobj      cookie;
    nlm4_share  share;
    bool        reclaim;
};

typedef nlm4_shareargs SHARE4args;   /* INHERIT:1 */
typedef nlm4_shareargs UNSHARE4args; /* INHERIT:1 */

struct nlm4_shareres {
    netobj      cookie;
    nlm4_stats  status;
    int         sequence;
};

typedef nlm4_shareres SHARE4res;   /* INHERIT:1 */
typedef nlm4_shareres UNSHARE4res; /* INHERIT:1 */

/* STRFMT1: state:{1} name:{0} */
struct FREE_ALL4args {
    string  name<MAXNAMELEN>;
    int32   state;
};

/* Procedures */
enum nlm_proc4 {
    NLMPROC4_NULL        = 0,
    NLMPROC4_TEST        = 1,
    NLMPROC4_LOCK        = 2,
    NLMPROC4_CANCEL      = 3,
    NLMPROC4_UNLOCK      = 4,
    NLMPROC4_GRANTED     = 5,
    NLMPROC4_TEST_MSG    = 6,
    NLMPROC4_LOCK_MSG    = 7,
    NLMPROC4_CANCEL_MSG  = 8,
    NLMPROC4_UNLOCK_MSG  = 9,
    NLMPROC4_GRANTED_MSG = 10,
    NLMPROC4_TEST_RES    = 11,
    NLMPROC4_LOCK_RES    = 12,
    NLMPROC4_CANCEL_RES  = 13,
    NLMPROC4_UNLOCK_RES  = 14,
    NLMPROC4_GRANTED_RES = 15,
    NLMPROC4_SHARE       = 20,
    NLMPROC4_UNSHARE     = 21,
    NLMPROC4_NM_LOCK     = 22,
    NLMPROC4_FREE_ALL    = 23,
};

/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _pindex=9,_strname="NLM" */
/* OBJATTR: argop=procedure,op=procedure */
union NLM4args switch(nlm_proc4 procedure) {
    case NLMPROC4_NULL:        void; /* STRFMT2: NULL() */
    case NLMPROC4_TEST:        TEST4args        optest;
    case NLMPROC4_LOCK:        LOCK4args        oplock;
    case NLMPROC4_CANCEL:      CANCEL4args      opcancel;
    case NLMPROC4_UNLOCK:      UNLOCK4args      opunlock;
    case NLMPROC4_GRANTED:     GRANTED4args     opgranted;
    case NLMPROC4_TEST_MSG:    TEST_MSG4args    optest_msg;
    case NLMPROC4_LOCK_MSG:    LOCK_MSG4args    oplock_msg;
    case NLMPROC4_CANCEL_MSG:  CANCEL_MSG4args  opcancel_msg;
    case NLMPROC4_UNLOCK_MSG:  UNLOCK_MSG4args  opunlock_msg;
    case NLMPROC4_GRANTED_MSG: GRANTED_MSG4args opgranted_msg;
    case NLMPROC4_TEST_RES:    TEST_RES4args    optest_res;
    case NLMPROC4_LOCK_RES:    LOCK_RES4args    oplock_res;
    case NLMPROC4_CANCEL_RES:  CANCEL_RES4args  opcancel_res;
    case NLMPROC4_UNLOCK_RES:  UNLOCK_RES4args  opunlock_res;
    case NLMPROC4_GRANTED_RES: GRANTED_RES4args opgranted_res;
    case NLMPROC4_SHARE:       SHARE4args       opshare;
    case NLMPROC4_UNSHARE:     UNSHARE4args     opunshare;
    case NLMPROC4_NM_LOCK:     NM_LOCK4args     opnm_lock;
    case NLMPROC4_FREE_ALL:    FREE_ALL4args    opfree_all;
};

/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _pindex=9,_strname="NLM" */
/* OBJATTR: resop=procedure,op=procedure */
union NLM4res switch(nlm_proc4 procedure) {
    case NLMPROC4_NULL:        void; /* STRFMT2: NULL() */
    case NLMPROC4_TEST:        TEST4res    optest;
    case NLMPROC4_LOCK:        LOCK4res    oplock;
    case NLMPROC4_CANCEL:      CANCEL4res  opcancel;
    case NLMPROC4_UNLOCK:      UNLOCK4res  opunlock;
    case NLMPROC4_GRANTED:     GRANTED4res opgranted;
    case NLMPROC4_TEST_MSG:    void; /* STRFMT2: TEST_MSG4res() */
    case NLMPROC4_LOCK_MSG:    void; /* STRFMT2: LOCK_MSG4res() */
    case NLMPROC4_CANCEL_MSG:  void; /* STRFMT2: CANCEL_MSG4res() */
    case NLMPROC4_UNLOCK_MSG:  void; /* STRFMT2: UNLOCK_MSG4res() */
    case NLMPROC4_GRANTED_MSG: void; /* STRFMT2: GRANTED_MSG4res() */
    case NLMPROC4_TEST_RES:    void; /* STRFMT2: TEST_RES4res() */
    case NLMPROC4_LOCK_RES:    void; /* STRFMT2: LOCK_RES4res() */
    case NLMPROC4_CANCEL_RES:  void; /* STRFMT2: CANCEL_RES4res() */
    case NLMPROC4_UNLOCK_RES:  void; /* STRFMT2: UNLOCK_RES4res() */
    case NLMPROC4_GRANTED_RES: void; /* STRFMT2: GRANTED_RES4res() */
    case NLMPROC4_SHARE:       SHARE4res   opshare;
    case NLMPROC4_UNSHARE:     UNSHARE4res opunshare;
    case NLMPROC4_NM_LOCK:     NM_LOCK4res opnm_lock;
    case NLMPROC4_FREE_ALL:    void; /* STRFMT2: FREE_ALL4res() */
};

program NLM_PROGRAM {
      version NLM {
         void
            NLMPROC4_NULL(void)                    = 0;

         TEST4res
            NLMPROC4_TEST(TEST4args)               = 1;

         LOCK4res
            NLMPROC4_LOCK(LOCK4args)               = 2;

         CANCEL4res
            NLMPROC4_CANCEL(CANCEL4args)           = 3;

         UNLOCK4res
            NLMPROC4_UNLOCK(UNLOCK4args)           = 4;

         GRANTED4res
            NLMPROC4_GRANTED(GRANTED4args)         = 5;

         void
            NLMPROC4_TEST_MSG(TEST_MSG4args)       = 6;

         void
            NLMPROC4_LOCK_MSG(LOCK_MSG4args)       = 7;

         void
            NLMPROC4_CANCEL_MSG(CANCEL_MSG4args)   = 8;

         void
            NLMPROC4_UNLOCK_MSG(UNLOCK_MSG4args)   = 9;

         void
            NLMPROC4_GRANTED_MSG(GRANTED_MSG4args) = 10;

         void
            NLMPROC4_TEST_RES(TEST_RES4args)       = 11;

         void
            NLMPROC4_LOCK_RES(LOCK_RES4args)       = 12;

         void
            NLMPROC4_CANCEL_RES(CANCEL_RES4args)   = 13;

         void
            NLMPROC4_UNLOCK_RES(UNLOCK_RES4args)   = 14;

         void
            NLMPROC4_GRANTED_RES(GRANTED_RES4args) = 15;

         SHARE4res
            NLMPROC4_SHARE(SHARE4args)             = 20;

         UNSHARE4res
            NLMPROC4_UNSHARE(UNSHARE4args)         = 21;

         NM_LOCK4res
            NLMPROC4_NM_LOCK(NM_LOCK4args)         = 22;

         void
            NLMPROC4_FREE_ALL(FREE_ALL4args)       = 23;
      } = 4;
} = 100021;
