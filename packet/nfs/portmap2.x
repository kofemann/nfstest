/*
 * Copyright (c) 1995
 *
 * Port Mapper Program Version 2 Protocol Specification
 * The document authors are identified in RFC 1833
 *
 *=====================================================================
 * This Document was changed to add directives for converting
 * it to python code. Also the name of some variables were
 * changed to be consistent throughout this document and to
 * have a similar interface with other protocols.
 *=====================================================================
 */
/* COPYRIGHT: 2014 */

enum proto2 {
    TCP = 6;      /* protocol number for TCP/IP */
    UDP = 17;     /* protocol number for UDP/IP */
};

/* STRFMT1: prog:{0} vers:{1} proto:{2} port:{3} */
struct mapping {
    unsigned int prog;
    unsigned int vers;
    proto2       prot;
    unsigned int port;
};

typedef mapping SET2args;     /* INHERIT:1 */
typedef mapping UNSET2args;   /* INHERIT:1 */
typedef mapping GETPORT2args; /* INHERIT:1 */

/* STRFMT1: {0} */
struct entry2 {
    mapping   map;
    entry2   *next;
};

/* STRFMT1: {0} */
struct DUMP2res {
    entry2 *entries;
};

/* STRFMT1: prog:{0} vers:{1} proc:{2} args:{3} */
struct CALLIT2args {
    unsigned int prog;
    unsigned int vers;
    unsigned int proc;
    opaque args<>;
};

/* STRFMT1: port:{0} res:{1:#x} */
struct CALLIT2res {
    unsigned int port;
    opaque res<>;
};

/* STRFMT1: {0} */
struct bool_res {
    bool result;
};

typedef bool_res SET2res;   /* INHERIT:1 */
typedef bool_res UNSET2res; /* INHERIT:1 */

/* STRFMT1: {0} */
struct GETPORT2res {
    unsigned int result;
};

/* Procedures */
enum portmap_proc2 {
    PMAPPROC_NULL    = 0,
    PMAPPROC_SET     = 1,
    PMAPPROC_UNSET   = 2,
    PMAPPROC_GETPORT = 3,
    PMAPPROC_DUMP    = 4,
    PMAPPROC_CALLIT  = 5,
};

/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _pindex=9,_strname="PORTMAP" */
/* OBJATTR: argop=procedure,op=procedure */
union PORTMAP2args switch(portmap_proc2 procedure) {
    case PMAPPROC_NULL:    void; /* STRFMT2: NULL() */
    case PMAPPROC_SET:     SET2args     opset;
    case PMAPPROC_UNSET:   UNSET2args   opunset;
    case PMAPPROC_GETPORT: GETPORT2args opgetport;
    case PMAPPROC_DUMP:    void; /* STRFMT2: DUMP2args() */
    case PMAPPROC_CALLIT:  CALLIT2args  opcallit;
};

/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _pindex=9,_strname="PORTMAP" */
/* OBJATTR: resop=procedure,op=procedure */
union PORTMAP2res switch(portmap_proc2 procedure) {
    case PMAPPROC_NULL:    void; /* STRFMT2: NULL() */
    case PMAPPROC_SET:     SET2res     opset;
    case PMAPPROC_UNSET:   UNSET2res   opunset;
    case PMAPPROC_GETPORT: GETPORT2res opgetport;
    case PMAPPROC_DUMP:    DUMP2res    opdump;
    case PMAPPROC_CALLIT:  CALLIT2res  opcallit;
};

program PMAP_PROG {
    version PORTMAP {
        void
        PMAPPROC_NULL(void)         = 0;

        SET2res
        PMAPPROC_SET(SET2args)      = 1;

        UNSET2res
        PMAPPROC_UNSET(UNSET2args)  = 2;

        GETPORT2res
        PMAPPROC_GETPORT(GETPORT2args) = 3;

        DUMP2res
        PMAPPROC_DUMP(void)         = 4;

        CALLIT2res
        PMAPPROC_CALLIT(CALLIT2args)  = 5;
    } = 2;
} = 100000;
