/*
 * Copyright (c) 2010-2017 IETF Trust and the persons
 * identified as authors of the code.  All rights reserved.
 *
 * The authors of the code are:
 * B. Callaghan, T. Talpey, and C. Lever
 *
 * Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that the
 * following conditions are met:
 *
 * - Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other
 *   materials provided with the distribution.
 *
 * - Neither the name of Internet Society, IETF or IETF
 *   Trust, nor the names of specific contributors, may be
 *   used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
 *   AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 *   EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* RFC 8166 Remote Direct Memory Access Transport for Remote Procedure Call */
/* COPYRIGHT: 2017 */
/* VERSION: "1.0" */

/*
 * Basic data types
 */
typedef int            int32;
typedef unsigned int   uint32;
typedef hyper          int64;
typedef unsigned hyper uint64;

/*
 * Plain RDMA segment
 */
struct xdr_rdma_segment {
    uint32 handle;          /* Registered memory handle */ /* STRHEX:1 */
    uint32 length;          /* Length of the chunk in bytes */
    uint64 offset;          /* Chunk virtual address or offset */
};

/*
 * RDMA read segment
 */
struct xdr_read_chunk {
    uint32 position;        /* Position in XDR stream */
    xdr_rdma_segment target; /* FLATATTR:1 */
};

/*
 * Read list
 */
struct xdr_read_list {
    xdr_read_chunk   entry;
    xdr_read_list   *next;
};

/*
 * Write chunk
 */
/* STRFMT2: {0:len} */
struct xdr_write_chunk {
    xdr_rdma_segment target<>;
};

/*
 * Write list
 */
struct xdr_write_list {
    xdr_write_chunk   entry;
    xdr_write_list   *next;
};

/*
 * Chunk lists
 */
/* STRFMT2: reads: {0:len}, writes: {1:len}, reply: {2:?{2}:0} */
struct rpc_rdma_header {
    xdr_read_list    *reads;
    xdr_write_list   *writes;
    xdr_write_chunk  *reply;
    /* rpc body follows */
};

/* STRFMT2: reads: {0:len}, writes: {1:len}, reply: {2:?{2}:0} */
struct rpc_rdma_header_nomsg {
    xdr_read_list    *reads;
    xdr_write_list   *writes;
    xdr_write_chunk  *reply;
};

/* Not to be used: obsoleted by RFC 8166 */
/* STRFMT2: reads: {2:len}, writes: {3:len}, reply: {4:?{4}:0} */
struct rpc_rdma_header_padded {
    uint32            align;   /* Padding alignment */
    uint32            thresh;  /* Padding threshold */
    xdr_read_list    *reads;
    xdr_write_list   *writes;
    xdr_write_chunk  *reply;
    /* rpc body follows */
};

/*
 * Error handling
 */
enum rpc_rdma_errcode {
    ERR_VERS  = 1,      /* Value fixed for all versions */
    ERR_CHUNK = 2
};

/* Structure fixed for all versions */
/* STRFMT2: low: {0}, high: {1} */
struct rpc_rdma_errvers {
    uint32  low;
    uint32  high;
};

/* STRFMT2: {0} */
union rpc_rdma_error switch (rpc_rdma_errcode err) {
    case ERR_VERS:
        /* STRFMT2: {0} {1} */
        rpc_rdma_errvers range;
    case ERR_CHUNK:
        void;
};

/*
 * Procedures
 */
enum rdma_proc {
    RDMA_MSG   = 0,   /* Value fixed for all versions */
    RDMA_NOMSG = 1,   /* Value fixed for all versions */
    RDMA_MSGP  = 2,   /* Not to be used */
    RDMA_DONE  = 3,   /* Not to be used */
    RDMA_ERROR = 4    /* Value fixed for all versions */
};

/*
 * The position of the proc discriminator field is
 * fixed for all versions
 */
/* STRFMT2: {1} */
union rdma_body switch (rdma_proc proc) {
    case RDMA_MSG:
       rpc_rdma_header rdma_msg;
    case RDMA_NOMSG:
       rpc_rdma_header_nomsg rdma_nomsg;
    case RDMA_MSGP:   /* Not to be used */
       rpc_rdma_header_padded rdma_msgp;
    case RDMA_DONE:   /* Not to be used */
       void;
    case RDMA_ERROR:
       rpc_rdma_error rdma_error;
};

/*
 * Fixed header fields
 */
/* STRFMT1: RPCoRDMA {3.proc} xid: {0} */
/* STRFMT2: {3.proc}, xid: {0}, credits: {2} {3} */
/* CLASSATTR: _strname="RPCoRDMA" */
struct RPCoRDMA {
    uint32     xid;     /* Mirrors the RPC header xid */ /* STRHEX:1 */
    uint32     vers;    /* Version of this protocol */
    uint32     credit;  /* Buffers requested/granted */
    rdma_body  body;    /* FLATATTR: 1 */
};
