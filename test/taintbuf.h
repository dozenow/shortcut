#ifndef __TAINTBUF_H__
#define __TAINTBUF_H__

#define RETVAL             1
#define RETBUF             2
#define STAT64_INO        10
#define STAT64_NLINK      11
#define STAT64_SIZE       12
#define STAT64_MTIME      13
#define STAT64_CTIME      14
#define STAT64_ATIME      15
#define STAT64_BLOCKS     16
#define NEWSELECT_TIMEOUT 10
#define GETTIMEOFDAY_TV   10
#define GETTIMEOFDAY_TZ   11
#define UNAME_VERSION     10
#define STATFS64_BFREE    10
#define STATFS64_BAVAIL   11
#define STATFS64_FFREE    12
#define CLOCK_GETTIME     13
#define CLOCK_GETRES      14


struct taint_retval {
    short syscall;
    short rettype;
    u_long clock;
    u_long size;
};
/* Followed by size bytes */

#define DIVERGE_MISMATCH 0
#define DIVERGE_JUMP     1
#define DIVERGE_INDEX    2

struct taintbuf_hdr {
    u_long diverge_type;
    u_long diverge_ndx;
    u_long last_clock;
};

#endif
