#ifndef __RECHECK_LOG_H__
#define __RECHECK_LOG_H__

#include "../test/parseklib.h"

/* Generic entry header */
struct recheck_entry { 
    int sysnum;
    int flag;
    long retval;
    int len; /* Length of syscall specific data to follow */
};

/************************* Syscall-specific data ******************************/

struct read_recheck {
    int has_retvals;
    int fd;
    void* buf;
    size_t count;
    size_t readlen;
    int partial_read; //these are bytes that need to be copied to buf on recheck; other bytes should be verified
    size_t partial_read_start;
    size_t partial_read_end;
};
/* Followed by variable length read data */

struct open_recheck {
    int has_retvals;
    struct open_retvals retvals;
    int flags;
    int mode;
};
/* Followed by filename */

struct close_recheck {
    int fd;
};

struct access_recheck {
    int mode;
};
/* Followed by pathname */

struct stat64_recheck {
    int has_retvals;
    struct stat64 retvals;
    void* buf;
};
/* Followed by pathname */

struct fstat64_recheck {
    int has_retvals;
    struct stat64 retvals;
    int fd;
    void* buf;
};

struct write_recheck {
    int has_retvals;
    int fd;
    void* buf;
    size_t count;
    size_t writelen;
};
/* Followed by variable length write data */

struct ugetrlimit_recheck {
    int resource;
    struct rlimit rlim;
};

struct uname_recheck {
    struct utsname* buf;
    struct utsname utsname;
};

struct statfs64_recheck {
    size_t sz;
    struct statfs64* buf;
    struct statfs64 statfs;
};
/* Followed by variable length write path */

struct prlimit64_recheck {
    int has_retvals;
    pid_t pid;
    int resource;
    struct rlimit64* new_limit;
    struct rlimit64* old_limit;
    struct rlimit64 retparams;
};

/* Prototypes */
struct recheck_handle;

struct recheck_handle* open_recheck_log (u_long record_grp, pid_t record_pid);
int close_recheck_log (struct recheck_handle* handle);
int recheck_read (struct recheck_handle* handle, int fd, void* buf, size_t count, int, size_t, size_t);
int recheck_open (struct recheck_handle* handle, char* filename, int flags, int mode);
int recheck_close (struct recheck_handle* handle, int fd);
int recheck_access (struct recheck_handle* handle, char* pathname, int mode);
int recheck_stat64 (struct recheck_handle* handle, char* path, void* buf);
int recheck_fstat64 (struct recheck_handle* handle, int fd, void* buf); 
int recheck_write (struct recheck_handle* handle, int fd, void* buf, size_t count);
int recheck_ugetrlimit (struct recheck_handle* handle, int resource, struct rlimit* prlim);
int recheck_uname (struct recheck_handle* handle, struct utsname* buf);
int recheck_statfs64 (struct recheck_handle* handle, const char* path, size_t sz, struct statfs64* buf);
int recheck_prlimit64 (struct recheck_handle* handle, pid_t pid, int resource, struct rlimit64* new_limit, struct rlimit64* old_limit);

#endif
