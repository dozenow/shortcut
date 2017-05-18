#ifndef __RECHECK_LOG_H__
#define __RECHECK_LOG_H__

#include "../test/parseklib.h"

/* Generic entry header */
struct recheck_entry { 
    int sysnum;
    int flag;
    long retval;
    int len; /* Length of syscall specifc data to follow */
};

/************************* Syscall-specific data ******************************/

struct read_recheck {
    int has_retvals;
    int fd;
    void* buf;
    size_t count;
    size_t readlen;
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


/* Prototypes */
struct recheck_handle;

struct recheck_handle* open_recheck_log (u_long record_grp, pid_t record_pid);
int close_recheck_log (struct recheck_handle* handle);
int recheck_read (struct recheck_handle* handle, int fd, void* buf, size_t count);
int recheck_open (struct recheck_handle* handle, char* filename, int flags, int mode);
int recheck_close (struct recheck_handle* handle, int fd);
int recheck_access (struct recheck_handle* handle, char* pathname, int mode);
int recheck_stat64 (struct recheck_handle* handle, char* path, void* buf);
int recheck_fstat64 (struct recheck_handle* handle, int fd, void* buf);
int recheck_write (struct recheck_handle* handle, int fd, void* buf, size_t count);

#endif
