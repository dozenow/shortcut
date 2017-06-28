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

struct openat_recheck { 
    int dirfd;
    int flags;
    int mode;
    char filename[0];
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
};

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

struct gettimeofday_recheck {
    struct timeval* tv_ptr;
    struct timezone* tz_ptr;
};

struct time_recheck { 
    time_t *t;
};

struct prlimit64_recheck {
    int has_retvals;
    pid_t pid;
    int resource;
    struct rlimit64* new_limit;
    struct rlimit64* old_limit;
    struct rlimit64 retparams;
};

struct setpgid_recheck {
    pid_t pid;
    pid_t pgid;
    char is_pid_tainted;
    char is_pgid_tainted;
};

struct readlink_recheck {
    char* buf;
    size_t bufsiz;
};
/* Followed by readlink results (size given by rc) */
/* Followed by variable length path */

struct socket_recheck {
    int domain;
    int type; 
    int protocol;
};

struct connect_recheck {
    int sockfd;
    socklen_t addrlen;
};
/* Followed by address of size addrlen */

struct llseek_recheck {
    u_int fd;
    u_long offset_high;
    u_long offset_low;
    loff_t result;
    u_int whence;
};

struct ioctl_recheck {
    u_int fd;
    u_int cmd;
    u_int dir;
    u_int size;
    char* arg;
    u_long arglen;
};

struct fcntl64_getfl_recheck {
    int fd;
};

struct fcntl64_setfl_recheck {
    int fd;
    long flags;
};

struct fcntl64_getlk_recheck {
    int has_retvals;
    struct flock flock;
    int fd;
    void* arg;
};

struct fcntl64_getown_recheck {
    int fd;
};

struct fcntl64_setown_recheck {
    int fd;
    long owner;
};

/* Prototypes */
struct recheck_handle;

struct recheck_handle* open_recheck_log (u_long record_grp, pid_t record_pid);
int close_recheck_log (struct recheck_handle* handle);
int recheck_read (struct recheck_handle* handle, int fd, void* buf, size_t count, int, size_t, size_t);
int recheck_open (struct recheck_handle* handle, char* filename, int flags, int mode);
int recheck_openat (struct recheck_handle* handle, int dirfd, char* filename, int flags, int mode);
int recheck_close (struct recheck_handle* handle, int fd);
int recheck_access (struct recheck_handle* handle, char* pathname, int mode);
int recheck_stat64 (struct recheck_handle* handle, char* path, void* buf);
int recheck_fstat64 (struct recheck_handle* handle, int fd, void* buf); 
int recheck_lstat64 (struct recheck_handle* handle, char* pathname, void* buf);
int recheck_write (struct recheck_handle* handle, int fd, void* buf, size_t count);
int recheck_ugetrlimit (struct recheck_handle* handle, int resource, struct rlimit* prlim);
int recheck_uname (struct recheck_handle* handle, struct utsname* buf);
int recheck_statfs64 (struct recheck_handle* handle, const char* path, size_t sz, struct statfs64* buf);
int recheck_gettimeofday (struct recheck_handle* handle, struct timeval* tv, struct timezone* tz);
int recheck_time (struct recheck_handle* handle, time_t* t);
int recheck_prlimit64 (struct recheck_handle* handle, pid_t pid, int resource, struct rlimit64* new_limit, struct rlimit64* old_limit);
int recheck_setpgid (struct recheck_handle* handle, pid_t pid, pid_t pgid, int is_pid_tainted, int is_pgid_tainted);
int recheck_readlink (struct recheck_handle* handle, char* path, char* buf, size_t bufsiz);
int recheck_socket (struct recheck_handle* handle, int domain, int type, int protocol);
int recheck_connect_or_bind (struct recheck_handle* handle, int sockfd, struct sockaddr* addr, socklen_t addrlen);
int recheck_getpid (struct recheck_handle* handle);
int recheck_getuid32 (struct recheck_handle* handle);
int recheck_geteuid32 (struct recheck_handle* handle);
int recheck_getgid32 (struct recheck_handle* handle);
int recheck_getegid32 (struct recheck_handle* handle);
int recheck_llseek (struct recheck_handle* handle, u_int fd, u_long offset_high, u_long offset_low, loff_t* result, u_int whence);
int recheck_ioctl (struct recheck_handle* handle, u_int fd, u_int cmd, char* arg);
int recheck_fcntl64_getfl (struct recheck_handle* handle, int fd);
int recheck_fcntl64_setfl (struct recheck_handle* handle, int fd, long flags);
int recheck_fcntl64_getlk (struct recheck_handle* handle, int fd, void* arg);
int recheck_fcntl64_getown (struct recheck_handle* handle, int fd);
int recheck_fcntl64_setown (struct recheck_handle* handle, int fd, long owner);

#endif
