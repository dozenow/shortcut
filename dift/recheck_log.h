#ifndef __RECHECK_LOG_H__
#define __RECHECK_LOG_H__

#include "../test/parseklib.h"
#include <sys/utsname.h>
#include <poll.h>

struct go_live_process_map {
    int record_pid;
    int current_pid;
};
//****
//note: there is one kernel-level structure corresponding to this one in replay.h 
//note2: the atomic_t in linux is integer on 32bit
//****
struct go_live_clock {
    char skip[128];  //since we put this structure in the shared uclock region, make sure it won't mess up original data in that region (I believe original data only occupies first 8 bytes)
    unsigned long slice_clock;
    int num_threads;  //the number of started threads
    int wait_for_other_threads; //if non-zero, there are still other threads not ready for slice executing
    int num_remaining_threads; //the number of threads that hasn't finished slice exeucting
    int mutex; //for slice ordering
    void* replay_group;
    struct go_live_process_map process_map[0];
};
 
/* Generic entry header */
struct recheck_entry { 
    int sysnum;
    int flag;
    u_long clock;
    long retval;
    int len; /* Length of syscall specific data to follow */
};

/************************* Syscall-specific data ******************************/

struct read_recheck {
    int has_retvals;
    int fd;
    void* buf;
    size_t count;
    int is_count_tainted;
    size_t readlen;
    u_long max_bound; // Variable length read allowed up to this bound - results are tainted
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
/* Followed by data actually written */

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

struct clock_getx_recheck {  //shared by clock_gettime and clock_getres
    clockid_t clk_id;
    struct timespec* tp;
    int clock_id_tainted;
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
    struct sockaddr* addr;
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
    int is_owner_tainted;
};

struct getdents64_recheck {
    u_int fd;
    char* buf;
    u_int count;
    u_long arglen;
};
/* Followed by variable length buffer of size arglen */

struct eventfd2_recheck {
    u_int count;
    int flags;
};

struct poll_recheck {
    u_int nfds;
    int timeout;
    char* buf;
};
/* Followed by nfds pollfd structures/short retvals */

struct newselect_recheck {
    int nfds;
    fd_set* preadfds;
    fd_set* pwritefds;
    fd_set* pexceptfds;
    struct timeval* ptimeout;
    u_long setsize;
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    struct timeval timeout;
    int is_timeout_tainted;
    u_long retlen;
};
/* Followed by kernel retvals */

struct set_robust_list_recheck {
    struct robust_list_head* head;
    size_t len;
};

struct set_tid_address_recheck {
    int* tidptr;
};

struct rt_sigaction_recheck {
    int sig;
    const struct sigaction* act;
    struct sigaction* oact;
    size_t sigsetsize;
};
/* Followed by contents of act as applicable */

struct rt_sigprocmask_recheck {
    int how;
    sigset_t* set;
    sigset_t* oset;
    size_t sigsetsize;
};
/* Followed by contents of act and oact as applicable */

struct mkdir_recheck {
    int mode;
    char pathname[0];
};
/* Followed by filename */

struct sched_getaffinity_recheck {
    pid_t pid;
    char is_pid_tainted;
    size_t cpusetsize;
    cpu_set_t mask[0];
};
/* Followed by contents of mask*/

struct ftruncate_recheck {
    u_int fd;
    u_long length;
};

/* Prototypes */
struct recheck_handle;

struct recheck_handle* open_recheck_log (int threadid, u_long record_grp, pid_t record_pid);
int close_recheck_log (struct recheck_handle* handle);
int recheck_read_ignore (struct recheck_handle* handle);
int recheck_read (struct recheck_handle* handle, int fd, void* buf, size_t count, int, size_t, size_t, u_long max_count, u_long clock);
int recheck_open (struct recheck_handle* handle, char* filename, int flags, int mode, u_long clock);
int recheck_openat (struct recheck_handle* handle, int dirfd, char* filename, int flags, int mode, u_long clock);
int recheck_close (struct recheck_handle* handle, int fd, u_long clock);
int recheck_access (struct recheck_handle* handle, char* pathname, int mode, u_long clock);
int recheck_stat64 (struct recheck_handle* handle, char* path, void* buf, u_long clock);
int recheck_fstat64 (struct recheck_handle* handle, int fd, void* buf, u_long clock);
int recheck_lstat64 (struct recheck_handle* handle, char* pathname, void* buf, u_long clock);
int recheck_write (struct recheck_handle* handle, int fd, void* buf, size_t count, u_long clock);
int recheck_ugetrlimit (struct recheck_handle* handle, int resource, struct rlimit* prlim, u_long clock);
int recheck_uname (struct recheck_handle* handle, struct utsname* buf, u_long clock);
int recheck_statfs64 (struct recheck_handle* handle, const char* path, size_t sz, struct statfs64* buf, u_long clock);
int recheck_gettimeofday (struct recheck_handle* handle, struct timeval* tv, struct timezone* tz, u_long clock);
int recheck_time (struct recheck_handle* handle, time_t* t, u_long clock);
int recheck_prlimit64 (struct recheck_handle* handle, pid_t pid, int resource, struct rlimit64* new_limit, struct rlimit64* old_limit, u_long clock);
int recheck_setpgid (struct recheck_handle* handle, pid_t pid, pid_t pgid, int is_pid_tainted, int is_pgid_tainted, u_long clock);
int recheck_readlink (struct recheck_handle* handle, char* path, char* buf, size_t bufsiz, u_long clock);
int recheck_socket (struct recheck_handle* handle, int domain, int type, int protocol, u_long clock);
int recheck_connect_or_bind (struct recheck_handle* handle, int sockfd, struct sockaddr* addr, socklen_t addrlen, u_long clock);
int recheck_getpid (struct recheck_handle* handle, u_long clock);
int recheck_gettid (struct recheck_handle* handle, u_long clock);
int recheck_getpgrp (struct recheck_handle* handle, u_long clock);
int recheck_getuid32 (struct recheck_handle* handle, u_long clock);
int recheck_geteuid32 (struct recheck_handle* handle, u_long clock);
int recheck_getgid32 (struct recheck_handle* handle, u_long clock);
int recheck_getegid32 (struct recheck_handle* handle, u_long clock);
int recheck_llseek (struct recheck_handle* handle, u_int fd, u_long offset_high, u_long offset_low, loff_t* result, u_int whence, u_long clock);
int recheck_ioctl (struct recheck_handle* handle, u_int fd, u_int cmd, char* arg, u_long clock);
int recheck_fcntl64_getfl (struct recheck_handle* handle, int fd, u_long clock);
int recheck_fcntl64_setfl (struct recheck_handle* handle, int fd, long flags, u_long clock);
int recheck_fcntl64_getlk (struct recheck_handle* handle, int fd, void* arg, u_long clock);
int recheck_fcntl64_getown (struct recheck_handle* handle, int fd, u_long clock);
int recheck_fcntl64_setown (struct recheck_handle* handle, int fd, long owner, int is_owner_tainted, u_long clock);
int recheck_getdents (struct recheck_handle* handle, u_int fd, char* buf, int count, u_long clock);
int recheck_getdents64 (struct recheck_handle* handle, u_int fd, char* buf, int count, u_long clock);
int recheck_eventfd2 (struct recheck_handle* handle, u_int count, int flags, u_long clock);
int recheck_poll (struct recheck_handle* handle, struct pollfd* fds, u_int nfds, int timeout, u_long clock);
int recheck__newselect (struct recheck_handle* handle, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout, u_long clock);
int recheck_set_robust_list (struct recheck_handle* handle, struct robust_list_head* head, size_t len, u_long clock);
int recheck_set_tid_address (struct recheck_handle* handle, int* tidptr, u_long clock);
int recheck_rt_sigaction (struct recheck_handle* handle, int sig, const struct sigaction* act, struct sigaction* oact, size_t sigsetsize, u_long clock);
int recheck_rt_sigprocmask (struct recheck_handle* handle, int how, sigset_t* set, sigset_t* oset, size_t sigsetsize, u_long clock);
int recheck_clock_gettime (struct recheck_handle* handle, clockid_t clk_id, struct timespec* tp, u_long clock);
int recheck_clock_getres (struct recheck_handle* handle, clockid_t clk_id, struct timespec* tp, int clock_id_tainted, u_long clock);
int recheck_mkdir (struct recheck_handle* handle, char* pathname, int mode, u_long clock);
int recheck_sched_getaffinity (struct recheck_handle* handle, pid_t pid, size_t cpusetsize, cpu_set_t* mask, int is_pid_tainted, u_long clock);
int recheck_ftruncate (struct recheck_handle* handle, u_int fd, u_long length, u_long clock);
#endif
