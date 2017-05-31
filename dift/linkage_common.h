#ifndef LINKAGE_COMMON_H
#define LINKAGE_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "taint_interface/taint.h"
#include "uthash.h"

#define NUM_REGS 120
#define REG_SIZE 16

// flag register (status) 
#define NUM_FLAGS 7

//These are only flags, not corresponding to the actual hardware mask
//The actual flag register taints are layed out according to these FLAGs instead of the actual hardware layouts
#define CF_FLAG 0x01
#define PF_FLAG 0x02
#define AF_FLAG 0x04
#define ZF_FLAG 0x08
#define SF_FLAG 0x10
#define OF_FLAG 0x20
#define DF_FLAG 0x40

#define DF_INDEX 6

//actual hardware mask// Don't use them directly (only used once in computeEA function) 
#define CF_MASK 0x01
#define PF_MASK 0x04
#define AF_MASK 0x10
#define ZF_MASK 0x40
#define SF_MASK 0x80
#define OF_MASK 0x800
#define DF_MASK 0x400

const int FLAG_TO_MASK[] = {0, CF_MASK, PF_MASK, AF_MASK, ZF_MASK, SF_MASK, OF_MASK, DF_MASK};
#define GET_FLAG_VALUE(eflag, index) (eflag&FLAG_TO_MASK[index])

#define OPEN_PATH_LEN 256
struct open_info {
    char name[OPEN_PATH_LEN];
    int flags;
    int fileno;
};

struct read_info {
    int      fd;
    u_long  fd_ref;
    char*    buf;
};

struct write_info {
    int      fd;
    char*    buf;
};

struct writev_info {
    int fd;
    struct iovec* vi;
    int count;
};

struct mmap_info {
    u_long addr;
    int length;
    int prot;
    int flags;
    int fd;
    int fd_ref;
    int offset;
};

struct socket_info {
    int call;
    int domain;
    int type;
    int protocol;
    int fileno; // so we can later interpret our results
    struct connect_info* ci;
};

struct connect_info {
    int fd;
    char path[OPEN_PATH_LEN];    // for AF_UNIX
    int port;                   // for AF_INET/6
    struct in_addr sin_addr;    // for AF_INET
    struct in6_addr sin_addr6;  // for AF_INET6
};

struct sendmsg_info {
    int fd;
    struct msghdr* msg;
    int flags;
};

struct recvmsg_info {
    int fd;
    struct msghdr* msg;
    int flags;
};

struct select_info {
    int nfds;
    fd_set* readfds;
    fd_set* writefds;
    fd_set* exceptfds;
    struct timeval* timeout;
};

struct gettimeofday_info {
	struct timeval* tv;
	struct timezone* tz;
};

/* Commonly used fields in a syscall */
struct syscall_info {
    char name[256];
    int flags;
    int fd;
    void* arg;
    int len;
};

struct syscall_ret_info {
	int retval;
};

struct getrusage_info {
	struct rusage* usage;
};

struct clock_gettime_info {
	struct timespec* tp;
};

struct fstat64_info {
	int fd;
	struct stat64* buf;
};

struct ugetrlimit_info {
	int resource;
	struct rlimit* prlim;
};

struct uname_info {
	struct utsname* buf;
};

struct address_taint_set {
	u_long loc;
	int is_imm;
	uint32_t size;
	UT_hash_handle hh;
};

// Per-thread data structure
struct thread_data {
    int                      threadid;
    // This stuff only used for replay
    u_long                   app_syscall; // Per thread address for specifying pin vs. non-pin system calls
    u_long                   app_syscall_chk; // Per thread address for helping disambiguate pin vs. non-pin system calls with same app_sycall
    int                      record_pid;  // Ask kernel for corresponding record pid and save it here
    uint64_t                 rg_id;       // record group id
    u_long                   ignore_flag; // location of the ignore flag
    int                      sysnum;      // Stores number of system calls for return
    int                      syscall_in_progress; // True when in middle of a syscall
    int                      syscall_cnt; // per-thread syscall cnt, resets on fork
    
    // These caches are to avoid extra allocations 
    // and resulting memory fragmentation
    // This should really be a union to save space... 
    union {
	struct read_info read_info_cache;
	struct write_info write_info_cache;
	struct writev_info writev_info_cache;
	struct mmap_info mmap_info_cache;
	struct select_info select_info_cache;
	struct gettimeofday_info gettimeofday_info_cache;
	struct syscall_ret_info syscall_ret_info_cache;
	struct getrusage_info getrusage_info_cache;
	struct clock_gettime_info clock_gettime_info_cache;
	struct fstat64_info fstat64_info_cache;
	struct ugetrlimit_info ugetrlimit_info_cache;
	struct uname_info uname_info_cache;
    } op;

    void* save_syscall_info;
    int socketcall;
    int syscall_handled;            // flag to indicate if a syscall is handled at the glibc wrapper instead
    taint_t shadow_reg_table[NUM_REGS * REG_SIZE];
    taint_t current_flag_taint;
    struct syscall_info syscall_info_cache;
    struct thread_data*      next;
    struct thread_data*      prev;
    struct recheck_handle* recheck_handle;
    struct address_taint_set* address_taint_set;
};

struct memcpy_header {
    u_long dst;
    u_long src;
    u_long len;
};

#endif
