#ifndef LINKAGE_COMMON_H
#define LINKAGE_COMMON_H

#include "pin.H"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "taint_interface/taint.h"
#include <boost/icl/interval_set.hpp>
#include <list>
#include <map>
#include <stack>
#include <queue>
#include <set>

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
#define ALL_FLAGS 0x7f

#define DF_INDEX 6

//actual hardware mask
//Normally we don't use them directly (only used once in computeEA function) 
#define CF_MASK 0x01
#define PF_MASK 0x04
#define AF_MASK 0x10
#define ZF_MASK 0x40
#define SF_MASK 0x80
#define OF_MASK 0x800
#define DF_MASK 0x400

#define TRACK_READONLY_REGION 
#define TRACK_CTRL_FLOW_DIVERGE   //I suspect this will break the backward taint tracing tool, but we're not actively using it anyway. It could be broken because I didn't roll back merge log when handling ctrl flow divergences, but it may still work though as the merge log may not need to be rolled back

const int FLAG_TO_MASK[] = {0, CF_MASK, PF_MASK, AF_MASK, ZF_MASK, SF_MASK, OF_MASK, DF_MASK};
#define GET_FLAG_VALUE(eflag, index) (eflag&FLAG_TO_MASK[index])

struct flag_taints {
    taint_t t[REG_SIZE];
};

#define OPEN_PATH_LEN 256
struct open_info {
    char name[OPEN_PATH_LEN];
    int flags;
    int fileno;
    int dirfd;
};

struct read_info {
    int      fd;
    u_long  fd_ref;
    char*    buf;
    int size;
    struct recheck_handle* recheck_handle;
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

struct stat64_info {
    struct stat64* buf;
};

struct ugetrlimit_info {
    int resource;
    struct rlimit* prlim;
};

struct uname_info {
    struct utsname* buf;
};

struct statfs64_info {
    struct statfs64* buf;
};

struct prlimit64_info {
    struct rlimit64* old_limit;
};

struct ioctl_info {
    u_int fd;
    char* buf;
    u_long retval_size;
};

struct getdents64_info {
    u_int fd;
    char* buf;
    u_int count;
};

//store the original taint and value for the mem address
struct ctrl_flow_origin_value { 
    taint_t taint;
    char value;
};

struct ctrl_flow_block_index { 
    u_long clock;
    uint64_t index;
};

#define IS_BLOCK_INDEX_EQUAL(x, y) (x.clock == y.clock && x.index == y.index)
#define IS_BLOCK_INDEX_GREATER_OR_EQUAL(x,y) ((x.clock >= y.clock && x.index >= y.index))
#define IS_BLOCK_INDEX_LESS_OR_EQUAL(x,y) ((x.clock <= y.clock && x.index <= y.index))
#define CTRL_FLOW_BLOCK_TYPE_DIVERGENCE 1
#define CTRL_FLOW_BLOCK_TYPE_INSTRUMENT 2
#define CTRL_FLOW_BLOCK_TYPE_MERGE      3

struct ctrl_flow_param {
    int type;
    u_long clock;
    uint64_t index;
    uint32_t ip;
    int pid;
};

struct ctrl_flow_info { 
    struct ctrl_flow_block_index block_index;  //current block index
    std::queue<struct ctrl_flow_block_index> *diverge_point; //index for all divergences
    std::queue<struct ctrl_flow_block_index> *merge_point;  //index for all merge points, corresponding to the diverege point
    std::set<uint32_t> *block_instrumented;  //these are the instructions we need to inspect and potentially add to the store set
    std::set<uint32_t> *store_set_reg;
    std::map<u_long, struct ctrl_flow_origin_value> *store_set_mem; //for memory, we also store the original taint value and value for this memory location, which is used laster for rolling back
    bool change_jump;

    //checkpoint and rollback
    bool is_rollback;
    CONTEXT ckpt_context;
    u_long ckpt_clock; //for sanity check only; diverge and merge point should not cross syscall or pthread operations
    // reg taints and flag taints; mem taints is stored in store_set_mem
    // other stuff in thread_data don't need to be checkpointed. Otherwise, add it here
    taint_t ckpt_reg_table[NUM_REGS * REG_SIZE];
    std::stack<struct flag_taints>* ckpt_flag_taints;
};

// Per-thread data structure
// Note: if you add more fields, remeber to add checkpoints to ctrl_flow_info if necessary
struct thread_data {
    int                      threadid;
    // This stuff only used for replay
    u_long                   app_syscall; // Per thread address for specifying pin vs. non-pin system calls
    u_long                   app_syscall_chk; // Per thread address for helping disambiguate pin vs. non-pin system calls with same app_sycall
    u_long                   status_addr; // Records where record/replay status is kept
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
	struct stat64_info stat64_info_cache;
	struct ugetrlimit_info ugetrlimit_info_cache;
	struct uname_info uname_info_cache;
	struct statfs64_info statfs64_info_cache;
	struct prlimit64_info prlimit64_info_cache;
	struct ioctl_info ioctl_info_cache;
	struct getdents64_info getdents64_info_cache;
    } op;

    void* save_syscall_info;
    int socketcall;
    int syscall_handled;            // flag to indicate if a syscall is handled at the glibc wrapper instead
    taint_t shadow_reg_table[NUM_REGS * REG_SIZE];
    std::stack<struct flag_taints>* saved_flag_taints;
    //taint_t saved_flag_taints[REG_SIZE]; //for pushfd and popfd
   
    uint32_t repz_counts;
    u_long repz_src_mem_loc;
    u_long repz_dst_mem_loc;
    
    struct syscall_info syscall_info_cache;
    struct thread_data*      next;
    struct thread_data*      prev;
    struct recheck_handle* recheck_handle;
    boost::icl::interval_set<unsigned long> *address_taint_set;
    struct ctrl_flow_info ctrl_flow_info;
};

struct memcpy_header {
    u_long dst;
    u_long src;
    u_long len;
};

#endif
