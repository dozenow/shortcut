#ifndef LINKAGE_COMMON_H
#define LINKAGE_COMMON_H

#include "pin.H"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>
#include "taint_interface/taint.h"
#include <boost/icl/interval_set.hpp>
#include <list>
#include <map>
#include <stack>
#include <queue>
#include <deque>
#include <set>
#include "../test/parseklib.h"
#include "../test/parseulib.h"
#include "track_pthread.h"

//#define OPTIMIZED

#define PRINT_DEBUG_INFO
#ifdef PRINT_DEBUG_INFO
#define OUTPUT_MAIN_THREAD(thread,format,...) fprintf (thread->main_output_file, "\"" format "\\n\"\n", ## __VA_ARGS__);
#define OUTPUT_SLICE_THREAD(thread,addr,format,...) fprintf (thread->slice_output_file, "\"" format " /*[SLICE] #%08x ", ## __VA_ARGS__, addr);
#define OUTPUT_SLICE_INFO_THREAD(thread,format,...) fprintf (thread->slice_output_file, "[SLICE_INFO] " format "*/\\n\"\n", ## __VA_ARGS__); thread->slice_linecnt++;
#define OUTPUT_SLICE_EXTRA_THREAD(thread,ip,format,...) fprintf (thread->slice_output_file, "\"" format " /*[SLICE_EXTRA] comes with %08x*/\\n\"\n", ## __VA_ARGS__, ip); thread->slice_linecnt++;
#define OUTPUT_SLICE_CTRL_FLOW_THREAD(thread,ip,format,...) fprintf (thread->slice_output_file, "\"" format " /*[SLICE_CTRL_FLOW] comes with %08x*/\\n\"\n", ## __VA_ARGS__, ip); thread->slice_linecnt++;
#define OUTPUT_SLICE_VERIFICATION_THREAD(thread,format,...) fprintf (thread->slice_output_file, "\"" format " /*", ## __VA_ARGS__);
#define OUTPUT_SLICE_VERIFICATION_INFO_THREAD(thread,format,...) fprintf (thread->slice_output_file, "[SLICE_VERIFICATION] " format "*/\\n\"\n", ## __VA_ARGS__); thread->slice_linecnt++;
#define OUTPUT_TAINT_INFO_THREAD(thread,format,...) fprintf (thread->slice_output_file, "\"/* [TAINT_INFO] " format " */\\n\"\n", ## __VA_ARGS__); thread->slice_linecnt++;
#define OUTPUT_SLICE_CHECK_ROTATE if (current_thread->slice_linecnt > 2500000) fw_slice_rotate_file (current_thread);
//#define DEBUG_INFO printf
#define DEBUG_INFO(x,...)
#else
#define OUTPUT_MAIN_THREAD(thread,format,...) fprintf (thread->main_output_file, "\"" format "\\n\"\n", ## __VA_ARGS__); 
#define OUTPUT_SLICE_THREAD(thread,addr,format,...) fprintf (thread->slice_output_file, "\"" format "\\n\"\n", ## __VA_ARGS__); thread->slice_linecnt++;
#define OUTPUT_SLICE_INFO_THREAD(x,...)
#define OUTPUT_SLICE_EXTRA_THREAD(thread,ip,format,...) fprintf (thread->slice_output_file, "\"" format "\\n\"\n", ## __VA_ARGS__); thread->slice_linecnt++;
#define OUTPUT_SLICE_CTRL_FLOW_THREAD(thread,ip,format,...) fprintf (thread->slice_output_file, "\"" format "\\n\"\n", ## __VA_ARGS__); thread->slice_linecnt++;
#define OUTPUT_SLICE_VERIFICATION_THREAD(thread,format,...) fprintf (thread->slice_output_file, "\"" format "\\n\"\n", ## __VA_ARGS__); thread->slice_linecnt++;
#define OUTPUT_SLICE_VERIFICATION_INFO_THREAD(x,...)
#define OUTPUT_SLICE_CHECK_ROTATE if (current_thread->slice_linecnt > 10000000) fw_slice_rotate_file (current_thread);
#define OUTPUT_TAINT_INFO_THREAD(x,...)
#define DEBUG_INFO(x,...)
#endif

#define OUTPUT_MAIN(format,...) OUTPUT_MAIN_THREAD(current_thread,format,## __VA_ARGS__)
#define OUTPUT_SLICE(addr,format,...) OUTPUT_SLICE_THREAD(current_thread,addr,format,## __VA_ARGS__)
#define OUTPUT_SLICE_INFO(format,...) OUTPUT_SLICE_INFO_THREAD(current_thread,format,## __VA_ARGS__)
#define OUTPUT_SLICE_EXTRA(ip,format,...) OUTPUT_SLICE_EXTRA_THREAD(current_thread,ip,format,## __VA_ARGS__);
#define OUTPUT_SLICE_CTRL_FLOW(ip,format,...) OUTPUT_SLICE_CTRL_FLOW_THREAD(current_thread,ip,format,## __VA_ARGS__);
#define OUTPUT_SLICE_VERIFICATION(format,...) OUTPUT_SLICE_VERIFICATION_THREAD(current_thread,format,## __VA_ARGS__)
#define OUTPUT_SLICE_VERIFICATION_INFO(format,...) OUTPUT_SLICE_VERIFICATION_INFO_THREAD(current_thread,format,## __VA_ARGS__)

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

#define CF_INDEX 0
#define PF_INDEX 1
#define AF_INDEX 2
#define ZF_INDEX 3
#define SF_INDEX 4
#define OF_INDEX 5
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

using namespace std;
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
    u_long   fd_ref;
    char*    buf;
    int      size;
    u_long   clock;
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

struct mremap_info {
    void* old_address;
    size_t old_size;
    size_t new_size;
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
    clockid_t clk_id;
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
    u_int cmd;
};

struct getdents64_info {
    u_int fd;
    char* buf;
    u_int count;
};

struct sigaction_info {
    struct sigaction* oact;
};

struct clone_info { 
    int flags;
    pid_t* ptid;
    pid_t* ctid;
    pid_t child_pid;
};

struct sched_getaffinity_info {
    cpu_set_t* mask;
    size_t size;
};

struct shmat_info {
    void* raddr;
};

struct recvfrom_info {
    int sockfd;
    void* buf;
    size_t len;
    int flags;
    struct sockaddr* src_addr;
    socklen_t* addrlen;
    u_long clock;
};

//store the original taint and value for the mem address
struct ctrl_flow_origin_value { 
    taint_t taint;
    char value;
};

struct ctrl_flow_branch_info {
    u_long ip;
    char branch_flag;
    int tag;
};

struct ctrl_flow_block_info { 
    //all information for a given divergence; including the index, diverge and merge point, all branches/blocks between the divergence and merge point
    u_long clock;
    uint64_t index;
    u_long ip;
    bool orig_taken;
    uint32_t merge_ip;
    int extra_loop_iterations;
    queue<struct ctrl_flow_branch_info> orig_path; // List of branches taken and not
    vector<queue<struct ctrl_flow_branch_info> > alt_path; // List of branches taken and not
    bool orig_path_nonempty; // For loops 
    vector<bool> alt_path_nonempty; // For loops
    int iter_count; // For loops - maximum number of iterations to add
    int alt_path_count;  //How many possible alternative paths between divergence and merge point
};

#define IS_BLOCK_INDEX_EQUAL(x, y) (x.clock == y.clock && x.index == y.index)
#define IS_BLOCK_INDEX_GREATER_OR_EQUAL(x,y) ((x.clock >= y.clock && x.index >= y.index))
#define IS_BLOCK_INDEX_LESS_OR_EQUAL(x,y) ((x.clock <= y.clock && x.index <= y.index))
#define CTRL_FLOW_BLOCK_TYPE_DIVERGENCE      1
#define CTRL_FLOW_BLOCK_TYPE_INSTRUMENT_ORIG 2
#define CTRL_FLOW_BLOCK_TYPE_INSTRUMENT_ALT  3
#define CTRL_FLOW_BLOCK_TYPE_MERGE           4
#define CTRL_FLOW_BLOCK_TYPE_DISTANCE        5
#define CTRL_FLOW_POSSIBLE_PATH_BEGIN        6
#define CTRL_FLOW_POSSIBLE_PATH_END          7

struct ctrl_flow_param {
    int type;
    u_long clock;
    uint64_t index;
    uint32_t ip;
    int pid;
    int iter_count;
    char branch_flag;
    int alt_branch_count;
    int tag;  //used for nested divergence
};

struct check_syscall { 
    int pid;
    u_long index;
};

struct ctrl_flow_checkpoint { 
    CONTEXT context;
    u_long clock; //for sanity check only; diverge and merge point should not cross syscall or pthread operations
    // reg taints and flag taints; mem taints is stored in store_set_mem
    // other stuff in thread_data don't need to be checkpointed. Otherwise, add it here
    taint_t reg_table[NUM_REGS * REG_SIZE];
    std::stack<struct flag_taints>* flag_taints;
    int slice_fp_top; //tracks the top of fpu stack registers in the slice; this could be different than the top of stack in the original execution
    uint64_t save_index;  //The block index before exploring alternative paths
};

/***** 
 * Please read https://endplay.eecs.umich.edu/wiki/index.php?title=Ctrl_flow for details 
 * *****/
struct ctrl_flow_info { 
    u_long clock; // Current clock value
    uint64_t index; // Current index value
    int alt_path_index;  //which alternative path we are in

    std::deque<struct ctrl_flow_block_info> *diverge_point; //index for all divergences at a specific dynamic bb
    std::map<u_long, struct ctrl_flow_block_info> *diverge_inst; //index for all divergences at all occurrences of a static bb


    //a store set is a set of modified mem/register during a possible path
    std::set<uint32_t> *store_set_reg;
    std::map<u_long, struct ctrl_flow_origin_value> *store_set_mem; //for memory, we also store the original taint value and value for this memory location, which is used laster for rolling back

    //these two vectors cover all alternative branches
    vector<set<uint32_t> > *alt_branch_store_set_reg;
    vector<map<u_long, struct ctrl_flow_origin_value> > *alt_branch_store_set_mem; //for memory, we also store the original taint value and value for this memory location, which is used laster for rolling back

    set<uint32_t> *merge_insts; 
    set<uint32_t> *insts_instrumented;  //these are the instructions we need to inspect and potentially add to the store set

    //checkpoint and rollback
    bool is_in_original_branch; //are we tracking along the original path?
    bool is_in_branch_first_inst; //are we at the first instruction, which is often equal to the jump instruction at the divergence point
    bool is_in_diverged_branch; //are we tracking one of the alternative paths?
    bool is_rolled_back; //have we rolled back to our checkpoints for at least once?
    bool changed_jump; //True is we change the jump instruction to take the opposite direction
    bool is_nested_jump; //True if this is a nested divergence
    bool is_tracking_orig_path; //True if this is a multi-path divergence with wildcards and we *will* figure out which path is the original path for this instance...
    bool is_orig_path_tracked; //True if this is a multi-path divergence with wildcards and we have *already* figure out which path is the original path for this instance...
    deque<struct ctrl_flow_branch_info>* tracked_orig_path; //Used with the above flag
    int swap_index; //The index of the alternative path that will be swapped with the original path; used by wildcard matching
    FILE* saved_slice_output_file; 
    multimap<int, bool> *handled_tags; //used for nested divergence
    
    struct ctrl_flow_checkpoint ckpt;   //this is the checkpoint before the divergence, so that we can roll back and explore the alternative path
 };

struct mutex_info_cache {
    ADDRINT mutex;
    ADDRINT attr;
};

struct wait_info_cache {
    ADDRINT mutex;
    ADDRINT cond;
    ADDRINT abstime;
    ADDRINT tid;
};

struct lll_lock_info_cache {
    ADDRINT plock;
    ADDRINT type;
};

struct patch_based_ckpt_info  {
    bool read_reg[NUM_REGS*REG_SIZE];
    char read_reg_value[NUM_REGS*REG_SIZE];
    set<int>* write_reg;
    set<u_long> *write_mem;
    map<u_long, char> *read_mem;   
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
	struct sigaction_info sigaction_info_cache;
        struct clone_info clone_info_cache;
        struct sched_getaffinity_info sched_getaffinity_info_cache;
	struct shmat_info shmat_info_cache;
        struct recvfrom_info recvfrom_info_cache;
	struct mremap_info mremap_info_cache;
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
    struct ctrl_flow_info ctrl_flow_info;
    struct patch_based_ckpt_info patch_based_ckpt_info;

    queue<string>* slice_buffer;  //generated slice is put on this buffer first:::: deprecated
    FILE* slice_output_file;        //and then written to this file
    FILE* main_output_file;        
    u_long slice_linecnt;
    u_long slice_filecnt;

    union {
        struct mutex_info_cache mutex_info_cache;
        struct wait_info_cache wait_info_cache;
        struct lll_lock_info_cache lll_lock_info_cache;
    } pthread_info; //for remembering input parameters to pthread functions

    int slice_fp_top; //tracks the top of fpu stack registers in the slice; this could be different than the top of stack in the original execution
    bool start_tracking; //Used along with function level tracking; only start to slice and taint when this flag is true
    u_long max_heap; //The maximum heap size (denoted by the end addr) the program uses; similar ideas to the mechanism we use for mmap regions in mmap_regions.cpp
};

#define FP_POP   1
#define FP_PUSH  2
#define FP_NO_STACK_CHANGE 0

struct memcpy_header {
    u_long dst;
    u_long src;
    u_long len;
};

// For syscall return divergences
#define SYSCALL_READ_EXTRA 0
struct syscall_check {
    u_long type;
    u_long clock;
    long   value;
};
#define PAGE_SIZE 4096
#endif
