#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <assert.h>
#include <sys/types.h>
#include <syscall.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sched.h>
#include <errno.h>
#include <stdint.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/vfs.h>

#include <map>
using namespace std;

#include "util.h" //why doesn't this fail? 
#include "list.h"
#include "linkage_common.h"
#include "taint_interface/taint_interface.h"
#include "taint_interface/taint_creation.h"
#include "xray_monitor.h"
#include "xray_token.h"
#include "xray_slab_alloc.h"
#include "trace_x.h"
#include "splice.h"
#include "taint_nw.h"
#include "recheck_log.h"

#define PIN_NORMAL         0
#define PIN_ATTACH_RUNNING 1
#define PIN_ATTACH_BLOCKED 2
#define PIN_ATTACH_REDO    4

#define SYSNUM                      (ptdata->sysnum)
#define CURRENT_BBL                 (ptdata->current_bbl)
#define CALLING_BBLOCK_HEAD         (ptdata->calling_bblock_head)
#define CALLING_BBLOCK_SIZE         (ptdata->calling_bblock_size)
#define CTRFLOW_TAINT_STACK         (ptdata->ctrflow_taint_stack)
#define CTRFLOW_TAINT_STACK_SIZE    (ptdata->ctrflow_taint_stack_size)
#define CKPTS                       (ptdata->ckpts)
#define ALLOC_CKPTS                 (ptdata->alloc_ckpts)
#define NUM_CKPTS                   (ptdata->num_ckpts)
#define TOTAL_NUM_CKPTS             (ptdata->total_num_ckpts)
#define HANDLED_FUNC_HEAD           (ptdata->handled_func_head)
#define MERGE_ON_NEXT_RET           (ptdata->merge_on_next_ret)
#define NUM_INSTS                   (ptdata->num_insts)
#define BBL_OVER                    (ptdata->bbl_over)
#define BBLOCK_DIFFERENCE_MATCHED   (ptdata->bblock_difference_matched)
#define SAVED_REG_TAINTS            (ptdata->saved_reg_taints)
#define SAVED_FLAG_TAINTS           (ptdata->saved_flag_taints)
#define SELECT_TAINT                (ptdata->select_taint)




u_int redo_syscall = 0;

#if defined(USE_NW) || defined(USE_SHMEM)
int s = -1;
#endif
//A principle for control flow checks (startup speedups)
//if any instruction depends on a flag register, it must be re-checked on re-execution or it must be guaranteed to be the same
//We assume if the input (data and flag registers) is the same for the same instruction, the output and branches should remain the same (determinism of instructions)

// List of available Linkage macros]    // DO NOT TURN THESE ON HERE. Turn these on in makefile.rules.
// #define COPY_ONLY                    // just copies
// #define LINKAGE_DATA                 // data flow
// #define LINKAGE_DATA_OFFSET
// #define LINKAGE_SYSCALL              // system call & libc function abstraction
// #define LINKAGE_CODE
//#define LINKAGE_FDTRACK
// #define CTRL_FLOW_OLD                    // direct control flow (old def in dift);
//#define CTRL_FLOW                    // direct control flow (xdou)
//TODO: IMPORTANT: make CTRL_FLOW consistent with the defs in taint_interface/taint_full_interface.c
// #define ALT_PATH_EXPLORATION         // indirect control flow
// #define CONFAID
#define RECORD_TRACE_INFO 
#define FW_SLICE
//TODO: xdou  we may print out the same instruction several times, such as instrument_movx: it calls instrument_taint_xxxx functions several times

//used in order to trace instructions! 
//#define TRACE_INST

//#define LOGGING_ON
#define LOG_F log_f
#define ERROR_PRINT fprintf

/* Set this to clock value where extra logging should begin */
#define EXTRA_DEBUG 14067

//#define ERROR_PRINT(x,...);
#ifdef LOGGING_ON
#define LOG_PRINT(args...) \
{                           \
    fprintf(LOG_F, args);   \
    fflush(LOG_F);          \
}

#define INSTRUMENT_PRINT(args...) \
{                                   \
    fprintf(args);                  \
    fflush(log_f);                  \
}
// #define INSTRUMENT_PRINT(x,...);
 #define PRINTX fprintf
 #define SYSCALL_DEBUG fprintf
#else
 #define LOG_PRINT(x,...);
 #define INSTRUMENT_PRINT(x,...);
 #define SYSCALL_DEBUG(x,...);
 #define PRINTX(x,...);
#endif

//#define USE_CODEFLUSH_TRACK
// Debug Macros

//#define MMAP_INPUTS
//#define EXEC_INPUTS

//ARQUINN: added constant for copyfile
#define COPY_BUFFER_SIZE 1024

struct save_state {
    uint64_t rg_id; // for verification purposes, ask the kernel for these!
    int record_pid;
    unsigned long global_syscall_cnt;
    int syscall_cnt; // the per-thread count
    unsigned long open_file_cnt; 
};

/* Global state */

TLS_KEY tls_key; // Key for accessing TLS. 
int dev_fd; // File descriptor for the replay device
int get_record_pid(void);
#ifndef NO_FILE_OUTPUT
void init_logs(void);
#endif
struct thread_data* current_thread; // Always points to thread-local data (changed by kernel on context switch)
int first_thread = 1;
int child = 0;
char** main_prev_argv = 0;
char group_directory[256];
#ifndef NO_FILE_OUTPUT
FILE* log_f = NULL; // For debugging
#endif
unsigned long global_syscall_cnt = 0;
unsigned long open_file_cnt = FILENO_START; // 0 is stdin, 1 is exec args, 2 is env
struct xray_monitor* open_fds = NULL; // List of open fds
struct xray_monitor* open_socks = NULL; // list of open sockets
struct xray_monitor* open_x_fds = NULL; // list of open x sockets
FILE* filter_f = NULL;
int tokens_fd = -1;
int outfd = -1;
int trace_x = 0;
int xoutput_fd = -1;
unsigned long long inst_count = 0;
int filter_x = 0;
int filter_inputs = 0;
int print_all_opened_files = 0;
unsigned int checkpoint_clock = UINT_MAX;
unsigned long recheck_group = 0;
const char* filter_read_filename = NULL;
u_long segment_length = 0;
int splice_output = 0;
int all_output = 0;
const char* splice_semname = NULL;
const char* splice_input = NULL;
u_long num_merge_entries = 0x40000000/(sizeof(taint_t)*2);
u_long inst_cnt = 0;
map<pid_t,struct thread_data*> active_threads;
u_long* ppthread_log_clock = NULL;
u_long filter_outputs_before = 0;  // Only trace outputs starting at this value
#ifdef RECORD_TRACE_INFO
bool record_trace_info = true;
static u_long trace_total_count = 0;
static u_long trace_inst_total_count = 0;
#endif

//added for multi-process replay
const char* fork_flags = NULL;
u_int fork_flags_index = 0;
bool produce_output = true; 


#ifdef OUTPUT_FILENAMES
FILE* filenames_f = NULL; // Mapping of all opened filenames
#endif


struct slab_alloc open_info_alloc;
struct slab_alloc thread_data_alloc;

KNOB<bool> KnobFilterInputs(KNOB_MODE_WRITEONCE,
    "pintool", "i", "",
    "filter input or not");
KNOB<string> KnobFilterInputFiles(KNOB_MODE_APPEND,
    "pintool", "f", "",
    "files to input filter on, only valid with -i on");
KNOB<string> KnobFilterInputPartFilename(KNOB_MODE_APPEND,
    "pintool", "e", "",
    "partial filename to filter input on, only valid with -i on");
KNOB<string> KnobFilterInputSyscalls(KNOB_MODE_APPEND,
    "pintool", "s", "",
    "syscalls to filter input on, only valid with -i on");
KNOB<string> KnobFilterInputRegex(KNOB_MODE_APPEND,
    "pintool", "r", "",
    "regex to filter input on, only valid with -i on");
KNOB<string> KnobFilterByteRange(KNOB_MODE_APPEND,
    "pintool", "b", "",
    "byte range to filter input on, only valid with -i on");
KNOB<string> KnobFilterReadFile(KNOB_MODE_WRITEONCE,
    "pintool", "rf", "",
    "filename of filter-file to get bytes to filter input on, only valid with -i on");
KNOB<unsigned int> KnobFilterOutputsBefore(KNOB_MODE_WRITEONCE,
    "pintool", "ofb", "",
    "if set, specific clock before which we do not report output taints");
KNOB<bool> KnobTraceX(KNOB_MODE_WRITEONCE,
    "pintool", "x", "",
    "output taints to X");
KNOB<bool> KnobRecordOpenedFiles(KNOB_MODE_WRITEONCE,
    "pintool", "o", "",
    "print all opened files");
KNOB<unsigned int> KnobSegmentLength(KNOB_MODE_WRITEONCE,
    "pintool", "l", "",
    "segment length"); //FIXME: take into consideration offset of being attached later. Remember, this is to specify where to kill application.
KNOB<bool> KnobSpliceOutput(KNOB_MODE_WRITEONCE,
    "pintool", "so", "",
    "generate output splice file");
KNOB<bool> KnobAllOutput(KNOB_MODE_WRITEONCE,
    "pintool", "ao", "",
    "generate output file of changed taints");
KNOB<int> KnobMergeEntries(KNOB_MODE_WRITEONCE,
    "pintool", "me", "",
    "merge entries"); 
KNOB<string> KnobNWHostname(KNOB_MODE_WRITEONCE,
    "pintool", "host", "",
    "hostname for nw output");
KNOB<int> KnobNWPort(KNOB_MODE_WRITEONCE,
    "pintool", "port", "",
    "port for nw output");
KNOB<string> KnobForkFlags(KNOB_MODE_WRITEONCE,
    "pintool", "fork_flags", "",
    "flags for which way to go on each fork");
KNOB<unsigned int> KnobCheckpointClock(KNOB_MODE_WRITEONCE,
    "pintool", "ckpt_clock", "",
    "taint tracking until ckpt_clock(inclusive) and generates params_log logs. The clock should always be the end clock of a syscall (checkpoint files has the same property in namings)");
KNOB<unsigned int> KnobRecheckGroup(KNOB_MODE_WRITEONCE,
    "pintool", "recheck_group", "",
    "specifies the group for the recheck log (if not specified, then don't generate log)");
KNOB<string> KnobGroupDirectory(KNOB_MODE_WRITEONCE, 
    "pintool", "group_dir", "",
    "the directory for the output files");
#ifdef RETAINT
KNOB<string> KnobRetaintEpochs(KNOB_MODE_WRITEONCE,
    "pintool", "retaint", "",
    "list of clock values to retaint on");
#endif
#ifdef RECORD_TRACE_INFO
KNOB<bool> KnobRecordTraceInfo(KNOB_MODE_WRITEONCE,
    "pintool", "rectrace", "",
    "record trace information");
#endif

//ARQUINN: added helper methods for copying tokens from the file
#ifdef USE_FILE
static void copy_file(int src, int dest) { 
    char buff[COPY_BUFFER_SIZE]; 
    int read_bytes, written_bytes,rc;

    rc = lseek(src,0, SEEK_SET);
    if(rc < 0) 
	fprintf(stderr, "There was an error using lseek rc %d, errno %d\n",rc,errno);

    while((read_bytes = read(src,buff,COPY_BUFFER_SIZE)) > 0) 
    {
	written_bytes = 0;
	while(written_bytes < read_bytes) { 
	    written_bytes += write(dest,buff,read_bytes - written_bytes);
	}
    }
    if(read_bytes < 0) { 
	fprintf(stderr, "There was an error reading file (int) rc %d, errno %d\n",read_bytes,errno);
    }
}
#ifdef OUTPUT_FILENAME
static void copy_file(FILE* src, FILE* dest) { 
    char buff[COPY_BUFFER_SIZE]; 
    int read_chars,written_chars, rc;

    rc = fseek(src,0, SEEK_SET);
    if(rc < 0) 
	fprintf(stderr, "There was an error using lseek rc %d, errno %d\n",rc,errno);

    while((read_chars = fread(buff,sizeof(char),COPY_BUFFER_SIZE,src)) > 0) 
    { 
	written_chars = 0;
	while(written_chars < read_chars) { 
	    written_chars += fwrite(buff,sizeof(char),read_chars-written_chars, dest);
	}
	fprintf(stderr, "\t wrote another %d bytes\n",written_chars);
    }
    if(read_chars < 0) { 
	fprintf(stderr, "There was an error reading file (FILE*) rc %d, errno %d\n",read_chars,errno);
    }
}
#endif
#endif

#ifdef RETAINT
void reset_taints ();
const char* retaint;
char* retaint_str;
u_long retaint_next_clock = 0;
u_long retaint_us = 0;

#endif

static int terminated = 0;
extern int dump_mem_taints (int fd);
extern int dump_reg_taints (int fd, taint_t* pregs, int thread_ndx);
extern int dump_mem_taints_start (int fd);
extern int dump_reg_taints_start (int fd, taint_t* pregs, int thread_ndx);
extern taint_t taint_num;
#ifdef RECORD_TRACE_INFO 
static inline void flush_trace_hash (int sysnum);
static inline void term_trace_buf ();
#endif

#ifdef TAINT_DEBUG
extern void print_taint_debug_reg (int tid, taint_t* pregs);
extern void print_taint_debug_mem ();
extern u_long debug_taint_cnt;
FILE* debug_f;
u_long taint_debug_inst = 0;
#endif
FILE* slice_f;

#ifdef TAINT_STATS
struct timeval begin_tv, end_tv;
u_long inst_instrumented = 0;
u_long traces_instrumented = 0;
u_long mm_len = 0;
uint64_t instrument_time = 0;

u_long collisions = 0;
u_long hash_flushes = 0;
//u_long entries = 0;
FILE* stats_f;
u_long num_of_inst_executed = 0;
#endif

extern void write_token_finish (int fd);
extern void output_finish (int fd);
void instrument_test_or_cmp(INS ins, uint32_t set_mask, uint32_t clear_mask);

//In here we need to mess with stuff for if we are no longer following this process
static int dift_done ()
{    
    /* 
       in the case where this is called when pin hasn't attached to everyone we have to lock here 
       b/c otherwise we have a race
     */

    PIN_LockClient();
    if (terminated) {
	PIN_UnlockClient();
	return 0;  // Only do this once
    }    
    terminated = 1;
    PIN_UnlockClient();
    fprintf(stderr, "%d: in dift_done\n",PIN_GetTid());

#ifdef USE_FILE
    char taint_structures_file[256];
    snprintf(taint_structures_file, 256, "%s/taint_structures", group_directory);
    int taint_fd = open(taint_structures_file, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
    assert(taint_fd > 0);
#endif
#ifdef USE_SHMEM
    char taint_structures_file[256];
    snprintf(taint_structures_file, 256, "/taint_structures_shm%s", group_directory);
    for (u_int i = 1; i < strlen(taint_structures_file); i++) {
	if (taint_structures_file[i] == '/') taint_structures_file[i] = '.';
    }
    int taint_fd = shm_open(taint_structures_file, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (taint_fd < 0) {
	fprintf(stderr, "could not open taint shmem %s, errno %d\n", taint_structures_file, errno);
	assert(0);
    }
    if (all_output) {
	int rc = ftruncate64 (taint_fd, MAX_DUMP_SIZE);
	if (rc < 0) {
	    fprintf(stderr, "could not truncate shmem %s, errno %d\n", taint_structures_file, errno);
	    assert(0);
	}
    }
#endif
#ifdef USE_NW
    int taint_fd = s;
#endif

#ifndef USE_NULL    
    if (all_output) {
	int thread_ndx = 0;
	if (splice_output) {
	    // Dump out the active registers in order of the record thread id
	    for (map<pid_t,struct thread_data*>::iterator iter = active_threads.begin(); 
		 iter != active_threads.end(); iter++) {
		dump_reg_taints(taint_fd, iter->second->shadow_reg_table, thread_ndx++);
	    }
	    dump_mem_taints(taint_fd);
	} else {
	    // Dump out the active registers in order of the record thread id
	    for (map<pid_t,struct thread_data*>::iterator iter = active_threads.begin(); 
		 iter != active_threads.end(); iter++) {
		dump_reg_taints_start(taint_fd, iter->second->shadow_reg_table, thread_ndx++);
	    }
	    dump_mem_taints_start(taint_fd);
	}
    }
#endif
    // Finish up output of other files
#ifdef USE_NW
    write_token_finish (s);
#endif
#ifdef USE_SHMEM
    //sential for not following
    if (tokens_fd != -99999 && outfd != -99999) { 
	write_token_finish (tokens_fd);
	output_finish (outfd);
    }
#endif
#ifdef RECORD_TRACE_INFO
    if (record_trace_info) term_trace_buf ();
#endif
#ifdef TAINT_STATS
#ifndef USE_FILE
    if (tokens_fd != -99999 && outfd != -99999 && s != -99999) { 
#else
    if (tokens_fd != -99999 && outfd != -99999) { 
#endif
	gettimeofday(&end_tv, NULL);
	fprintf (stats_f, "Instructions instrumented: %ld\n", inst_instrumented);
	fprintf (stats_f, "Traces instrumented: %ld\n", traces_instrumented);
#ifdef RECORD_TRACE_INFO
	fprintf (stats_f, "Traces executed: %ld\n", trace_total_count/sizeof(u_long));
	fprintf (stats_f, "collisions: %lu us\n", collisions);
	fprintf (stats_f, "has_flushes: %lu us\n", hash_flushes);
#endif
	fprintf (stats_f, "Instrument time: %lld us\n", instrument_time);

	fprintf (stats_f, "DIFT began at %ld.%06ld\n", begin_tv.tv_sec, begin_tv.tv_usec);
	fprintf (stats_f, "DIFT ended at %ld.%06ld\n", end_tv.tv_sec, end_tv.tv_usec);

	fprintf (stats_f, "mmap_len %lu\n",mm_len);

//	fprintf (stats_f, "MM time %.3f seconds\n",mm_time);
#ifdef RETAINT
	float retaint_time = end_tv.tv_sec - begin_tv.tv_sec;
	retaint_time += (float) (end_tv.tv_usec - begin_tv.tv_usec)/1000000.0;
	retaint_time -= (float) retaint_us/1000000.0;
	fprintf (stats_f, "Retaint execution time: %.3f seconds\n", retaint_time);
#endif
	fprintf (stats_f, "Total number of inst executed: %lu\n", num_of_inst_executed);
	finish_and_print_taint_stats(stats_f);
	fclose (stats_f);
    }
#ifdef RETAINT
	float retaint_time = end_tv.tv_sec - begin_tv.tv_sec;
	retaint_time += (float) (end_tv.tv_usec - begin_tv.tv_usec)/1000000.0;
	retaint_time -= (float) retaint_us/1000000.0;
	fprintf (stats_f, "Retaint execution time: %.3f seconds\n", retaint_time);
#endif

#else
    finish_and_print_taint_stats(stdout);
#endif

#ifdef TAINT_DEBUG
    fclose (debug_f);
#endif

    printf("DIFT done at %ld\n", *ppthread_log_clock);

#ifndef RETAINT
#ifdef USE_SHMEM
    // Send "done" message to aggregator
    if (s != -99999) {
	int rc = write (s, &group_directory, sizeof(group_directory));
	if (rc != sizeof(group_directory)) {
	    fprintf (stderr, "write of directory failed, rc=%d, errno=%d\n", rc, errno);
	}
    }
#endif
#endif
    return 1; //we are the one that acutally did the dift done
}

ADDRINT find_static_address(ADDRINT ip)
{
    PIN_LockClient();
    IMG img = IMG_FindByAddress(ip);
    if (!IMG_Valid(img)) return ip;
    ADDRINT offset = IMG_LoadOffset(img);
    PIN_UnlockClient();
    return ip - offset;
}

void print_static_address(FILE* fp, ADDRINT ip)
{
    const char* img_name = "--";
    ADDRINT static_ip = find_static_address(ip);
    PIN_LockClient();
    if (IMG_Valid(IMG_FindByAddress(ip))) {
        img_name = IMG_Name(IMG_FindByAddress(ip)).c_str();
    }
    fprintf(fp, "%#x %s\n", static_ip, img_name);
    PIN_UnlockClient();
}

static inline void increment_syscall_cnt (int syscall_num)
{
    // ignore pthread syscalls, or deterministic system calls that we don't log (e.g. 123, 186, 243, 244)
    if (!(syscall_num == 17 || syscall_num == 31 || syscall_num == 32 || 
	  syscall_num == 35 || syscall_num == 44 || syscall_num == 53 || 
	  syscall_num == 56 || syscall_num == 58 || syscall_num == 98 || 
	  syscall_num == 119 || syscall_num == 123 || syscall_num == 127 ||
	  syscall_num == 186 || syscall_num == 243 || syscall_num == 244)) {
        if (current_thread->ignore_flag) {
            if (!(*(int *)(current_thread->ignore_flag))) {
                global_syscall_cnt++;
                current_thread->syscall_cnt++;
            }
        } else {
            global_syscall_cnt++;
            current_thread->syscall_cnt++;
        }
#if 0
#ifdef TAINT_DEBUG
	fprintf (debug_f, "pid %d syscall %d global syscall cnt %lu num %d clock %ld\n", current_thread->record_pid, 
		 current_thread->syscall_cnt, global_syscall_cnt, syscall_num, *ppthread_log_clock);
#endif
#endif
    }
}

static void create_connect_info_name(char* connect_info_name, int domain,
				     struct connect_info* ci)
{
    assert(ci);
    if (domain == AF_UNIX) {
        memcpy(connect_info_name, ci->path, 108); // 108 is the magic number
    } else if (domain == AF_INET) {
        char address[256];
        if (!inet_ntop(AF_INET, &ci->sin_addr, address, 256)) {
            strcpy(connect_info_name, "UNKNOWN_SOCKET");
            return;
        }
        snprintf(connect_info_name, 256, "%s:%d", address, ci->port);
    } else if (domain == AF_INET6) {
        char address[256];
        if (!inet_ntop(AF_INET6, &ci->sin_addr6, address, 256)) {
            strcpy(connect_info_name, "UNKNOWN_SOCKET");
            return;
        }
        snprintf(connect_info_name, 256, "%s:%d", address, ci->port);
    } else {
        strcpy(connect_info_name, "UNKNOWN_SOCKET");
    }
}

char* get_file_ext(char* filename){
    char* last = strrchr(filename, '/');
    char* dot;
    if (!last) {
        dot = strrchr(filename, '.');
    }
    else {
        dot = strrchr(last, '.');
    }
    if(!dot || dot == filename) {
        return NULL;
    }
    return dot+1;
}

static inline void add_tainted_mem_for_final_check (u_long mem_loc, uint32_t size) { 
	struct address_taint_set* addr_struct = NULL;
	HASH_FIND_ULONG (current_thread->address_taint_set, &mem_loc, addr_struct);
	if (addr_struct == NULL) {
		addr_struct = (struct address_taint_set*)malloc (sizeof(struct address_taint_set));
		addr_struct->loc = mem_loc;
		addr_struct->is_imm = 1;
		addr_struct->size = size;
		HASH_ADD_ULONG (current_thread->address_taint_set, loc, addr_struct);
	} else { 
		//TODO: we didn't check memory overlapping correctly
		if (addr_struct->size != size) { 
		    printf ("[BUG] tricky: the memory address is overlapping (for checking taints on the final checkpoint\n");
		}
	}
}

static inline void sys_open_start(struct thread_data* tdata, char* filename, int flags, int mode)
{
    SYSCALL_DEBUG (stderr, "open_start: filename %s, clock %lu\n", filename, *ppthread_log_clock);
    struct open_info* oi = (struct open_info *) malloc (sizeof(struct open_info));
    strncpy(oi->name, filename, OPEN_PATH_LEN);
    oi->fileno = open_file_cnt;
    oi->flags = flags;
    open_file_cnt++;
    tdata->save_syscall_info = (void *) oi;
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call open_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_open (tdata->recheck_handle, filename, flags, mode);
    } 
}

static inline void sys_open_stop(int rc)
{
    if (rc > 0) {
      struct open_info* oi = (struct open_info *) current_thread->save_syscall_info; 
        monitor_add_fd(open_fds, rc, 0, current_thread->save_syscall_info);
	//SYSCALL_DEBUG(stderr, "open: added fd %d\n", rc);
#ifdef OUTPUT_FILENAMES
        write_filename_mapping(filenames_f, oi->fileno, oi->name);
#endif

#ifdef LINKAGE_FDTRACK
        int cloexec = oi->flags | O_CLOEXEC;
        add_taint_fd(rc, cloexec);
#else 
	if (oi->flags) {
		//do nothing, just to shut up the compiler
	}
#endif
    }
    current_thread->save_syscall_info = NULL;
}

static inline void sys_openat_start (struct thread_data* tdata, int dirfd, char* filename, int flags, int mode) {
    SYSCALL_DEBUG (stderr, "openat_start: filename %s, clock %lu, dirfd %d\n", filename, *ppthread_log_clock, dirfd);
    struct open_info* oi = (struct open_info*) malloc (sizeof(struct open_info));
    strncpy (oi->name, filename, OPEN_PATH_LEN);
    oi->fileno = open_file_cnt ++;
    oi->flags = flags;
    oi->dirfd = dirfd;
    tdata->save_syscall_info = (void*) oi;
    if (tdata->recheck_handle) { 
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call openat_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
        recheck_openat (tdata->recheck_handle, dirfd, filename, flags, mode);
    }
}

static inline void sys_openat_stop (int rc) { 
    return sys_open_stop (rc);
}

static inline void sys_close_start(struct thread_data* tdata, int fd)
{
    SYSCALL_DEBUG (stderr, "close_start @ %lu\n", *ppthread_log_clock);
    tdata->save_syscall_info = (void *) fd;
    if (tdata->recheck_handle) {
	if (!current_thread->ignore_flag || !(*(int *)(current_thread->ignore_flag))) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call close_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_close (tdata->recheck_handle, fd);
	} else {
	    printf ("close occurred during ignore region of the replay code\n");
	}
    }
}

static inline void sys_close_stop(int rc)
{
    SYSCALL_DEBUG (stderr, "close_stop @ %lu\n", *ppthread_log_clock);
    int fd = (int) current_thread->save_syscall_info;
    // remove the fd from the list of open files
    if (!rc) {
        if (monitor_has_fd(open_fds, fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, fd);
	    free (oi);
            monitor_remove_fd(open_fds, fd);
	    SYSCALL_DEBUG (stderr, "close: remove fd %d\n", fd);
        } 
	if (monitor_has_fd(open_socks, fd)) {
		monitor_remove_fd(open_socks, fd);
		SYSCALL_DEBUG (stderr, "close: remove sock fd %d\n", fd);
	}
#ifdef LINKAGE_FDTRACK
        remove_taint_fd(fd);
#endif
    }
    current_thread->save_syscall_info = 0;
}

static inline void sys_llseek_start(struct thread_data* tdata, u_int fd, u_long offset_high, u_long offset_low, loff_t* result, u_int whence)
{
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call llseek_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_llseek (tdata->recheck_handle, fd, offset_high, offset_low, result, whence);
    }
}

static inline void sys_brk_start(struct thread_data* tdata, void *addr)
{
    tdata->save_syscall_info = (void *) addr;
}

static inline void sys_brk_stop(int rc)
{
    current_thread->save_syscall_info = 0;
}

static inline void sys_read_start(struct thread_data* tdata, int fd, char* buf, int size)
{
    SYSCALL_DEBUG(stderr, "sys_read_start: fd = %d, buf %x\n", fd, (unsigned int)buf);
    struct read_info* ri = &tdata->op.read_info_cache;
    ri->fd = fd;
    ri->buf = buf;
    ri->size = size;
    ri->recheck_handle = tdata->recheck_handle;
    tdata->save_syscall_info = (void *) ri;
}

static inline void sys_read_stop(int rc)
{
    int read_fileno = -1;
    struct read_info* ri = (struct read_info*) &current_thread->op.read_info_cache;

    if (ri->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call read_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	if (filter_input()) {
	    size_t start = 0;
	    size_t end = 0;
	    if (get_partial_taint_byte_range(current_thread->syscall_cnt, &start, &end)) {
		recheck_read (ri->recheck_handle, ri->fd, ri->buf, ri->size, 1, start, end);
		add_tainted_mem_for_final_check ((u_long) (ri->buf+start), end-start);
	    } else {
		recheck_read (ri->recheck_handle, ri->fd, ri->buf, ri->size, 0, 0, 0);
	    }
	} else {
             recheck_read (ri->recheck_handle, ri->fd, ri->buf, ri->size, 0, 0, 0);
	}
    }

    if (rc > 0) {
        struct taint_creation_info tci;
        char* channel_name = (char *) "--";
	char* channel_name_ret = (char*) "read_retval";

        if (monitor_has_fd(open_fds, ri->fd)) {
            struct open_info* oi;
            oi = (struct open_info *)monitor_get_fd_data(open_fds, ri->fd);
            read_fileno = oi->fileno;
            channel_name = oi->name;
        } else if (monitor_has_fd(open_socks, ri->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ri->fd);
	    if (si) {
		if (si->domain == AF_INET || si->domain == AF_INET6) {
		    channel_name = (char *) "inetsocket";
		} else {
		    channel_name = (char *) "recvsocket";
		}
	    } else {
		fprintf (stderr, "read from socket no si, rc=%d\n", rc);
	    }
        } else if(ri->fd == fileno(stdin)) {
		read_fileno = FILENO_STDIN;
	}

	tci.rg_id = current_thread->rg_id;
	tci.record_pid = current_thread->record_pid;
	tci.syscall_cnt = current_thread->syscall_cnt;
	tci.offset = 0;
	tci.fileno = read_fileno;
	tci.data = 0;
	tci.type = TOK_READ;

        LOG_PRINT ("Create taints from buffer sized %d at location %#lx\n",
                        rc, (unsigned long) ri->buf);
        //fprintf(stderr, "inst_count = %lld\n", inst_count);
	//clear mem taints: if we don't taint this input buffer, then the memory region should be untainted
	clear_mem_taints ((u_long)ri->buf, rc);
        create_taints_from_buffer(ri->buf, rc, &tci, tokens_fd, channel_name);
	//track control flow taints for retvals	
	tci.fileno = -1;
	tci.type = TOK_READ_RET;
	create_syscall_retval_taint (&tci, tokens_fd, channel_name_ret);
#ifdef LINKAGE_FDTRACK
        //fprintf(stderr, "read from fd %d\n", ri->fd);
        if (is_fd_tainted(ri->fd)) {
            taint_add_fd2mem((u_long) ri->buf, rc, ri->fd);
        }
#endif
    }

    memset(&current_thread->op.read_info_cache, 0, sizeof(struct read_info));
    current_thread->save_syscall_info = 0;
}

static inline void sys_pread_start(struct thread_data* tdata, int fd, char* buf, int size)
{
    SYSCALL_DEBUG(stderr, "pread fd = %d\n", fd);
    struct read_info* ri = &tdata->op.read_info_cache;
    ri->fd = fd;
    ri->buf = buf;
    tdata->save_syscall_info = (void *) ri;

#ifdef TAINT_DEBUG
    fprintf (debug_f, "pid %d pread fd %d clock %lu\n", tdata->record_pid, fd, *ppthread_log_clock);

#endif
}

static inline void sys_pread_stop(int rc)
{
    int read_fileno = -1;
    struct read_info* ri = (struct read_info*) &current_thread->op.read_info_cache;

    // If global_syscall_cnt == 0, then handled in previous epoch
    if (rc > 0) {
        struct taint_creation_info tci;
        char* channel_name = (char *) "--";

        if (monitor_has_fd(open_fds, ri->fd)) {
            struct open_info* oi;
            oi = (struct open_info *)monitor_get_fd_data(open_fds, ri->fd);
            read_fileno = oi->fileno;
            channel_name = oi->name;
        } else if(ri->fd == fileno(stdin)) {
            read_fileno = 0;
        }

        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = read_fileno;
        tci.data = 0;
	tci.type = TOK_READ;

        LOG_PRINT ("Create taints from buffer sized %d at location %#lx\n",
                        rc, (unsigned long) ri->buf);
        create_taints_from_buffer(ri->buf, rc, &tci, tokens_fd, channel_name);
    }

    memset(&current_thread->op.read_info_cache, 0, sizeof(struct read_info));
    current_thread->save_syscall_info = 0;
}

static inline void sys_readlink_start(struct thread_data* tdata, char* path, char* buf, size_t bufsiz)
{
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call readlink_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_readlink (tdata->recheck_handle, path, buf, bufsiz);
    }
}

static void sys_ioctl_start(struct thread_data* tdata, int fd, u_int cmd, char* arg)
{
    struct ioctl_info* ii = &tdata->op.ioctl_info_cache;
    ii->fd = fd;
    ii->buf = arg;
    ii->retval_size = 0;
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call ioctl_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	ii->retval_size = recheck_ioctl (tdata->recheck_handle, fd, cmd, arg);
    }
}

static inline void taint_syscall_memory_out (const char* sysname, char* buf, u_long size) 
{
    struct taint_creation_info tci;
    tci.type = TOK_SYSCALL_MEM;
    tci.rg_id = current_thread->rg_id;
    tci.record_pid = current_thread->record_pid;
    tci.syscall_cnt = current_thread->syscall_cnt;
    tci.offset = 0;
    tci.fileno = 0;
    tci.data = 0;
    create_taints_from_buffer_unfiltered (buf, size, &tci, tokens_fd);
    printf ("[SLICE_TAINT] %s %lx %lx\n", sysname, (u_long)buf, (u_long)buf+size);
    add_tainted_mem_for_final_check ((u_long)buf, size);
}

static void sys_ioctl_stop (int rc) 
{
    struct ioctl_info* ii = &current_thread->op.ioctl_info_cache;
    if (rc >= 0 && ii->retval_size > 0) {
	taint_syscall_memory_out ("ioctl", ii->buf, ii->retval_size);
    }
}

static void sys_fcntl64_start(struct thread_data* tdata, int fd, int cmd, void* arg)
{
    printf ("fcntl64: fd %d cmd %d arg %p\n", fd, cmd, arg);
    switch (cmd) {
    case F_GETFL:
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call fcntl64_getfl_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_fcntl64_getfl (tdata->recheck_handle, fd);
	}
	break;
    case F_SETFL:
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call fcntl64_setfl_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_fcntl64_setfl (tdata->recheck_handle, fd, (long) arg);
	}
	break;
    case F_GETLK:
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call fcntl64_getlk_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_fcntl64_getlk (tdata->recheck_handle, fd, arg);
	}
	break;
    case F_GETOWN:
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call fcntl64_getown_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_fcntl64_getown (tdata->recheck_handle, fd);
	}
	break;
    case F_SETOWN:
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call fcntl64_setown_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_fcntl64_setown (tdata->recheck_handle, fd, (long) arg);
	}
	break;
    default:
	fprintf (stderr, "[ERROR] fcntl64 cmd %d not yet handled for recheck\n", cmd);
    }
}

#ifdef LINKAGE_FDTRACK
static void sys_select_start(struct thread_data* tdata, int nfds, fd_set* readfds, fd_set* writefds, 
			     fd_set* exceptfds, struct timeval* timeout)
{
    tdata->op.select_info_cache.nfds = nfds;
    tdata->op.select_info_cache.readfds = readfds;
    tdata->op.select_info_cache.writefds = writefds;
    tdata->op.select_info_cache.exceptfds = exceptfds;
    tdata->op.select_info_cache.timeout = timeout;
}

static void sys_select_stop(int rc)
{
    // If global_syscall_cnt == 0, then handled in previous epoch
    if (rc != -1) {
        // create a taint
        struct taint_creation_info tci;
        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = FILENO_SELECT;
        tci.data = 0;
        tci.type = TOK_SELECT;

        create_fd_taints(current_thread->op.select_info_cache.nfds,
                current_thread->op.select_info_cache.readfds,
                &tci, tokens_fd);
    }
}
#endif

static void sys_mmap_start(struct thread_data* tdata, u_long addr, int len, int prot, int fd)
{
    struct mmap_info* mmi = &tdata->op.mmap_info_cache;
    mmi->addr = addr;
    mmi->length = len;
    mmi->prot = prot;
    mmi->fd = fd;
    tdata->save_syscall_info = (void *) mmi;
    tdata->app_syscall_chk = len + prot; // Pin sometimes makes mmaps during mmap
}

static void sys_mmap_stop(int rc)
{
    struct mmap_info* mmi = (struct mmap_info*) current_thread->save_syscall_info;
//    struct timeval mm_st, mm_end; 

    SYSCALL_DEBUG(stderr, "mmap file fd %d rc 0x%x @ %ld %d\n", mmi->fd, rc, *ppthread_log_clock , mmi->prot & PROT_EXEC);
#ifdef MMAP_INPUTS
    // If global_syscall_cnt == 0, then handled in previous epoch
    if (rc != -1 && (mmi->fd != -1)) {
        fprintf(stderr, "mmap stop fd %d\n", mmi->fd);
        int read_fileno = -1;
        struct open_info* oi = NULL;
        char* channel_name = (char *) "--";

        if (monitor_has_fd(open_fds, mmi->fd)) {
            oi = (struct open_info *) monitor_get_fd_data(open_fds, mmi->fd);
            assert (oi);
            read_fileno = oi->fileno;
            channel_name = oi->name;
            fprintf(stderr, "mmap file name is %s, %d\n", channel_name, mmi->prot & PROT_EXEC);
        }
        if (!(mmi->prot & PROT_EXEC)) {
            struct taint_creation_info tci;
            tci.rg_id = current_thread->rg_id;
            tci.record_pid = current_thread->record_pid;
            tci.syscall_cnt = current_thread->syscall_cnt;
            tci.offset = 0;
            tci.fileno = read_fileno;
            tci.data = 0;
	    tci.type = TOK_MMAP;

            fprintf(stderr, "mmap: call create taints from buffer %#lx, %d\n", (u_long) rc, mmi->length);
            create_taints_from_buffer ((void *) rc, mmi->length, &tci, tokens_fd,
                                        channel_name);
        } else {
            fprintf(stderr, "mmap is PROT_EXEC\n");
        }
    }
    current_thread->save_syscall_info = 0;
    SYSCALL_DEBUG (stderr, "sys_mmap_stop done\n");
#else
    mm_len += mmi->length;
    //if there are taints to be cleared, and we aren't a splice_output
    if (!splice_output && taint_num > 1) {
	clear_mem_taints (rc, mmi->length);
    }

#endif
}

#if 0
static void sys_munmap_start(struct thread_data* tdata, u_long addr, int len)
{
    struct mmap_info* mmi = &tdata->op.mmap_info_cache;
    mmi->addr = addr;
    mmi->length = len;
    tdata->save_syscall_info = (void *) mmi;
}

static void sys_munmap_stop(int rc)
{
    struct mmap_info* mmi = (struct mmap_info*) current_thread->save_syscall_info;
    if (rc == 0) {
	fprintf (stderr, "munmap at clock %ld addr %lx len %x\n", *ppthread_log_clock, mmi->addr, mmi->length);
    }
}
#endif

static inline void sys_write_start(struct thread_data* tdata, int fd, char* buf, size_t count)
{
    struct write_info* wi = &tdata->op.write_info_cache;
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call write_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_write (tdata->recheck_handle, fd, buf, count);
    }
    wi->fd = fd;
    wi->buf = buf;
    tdata->save_syscall_info = (void *) wi;
}

static inline void sys_write_stop(int rc)
{
    struct write_info* wi = (struct write_info *) &current_thread->op.write_info_cache;
    int channel_fileno = -1;
    if (rc > 0) {
	if (*ppthread_log_clock >= filter_outputs_before) {
	    struct taint_creation_info tci;
	    SYSCALL_DEBUG (stderr, "write_stop: sucess write of size %d\n", rc);
	    
	    if (monitor_has_fd(open_fds, wi->fd)) {
		struct open_info* oi;
		oi = (struct open_info *) monitor_get_fd_data(open_fds, wi->fd);
		assert(oi);
		channel_fileno = oi->fileno;
	    } else if (wi->fd == fileno(stdout)) {
		channel_fileno = FILENO_STDOUT;
	    } else if (wi->fd == fileno(stderr)) {
		channel_fileno = FILENO_STDERR;
	    } else if (wi->fd == fileno(stdin)) {
		channel_fileno = FILENO_STDIN;
	    } else {
		channel_fileno = -1;
	    }
	    tci.type = 0;
	    tci.rg_id = current_thread->rg_id;
	    tci.record_pid = current_thread->record_pid;
	    tci.syscall_cnt = current_thread->syscall_cnt;
	    if (!current_thread->syscall_in_progress) {
		tci.syscall_cnt--; // Weird restart issue
	    }
	    tci.offset = 0;
	    tci.fileno = channel_fileno;
	    
	    LOG_PRINT ("Output buffer result syscall %u, %#lx\n", tci.syscall_cnt, (u_long) wi->buf);
	    if (produce_output) { 
		output_buffer_result (wi->buf, rc, &tci, outfd);
	    }
	}
    }
}

static inline void sys_writev_start(struct thread_data* tdata, int fd, struct iovec* iov, int count)
{
    SYSCALL_DEBUG(stderr, "sys_writev_start: fd = %d\n", fd);
    struct writev_info* wvi;
    wvi = (struct writev_info *) &tdata->op.writev_info_cache;
    wvi->fd = fd;
    wvi->count = count;
    wvi->vi = iov;
    tdata->save_syscall_info = (void *) wvi;
}

static inline void sys_writev_stop(int rc)
{
    // If syscall cnt = 0, then write handled in previous epoch
    if (rc > 0) {
	if (*ppthread_log_clock >= filter_outputs_before) {
	    struct taint_creation_info tci;
	    struct writev_info* wvi = (struct writev_info *) &current_thread->op.writev_info_cache;
	    int channel_fileno = -1;
	    if (monitor_has_fd(open_fds, wvi->fd)) {
		struct open_info* oi;
		oi = (struct open_info *) monitor_get_fd_data(open_fds, wvi->fd);
		assert(oi);
		channel_fileno = oi->fileno;
	    } if (monitor_has_fd(open_socks, wvi->fd)) {
		struct socket_info* si;
		si = (struct socket_info *) monitor_get_fd_data(open_socks, wvi->fd);
		channel_fileno = si->fileno;
	    } else {
		channel_fileno = -1;
	    }
	    
	    tci.type = 0;
	    tci.rg_id = current_thread->rg_id;
	    tci.record_pid = current_thread->record_pid;
	    tci.syscall_cnt = current_thread->syscall_cnt;
	    tci.offset = 0;
	    tci.fileno = channel_fileno;
	    
	    if (filter_x) {
		if (!monitor_has_fd(open_x_fds, wvi->fd)) {
		    for (int i = 0; i < wvi->count; i++) {
			struct iovec* vi = (wvi->vi + i);
			if (produce_output) { 
			    output_buffer_result(vi->iov_base, vi->iov_len, &tci, outfd);
			}
			tci.offset += vi->iov_len;
		    }
		}
	    } else {
		for (int i = 0; i < wvi->count; i++) {
		    struct iovec* vi = (wvi->vi + i);
		    if (produce_output) { 
			output_buffer_result(vi->iov_base, vi->iov_len, &tci, outfd);
		    }
		    tci.offset += vi->iov_len;
		}
	    }
        }
    }
    memset(&current_thread->op.writev_info_cache, 0, sizeof(struct writev_info));
}

static void sys_socket_start (struct thread_data* tdata, int domain, int type, int protocol)
{
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call socket_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_socket (tdata->recheck_handle, domain, type, protocol);
    }
    struct socket_info* si = (struct socket_info*) malloc(sizeof(struct socket_info));
    if (si == NULL) {
	fprintf (stderr, "Unable to malloc socket info\n");
	assert (0);
    }
    si->call = SYS_SOCKET;
    si->domain = domain;
    si->type = type;
    si->protocol = protocol;
    si->fileno = -1; // will be set in connect/accept/bind
    si->ci = NULL;

    tdata->save_syscall_info = si;
}

static void sys_socket_stop(int rc)
{
    if (rc > 0) {
        struct socket_info* si = (struct socket_info *) current_thread->save_syscall_info;
        monitor_add_fd(open_socks, rc, 0, si);
        current_thread->save_syscall_info = NULL; // Giving si to the monitor
    }
}

static void sys_connect_start(thread_data* tdata, int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call connect_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_connect (tdata->recheck_handle, sockfd, addr, addrlen);
    }
    if (monitor_has_fd(open_socks, sockfd)) {
        struct socket_info* si = (struct socket_info*) monitor_get_fd_data(open_socks, sockfd);
        struct connect_info* ci = (struct connect_info *) malloc(sizeof(struct connect_info));
	if (ci == NULL) {
	    fprintf (stderr, "Unable to malloc connect_info\n");
	    assert (0);
	}
        memset(ci, 0, sizeof(struct connect_info));
        assert(si);

        ci->fd = sockfd;
        if (si->domain == AF_UNIX) {
            struct sockaddr_un* sun = (struct sockaddr_un*) addr;
            if (addr->sa_family == AF_UNIX) {
                memcpy(ci->path, sun->sun_path, 108); // apparently 108 is the magic number
            } else {
                //fprintf (stderr, "unknown sa_family %d is not AF_UNIX len is %d vs %d\n", addr->sa_family, addrlen, sizeof(struct sockaddr_un));
                memcpy(ci->path, "UNK", 4);
            }
        } else if (si->domain == AF_INET) {
            if (addr->sa_family == AF_INET || addrlen == sizeof(struct sockaddr_in)) {
                struct sockaddr_in* sin = (struct sockaddr_in*) addr;
                ci->port = htons(sin->sin_port);
                memcpy(&ci->sin_addr, &sin->sin_addr, sizeof(struct in_addr));
                //fprintf (stderr, "connect AF_INET port %d addr %x\n", ci->port, ci->sin_addr.s_addr);
            } else {
		//fprintf (stderr, "unknown sa_family %d is not AF_INET len is %d vs %d\n", addr->sa_family, addrlen, sizeof(struct sockaddr_in));
                ci->port = 0;
                memcpy(&ci->sin_addr, "UNK", 4);
            }
        } else if (si->domain == AF_INET6) {
            if (addr->sa_family == AF_INET6) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*) addr;
                ci->port = htons(sin6->sin6_port);
                memcpy(&ci->sin_addr6, &sin6->sin6_addr, sizeof(struct in6_addr));
            } else {
                //fprintf (stderr, "unknown sa_family %d is not AF_INET6 len is %d vs %d\n", addr->sa_family, addrlen, sizeof(struct sockaddr_in6));
                ci->port = 0;
                memcpy(&ci->sin_addr6, "UNK", 4);
            }
        } else {
            fprintf(stderr, "unsupport socket family %d\n", si->domain);
            free(ci);
            return;
        }
        tdata->save_syscall_info = (void *) ci;
    }
}

static void sys_connect_stop(int rc)
{
    // successful connect
    if (!rc && current_thread->save_syscall_info) {
        struct connect_info* ci = (struct connect_info *) current_thread->save_syscall_info;
        struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ci->fd);
        char connect_info_name[256];
        if (!si) {
            fprintf(stderr, "could not find socket for connect %d\n", ci->fd);
            free(ci);
            current_thread->save_syscall_info = NULL;
            return;
        }
        //assert(si);
        if (filter_x) {
            if (si->domain == AF_UNIX) {
                char* c;
                c = ci->path;
                c += 1;
                if (strstr(ci->path, "tmp/.X11-unix/X") ||
                        strstr(c, "tmp/.X11-unix/X")) {
                    fprintf(stderr, "connect to X11, fd %d\n", ci->fd);
                    monitor_add_fd(open_x_fds, ci->fd, 0, 0);
                }
            } else if (si->domain == AF_INET) {
                struct in_addr ina;
                // X port is 6010, address is 127.0.0.1
                if (!inet_pton(AF_INET, "127.0.0.1", &ina)) { // create an address to check against
                    fprintf(stderr, "inet_pton failed?!\n");
                    assert(false);
                }
                fprintf(stderr, "connect to port %d\n", ci->port);
                if (ci->port == 6010 && ina.s_addr == ci->sin_addr.s_addr) {
                    monitor_add_fd(open_x_fds, ci->fd, 0, 0);
                    fprintf(stderr, "connect to X11 (over ssh forwarding)\n");
                }
            }
        }

        si->ci = ci;
        si->fileno = open_file_cnt;
        open_file_cnt++;
        create_connect_info_name(connect_info_name, si->domain, ci);
#ifdef OUTPUT_FILENAMES
        write_filename_mapping(filenames_f, si->fileno, connect_info_name);
#endif

        current_thread->save_syscall_info = NULL; // Socket_info owns this now
    }
}

static void sys_recv_start(thread_data* tdata, int fd, char* buf, int size) 
{
    // recv and read are similar so they can share the same info struct
    struct read_info* ri = (struct read_info*) &tdata->op.read_info_cache;
    ri->fd = fd;
    ri->buf = buf;
    tdata->save_syscall_info = (void *) ri;
    LOG_PRINT ("recv on fd %d\n", fd);
}

static void sys_recv_stop(int rc) 
{
    struct read_info* ri = (struct read_info *) &current_thread->op.read_info_cache;
    LOG_PRINT ("Pid %d syscall recv returns %d\n", PIN_GetPid(), rc);
    SYSCALL_DEBUG (stderr, "Pid %d syscall recv returns %d\n", PIN_GetPid(), rc);

    // If syscall cnt = 0, then write handled in previous epoch
    if (rc > 0) {
        struct taint_creation_info tci;
        char* channel_name = (char *) "--";
        int read_fileno = -1;
        if(ri->fd == fileno(stdin)) {
            read_fileno = 0;
            channel_name = (char *) "stdin";
        } else if (monitor_has_fd(open_socks, ri->fd)) {
            struct socket_info* si;
            si = (struct socket_info *) monitor_get_fd_data(open_socks, ri->fd);
            read_fileno = si->fileno;
            // FIXME
	    if (si->domain == AF_INET || si->domain == AF_INET6) {
		channel_name = (char *) "inetsocket";
	    } else {
		channel_name = (char *) "recvsocket";
	    }
	    //not sure why we'd need this... but I can't get the filter inets to work out for me
        }

	else if (monitor_has_fd(open_fds, ri->fd)) {
            struct open_info* oi;
            oi = (struct open_info *)monitor_get_fd_data(open_fds, ri->fd);
            read_fileno = oi->fileno;
            channel_name = oi->name;
        }

        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = read_fileno;
        tci.data = 0;
	tci.type = TOK_RECV;

        LOG_PRINT ("Create taints from buffer sized %d at location %#lx, clock %lu\n",
		   rc, (unsigned long) ri->buf, *ppthread_log_clock );
        create_taints_from_buffer(ri->buf, rc, &tci, tokens_fd, channel_name);

#ifdef LINKAGE_FDTRACK
        if (is_fd_tainted(ri->fd)) {
            taint_fd2mem((u_long) ri->buf, rc, ri->fd);
        }
#endif

    }
    memset(&current_thread->op.read_info_cache, 0, sizeof(struct read_info));
    current_thread->save_syscall_info = 0;
}

static void sys_recvmsg_start(struct thread_data* tdata, int fd, struct msghdr* msg, int flags) 
{
    struct recvmsg_info* rmi;
    rmi = (struct recvmsg_info *) malloc(sizeof(struct recvmsg_info));
    if (rmi == NULL) {
	fprintf (stderr, "Unable to malloc recvmsg_info\n");
	assert (0);
    }
    rmi->fd = fd;
    rmi->msg = msg;
    rmi->flags = flags;

    tdata->save_syscall_info = (void *) rmi;
}

static void sys_recvmsg_stop(int rc) 
{
    struct recvmsg_info* rmi = (struct recvmsg_info *) current_thread->save_syscall_info;

    // If syscall cnt = 0, then write handled in previous epoch
    if (rc > 0) {
        struct taint_creation_info tci;
        char* channel_name = (char *) "recvmsgsocket";
        u_int i;
        int read_fileno = -1;
        if (monitor_has_fd(open_socks, rmi->fd)) {
            struct socket_info* si;
            si = (struct socket_info *) monitor_get_fd_data(open_socks, rmi->fd);
            read_fileno = si->fileno;
        } else {
            read_fileno = -1;
        }

        //fprintf (stderr, "rcvmsg_stop from channel: %s\n", channel_name);
        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = read_fileno;
        tci.data = 0;
	tci.type = TOK_RECVMSG;

        for (i = 0; i < rmi->msg->msg_iovlen; i++) {
            struct iovec* vi = (rmi->msg->msg_iov + i);
            // TODO support filtering on certain sockets
            LOG_PRINT ("Create taints from buffer sized %d at location %#lx\n",
                        vi->iov_len, (unsigned long) vi->iov_base);
            create_taints_from_buffer(vi->iov_base, vi->iov_len, &tci, tokens_fd,
                                        channel_name);
            tci.offset += vi->iov_len;
        }
    }
    SYSCALL_DEBUG (stderr, "recvmsg_stop done\n");
    free(rmi);
}

static void sys_sendmsg_start(struct thread_data* tdata, int fd, struct msghdr* msg, int flags)
{
    struct sendmsg_info* smi;
    smi = (struct sendmsg_info *) malloc(sizeof(struct sendmsg_info));
    if (smi == NULL) {
	fprintf (stderr, "Unable to malloc sendmsg_info\n");
	assert (0);
    }
    smi->fd = fd;
    smi->msg = msg;
    smi->flags = flags;

    tdata->save_syscall_info = (void *) smi;
}

static void sys_sendmsg_stop(int rc)
{
    u_int i;
    struct sendmsg_info* smi = (struct sendmsg_info *) current_thread->save_syscall_info;
    int channel_fileno = -1;

    // If syscall cnt = 0, then write handled in previous epoch
    if (rc > 0) {
	if (*ppthread_log_clock >= filter_outputs_before) {
	    struct taint_creation_info tci;
	    SYSCALL_DEBUG (stderr, "sendmsg_stop: sucess sendmsg of size %d\n", rc);
	    if (monitor_has_fd(open_socks, smi->fd)) {
		struct socket_info* si;
		si = (struct socket_info *) monitor_get_fd_data(open_socks, smi->fd);
		channel_fileno = si->fileno;
	    } else {
		channel_fileno = -1;
	    }
	    
	    tci.type = 0;
	    tci.rg_id = current_thread->rg_id;
	    tci.record_pid = current_thread->record_pid;
	    tci.syscall_cnt = current_thread->syscall_cnt;
	    tci.offset = 0;
	    tci.fileno = channel_fileno;
	    
	    for (i = 0; i < smi->msg->msg_iovlen; i++) {
		struct iovec* vi = (smi->msg->msg_iov + i);
		if (produce_output) { 
		    output_buffer_result(vi->iov_base, vi->iov_len, &tci, outfd);
		}
		tci.offset += vi->iov_len;
	    }
	}
    }
    SYSCALL_DEBUG (stderr, "sys_sendmsg_stop done\n");
    free(smi);
}


static void sys_send_start(struct thread_data* tdata, int fd, char* msg, size_t len, int flags)
{
    struct write_info* si;
    si = (struct write_info *) malloc(sizeof(struct write_info));
    if (si == NULL) {
	fprintf (stderr, "Unable to malloc sendmsg_info\n");
	assert (0);
    }
    si->fd = fd;
    si->buf = msg;

    tdata->save_syscall_info = (void *) si;
}

static void sys_send_stop(int rc)
{
    struct write_info* si = (struct write_info *) current_thread->save_syscall_info;
    int channel_fileno = -1;

    SYSCALL_DEBUG (stderr, "Pid %d syscall send %d \n", PIN_GetPid(), rc);
    if (rc > 0) {
	if (*ppthread_log_clock >= filter_outputs_before) {
	    struct taint_creation_info tci;
	    SYSCALL_DEBUG (stderr, "send_stop: sucess write of size %d\n", rc);
	    
	    if (monitor_has_fd(open_fds, si->fd)) {
		struct open_info* oi;
		oi = (struct open_info *) monitor_get_fd_data(open_fds, si->fd);
		assert(oi);
		channel_fileno = oi->fileno;
	    } else if (si->fd == fileno(stdout)) {
		channel_fileno = FILENO_STDOUT;
	    } else if (si->fd == fileno(stderr)) {
		channel_fileno = FILENO_STDERR;
	    } else if (si->fd == fileno(stdin)) {
		channel_fileno = FILENO_STDIN;
	    } else {
		channel_fileno = -1;
	    }
	    tci.type = 0;
	    tci.rg_id = current_thread->rg_id;
	    tci.record_pid = current_thread->record_pid;
	    tci.syscall_cnt = current_thread->syscall_cnt;
	    if (!current_thread->syscall_in_progress) {
		tci.syscall_cnt--; // Weird restart issue
	    }
	    tci.offset = 0;
	    tci.fileno = channel_fileno;
	    
	    LOG_PRINT ("Output buffer result syscall %u, %#lx\n", tci.syscall_cnt, (u_long) si->buf);
	    if (produce_output) { 
		output_buffer_result (si->buf, rc, &tci, outfd);
	    }
	}
    }
    free(si);
}


static inline void sys_gettimeofday_start (struct thread_data* tdata, struct timeval* tv, struct timezone *tz) {
	SYSCALL_DEBUG(stderr, "sys_gettimeofday_start.\n");
	LOG_PRINT ("start to handle gettimeofday, tv %p, tz %p\n", tv, tz);
	struct gettimeofday_info* info = &tdata->op.gettimeofday_info_cache;
	info->tv = tv;
	info->tz = tz;
	tdata->save_syscall_info = (void*) info;
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
		printf ("[SLICE] #0000000 #call gettimeofday_recheck [SLICE_INFO] %lu\n", *ppthread_log_clock);
#endif
		recheck_gettimeofday (tdata->recheck_handle, tv, tz);
	}
}

static inline void sys_gettimeofday_stop (int rc) {
    struct gettimeofday_info* ri = (struct gettimeofday_info*) &current_thread->op.gettimeofday_info_cache;
    if (rc == 0) {
	taint_syscall_memory_out ("gettimeofday", (char *) ri->tv, sizeof(struct timeval));
	if (ri->tz != NULL) {
	    taint_syscall_memory_out ("gettimeofday", (char *) ri->tz, sizeof(struct timezone));
	}
    }
    memset (&current_thread->op.gettimeofday_info_cache, 0, sizeof (struct gettimeofday_info));
    current_thread->save_syscall_info = 0;
}

static inline void sys_time_start (struct thread_data* tdata, time_t* t) {
	SYSCALL_DEBUG(stderr, "sys_time_start.\n");
	tdata->save_syscall_info = (void*) t;
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
            printf ("[SLICE] #0000000 #call time_recheck [SLICE_INFO] %lu\n", *ppthread_log_clock);
#endif
            recheck_time (tdata->recheck_handle, t);
	}
}

static inline void sys_time_stop (int rc) {
    time_t* t = (time_t*) current_thread->save_syscall_info;
    if (rc != -1) {
	struct taint_creation_info tci;
	tci.rg_id = current_thread->rg_id;
	tci.record_pid = current_thread->record_pid;
	tci.syscall_cnt = current_thread->syscall_cnt;
	tci.offset = 0;
	tci.fileno = -1;
	tci.data = 0;
	tci.type = TOK_TIME;

	create_syscall_retval_taint_unfiltered (&tci, tokens_fd);
	if (t != NULL) {
	    taint_syscall_memory_out ("time", (char *) t, sizeof(time_t));
	}
    }
    current_thread->save_syscall_info = 0;
}

static inline void sys_clock_gettime_start (struct thread_data* tdata, struct timespec* tp) { 
	SYSCALL_DEBUG(stderr, "sys_clock_gettime_start %p.\n", tp);
	LOG_PRINT ("start to handle clock_gettime %p\n", tp);
	struct clock_gettime_info* info = &tdata->op.clock_gettime_info_cache;
	info->tp = tp;
	tdata->save_syscall_info = (void*) info;
}

static inline void sys_clock_gettime_stop (int rc) { 
	struct clock_gettime_info* ri = (struct clock_gettime_info*) &current_thread->op.clock_gettime_info_cache;
	if (rc == 0) { 
		struct taint_creation_info tci;
		char* channel_name = (char*) "clock_gettime";
		tci.type = TOK_CLOCK_GETTIME;
		tci.rg_id = current_thread->rg_id;
		tci.record_pid = current_thread->record_pid;
		tci.syscall_cnt = current_thread->syscall_cnt;
		tci.offset = 0;
		tci.fileno = -1;
		tci.data = 0;
		create_taints_from_buffer(ri->tp, sizeof(struct timespec), &tci, tokens_fd, channel_name);
	}
	memset (&current_thread->op.clock_gettime_info_cache, 0, sizeof(struct clock_gettime_info));
	current_thread->save_syscall_info = 0;
	LOG_PRINT ("Done with clock_gettime.\n");
}

static inline void sys_getpid_start (struct thread_data* tdata) {
    SYSCALL_DEBUG(stderr, "sys_getpid_start.\n");
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call getpid_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_getpid (tdata->recheck_handle);
    }
}

static inline void sys_getpid_stop (int rc) {
	struct taint_creation_info tci;
	tci.rg_id = current_thread->rg_id;
	tci.record_pid = current_thread->record_pid;
	tci.syscall_cnt = current_thread->syscall_cnt;
	tci.offset = 0;
	tci.fileno = -1;
	tci.data = 0;
	tci.type = TOK_GETPID;
	create_syscall_retval_taint_unfiltered (&tci, tokens_fd);
	LOG_PRINT ("Done with getpid\n");
}

static inline void sys_getpgrp_start (struct thread_data* tdata) {
	SYSCALL_DEBUG(stderr, "sys_getpgrp_start.\n");
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #mov eax, %d [SLICE_INFO]\n", SYS_getpgrp);
	printf ("[SLICE] #00000000 #int 0x80 [SLICE_INFO] sys_getpgrp clock %lu\n", *ppthread_log_clock);
#endif
}

static inline void sys_getpgrp_stop (int rc) {
	struct taint_creation_info tci;
	tci.rg_id = current_thread->rg_id;
	tci.record_pid = current_thread->record_pid;
	tci.syscall_cnt = current_thread->syscall_cnt;
	tci.offset = 0;
	tci.fileno = -1;
	tci.data = 0;
	tci.type = TOK_GETPID;
	create_syscall_retval_taint_unfiltered (&tci, tokens_fd);
	LOG_PRINT ("Done with getpgrp\n");
}

static inline void sys_getuid32_start (struct thread_data* tdata) {
    SYSCALL_DEBUG(stderr, "sys_getuid32_start.\n");
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call getuid32_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_getuid32 (tdata->recheck_handle);
    }
}

static inline void sys_geteuid32_start (struct thread_data* tdata) {
    SYSCALL_DEBUG(stderr, "sys_geteuid32_start.\n");
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call geteuid32_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_geteuid32 (tdata->recheck_handle);
    }
}

static inline void sys_getgid32_start (struct thread_data* tdata) {
    SYSCALL_DEBUG(stderr, "sys_getgid32_start.\n");
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call getgid32_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_getgid32 (tdata->recheck_handle);
    }
}

static inline void sys_getegid32_start (struct thread_data* tdata) {
    SYSCALL_DEBUG(stderr, "sys_getegid32_start.\n");
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call getegid32_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_getegid32 (tdata->recheck_handle);
    }
}

static inline void sys_setpgid_start (struct thread_data* tdata, pid_t pid, pid_t pgid) {
    if (tdata->recheck_handle) {
	int pid_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_EBX, 4, 0);
	int pgid_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_ECX, 4, 0);
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #push ecx [SLICE_INFO] pgid argument to setpgid\n");
	printf ("[SLICE] #00000000 #push ebx [SLICE_INFO] pid argument to setpgid\n");
	printf ("[SLICE] #00000000 #call setpgid_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
	printf ("[SLICE] #00000000 #pop ebx [SLICE_INFO]\n");
	printf ("[SLICE] #00000000 #pop ecx [SLICE_INFO]\n");
#endif
	recheck_setpgid (tdata->recheck_handle, pid, pgid, pid_tainted, pgid_tainted);
    }
}

static inline void sys_set_tid_address_start (struct thread_data* tdata) {
	SYSCALL_DEBUG(stderr, "sys_set_tid_address_start.\n");
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #mov eax, %d [SLICE_INFO]\n", SYS_set_tid_address);
	printf ("[SLICE] #00000000 #int 0x80 [SLICE_INFO] set_tid_address clock %lu\n", *ppthread_log_clock);
#endif
}

static inline void sys_set_tid_address_stop (int rc) {
	struct taint_creation_info tci;
	tci.rg_id = current_thread->rg_id;
	tci.record_pid = current_thread->record_pid;
	tci.syscall_cnt = current_thread->syscall_cnt;
	tci.offset = 0;
	tci.fileno = -1;
	tci.data = 0;
	tci.type = TOK_GETPID;
	create_syscall_retval_taint_unfiltered (&tci, tokens_fd);
	LOG_PRINT ("Done with set_tid_address\n");
}

static inline void sys_fstat64_start (struct thread_data* tdata, int fd, struct stat64* buf) {
	struct fstat64_info* fsi = (struct fstat64_info*) &current_thread->op.fstat64_info_cache;
	fsi->fd = fd;
	fsi->buf = buf;
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call fstat64_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_fstat64 (tdata->recheck_handle, fd, buf);
	}
}

static inline void sys_fstat64_stop (int rc) 
{
    struct fstat64_info* fsi = (struct fstat64_info*) &current_thread->op.fstat64_info_cache;
    clear_mem_taints ((u_long)fsi->buf, sizeof(struct stat64));
    if (rc == 0) {
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_ino, sizeof(fsi->buf->st_ino));
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_atime, sizeof(fsi->buf->st_atime));
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_ctime, sizeof(fsi->buf->st_ctime));
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_mtime, sizeof(fsi->buf->st_mtime));
    }
    LOG_PRINT ("Done with fstat64.\n");
}

static inline void sys_stat64_start (struct thread_data* tdata, char* path, struct stat64* buf) {
	struct stat64_info* si = (struct stat64_info*) &current_thread->op.stat64_info_cache;
	si->buf = buf;
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call stat64_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_stat64 (tdata->recheck_handle, path, buf);
	}
}

static inline void sys_stat64_stop (int rc) 
{
	struct stat64_info* si = (struct stat64_info*) &current_thread->op.stat64_info_cache;
	clear_mem_taints ((u_long)si->buf, sizeof(struct stat64));
	if (rc == 0) {
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_ino, sizeof(si->buf->st_ino));
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_atime, sizeof(si->buf->st_atime));
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_ctime, sizeof(si->buf->st_ctime));
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_mtime, sizeof(si->buf->st_mtime));
	}
	LOG_PRINT ("Done with stat64.\n");
}

static inline void sys_lstat64_start (struct thread_data* tdata, char* path, struct stat64* buf) {
	struct stat64_info* si = (struct stat64_info*) &current_thread->op.stat64_info_cache;
	si->buf = buf;
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call lstat64_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_lstat64 (tdata->recheck_handle, path, buf);
	}
}

static inline void sys_lstat64_stop (int rc) 
{
	struct stat64_info* si = (struct stat64_info*) &current_thread->op.stat64_info_cache;
	clear_mem_taints ((u_long)si->buf, sizeof(struct stat64));
	if (rc == 0) {
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_ino, sizeof(si->buf->st_ino));
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_atime, sizeof(si->buf->st_atime));
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_ctime, sizeof(si->buf->st_ctime));
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_mtime, sizeof(si->buf->st_mtime));
	}
}

static inline void sys_ugetrlimit_start (struct thread_data* tdata, int resource, struct rlimit* prlim) 
{
	struct ugetrlimit_info* ugri = (struct ugetrlimit_info*) &current_thread->op.ugetrlimit_info_cache;
	ugri->resource = resource;
	ugri->prlim = prlim;
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call ugetrlimit_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_ugetrlimit (tdata->recheck_handle, resource, prlim);
	}
}

static inline void sys_ugetrlimit_stop (int rc) 
{
	struct ugetrlimit_info* ugri = (struct ugetrlimit_info*) &current_thread->op.ugetrlimit_info_cache;
	clear_mem_taints ((u_long)ugri->prlim, sizeof(struct rlimit));
	LOG_PRINT ("Done with ugetrlimit.\n");
}

static inline void sys_prlimit64_start (struct thread_data* tdata, pid_t pid, int resource, struct rlimit64* new_limit, struct rlimit64* old_limit) 
{
    struct prlimit64_info* pri = (struct prlimit64_info*) &current_thread->op.prlimit64_info_cache;
    pri->old_limit = old_limit;
    if (tdata->recheck_handle) {
#ifdef FW_SLICE
	printf ("[SLICE] #00000000 #call prlimit64_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	recheck_prlimit64 (tdata->recheck_handle, pid, resource, new_limit, old_limit);
    }
}

static inline void sys_prlimit64_stop (int rc) 
{
    struct prlimit64_info* pri = (struct prlimit64_info*) &current_thread->op.prlimit64_info_cache;
    if (pri->old_limit) clear_mem_taints ((u_long)pri->old_limit, sizeof(struct rlimit64));
    LOG_PRINT ("Done with prlimit64.\n");
}

static inline void sys_uname_start (struct thread_data* tdata, struct utsname* buf) 
{
	struct uname_info* uni = (struct uname_info*) &current_thread->op.uname_info_cache;
	uni->buf = buf;
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call uname_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_uname (tdata->recheck_handle, buf);
	}
}

static inline void sys_uname_stop (int rc) 
{
    struct uname_info* uni = (struct uname_info*) &current_thread->op.uname_info_cache;
    clear_mem_taints ((u_long)uni->buf, sizeof(struct utsname));
    if (rc == 0) {
	taint_syscall_memory_out ("uname", (char *)&uni->buf->version, sizeof(uni->buf->version));
    }
    LOG_PRINT ("Done with uname.\n");
}

static inline void sys_statfs64_start (struct thread_data* tdata, const char* path, size_t sz, struct statfs64* buf) 
{
	struct statfs64_info* sfi = (struct statfs64_info*) &current_thread->op.statfs64_info_cache;
	sfi->buf = buf;
	if (tdata->recheck_handle) {
#ifdef FW_SLICE
	    printf ("[SLICE] #00000000 #call statfs64_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    recheck_statfs64 (tdata->recheck_handle, path, sz, buf);
	}
}

static inline void sys_statfs64_stop (int rc) 
{
    struct statfs64_info* sfi = (struct statfs64_info*) &current_thread->op.statfs64_info_cache;
    clear_mem_taints ((u_long)sfi->buf, sizeof(struct statfs64));
    if (rc == 0) {
	taint_syscall_memory_out ("statfs64", (char *)&sfi->buf->f_bfree, sizeof(sfi->buf->f_bfree));	
	taint_syscall_memory_out ("statfs64", (char *)&sfi->buf->f_bavail, sizeof(sfi->buf->f_bavail));
	taint_syscall_memory_out ("statfs64", (char *)&sfi->buf->f_ffree, sizeof(sfi->buf->f_ffree));
    }
    LOG_PRINT ("Done with statfs64.\n");
}

static inline void sys_getrusage_start (struct thread_data* tdata, struct rusage* usage) {
	SYSCALL_DEBUG (stderr, "sys_getrusage_start.\n");
	LOG_PRINT ("start to handle getrusage, usage addr %p\n", usage);
	struct getrusage_info* info = &tdata->op.getrusage_info_cache;
	info->usage = usage;
	tdata->save_syscall_info = (void*) info;
}

static inline void sys_getrusage_stop (int rc) {
	struct getrusage_info* ri = (struct getrusage_info*) &current_thread->op.getrusage_info_cache;
	if (rc == 0) {
		struct taint_creation_info tci;
		char* channel_name = (char*) "getrusage";
		tci.rg_id = current_thread->rg_id;
		tci.record_pid = current_thread->record_pid;
		tci.syscall_cnt = current_thread->syscall_cnt;
		tci.offset = 0;
		tci.fileno = -1;
		tci.data = 0;
		tci.type = TOK_GETRUSAGE;
		create_taints_from_buffer (ri->usage, sizeof(struct rusage), &tci, tokens_fd, channel_name);	
	}
	memset (&current_thread->op.getrusage_info_cache, 0, sizeof(struct rusage));
	current_thread->save_syscall_info = 0;
	LOG_PRINT ("Done with getrusage\n");
}

void syscall_start(struct thread_data* tdata, int sysnum, ADDRINT syscallarg0, ADDRINT syscallarg1,
		   ADDRINT syscallarg2, ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{ 
    switch (sysnum) {
        case SYS_open:
            sys_open_start(tdata, (char *) syscallarg0, (int) syscallarg1, (int) syscallarg2);
            break;
        case SYS_openat:
            sys_openat_start(tdata, (int) syscallarg0, (char*) syscallarg1, (int) syscallarg2, (int) syscallarg3);
            break;
        case SYS_close:
            sys_close_start(tdata, (int) syscallarg0); 
            break; 
       case SYS_read:
	    sys_read_start(tdata, (int) syscallarg0, (char *) syscallarg1, (int) syscallarg2);
            break;
        case SYS_write:
        case SYS_pwrite64:
	    sys_write_start(tdata, (int) syscallarg0, (char *) syscallarg1, (size_t) syscallarg2);
            break;
        case SYS_writev:
            sys_writev_start(tdata, (int) syscallarg0, (struct iovec *) syscallarg1, (int) syscallarg2);
            break;
        case SYS_pread64:
            sys_pread_start(tdata, (int) syscallarg0, (char *) syscallarg1, (int) syscallarg2);
            break;
        case SYS__llseek:
            sys_llseek_start(tdata, (u_int) syscallarg0, (u_long) syscallarg1, (u_long) syscallarg2,
			     (loff_t *) syscallarg3, (u_int) syscallarg4); 
            break;
        case SYS_readlink:
	    sys_readlink_start(tdata, (char *) syscallarg0, (char *) syscallarg1, (size_t) syscallarg2);
            break;
        case SYS_ioctl:
	    sys_ioctl_start(tdata, (u_int) syscallarg0, (u_int) syscallarg1, (char *) syscallarg2);
            break;
#ifdef LINKAGE_FDTRACK
        case SYS_select:
        case 142:
            sys_select_start(tdata, (int) syscallarg0, (fd_set *) syscallarg1, (fd_set *) syscallarg2,
			     (fd_set *) syscallarg3, (struct timeval *) syscallarg4);
            break;
#endif
        case SYS_socketcall:
        {
            int call = (int) syscallarg0;
            unsigned long *args = (unsigned long *)syscallarg1;
            tdata->socketcall = call;
	    SYSCALL_DEBUG(stderr, "new socketcall is %d\n",call);
            switch (call) {
                case SYS_SOCKET:
                    SYSCALL_DEBUG(stderr, "socket_start\n");
                    sys_socket_start(tdata, (int)args[0], (int)args[1], (int)args[2]);
                    break;
                case SYS_CONNECT:
                    SYSCALL_DEBUG(stderr, "connect_start\n");
                    sys_connect_start(tdata, (int)args[0], (struct sockaddr *)args[1], (socklen_t)args[2]);
                    break;
                case SYS_RECV:
                case SYS_RECVFROM:
                    SYSCALL_DEBUG(stderr, "recv_start\n");
                    sys_recv_start(tdata, (int)args[0], (char *)args[1], (int)args[2]);
                    break;
                case SYS_RECVMSG:
                    SYSCALL_DEBUG(stderr, "recvmsg_start\n");
                    sys_recvmsg_start(tdata, (int)args[0], (struct msghdr *)args[1], (int)args[2]);
                    break;
                case SYS_SENDMSG:
                    SYSCALL_DEBUG(stderr, "sendmsg_start\n");
                    sys_sendmsg_start(tdata, (int)args[0], (struct msghdr *)args[1], (int)args[2]);
                    break;
	        case SYS_SEND:
		    SYSCALL_DEBUG(stderr, "send_start\n");
                    sys_send_start(tdata, (int)args[0], (char *)args[1], (int)args[2], (int)args[3]);
		    break;
                default:
                    break;
            }
            break;
        }
        case SYS_fcntl64:
	    sys_fcntl64_start (tdata, (int)syscallarg0, (int)syscallarg1,(void *)syscallarg2);
	    break;
        case SYS_mmap:
        case SYS_mmap2:
            sys_mmap_start(tdata, (u_long)syscallarg0, (int)syscallarg1, (int)syscallarg2, (int)syscallarg4);
            break;
	case SYS_gettimeofday:
	    sys_gettimeofday_start(tdata, (struct timeval*) syscallarg0, (struct timezone*) syscallarg1);
	    break;
        case SYS_time:
            sys_time_start (tdata, (time_t*) syscallarg0);
            break;
	case SYS_getpid:
	    sys_getpid_start (tdata);
	    break;
	case SYS_getpgrp:
	    sys_getpgrp_start (tdata);
	    break;
	case SYS_getuid32:
	    sys_getuid32_start (tdata);
	    break;
	case SYS_geteuid32:
	    sys_geteuid32_start (tdata);
	    break;
	case SYS_getgid32:
	    sys_getgid32_start (tdata);
	    break;
	case SYS_getegid32:
	    sys_getegid32_start (tdata);
	    break;
	case SYS_setpgid:
	    sys_setpgid_start (tdata, (int) syscallarg0, (int) syscallarg1);
	    break;
        case SYS_ugetrlimit:
	    sys_ugetrlimit_start (tdata, (int) syscallarg0, (struct rlimit *) syscallarg1);
	    break;
        case SYS_prlimit64:
	    sys_prlimit64_start (tdata, (pid_t) syscallarg0, (int) syscallarg1, (struct rlimit64 *) syscallarg2, (struct rlimit64 *) syscallarg3);
	    break;
        case SYS_uname:
	    sys_uname_start (tdata, (struct utsname *) syscallarg0);
	    break;
        case SYS_statfs64:
	    sys_statfs64_start (tdata, (const char *) syscallarg0, (size_t) syscallarg1, (struct statfs64 *) syscallarg2);
	    break;
      	case SYS_set_tid_address:
	    sys_set_tid_address_start (tdata);
	    break;
	case SYS_clock_gettime:
	    sys_clock_gettime_start (tdata, (struct timespec*) syscallarg1);
	    break;
	case SYS_access:
	    if (tdata->recheck_handle) {
		recheck_access (tdata->recheck_handle, (char *) syscallarg0, (int) syscallarg1);
#ifdef FW_SLICE
		printf ("[SLICE] #00000000 #call access_recheck [SLICE_INFO] clock %lu\n", *ppthread_log_clock);
#endif
	    }
	    break;
	case SYS_stat64:
	    sys_stat64_start (tdata, (char *)syscallarg0, (struct stat64 *)syscallarg1);
	    break;
	case SYS_fstat64:
	    sys_fstat64_start (tdata, (int)syscallarg0, (struct stat64 *)syscallarg1);
	    break;
        case SYS_lstat64:
            sys_lstat64_start (tdata, (char*) syscallarg0, (struct stat64*) syscallarg1);
            break;
    }
}

void syscall_end(int sysnum, ADDRINT ret_value)
{
    int rc = (int) ret_value;
    switch(sysnum) {
        case SYS_clone:
            SYSCALL_DEBUG(stderr, "%d clone done\n", PIN_GetPid());
            break;
        case SYS_open:
            sys_open_stop(rc);
            break;
        case SYS_openat:
            sys_openat_stop(rc);
            break;
        case SYS_close:
            sys_close_stop(rc);
            break;
        case SYS_read:
            sys_read_stop(rc);
            break;
        case SYS_write:
        case SYS_pwrite64:
          //  sys_write_stop(rc);
            break;
        case SYS_writev:
            sys_writev_stop(rc);
            break;
        case SYS_pread64:
            sys_pread_stop(rc);
            break;
        case SYS_brk:
	  //  sys_brk_stop(rc);
      break;
#ifdef LINKAGE_FDTRACK
        case SYS_select:
        case 142:
            sys_select_stop(rc);
            break;
#endif
        case SYS_mmap:
        case SYS_mmap2:
            sys_mmap_stop(rc);
            break;
#if 0
        case SYS_munmap:
            sys_munmap_stop(rc);
            break;
#endif
	case SYS_gettimeofday:
	    sys_gettimeofday_stop(rc);
	    break;
        case SYS_time:
            sys_time_stop (rc);
            break;
        case SYS_ioctl:
	    sys_ioctl_stop(rc);
	    break;
	case SYS_getpid:
	    sys_getpid_stop(rc);
	    break;
	case SYS_getpgrp:
	    sys_getpgrp_stop(rc);
	    break;
	case SYS_set_tid_address:
	    sys_set_tid_address_stop(rc);
	    break;
	case SYS_stat64:
	    sys_stat64_stop(rc);
	    break;
	case SYS_fstat64:
	    sys_fstat64_stop(rc);
	    break;
        case SYS_lstat64:
            sys_lstat64_stop(rc);
            break;
	case SYS_ugetrlimit:
	    sys_ugetrlimit_stop(rc);
	    break;
	case SYS_prlimit64:
	    sys_prlimit64_stop(rc);
	    break;
	case SYS_uname:
	    sys_uname_stop(rc);
	    break;
	case SYS_statfs64:
	    sys_statfs64_stop(rc);
	    break;
	case SYS_clock_gettime:
	    sys_clock_gettime_stop(rc);
	    break;
        case SYS_socketcall:
        {
	    
            switch (current_thread->socketcall) {
                case SYS_SOCKET:
                    sys_socket_stop(rc);
                    break;
                case SYS_CONNECT:
                    sys_connect_stop(rc);
                    break;
                case SYS_RECV:
                case SYS_RECVFROM:
                    sys_recv_stop(rc);
                    break;
                case SYS_RECVMSG:
                    sys_recvmsg_stop(rc);
		    break;
                case SYS_SENDMSG:
                    sys_sendmsg_stop(rc);
                    break;
    	        case SYS_SEND:
		    sys_send_stop(rc);
		    break;
                default:
                    break;
            }
            current_thread->socketcall = 0;
            break;
        }
    }
    //Note: the checkpoint is always taken after a syscall and ppthread_log_clock should be the next expected clock
    if (*ppthread_log_clock >= checkpoint_clock) { 
	struct fd_struct* fds;
	//TODO: socks, x server ...
	printf ("opened files: \n");
	list_for_each_entry (fds, &open_fds->fds, list) {
		printf ("opened file %s\n", ((struct open_info*)fds->data)->name);
	}
	//let's scan over all memory address included in the slice
	printf ("check mem taints in forward slice.\n");
        if (fw_slice_check_final_mem_taint (current_thread->shadow_reg_table) == 0) { 
		printf ("all mem address in the slice are also tainted in the final checkpoint\n");
	}
	
	//stop tracing after this 
	int calling_dd = dift_done ();
	while (!calling_dd || is_pin_attaching(dev_fd)) {
		usleep (1000);
	}
	fprintf(stderr, "%d: calling try_to_exit\n", PIN_GetTid());
	try_to_exit(dev_fd, PIN_GetPid());
	PIN_ExitApplication(0); 
    }
}

// called before every application system call
void instrument_syscall(ADDRINT syscall_num, 
			ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2,
			ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{   
    int sysnum = (int) syscall_num;

    // Because of Pin restart issues, this function alone has to use PIN thread-specific data
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    tdata->sysnum = sysnum;
    tdata->syscall_in_progress = true;

#ifdef RECORD_TRACE_INFO
    if (record_trace_info &&
	!(sysnum == 17 || sysnum == 31 || sysnum == 32 ||
	  sysnum == 35 || sysnum == 44 || sysnum == 53 ||
          sysnum == 56 || sysnum == 58 || sysnum == 98 ||
          sysnum == 119 || sysnum == 123 || sysnum == 127 ||
	  sysnum == 186 || sysnum == 243 || sysnum == 244)) {

	if (current_thread->ignore_flag) {
	    if (!(*(int *)(current_thread->ignore_flag))) {
		flush_trace_hash(sysnum);
	    }
        } else {
	    flush_trace_hash(sysnum);
        }
    }
#endif


#ifdef TAINT_DEBUG
      fprintf (debug_f, "Thread %d sees sysnum %d in progress\n", tdata->record_pid, sysnum);
      if (current_thread != tdata) fprintf (debug_f, "current thread %d tdata %d\n", current_thread->record_pid, tdata->record_pid);
#endif

    if (sysnum == 31) {
	tdata->ignore_flag = (u_long) syscallarg1;
    }
    if (sysnum == 56) {
	tdata->status_addr = (u_long) syscallarg0;
	printf ("[SLICE] #00000000 #mov dword ptr [0x%lx], 3 [SLICE_INFO] reset the user-level record/replay flag", tdata->status_addr);
    }
    if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || 
	sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	check_clock_before_syscall (dev_fd, (int) syscall_num);
    }
    if (sysnum == 252) dift_done();


#ifdef RETAINT
    if (retaint_next_clock && *ppthread_log_clock >= retaint_next_clock) {
	fprintf(stderr,"resetting taints\n");
	reset_taints();
	char* p;
	for (p = retaint_str; *p != '\0' && *p != ','; p++);
	*p = '\0';
	retaint_next_clock = strtoul(retaint_str, NULL, 10);
	if (retaint_next_clock) fprintf (stderr, "Next epoch to retaint: %lu\n", retaint_next_clock);
	retaint_str = p+1;
	fprintf(stderr, "merrily we go along\n");
    }
#endif

    if (segment_length && *ppthread_log_clock >= segment_length) {
	// Done with this replay - do exit stuff now because we may not get clean unwind
#ifdef TAINT_DEBUG
	fprintf (debug_f, "Pin terminating at Pid %d, entry to syscall %ld, term. clock %ld cur. clock %ld\n", PIN_GetTid(), global_syscall_cnt, segment_length, *ppthread_log_clock);
#endif

	/*
	 * there's a race condition here if we are still attaching to multiple threads. A thread that skips 
	 * dift_done might fly through the rest of this and exit before dift_done has been called. This
	 * *is* what is happening in a partitioning for firefox (weird). 
	 */
	//we can't exit if we haven't aren't the one calling dift_done or if some threads are still attaching

	int calling_dd = dift_done ();
	while (!calling_dd || is_pin_attaching(dev_fd)) { 
	    usleep(1000); 
	}

	fprintf(stderr, "%d: calling try_to_exit\n", PIN_GetTid());
	try_to_exit(dev_fd, PIN_GetPid());
	PIN_ExitApplication(0); 

    }
	
    syscall_start(tdata, sysnum, syscallarg0, syscallarg1, syscallarg2, 
		  syscallarg3, syscallarg4, syscallarg5);
    
    tdata->app_syscall = syscall_num;
}

#ifdef RECORD_TRACE_INFO

#define MAX_TRACE_INST_SIZE 0x1000000
#define MAX_TRACE_SIZE 0x40000000
#define TRACE_ENTRIES (1024*1024 * 2)

#define TRACE_BUF_SIZE (TRACE_ENTRIES*sizeof(u_long))
static u_long* trace_buf;
static u_long* trace_inst_buf;
int trace_buf_fd = -1;
int trace_inst_fd = -1;
u_long trace_cnt = 0;
u_long trace_inst_cnt = 0;


//make this bigger, see what happens!
#define TRACE_HASH_ENTRIES 2048
u_long trace_hash[TRACE_HASH_ENTRIES];

static void init_trace_buf (void)
{
    char trace_buf_file[256];
    snprintf(trace_buf_file, 256, "/trace_exec_%s", group_directory);
    for (u_int i = 1; i < strlen(trace_buf_file); i++) {
	if (trace_buf_file[i] == '/') trace_buf_file[i] = '.';
    }

    trace_buf_fd = shm_open(trace_buf_file, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (trace_buf_fd < 0) {
	fprintf(stderr, "could not open taint shmem %s, errno %d\n", trace_buf_file, errno);
	assert(0);
    }

    int rc = ftruncate64 (trace_buf_fd, MAX_TRACE_SIZE);
    if (rc < 0) {
	fprintf(stderr, "could not truncate shmem %s, errno %d\n", trace_buf_file, errno);
	assert(0);
    }

    trace_buf = (u_long *) mmap (0, TRACE_BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, trace_buf_fd, 0);
    if (trace_buf == MAP_FAILED) {
	fprintf (stderr, "could not map trace buffer, errno=%d\n", errno);
	assert (0);
    }

    flush_trace_hash(0);

    snprintf(trace_buf_file, 256, "/trace_inst_%s", group_directory);
    for (u_int i = 1; i < strlen(trace_buf_file); i++) {
	if (trace_buf_file[i] == '/') trace_buf_file[i] = '.';
    }

    trace_inst_fd = shm_open(trace_buf_file, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (trace_inst_fd < 0) {
	fprintf(stderr, "could not open taint shmem %s, errno %d\n", trace_buf_file, errno);
	assert(0);
    }

    rc = ftruncate64 (trace_inst_fd, MAX_TRACE_SIZE);
    if (rc < 0) {
	fprintf(stderr, "could not truncate shmem %s, errno %d\n", trace_buf_file, errno);
	assert(0);
    }

    trace_inst_buf = (u_long *) mmap (0, TRACE_BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, trace_inst_fd, 0);
    if (trace_inst_buf == MAP_FAILED) {
	fprintf (stderr, "could not map trace buffer, errno=%d\n", errno);
	assert (0);
    }
}

static void term_trace_buf()
{
    trace_total_count += trace_cnt*sizeof(u_long);
    long rc = ftruncate64 (trace_buf_fd, trace_total_count); 
    if (rc < 0) {
	fprintf (stderr, "Cannot ftruncate trace buffer, errno=%d\n", errno);
    }
    close (trace_buf_fd);

    trace_inst_total_count += trace_inst_cnt*sizeof(u_long);
    rc = ftruncate64 (trace_inst_fd, trace_inst_total_count); 
    if (rc < 0) {
	fprintf (stderr, "Cannot ftruncate trace instruction buffer, errno=%d\n", errno);
    }
    close (trace_inst_fd);
}

static void flush_trace_buf (void)
{
    trace_total_count += trace_cnt*sizeof(u_long);

    // Check for overflow
    if (trace_total_count >= MAX_TRACE_SIZE) {
	fprintf (stderr, "Cannot allocate any more trace buffer than %ld bytes\n", trace_total_count);
	assert (0);
    }

    // Unmap the current region
    if (munmap (trace_buf, TRACE_BUF_SIZE) < 0) {
	fprintf (stderr, "could not munmap trace buffer, errno=%d\n", errno);
	assert (0);
    }

    // Map in the next region
    trace_buf = (u_long *) mmap (0, TRACE_BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, trace_buf_fd, trace_total_count);
    if (trace_buf == MAP_FAILED) {
	fprintf (stderr, "could not map trace buffer, errno=%d\n", errno);
	assert (0);
    }
    trace_cnt = 0;
}

static void flush_trace_inst_buf (void)
{
    trace_inst_total_count += trace_inst_cnt*sizeof(u_long);

    // Check for overflow
    if (trace_inst_total_count >= MAX_TRACE_SIZE) {
	fprintf (stderr, "Cannot allocate any more trace instruction buffer than %ld bytes\n", trace_inst_total_count);
	assert (0);
    }

    // Unmap the current region
    if (munmap (trace_inst_buf, TRACE_BUF_SIZE) < 0) {
	fprintf (stderr, "could not munmap trace instruction buffer, errno=%d\n", errno);
	assert (0);
    }

    // Map in the next region
    trace_inst_buf = (u_long *) mmap (0, TRACE_BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, trace_inst_fd, trace_inst_total_count);
    if (trace_inst_buf == MAP_FAILED) {
	fprintf (stderr, "could not map trace instruction buffer, errno=%d\n", errno);
	assert (0);
    }
    trace_inst_cnt = 0;
}

static inline void flush_trace_hash (int sysnum)
{
#ifdef TAINT_STATS
    hash_flushes++;
#endif
    memset (trace_hash, 0, sizeof(trace_hash)); //maybe smaller would actually help? 
    trace_buf[trace_cnt++] = 0; // Denote new system call by writing 0 and syscall # to the log
    if (trace_cnt == TRACE_ENTRIES) flush_trace_buf();
    trace_buf[trace_cnt++] = get_record_pid();
    if (trace_cnt == TRACE_ENTRIES) flush_trace_buf();
    trace_buf[trace_cnt++] = *ppthread_log_clock;
    if (trace_cnt == TRACE_ENTRIES) flush_trace_buf();
    trace_buf[trace_cnt++] = sysnum;
    if (trace_cnt == TRACE_ENTRIES) flush_trace_buf();
    trace_buf[trace_cnt++] = get_num_merges();
    if (trace_cnt == TRACE_ENTRIES) flush_trace_buf();



}
#endif

static void syscall_after_redo (ADDRINT ip)
{
#ifdef RECORD_TRACE_INFO
    if (record_trace_info) {
	u_int index = ip ^ (ip >> 11); //fold ourself!
	if (trace_hash[index%TRACE_HASH_ENTRIES] != ip) {
	    trace_hash[index%TRACE_HASH_ENTRIES] = ip;
	    trace_buf[trace_cnt++] = ip;
	    if (trace_cnt == TRACE_ENTRIES) flush_trace_buf();
	}
    }
#endif

    if (redo_syscall) {
	u_long rc, len, retval;
	int syscall_to_redo = check_for_redo(dev_fd);
	if (syscall_to_redo == 192) {
	    redo_syscall--;
	    //fprintf (stderr, "Instruction %x redo mmap please %d\n", ip, redo_syscall);
	    retval = redo_mmap (dev_fd, &rc, &len);
	    if (retval) fprintf (stderr, "redo_mmap failed, rc=%ld\n", retval);
#if 0
	    fprintf (stderr, "syscall_after, eax is %x\n", PIN_GetContextReg(ctxt, LEVEL_BASE::REG_EAX));
	    fprintf (stderr, "syscall_after, ebx is %x\n", PIN_GetContextReg(ctxt, LEVEL_BASE::REG_EBX));
	    fprintf (stderr, "syscall_after, ecx is %x\n", PIN_GetContextReg(ctxt, LEVEL_BASE::REG_ECX));
#endif
	    //fprintf (stderr, "Clearing taints %lx,%lx\n", rc, len);
	    clear_mem_taints (rc, len);
	    current_thread->app_syscall = 0;  
	}
	else if(syscall_to_redo == 91) { 
	    redo_syscall--;
	    //fprintf (stderr, "Instruction %x redo mmap please %d\n", ip, redo_syscall);
	    retval = redo_munmap (dev_fd);
	    fprintf(stderr, "running the redo_munmap!\n");
	    if (retval) fprintf (stderr, "redo_mmap failed, rc=%ld\n", retval);
#if 0
	    fprintf (stderr, "syscall_after, eax is %x\n", PIN_GetContextReg(ctxt, LEVEL_BASE::REG_EAX));
	    fprintf (stderr, "syscall_after, ebx is %x\n", PIN_GetContextReg(ctxt, LEVEL_BASE::REG_EBX));
	    fprintf (stderr, "syscall_after, ecx is %x\n", PIN_GetContextReg(ctxt, LEVEL_BASE::REG_ECX));
#endif
	    //fprintf (stderr, "Clearing taints %lx,%lx\n", rc, len);
	    current_thread->app_syscall = 0;
	}      
    } else if (current_thread->app_syscall == 999) {
	check_clock_after_syscall (dev_fd);
	current_thread->app_syscall = 0;  
    }
}

#if 0
void syscall_after (ADDRINT ip)
{

//    fprintf(stderr, "%p\n",current_thread);
    if (current_thread->app_syscall == 999) {
	check_clock_after_syscall (dev_fd);
	current_thread->app_syscall = 0;  
    }
}
#endif

void instrument_syscall_ret(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    if (current_thread->app_syscall != 999) current_thread->app_syscall = 0;

    ADDRINT ret_value = PIN_GetSyscallReturn(ctxt, std);
    if (current_thread->sysnum == SYS_gettid) {
	// Pin "helpfully" changes the return value to the replay tid - change it back here
	//printf ("eax is %d changing to %d\n", PIN_GetContextReg (ctxt, LEVEL_BASE::REG_EAX), current_thread->record_pid);
	PIN_SetContextReg (ctxt, LEVEL_BASE::REG_EAX, current_thread->record_pid);
    }

    if (segment_length && *ppthread_log_clock > segment_length) {
#ifdef TAINT_DEBUG
	fprintf (debug_f, "Skip Pid %d, exit from syscall %ld due to termination, term. clock %ld cur. clock %ld\n", PIN_GetPid(), global_syscall_cnt, segment_length, *ppthread_log_clock);
#endif
    } else {
	syscall_end(current_thread->sysnum, ret_value);
    }

    if (!current_thread->syscall_in_progress) {
	/* Pin restart oddity: initial write will nondeterministically return twice (once with rc=0).
	   Just don't increment the global syscall cnt when this happens. */
	if (global_syscall_cnt == 0) {
	    if (current_thread->sysnum != SYS_write) {
#ifdef TAINT_DEBUG
		fprintf (debug_f, "First syscall %d not in progress and not write\n", current_thread->sysnum);
#endif
	    }
	} else {
#ifdef TAINT_DEBUG
	  fprintf (debug_f, "Syscall not in progress for global_syscall_cnt %ld sysnum %d thread %d\n", global_syscall_cnt, current_thread->sysnum, current_thread->record_pid);
	  struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
	  fprintf (debug_f, "tdata is %p current_thread is %p\n", tdata, current_thread);
#endif
	}
    } else {
	// reset the syscall number after returning from system call
	increment_syscall_cnt (current_thread->sysnum);
	current_thread->syscall_in_progress = false;
    }

    // The first syscall returns twice 
    if (global_syscall_cnt > 1) { 
	current_thread->sysnum = 0;
    }
}

void track_inst(INS ins, void* data) 
{
    if(INS_IsSyscall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_syscall),
                IARG_SYSCALL_NUMBER, 
                IARG_SYSARG_VALUE, 0, 
                IARG_SYSARG_VALUE, 1,
                IARG_SYSARG_VALUE, 2,
                IARG_SYSARG_VALUE, 3,
                IARG_SYSARG_VALUE, 4,
                IARG_SYSARG_VALUE, 5,
                IARG_END);
    }
}

/* Interpose on top this X function and check the taints for certain coordinates */
void trace_x_xputimage_start(ADDRINT dest_x, ADDRINT dest_y, ADDRINT w_ref, ADDRINT h_ref)
{
    PRINTX (stderr, "[TRACEX] xputimage (%d, %d)\n", (int) dest_x, (int) dest_y);
    // output x, y coords with taint
    output_xcoords(xoutput_fd, current_thread->syscall_cnt,
            (int) dest_x, (int) dest_y, w_ref);
    output_xcoords(xoutput_fd, current_thread->syscall_cnt,
            (int) dest_x, (int) dest_y, h_ref);
}

void trace_x_cairo_show_glyphs_start(ADDRINT cairo_context, ADDRINT array_glyphs, ADDRINT num_glyphs)
{
    int numglyphs = (int) num_glyphs;
    PRINTX (stderr, "[TRACEX] cairo_show_glyphs, num glyphs %d\n", (int) num_glyphs);
    // size of a glyph is 20
    for (int i = 0; i < numglyphs; i++) {
        for (unsigned j = 0; j < sizeof(cairo_glyph_t); j++) {
            u_long mem_loc = array_glyphs + (i * sizeof(cairo_glyph_t)) + j;
            output_xcoords(xoutput_fd, current_thread->syscall_cnt, -1, -1, mem_loc);
        }
    }
}

void trace_x_cairo_scaled_font_show_glyphs(ADDRINT array_glyphs, ADDRINT num_glyphs)
{
    int numglyphs = (int) num_glyphs;
    PRINTX (stderr, "[TRACEX] cairo_scaled_font_show_glyphs, num glyphs %d\n", (int) num_glyphs);
    // size of a glyph is 20
    for (int i = 0; i < numglyphs; i++) {
        for (int j = 0; j < 20; j++) {
            u_long mem_loc = array_glyphs + (i * 20) + j;
            output_xcoords(xoutput_fd, current_thread->syscall_cnt, -1, -1, mem_loc);
        }
    }
}

void trace_x_xrendercompositetext(ADDRINT dst_x, ADDRINT dst_y, ADDRINT ptr, ADDRINT len)
{
    PRINTX (stderr, "[TRACEX] xrendercompositetext (%d,%d)\n", (int) dst_x, (int) dst_y);
    for (int i = 0; i < (int)len; i++) {
        for (int j = 0; j < 16; j++) { 
            // _XGlyphElt8 is a minimum of 17 bytes, not sure about padding etc, 
            // but we'll say 16 for now, since we're just fishing for taints
            u_long mem_loc = ptr + (i * 16) + j;
            output_xcoords(xoutput_fd, current_thread->syscall_cnt,
                            (int) dst_x, (int) dst_y, mem_loc);
        }
    }
}

void string_inspect(ADDRINT ptr)
{
    fprintf(stderr,  "[TRACEX] string_inspect at %#x\n", ptr);
    for (int i = 0; i < (int)24; i++) {
            u_long mem_loc = ptr + i;
            output_xcoords(xoutput_fd, current_thread->syscall_cnt, 0, 0, mem_loc);
    }
}

void track_function(RTN rtn, void* v)
{
    RTN_Open(rtn);
    const char* name = RTN_Name(rtn).c_str();
    if (trace_x) {
        /* Note this does not work, if you don't have debug symbols
         * compiled into your library/binary */
        if (!strcmp(name, "XPutImage")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_xputimage_start,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
                    IARG_FUNCARG_ENTRYPOINT_REFERENCE, 8,
                    IARG_FUNCARG_ENTRYPOINT_REFERENCE, 9,
                    IARG_END);
        } else if (!strcmp(name, "_moz_cairo_show_glyphs") || 
                !strcmp(name, "cairo_show_glyphs")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_cairo_show_glyphs_start,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_END);
        } 
        else if (!strcmp(name, "_moz_cairo_glyph_extents") ||
                (!strcmp(name, "cairo_glyph_extents"))){
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_cairo_show_glyphs_start,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_END);
        }
        else if (!strcmp(name, "_moz_cairo_scaled_font_glyph_extents") ||
                strstr(name, "_cairo_scaled_font_glyph_device_extents")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, 
                    (AFUNPTR)trace_x_cairo_show_glyphs_start,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_END);
        }
        else if (strstr(name, "_cairo_scaled_font_show_glyphs")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_cairo_scaled_font_show_glyphs,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
                    IARG_END);
        }
        else if (!strcmp(name, "XRenderCompositeText8")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_xrendercompositetext,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 7,   // dst x coord
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 8,   // dst y coord
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
                    IARG_END);
        }
        else if (strstr(name, "Html5") && strstr(name, "AppendText")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)string_inspect,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_END);
        }
    }

    RTN_Close(rtn);
}

int get_record_pid()
{
    //calling kernel for this replay thread's record log
    int record_log_id;

    record_log_id = get_log_id (dev_fd);
    if (record_log_id == -1) {
        int pid = PIN_GetPid();
        fprintf(stderr, "Could not get the record pid from kernel, pid is %d\n", pid);
        return pid;
    }
    return record_log_id;
}

void instrument_taint_reg2reg(INS ins, REG dstreg, REG srcreg, int extend);
void instrument_taint_reg2mem(INS ins, REG srcreg, int extend);
void instrument_taint_mem2reg(INS ins, REG dstreg, int extend);
void instrument_taint_mem2mem(INS ins, int extend);

void instrument_taint_add_reg2reg(INS ins, REG dstreg, REG srcreg, int set_flags, int clear_flags);
void instrument_taint_add_reg2mem(INS ins, REG srcreg, int set_flags, int clear_flags);
void instrument_taint_add_mem2reg(INS ins, REG dstreg, int set_flags, int clear_flags);
void instrument_taint_add_mem2mem(INS ins);

// predicated instrumentation
void pred_instrument_taint_reg2reg(INS ins, REG dstreg, REG srcreg, int extend);
void pred_instrument_taint_mem2reg(INS ins, REG dstreg, int extend);

void instrument_taint_immval2mem(INS ins);
void instrument_taint_reg2regflag (INS ins, REG dstreg, REG srcreg, int set_flags, int clear_flags);
void instrument_taint_mem2regflag (INS ins, REG dstreg, int set_flags, int clear_flags);

void instrument_clear_dst(INS ins);
void instrument_clear_reg(INS ins, REG reg);
void instrument_clear_flag (INS ins, uint32_t mask);
void instrument_clear_mem_src (INS ins);

// Trivial analysis routine to pass its argument back in an IfCall 
// so that we can use it to control the next piece of instrumentation.
static ADDRINT returnArg (BOOL arg)
{
    return arg;
}

TAINTSIGN do_nothing () { 
}

#ifdef FW_SLICE
static inline char* get_copy_of_disasm (INS ins) { 
	const char* tmp = INS_Disassemble (ins).c_str();
	char* str = NULL;
	assert (tmp != NULL);
	str = (char*) malloc (strlen (tmp) + 1);
	assert (str != NULL);
	strcpy (str, tmp);
	return str;
}
static inline void put_copy_of_disasm (char* str) { 
	//if (str) free (str);
	//TODO memory leak
}

static inline void fw_slice_check_address (INS ins) { 
	UINT32 count = INS_OperandCount (ins);
	UINT32 i = 0;
	int has_mem_operand = 0;
	int memory_read_count = 0;
	if (INS_MemoryOperandCount(ins) == 1) {
		for (; i<count; ++i) { 
			if (INS_OperandIsMemory(ins, i)) { 
				IARG_TYPE mem_ea = IARG_INVALID;
				UINT32 memsize = 0;
				if (INS_IsMemoryRead(ins)) {
					if (memory_read_count == 1) {//this is the second read
						mem_ea = IARG_MEMORYREAD2_EA,
						memsize = INS_MemoryOperandSize(ins, 1);
					} else {
						mem_ea = IARG_MEMORYREAD_EA;
						memsize = INS_MemoryReadSize(ins);
                                                ++ memory_read_count;
					}
				} else if (INS_IsMemoryWrite(ins)) {
					mem_ea = IARG_MEMORYWRITE_EA;
					memsize = INS_MemoryWriteSize(ins);
				}

				REG base_reg = INS_OperandMemoryBaseReg(ins, i);			
				REG index_reg = INS_OperandMemoryIndexReg(ins, i);			
				if (REG_valid (base_reg) && REG_valid(index_reg)) {
					INS_InsertThenCall(ins, IPOINT_BEFORE,
							AFUNPTR(fw_slice_addressing),
							IARG_FAST_ANALYSIS_CALL,
							IARG_INST_PTR,
							IARG_UINT32, translate_reg (base_reg),
							IARG_UINT32, REG_Size(base_reg),
							IARG_REG_VALUE, base_reg,
							IARG_UINT32, REG_is_Upper8(base_reg),
							IARG_UINT32, translate_reg(index_reg),
							IARG_UINT32, REG_Size(index_reg),
							IARG_REG_VALUE, index_reg,
							IARG_UINT32, REG_is_Upper8(index_reg),
							mem_ea,
							IARG_UINT32, memsize, 
							IARG_UINT32, INS_IsMemoryRead(ins),
							IARG_END);
					has_mem_operand = 1;
				} else if (REG_valid (base_reg) && !REG_valid (index_reg)) {
					INS_InsertThenCall(ins, IPOINT_BEFORE,
							AFUNPTR(fw_slice_addressing),
							IARG_FAST_ANALYSIS_CALL,
							IARG_INST_PTR,
							IARG_UINT32, translate_reg (base_reg),
							IARG_UINT32, REG_Size(base_reg),
							IARG_REG_VALUE, base_reg,
							IARG_UINT32, REG_is_Upper8(base_reg),
							IARG_UINT32, 0,
							IARG_UINT32, 0, 
							IARG_UINT32, 0, 
							IARG_UINT32, 0,
							mem_ea,
							IARG_UINT32, memsize, 
							IARG_UINT32, INS_IsMemoryRead(ins),
							IARG_END);
					has_mem_operand = 1;
				} else if (!REG_valid (base_reg) && !REG_valid (index_reg)) {
					INS_InsertThenCall(ins, IPOINT_BEFORE,
							AFUNPTR(fw_slice_addressing),
							IARG_FAST_ANALYSIS_CALL,
							IARG_INST_PTR,
							IARG_UINT32, 0,
							IARG_UINT32, 0, 
							IARG_UINT32, 0, 
							IARG_UINT32, 0,
							IARG_UINT32, 0,
							IARG_UINT32, 0,
							IARG_UINT32, 0, 
							IARG_UINT32, 0, 
							mem_ea,
							IARG_UINT32, memsize, 
							IARG_UINT32, INS_IsMemoryRead(ins),
							IARG_END);
					has_mem_operand = 1;
				} else if (!REG_valid (base_reg) && REG_valid (index_reg)) {
					INS_InsertThenCall(ins, IPOINT_BEFORE,
							AFUNPTR(fw_slice_addressing),
							IARG_FAST_ANALYSIS_CALL,
							IARG_INST_PTR,
							IARG_UINT32, 0,
							IARG_UINT32, 0, 
							IARG_UINT32, 0, 
							IARG_UINT32, 0, 
							IARG_UINT32, translate_reg (index_reg),
							IARG_UINT32, REG_Size(index_reg),
							IARG_REG_VALUE, index_reg,
							IARG_UINT32, REG_is_Upper8(index_reg),
							mem_ea,
							IARG_UINT32, memsize, 
							IARG_UINT32, INS_IsMemoryRead(ins),
							IARG_END);
					has_mem_operand = 1;
				} else {
					fprintf (stderr, "[ERROR] unrecognized mem addr %s\n", INS_Disassemble(ins).c_str());
					assert (0);
				}
			}
		}
	} else if (INS_MemoryOperandCount (ins) == 2) {
		REG base_reg[2];
		REG index_reg[2];
		uint32_t base_reg_size[2] = {0};
		uint32_t index_reg_size[2] = {0};
		IARG_TYPE base_type[2] = {IARG_INVALID, IARG_INVALID};
		IARG_TYPE index_type[2] = {IARG_INVALID, IARG_INVALID};
		int base_value[2] = {0};
		int index_value[2] = {0};
		uint32_t index = 0;
		uint32_t is_read[2] = {0,0};
		IARG_TYPE mem_type[2];
		UINT32 memsize[2];
		if (INS_MemoryOperandIsWritten(ins, 0)) {
			mem_type[0] = IARG_MEMORYWRITE_EA;
			is_read[0] = 0;
		} else if(INS_MemoryOperandIsRead(ins, 0)) {
			mem_type[0] = IARG_MEMORYREAD_EA;
			is_read[0] = 1;
                        ++ memory_read_count;
		} else 
			assert (0);
		if (INS_MemoryOperandIsWritten(ins, 1)) {
			mem_type[1] = IARG_MEMORYWRITE_EA;
			is_read[0] = 0;
		} else if(INS_MemoryOperandIsRead(ins, 1)) {
                        if (memory_read_count == 1) 
                            mem_type[1] = IARG_MEMORYREAD2_EA;
                        else
                            mem_type[1] = IARG_MEMORYREAD_EA;
			is_read[0] = 1;
		} else 
			assert (0);
		memsize[0] = INS_MemoryOperandSize (ins, 0);
		memsize[1] = INS_MemoryOperandSize (ins, 1);

		//printf ("[DEBUG]two mem operands: %s\n", INS_Disassemble(ins).c_str());
		for (i=0; i<count; ++i) { 
			if (INS_OperandIsMemory(ins, i)) { 
				base_reg[index] = INS_OperandMemoryBaseReg(ins, i);			
				index_reg[index] = INS_OperandMemoryIndexReg(ins, i);			
				if (REG_valid (base_reg[index])) {
					base_reg_size[index] = REG_Size(base_reg[index]);
					base_type[index] = IARG_REG_VALUE;
					base_value[index] = base_reg[index];
				} else { 
					base_reg_size[index] = 0;
					base_type[index] = IARG_UINT32;
					base_value[index] = 0;
				}
				if (REG_valid (index_reg[index])) {
					index_reg_size[index] = REG_Size (index_reg[index]);
					index_type[index] = IARG_REG_VALUE;
					index_value[index] = index_reg[index];
				} else { 
					index_reg_size[index] = 0;
					index_type[index] = IARG_UINT32;
					index_value[index] = 0;
				}
				++index;
			}
		}
		INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(fw_slice_addressing_check_two),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_UINT32, translate_reg(base_reg[0]),
				IARG_UINT32, base_reg_size[0],
				base_type[0], base_value[0],
				IARG_UINT32, REG_is_Upper8(base_reg[0]),
				IARG_UINT32, translate_reg(index_reg[0]),
				IARG_UINT32, index_reg_size[0],
				index_type[0], index_value[0],
				IARG_UINT32, REG_is_Upper8(index_reg[0]),
				mem_type[0],
				IARG_UINT32, memsize[0],
				IARG_UINT32, is_read[0],
				IARG_UINT32, translate_reg(base_reg[1]),
				IARG_UINT32, base_reg_size[1],
				base_type[1], base_value[1],
				IARG_UINT32, REG_is_Upper8(base_reg[1]),
				IARG_UINT32, translate_reg(index_reg[1]),
				IARG_UINT32, index_reg_size[1],
				index_type[1], index_value[1],
				IARG_UINT32, REG_is_Upper8(index_reg[1]),
				mem_type[1],
				IARG_UINT32, memsize[0],
				IARG_UINT32, is_read[1],
				IARG_END);
		has_mem_operand = 1;
	} else 
		assert (0);
	if (has_mem_operand == 0) { 
		fprintf (stderr, "[ERROR] unrecognized mem operands %s, operand count %d\n", INS_Disassemble(ins).c_str(), count);
		INS_InsertThenCall (ins, IPOINT_BEFORE, 
				AFUNPTR(do_nothing),
				IARG_FAST_ANALYSIS_CALL,
				IARG_END);
	}
}

static inline void fw_slice_src_reg (INS ins, REG srcreg, uint32_t src_regsize, int is_dst_mem) { 
	char* str = get_copy_of_disasm (ins);
	IARG_TYPE mem_ea = IARG_INVALID;
        
	if (is_dst_mem == 0) { 
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(fw_slice_reg),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_PTR, str,
				IARG_UINT32, srcreg, //no need for translate_reg
				IARG_UINT32, src_regsize,
				IARG_ADDRINT, 0,
                                IARG_CONST_CONTEXT,
				IARG_UINT32, REG_is_Upper8(srcreg),
				IARG_END);
	} else { 
		if (INS_IsMemoryRead(ins)) {
			mem_ea = IARG_MEMORYREAD_EA;
		} else if (INS_IsMemoryWrite(ins)) {
			mem_ea = IARG_MEMORYWRITE_EA;
		}

                if (INS_MemoryOperandCount (ins) > 0) {
			INS_InsertIfCall(ins, IPOINT_BEFORE,
					AFUNPTR(fw_slice_reg),
					IARG_FAST_ANALYSIS_CALL,
					IARG_INST_PTR,
					IARG_PTR, str,
                                        IARG_UINT32, srcreg, //no need for translate_reg
					IARG_UINT32, src_regsize,
					mem_ea,
                                        IARG_CONST_CONTEXT,
					IARG_UINT32, REG_is_Upper8(srcreg),
					IARG_END);

			fw_slice_check_address (ins);
		} else 
			INS_InsertCall(ins, IPOINT_BEFORE,
					AFUNPTR(fw_slice_reg),
					IARG_FAST_ANALYSIS_CALL,
					IARG_INST_PTR,
					IARG_PTR, str,
                                        IARG_UINT32, srcreg, //no need for translate_reg
					IARG_UINT32, src_regsize,
					mem_ea,
                                        IARG_CONST_CONTEXT,
					IARG_UINT32, REG_is_Upper8(srcreg),
					IARG_END);

	}
	put_copy_of_disasm (str);
}
static inline void fw_slice_src_mem (INS ins, int is_dst_mem) {
	    char* str = get_copy_of_disasm (ins);
	    if (is_dst_mem) { 
		    INS_InsertIfCall(ins, IPOINT_BEFORE,
				    AFUNPTR(fw_slice_mem),
				    IARG_FAST_ANALYSIS_CALL,
				    IARG_INST_PTR,
				    IARG_PTR, str,
				    IARG_MEMORYREAD_EA,
				    IARG_UINT32, INS_MemoryReadSize(ins),
				    IARG_MEMORYWRITE_EA,
				    IARG_END);
		    fw_slice_check_address(ins);
	    } else { 
		 if (INS_MemoryOperandCount (ins) > 0) {
			INS_InsertIfCall(ins, IPOINT_BEFORE,
				    AFUNPTR(fw_slice_mem),
				    IARG_FAST_ANALYSIS_CALL,
				    IARG_INST_PTR,
				    IARG_PTR, str,
				    IARG_MEMORYREAD_EA,
				    IARG_UINT32, INS_MemoryReadSize(ins),
				    IARG_ADDRINT, 0,
				    IARG_END);
			fw_slice_check_address (ins);
		} else 
		    INS_InsertCall(ins, IPOINT_BEFORE,
				    AFUNPTR(fw_slice_mem),
				    IARG_FAST_ANALYSIS_CALL,
				    IARG_INST_PTR,
				    IARG_PTR, str,
				    IARG_MEMORYREAD_EA,
				    IARG_UINT32, INS_MemoryReadSize(ins),
				    IARG_ADDRINT, 0,
				    IARG_END);

	    }
	    put_copy_of_disasm (str);
}
//the following three functions merges taints from two operands and also consider different operand sizes
//dstreg does not necessarily mean the destination register, refer to instrument_lea
static inline void fw_slice_src_regreg (INS ins, REG dstreg, uint32_t dst_regsize, REG srcreg, uint32_t src_regsize) { 
	char* str = get_copy_of_disasm (ins);
	if (INS_MemoryOperandCount (ins) > 0) {
		INS_InsertIfCall(ins, IPOINT_BEFORE,
				AFUNPTR(fw_slice_regreg),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_PTR, str,
				IARG_UINT32, dstreg,
				IARG_UINT32, srcreg,
				IARG_UINT32, dst_regsize,
				IARG_UINT32, src_regsize,
                                IARG_CONST_CONTEXT,
				IARG_UINT32, REG_is_Upper8(dstreg),
				IARG_UINT32, REG_is_Upper8(srcreg),
				IARG_END);
		fw_slice_check_address (ins);
	} else {
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(fw_slice_regreg),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_PTR, str,
				IARG_UINT32, dstreg,
				IARG_UINT32, srcreg,
				IARG_UINT32, dst_regsize,
				IARG_UINT32, src_regsize,
                                IARG_CONST_CONTEXT,
				IARG_UINT32, REG_is_Upper8(dstreg),
				IARG_UINT32, REG_is_Upper8(srcreg),
				IARG_END);
	}
	put_copy_of_disasm (str);
}
static inline void fw_slice_src_memmem (INS ins, uint32_t memread_size, uint32_t memwrite_size) { 
	char* str = get_copy_of_disasm (ins);
	INS_InsertIfCall(ins, IPOINT_BEFORE,
			AFUNPTR(fw_slice_memmem),
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_PTR, str,
			IARG_MEMORYREAD_EA,
			IARG_MEMORYWRITE_EA,
			IARG_UINT32, memread_size,
			IARG_UINT32, memwrite_size,
			IARG_END);
	fw_slice_check_address (ins);
	put_copy_of_disasm (str);
}
static inline void fw_slice_src_regmem (INS ins, REG reg, uint32_t reg_size,  IARG_TYPE mem_ea, uint32_t memsize) { 
	char* str = get_copy_of_disasm (ins);
	INS_InsertIfCall(ins, IPOINT_BEFORE,
			AFUNPTR(fw_slice_memreg),
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_PTR, str,
			IARG_ADDRINT, reg, 
			IARG_UINT32, reg_size,
                        IARG_CONST_CONTEXT,
			IARG_UINT32, REG_is_Upper8(reg),
			mem_ea, 
			IARG_UINT32, memsize,
			IARG_END);
	fw_slice_check_address(ins);
	put_copy_of_disasm (str);
}

static inline void fw_slice_src_flag (INS ins, uint32_t mask) { 
	char* str = get_copy_of_disasm (ins);
	if (INS_MemoryOperandCount(ins) > 0) {
		INS_InsertIfCall(ins, IPOINT_BEFORE,
				AFUNPTR(fw_slice_flag),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_PTR, str,
				IARG_UINT32, mask,
				IARG_BRANCH_TAKEN,
				IARG_END);
		fw_slice_check_address(ins);
	} else {
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(fw_slice_flag),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_PTR, str,
				IARG_UINT32, mask,
				IARG_BRANCH_TAKEN,
				IARG_END);
	}
	put_copy_of_disasm (str);
}

static inline void fw_slice_src_regregreg (INS ins, REG dstreg, uint32_t dst_regsize, REG srcreg, uint32_t src_regsize, REG countreg, uint32_t count_regsize) { 
	char* str = get_copy_of_disasm (ins);

	if (INS_MemoryOperandCount(ins) > 0) { 
		INS_InsertIfCall(ins, IPOINT_BEFORE,
				AFUNPTR(fw_slice_regregreg),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_PTR, str,
				IARG_UINT32, dstreg,
				IARG_UINT32, srcreg,
				IARG_UINT32, countreg,
				IARG_UINT32, dst_regsize,
				IARG_UINT32, src_regsize,
				IARG_UINT32, count_regsize,
                                IARG_CONST_CONTEXT,
				IARG_UINT32, REG_is_Upper8(dstreg),
				IARG_UINT32, REG_is_Upper8(srcreg),
				IARG_UINT32, REG_is_Upper8(countreg),
				IARG_END);
		fw_slice_check_address (ins);
	} else {
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(fw_slice_regregreg),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_PTR, str,
				IARG_UINT32, dstreg,
				IARG_UINT32, srcreg,
				IARG_UINT32, countreg,
				IARG_UINT32, dst_regsize,
				IARG_UINT32, src_regsize,
				IARG_UINT32, count_regsize,
                                IARG_CONST_CONTEXT,
				IARG_UINT32, REG_is_Upper8(dstreg),
				IARG_UINT32, REG_is_Upper8(srcreg),
				IARG_UINT32, REG_is_Upper8(countreg),
				IARG_END);
	}
	put_copy_of_disasm (str);
}

static inline void fw_slice_src_regregmem (INS ins, REG reg1, uint32_t reg1_size, REG reg2, uint32_t reg2_size, IARG_TYPE mem_ea, uint32_t memsize) { 
	char* str = get_copy_of_disasm (ins);
	INS_InsertIfCall(ins, IPOINT_BEFORE,
			AFUNPTR(fw_slice_memregreg),
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_PTR, str,
			IARG_ADDRINT, translate_reg (reg1), 
			IARG_UINT32, reg1_size,
			IARG_REG_VALUE, reg1, 
			IARG_UINT32, REG_is_Upper8(reg1),
			IARG_ADDRINT, translate_reg (reg2), 
			IARG_UINT32, reg2_size,
			IARG_REG_VALUE, reg2, 
			IARG_UINT32, REG_is_Upper8(reg2),
			mem_ea, 
			IARG_UINT32, memsize,
			IARG_END);
	fw_slice_check_address (ins);
	put_copy_of_disasm (str);
}

#ifdef LINKAGE_DATA_OFFSET
//only use this for CMOV  with index tool enabled
static inline void fw_slice_src_regregmemflag_cmov (INS ins, REG dest_reg, REG base_reg, uint32_t base_reg_size, REG index_reg, uint32_t index_reg_size, IARG_TYPE mem_ea, uint32_t memsize, uint32_t flag) 
{ 
    char* str = get_copy_of_disasm (ins);
    printf ("%s\n", str);
    fflush(stdout);
    int base_is_upper = 0, index_is_upper = 0, tbase_reg = 0, tindex_reg = 0;
    IARG_TYPE base_reg_value_type = IARG_UINT32, index_reg_value_type = IARG_UINT32;
    if (!REG_valid(base_reg)) {
	base_reg_size = 0;
    } else {
	tbase_reg = translate_reg (base_reg);
	base_is_upper = REG_is_Upper8(base_reg);
	base_reg_value_type = IARG_REG_VALUE;
    }
    if (!REG_valid(index_reg)) {
	index_reg_size = 0;
    } else {
	tindex_reg = translate_reg (index_reg);
	index_is_upper = REG_is_Upper8(index_reg);
	index_reg_value_type = IARG_REG_VALUE;
    }

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_memregregflag_cmov),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_ADDRINT, translate_reg(dest_reg),
		   IARG_UINT32, REG_Size(dest_reg),
		   IARG_REG_REFERENCE, dest_reg,
		   IARG_UINT32, REG_is_Upper8(dest_reg),
		   IARG_ADDRINT, tbase_reg,
		   IARG_UINT32, base_reg_size,
		   base_reg_value_type, base_reg, 
		   IARG_UINT32, base_is_upper,
		   IARG_ADDRINT, tindex_reg,
		   IARG_UINT32, index_reg_size,
		   index_reg_value_type, index_reg, 
		   IARG_UINT32, index_is_upper,
		   mem_ea, 
		   IARG_UINT32, memsize,
		   IARG_UINT32, flag,
		   IARG_EXECUTING,
		   IARG_END);

    put_copy_of_disasm (str);
}

//only use this for MOV/MOVX  with index tool enabled
static inline void fw_slice_src_regregmem_mov (INS ins, REG base_reg, REG index_reg, IARG_TYPE mem_ea, uint32_t memsize) { 
#ifdef FW_SLICE
	char* str = get_copy_of_disasm (ins);
        int t_base_reg = 0;
        int t_index_reg = 0;
        int base_reg_size = 0;
        int index_reg_size = 0;
        int base_reg_u8 = 0;
        int index_reg_u8 = 0;
        IARG_TYPE base_reg_value_type = IARG_UINT32;
        IARG_TYPE index_reg_value_type = IARG_UINT32;
        if (REG_valid(base_reg)) { 
            t_base_reg = translate_reg (base_reg);
            base_reg_size = REG_Size (base_reg);
            base_reg_u8 = REG_is_Upper8 (base_reg);
            base_reg_value_type = IARG_REG_VALUE;
        }
        if (REG_valid(index_reg)) { 
            t_index_reg = translate_reg (index_reg);
            index_reg_size = REG_Size (index_reg);
            index_reg_u8 = REG_is_Upper8 (index_reg);
            index_reg_value_type = IARG_REG_VALUE;
        }

        INS_InsertIfCall(ins, IPOINT_BEFORE,
                AFUNPTR(fw_slice_memregreg_mov),
                IARG_FAST_ANALYSIS_CALL,
                IARG_INST_PTR,
                IARG_PTR, str,
                IARG_ADDRINT, t_base_reg, 
                IARG_UINT32, base_reg_size,
                base_reg_value_type, base_reg, 
                IARG_UINT32, base_reg_u8,
                IARG_ADDRINT, t_index_reg, 
                IARG_UINT32, index_reg_size,
                index_reg_value_type, index_reg, 
                IARG_UINT32, index_reg_u8,
                mem_ea, 
                IARG_UINT32, memsize,
                IARG_END);

	fw_slice_check_address (ins);
	put_copy_of_disasm (str);
#endif
}

//only use this for MOV/MOVX  with index tool enabled
static inline void fw_slice_src_regregreg_mov (INS ins, REG reg, REG base_reg, REG index_reg) { 
#ifdef FW_SLICE
	char* str = get_copy_of_disasm (ins);
        int t_base_reg = 0;
        int t_index_reg = 0;
        int base_reg_size = 0;
        int index_reg_size = 0;
        int base_reg_u8 = 0;
        int index_reg_u8 = 0;
        IARG_TYPE base_reg_value_type = IARG_UINT32;
        IARG_TYPE index_reg_value_type = IARG_UINT32;
        if (REG_valid(base_reg)) { 
            t_base_reg = translate_reg (base_reg);
            base_reg_size = REG_Size (base_reg);
            base_reg_u8 = REG_is_Upper8 (base_reg);
            base_reg_value_type = IARG_REG_VALUE;
        }
        if (REG_valid(index_reg)) { 
            t_index_reg = translate_reg (index_reg);
            index_reg_size = REG_Size (index_reg);
            index_reg_u8 = REG_is_Upper8 (index_reg);
            index_reg_value_type = IARG_REG_VALUE;
        }

        INS_InsertIfCall(ins, IPOINT_BEFORE,
                AFUNPTR(fw_slice_regregreg_mov),
                IARG_FAST_ANALYSIS_CALL,
                IARG_INST_PTR,
                IARG_PTR, str,
                IARG_ADDRINT, translate_reg (reg), 
                IARG_UINT32, REG_Size (reg), 
                IARG_REG_REFERENCE, reg, 
                IARG_UINT32, REG_is_Upper8 (reg), 
                IARG_ADDRINT, t_base_reg, 
                IARG_UINT32, base_reg_size,
                base_reg_value_type, base_reg, 
                IARG_UINT32, base_reg_u8,
                IARG_ADDRINT, t_index_reg, 
                IARG_UINT32, index_reg_size,
                index_reg_value_type, index_reg, 
                IARG_UINT32, index_reg_u8,
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, INS_MemoryWriteSize(ins), 
                IARG_END);

	fw_slice_check_address (ins);
	put_copy_of_disasm (str);
#endif
}
#endif

static inline void fw_slice_src_regflag (INS ins, uint32_t mask, REG reg, uint32_t reg_size) {
	char* str = get_copy_of_disasm (ins);
	if (INS_MemoryOperandCount (ins) > 0) {
		INS_InsertIfCall(ins, IPOINT_BEFORE,
				AFUNPTR(fw_slice_regflag),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_PTR, str,
				IARG_UINT32, mask,
				IARG_ADDRINT, reg, 
				IARG_UINT32, reg_size,
                                IARG_CONST_CONTEXT,
				IARG_UINT32, REG_is_Upper8(reg),
				IARG_END);
		fw_slice_check_address (ins);
	} else 
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(fw_slice_regflag),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR,
				IARG_PTR, str,
				IARG_UINT32, mask,
				IARG_ADDRINT, reg, 
				IARG_UINT32, reg_size,
                                IARG_CONST_CONTEXT,
				IARG_UINT32, REG_is_Upper8(reg),
				IARG_END);
	put_copy_of_disasm (str);
}

static inline void fw_slice_src_memflag (INS ins, uint32_t mask, IARG_TYPE mem_ea, uint32_t memsize) { 
	char* str = get_copy_of_disasm (ins);
	INS_InsertIfCall(ins, IPOINT_BEFORE,
			AFUNPTR(fw_slice_memflag),
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR,
			IARG_PTR, str,
			IARG_UINT32, mask,
			mem_ea, 
			IARG_UINT32, memsize,
			IARG_END);
	fw_slice_check_address (ins);
	put_copy_of_disasm (str);
}

static ADDRINT computeEA(ADDRINT firstEA, UINT eflags, UINT32 count, UINT32 op_size);

//it depends on not only the source string, but also ECX (count); 
//it also depends on esi and edi probably for the index tool
//TODO: it should also depend on DF_FLAG
//TODO: for repz, we probably need the exact number of iterations, which is supported with scan_string
TAINTINT fw_slice_string_internal (ADDRINT ip, char* inst_str, ADDRINT src_mem_loc, ADDRINT eflags, uint32_t count_reg, ADDRINT counts, UINT32 op_size, u_long dst_mem, uint32_t first_iter) { 
	//only check on the first iteration
    if (first_iter) {
        int size = (int) (counts*op_size);
        int tainted = 0;
        if (!size) return 0;
        ADDRINT ea_src_mem_loc = computeEA (src_mem_loc, eflags, counts, op_size);
        //fprintf (stderr, "fw_slice_string_internal %s src_mem_loc %x eflags %x counts %xop_size  %x dst_mem %lx ea_src %x\n", inst_str, src_mem_loc, eflags, counts, op_size, dst_mem, ea_src_mem_loc);
	if (count_reg) { //count_reg is set only with REP prefix
		assert (count_reg == 9); //should always be ecx, otherwise, add the support
		tainted = fw_slice_memreg_imm_value (ip, inst_str, count_reg, 4, counts, 0, ea_src_mem_loc, size);
	} else{ 
		tainted = fw_slice_mem (ip, inst_str, ea_src_mem_loc, size, dst_mem);
	}
	//assert for DF_FLAG
	assert (is_flag_tainted(DF_FLAG) == 0);
        return tainted;
    }
    return 0;
}

//TODO: depends on DF_FLAG
//TODO: for repz, we probably need the exact number of iterations, which is supported with scan_string
TAINTINT fw_slice_stringstring_internal (ADDRINT ip, char* inst_str, ADDRINT src_mem_loc, ADDRINT eflags, uint32_t count_reg, ADDRINT counts, UINT32 op_size, u_long dst_mem_loc, uint32_t first_iter) { 
	//only check on the first iteration
    if (first_iter) {
        int size = (int) (counts*op_size);
        int tainted = 0;
        if (!size) return 0;
        ADDRINT ea_src_mem_loc = computeEA (src_mem_loc, eflags, counts, op_size);
	ADDRINT ea_dst_mem_loc = computeEA (dst_mem_loc, eflags, counts, op_size);
	if (count_reg) { //count_reg is set only with REP prefix
		assert (count_reg == 9); //should always be ecx, otherwise, add the support
		tainted = fw_slice_memmemreg_imm_value (ip, inst_str, ea_src_mem_loc, ea_dst_mem_loc, size, size, count_reg, 4, counts, 0);
	} else{ 
		tainted = fw_slice_memmem (ip, inst_str, ea_src_mem_loc, ea_dst_mem_loc, size, size);
	}
	//assert for DF_FLAG
	assert (is_flag_tainted(DF_FLAG) == 0);
        return tainted;
    }
    return 0;
}

TAINTINT fw_slice_stringreg_internal (ADDRINT ip, char* inst_str, 
        ADDRINT src_mem_loc, ADDRINT eflags, 
        uint32_t count_reg, ADDRINT counts, UINT32 op_size, 
        uint32_t reg, uint32_t reg_size, uint32_t is_upper8, uint32_t reg_value, 
        uint32_t first_iter, uint32_t is_rep, uint32_t is_repz) { 
    //for rep, only check on the first iteration
    //but for repz, check on the final iternation, when we know the exact number of iterations
    if ((is_rep && first_iter) ||  (is_repz && (eflags & ZF_MASK))) {
        //for repz, we cannot infer the actual number of executions from the count register
        if (is_repz) { 
            src_mem_loc = current_thread->repz_src_mem_loc;
            counts = current_thread->repz_counts;
            counts ++; //IMPORTANT: this function get called before repz_execute_count, we add 1 here
        }
        //fprintf (stderr, "fw_slice_stringrep_internal %s, is_rep %u repz %u, counts %u, zf_flag %u\n", inst_str, is_rep, is_repz, counts, eflags & ZF_MASK);
        int size = (int) (counts*op_size);
        int tainted = 0;
        if (!size) return 0;
        ADDRINT ea_src_mem_loc = computeEA (src_mem_loc, eflags, counts, op_size);
	if (count_reg) { //count_reg is set only with REP prefix
		assert (count_reg == 9); //should always be ecx, otherwise, add the support
		tainted = fw_slice_memregreg (ip, inst_str, count_reg, 4, counts, 0, reg, reg_size, reg_value, is_upper8, ea_src_mem_loc, size);
	} else{ 
		tainted = fw_slice_memreg_imm_value (ip, inst_str, reg, reg_size, reg_value, is_upper8, ea_src_mem_loc, size);
	}
	//assert for DF_FLAG
	assert (is_flag_tainted(DF_FLAG) == 0);
        return tainted;
    }
    return 0;
}


static inline void fw_slice_src_string (INS ins, int rep, uint32_t is_dst_mem) { 
    char* str = get_copy_of_disasm (ins);
    if (rep) {
        if (is_dst_mem) 
            //we only print the slice once on the first iteration of rep
            //and also call taint_rep
            INS_InsertIfCall(ins, IPOINT_BEFORE,
                    AFUNPTR(fw_slice_string_internal),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_INST_PTR,
                    IARG_PTR, str,
                    IARG_MEMORYREAD_EA,
                    IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_UINT32, translate_reg(INS_RepCountRegister (ins)),
                    IARG_REG_VALUE, INS_RepCountRegister (ins),
                    IARG_UINT32, INS_MemoryOperandSize (ins,0),
                    IARG_MEMORYWRITE_EA,
                    IARG_FIRST_REP_ITERATION,
                    IARG_END);
        else 
            INS_InsertIfCall(ins, IPOINT_BEFORE,
                    AFUNPTR(fw_slice_string_internal),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_INST_PTR,
                    IARG_PTR, str,
                    IARG_MEMORYREAD_EA,
                    IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_UINT32, translate_reg(INS_RepCountRegister (ins)),
                    IARG_REG_VALUE, INS_RepCountRegister (ins),
                    IARG_UINT32, INS_MemoryOperandSize (ins,0),
                    IARG_UINT32, 0, 
                    IARG_FIRST_REP_ITERATION,
                    IARG_END);
    } else {
        if (is_dst_mem)  
            INS_InsertIfCall(ins, IPOINT_BEFORE,
                    AFUNPTR(fw_slice_string_internal),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_INST_PTR,
                    IARG_PTR, str,
                    IARG_MEMORYREAD_EA,
                    IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_UINT32, 0,
                    IARG_UINT32, 1,
                    IARG_UINT32, INS_MemoryOperandSize (ins,0),
                    IARG_MEMORYWRITE_EA,
                    IARG_UINT32, 0,
                    IARG_END);

        else
            INS_InsertIfCall(ins, IPOINT_BEFORE,
                    AFUNPTR(fw_slice_string_internal),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_INST_PTR,
                    IARG_PTR, str,
                    IARG_MEMORYREAD_EA,
                    IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_UINT32, 0,
                    IARG_UINT32, 1,
                    IARG_UINT32, INS_MemoryOperandSize (ins,0),
                    IARG_UINT32, 0, 
                    IARG_UINT32, 0,
                    IARG_END);
    }
    fw_slice_check_address (ins);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_stringstring (INS ins, int rep) { 
    char* str = get_copy_of_disasm (ins);
    if (rep) {
	    //we only print the slice once on the first iteration of rep
	    //and also call taint_rep
	    INS_InsertIfCall(ins, IPOINT_BEFORE,
			    AFUNPTR(fw_slice_stringstring_internal),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_INST_PTR,
			    IARG_PTR, str,
			    IARG_MEMORYREAD_EA,
			    IARG_REG_VALUE, REG_EFLAGS, 
			    IARG_UINT32, translate_reg(INS_RepCountRegister (ins)),
			    IARG_REG_VALUE, INS_RepCountRegister (ins),
			    IARG_UINT32, INS_MemoryOperandSize (ins,0),
			    IARG_MEMORYREAD2_EA, 
			    IARG_FIRST_REP_ITERATION,
			    IARG_END);
    } else {
	    INS_InsertIfCall(ins, IPOINT_BEFORE,
			    AFUNPTR(fw_slice_stringstring_internal),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_INST_PTR,
			    IARG_PTR, str,
			    IARG_MEMORYREAD_EA,
			    IARG_REG_VALUE, REG_EFLAGS, 
			    IARG_UINT32, 0,
			    IARG_UINT32, 1,
			    IARG_UINT32, INS_MemoryOperandSize (ins,0),
			    IARG_MEMORYREAD2_EA, 
			    IARG_UINT32, 0,
			    IARG_END);

    }
    fw_slice_check_address (ins);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_stringreg (INS ins, int rep, int repz) { 
    char* str = get_copy_of_disasm (ins);
    if (rep) {
	    //we only print the slice once on the first iteration of rep
	    //and also call taint_rep
	    INS_InsertIfCall(ins, IPOINT_BEFORE,
			    AFUNPTR(fw_slice_stringreg_internal),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_INST_PTR,
			    IARG_PTR, str,
			    IARG_MEMORYREAD_EA,
			    IARG_REG_VALUE, REG_EFLAGS, 
			    IARG_UINT32, translate_reg(INS_RepCountRegister (ins)),
			    IARG_REG_VALUE, INS_RepCountRegister (ins),
			    IARG_UINT32, INS_MemoryOperandSize (ins,0),
			    IARG_UINT32, LEVEL_BASE::REG_EAX, 
			    IARG_UINT32, INS_MemoryOperandSize (ins,0),
			    IARG_UINT32, 0, //can't be ah
			    IARG_REG_VALUE, LEVEL_BASE::REG_EAX, 			
			    IARG_FIRST_REP_ITERATION,
                            IARG_UINT32, rep,
                            IARG_UINT32, repz,
			    IARG_END);
    } else if (repz) {
	    //we only print the slice once on the first iteration of rep
	    //and also call taint_rep
	    INS_InsertIfCall(ins, IPOINT_AFTER,
			    AFUNPTR(fw_slice_stringreg_internal),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_INST_PTR,
			    IARG_PTR, str,
                            IARG_ADDRINT, 0,
			    IARG_REG_VALUE, REG_EFLAGS, 
			    IARG_UINT32, translate_reg(INS_RepCountRegister (ins)),
			    IARG_REG_VALUE, INS_RepCountRegister (ins),
			    IARG_UINT32, INS_MemoryOperandSize (ins,0),
			    IARG_UINT32, LEVEL_BASE::REG_EAX, 
			    IARG_UINT32, INS_MemoryOperandSize (ins,0),
			    IARG_UINT32, 0, //can't be ah
			    IARG_REG_VALUE, LEVEL_BASE::REG_EAX, 			
			    IARG_FIRST_REP_ITERATION,
                            IARG_UINT32, rep,
                            IARG_UINT32, repz,
			    IARG_END);
    } else {
	    INS_InsertIfCall(ins, IPOINT_BEFORE,
			    AFUNPTR(fw_slice_stringreg_internal),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_INST_PTR,
			    IARG_PTR, str,
			    IARG_MEMORYREAD_EA,
			    IARG_REG_VALUE, REG_EFLAGS, 
			    IARG_UINT32, 0,
			    IARG_UINT32, 1,
			    IARG_UINT32, INS_MemoryOperandSize (ins,0),
			    IARG_UINT32, LEVEL_BASE::REG_EAX, 
			    IARG_UINT32, INS_MemoryOperandSize (ins,0),
			    IARG_UINT32, 0, //can't be ah
			    IARG_REG_VALUE, LEVEL_BASE::REG_EAX, 			
			    IARG_UINT32, 0,
			    IARG_UINT32, 0,
			    IARG_UINT32, 0,
			    IARG_END);

    }
    if (!repz) 
        fw_slice_check_address (ins);
    else {
        INS_InsertThenCall (ins, IPOINT_AFTER, (AFUNPTR)fw_slice_addressing_repz,
                IARG_INST_PTR,
                IARG_UINT32, INS_MemoryOperandSize (ins,0),
                IARG_END);
    }
    put_copy_of_disasm (str);
}

#endif

static UINT32 get_reg_off (REG reg)
{
    int treg = translate_reg((int)reg);
    UINT32 reg_offset = treg * REG_SIZE;
    if (REG_is_Upper8(reg)) reg_offset += 1;
    return reg_offset;
}

void instrument_taint_reg2reg_slice(INS ins, REG dstreg, REG srcreg, int extend, int fw_slice)
{
    UINT32 dst_regsize = REG_Size(dstreg);
    UINT32 src_regsize = REG_Size(srcreg);

#ifdef FW_SLICE
    if (fw_slice) fw_slice_src_reg (ins, srcreg, src_regsize, 0);
#endif

    if (dstreg == srcreg) return;

    UINT32 dst_reg_off = get_reg_off(dstreg);
    UINT32 src_reg_off = get_reg_off(srcreg);
    UINT32 size = (dst_regsize < src_regsize) ? dst_regsize : src_regsize;

    if (extend && dst_regsize > src_regsize) {
	// JNF: Bug compatible with previous version
	// Not sure this is right for all extension types
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_reg2reg_ext_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_UINT32, dst_reg_off,
		       IARG_UINT32, src_reg_off,
		       IARG_UINT32, size,
		       IARG_END);
    } else {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_reg2reg_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_UINT32, dst_reg_off,
		       IARG_UINT32, src_reg_off,
		       IARG_UINT32, size,
		       IARG_END);
    } 
}

void instrument_taint_reg2reg(INS ins, REG dstreg, REG srcreg, int extend)
{
	return instrument_taint_reg2reg_slice(ins, dstreg, srcreg, extend, 1); 
}

void instrument_taint_reg2mem_slice(INS ins, REG reg, int extend, int fw_slice)
{
    int treg = translate_reg((int)reg);
    UINT32 regsize = REG_Size(reg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

#ifdef FW_SLICE
    if(fw_slice) fw_slice_src_reg (ins, reg, regsize, 1);
#endif

    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_lbreg2mem),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(reg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_UBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_ubreg2mem),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_dwreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        //IARG_UINT32, find_static_address(INS_Address(ins)),
                        IARG_UINT32, TAINT_QWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_qwreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        //IARG_UINT32, find_static_address(INS_Address(ins)),
                        IARG_UINT32, TAINT_QWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
        }
    } else if (regsize < memsize) {
        if (extend) {
            switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2HWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2hwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2WMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_lbreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2DWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2dwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2QWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2qwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2HWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2hwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2WMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2wmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2DWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2dwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2QWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2qwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_WREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_wreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_WREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_wreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_DWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_dwreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
            }
        } else {
            switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2HWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2hwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2HWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2hwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_wreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_wreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_DWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_dwreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
            }
        } 
    } else {
        // regsize if greater than mem, just move the lower memsize bits
        // of the register to memory
        switch(memsize) {
            case 1:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_lbreg2mem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_dwreg2mem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                break;
            default:
                INSTRUMENT_PRINT (log_f, "Instruction: %s\n", INS_Disassemble(ins).c_str());
                INSTRUMENT_PRINT (log_f, "memsize %d, regsize %d\n", memsize, regsize);
                assert(0);
                break;
        }
    }
}
inline void instrument_taint_reg2mem(INS ins, REG reg, int extend) {
	return instrument_taint_reg2mem_slice (ins, reg, extend, 1);
}

void instrument_taint_mem2reg_slice(INS ins, REG dstreg, int extend, int fw_slice)
{
#ifdef FW_SLICE
    if(fw_slice) fw_slice_src_mem (ins, 0);
#endif

    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryWriteSize(ins);
    assert (memsize > 0);
    UINT32 size = (regsize < memsize) ? regsize : memsize;

    if (extend && regsize > memsize) {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_mem2reg_ext_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_MEMORYREAD_EA,
		       IARG_UINT32, get_reg_off (dstreg),
		       IARG_UINT32, size,
		       IARG_END);
    } else {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_mem2reg_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_MEMORYREAD_EA,
		       IARG_UINT32, get_reg_off (dstreg),
		       IARG_UINT32, size,
		       IARG_END);
    }
}

inline void instrument_taint_mem2reg(INS ins, REG dstreg, int extend) {
    return instrument_taint_mem2reg_slice (ins, dstreg, extend, 1);
}

void instrument_taint_mem2mem_slice(INS ins, int extend, int fw_slice)
{
    UINT32 dst_memsize = INS_MemoryWriteSize(ins);
    UINT32 src_memsize = INS_MemoryReadSize(ins);

    assert(dst_memsize == src_memsize);
#ifdef FW_SLICE
    if(fw_slice) fw_slice_src_mem (ins, 1);
#endif

    switch (dst_memsize) {
        case 1:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_b),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
        case 2:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_hw),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       case 4:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_W,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_w),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_W,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       case 8:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_DW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_dw),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_DW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       case 16:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_QW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_qw),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_QW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       default:
            assert(0);
            break;
    }
}
inline void instrument_taint_mem2mem(INS ins, int extend) {
	return instrument_taint_mem2mem_slice (ins, extend, 1);
}

// Mix values in register: implies partial taint -> full taint
// Example: shr eax, 5
void instrument_taint_mix_reg (INS ins, REG reg, int set_flags, int clear_flags)
{
    UINT32 regsize = REG_Size(reg);
    fw_slice_src_reg (ins, reg, regsize, 0);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_mix_reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(reg),
		   IARG_UINT32, regsize,
		   IARG_UINT32, set_flags, 
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

void instrument_taint_mix_regreg2reg (INS ins, REG dstreg, REG srcreg1, REG srcreg2, int set_flags, int clear_flags)
{
    UINT32 dstregsize = REG_Size(dstreg);
    UINT32 srcreg1size = REG_Size(srcreg1);
    UINT32 srcreg2size = REG_Size(srcreg2);
    fw_slice_src_regregreg (ins, dstreg, dstregsize, srcreg1, srcreg1size, srcreg2, srcreg2size);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_mix_regreg2reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(dstreg),
		   IARG_UINT32, dstregsize,
		   IARG_UINT32, get_reg_off(srcreg1),
		   IARG_UINT32, srcreg1size,
		   IARG_UINT32, get_reg_off(srcreg2),
		   IARG_UINT32, srcreg2size,
		   IARG_UINT32, set_flags, 
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

void instrument_taint_add_reg2reg_slice(INS ins, REG dstreg, REG srcreg, int fw_slice, int set_flags, int clear_flags)
{
    UINT32 dst_regsize = REG_Size(dstreg);
    UINT32 src_regsize = REG_Size(srcreg);

#ifdef FW_SLICE
    if(fw_slice) fw_slice_src_regreg (ins, dstreg, dst_regsize, srcreg, src_regsize);
#endif

    UINT32 dst_reg_off = get_reg_off(dstreg);
    UINT32 src_reg_off = get_reg_off(srcreg);
    UINT32 size = (dst_regsize < src_regsize) ? dst_regsize : src_regsize;

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_add_reg2reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, dst_reg_off,
		   IARG_UINT32, src_reg_off,
		   IARG_UINT32, size,
		   IARG_UINT32, set_flags, 
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

inline void instrument_taint_add_reg2reg(INS ins, REG dstreg, REG srcreg, int set_flags, int clear_flags) {
    return instrument_taint_add_reg2reg_slice (ins, dstreg, srcreg, 1, set_flags, clear_flags);
}

void instrument_taint_add_reg2mem_slice(INS ins, REG srcreg, int fw_slice, int set_flags, int clear_flags)
{
    UINT32 regsize = REG_Size(srcreg);
    UINT32 memsize;
    IARG_TYPE mem_ea;

    if (INS_IsMemoryRead(ins)) {
        mem_ea = IARG_MEMORYREAD_EA;
        memsize = INS_MemoryReadSize(ins);
    } else if (INS_IsMemoryWrite(ins)) {
        mem_ea = IARG_MEMORYWRITE_EA;
        memsize = INS_MemoryWriteSize(ins);
    } else {
        assert(0);
    }

#ifdef FW_SLICE
    if (fw_slice) fw_slice_src_regmem (ins, srcreg, regsize, mem_ea, memsize);
#endif

    UINT32 reg_off = get_reg_off(srcreg);
    UINT32 size = (regsize < memsize) ? regsize : memsize;

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_add_reg2mem_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   mem_ea,
		   IARG_UINT32, reg_off,
		   IARG_UINT32, size,
		   IARG_UINT32, set_flags,
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

inline void instrument_taint_add_reg2mem(INS ins, REG srcreg, int set_flags, int clear_flags) {
    return instrument_taint_add_reg2mem_slice (ins, srcreg, 1, set_flags, clear_flags);
}

void instrument_taint_add_mem2reg_slice(INS ins, REG dstreg, int fw_slice, int set_flags, int clear_flags)
{
    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryWriteSize(ins);//TODO?? why not ReadSize
    assert (memsize > 0);

#ifdef FW_SLICE
    if (fw_slice) fw_slice_src_regmem (ins, dstreg, regsize, IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins));
#endif

    UINT32 reg_off = get_reg_off(dstreg);
    UINT32 size = (regsize < memsize) ? regsize : memsize;

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_add_mem2reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_MEMORYREAD_EA,
		   IARG_UINT32, reg_off,
		   IARG_UINT32, size,
		   IARG_UINT32, set_flags,
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

inline void instrument_taint_add_mem2reg(INS ins, REG dstreg, int set_flags, int clear_flags) {
    return instrument_taint_add_mem2reg_slice (ins, dstreg, 1, set_flags, clear_flags);
}

void instrument_taint_add_mem2mem_slice(INS ins, int fw_slice)
{
    UINT32 dst_memsize = INS_MemoryWriteSize(ins);
    UINT32 src_memsize = INS_MemoryReadSize(ins);

    assert(dst_memsize == src_memsize);
#ifdef FW_SLICE
    if(fw_slice) fw_slice_src_memmem (ins, src_memsize, dst_memsize);
#endif

    switch (dst_memsize) {
        case 1:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_b),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
        case 2:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_hw),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       case 4:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_w),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       case 8:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_dw),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       case 16:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_qw),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       default:
            assert(0);
            break;
    }
}
inline void instrument_taint_add_mem2mem(INS ins) {
	return instrument_taint_add_mem2mem_slice (ins, 1);
}

void pred_instrument_taint_reg2reg(INS ins, REG dstreg, REG srcreg, int extend)
{
    UINT32 dst_regsize = REG_Size(dstreg);
    UINT32 src_regsize = REG_Size(srcreg);

#ifdef FW_SLICE
    fw_slice_src_reg (ins, srcreg, src_regsize, 0);
#endif

    if (dstreg == srcreg) return;

    UINT32 dst_reg_off = get_reg_off(dstreg);
    UINT32 src_reg_off = get_reg_off(srcreg);
    UINT32 size = (dst_regsize < src_regsize) ? dst_regsize : src_regsize;

    if (extend && dst_regsize > src_regsize) {
	// JNF: Bug compatible with previous version
	// Not sure this is right for all extension types
	INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
				 AFUNPTR(taint_reg2reg_ext_offset),
				 IARG_FAST_ANALYSIS_CALL,
				 IARG_UINT32, dst_reg_off,
				 IARG_UINT32, src_reg_off,
				 IARG_UINT32, size,
				 IARG_END);
    } else {
	INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
				 AFUNPTR(taint_reg2reg_offset),
				 IARG_FAST_ANALYSIS_CALL,
				 IARG_UINT32, dst_reg_off,
				 IARG_UINT32, src_reg_off,
				 IARG_UINT32, size,
				 IARG_END);
    } 
}

void pred_instrument_taint_reg2mem(INS ins, REG reg, int extend)
{
    int treg = translate_reg((int)reg);
    UINT32 regsize = REG_Size(reg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

#ifdef FW_SLICE
    fw_slice_src_reg (ins, reg, regsize, 1);
#endif
    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_lbreg2mem),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(reg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_UBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_ubreg2mem),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_dwreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        //IARG_UINT32, find_static_address(INS_Address(ins)),
                        IARG_UINT32, TAINT_QWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_qwreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        //IARG_UINT32, find_static_address(INS_Address(ins)),
                        IARG_UINT32, TAINT_QWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
        }
    } else if (regsize < memsize) {
        if (extend) {
            switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2HWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2hwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2WMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_lbreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2DWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2dwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2QWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2qwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2HWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2hwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2WMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2wmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2DWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2dwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2QWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2qwmem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_WREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_wreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_WREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_wreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_DWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_dwreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
            }
        } else {
            switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2HWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2hwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2HWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2hwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2wmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_wreg2dwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_wreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_DWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_dwreg2qwmem),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
            }
        } 
    } else {
        // regsize if greater than mem, just move the lower memsize bits
        // of the register to memory
        switch(memsize) {
            case 1:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_lbreg2mem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_dwreg2mem),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                break;
            default:
                INSTRUMENT_PRINT (log_f, "Instruction: %s\n", INS_Disassemble(ins).c_str());
                INSTRUMENT_PRINT (log_f, "memsize %d, regsize %d\n", memsize, regsize);
                assert(0);
                break;
        }
    }
}

void pred_instrument_taint_memflag2reg (INS ins, uint32_t mask, REG dstreg) { 
	int treg = translate_reg (dstreg);
	UINT32 regsize = REG_Size (dstreg);
	UINT32 memsize = INS_MemoryReadSize (ins);
	assert (regsize == memsize);
	
	INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
			AFUNPTR(taint_memflag2reg),
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, mask,
			IARG_UINT32, treg, 
			IARG_MEMORYREAD_EA,
			IARG_UINT32, regsize,
			IARG_END);
}


void pred_instrument_taint_regflag2reg (INS ins, uint32_t mask, REG dstreg, REG srcreg) {
	UINT32 dst_regsize = REG_Size (dstreg);
	UINT32 src_regsize = REG_Size (srcreg);
	assert (dst_regsize == src_regsize);

	INS_InsertPredicatedCall (ins, IPOINT_BEFORE,
			AFUNPTR(taint_regflag2reg),
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, mask,
			IARG_UINT32, translate_reg(dstreg), 
			IARG_UINT32, translate_reg(srcreg), 
			IARG_UINT32, dst_regsize,
			IARG_END);
}

void pred_instrument_taint_mem2reg(INS ins, REG dstreg, int extend)
{
#ifdef FW_SLICE
    fw_slice_src_mem (ins, 0);
#endif

    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryWriteSize(ins);
    assert (memsize > 0);
    UINT32 size = (regsize < memsize) ? regsize : memsize;

    if (extend && regsize > memsize) {
	INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
				 AFUNPTR(taint_mem2reg_offset),
				 IARG_FAST_ANALYSIS_CALL,
				 IARG_MEMORYREAD_EA,
				 IARG_UINT32, get_reg_off (dstreg),
				 IARG_UINT32, size,
				 IARG_END);
    } else {
	INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
				 AFUNPTR(taint_mem2reg_offset),
				 IARG_FAST_ANALYSIS_CALL,
				 IARG_MEMORYREAD_EA,
				 IARG_UINT32, get_reg_off (dstreg),
				 IARG_UINT32, size,
				 IARG_END);
    }
}

void pred_instrument_taint_add_reg2reg(INS ins, REG dstreg, REG srcreg)
{
    UINT32 dst_regsize = REG_Size(dstreg);
    UINT32 src_regsize = REG_Size(srcreg);

#ifdef FW_SLICE
    fw_slice_src_regreg (ins, dstreg, dst_regsize, srcreg, src_regsize);
#endif

    if (dstreg == srcreg) return;

    UINT32 dst_reg_off = get_reg_off(dstreg);
    UINT32 src_reg_off = get_reg_off(srcreg);
    UINT32 size = (dst_regsize < src_regsize) ? dst_regsize : src_regsize;

    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
			     AFUNPTR(taint_add_reg2reg_offset),
			     IARG_FAST_ANALYSIS_CALL,
			     IARG_UINT32, dst_reg_off,
			     IARG_UINT32, src_reg_off,
			     IARG_UINT32, size,
			     IARG_END);
}

void pred_instrument_taint_add_reg2mem(INS ins, REG srcreg)
{
    UINT32 regsize = REG_Size(srcreg);
    UINT32 memsize;
    IARG_TYPE mem_ea;

    if (INS_IsMemoryRead(ins)) {
        mem_ea = IARG_MEMORYREAD_EA;
        memsize = INS_MemoryReadSize(ins);
    } else if (INS_IsMemoryWrite(ins)) {
        mem_ea = IARG_MEMORYWRITE_EA;
        memsize = INS_MemoryWriteSize(ins);
    } else {
        assert(0);
    }
#ifdef FW_SLICE
    fw_slice_src_regmem(ins, srcreg, regsize, mem_ea, memsize);
#endif

    UINT32 reg_off = get_reg_off(srcreg);
    UINT32 size = (regsize < memsize) ? regsize : memsize;

    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
			     AFUNPTR(taint_add_reg2mem_offset),
			     IARG_FAST_ANALYSIS_CALL,
			     mem_ea,
			     IARG_UINT32, reg_off,
			     IARG_UINT32, size,		   
			     IARG_END);
}

void pred_instrument_taint_add_mem2reg(INS ins, REG dstreg)
{
    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryWriteSize(ins);//TODO?? why not ReadSize
    assert (memsize > 0);

#ifdef FW_SLICE
    fw_slice_src_regmem (ins, dstreg, regsize, IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins));
#endif

    UINT32 reg_off = get_reg_off(dstreg);
    UINT32 size = (regsize < memsize) ? regsize : memsize;

    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
			     AFUNPTR(taint_add_mem2reg_offset),
			     IARG_FAST_ANALYSIS_CALL,
			     IARG_MEMORYREAD_EA,
			     IARG_UINT32, reg_off,
			     IARG_UINT32, size,
			     IARG_END);
}

void instrument_taint_immval2mem(INS ins)
{
    UINT32 addrsize = INS_MemoryWriteSize(ins);
    switch(addrsize) {
                case 1:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvalb2mem),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               case 2:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvalhw2mem),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               case 4:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvalw2mem),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               case 8:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvaldw2mem),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               case 16:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvalqw2mem),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               default:
                    assert(0);
                    break;
            }

}

void instrument_clear_dst(INS ins)
{
    if (INS_IsMemoryWrite(ins)) {
        uint32_t addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE,
                AFUNPTR(clear_mem_taints),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, addrsize,
                IARG_END);
    } else if (INS_OperandIsReg(ins, 0)) {
        REG reg = INS_OperandReg(ins, 0);
        int treg = translate_reg((int)reg);
        INS_InsertCall(ins, IPOINT_BEFORE,
                AFUNPTR(clear_reg),
                IARG_UINT32, treg,
                IARG_UINT32, REG_Size(reg),
                IARG_END);
    }
}

void instrument_clear_reg(INS ins, REG reg)
{
    int treg = translate_reg((int)reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(clear_reg),
            IARG_UINT32, treg,
            IARG_UINT32, REG_Size(reg),
            IARG_END);
}

void instrument_clear_flag_slice (INS ins, uint32_t mask, int fw_slice) { 
    if (mask != 0) {
#ifdef FW_SLICE
	if (fw_slice) fw_slice_src_flag (ins, mask);
#endif
	INS_InsertCall (ins, IPOINT_BEFORE,
			AFUNPTR(clear_flag_taint),
			IARG_FAST_ANALYSIS_CALL, 
			IARG_UINT32, mask,
			IARG_END);
    }
}

inline void instrument_clear_flag (INS ins, uint32_t mask) { 
    return instrument_clear_flag_slice (ins, mask, 1);
}

void instrument_clear_mem_src (INS ins) {
	uint32_t addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE,
                AFUNPTR(clear_mem_taints),
                IARG_MEMORYREAD_EA,
                IARG_UINT32, addrsize,
                IARG_END);
}

static inline ADDRINT computeEA(ADDRINT firstEA, UINT eflags,
                                 UINT32 count, UINT32 op_size)
{
    if (eflags & DF_MASK) {
        ADDRINT size = op_size * count;
        return firstEA - size + op_size;
    } 
    return firstEA;
}

//TODO: the index tool doesn't merge taints from esi and edi
void taint_whole_mem2mem(ADDRINT ip, ADDRINT src_mem_loc, ADDRINT dst_mem_loc,
                         ADDRINT eflags, uint32_t count_reg, ADDRINT counts, UINT32 op_size, uint32_t check_zf)
{
    int size = (int)(counts * op_size);
    if (!size) return;
    assert (size > 0);
    ADDRINT ea_src_mem_loc = computeEA(src_mem_loc, eflags, counts, op_size);
    ADDRINT ea_dst_mem_loc = computeEA(dst_mem_loc, eflags, counts, op_size);
    //fprintf (stderr, "taint_whole_mem2mem: src %x (%x), dst %x (%x), size %u\n", src_mem_loc, ea_src_mem_loc, dst_mem_loc, ea_dst_mem_loc, op_size);
    if (count_reg) {
	    assert (count_reg == 9); //ecx
	    taint_mem2mem(ea_src_mem_loc, ea_dst_mem_loc, size);
	    taint_add_reg2mem_offset (ea_dst_mem_loc, LEVEL_BASE::REG_ECX*REG_SIZE, 4, 0, 0);
    } else { 
	    taint_mem2mem(ea_src_mem_loc, ea_dst_mem_loc, size);
    }
#ifdef LINKAGE_DATA_OFFSET
    //not handled
    //we may need to taint esi and edi probably in this case
    if (is_reg_arg_tainted (LEVEL_BASE::REG_ESI, 4, 0) || is_reg_arg_tainted(LEVEL_BASE::REG_EDI, 4, 0))
	    fprintf (stderr, "[NOT handled] index tool for move_string\n");
#endif
    taint_string_operation (ip);
    if (check_zf) taint_rep (ZF_FLAG, ip);
}

void taint_whole_memmem2flag(ADDRINT mem_loc1, ADDRINT mem_loc2,
                         ADDRINT eflags, uint32_t count_reg, ADDRINT counts, UINT32 op_size, uint32_t check_zf, uint32_t mask, ADDRINT ip)
{
    int size = (int)(counts * op_size);
    if (!size) return;
    assert (size > 0);
    ADDRINT ea_mem_loc1 = computeEA(mem_loc1, eflags, counts, op_size);
    ADDRINT ea_mem_loc2 = computeEA(mem_loc2, eflags, counts, op_size);

    if (count_reg) {
	    assert (count_reg == 9); //ecx
	    taint_memmem2flag(ea_mem_loc1, ea_mem_loc2, mask, size);
	    taint_add_reg2flag_offset (LEVEL_BASE::REG_ECX*REG_SIZE, 4, mask);
    } else { 
	    taint_memmem2flag(ea_mem_loc1, ea_mem_loc2, mask, size);
    }
#ifdef LINKAGE_DATA_OFFSET
    //not handled
    //we may need to taint esi and edi probably in this case
    if (is_reg_arg_tainted (LEVEL_BASE::REG_ESI, 4, 0) || is_reg_arg_tainted(LEVEL_BASE::REG_EDI, 4, 0))
	    fprintf (stderr, "[NOT handled] index tool for compare_string\n");
#endif
    taint_string_operation (ip);
    if (check_zf) taint_rep (ZF_FLAG, ip);
}

void taint_whole_regmem2flag(uint32_t reg, ADDRINT mem_loc,
                         ADDRINT eflags, uint32_t count_reg, ADDRINT counts, UINT32 op_size, UINT32 reg_size, uint32_t check_zf, uint32_t mask, ADDRINT ip)
{
    //for repz, we cannot infer the actual number of executions from the count register
    //otherwise, we'll overtaint
    if (check_zf) { 
        mem_loc = current_thread->repz_src_mem_loc;
        counts = current_thread->repz_counts;
    }
    int size = (int)(counts * op_size);
    if (size <= 0) { 
	    if (size < 0)
	    	fprintf (stderr, "taint_whole_regmem2flag : size < 0, size %d, counts %d, op_size %u\n", size, (int) counts, op_size);
	    return;
    }
    ADDRINT ea_mem_loc = computeEA(mem_loc, eflags, counts, op_size);
    //fprintf (stderr, "taint_whole_regmem2flag: size %d, ip %x, ea_mem %x , original %x, char %s\n", size, ip, ea_mem_loc, mem_loc, (char*) mem_loc);
    if (count_reg) { //for rep and repz
    	taint_regmem2flag_with_different_size(ea_mem_loc, reg, mask, size, reg_size);
	taint_add_reg2flag_offset (LEVEL_BASE::REG_ECX*REG_SIZE, 4, mask);
    } else { //no rep
    	taint_regmem2flag_with_different_size(ea_mem_loc, reg, mask, size, reg_size);
    }
#ifdef LINKAGE_DATA_OFFSET
    //not handled
    //we may need to taint edi probably in this case
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EDI, 4, 0))
	    fprintf (stderr, "[NOT handled] index tool for scan_string\n");
#endif
    taint_string_operation (ip);
    if (check_zf) taint_rep(ZF_FLAG, ip);
}

void taint_whole_reg2mem(ADDRINT ip, ADDRINT dst_mem_loc,
			   uint32_t reg,
			   uint32_t reg_size,
			   ADDRINT eflags,
			   uint32_t count_reg,
			   ADDRINT counts,
			   UINT32 op_size, uint32_t check_zf)
{
    ADDRINT effective_addr = computeEA(dst_mem_loc, eflags, counts, op_size);
    int size = (int) (counts*op_size);
    if (size <= 0) { 
	    if (size < 0) 
	    	fprintf (stderr, "taint_whole_reg2mem : size < 0, size %d, counts %d, op_size %u\n", size, (int) counts, op_size);
	    return;
    }
    taint_rep_reg2mem (effective_addr, reg, reg_size, size);
#ifdef LINKAGE_DATA_OFFSET
    //not handled
    //we may need to taint edi probably in this case
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EDI, 4, 0))
	    fprintf (stderr, "[NOT handled] index tool for store_string\n");
#endif
    taint_string_operation (ip);
    if (check_zf) taint_rep(ZF_FLAG, ip);
}

//TODO: for repz, we probably need the exact number of iterations, which is supported with scan_string
void instrument_move_string(INS ins)
{
    UINT32 opw = INS_OperandWidth(ins, 0);
    UINT32 size = opw / 8;
    if (INS_RepPrefix(ins) || INS_RepnePrefix(ins)) {
#ifdef FW_SLICE
        fw_slice_src_string(ins, 1, 1);
#endif
        assert(size == INS_MemoryOperandSize(ins, 0));
        INS_InsertIfCall (ins, IPOINT_BEFORE, (AFUNPTR)returnArg,
                IARG_FIRST_REP_ITERATION,
                IARG_END);
	INS_InsertThenCall (ins, IPOINT_BEFORE, (AFUNPTR)taint_whole_mem2mem,
			IARG_ADDRINT, INS_Address(ins),
			IARG_MEMORYREAD_EA,
			IARG_MEMORYWRITE_EA,
			IARG_REG_VALUE, REG_EFLAGS,
			IARG_UINT32, INS_RepCountRegister(ins),
			IARG_REG_VALUE, INS_RepCountRegister(ins),
			IARG_UINT32, INS_MemoryOperandSize(ins, 0),
			IARG_UINT32, INS_RepnePrefix(ins),
			IARG_END);
    } else {
        assert(size == INS_MemoryOperandSize(ins, 0));
        if (size > 0) {
#ifdef FW_SLICE
            fw_slice_src_string (ins, 0, 1);
#endif
	    INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)taint_whole_mem2mem,
			    IARG_ADDRINT, INS_Address(ins),
			    IARG_MEMORYREAD_EA,
			    IARG_MEMORYWRITE_EA,
			    IARG_REG_VALUE, REG_EFLAGS,
			    IARG_UINT32, 0,
			    IARG_UINT32, 1,
			    IARG_UINT32, INS_MemoryOperandSize(ins, 0),
			    IARG_UINT32, INS_RepnePrefix(ins),
			    IARG_END);
	}
    }
}

//TODO: for repz, we probably need the exact number of iterations, which is supported with scan_string
void instrument_compare_string(INS ins, uint32_t mask)
{
	UINT32 opw = INS_OperandWidth(ins, 0);
	UINT32 size = opw / 8;

	assert(size == INS_MemoryOperandSize(ins, 0));
	INSTRUMENT_PRINT (log_f, "instrument_cmps: size %u\n", size);

	if (INS_RepPrefix(ins) || INS_RepnePrefix(ins)) {
#ifdef FW_SLICE
		fw_slice_src_stringstring (ins, 1);
#endif
		INS_InsertIfCall (ins, IPOINT_BEFORE, (AFUNPTR)returnArg,
				IARG_FIRST_REP_ITERATION,
				IARG_END);
		INS_InsertThenCall (ins, IPOINT_BEFORE, (AFUNPTR)taint_whole_memmem2flag,
				IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD2_EA,
				IARG_REG_VALUE, REG_EFLAGS, 
				IARG_UINT32, INS_RepCountRegister(ins),
				IARG_REG_VALUE, INS_RepCountRegister(ins),
				IARG_UINT32, INS_MemoryOperandSize(ins, 0),
				IARG_UINT32, INS_RepnePrefix(ins),
				IARG_UINT32, mask,
				IARG_ADDRINT, INS_Address(ins),
				IARG_END);
	} else {
#ifdef FW_SLICE
		fw_slice_src_stringstring (ins, 0);
#endif
		INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)taint_whole_memmem2flag,
				IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD2_EA,
				IARG_REG_VALUE, REG_EFLAGS, 
				IARG_UINT32, 0, 
				IARG_UINT32, 1,
				IARG_UINT32, INS_MemoryOperandSize(ins, 0),
				IARG_UINT32, INS_RepnePrefix(ins),
				IARG_UINT32, mask,
				IARG_ADDRINT, INS_Address(ins),
				IARG_END);

	}
}

//we need this function mainly because we cannot get the memory location with IPONT_AFTER insertion
TAINTSIGN repz_execute_init (u_long dst_mem_loc, u_long src_mem_loc) { 
    current_thread->repz_counts = 0;
    current_thread->repz_src_mem_loc = src_mem_loc;
    current_thread->repz_dst_mem_loc = dst_mem_loc;
    //fprintf (stderr, "repz_execute_init %lx %lx\n", dst_mem_loc, src_mem_loc);
}

//return true when this is the last execution
TAINTINT repz_execute_count (uint32_t flags) { 
    int zf_set = flags & ZF_MASK;
    current_thread->repz_counts ++;
    //fprintf (stderr, "repz_execute_count: %u %u\n", current_thread->repz_counts, zf_set);
    if (zf_set) 
        return 1;
    return 0;
}

void instrument_scan_string(INS ins, uint32_t mask)
{
	UINT32 opw = INS_OperandWidth(ins, 0);
	UINT32 size = opw / 8;

	assert(size == INS_MemoryOperandSize(ins, 0));

	if (INS_RepPrefix(ins)) {
            // The number of iterations is determined solely by the count register value,
            // therefore we can log all we need at the start of each REP "loop", and skip the
            // instrumentation on all the other iterations of the REP prefixed operation. Simply use
            // IF/THEN instrumentation which tests IARG_FIRST_REP_ITERATION.
#ifdef FW_SLICE
            fw_slice_src_stringreg (ins, 1, 0);
#endif
            INS_InsertIfCall (ins, IPOINT_AFTER, (AFUNPTR)returnArg,
                    IARG_FIRST_REP_ITERATION,
                    IARG_END);
            INS_InsertThenCall (ins, IPOINT_AFTER, (AFUNPTR)taint_whole_regmem2flag,
                    IARG_UINT32, translate_reg(LEVEL_BASE::REG_EAX),
                    IARG_MEMORYREAD_EA,
                    IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_UINT32, INS_RepCountRegister(ins),
                    IARG_REG_VALUE, INS_RepCountRegister(ins),
                    IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                    IARG_UINT32, size, 
                    IARG_UINT32, INS_RepnePrefix(ins),
                    IARG_UINT32, mask,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_END);
        } else if (INS_RepnePrefix(ins)) {
            // We have no smart way to lessen the number of
            // instrumentation calls because we can't determine when
            // the conditional instruction will finish.  So we just
            // let the instruction execute and have our
            // instrumentation be called on each iteration.  This is
            // the simplest way of handling REP prefixed instructions, where
            // each iteration appears as a separate instruction, and
            // is independently instrumented.
#ifdef FW_SLICE
            fw_slice_src_stringreg (ins, 0, 1);
#endif
            //first iteration
            INS_InsertIfCall (ins, IPOINT_BEFORE, (AFUNPTR)returnArg,
                    IARG_FIRST_REP_ITERATION,
                    IARG_END);
            INS_InsertThenCall (ins, IPOINT_BEFORE, (AFUNPTR) repz_execute_init,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_ADDRINT, 0,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
            //all iterations, including first one
            INS_InsertIfCall (ins, IPOINT_AFTER, (AFUNPTR)repz_execute_count,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_REG_VALUE, REG_EFLAGS,
                    IARG_END);
            INS_InsertThenCall (ins, IPOINT_AFTER, (AFUNPTR)taint_whole_regmem2flag,
                    IARG_UINT32, translate_reg(LEVEL_BASE::REG_EAX),
                    IARG_ADDRINT, 0,
                    IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_UINT32, INS_RepCountRegister(ins),
                    IARG_UINT32, 0, 
                    IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                    IARG_UINT32, size, 
                    IARG_UINT32, INS_RepnePrefix(ins),
                    IARG_UINT32, mask,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_END);
        } else {
#ifdef FW_SLICE
            fw_slice_src_stringreg (ins, 0, 0);
#endif
            INS_InsertThenCall (ins, IPOINT_BEFORE, (AFUNPTR)taint_whole_regmem2flag,
                    IARG_UINT32, translate_reg(LEVEL_BASE::REG_EAX),
                    IARG_MEMORYREAD_EA,
                    IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_UINT32, 0,
                    IARG_UINT32, 1,
                    IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                    IARG_UINT32, size, 
                    IARG_UINT32, INS_RepnePrefix(ins),
                    IARG_UINT32, mask,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_END);
        }
}

TAINTSIGN pcmpestri_reg_mem (ADDRINT ip, char* ins_str, uint32_t reg1, PIN_REGISTER* reg1content, u_long mem_loc2, uint32_t size1, uint32_t size2) { 
	char str1[17] = {0};
	char str2[17] = {0};
	if (reg1content) strncpy (str1, (char*) reg1content, 16);
	if (mem_loc2) strncpy (str2, (char*) mem_loc2, 16);

	//fprintf (stderr, "pcmpestri reg1 %s, mem2 %s, mem2_addr %lx, ip %x, size %u %u\n", str1, str2, mem_loc2, ip, size1, size2);
#ifdef FW_SLICE
        fw_slice_pcmpistri_reg_mem (ip, ins_str, reg1, mem_loc2, size1, size2, (char*)reg1content);
#endif
	taint_regmem2flag_pcmpxstri (reg1, mem_loc2, 0, size1, size2, 0);
}
TAINTSIGN pcmpestri_reg_reg (ADDRINT ip, char* ins_str, uint32_t reg1, PIN_REGISTER* reg1content, uint32_t reg2, PIN_REGISTER* reg2content, uint32_t size1, uint32_t size2) {
	char str1[17] = {0};
	char str2[17] = {0};
	if (reg1content) strncpy (str1, (char*) reg1content, 16);
	if (reg2content) strncpy (str2, (char*) reg2content, 16);
	//fprintf (stderr, "pcmpestri reg1 %s, reg2 %s, ip %x, size %u %u\n", str1, str2, ip, size1, size2);
#ifdef FW_SLICE
        fw_slice_pcmpistri_reg_reg (ip, ins_str, reg1, reg2, size1, size2, (char*)reg1content, (char*)reg2content);
#endif
	taint_regmem2flag_pcmpxstri (reg1, 0, reg2, size1, size2, 0);
}

//INPUT: EAX, EDX, two operands
//OUTPUT: ECX, FLAGS
void instrument_pcmpestri (INS ins) { 
	int op1reg;
	int op2mem;
	int op2reg;
	int reg1;
	int reg2;

	op1reg = INS_OperandIsReg(ins, 0);
	op2mem = INS_OperandIsMemory(ins, 1);
	op2reg = INS_OperandIsReg(ins, 1);

	INSTRUMENT_PRINT(log_f, "instrument_pcmpestri, %s, reg1 %u, addr %x\n", INS_Disassemble(ins).c_str(), INS_OperandReg(ins, 0), INS_Address(ins));
	if (op1reg && op2mem) { 
		reg1 = translate_reg (INS_OperandReg (ins, 0));
                char* str = get_copy_of_disasm (ins);
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(pcmpestri_reg_mem),
				IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_PTR, str,
				IARG_UINT32, reg1, 
				IARG_REG_REFERENCE, INS_OperandReg(ins, 0), 
				IARG_MEMORYREAD_EA,
				IARG_REG_VALUE, LEVEL_BASE::REG_EAX, 
				IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 
				IARG_END);
                put_copy_of_disasm (str);
	} else if (op1reg && op2reg) { 
		reg1 = translate_reg (INS_OperandReg (ins, 0));
		reg2 = translate_reg (INS_OperandReg (ins, 1));
                char* str = get_copy_of_disasm (ins);
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(pcmpestri_reg_reg),
				IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_PTR, str,
				IARG_UINT32, reg1, 
				IARG_REG_REFERENCE, INS_OperandReg(ins, 0), 
				IARG_UINT32, reg2, 
				IARG_REG_REFERENCE, INS_OperandReg(ins, 1), 
				IARG_REG_VALUE, LEVEL_BASE::REG_EAX, 
				IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 
				IARG_END);
                put_copy_of_disasm (str);
	} else { 
		ERROR_PRINT (stderr, "[BUG] unrecognized instruction: pcmpestri\n");
	}
}

TAINTSIGN pcmpistri_reg_mem (ADDRINT ip, char* ins_str, uint32_t reg1, PIN_REGISTER* reg1content, u_long mem_loc2) { 
	char str1[17] = {0};
	char str2[17] = {0};
	uint32_t size1;
	uint32_t size2;
	if (reg1content) strncpy (str1, (char*) reg1content, 16);
	if (mem_loc2) strncpy (str2, (char*) mem_loc2, 16);
	size1 = strlen (str1);
	size2 = strlen (str2);
        if (size1 < 16) ++size1;
        if (size2 < 16) ++size2; //NULL terminal

	//fprintf (stderr, "pcmpistri reg1 %s, mem2 %s, mem2_addr %lx, ip %x, size %u %u\n", str1, str2, mem_loc2, ip, size1, size2);
#ifdef FW_SLICE
        fw_slice_pcmpistri_reg_mem (ip, ins_str, reg1, mem_loc2, size1, size2, (char*) reg1content);
#endif
	taint_regmem2flag_pcmpxstri (reg1, mem_loc2, 0, size1, size2, 1);
}

TAINTSIGN pcmpistri_reg_reg (ADDRINT ip, char* ins_str, uint32_t reg1, PIN_REGISTER* reg1content, uint32_t reg2, PIN_REGISTER* reg2content) {
	char str1[17] = {0};
	char str2[17] = {0};
	uint32_t size1;
	uint32_t size2;
	if (reg1content) strncpy (str1, (char*) reg1content, 16);
	if (reg2content) strncpy (str2, (char*) reg2content, 16);
	size1 = strlen (str1);
	size2 = strlen (str2);
	if (size1 < 16) size1++; // Account for NULL terminal of string since this affects operation
	if (size2 < 16) size2++;
	//fprintf (stderr, "pcmpistri reg1 %s, reg2 %s, ip %x, size %u %u\n", str1, str2, ip, size1, size2);
#ifdef FW_SLICE
	fw_slice_pcmpistri_reg_reg (ip, ins_str, reg1, reg2, size1, size2, (char *) reg1content, (char *) reg2content);
#endif
	taint_regmem2flag_pcmpxstri (reg1, 0, reg2, size1, size2, 1);
}

//INPUT: EAX, EDX, two operands
//OUTPUT: ECX, FLAGS
void instrument_pcmpistri (INS ins) { 
	int op1reg;
	int op2mem;
	int op2reg;
	int reg1;
	int reg2;

	op1reg = INS_OperandIsReg(ins, 0);
	op2mem = INS_OperandIsMemory(ins, 1);
	op2reg = INS_OperandIsReg(ins, 1);

	INSTRUMENT_PRINT(log_f, "instrument_pcmpistri, %s, reg1 %u, addr %x\n", INS_Disassemble(ins).c_str(), INS_OperandReg(ins, 0), INS_Address(ins));
	if (op1reg && op2mem) { 
		char* str = get_copy_of_disasm (ins);
		reg1 = translate_reg (INS_OperandReg (ins, 0));
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(pcmpistri_reg_mem),
				IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_PTR, str,
				IARG_UINT32, reg1, 
				IARG_REG_REFERENCE, INS_OperandReg(ins, 0), 
				IARG_MEMORYREAD_EA,
				IARG_END);
		put_copy_of_disasm (str);
	} else if (op1reg && op2reg) { 
		REG r1 = INS_OperandReg(ins, 0);
		REG r2 = INS_OperandReg(ins, 1);
		reg1 = translate_reg (r1);
		reg2 = translate_reg (r2);
		char* str = get_copy_of_disasm (ins);
		INS_InsertCall(ins, IPOINT_BEFORE,
			       AFUNPTR(pcmpistri_reg_reg),
			       IARG_FAST_ANALYSIS_CALL,
			       IARG_ADDRINT, INS_Address(ins),
			       IARG_PTR, str,
			       IARG_UINT32, reg1, 
			       IARG_REG_REFERENCE, INS_OperandReg(ins, 0), 
			       IARG_UINT32, reg2, 
			       IARG_REG_REFERENCE, INS_OperandReg(ins, 1), 
			       IARG_END);
		put_copy_of_disasm (str);
	} else { 
		ERROR_PRINT (stderr, "[BUG] unrecognized instruction: pcmpistri\n");
	}
}


//TODO: for repz, we probably need the exact number of iterations, which is supported with scan_string
void instrument_store_string(INS ins)
{
    UINT32 opw = INS_OperandWidth(ins, 0);
    UINT32 size = opw / 8;

    assert(INS_OperandIsMemory(ins, 0));
    assert(size == INS_MemoryOperandSize(ins, 0));
#ifdef FW_SLICE
    fw_slice_src_reg (ins, LEVEL_BASE::REG_EAX, size, 1);
#endif

    // fprintf(stderr, "store string size %d\n", size);
    if (INS_RepPrefix(ins) || INS_RepnePrefix(ins)) {
	    INS_InsertIfCall (ins, IPOINT_BEFORE, (AFUNPTR)returnArg,
			    IARG_FIRST_REP_ITERATION,
			    IARG_END);
	    INS_InsertThenCall (ins, IPOINT_BEFORE,
			    (AFUNPTR)taint_whole_reg2mem,
			    IARG_ADDRINT, INS_Address(ins),
			    IARG_MEMORYWRITE_EA,
			    IARG_UINT32, LEVEL_BASE::REG_EAX,
			    IARG_UINT32, size, 
			    IARG_REG_VALUE, REG_EFLAGS,
			    IARG_UINT32, translate_reg(INS_RepCountRegister(ins)),
			    IARG_REG_VALUE, INS_RepCountRegister(ins),
			    IARG_UINT32, INS_MemoryOperandSize(ins, 0),
			    IARG_UINT32, INS_RepnePrefix(ins),
			    IARG_END);
    } else {
	    INS_InsertIfCall (ins, IPOINT_BEFORE, (AFUNPTR)returnArg,
			    IARG_FIRST_REP_ITERATION,
			    IARG_END);
	    INS_InsertThenCall (ins, IPOINT_BEFORE,
			    (AFUNPTR)taint_whole_reg2mem,
			    IARG_ADDRINT, INS_Address(ins),
			    IARG_MEMORYWRITE_EA,
			    IARG_UINT32, LEVEL_BASE::REG_EAX,
			    IARG_UINT32, size, 
			    IARG_REG_VALUE, REG_EFLAGS,
			    IARG_UINT32, 0,
			    IARG_UINT32, 1,
			    IARG_UINT32, INS_MemoryOperandSize(ins, 0),
			    IARG_UINT32, INS_RepnePrefix(ins),
			    IARG_END);
    }
}

//TODO: for repz, we probably need the exact number of iterations, which is supported with scan_string
void instrument_load_string(INS ins)
{
    assert(INS_OperandIsReg(ins, 0));
    assert(INS_OperandIsMemory(ins, 1));

    if (INS_RepPrefix(ins) || INS_RepnePrefix(ins)) {
        INSTRUMENT_PRINT (log_f, "[WARN] a rep'ed load string\n");
        INS_InsertIfCall (ins, IPOINT_BEFORE, (AFUNPTR)returnArg,
                IARG_FIRST_REP_ITERATION,
                IARG_END);
        /* Even if it's rep'ed, we run this for every rep iteration.
         *  Because we really just want the last rep iteration.
         * */

	// JNF - I don't get this, but these are equivalent to what was here before
	INS_InsertCall (ins, IPOINT_BEFORE,
			(AFUNPTR)taint_mem2reg_offset,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
                        IARG_UINT32, get_reg_off(LEVEL_BASE::REG_EAX),
			IARG_UINT32, INS_MemoryOperandSize(ins, 0),
			IARG_END);
    } else {
        /* Ugh we don't know the address until runtime, so this is the
         * best we can do at instrumentation time. */

	INS_InsertCall (ins, IPOINT_BEFORE,
			(AFUNPTR)taint_mem2reg_offset,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
                        IARG_UINT32, get_reg_off(LEVEL_BASE::REG_EAX),
			IARG_UINT32, INS_MemoryOperandSize(ins, 0),
			IARG_END);
    }
}

void instrument_xchg (INS ins)
{
    int op1mem, op2mem, op1reg, op2reg;
    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);

    if (op1reg && op2reg) {
        REG reg1, reg2;

        reg1 = INS_OperandReg(ins, 0);
        reg2 = INS_OperandReg(ins, 1);
        INSTRUMENT_PRINT(log_f, "op1 and op2 of xchg are registers: %u %u\n", reg1, reg2);
        if(!REG_valid(reg1) || !REG_valid(reg2)) {
            return;
        }
        assert(REG_Size(reg1) == REG_Size(reg2));
        UINT32 regsize1 = REG_Size(reg1);
        UINT32 regsize2 = REG_Size(reg2);
#ifdef FW_SLICE
	fw_slice_src_regreg (ins, reg1, regsize1, reg2, regsize2);
#endif
        if(reg1 == reg2) return;
        UINT32 reg1_off = get_reg_off (reg1);
        UINT32 reg2_off = get_reg_off (reg2);

        INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_xchg_reg2reg_offset),
                IARG_FAST_ANALYSIS_CALL,
                IARG_UINT32, reg1_off,
                IARG_UINT32, reg2_off,
                IARG_UINT32, regsize1,
                IARG_END);
    } else if (op1reg && op2mem) {
        REG reg;
        int treg;
        UINT32 addrsize;

        addrsize = INS_MemoryReadSize(ins);
        reg = INS_OperandReg(ins, 0);
        treg = translate_reg(reg);
        if (!REG_valid(reg)) {
            return;
        }
        assert(addrsize == REG_Size(reg));
#ifdef FW_SLICE
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYWRITE_EA, addrsize);
#endif

        switch(addrsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_xchg_bmem2lbreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                } else {
                    assert(REG_is_Upper8(reg));
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_xchg_bmem2ubreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                }
                break;
            case 2:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_hwmem2hwreg),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_wmem2wreg),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 8:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_dwmem2dwreg),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else if (op1mem && op2reg) {
        REG reg;
        int treg;
        UINT32 addrsize;

        addrsize = INS_MemoryReadSize(ins);
        reg = INS_OperandReg(ins, 1);
        treg = translate_reg(reg);
        if (!REG_valid(reg)) {
            return;
        }
        assert(addrsize == REG_Size(reg));
#ifdef FW_SLICE
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYWRITE_EA, addrsize);
#endif

        // Note: xchg mem2reg and reg2mem are the same
        switch(addrsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_xchg_bmem2lbreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                } else {
                    assert(REG_is_Upper8(reg));
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_xchg_bmem2ubreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                }
                break;
            case 2:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_hwmem2hwreg),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_wmem2wreg),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 8:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_dwmem2dwreg),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else {
        ERROR_PRINT (stderr, "Unknown combination of xchg\n");
        assert(0);
    }
}

void instrument_bswap (INS ins)
{
    int treg;
    assert(INS_OperandIsReg(ins, 0));
    assert(REG_Size(INS_OperandReg(ins, 0)) == 4);

    treg = translate_reg(INS_OperandReg(ins, 0));
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(reverse_reg_taint),
            IARG_UINT32, treg,
            IARG_UINT32, 4,
            IARG_END);
}

void instrument_cmpxchg (INS ins)
{
	REG srcreg = INS_OperandReg (ins, 1);
	uint32_t size = REG_Size (srcreg);
	
	if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) { 
#ifdef FW_SLICE
		//EAX with size can also represent AX/AL
		fw_slice_src_regmem (ins, LEVEL_BASE::REG_EAX, size, IARG_MEMORYREAD_EA, size);
#endif
		INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_cmpxchg_mem),
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, srcreg,
				IARG_MEMORYREAD_EA,
				IARG_UINT32, translate_reg(srcreg),
				IARG_UINT32, size,
				IARG_END);
	} else { 
		REG dstreg = INS_OperandReg (ins, 0);
#ifdef FW_SLICE
		fw_slice_src_regreg (ins, dstreg, size, LEVEL_BASE::REG_EAX, size);
#endif
		INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_cmpxchg_reg),
				IARG_FAST_ANALYSIS_CALL,
				IARG_REG_VALUE, dstreg,
				IARG_UINT32, translate_reg(dstreg),
				IARG_UINT32, translate_reg(srcreg),
				IARG_UINT32, size,
				IARG_END);
	}
}

void instrument_mov (INS ins) 
{
    int ismemread = 0, ismemwrite = 0;
    int immval = 0;
    REG reg = REG_INVALID();
    REG dstreg = REG_INVALID();
    int treg = (int)REG_INVALID();

    if(INS_IsMemoryRead(ins)) {
        ismemread = 1;
        reg = INS_OperandReg(ins, 0);
        if(!REG_valid(reg)) return;
    } else if(INS_IsMemoryWrite(ins)) {
        ismemwrite = 1;
        if(INS_OperandIsReg(ins, 1)) {
            reg = INS_OperandReg(ins, 1);
            if(!REG_valid(reg)) return;
        } else {
            if(!INS_OperandIsImmediate(ins, 1)) return;
            //must be an immediate value
            immval = 1;
        }
    } else {
        if(!(INS_OperandIsReg(ins, 0))) return;
        dstreg = INS_OperandReg(ins, 0);
        if(!REG_valid(dstreg)) return;

        if(INS_OperandIsReg(ins, 1)) {
            reg = INS_OperandReg(ins, 1);
            if(!REG_valid(reg)) return;
        } else {
            //sometimes get an offset into video memory
            if(!INS_OperandIsImmediate(ins, 1)) return;
            //must be an immediate value
            immval = 1;
        }
    }

    //2 (src) operand is memory...destination must be a register
    if(ismemread) {
        // REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        // REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        // ADDRDELTA displacement = INS_MemoryDisplacement(ins);

        assert(INS_IsMemoryRead(ins) == 1);

        REG dst_reg = INS_OperandReg(ins, 0);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
		//addressing mode: base+index+offset
/*
   +-------------+----------------------------+-----------------------------+
    | Mode        | Intel                      | AT&T                        |
    +-------------+----------------------------+-----------------------------+
    | Immediate   | MOV EAX, [0100]            | movl           0x0100, %eax |
    | Register    | MOV EAX, [ESI]             | movl           (%esi), %eax |
    | Reg + Off   | MOV EAX, [EBP-8]           | movl         -8(%ebp), %eax |
    | R*W + Off   | MOV EAX, [EBX*4 + 0100]    | movl   0x100(,%ebx,4), %eax |
    | B + R*W + O | MOV EAX, [EDX + EBX*4 + 8] | movl 0x8(%edx,%ebx,4), %eax |
    +-------------+----------------------------+-----------------------------+
*/

        fw_slice_src_regregmem_mov (ins, base_reg, index_reg, IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins));
	instrument_taint_mem2reg_slice (ins, dst_reg, 0, 0);
    } else if(ismemwrite) {
        if(!immval) {
            //mov register to memory location
            REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
            REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
            fw_slice_src_regregreg_mov (ins, reg, base_reg, index_reg);
	    instrument_taint_reg2mem_slice(ins, reg, 0, 0);
        } else {
            //move immediate to memory location
            instrument_taint_immval2mem(ins);
        }
    } else {
        if(immval) {
            treg = translate_reg((int)dstreg);
            //mov immediate value into register
            switch(REG_Size(dstreg)) {
                case 1:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2lbreg),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 2:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2hwreg),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 4:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2wreg),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 8:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2dwreg),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 16:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2qwreg),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_UINT32, treg, IARG_END);
                    break;
               default:
                    assert(0);
                    break;
            }
        } else {
            //mov one reg val into another
            if (REG_is_seg(reg) || REG_is_seg(dstreg)) {
                // ignore segment registers for now
                return;
            }
            if (REG_Size(reg) != REG_Size(dstreg)) {

                fprintf(stderr, "%#x [mov] %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
                fprintf(stderr, "%#x instrument mov is src reg: %d into dst reg: %d\n", INS_Address(ins), reg, dstreg); 
            }
            assert(REG_Size(reg) == REG_Size(dstreg));
            instrument_taint_reg2reg(ins, dstreg, reg, 0);
        }
    }
}

/* 
 * Instrument a move that extends if the dst is smaller than src.
 *
 * Dst: register/memory
 * Src: register/memory
 * */
void instrument_movx (INS ins)
{
    int op1mem, op2mem, op1reg, op2reg;
    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);

    INSTRUMENT_PRINT (log_f, "[movx] %#x %s\n",
            INS_Address(ins),
            INS_Disassemble(ins).c_str());

    if (op1reg && op2reg) {
        REG dst_reg = INS_OperandReg(ins, 0);
        REG src_reg = INS_OperandReg(ins, 1);

        INSTRUMENT_PRINT(log_f, "instrument movx address %#x is src reg: %d into dst reg: %d\n", INS_Address(ins), src_reg, dst_reg); 
        instrument_taint_reg2reg(ins, dst_reg, src_reg, 1);
    } else if (op1reg && op2mem) {
        assert(INS_IsMemoryRead(ins) == 1);
        REG dst_reg = INS_OperandReg(ins, 0);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);

        fw_slice_src_regregmem_mov (ins, base_reg, index_reg, IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins));
	instrument_taint_mem2reg_slice(ins, dst_reg, 1, 0);
    } else if (op1mem && op2reg) {
        assert(INS_IsMemoryWrite(ins) == 1);
        REG src_reg = INS_OperandReg(ins, 1);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
        fw_slice_src_regregreg_mov (ins, src_reg, base_reg, index_reg);
        instrument_taint_reg2mem_slice(ins, src_reg, 1, 0);
    } else if (op1mem && op2mem) {
        instrument_taint_mem2mem(ins, 1);
    } else {
        ERROR_PRINT(stderr, "ERROR: second operand of MOVZX/MOVSX is not reg or memory\n");
    }
} 

//doesn't handle upper 8
TAINTSIGN taint_cmov_reg2reg (uint32_t mask, uint32_t dst_reg, uint32_t src_reg, uint32_t size, BOOL executed) { 
    if (executed) {
        taint_regflag2reg (mask, dst_reg, src_reg, size);
    } else { 
        taint_regflag2reg (mask, dst_reg, dst_reg, size);
    }
}

TAINTSIGN taint_cmov_memregreg2reg (uint32_t mask, uint32_t dst_reg, u_long mem_loc, uint32_t size, BOOL executed, uint32_t base_reg, uint32_t base_reg_size, uint32_t index_reg, uint32_t index_reg_size) { 
    if (executed) { 
        taint_memflag2reg (mask, dst_reg, mem_loc, size);
        //also merge the addressing registers if there is any
        if(base_reg_size>0) {
            assert (base_reg_size == size);
            taint_add_reg2reg_offset (dst_reg*REG_SIZE, base_reg*REG_SIZE, base_reg_size, -1, -1);
        }
        if (index_reg_size > 0) { 
            assert (index_reg_size == size);
            taint_add_reg2reg_offset (dst_reg*REG_SIZE, index_reg*REG_SIZE, index_reg_size, -1, -1);
        }
    } else { 
        taint_regflag2reg (mask, dst_reg, dst_reg, size);
    }
}

    //    if flag tainted: if flag set => dst = flag + source
    //    		       not set => dst = flag + dst
    //    if flag not tainted: if flag set => dst = source
    //    			  not set  => dst = dst (unchanged)
    //    In summary, this is equivalent to :
    //          if flag is set, dst => merge flag and source
    //    			not set, dst => merge dst and flag
    //    TODO: I think we should include cmov as an output for the byte range analysis tool

void instrument_cmov(INS ins, uint32_t mask)
{
    int ismemread = 0, ismemwrite = 0;
    int immval = 0;
    USIZE addrsize = 0;
    REG reg = REG_INVALID();
    REG dstreg = REG_INVALID();
    //int treg = (int)REG_INVALID();

    assert(INS_IsPredicated(ins));

    if(INS_IsMemoryRead(ins)) {
        ismemread = 1;
        addrsize = INS_MemoryReadSize(ins);
        reg = INS_OperandReg(ins, 0);
        if(!REG_valid(reg)) return;
    } else if(INS_IsMemoryWrite(ins)) {
        ismemwrite = 1;
        addrsize = INS_MemoryWriteSize(ins);
        if(INS_OperandIsReg(ins, 1)) {
            reg = INS_OperandReg(ins, 1);
            if(!REG_valid(reg)) return;
        } else {
            if(!INS_OperandIsImmediate(ins, 1)) return;
            //must be an immediate value
            immval = 1;
        }
    } else {
        if(!(INS_OperandIsReg(ins, 0))) return;
        dstreg = INS_OperandReg(ins, 0);
        if(!REG_valid(dstreg)) return;

        if(INS_OperandIsReg(ins, 1)) {
            reg = INS_OperandReg(ins, 1);
            if(!REG_valid(reg)) return;
        } else {
            //sometimes get an offset into video memory
            if(!INS_OperandIsImmediate(ins, 1)) return;
            //must be an immediate value
            immval = 1;
        }
    }

    //2 (src) operand is memory...destination must be a register
    if(ismemread) {
        INSTRUMENT_PRINT(log_f, "instrument mov is mem read: reg: %d (%s), size of mem read is %u\n", 
                reg, REG_StringShort(reg).c_str(), addrsize);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        uint32_t base_reg_size = 0;
        uint32_t index_reg_size = 0;
        if (REG_valid(base_reg)) base_reg_size = REG_Size (base_reg);
        if (REG_valid(index_reg)) index_reg_size = REG_Size (index_reg);
        assert (!REG_is_Upper8(base_reg));
        assert (!REG_is_Upper8(index_reg));
        assert (!REG_is_Upper8(reg));
        fw_slice_src_regregmemflag_cmov (ins, reg, base_reg, base_reg_size, index_reg, index_reg_size, IARG_MEMORYREAD_EA, addrsize, mask); 
        INS_InsertCall (ins, IPOINT_BEFORE,
			AFUNPTR(taint_cmov_mem2reg),
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, mask, 
			IARG_UINT32, translate_reg (reg),
			IARG_MEMORYREAD_EA,
			IARG_UINT32, REG_Size(reg),
			IARG_EXECUTING,
			IARG_END);
    } else if(ismemwrite) {
	assert (0);//shouldn't happen for cmov
    } else {
        if(immval) {
	    assert (0);// shouldn't happen
        } else {
            //reg to reg
            assert(REG_Size(reg) == REG_Size(dstreg));
            int dst_treg = translate_reg((int)dstreg);
            int src_treg = translate_reg((int)reg);
            assert (!REG_is_Upper8(reg));
            assert (!REG_is_Upper8(dstreg));
	    
            INSTRUMENT_PRINT(log_f, "instrument cmov is src reg: %d into dst reg: %d\n", reg, dstreg); 
#ifdef FW_SLICE
            fw_slice_src_regflag (ins, mask, reg, REG_Size(reg));
#endif
            INS_InsertCall (ins, IPOINT_BEFORE,
                    AFUNPTR(taint_cmov_reg2reg),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_UINT32, mask, 
                    IARG_UINT32, dst_treg, 
                    IARG_UINT32, src_treg, 
                    IARG_UINT32, REG_Size(reg),
                    IARG_EXECUTING,
                    IARG_END);
        }
    }
}

//This function doesn't handle RCR and RCL
void instrument_rotate(INS ins)
{
	int op1reg = INS_OperandIsReg (ins, 0);
	int op1mem = INS_OperandIsMemory (ins, 0);
	int op2imm = INS_OperandIsImmediate (ins, 1);
	int op2reg = INS_OperandIsReg (ins, 1);
	if (op2imm) {
		UINT64 imm = INS_OperandImmediate (ins, 1);
		assert (imm != 1); //we also need to taint OF in this case
	}
	if (op1reg) { 
		REG reg = INS_OperandReg (ins, 0);
		uint32_t regsize = REG_Size (reg);
		if (regsize == 1) assert (REG_is_Lower8(reg));
#ifdef FW_SLICE
		fw_slice_src_reg (ins, reg, regsize, 0);
#endif
		if (regsize == 1) {
			// we only track taint at a byte granularily,
			//  rotating 8 bits doesn't affect the taint
			return;
		}
		INS_InsertCall (ins, IPOINT_BEFORE, 
				AFUNPTR (taint_rotate_reg),
				IARG_FAST_ANALYSIS_CALL,
				IARG_UINT32, translate_reg (reg),
				IARG_UINT32, regsize,
				IARG_UINT32, op2reg,
				IARG_END);
	} else if (op1mem) { 
		uint32_t size = INS_MemoryWriteSize (ins);
#ifdef FW_SLICE
		fw_slice_src_mem (ins, INS_OperandIsMemory(ins, 1));
#endif
		if (size == 1) return;
		INS_InsertCall (ins, IPOINT_BEFORE, 
				AFUNPTR (taint_rotate_mem),
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, size,
				IARG_UINT32, op2reg,
				IARG_END);
	} else { 
		assert (0);
	}
}

void instrument_shift(INS ins)
{
    int count = INS_OperandCount(ins);
    if(count == 2) {
        assert (0);
    } else if (count == 3) {
	if (INS_OperandIsReg(ins, 0)) {
	    if (INS_OperandIsReg(ins, 1)) {
		instrument_taint_add_reg2reg(ins, INS_OperandReg(ins, 0), INS_OperandReg(ins, 1), -1, -1);
	    } else {
		instrument_taint_mix_reg (ins, INS_OperandReg(ins, 0), -1, -1);
	    }
	} else {
	    if (INS_OperandIsReg(ins, 1)) {
		instrument_taint_add_reg2mem (ins, INS_OperandReg(ins, 1), -1, -1); 
	    } else {
		assert (0);
	    }
	}
    } else if (count == 4) {
        if (INS_OperandIsReg(ins, 2)) {
            if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
                instrument_taint_mix_regreg2reg(ins, INS_OperandReg(ins, 0), INS_OperandReg(ins, 1), INS_OperandReg(ins,2), -1, -1);
	    } else {
		printf ("Probably incorrect shift: %s\n", INS_Disassemble(ins).c_str());
		assert (0);
		if (INS_OperandIsReg(ins, 0)) {
		    instrument_taint_add_reg2reg(ins, INS_OperandReg(ins, 0),
						 INS_OperandReg(ins, 2), -1, -1);
		} 
		if(INS_OperandIsReg(ins, 1)) {
		    instrument_taint_add_reg2reg(ins, INS_OperandReg(ins, 1),
						 INS_OperandReg(ins, 2), -1, -1);
		} else if (INS_OperandIsMemory(ins, 1)) {
		    instrument_taint_add_reg2mem(ins, INS_OperandReg(ins, 2), -1, -1);
		}
	    }
        } else {
            if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
                instrument_taint_add_reg2reg(ins, INS_OperandReg(ins, 0), INS_OperandReg(ins, 1), -1, -1);
	    } else {
		printf ("Unhanded shift: %s\n", INS_Disassemble(ins).c_str());
		assert (0);
	    }
	}
    }
}

void instrument_lea(INS ins)
{
    REG dstreg = INS_OperandReg(ins, 0);
    REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
    REG index_reg = INS_OperandMemoryIndexReg(ins, 1);

    if (REG_valid (index_reg) && !REG_valid(base_reg)) {
        // This is a nummeric calculation in disguise
#ifdef FW_SLICE
      fw_slice_src_reg (ins, index_reg, REG_Size(index_reg), 0);
#endif
        INSTRUMENT_PRINT (log_f, "LEA: index reg is %d(%s) base reg invalid, dst %d(%s)\n",
                index_reg, REG_StringShort(index_reg).c_str(),
                dstreg, REG_StringShort(dstreg).c_str());
        assert(REG_Size(index_reg) == REG_Size(dstreg));
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_reg2reg_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_UINT32, get_reg_off(dstreg),
		       IARG_UINT32, get_reg_off(index_reg),
		       IARG_UINT32, REG_Size(dstreg),
		       IARG_END);
    } else if(REG_valid(base_reg) && REG_valid (index_reg)) {
#ifdef FW_SLICE
      fw_slice_src_regreg (ins, base_reg, REG_Size(base_reg), index_reg, REG_Size(index_reg));
#endif
        switch(REG_Size(dstreg)) {
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wregwreg2wreg),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_UINT32, translate_reg(dstreg),
			IARG_UINT32, translate_reg(base_reg),
			IARG_UINT32, translate_reg(index_reg),
                        IARG_END);
                break;
            default:
                ERROR_PRINT (stderr, "[ERROR] taint_immval2reg dstreg %d(%s) size is %d\n",
                        dstreg, REG_StringShort(dstreg).c_str(), REG_Size(dstreg));
                assert(0);
                break;
        }
    } else if (!REG_valid (index_reg) && REG_valid(base_reg)) {
#ifdef FW_SLICE
	    fw_slice_src_reg (ins, base_reg, REG_Size(base_reg), 0);
#endif
        INSTRUMENT_PRINT (log_f, "LEA: base reg is %d(%s) index reg invalid, dst %d(%s)\n",
                base_reg, REG_StringShort(base_reg).c_str(),
                dstreg, REG_StringShort(dstreg).c_str());
        assert(REG_Size(base_reg) == REG_Size(dstreg));
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_reg2reg_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_UINT32, get_reg_off(dstreg),
		       IARG_UINT32, get_reg_off(base_reg),
		       IARG_UINT32, REG_Size(dstreg),
		       IARG_END);
    } else { 
	    //operand should be immval
	    switch(REG_Size(dstreg)) {
		    case 4:
			    INS_InsertCall(ins, IPOINT_BEFORE,
					    AFUNPTR(taint_immval2wreg),
					    IARG_FAST_ANALYSIS_CALL,
					    IARG_UINT32, dstreg,
					    IARG_END);
			    break;
		    default:
			    ERROR_PRINT (stderr, "[ERROR] taint_immval2reg dstreg %d(%s) size is %d\n",
					    dstreg, REG_StringShort(dstreg).c_str(), REG_Size(dstreg));
			    assert(0);
			    break;

	    }
    }
}

void instrument_push(INS ins)
{
	USIZE addrsize = INS_MemoryWriteSize(ins);
	int src_reg = INS_OperandIsReg(ins, 0);
	int src_imm = INS_OperandIsImmediate(ins, 0);

    if (src_imm) {
        switch(addrsize) {
            case 1:
                INS_InsertCall (ins, IPOINT_BEFORE,
                                        AFUNPTR(taint_immvalb2mem),
                                        IARG_FAST_ANALYSIS_CALL,
                                        IARG_MEMORYWRITE_EA,
                                        IARG_END);
                break;
            case 2:
                INS_InsertCall (ins, IPOINT_BEFORE,
                                        AFUNPTR(taint_immvalhw2mem),
                                        IARG_FAST_ANALYSIS_CALL,
                                        IARG_MEMORYWRITE_EA,
                                        IARG_END);
                break;
            case 4:
                INS_InsertCall (ins, IPOINT_BEFORE,
                                        AFUNPTR(taint_immvalw2mem),
                                        IARG_FAST_ANALYSIS_CALL,
                                        IARG_MEMORYWRITE_EA,
                                        IARG_END);
                break;
            default:
                ERROR_PRINT (stderr, "[ERROR]Unsupported imm push size\n");
                assert(0);
                break;
        }
    } else if (src_reg) {
        REG reg = INS_OperandReg(ins, 0);
        int treg = translate_reg(reg);
	assert(addrsize == REG_Size(reg));
#ifdef FW_SLICE
	fw_slice_src_reg (ins, reg, REG_Size(reg), 1);
#endif
        switch(addrsize) {
            case 1:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_lbreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 2:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                ERROR_PRINT (stderr, "[ERROR]Unsupported reg push size\n");
                assert(0);
                break;
        }
    } else {
        assert(INS_OperandIsMemory(ins, 0));
#ifdef FW_SLICE
    	fw_slice_src_mem (ins, 1);
#endif
        switch(addrsize) {
            case 1:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_b),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
                break;
            case 2:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_hw),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_w),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
                break;
            default:
                ERROR_PRINT (stderr, "[ERROR]Unsupported mem push size\n");
                assert(0);
                break;
        }
    }
}

void instrument_pop(INS ins)
{
    USIZE addrsize = INS_MemoryReadSize(ins);
    if (INS_OperandIsMemory(ins, 0)) {
#ifdef FW_SLICE
    	fw_slice_src_mem (ins, 1);
#endif
        switch(addrsize) {
            case 1:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_w),
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
                break;
            default:
                ERROR_PRINT(stderr, "[ERROR] unsupported pop mem size\n");
                assert(0);
                break;
        }
    } else if (INS_OperandIsReg(ins, 0)) {
#ifdef FW_SLICE
    	fw_slice_src_mem (ins, 0);
#endif
        REG reg = INS_OperandReg(ins, 0);
	INS_InsertCall (ins, IPOINT_BEFORE,
			AFUNPTR(taint_mem2reg_offset),
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_UINT32, get_reg_off(reg),
			IARG_UINT32, REG_Size(reg),
			IARG_END);
    }
    //I think we should clear the source mem for POP, since that memory address is not freed
    // JNF: I think not
    instrument_clear_mem_src (ins);
}

void instrument_leave (INS ins) { 
    USIZE addrsize = INS_MemoryReadSize (ins);
    assert (addrsize == 4); //only care about 32bit for now
#ifdef FW_SLICE
    fw_slice_src_regmem (ins, LEVEL_BASE::REG_EBP, 4, IARG_MEMORYREAD_EA, 4);
    instrument_taint_reg2reg_slice (ins, LEVEL_BASE::REG_ESP, LEVEL_BASE::REG_EBP, 0, 0);
    instrument_taint_mem2reg_slice (ins, LEVEL_BASE::REG_EBP, 0, 0);
#else
    instrument_taint_reg2reg (ins, LEVEL_BASE::REG_ESP, LEVEL_BASE::REG_EBP, 0);
    instrument_taint_mem2reg (ins, LEVEL_BASE::REG_EBP, 0);
#endif
}

void instrument_addorsub(INS ins, int set_flags, int clear_flags)
{
    int op1mem;
    int op2mem;
    int op1reg;
    int op2reg;
    int op2imm;

    OPCODE opcode;
    USIZE addrsize;

    opcode = INS_Opcode(ins);
    INSTRUMENT_PRINT(log_f, "instrument_addorsub: arith ins is %s (%#x)\n",
            INS_Mnemonic(ins).c_str(), INS_Address(ins));

    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);

    if((op1mem && op2reg)) {
        REG reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is mem and op2 is register\n");
        addrsize = INS_MemoryWriteSize(ins);
        assert (REG_Size(reg) == addrsize);
        instrument_taint_add_reg2mem(ins, reg, set_flags, clear_flags);
    } else if(op1reg && op2mem) {
        REG reg = INS_OperandReg(ins, 0);
        if(!INS_IsMemoryRead(ins) || !REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is register and op2 is mem\n");
        addrsize = INS_MemoryReadSize(ins);
	if (addrsize != REG_Size(reg)) {
	  fprintf (stderr, "addrsize is %u reg size is %u\n", addrsize, REG_Size(reg));
	}
        instrument_taint_add_mem2reg(ins, reg, set_flags, clear_flags);
    } else if(op1reg && op2reg) {
        REG reg;
        REG dstreg;

        dstreg = INS_OperandReg(ins, 0);
        reg = INS_OperandReg(ins, 1);
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 and op2 of Arith are registers: %d (%s), %d (%s)\n", 
                dstreg, REG_StringShort(dstreg).c_str(), reg, REG_StringShort(reg).c_str());
        if(!REG_valid(dstreg) || !REG_valid(reg)) {
            return;
        } 

        if((opcode == XED_ICLASS_SUB || opcode == XED_ICLASS_XOR ||
	    opcode == XED_ICLASS_PXOR || opcode == XED_ICLASS_XORPS)  
	   && (dstreg == reg)) {
            int dst_treg = translate_reg(dstreg);
            INSTRUMENT_PRINT(log_f, "handling reg reset\n");
#ifdef FW_SLICE
	    fw_slice_src_regreg (ins, dstreg, REG_Size(dstreg), reg, REG_Size(reg));
#endif
	    // Mike didn't handle ubreg - should I?
	    INS_InsertCall (ins, IPOINT_BEFORE,
			    AFUNPTR(taint_clear_reg_offset),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_UINT32, dst_treg * REG_SIZE,
			    IARG_UINT32, REG_Size(dstreg),
			    IARG_UINT32, set_flags,
			    IARG_UINT32, clear_flags,
			    IARG_END);
        } else {
            assert (REG_Size(dstreg) == REG_Size(reg));
	    instrument_taint_add_reg2reg(ins, dstreg, reg, set_flags, clear_flags);
        }
    } else if(op1mem && op2imm) {
#ifdef FW_SLICE
	fw_slice_src_mem (ins, 1);
#endif
        /*imm does not change taint value of the destination*/
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is mem and op2 is immediate\n");
    } else if(op1reg && op2imm){
        REG reg = INS_OperandReg(ins, 0);
#ifdef FW_SLICE
	fw_slice_src_reg (ins, reg, REG_Size(reg), 0);
#endif
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is reg (%d) and op2 is immediate\n", reg);
    } else {
        //if the arithmatic involves an immediate instruction the taint does
        //not propagate...
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of arithmatic ins: %s\n", instruction.c_str());
    }
}

/* Divide has 3 operands.
 *
 *  r/m, AX, AL/H/X <- quotient, AH <- remainder
 * */
void instrument_div(INS ins)
{
    INSTRUMENT_PRINT (log_f, "div instruction: %s\n", INS_Disassemble(ins).c_str());
    if (INS_IsMemoryRead(ins)) {
        UINT32 addrsize;
        // Register translations
        int msb_treg, lsb_treg, dst1_treg, dst2_treg;

        addrsize = INS_MemoryReadSize(ins);
	INSTRUMENT_PRINT (log_f, "div addrsize %u\n", addrsize);
        switch (addrsize) {
            case 1:
                // mem_loc is Divisor
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX); // Dividend
                dst1_treg = translate_reg(LEVEL_BASE::REG_AL); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_AH); // Remainder
#ifdef FW_SLICE
		fw_slice_src_regmem (ins, LEVEL_BASE::REG_AX, 2, IARG_MEMORYREAD_EA, 1);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add2_hwmemhwreg_2breg),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, lsb_treg,
                                    IARG_UINT32, dst1_treg,
                                    IARG_UINT32, dst2_treg,
                                    IARG_END);
                break;
            case 2:
                // mem_loc is Divisor
                msb_treg = translate_reg(LEVEL_BASE::REG_DX);
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX); // Dividend
                dst1_treg = translate_reg(LEVEL_BASE::REG_AX); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_DX); // Remainder

#ifdef FW_SLICE
		fw_slice_src_regregmem (ins, LEVEL_BASE::REG_DX, 2, LEVEL_BASE::REG_AX, 2, IARG_MEMORYREAD_EA, 2);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
			       AFUNPTR(taint_add3_mem2reg_2reg),
			       IARG_FAST_ANALYSIS_CALL,
			       IARG_MEMORYREAD_EA,
			       IARG_UINT32, msb_treg,
			       IARG_UINT32, lsb_treg,
			       IARG_UINT32, dst1_treg,
			       IARG_UINT32, dst2_treg,
			       IARG_UINT32, addrsize,
			       IARG_END);
                break;
            case 4:
                // Dividend is msb_treg:lsb_treg
                // Divisor is src_treg
                msb_treg = translate_reg(LEVEL_BASE::REG_EDX);
                lsb_treg = translate_reg(LEVEL_BASE::REG_EAX);
                dst1_treg = translate_reg(LEVEL_BASE::REG_EAX); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_EDX); // Remainder
#ifdef FW_SLICE
		fw_slice_src_regregmem (ins, LEVEL_BASE::REG_EDX, 4, LEVEL_BASE::REG_EAX, 4, IARG_MEMORYREAD_EA, 4);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
			       AFUNPTR(taint_add3_mem2reg_2reg),
			       IARG_FAST_ANALYSIS_CALL,
			       IARG_MEMORYREAD_EA,
			       IARG_UINT32, msb_treg,
			       IARG_UINT32, lsb_treg,
			       IARG_UINT32, dst1_treg,
			       IARG_UINT32, dst2_treg,
			       IARG_UINT32, addrsize,
			       IARG_END);
                break;
            default:
                ERROR_PRINT(stderr, "[ERROR] Unsupported div sizes\n");
                ERROR_PRINT (stderr, "div ins: %s\n", INS_Disassemble(ins).c_str());
                assert(0);
                break;
        }
    } else {
        UINT32 size;
        REG src_reg;

        // Register translations
        int msb_treg, lsb_treg, src_treg, dst1_treg, dst2_treg;

        assert (INS_OperandIsReg(ins, 0));
        src_reg = INS_OperandReg(ins, 0);
        src_treg = translate_reg(src_reg);
        size = REG_Size(src_reg);
        // fprintf (stderr, "div: src_reg is %d(%s) size is %d\n", src_reg, REG_StringShort(src_reg).c_str(), size);
        switch (size) {
            case 1:
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX); // Dividend
                dst1_treg = translate_reg(LEVEL_BASE::REG_AL); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_AH); // Remainder
#ifdef FW_SLICE
		fw_slice_src_regreg (ins, LEVEL_BASE::REG_AX, 2, src_reg, size);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add2_hwregbreg_2breg),
                                    IARG_FAST_ANALYSIS_CALL,
                                    IARG_UINT32, lsb_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_UINT32, dst1_treg,
                                    IARG_UINT32, dst2_treg,
                                    IARG_END);
                break;
            case 2:
		//xdou: I don't think the original code handles this properly
                // Dividend is msb_treg:lsb_treg
                // Divisor is src_treg
                msb_treg = translate_reg(LEVEL_BASE::REG_DX);
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX);
                dst1_treg = translate_reg(LEVEL_BASE::REG_AX); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_DX); // Remainder
#ifdef FW_SLICE
		fw_slice_src_regregreg (ins, src_reg, size, LEVEL_BASE::REG_DX, 2, LEVEL_BASE::REG_AX, 2);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add3_2hwreg_2hwreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_UINT32, msb_treg,
                                IARG_UINT32, lsb_treg,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, dst1_treg,
                                IARG_UINT32, dst2_treg,
                                IARG_END);
                break;
            case 4:
                // Dividend is msb_treg:lsb_treg
                // Divisor is src_treg
                msb_treg = translate_reg(LEVEL_BASE::REG_EDX);
                lsb_treg = translate_reg(LEVEL_BASE::REG_EAX);
                dst1_treg = translate_reg(LEVEL_BASE::REG_EAX); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_EDX); // Remainder
#ifdef FW_SLICE
		fw_slice_src_regregreg (ins, src_reg, size, LEVEL_BASE::REG_EDX, 4, LEVEL_BASE::REG_EAX, 4);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add3_2wreg_2wreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_UINT32, msb_treg,
                                IARG_UINT32, lsb_treg,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, dst1_treg,
                                IARG_UINT32, dst2_treg,
                                IARG_END);
                break;
            default:
                ERROR_PRINT(stderr, "[ERROR] Unsupport div sizes\n");
                ERROR_PRINT (stderr, "div ins: %s\n", INS_Disassemble(ins).c_str());
                assert(0);
                break;
        }
    }
}

void instrument_mul(INS ins)
{
    INSTRUMENT_PRINT (log_f, "mul instruction: %s\n", INS_Disassemble(ins).c_str());
    if (INS_IsMemoryRead(ins)) {
        int lsb_dst_treg, msb_dst_treg;
        int src_treg;
        UINT32 addrsize;

        addrsize = INS_MemoryReadSize(ins);
        switch (addrsize) {
            case 1:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_AX);
                src_treg = translate_reg(LEVEL_BASE::REG_AL);
#ifdef FW_SLICE
		fw_slice_src_regmem (ins, LEVEL_BASE::REG_AL, 1, IARG_MEMORYREAD_EA, addrsize);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_bmemlbreg_hwreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_END);
                break;
            case 2:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_AX); 
                msb_dst_treg = translate_reg(LEVEL_BASE::REG_DX);
                src_treg = translate_reg(LEVEL_BASE::REG_AX); 
#ifdef FW_SLICE
		fw_slice_src_regregmem (ins, LEVEL_BASE::REG_AX, 2, LEVEL_BASE::REG_DX, 2, IARG_MEMORYREAD_EA, addrsize);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_hwmemhwreg_2hwreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_UINT32, msb_dst_treg,
                                IARG_END);
                break;
            case 4:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_EAX); 
                msb_dst_treg = translate_reg(LEVEL_BASE::REG_EDX);
                src_treg = translate_reg(LEVEL_BASE::REG_EAX); 
#ifdef FW_SLICE
		fw_slice_src_regregmem (ins, LEVEL_BASE::REG_EAX, 4, LEVEL_BASE::REG_EDX, 4, IARG_MEMORYREAD_EA, addrsize);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_wmemwreg_2wreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_UINT32, msb_dst_treg,
                                IARG_END);
                break;
            default:
                ERROR_PRINT(stderr, "[ERROR] Unsupported mul sizes\n");
                ERROR_PRINT (stderr, "mul ins: %s\n", INS_Disassemble(ins).c_str());
                assert(0);
                break;
        }
    } else if (INS_OperandIsReg(ins, 0)) {
        REG src2_reg;
        int lsb_dst_treg, msb_dst_treg;
        int src_treg, src2_treg;

        assert (INS_OperandIsReg(ins, 0));
        src2_reg = INS_OperandReg(ins, 0);

        switch(REG_Size(src2_reg)) {
            case 1:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_AX);
                src_treg = translate_reg(LEVEL_BASE::REG_AL);
                src2_treg = translate_reg(src2_reg);
#ifdef FW_SLICE
		fw_slice_src_regreg (ins, LEVEL_BASE::REG_AX, 1, src2_reg, REG_Size(src2_reg)), 
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_lbreglbreg_hwreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, src2_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_END);
                break;
            case 2:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_AX);
                msb_dst_treg = translate_reg(LEVEL_BASE::REG_DX);
                src_treg = translate_reg(LEVEL_BASE::REG_AX);
                src2_treg = translate_reg(src2_reg);
#ifdef FW_SLICE
		fw_slice_src_regregreg (ins, LEVEL_BASE::REG_AX, 2, LEVEL_BASE::REG_DX, 2, src2_reg, REG_Size(src2_reg));
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_hwreghwreg_2hwreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, src2_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_UINT32, msb_dst_treg,
                                IARG_END);
                break;
            case 4:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_EAX);
                msb_dst_treg = translate_reg(LEVEL_BASE::REG_EDX);
                src_treg = translate_reg(LEVEL_BASE::REG_EAX);
                src2_treg = translate_reg(src2_reg);
#ifdef FW_SLICE
		fw_slice_src_regregreg(ins, LEVEL_BASE::REG_EAX, 4, LEVEL_BASE::REG_EDX, 4, src2_reg, REG_Size(src2_reg));
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_wregwreg_2wreg),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, src2_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_UINT32, msb_dst_treg,
                                IARG_END);
                break;
            default:
                ERROR_PRINT(stderr, "[ERROR] Unsupported mul sizes\n");
                ERROR_PRINT (stderr, "mul ins: %s\n", INS_Disassemble(ins).c_str());
                assert(0);
                break;
        }
    } else {
        ERROR_PRINT(stderr, "[ERROR] Unsupported mul sizes\n");
        ERROR_PRINT (stderr, "mul ins: %s\n", INS_Disassemble(ins).c_str());
        assert(0);
    }
}

//IMPORTANT: retval of INS_OperandCount won't correspond to the actual operand counts in the intel manual! 
//Apperantly, pin has its only definition of operand counts
//It prints out all hidden registers and EFLAGS as operands
void instrument_imul(INS ins)
{
    int count;
    INSTRUMENT_PRINT (log_f, "imul instruction: %s\n", INS_Disassemble(ins).c_str());
    count = INS_OperandCount(ins);
    INSTRUMENT_PRINT (log_f, "num operands is %d\n", count);
    if (count == 3) {
        //format: imul r32, r/m32  (r32 = r32*r/m32)
        // taint_add src to dst
        assert (INS_OperandIsReg(ins, 0));
        REG dst_reg = INS_OperandReg(ins, 0);
        if (INS_IsMemoryRead(ins)) {
            assert (REG_Size(dst_reg) == INS_MemoryReadSize(ins));
#ifdef FW_SLICE
	    fw_slice_src_regmem (ins, dst_reg, REG_Size(dst_reg), IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins));
#endif
	    INS_InsertCall(ins, IPOINT_BEFORE,
			   AFUNPTR(taint_add_mem2reg_offset),
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_MEMORYREAD_EA,
			   IARG_UINT32, get_reg_off(dst_reg),
			   IARG_UINT32, CF_FLAG|OF_FLAG,
			   IARG_UINT32, SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG,
			   IARG_END);
        } else {
            assert (INS_OperandIsReg(ins, 1));
            REG src_reg = INS_OperandReg(ins, 1);
            assert (REG_Size(dst_reg) == REG_Size(src_reg));
#ifdef FW_SLICE
	    fw_slice_src_regreg (ins, dst_reg, REG_Size(dst_reg), src_reg, REG_Size(src_reg));
#endif
	    INS_InsertCall(ins, IPOINT_BEFORE,
			   AFUNPTR(taint_add_reg2reg_offset),
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_UINT32, get_reg_off(dst_reg),
			   IARG_UINT32, get_reg_off(src_reg),
			   IARG_UINT32, REG_Size(dst_reg),
			   IARG_UINT32, CF_FLAG|OF_FLAG,
			   IARG_UINT32, SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG,
			   IARG_END);
        }
    } else if (count == 2) {
        //xdou: I don't think this will happen? 
        fprintf (stderr, "[BUG] imul with 2 operands??\n");
        assert (0);
    }else if (count == 4) {
        //format1: imul r/m32 (EDX:EAX = EAX*r/m32), same as mul
        //format2: imul r32, r/m32, imm32 (r32=r/m32*imm32),  taint src to dst
        /*int i = 0;
        for (; i<4; ++i) { 
            fprintf (stderr, "[INFO]imul %d %d %d %d, reg (%d)\n", INS_OperandIsReg (ins, i), INS_OperandIsMemory(ins, i), INS_OperandIsImmediate(ins, i), INS_OperandIsImplicit(ins, i), INS_OperandReg(ins, i));
        }
        fprintf (stderr, "[INFO] imul %s\n", INS_Disassemble(ins).c_str());*/
        if (INS_OperandIsImmediate (ins, 2)) {
            //format 2
            assert (INS_OperandIsReg(ins, 0));
            REG dst_reg = INS_OperandReg(ins, 0);

            if (INS_IsMemoryRead(ins)) {
                UINT32 addrsize = INS_MemoryReadSize(ins);
                assert (addrsize == REG_Size(dst_reg));
#ifdef FW_SLICE
		fw_slice_src_mem (ins, 0);
#endif
		INS_InsertCall(ins, IPOINT_BEFORE,
			       AFUNPTR(taint_mem2reg_offset),
			       IARG_FAST_ANALYSIS_CALL,
			       IARG_MEMORYREAD_EA,
			       IARG_UINT32, get_reg_off(dst_reg),
			       IARG_UINT32, addrsize,
			       IARG_END);
            } else {
                assert (INS_OperandIsReg(ins, 1));
                REG src_reg = INS_OperandReg(ins, 1);
#ifdef FW_SLICE
		fw_slice_src_reg (ins, src_reg, REG_Size(src_reg), 0);
#endif
                assert (REG_Size(dst_reg) == REG_Size(src_reg));
		INS_InsertCall(ins, IPOINT_BEFORE,
			       AFUNPTR(taint_reg2reg_offset),
			       IARG_FAST_ANALYSIS_CALL,
			       IARG_UINT32, get_reg_off(dst_reg),
			       IARG_UINT32, get_reg_off(src_reg),
                               IARG_UINT32, REG_Size(src_reg),
			       IARG_END);
            }
        } else { 
            //format 1
            instrument_mul (ins);
        }
    }
}

void instrument_call_near (INS ins)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_call_near),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_REG_VALUE, LEVEL_BASE::REG_ESP, 
		   IARG_END);
}

void instrument_call_far (INS ins)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_call_far),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_REG_VALUE, LEVEL_BASE::REG_ESP, 
		   IARG_END);
}

void instrument_palignr(INS ins)
{
    UINT32 imm;
    REG reg;
    int treg;
    assert(INS_OperandIsImmediate(ins, 2));
    assert(INS_OperandIsReg(ins, 0));

    imm = INS_OperandImmediate(ins, 2);
    assert(imm > 0 && imm < 16);
    reg = INS_OperandReg(ins, 0);

    treg = translate_reg((int)reg);
    if (INS_OperandIsMemory(ins, 1)) {
        UINT32 addrsize;
        addrsize = INS_MemoryReadSize(ins);
        assert(addrsize == REG_Size(reg));
        assert(addrsize == 8 || addrsize == 16);
#ifdef FW_SLICE
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYREAD_EA, addrsize);
#endif

        if (addrsize == 8) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_palignr_mem2dwreg),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_UINT32, treg,
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, imm,
                    IARG_END);
        } else if (addrsize == 16) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_palignr_mem2qwreg),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_UINT32, treg,
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, imm,
                    IARG_END);
        } else {
            assert(0);
        }

    } else if (INS_OperandIsReg(ins, 1)) {
        REG reg2 = INS_OperandReg(ins, 1);
        int treg2 = translate_reg((int)reg2);

        assert(REG_Size(reg) == REG_Size(reg2));

#ifdef FW_SLICE
	fw_slice_src_regreg (ins, reg, REG_Size(reg), reg2, REG_Size(reg2));
#endif
        if (REG_Size(reg2) == 8) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_palignr_dwreg2dwreg),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_UINT32, treg,
                    IARG_UINT32, treg2,
                    IARG_UINT32, imm,
                    IARG_END);
        } else if (REG_Size(reg2) == 16) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_palignr_qwreg2qwreg),
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_UINT32, treg,
                    IARG_UINT32, treg2,
                    IARG_UINT32, imm,
                    IARG_END);
        }
    } else {
        assert(0);
    }
}

void instrument_psrldq(INS ins)
{
    assert(INS_OperandIsReg(ins, 0));
    assert(INS_OperandIsImmediate(ins, 1));
    int treg = translate_reg(INS_OperandReg(ins, 0));
    int shift = INS_OperandImmediate(ins, 1);
#ifdef FW_SLICE
    fw_slice_src_reg (ins, INS_OperandReg(ins, 0), REG_Size(INS_OperandReg(ins, 0)), 0);
#endif

    INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(shift_reg_taint_right),
                    IARG_UINT32, treg,
                    IARG_UINT32, shift,
                    IARG_END);
}

void instrument_pmovmskb(INS ins)
{
    int src_treg;
    int dst_treg;

    assert(INS_OperandIsReg(ins, 0));
    assert(INS_OperandIsReg(ins, 1));
    assert(REG_Size(INS_OperandReg(ins, 0)) == 4);
    assert(REG_Size(INS_OperandReg(ins, 1)) == 16);

    dst_treg = translate_reg(INS_OperandReg(ins, 0));
    src_treg = translate_reg(INS_OperandReg(ins, 1));
#ifdef FW_SLICE
    fw_slice_src_reg (ins, INS_OperandReg(ins, 1), REG_Size(INS_OperandReg(ins, 1)), 0);
#endif

    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(taint_mask_reg2reg),
            IARG_FAST_ANALYSIS_CALL,
            IARG_UINT32, dst_treg,
            IARG_UINT32, src_treg,
            IARG_END);
}

inline void instrument_taint_regmem2flag (INS ins, REG reg, uint32_t flags) {
	int treg;
	UINT32 regsize;
	UINT32 memsize;
	IARG_TYPE mem_ea;

	treg = translate_reg ((int) reg);
	regsize = REG_Size(reg);

	if (INS_IsMemoryRead(ins)) {
		mem_ea = IARG_MEMORYREAD_EA;
		memsize = INS_MemoryReadSize(ins);
	} else if (INS_IsMemoryWrite(ins)) {
		mem_ea = IARG_MEMORYWRITE_EA;
		memsize = INS_MemoryWriteSize(ins);
	} else {
		assert(0);
	}

#ifdef FW_SLICE
	fw_slice_src_regmem (ins, reg, regsize, mem_ea, memsize);
#endif

	if (regsize != memsize) 
		fprintf (stderr, "TODO: instrument_taint_regmem2flag: fix regsize problem\n");

	INSTRUMENT_PRINT (log_f, "instrument_taint_regmem2flag: flags %u, reg %u size %u, memsize %u\n", flags, reg, regsize, memsize);
	INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_regmem2flag),
			IARG_FAST_ANALYSIS_CALL,
			mem_ea,
			IARG_UINT32, treg,
			IARG_UINT32, flags, 
			IARG_UINT32, regsize,
			IARG_END);
}

inline void instrument_taint_regreg2flag (INS ins, REG dst_reg, REG src_reg, uint32_t flags) 
{
	int dst_treg;
	int src_treg;
	UINT32 dst_regsize;
	UINT32 src_regsize;

	dst_treg = translate_reg ((int) dst_reg);
	src_treg = translate_reg ((int) src_reg);
	dst_regsize = REG_Size(dst_reg);
	src_regsize = REG_Size(src_reg);
	assert (dst_regsize == src_regsize);
#ifdef FW_SLICE
	fw_slice_src_regreg (ins, dst_reg, dst_regsize, src_reg, src_regsize);
#endif

	INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_regreg2flag),
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, dst_treg,
			IARG_UINT32, src_treg,
			IARG_UINT32, flags, 
			IARG_UINT32, src_regsize,
			IARG_END);
}

void instrument_test_or_cmp (INS ins, uint32_t set_mask, uint32_t clear_mask)
{
	//TODO: I didn't check the size of the reg here! This could be over tainting
    int op1mem, op1reg, op2reg, op2imm, op2mem;
    string instruction;
    REG reg;
    USIZE addrsize;

    op1mem = INS_OperandIsMemory(ins, 0);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);
    op2mem = INS_OperandIsMemory(ins, 1);
    instrument_clear_flag_slice (ins, clear_mask, 0); //clear mask
    if((op1mem && op2reg) || (op1reg && op2mem)) { //ordering doesn't matter
	    REG reg = (op1reg?INS_OperandReg(ins, 0):INS_OperandReg(ins,1));
	    assert (REG_valid (reg));
	    INSTRUMENT_PRINT (log_f, "instrument_test: op1 is mem and op2 is register\n");
	    addrsize = INS_MemoryReadSize(ins);
	    assert (REG_Size(reg) == addrsize);
	    instrument_taint_regmem2flag (ins, reg, set_mask);
    } else if(op1reg && op2reg) {
        REG dstreg;
        dstreg = INS_OperandReg(ins, 0);
        reg = INS_OperandReg(ins, 1);
        INSTRUMENT_PRINT(log_f, "instrument_test: op1 and op2 of are registers %d(%s), %d(%s)\n", 
                dstreg, REG_StringShort(dstreg).c_str(), reg, REG_StringShort(reg).c_str());
	INSTRUMENT_PRINT (log_f, "%d EFLAGS %s, %d, %d\n", REG_EFLAGS, REG_StringShort(REG_EFLAGS).c_str(), REG_is_flags (REG_EFLAGS), REG_is_flags(dstreg));
        if(!REG_valid(dstreg) || !REG_valid(reg)) {
		ERROR_PRINT (stderr, "[ERROR]instrument_test: not valid registers.\n");
            	return;
        } 
	assert (REG_Size(reg) == REG_Size(dstreg));
        instrument_taint_regreg2flag (ins, dstreg, reg, set_mask);
   } else if(op1mem && op2imm) {
	    addrsize = INS_MemoryReadSize(ins);
	    INSTRUMENT_PRINT (log_f, "instrument_test: op1 is mem and op2 is imm\n");
#ifdef FW_SLICE
	    fw_slice_src_mem(ins, 0);
#endif
	    INS_InsertCall(ins, IPOINT_BEFORE,
			    AFUNPTR(taint_mem2flag),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_MEMORYREAD_EA,
			    IARG_UINT32, set_mask, 
			    IARG_UINT32, addrsize,
			    IARG_END);
   } else if(op1reg && op2imm){
	    REG reg = INS_OperandReg (ins, 0);
	    uint32_t regsize = REG_Size (reg);
	    assert (REG_valid (reg));
	    INSTRUMENT_PRINT (log_f, "instrument_test: op1 is reg and op2 is imm\n");
#ifdef FW_SLICE
	    fw_slice_src_reg(ins, reg, regsize, 0);
#endif
	    INS_InsertCall(ins, IPOINT_BEFORE,
			    AFUNPTR(taint_reg2flag),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_UINT32, translate_reg(reg), 
			    IARG_UINT32, set_mask, 
			    IARG_UINT32, regsize,
                            IARG_UINT32, REG_is_Upper8(reg),
			    IARG_END);
    }else{
        //if the arithmatic involves an immediate instruction the taint does
        //not propagate...
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of CMP ins: %s\n", instruction.c_str());
    }
}

TAINTSIGN instrument_unhandled_inst (ADDRINT ip) {
	fprintf (stderr, "unhanded inst %x\n", ip);
}

void instrument_jump (INS ins, uint32_t flags) {
#ifdef FW_SLICE
	fw_slice_src_flag (ins, flags);
#endif
	INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_jump),
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, REG_EFLAGS,
			IARG_UINT32, flags, 
			IARG_ADDRINT, INS_Address(ins),
			IARG_BRANCH_TAKEN,
			IARG_END);
}

void instrument_jump_ecx (INS ins, uint32_t size) {
#ifdef FW_SLICE
	fw_slice_src_reg (ins, LEVEL_BASE::REG_ECX, size, 0);
#endif
	INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_jump_ecx),
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
			IARG_UINT32, size,
			IARG_INST_PTR,
			IARG_BRANCH_TAKEN,
			IARG_END);
}

void instrument_not (INS ins) { 
#ifdef FW_SLICE
	int op1reg = INS_OperandIsReg (ins, 0);	
	int op1mem = INS_OperandIsMemory (ins, 0);
	if (op1reg) { 
		REG reg = INS_OperandReg(ins, 0);
		UINT32 regsize = REG_Size(reg);	
		fw_slice_src_reg (ins, reg, regsize, 0);
	} else if (op1mem) { 
		fw_slice_src_mem (ins, 0);
	} else {
		assert (0);
	}
#endif
}

#ifdef TAINT_DEBUG
void trace_inst(ADDRINT ptr)
{
    taint_debug_inst = ptr;
}
#endif
#ifdef TRACE_INST
void trace_inst(ADDRINT ip, CONTEXT* ctx)
{
    ADDRINT eax = LEVEL_PINCLIENT::PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX);
    ADDRINT ebx = LEVEL_PINCLIENT::PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX);
    ADDRINT ecx = LEVEL_PINCLIENT::PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX);
    ADDRINT edx = LEVEL_PINCLIENT::PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX);
    ADDRINT edi = LEVEL_PINCLIENT::PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI);

    PIN_LockClient();
    fprintf(stderr, "[INST] Pid %d (tid: %d) (record %d) - %#x clock %lu eax %x ebx %x ecx %x edx %x edi %x\n", PIN_GetPid(), PIN_GetTid(), get_record_pid(), ip, *ppthread_log_clock, eax, ebx, ecx, edx, edi);
    if (IMG_Valid(IMG_FindByAddress(ip))) {
	fprintf(stderr,"%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));
    }
    PIN_UnlockClient();
}
#endif

void instrument_incdec_neg (INS ins) {
#ifdef FW_SLICE
	int opmem = INS_OperandIsMemory (ins, 0);
	int opreg = INS_OperandIsReg (ins, 0);
	if (opmem) { 
		fw_slice_src_mem (ins, 0);
	} else if (opreg) { 
		REG reg = INS_OperandReg (ins, 0);
		fw_slice_src_reg (ins, reg, REG_Size(reg), 0);
	} else {
		assert (0);
	}
#endif
}

void instrument_set (INS ins, uint32_t mask) { 
#ifdef FW_SLICE
	fw_slice_src_flag (ins, mask);
#endif
	if (INS_IsMemoryWrite(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(taint_flag2mem),
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32,mask, 
				IARG_UINT32, 1,
				IARG_END);
	} else { 
		INS_InsertCall(ins, IPOINT_BEFORE,
				AFUNPTR(taint_flag2reg),
				IARG_FAST_ANALYSIS_CALL,
				IARG_UINT32, translate_reg(INS_OperandReg(ins, 0)),
				IARG_UINT32, mask, 
				IARG_UINT32, 1,
				IARG_END);
	}

}

void instrument_bt (INS ins) { 
	int op1reg = INS_OperandIsReg (ins, 0);
	int op2reg = INS_OperandIsReg (ins, 1);
	int op1mem = INS_OperandIsMemory (ins, 0);
	int op2imm = INS_OperandIsImmediate (ins, 1);
	if (op1reg && op2reg) { 
		instrument_taint_regreg2flag (ins, INS_OperandReg (ins, 0), INS_OperandReg(ins, 1), CF_FLAG);
	} else if (op1mem && op2reg) { 
		instrument_taint_regmem2flag (ins, INS_OperandReg(ins, 1), CF_FLAG);
	} else if (op1reg && op2imm) { 
	    REG reg = INS_OperandReg (ins, 0);
	    uint32_t regsize = REG_Size (reg);
	    assert (REG_valid (reg));
#ifdef FW_SLICE
	    fw_slice_src_reg(ins, reg, regsize, 0);
#endif
	    INS_InsertCall(ins, IPOINT_BEFORE,
			    AFUNPTR(taint_reg2flag),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_UINT32, reg, 
			    IARG_UINT32, CF_FLAG, 
			    IARG_UINT32, regsize,
                            IARG_UINT32, REG_is_Upper8(reg),
			    IARG_END);
	} else if (op1mem && op2imm) { 
	    uint32_t addrsize = INS_MemoryReadSize(ins);
#ifdef FW_SLICE
	    fw_slice_src_mem(ins, 0);
#endif
	    INS_InsertCall(ins, IPOINT_BEFORE,
			    AFUNPTR(taint_mem2flag),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_MEMORYREAD_EA,
			    IARG_UINT32, CF_FLAG, 
			    IARG_UINT32, addrsize,
			    IARG_END);
	} else { 
		assert (0);
	}
}

void instrument_bit_scan (INS ins) { 
    if (INS_IsMemoryRead(ins)) {  //mem to reg
        REG dstreg = INS_OperandReg(ins, 0);
#ifdef FW_SLICE
        fw_slice_src_mem (ins, 0);
#endif
        INS_InsertCall (ins, IPOINT_BEFORE, 
                AFUNPTR(taint_merge_mem2reg),
                IARG_FAST_ANALYSIS_CALL,
                IARG_MEMORYREAD_EA, 
                IARG_UINT32, translate_reg(dstreg),
                IARG_UINT32, REG_Size(dstreg),
                IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE,
                AFUNPTR(taint_mem2flag),
                IARG_FAST_ANALYSIS_CALL,
                IARG_MEMORYREAD_EA,
                IARG_UINT32, ZF_FLAG, 
                IARG_UINT32, INS_MemoryReadSize(ins),
                IARG_END);
    } else {
        REG dstreg = INS_OperandReg (ins, 0);
        REG srcreg = INS_OperandReg (ins, 1);
#ifdef FW_SLICE
        fw_slice_src_reg (ins, srcreg, REG_Size(srcreg), 0);
#endif
        assert (REG_is_Upper8(srcreg) == 0);
        INS_InsertCall (ins, IPOINT_BEFORE, 
                AFUNPTR(taint_merge_reg2reg), 
                IARG_FAST_ANALYSIS_CALL, 
                IARG_UINT32, translate_reg (dstreg),
                IARG_UINT32, translate_reg (srcreg),
                IARG_UINT32, REG_Size (dstreg),
                IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE,
                AFUNPTR(taint_reg2flag),
                IARG_FAST_ANALYSIS_CALL,
                IARG_UINT32, translate_reg(srcreg),
                IARG_UINT32, ZF_FLAG,  
                IARG_UINT32, REG_Size(srcreg),
                IARG_UINT32, REG_is_Upper8(srcreg),
                IARG_END);
    }
}

void count_inst_executed (void) { 
	++num_of_inst_executed;
}

void PIN_FAST_ANALYSIS_CALL debug_print_inst (ADDRINT ip, char* ins, u_long mem_loc1, u_long mem_loc2, ADDRINT val)
{
#ifdef EXTRA_DEBUG
    if (*ppthread_log_clock < EXTRA_DEBUG) return;
#endif
    printf ("#%x %s,mem %lx %lx\n", ip, ins, mem_loc1, mem_loc2);
    PIN_LockClient();
    if (IMG_Valid(IMG_FindByAddress(ip))) {
	printf ("%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));
    }
    PIN_UnlockClient();
    printf ("eax tainted? %d ebx tainted? %d ecx tainted? %d edx tainted? %d edx value %x ebp tainted? %d esp tainted? %d\n", 
	    is_reg_arg_tainted (LEVEL_BASE::REG_EAX, 4, 0), is_reg_arg_tainted (LEVEL_BASE::REG_EBX, 4, 0), is_reg_arg_tainted (LEVEL_BASE::REG_ECX, 4, 0), 
	    is_reg_arg_tainted (LEVEL_BASE::REG_EDX, 4, 0), val,
	    is_reg_arg_tainted (LEVEL_BASE::REG_EBP, 4, 0), is_reg_arg_tainted (LEVEL_BASE::REG_ESP, 4, 0));
    // If you want to debug a memory address or xmm taint, can uncomment and change this
    //printf ("bfffea20 val %lu tainted? %d%d%d%d\n", *((u_long *) 0xbfffea20), is_mem_arg_tainted (0xbfffea20, 1), is_mem_arg_tainted (0xbfffea21, 1), 
    //    is_mem_arg_tainted (0xbfffea22, 1), is_mem_arg_tainted (0xbfffea23, 1));
    printf ("reg xmm1 tainted? ");
    for (int i = 0; i < 16; i++) {
	printf ("%d", (current_thread->shadow_reg_table[LEVEL_BASE::REG_XMM1*REG_SIZE + i] != 0));
    }
    //printf ("\t");
    //printf ("reg xmm2 tainted? ");
    //for (int i = 0; i < 16; i++) {
//	printf ("%d", (current_thread->shadow_reg_table[LEVEL_BASE::REG_XMM2*REG_SIZE + i] != 0));
    //}
    printf ("\n");
    fflush (stdout);
}

void debug_print (INS ins) 
{
    char* str = get_copy_of_disasm (ins);
    int count = INS_MemoryOperandCount (ins);
    int mem1read = 0;
    int mem2read = 0;
    
    if (count >= 1) {
	mem1read = INS_MemoryOperandIsRead (ins, 0);
	if (count == 2) {
	    mem2read = INS_MemoryOperandIsRead (ins, 1);
	}
    }

    if (count == 2) {
	if (mem1read && mem2read) {
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)debug_print_inst, 
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_MEMORYREAD_EA, 
			   IARG_MEMORYREAD2_EA, 
			   IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
			   IARG_END);
	} else if ((mem1read && !mem2read) || (!mem1read && mem2read)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)debug_print_inst, 
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_MEMORYREAD_EA, 
			   IARG_MEMORYWRITE_EA,
			   IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
			   IARG_END);
	} else {
	    assert (0);
	}
    } else if (count == 1) {
	if (mem1read) {
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)debug_print_inst, 
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_MEMORYREAD_EA, 
			   IARG_ADDRINT, 0,
			   IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
			   IARG_END);
	} else {
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)debug_print_inst, 
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_MEMORYWRITE_EA, 
			   IARG_ADDRINT, 0,
			   IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
			   IARG_END);
	}
    } else { 
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)debug_print_inst, 
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_INST_PTR,
		       IARG_PTR, str,
		       IARG_ADDRINT, 0,
		       IARG_ADDRINT, 0,
		       IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
		       IARG_END);
    }
}

void instruction_instrumentation(INS ins, void *v)
{
    OPCODE opcode;
    UINT32 category;
    int instrumented = 0;
    int slice_handled = 0;
    int rep_handled = 0;

#ifdef TAINT_STATS
    inst_instrumented++;
    //INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR (count_inst_executed), IARG_END);
#endif
#ifdef EXTRA_DEBUG
    //DEBUG: print out dynamic instructions and their mem read/write
    debug_print (ins);
#endif
   
    if(INS_IsSyscall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_syscall),
                IARG_SYSCALL_NUMBER, 
                IARG_SYSARG_VALUE, 0, 
                IARG_SYSARG_VALUE, 1,
                IARG_SYSARG_VALUE, 2,
                IARG_SYSARG_VALUE, 3,
                IARG_SYSARG_VALUE, 4,
                IARG_SYSARG_VALUE, 5,
                IARG_END);
	slice_handled = 1;
    }
    //fprintf (stderr, "[DEBUG INSTRUMENT] inst %x, %s\n", INS_Address (ins), INS_Disassemble(ins).c_str());

    opcode = INS_Opcode(ins);
    category = INS_Category(ins);

#ifdef TRACE_INST
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(trace_inst),
		   IARG_INST_PTR,
		   IARG_CONTEXT,
		   IARG_END);
#endif

#ifdef USE_CODEFLUSH_TRICK
    if (option_cnt != 0) {
#endif

    if (INS_IsMov(ins)) {
        instrument_mov(ins);
	slice_handled = 1;
    } else if (category == XED_CATEGORY_CMOV) {
        // We separate out the tainting of the movement of data with
        //  cf, since we can do so much faster if we don't care about cf
	switch (opcode) {
		case XED_ICLASS_CMOVBE:
		case XED_ICLASS_CMOVNBE:
			instrument_cmov (ins, CF_FLAG | ZF_FLAG);
			break;
		case XED_ICLASS_CMOVZ:
		case XED_ICLASS_CMOVNZ:
			instrument_cmov (ins, ZF_FLAG);
			break;
		case XED_ICLASS_CMOVB:
		case XED_ICLASS_CMOVNB:
			instrument_cmov (ins, CF_FLAG);
			break;
		case XED_ICLASS_CMOVS:
		case XED_ICLASS_CMOVNS:
			instrument_cmov (ins, SF_FLAG);
			break;
                case XED_ICLASS_CMOVNLE:
                case XED_ICLASS_CMOVLE:
                        instrument_cmov (ins, ZF_FLAG | SF_FLAG | OF_FLAG);
                        break;
                case XED_ICLASS_CMOVL:
                case XED_ICLASS_CMOVNL:
                        instrument_cmov (ins, SF_FLAG | OF_FLAG);
                        break;
		default:
			fprintf (stderr, "[NOOP] cmov not instrumented : %s\n", INS_Disassemble(ins).c_str());
			break;
	}
	slice_handled = 1;
    } else if (category == XED_CATEGORY_SHIFT) {
#ifdef COPY_ONLY
        instrument_clear_dst(ins);
#else
	//TODO: flags are affected 
	switch (opcode) { 
	    //case XED_ICLASS_SAL:
	    case XED_ICLASS_SAR:
	    case XED_ICLASS_SHL:
	    case XED_ICLASS_SHR:
	    case XED_ICLASS_SHRD:
            case XED_ICLASS_SHLD: 
                    instrument_shift(ins);
		    slice_handled = 1;
		    break;
	    default:
		    break;
	}
#endif
    } else {
        switch(opcode) {
            // Move and sign/zero extend
            case XED_ICLASS_MOVSX:
            case XED_ICLASS_MOVZX:
                //flags affected: none
                instrument_movx(ins);
		slice_handled = 1;
                break;
            case XED_ICLASS_MOVD:
            case XED_ICLASS_MOVQ:
                instrument_movx(ins);
		slice_handled = 1;
                break;
            case XED_ICLASS_MOVDQU:
            case XED_ICLASS_MOVDQA:
            case XED_ICLASS_MOVAPS:
            case XED_ICLASS_MOVUPS:
            case XED_ICLASS_MOVLPD:
            case XED_ICLASS_MOVHPD:
            case XED_ICLASS_MOVNTDQA:
            case XED_ICLASS_MOVNTDQ:
                instrument_mov(ins);
                rep_handled = 1; //it seems these instructions are always prefixed with 0xF3
		slice_handled = 1;
                break;
            case XED_ICLASS_PALIGNR:
                instrument_palignr(ins);
		slice_handled = 1;
                break;
            case XED_ICLASS_MOVSB:
            case XED_ICLASS_MOVSW:
            case XED_ICLASS_MOVSD:
            case XED_ICLASS_MOVSQ:
                instrument_move_string(ins);
		slice_handled = 1;
		rep_handled = 1;
                break;
            case XED_ICLASS_STOSB:
            case XED_ICLASS_STOSW:
            case XED_ICLASS_STOSD:
            case XED_ICLASS_STOSQ:
                instrument_store_string(ins);
		slice_handled = 1;
		rep_handled = 1;
                break;
            case XED_ICLASS_LODSB:
            case XED_ICLASS_LODSW:
            case XED_ICLASS_LODSD:
            case XED_ICLASS_LODSQ:
                instrument_load_string(ins);
                break;
            case XED_ICLASS_XCHG:
                instrument_xchg(ins);
		slice_handled = 1;
                break;
            case XED_ICLASS_BSWAP:
                instrument_bswap(ins);
                break;
            case XED_ICLASS_CMPXCHG:
                instrument_cmpxchg(ins);
		slice_handled = 1;
                break;
            case XED_ICLASS_PUSH:
                instrument_push(ins);
		slice_handled = 1;
                break;
            case XED_ICLASS_POP:
                instrument_pop(ins);
		slice_handled = 1;
                break;
            case XED_ICLASS_LEA:
                instrument_lea(ins);
		slice_handled = 1;
                break;
            case XED_ICLASS_XADD:
                instrument_xchg(ins);
                instrument_addorsub(ins, SF_FLAG|ZF_FLAG|PF_FLAG|OF_FLAG|CF_FLAG|AF_FLAG, 0);
		slice_handled = 1;
                break;
            case XED_ICLASS_AND:
            case XED_ICLASS_OR:
            case XED_ICLASS_XOR:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_addorsub(ins, SF_FLAG|ZF_FLAG|PF_FLAG, OF_FLAG|CF_FLAG|AF_FLAG);
		slice_handled = 1;
#endif
		break;
            case XED_ICLASS_ADD:
            case XED_ICLASS_SUB:
            case XED_ICLASS_SBB:
            case XED_ICLASS_ADC:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_addorsub(ins, SF_FLAG|ZF_FLAG|PF_FLAG|OF_FLAG|CF_FLAG|AF_FLAG, 0);
		slice_handled = 1;
#endif
                break;
            case XED_ICLASS_DIV:
            case XED_ICLASS_IDIV:
#ifdef COPY_ONLY
                instrument_clear_reg(ins, LEVEL_BASE::REG_EAX);
#else
                instrument_div(ins);
		slice_handled = 1;
#endif
                break;
            case XED_ICLASS_MUL:
#ifdef COPY_ONLY
                instrument_clear_reg(ins, LEVEL_BASE::REG_EAX);
#else
                instrument_mul(ins);
		slice_handled = 1;
#endif
                break;
            case XED_ICLASS_IMUL:
                instrument_imul(ins);
		slice_handled = 1;
                break;
            // now all of the XMM packed instructions
            case XED_ICLASS_POR:
            case XED_ICLASS_PAND:
            case XED_ICLASS_PANDN:
            case XED_ICLASS_PXOR:
            case XED_ICLASS_PADDB:
            case XED_ICLASS_PADDW:
            case XED_ICLASS_PADDD:
            case XED_ICLASS_PADDQ:
            case XED_ICLASS_PSUBB:
            case XED_ICLASS_PSUBW:
            case XED_ICLASS_PSUBD:
            case XED_ICLASS_PSUBQ:
            case XED_ICLASS_PMADDWD:
            case XED_ICLASS_PMULHUW:
            case XED_ICLASS_PMINUB:
            case XED_ICLASS_PMULLW:
            case XED_ICLASS_PADDUSW:
            case XED_ICLASS_PADDUSB:
            case XED_ICLASS_PACKUSWB:
            case XED_ICLASS_PSHUFHW:
            case XED_ICLASS_PSHUFLW:
	    case XED_ICLASS_PSHUFD:
            case XED_ICLASS_PSHUFB:
            case XED_ICLASS_XORPS:
            case XED_ICLASS_SUBSD:
            case XED_ICLASS_DIVSD:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_addorsub(ins, -1, -1);
		slice_handled = 1;
#endif
                break;
            case XED_ICLASS_PCMPEQB:
            case XED_ICLASS_PCMPEQW:
            case XED_ICLASS_PCMPEQD:
            case XED_ICLASS_PCMPGTB:
            case XED_ICLASS_PCMPGTW:
            case XED_ICLASS_PCMPGTD:
            case XED_ICLASS_PCMPGTQ:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_addorsub(ins, -1, -1);
		slice_handled = 1;
#endif
                break;
            case XED_ICLASS_PSRLDQ:
                instrument_psrldq(ins);
                slice_handled = 1;
                break;
                /*
            case XED_ICLASS_PSRLW:
            case XED_ICLASS_PSRLD:
            case XED_ICLASS_PSRLQ:
                assert(0);
                break;
                */
            case XED_ICLASS_PMOVMSKB:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_pmovmskb(ins);
#endif
                slice_handled = 1;
                break;
            case XED_ICLASS_PUNPCKHBW:
            case XED_ICLASS_PUNPCKLBW:
            case XED_ICLASS_PUNPCKHWD:
            case XED_ICLASS_PUNPCKLWD:
            case XED_ICLASS_PUNPCKHDQ:
            case XED_ICLASS_PUNPCKLDQ:
            case XED_ICLASS_PUNPCKHQDQ:
            case XED_ICLASS_PUNPCKLQDQ:
                instrument_addorsub(ins, -1, -1);
		slice_handled = 1;
                break;
                /*
            case XED_ICLASS_PSHUFD:
                break;
                */
            case XED_ICLASS_CALL_NEAR:
		instrument_call_near(ins);
		slice_handled = 1;
		break;
            case XED_ICLASS_CALL_FAR:
		instrument_call_far(ins);
		slice_handled = 1;
		break;
            case XED_ICLASS_RET_NEAR:
            case XED_ICLASS_RET_FAR:
		slice_handled = 1;
		rep_handled = 1;
                break;
#ifdef CTRL_FLOW_OLD
            // TODO
            // case XED_ICLASS_INC:
            // case XED_ICLASS_DEC:
            // case XED_ICLASS_NEG:
                // flags affected: all but CF
            //    break;
#else
            case XED_ICLASS_INC:
            case XED_ICLASS_DEC:
            case XED_ICLASS_NEG:
		//TODO : control flow
                // flags affected: all but CF
		instrument_incdec_neg (ins);
		slice_handled = 1;
                break;
#endif
#ifdef CTRL_FLOW
            /*case XED_ICLASS_RCL:
            case XED_ICLASS_RCR:
                instrument_rotate(ins);
                // flags affected: CF, OF
                break;*/
            case XED_ICLASS_ROL:
	    case XED_ICLASS_ROR:
		instrument_rotate (ins);
		slice_handled = 1;
		break;
            case XED_ICLASS_SETB:
            case XED_ICLASS_SETNB:
		instrument_set (ins, CF_FLAG);
		slice_handled = 1;
		break;
            case XED_ICLASS_SETL:
            case XED_ICLASS_SETNL:
		instrument_set (ins, SF_FLAG | OF_FLAG);
		slice_handled = 1;
		break;
            case XED_ICLASS_SETNBE:
            case XED_ICLASS_SETBE:
		instrument_set (ins, CF_FLAG | ZF_FLAG);
		slice_handled = 1;
		break;
            case XED_ICLASS_SETLE:
            case XED_ICLASS_SETNLE:
		instrument_set (ins, ZF_FLAG|SF_FLAG|OF_FLAG);
		slice_handled = 1;
		break;
            case XED_ICLASS_SETNO:
            case XED_ICLASS_SETO:
		instrument_set (ins, OF_FLAG);
		slice_handled = 1;
		break;
            case XED_ICLASS_SETNP:
            case XED_ICLASS_SETP:
		instrument_set (ins, PF_FLAG);
		slice_handled = 1;
		break;
            case XED_ICLASS_SETNS:
            case XED_ICLASS_SETS:
		instrument_set (ins, SF_FLAG);
		slice_handled = 1;
		break;
            case XED_ICLASS_SETZ:
            case XED_ICLASS_SETNZ:
		instrument_set (ins, ZF_FLAG);
		slice_handled = 1;
                break;
#else
            case XED_ICLASS_SETB:
            case XED_ICLASS_SETNB:
            case XED_ICLASS_SETL:
            case XED_ICLASS_SETNL:
            case XED_ICLASS_SETNBE:
            case XED_ICLASS_SETBE:
            case XED_ICLASS_SETLE:
            case XED_ICLASS_SETNLE:
            case XED_ICLASS_SETNO:
            case XED_ICLASS_SETO:
            case XED_ICLASS_SETNP:
            case XED_ICLASS_SETP:
            case XED_ICLASS_SETNS:
            case XED_ICLASS_SETS:
            case XED_ICLASS_SETZ:
            case XED_ICLASS_SETNZ:
                instrument_clear_dst(ins);
                break;
#endif
#ifdef CTRL_FLOW
           case XED_ICLASS_BSF:
           case XED_ICLASS_BSR:
                instrument_bit_scan (ins);
                slice_handled = 1;
                break;
	   case XED_ICLASS_TEST:
                //INSTRUMENT_PRINT(log_f, "%#x: about to instrument TEST\n", INS_Address(ins));
                instrument_test_or_cmp(ins, SF_FLAG|ZF_FLAG|PF_FLAG, CF_FLAG|OF_FLAG|AF_FLAG);
		slice_handled = 1;
		break;
	   case XED_ICLASS_CMP:
		//INSTRUMENT_PRINT(log_f, "%#x: about to instrument TEST\n", INS_Address(ins));
		instrument_test_or_cmp(ins, SF_FLAG|ZF_FLAG|PF_FLAG|CF_FLAG|OF_FLAG|AF_FLAG, 0);
		slice_handled = 1;
		break;
	   case XED_ICLASS_PTEST:
		instrument_test_or_cmp(ins, ZF_FLAG | CF_FLAG, OF_FLAG|AF_FLAG|PF_FLAG|SF_FLAG);
		slice_handled = 1;
		break;
                //for the following 4 cases, refer to move_string
	   case XED_ICLASS_CMPSB:
		//INSTRUMENT_PRINT(log_f, "%#x: about to instrument TEST\n", INS_Address(ins));
		instrument_compare_string (ins, SF_FLAG|ZF_FLAG|PF_FLAG|CF_FLAG|OF_FLAG|AF_FLAG);
		rep_handled = 1;
		slice_handled = 1;
		break;
	   case XED_ICLASS_SCASB:
		instrument_scan_string (ins, SF_FLAG|ZF_FLAG|PF_FLAG|CF_FLAG|OF_FLAG|AF_FLAG);
		slice_handled = 1;
		rep_handled = 1;
		break;
	   case XED_ICLASS_PCMPESTRI:
		instrument_pcmpestri (ins);
                slice_handled = 1;
		break;
	   case XED_ICLASS_PCMPISTRI: 
		instrument_pcmpistri (ins);
                slice_handled = 1;
		break;
	   case XED_ICLASS_JNZ:
                //INSTRUMENT_PRINT(log_f, "%#x: about to instrument JNZ/JNE\n", INS_Address(ins)); instrument_jump (ins, ZF_FLAG);
		instrument_jump (ins, ZF_FLAG);
		slice_handled = 1;
		break;
       	   case XED_ICLASS_JZ:
                //INSTRUMENT_PRINT(log_f, "%#x: about to instrument JZ/JE\n", INS_Address(ins));
		instrument_jump (ins, ZF_FLAG);
		slice_handled = 1;
		break;
	   case XED_ICLASS_JMP:
                //INSTRUMENT_PRINT(log_f, "%#x: about to instrument JMP\n", INS_Address(ins));
		instrument_jump (ins, 0);
		slice_handled = 1;
		break;
        case XED_ICLASS_JB:
        case XED_ICLASS_JNB:
           	//INSTRUMENT_PRINT(log_f, "%#x: about to instrument JB/JNB\n", INS_Address(ins));
		instrument_jump (ins, CF_FLAG);
		slice_handled = 1;
		break;
        case XED_ICLASS_JBE:
        case XED_ICLASS_JNBE:
		//INSTRUMENT_PRINT(log_f, "%#x: about to instrument JBE/JNBE\n", INS_Address(ins));
		instrument_jump (ins, CF_FLAG|ZF_FLAG);
		slice_handled = 1;
		break;
        case XED_ICLASS_JL:
        case XED_ICLASS_JNL:
		//INSTRUMENT_PRINT(log_f, "%#x: about to instrument JL/JNL\n", INS_Address(ins));
		instrument_jump (ins, SF_FLAG|OF_FLAG);
		slice_handled = 1;
		break;
	case XED_ICLASS_JLE:
        case XED_ICLASS_JNLE: 
		//INSTRUMENT_PRINT(log_f, "%#x: about to instrument JLE/JNLE\n", INS_Address(ins));
		instrument_jump (ins, ZF_FLAG|SF_FLAG|OF_FLAG);
		slice_handled = 1;
		break;
	case XED_ICLASS_JNO:
        case XED_ICLASS_JO:
		//INSTRUMENT_PRINT(log_f, "%#x: about to instrument JO/JNO\n", INS_Address(ins));
		instrument_jump (ins, OF_FLAG);
		slice_handled = 1;
		break;
	case XED_ICLASS_JNP:
        case XED_ICLASS_JP:
		//INSTRUMENT_PRINT(log_f, "%#x: about to instrument JP/JNP\n", INS_Address(ins));
		instrument_jump (ins, PF_FLAG);
		slice_handled = 1;
		break;
        case XED_ICLASS_JNS:
        case XED_ICLASS_JS:
		//INSTRUMENT_PRINT(log_f, "%#x: about to instrument JS/JNS\n", INS_Address(ins));
		instrument_jump (ins, SF_FLAG);
		slice_handled = 1;
		break;
	case XED_ICLASS_JRCXZ:
		//TODO: should use different size for JCXZ..
		instrument_jump_ecx (ins, 4);
		slice_handled = 1;
		break;
#else
	   case XED_ICLASS_CMP:
		break;
	   case XED_ICLASS_TEST:
		break;
           case XED_ICLASS_JZ:
	   case XED_ICLASS_JNZ:
		break;
	   case XED_ICLASS_JMP:
		break;
        case XED_ICLASS_JB:
        case XED_ICLASS_JNB:
		break;
        case XED_ICLASS_JBE:
        case XED_ICLASS_JNBE:
        case XED_ICLASS_JL:
        case XED_ICLASS_JNL:
	case XED_ICLASS_JLE:
        case XED_ICLASS_JNLE:
		break;
	case XED_ICLASS_JNO:
        case XED_ICLASS_JO:
	case XED_ICLASS_JNP:
        case XED_ICLASS_JP:
        case XED_ICLASS_JNS:
        case XED_ICLASS_JS:
		break;
#endif
#ifndef CTRL_FLOW_OLD//xdou: TODO clean up the OLD control flow marco
            case XED_ICLASS_NOT:
#ifdef FW_SLICE
		instrument_not (ins);
		slice_handled = 1;
#endif
                break;
            case XED_ICLASS_LEAVE:
                instrument_leave (ins);
                slice_handled = 1;
                break;
            case XED_ICLASS_CLD:
		instrument_clear_flag (ins, DF_FLAG);
		slice_handled = 1;
                break;
            case XED_ICLASS_BT:
		instrument_bt (ins);
		slice_handled = 1;
                break;
#endif
            case XED_ICLASS_CPUID:
                // ignore this instruction
		slice_handled = 1;
                break;
            case XED_ICLASS_PUSHFD:
#ifdef FW_SLICE
                fw_slice_src_flag (ins, uint32_t(-1));
#endif
                INS_InsertCall (ins, IPOINT_BEFORE, 
                        AFUNPTR(taint_pushfd), 
                        IARG_FAST_ANALYSIS_CALL, 
                        IARG_MEMORYWRITE_EA, 
                        IARG_UINT32, INS_MemoryWriteSize(ins),
                        IARG_END);
                slice_handled = 1;
                break;
            case XED_ICLASS_POPFD:
#ifdef FW_SLICE
                fw_slice_src_mem (ins, 0);
#endif
                INS_InsertCall (ins, IPOINT_BEFORE, 
                        AFUNPTR(taint_popfd), 
                        IARG_FAST_ANALYSIS_CALL, 
                        IARG_MEMORYREAD_EA, 
                        IARG_UINT32, INS_MemoryReadSize(ins),
                        IARG_END);
                slice_handled = 1;
                break;
            case XED_ICLASS_FLD:
            case XED_ICLASS_FILD:
                INSTRUMENT_PRINT(log_f, "[INFO] FPU inst: %s, op_count %u\n", INS_Disassemble(ins).c_str(), INS_OperandCount(ins));
                assert (INS_OperandCount(ins) == 4);
                if (INS_IsMemoryRead(ins))
                    instrument_taint_mem2reg (ins, INS_OperandReg(ins, 0), 1);
                else 
                    instrument_taint_reg2reg (ins, INS_OperandReg(ins, 0), INS_OperandReg(ins, 1), 1);
                slice_handled = 1;
                break;
            case XED_ICLASS_FLDZ:
            case XED_ICLASS_FLD1:
            case XED_ICLASS_FLDL2T:
            case XED_ICLASS_FLDL2E:
            case XED_ICLASS_FLDPI:
            case XED_ICLASS_FLDLG2:
            case XED_ICLASS_FLDLN2:
                INSTRUMENT_PRINT(log_f, "[INFO] FPU inst: %s, op_count %u\n", INS_Disassemble(ins).c_str(), INS_OperandCount(ins));
                assert (INS_OperandCount(ins) == 3);
                instrument_clear_dst (ins);
                slice_handled = 1;
                break;
            case XED_ICLASS_FST:
            case XED_ICLASS_FSTP:
                INSTRUMENT_PRINT(log_f, "[INFO] FPU inst: %s, op_count %u\n", INS_Disassemble(ins).c_str(), INS_OperandCount(ins));
                assert (INS_OperandCount(ins) == 4 || INS_OperandCount(ins) == 3);
                if (INS_IsMemoryWrite(ins))
                    instrument_taint_reg2mem (ins, INS_OperandReg(ins, 1), 1);
                else 
                    instrument_taint_reg2reg (ins, INS_OperandReg(ins, 0), INS_OperandReg(ins, 1), 1);
                slice_handled = 1;
                break;
            case XED_ICLASS_FMULP:
            case XED_ICLASS_FMUL:
            case XED_ICLASS_FADD:
            case XED_ICLASS_FADDP:
            case XED_ICLASS_FSUB:
            case XED_ICLASS_FISUB:
            case XED_ICLASS_FSUBP:
            case XED_ICLASS_FSUBR:
            case XED_ICLASS_FISUBR:
            case XED_ICLASS_FSUBRP:
            case XED_ICLASS_FDIV:
            case XED_ICLASS_FIDIV:
            case XED_ICLASS_FDIVP:
                INSTRUMENT_PRINT(log_f, "[INFO] FPU inst: %s, op_count %u\n", INS_Disassemble(ins).c_str(), INS_OperandCount(ins));
                if (INS_IsMemoryRead(ins))
                    instrument_taint_add_mem2reg (ins, INS_OperandReg(ins, 0), -1, -1); //FPU flags are not tainted for now
                else 
                    instrument_taint_add_reg2reg (ins, INS_OperandReg(ins, 0), INS_OperandReg(ins, 1), -1, -1);
                slice_handled = 1;
                break;
            case XED_ICLASS_FCOMI:
            case XED_ICLASS_FCOMIP:
            case XED_ICLASS_FUCOMI:
            case XED_ICLASS_FUCOMIP:
                INSTRUMENT_PRINT(log_f, "[INFO] FPU inst: %s, op_count %u\n", INS_Disassemble(ins).c_str(), INS_OperandCount(ins));
                instrument_taint_regreg2flag (ins, INS_OperandReg(ins, 0), INS_OperandReg(ins, 1), ZF_FLAG | PF_FLAG | CF_FLAG);
                slice_handled = 1;
                break;
            case XED_ICLASS_FXCH:
                INSTRUMENT_PRINT(log_f, "[INFO] FPU inst: %s, op_count %u\n", INS_Disassemble(ins).c_str(), INS_OperandCount(ins));
                instrument_xchg (ins); //this function only supports reg2reg exchange with FPU registers  currently
                slice_handled = 1;
                break;
            //TODO:currently, we ignore the FPU control word
            case XED_ICLASS_FNSTCW:
                instrument_clear_dst (ins); 
                slice_handled = 1;
                break;
            case XED_ICLASS_FLDCW:
                //do nothing
                slice_handled = 1;
                break;
            case XED_ICLASS_FISTP:
            case XED_ICLASS_FIST:
                instrument_taint_reg2mem (ins, LEVEL_BASE::REG_ST0, 0);
                slice_handled = 1;
                break;
            case XED_ICLASS_FCMOVNBE:
                instrument_cmov (ins, CF_FLAG | ZF_FLAG);
                slice_handled = 1;
                break;
            default:
                if (INS_IsNop(ins)) {
                    INSTRUMENT_PRINT(log_f, "%#x: not instrument noop %s\n",
                            INS_Address(ins), INS_Disassemble(ins).c_str());
		    slice_handled = 1;
                    break;
                }
                if (INS_IsInterrupt(ins)) {
                    INSTRUMENT_PRINT(log_f, "%#x: not instrument an interrupt\n",
                            INS_Address(ins));
		    slice_handled = 1;
                    break;
                }
                if (INS_IsRDTSC(ins)) {
                    INSTRUMENT_PRINT(log_f, "%#x: not instrument an rdtsc\n",
                            INS_Address(ins));
		    slice_handled = 1;
                    break;
                }
                if (INS_IsSysenter(ins)) {
                    INSTRUMENT_PRINT(log_f, "%#x: not instrument a sysenter\n",
                            INS_Address(ins));
		    slice_handled = 1;
                    break;
                }
                if (instrumented) {
                    break;
                }
                ERROR_PRINT(stderr, "[NOOP] ERROR: instruction %s is not instrumented, address: %#x\n",
                        INS_Disassemble(ins).c_str(), (unsigned)INS_Address(ins));
		/*INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(instrument_unhandled_inst),
				IARG_FAST_ANALYSIS_CALL,
				IARG_ADDRINT, INS_Address(ins),
			IARG_END);*/
                // XXX This printing may cause a deadlock in Pin!
                // print_static_address(log_f, INS_Address(ins));
                break;
        }
    }
    //assertation for REPx
    //REP/REPE/REPNE usually affects INS, MOVS, OUTS, LODS, STOS, CMPS, SCAS
    if (INS_RepPrefix(ins) || (INS_RepnePrefix(ins))) {
	    if (rep_handled == 0) { 
		    ERROR_PRINT(stderr, "[NOOP] ERROR: instruction %s is not instrumented with REP, address: %#x\n", INS_Disassemble(ins).c_str(), (unsigned)INS_Address(ins));

	    }
    }
    //assertion for forward slicing
    if (slice_handled == 0) { 
#ifdef FW_SLICE
	    ERROR_PRINT (stderr, "[NOOP] ERROR: instruction %s is not handled for forward slicing, address %#x\n", INS_Disassemble(ins).c_str(), (unsigned)INS_Address(ins));
#endif
    }
	
#ifdef USE_CODEFLUSH_TRICK
    }
#endif
}

void trace_instrumentation(TRACE trace, void* v)
{
    struct timeval tv_end, tv_start;

#ifdef RECORD_TRACE_INFO
    u_long instrumented_cnt = 0;
    u_long first_instrumented = 0;
#endif

    gettimeofday (&tv_start, NULL);
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after_redo, IARG_INST_PTR, IARG_END);
    //TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
	for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
	    instruction_instrumentation (ins, NULL);
#ifdef RECORD_TRACE_INFO
	    instrumented_cnt++;
	    if (!first_instrumented) first_instrumented = INS_Address(ins);
#endif
	}
    }
    gettimeofday (&tv_end, NULL);

#ifdef RECORD_TRACE_INFO
    if (record_trace_info) {
	trace_inst_buf[trace_inst_cnt++] = instrumented_cnt;
	trace_inst_buf[trace_inst_cnt++] = first_instrumented;
	if (trace_inst_cnt == TRACE_ENTRIES) flush_trace_inst_buf();
    }
#endif

    traces_instrumented++;
    instrument_time += tv_end.tv_usec - tv_start.tv_usec + (tv_end.tv_sec - tv_start.tv_sec) * 1000000;
}

int restore_state_from_disk (struct thread_data* ptdata)
{
    int infd;
    int rc;
    char state_filename[256];
    struct save_state state;
    int monitor_size = 0;

    snprintf(state_filename, 256, "/tmp/%llu.%d.state",
            ptdata->rg_id,
            PIN_GetPid());
    if (access(state_filename, F_OK)) {
        fprintf(stderr, "retore_state: state file %s does not exist\n",
                state_filename);
        return -1;
    }
    infd = open(state_filename, O_RDONLY);
    if (infd < 0) {
        fprintf(stderr, "restore_state: could not open %s, %d\n",
                state_filename, errno);
        return -1;
    }

    rc = read(infd, &state, sizeof(struct save_state));
    if (rc != sizeof(struct save_state)) {
        fprintf(stderr, "could not read state info, errno %d\n", errno);
        return -1;
    }
    // integrity checks
    assert(ptdata->record_pid == state.record_pid);
    assert(ptdata->rg_id == state.rg_id);
    global_syscall_cnt = state.global_syscall_cnt;
    ptdata->syscall_cnt = state.syscall_cnt;
    open_file_cnt = state.open_file_cnt;

    // next read fd monitors
    rc = read(infd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "could not read open_fds monitor size, got %d, expected %d, errno %d\n", rc, sizeof(int), errno);
        close(infd);
        return -1;
    }
    if (monitor_size) {
        void* monitor_bytes;
        monitor_bytes = (void *) malloc(monitor_size);
	if (monitor_bytes == NULL) {
	    fprintf (stderr, "Unable to malloc monitor_bytes\n");
	    assert (0);
	}
        rc = read(infd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "could not read open_fds monitor, errno %d\n", errno);
            return -1;
        }

        monitor_deserialize(&open_fds, monitor_bytes);
    }

    rc = read(infd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "could not read open_socks monitor size, errno %d\n", errno);
        close(infd);
        return -1;
    }
    if (monitor_size) {
        void* monitor_bytes;
        monitor_bytes = (void *) malloc(monitor_size);
	if (monitor_bytes == NULL) {
	    fprintf (stderr, "Unable to malloc monitor_bytes\n");
	    assert (0);
	}
	rc = read(infd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "could not read open_socks monitor, errno %d\n", errno);
            return -1;
        }
        monitor_deserialize(&open_socks, monitor_bytes);
    }

    rc = read(infd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "could not read open_x_fds monitor size, errno %d\n", errno);
        close(infd);
        return -1;
    }
    if (monitor_size) {
        void* monitor_bytes;
        monitor_bytes = (void *) malloc(monitor_size);
	if (monitor_bytes == NULL) {
	    fprintf (stderr, "Unable to malloc monitor_bytes\n");
	    assert (0);
	}
        rc = read(infd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "could not read open_x_fds monitor, errno %d\n", errno);
            return -1;
        }
        monitor_deserialize(&open_x_fds, monitor_bytes);
    }

    // If we're restoring state, then we've successfully execv'ed.
    // Remove all fd's we were mirroring that were marked as CLOEXEC
    monitor_remove_cloexec(open_fds);
    monitor_remove_cloexec(open_socks);
    monitor_remove_cloexec(open_x_fds);

    // next read taint filters
    rc = deserialize_filters(infd);
    if (rc) {
        fprintf(stderr, "restore_state: problem restoring taint filters\n");
        return -1;
    }

    close(infd);
    // delete the state file
    if (unlink(state_filename)) {
        fprintf(stderr, "restore_state: cannot unlink state file %d\n", errno);
    }
    return 0;
}

int save_state_to_disk (struct thread_data* ptdata)
{
    int outfd;
    int rc;
    char state_filename[256];
    struct save_state state;
    int monitor_size = 0;
    void* monitor_bytes = NULL;

    snprintf(state_filename, 256, "/tmp/%llu.%d.state",
            ptdata->rg_id,
            PIN_GetPid());
    outfd = open(state_filename, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outfd < 0) {
        fprintf(stderr, "save_state: could not open %s\n", state_filename);
        return -1;
    }

    // save state
    state.rg_id = ptdata->rg_id;
    state.record_pid = ptdata->record_pid;
    state.global_syscall_cnt = global_syscall_cnt;
    state.syscall_cnt = ptdata->syscall_cnt;
    state.open_file_cnt = open_file_cnt;
    rc = write(outfd, &state, sizeof(struct save_state));
    if (rc != sizeof(struct save_state)) {
        fprintf(stderr, "problem writing state, errno %d\n", errno);
        return -1;
    }

    // next save fd monitors
    monitor_size = monitor_serialize(open_fds, &monitor_bytes);
    assert (monitor_size >= 0);
    rc = write(outfd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write open_fds monitor size, errno %d\n", errno);
    }
    if (monitor_size) {
        rc = write(outfd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "Could not write open_fds monitor to %s, errno %d\n", state_filename, errno);
            return -1;
        }
    }

    monitor_size = monitor_serialize(open_socks, &monitor_bytes);
    assert (monitor_size >= 0);
    rc = write(outfd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write open_socks monitor size, errno %d\n", errno);
    }
    if (monitor_size) {
        rc = write(outfd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "Could not write open_socks monitor to %s, errno %d\n", state_filename, errno);
            return -1;
        }
    }

    monitor_size = monitor_serialize(open_x_fds, &monitor_bytes);
    assert (monitor_size >= 0);
    rc = write(outfd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write open_x_fds monitor size, errno %d\n", errno);
    }
    if (monitor_size) {
        rc = write(outfd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "Could not write open_x_fds monitor to %s, errno %d\n", state_filename, errno);
            return -1;
        }
    }

    // next save taint filters
    rc = serialize_filters(outfd);
    if (rc) {
        fprintf(stderr, "problem serializing taint filters\n");
        return -1;
    }

    close(outfd);
    return 0;
}

BOOL follow_child(CHILD_PROCESS child, void* data)
{
    char** argv;
    assert(main_prev_argv);
    char** prev_argv = main_prev_argv;
    struct thread_data* ptdata = (struct thread_data *) data;
    int index = 0;

    fprintf(stderr, "follow_child\n");
    /* the format of pin command would be:
     * pin_binary -follow_execv -t pin_tool new_addr*/
    int new_argc = 5;
    argv = (char**)malloc(sizeof(char*) * new_argc);
    if (argv == NULL) {
	fprintf (stderr, "Unable to malloc argv\n");
	assert (0);
    }

    fprintf(stderr, "follow_child: %p\n", main_prev_argv);
    argv[0] = prev_argv[index++];                   // pin
    argv[1] = (char *) "-follow_execv";
    while(strcmp(prev_argv[index], "-t")) index++;
    argv[2] = prev_argv[index++];
    argv[3] = prev_argv[index++];
    argv[4] = (char *) "--";

    CHILD_PROCESS_SetPinCommandLine(child, new_argc, argv);

    // save necessary state to disk before exec-ing
    save_state_to_disk(ptdata);

    return TRUE;
}
void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PRINTX(stderr, "%d,%d:AfterForkInChild\n", PIN_GetPid(),get_record_pid());

#ifndef NO_FILE_OUTPUT
    fclose(log_f); 
    log_f = NULL;
    init_logs();
#endif

    //for now there is no change for not using the network
#ifndef USE_FILE
    //we use the fork_flags to determine which path to follow: 
    //means that the fork_flag was a 0... so we need to make the outfd's all our bs value:
    PRINTX(stderr, "\t fork_flags %s\n",fork_flags);
    PRINTX(stderr, "\t fork_flags_index %d\n",fork_flags_index);
    PRINTX(stderr, "\t fork_flags char %d\n",fork_flags[fork_flags_index] - '0');
    if(fork_flags && !(fork_flags[fork_flags_index++] - '0')) { 
	PRINTX(stderr, "\tnot following child\n");
	//close the sockets and assign them to some garbage. 
	close(outfd);
	close(tokens_fd);
//	close(s); //should I close this? Why wouldn't I? 
	  	    
	outfd = -99999;
	tokens_fd = -99999;
	s = -99999;
#ifdef RECORD_TRACE_INFO
	record_trace_info = false;
#endif
    }
    else { 
	PRINTX(stderr, "\tfollowing child\n");

	//logic to figure out if this is the child we actually want to track: 
	//fork_flags + fork_flags_index is a pointer to the rest of fork_flags

	//if we've reached the end of fork_flags, or there are no more 1's in fork_flags, 
	//start producing output
	if (fork_flags_index >= strlen(fork_flags) || 
	    !strstr((fork_flags + fork_flags_index), "1")) { 

	    produce_output = true;
	}


    }
#else
    /* grab the old file descriptors for things that we're going to have to copy
     * - close the old log, open a new log
     * - copy the filenames file
     * - copy the tokens file
     * - creating a new output file
     * 
     * are there any log files and things that need to be cleaned? 
     */
    int record_pid = get_record_pid();
    int tokens_fd_old = tokens_fd;


    //open new filenames

#ifdef OUTPUT_FILENAME
    FILE* filenames_f_old = filenames_f; 
    char filename_mapping[256];
    snprintf(filename_mapping, 256, "%s/filenames.%d", group_directory, record_pid);
    filenames_f = fopen(filename_mapping, "w");
    if (!filenames_f) {
      fprintf(stderr, "Could not open filenames mapping file %s\n", filename_mapping);
      exit(-1);
    }
    init_filename_mapping(filenames_f);
    copy_file(filenames_f_old, filenames_f); 
    fclose(filenames_f_old);
#endif

    char name[256];
    snprintf(name, 256, "%s/tokens.%d", group_directory, record_pid);
    tokens_fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (tokens_fd == -1) {
      fprintf(stderr, "Could not open tokens file %s\n", name);
      exit(-1);
    }
    copy_file(tokens_fd_old, tokens_fd);    
    close(tokens_fd_old);

    char output_file_name[256];
    snprintf(output_file_name, 256, "%s/dataflow.result.%d", group_directory, record_pid);
    outfd = open(output_file_name, O_CREAT | O_TRUNC | O_LARGEFILE | O_RDWR, 0644);
    if (outfd < 0) {
      fprintf(stderr, "could not open output file %s, errno %d\n", output_file_name, errno);
      exit(-1);
    }

    //copy the files and close the old ones 
    PRINTX(stderr, "\t- record_pid %d\n", record_pid);

#endif

    current_thread->record_pid = get_record_pid();
    // reset syscall index for thread
    current_thread->syscall_cnt = 0; //not ceratin that this is right anymore.. 
}

#ifndef USE_FILE
void AfterForkInParent(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PRINTX(stderr, "%d,%d:AfterForkInParent\n", PIN_GetPid(),get_record_pid());

    //we use the fork_flags to determine which path to follow: 
    //means that the fork_flag was a 1... so we need to make the outfd's all our bs value:
    PRINTX(stderr, "\t fork_flags %s\n",fork_flags);
    PRINTX(stderr, "\t fork_flags_index %d\n",fork_flags_index);
    PRINTX(stderr, "\t fork_flags char %d\n",fork_flags[fork_flags_index] - '0');
    if(fork_flags && fork_flags[fork_flags_index++] - '0' ) { 
	PRINTX(stderr, "\t not following parent\n");

	//no produce_output logic here, it will be dealt with by the last followed
	//fork, or will never be set if forks aren't supposed to be followed

#ifdef USE_NW      
	//close the sockets and assign them to some garbage. 
	close(outfd);
	close(tokens_fd);
#endif 
//	close(s); //shouldn't I close this? 
	outfd = -99999;
	tokens_fd = -99999;
	s = -99999;

#ifdef RECORD_TRACE_INFO
	record_trace_info = false;
#endif
    }
    else { 
	PRINTX(stderr, "\tfollowing parent\n");
    }
}
#endif

#ifdef RETAINT
extern void reset_mem_taints();
void reset_taints ()
{
    struct timeval tv1, tv2;

    gettimeofday(&tv1, NULL);
    fprintf (stderr, "Reset taints begins\n");
    // For testing purposes, reset all the taints to simulate new epoch
    int base = 0;
    for (map<pid_t,struct thread_data*>::iterator iter = active_threads.begin(); 
	 iter != active_threads.end(); iter++) {
	// Not sure that the order matters here for this test...
	for (int i = 0; i < NUM_REGS * REG_SIZE; i++) {
	    iter->second->shadow_reg_table[i] = base+i+1; 
	}
	base += NUM_REGS*REG_SIZE;
    }
    reset_mem_taints();
    splice_output = 1;
    fprintf (stderr, "Reset taints ends\n");
    gettimeofday(&tv2, NULL);
    retaint_us += tv2.tv_usec - tv1.tv_usec;
    retaint_us += (tv2.tv_sec - tv1.tv_sec)*1000000;
}
#endif

void thread_start (THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    struct thread_data* ptdata;
    

    // TODO Use slab allocator
    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    if (ptdata == NULL) {
	fprintf (stderr, "Unable to malloc pdata\n");
	assert (0);
    }
    assert(ptdata);
    memset(ptdata, 0, sizeof(struct thread_data));
    ptdata->threadid = threadid;
    ptdata->app_syscall = 0;
    ptdata->record_pid = get_record_pid();
    get_record_group_id(dev_fd, &(ptdata->rg_id));
    if (recheck_group) {
	ptdata->recheck_handle = open_recheck_log (recheck_group, ptdata->record_pid);
    } else {
	ptdata->recheck_handle = NULL;
    }	
    ptdata->address_taint_set = NULL;

    int thread_ndx;
    long thread_status = set_pin_addr (dev_fd, (u_long) &(ptdata->app_syscall), (u_long) &(ptdata->app_syscall_chk), 
				       ptdata, (void **) &current_thread, &thread_ndx);
    if (!(thread_status&PIN_ATTACH_BLOCKED)) {
	current_thread = ptdata;
    }
    if (thread_status&PIN_ATTACH_REDO) {
	//fprintf (stderr, "Need to redo system call (mmap)\n");
	redo_syscall++;
    }
    PIN_SetThreadData (tls_key, ptdata, threadid);

    if (splice_output && thread_status > 0) {
	int base = (NUM_REGS*REG_SIZE)*thread_ndx;
	for (int i = 0; i < NUM_REGS * REG_SIZE; i++) {
	    ptdata->shadow_reg_table[i] = base+i+1; // For small number of threads, not part of AS
	}
    }

    if (child) {
        restore_state_from_disk(ptdata);
    }

    if (first_thread) {
#ifdef EXEC_INPUTS
        int acc = 0;
        char** args;
        struct taint_creation_info tci;
#endif
        //PIN_AddFollowChildProcessFunction(follow_child, ptdata);
        first_thread = 0;
        if (!ptdata->syscall_cnt) {
            ptdata->syscall_cnt = 1;
        }
#ifdef OUTPUT_FILENAME
        if (!filenames_f) {
            // setup initial maps
            char filename_mapping[256];
            snprintf(filename_mapping, 256, "%s/filenames", group_directory);
            filenames_f = fopen(filename_mapping, "w");
            if (!filenames_f) {
                fprintf(stderr, "Could not open filenames mapping file %s\n", filename_mapping);
                exit(-1);
            }
            init_filename_mapping(filenames_f);
        }
#endif
        if (tokens_fd == -1) {
#ifdef USE_NW
	    tokens_fd = s;
#endif
#ifdef USE_SHMEM
	    char token_file[256];
	    snprintf(token_file, 256, "/tokens_shm%s", group_directory);
	    for (u_int i = 1; i < strlen(token_file); i++) {
		if (token_file[i] == '/') token_file[i] = '.';
	    }
	    tokens_fd = shm_open(token_file, O_CREAT | O_TRUNC | O_RDWR, 0644);
	    if (tokens_fd < 0) {
		fprintf(stderr, "could not open tokens shmem %s, errno %d\n", token_file, errno);
		assert(0);
	    }
	    int rc = ftruncate64 (tokens_fd, MAX_TOKENS_SIZE);
	    if (rc < 0) {
		fprintf(stderr, "could not truncate tokens %s, errno %d\n", token_file, errno);
		assert(0);
	    }
//	    fprintf(stderr, "%d read in tokens_file\n",PIN_GetTid());
#endif



#ifdef USE_FILE
            char name[256];
            snprintf(name, 256, "%s/tokens", group_directory);
            tokens_fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
            if (tokens_fd < 0) {
                fprintf(stderr, "Could not open tokens file %s\n", name);
                exit(-1);
            }
#endif
        }
        if (outfd == -1) {
#ifdef USE_NW
	    outfd = s;
#endif
#ifdef USE_SHMEM
	    char output_file[256];
	    snprintf(output_file, 256, "/dataflow.results_shm%s", group_directory);
	    for (u_int i = 1; i < strlen(output_file); i++) {
		if (output_file[i] == '/') output_file[i] = '.';
	    }
	    outfd = shm_open(output_file, O_CREAT | O_TRUNC | O_RDWR, 0644);
	    if (outfd < 0) {
		fprintf(stderr, "could not open tokens shmem %s, errno %d\n", output_file, errno);
		assert(0);
	    }
	    int rc = ftruncate64 (outfd, MAX_OUT_SIZE);
	    if (rc < 0) {
		fprintf(stderr, "could not truncate tokens %s, errno %d\n", output_file, errno);
		assert(0);
	    }
//	    fprintf(stderr, "%d created dataflow_results\n",PIN_GetTid());

#endif
#ifdef USE_FILE
            char output_file_name[256];
            snprintf(output_file_name, 256, "%s/dataflow.result", group_directory);
            outfd = open(output_file_name, O_CREAT | O_TRUNC | O_LARGEFILE | O_RDWR, 0644);
            if (outfd < 0) {
                fprintf(stderr, "could not open output file %s, errno %d\n", output_file_name, errno);
                exit(-1);
            }
#endif
        } 

        if (trace_x && xoutput_fd == -1) {
            char xoutput_file_name[256];
            snprintf(xoutput_file_name, 256, "%s/xoutput.result", group_directory);
            xoutput_fd = open(xoutput_file_name, O_CREAT | O_TRUNC | O_LARGEFILE | O_RDWR, 0644);
            if (xoutput_fd < 0) {
                fprintf(stderr, "could not open output file %s, errno %d\n", xoutput_file_name, errno);
                exit(-1);
            }
        }

#ifdef EXEC_INPUTS
        args = (char **) get_replay_args (dev_fd);
        tci.rg_id = ptdata->rg_id;
        tci.record_pid = ptdata->record_pid;
        tci.syscall_cnt = ptdata->syscall_cnt;
        tci.offset = 0;
        tci.fileno = FILENO_ARGS;
        tci.data = 0;
	tci.type = 0;
        while (1) {
            char* arg;
            arg = *args;
            // args ends with a NULL
            if (!arg) {
                break;
            }
            fprintf (stderr, "input arg is %s\n", arg);
            tci.offset = acc;
            create_taints_from_buffer(arg, strlen(arg) + 1, &tci, tokens_fd,
                                                            (char *) "EXEC_ARG");
            acc += strlen(arg) + 1;
            args += 1;
        }
        // Retrieve the location of the env. var from the kernel
        args = (char **) get_env_vars (dev_fd);
        LOG_PRINT ("env. vars are %#lx\n", (unsigned long) args);
        tci.fileno = FILENO_ENVP;
        while (1) {
            char* arg;
            arg = *args;
            // args ends with a NULL
            if (!arg) {
                break;
            }
            fprintf ("input arg is %s\n", arg);
            tci.offset = acc;
            create_taints_from_buffer(arg, strlen(arg) + 1, &tci, tokens_fd,
                                                            (char *) "EXEC_ENV");
            acc += strlen(arg) + 1;
            args += 1;
        }
#endif
    }
    active_threads[ptdata->record_pid] = ptdata;
}

void thread_fini (THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, threadid);
    active_threads.erase(tdata->record_pid);
    if (tdata->recheck_handle) close_recheck_log (tdata->recheck_handle);
}

#ifndef NO_FILE_OUTPUT
void init_logs(void)
{
    char log_name[256];
    if (!log_f) {
        snprintf(log_name, 256, "%s/confaid.log.%d",
                group_directory, PIN_GetPid());
        log_f = fopen(log_name, "w");
    	//to std output
	//log_f = stdout;
    }

#ifdef FW_SLICE
    char slice_file_name[256];
    if (!slice_f) { 
	    snprintf (slice_file_name, 256, "%s/slice", group_directory);
	    slice_f = fopen (slice_file_name, "w");
	    assert (slice_f != NULL);
    }
#endif

#ifdef TAINT_DEBUG
    {
        char debug_log_name[256];
        if (!debug_f) {
            snprintf(debug_log_name, 256, "%s/debug_taint", group_directory);
	    debug_f = fopen(debug_log_name, "w");
            if (!debug_f) {
                fprintf(stderr, "could not create debug taint log file, errno %d\n", errno);
                exit(0);
            }
        }
    }
#endif
#ifdef TAINT_STATS
    {
        char stats_log_name[256];
        if (!stats_f) {
            snprintf(stats_log_name, 256, "%s/taint_stats", group_directory);
	    stats_f = fopen(stats_log_name, "w");
            if (!stats_f) {
                fprintf(stderr, "could not create taint stats file, errno %d\n", errno);
                exit(0);
            }
        }
	gettimeofday(&begin_tv, NULL);
    }
#endif
}
#endif

void fini(INT32 code, void* v)
{
    dift_done ();
}

#ifdef TRACE_INST
VOID ImageLoad (IMG img, VOID *v)
{
    uint32_t id = IMG_Id (img);

    ADDRINT load_offset = IMG_LoadOffset(img);
    ADDRINT low_addr = IMG_LowAddress(img);
    ADDRINT high_addr = IMG_HighAddress(img);
    USIZE size  = IMG_SizeMapped(img);
    
    fprintf(stderr, "[IMG] Loading image id %d, name %s with load offset %#x, size %u, (%#x, %#x)\n",
            id, IMG_Name(img).c_str(), load_offset, size, low_addr, high_addr);
}
#endif

int get_open_file_descriptors ()
{
    struct open_fd ofds[4096];
    long rc = get_open_fds (dev_fd, ofds, 4096);
#ifdef TAINT_DEBUG      
	fprintf (debug_f, "get_open_file_desciptors returns %ld\n", rc);
#endif
    
    if (rc < 0) {
	fprintf (stderr, "get_open_file_desciptors returns %ld\n", rc);
	return rc;
    }

    for (long i = 0; i < rc; i++) {
#ifdef TAINT_DEBUG
	int fd = -1;
#endif
	if (ofds[i].type == OPEN_FD_TYPE_FILE) {
	    struct open_info* oi = (struct open_info *) malloc (sizeof(struct open_info));
	    strcpy (oi->name, ofds[i].channel);
	    oi->flags = 0;
	    oi->fileno = 0;
	    monitor_add_fd(open_fds, ofds[i].fd, 0, oi);
#ifdef TAINT_DEBUG	    
	    fd = ofds[i].fd;
#endif
	} else if (ofds[i].type == OPEN_FD_TYPE_SOCKET) {
	    struct socket_info* si = (struct socket_info *) malloc (sizeof(struct socket_info));
	    si->domain = ofds[i].data;
	    si->type = -1;
	    si->protocol = -1;
	    si->fileno = -1; 
	    si->ci = NULL;
	    monitor_add_fd(open_socks, ofds[i].fd, 0, si);
#ifdef TAINT_DEBUG
	    fd = ofds[i].fd;
#endif
	}
#ifdef TAINT_DEBUG
	fprintf (debug_f, "get_open_fds %d\n",fd);
#endif	
	
    }
    return 0;
}

//hack for malloc function
//Here, we add an assertion to make sure the input to malloc will remain the same the next time we re-execute the slice
//and untaint the input (size of memory region to be allocated)
TAINTSIGN before_function_call(ADDRINT name, ADDRINT rtn_addr, ADDRINT arg0, ADDRINT esp_value)
{
	//the input is stored at esp-0x2c+0x30=esp+0x4, calculated from the malloc code
	u_long addr = esp_value+0x4;
	//victim = _int_malloc(ar_ptr, bytes); malloc.c :2938
	if (strcmp ((char*)name, "linemap_add")) {
		if (strcmp ((char*)name, "_cpp_lex_direct") && strcmp((char*)name, "_cpp_clean_line")) {
			printf("Before call to %s (%#x), arg %u(hex %x), stack pointer %x, name pointer %x\n", (char *) name, rtn_addr, arg0, arg0, esp_value, name);
			/*if (*ppthread_log_clock >=170) { 
				long* tmp = (long*) 0xb7e37020;
				printf ("content b7e37020 is %ld\n", *tmp);
			}*/
		} 
		if (*ppthread_log_clock >= 86*2 && arg0 == 0xbae4db8) {
			long arg_buf = *((long*) arg0);
			taint_t* t = NULL;
			printf("Before call to %s (%#x), arg %u(hex %x), arg->buf->buf (%lx), stack pointer %x, name pointer %x\n", (char *) name, rtn_addr, arg0, arg0, *(long*)(*((long*) arg0)), esp_value, name);
			t = get_mem_taints (arg_buf, 4);
			if (t) {
				if (t[0] || t[1] || t[2] || t[3]) {
					printf ("argbuf is tainted: %d, %d, %d, %d\n", t[0], t[1], t[2], t[3]);
				}
			}

		}
	} else
		printf("Before call to %s (%#x), arg %u(hex %x) %s, stack pointer %x, name pointer %x\n", (char *) name, rtn_addr, arg0, arg0, (char*) arg0, esp_value, name);
	//print slice
	//untaint 
	//malloc
	if (!strcmp((char*)name, "malloc")) {
		clear_mem_taints (addr, 4);
		clear_mem_taints (addr-0x4+0x2c, 4);
		clear_reg (LEVEL_BASE::REG_EDI, 4);
		clear_reg (LEVEL_BASE::REG_ESP, 4);
		printf ("input size is %d\n", *(int*)addr);
	}
	//for _int_malloc
	//esp-0x4*4-0x8c=esp-0x9c
	if (!strcmp((char*)name, "_int_malloc")) {
		clear_reg (LEVEL_BASE::REG_EAX, 4);
		clear_mem_taints (addr-0x4-0x9c, 4);
		printf ("input size is %d\n", *(int*)addr);
	}
	//for free clear arg0-0x4
	if (!strcmp((char*)name, "free")) {
		clear_mem_taints (addr, 4);
		clear_mem_taints ((u_long) arg0 -0x4, 4);
	}
	//output for token len
	if (!strcmp ((char*) name, "cpp_token_len")) { 
		unsigned int len = *(unsigned int*) (arg0+8);
		printf ("cpp_token_len src_loc %u, %lx, %s, len %u\n", *((unsigned int*) arg0), *(long*) (arg0+12), (char*)(*(long*) (arg0+12)), *(unsigned int*) (arg0+8));

		if (len > 10000)
			printf ("cpp_token_len src_loc %u, %lx, %s, len %u, ident: %s, %lx\n", *((unsigned int*) arg0), *(long*) (arg0+12), (char*)(*(long*) (arg0+12)), *(unsigned int*) (arg0+8), (char*)(*(long*)len), *(long*)(*(long*) (arg0+8)));
	}

	if (!strcmp ((char*) name, "__strlen_ia32")) {
		printf ("strlen: %s\n", (char*) arg0);
	}
	if (!strcmp ((char*) name, "htab_hash_string")) { 
//TODO: for repz, we probably need the exact number of iterations, which is supported with scan_string
		char* fname = (char*) arg0;
		unsigned int i = 0;
		int tainted = 0;
		for (; i<strlen(fname); ++i) {
			taint_t* t = get_mem_taints(arg0+i, 1);
			if (t) {
				if (*t) tainted = 1;
			}
		}
		printf ("htab_hash_string: %s, tainted %d\n", fname, tainted);
	}

}

TAINTSIGN after_function_call(ADDRINT name, ADDRINT rtn_addr, ADDRINT eax_value)
{
	printf("After call to %s (%#x), eax value %x\n", (char *) name, rtn_addr, eax_value);
	//print slice
	//untaint 
	if (!strcmp ((char*) name, "malloc") || !strcmp((char*) name, "_int_malloc") || !strcmp ((char*) name, "_cpp_unaligned_alloc") || !strcmp ((char*)name, "_cpp_aligned_alloc"))
		clear_reg (LEVEL_BASE::REG_EAX, 4);
	if (eax_value == 0xbae67b0) { 
		taint_t* t = get_mem_taints (0xbae67b0, 4);
		if (t)
			printf ("address bae67b0 is tainted: %d, %d, %d, %d\n", t[0], t[1], t[2], t[3]);
		else 
			printf ("address bae67b0 is not tainted: 0\n");
	} else { 
		taint_t* t = &(current_thread->shadow_reg_table[LEVEL_BASE::REG_EAX*REG_SIZE]);
		printf ("eax tainted %d %d %d %d, %d \n", t[0], t[1], t[2], t[3], current_thread->shadow_reg_table[LEVEL_BASE::REG_EAX*REG_SIZE]);
	}
	if (!strcmp ((char*) name, "parse_include")) {
		char* fname = (char*)eax_value;
		unsigned int i = 0;
		int tainted = 0;
		for (; i<strlen(fname); ++i) {
			taint_t* t = get_mem_taints(eax_value+i, 1);
			if (t) {
				if (*t) tainted = 1;
			}
		}
		printf ("parse_include: %s, tainted %d\n", fname, tainted);
	}
	/*if (!strcmp ((char*)name, "cpp_get_token") || !strcmp ((char*)name, "_cpp_lex_token")) {
		unsigned int i = 0;
		int tainted = 0;
		unsigned int len = *(unsigned int*) (eax_value+8);
		for (; i<16; ++i) {
			taint_t* t = get_mem_taints(eax_value+i, 1);
			if (t) {
				if (*t) tainted = 1;
			}
		}
		printf ("cpp_get_token, _cpp_lex_token, tainted %d\n", tainted);
		printf ("src_loc %u, %lx, %s, len %u\n", *((unsigned int*) eax_value), *(long*) (eax_value+12), (char*)(*(long*) (eax_value+12)), *(unsigned int*) (eax_value+8));

		if (len > 10000)
			printf ("src_loc %u, %lx, %s, len %u, ident: %s, %lx\n", *((unsigned int*) eax_value), *(long*) (eax_value+12), (char*)(*(long*) (eax_value+12)), *(unsigned int*) (eax_value+8), (char*)(*(long*)len), *(long*)(*(long*) (eax_value+8)));

	}*/
}

void routine (RTN rtn, VOID *v)
{
    char *name;

    const char* tmp = RTN_Name(rtn).c_str();
    assert (tmp != NULL);
    name = (char*) malloc (strlen (tmp) + 1);
    strcpy (name, tmp);

    /*if (strcmp (name, "malloc") && strcmp(name, "free") && strcmp(name, "_int_malloc") && strcmp(name, "calloc")
		    && strcmp (name, "realloc") && strcmp (name, "memalign") && strcmp(name, "valloc") 
		    && strcmp (name, "pvalloc") && strcmp(name, "linemap_add") && strcmp (name, "_cpp_lex_direct") && strcmp (name, "_cpp_clean_line")) {
	    return;
    }*/

    RTN_Open(rtn);

    if (!strcmp (name, "linemap_add")) {
	    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)before_function_call,
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_PTR, name, 
			    IARG_ADDRINT, RTN_Address(rtn), 
			    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			    IARG_REG_VALUE, LEVEL_BASE::REG_ESP,
			    IARG_END);
    } else if (!strcmp(name, "__memcpy_ssse3_rep")) {
	    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)before_function_call,
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_PTR, name, 
			    IARG_ADDRINT, RTN_Address(rtn), 
			    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			    IARG_REG_VALUE, LEVEL_BASE::REG_ESP,
			    IARG_END);
    } else
	    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)before_function_call,
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_PTR, name, 
			    IARG_ADDRINT, RTN_Address(rtn), 
			    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			    IARG_REG_VALUE, LEVEL_BASE::REG_ESP,
			    IARG_END);


    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)after_function_call,
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_PTR, name, 
		    IARG_ADDRINT, RTN_Address(rtn), 
		    IARG_REG_VALUE, LEVEL_BASE::REG_EAX,
		    IARG_END);

    RTN_Close(rtn);
}

int main(int argc, char** argv) 
{    
    int rc;
    const char* tmp_filename = NULL;

    // This is a very specific trick to figure out if we're a child or not
    if (!strcmp(argv[4], "--")) { // pin injected into forked process
        child = 1;
    } else { // pin attached to replay process
        child = 0;
    }

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        fprintf(stderr, "ERROR: could not initialize Pin?\n");
        exit(-1);
    }

    tls_key = PIN_CreateThreadDataKey(0);

    // Intialize the replay device
    rc = devspec_init (&dev_fd);
    if (rc < 0) return rc;
    global_syscall_cnt = 0;

    /* Create a directory for logs etc for this replay group*/
    tmp_filename = KnobGroupDirectory.Value().c_str();
    if (tmp_filename && strlen(tmp_filename) > 0)  
	    strcpy (group_directory, tmp_filename);
    else 
    	snprintf(group_directory, 256, "/tmp/%d", PIN_GetPid());
#ifndef NO_FILE_OUTPUT
    if (mkdir(group_directory, 0755)) {
        if (errno == EEXIST) {
            fprintf(stderr, "directory already exists, using it: %s\n", group_directory);
        } else {
            fprintf(stderr, "could not make directory %s\n", group_directory);
            exit(-1);
        }
    }
#endif

    // Read in command line args
    trace_x = KnobTraceX.Value();
    print_all_opened_files = KnobRecordOpenedFiles.Value();
    filter_read_filename = KnobFilterReadFile.Value().c_str();
    segment_length = KnobSegmentLength.Value();
    splice_output = KnobSpliceOutput.Value();
    all_output = KnobAllOutput.Value();
    fork_flags = KnobForkFlags.Value().c_str();
    checkpoint_clock = KnobCheckpointClock.Value();
    if (checkpoint_clock == 0) 
	    checkpoint_clock = UINT_MAX;
    recheck_group = KnobRecheckGroup.Value();

#ifdef RETAINT
    retaint = KnobRetaintEpochs.Value().c_str();
    retaint_str = (char *) retaint;
    char* p;
    for (p = retaint_str; *p != '\0' && *p != ','; p++);
    *p = '\0';
    retaint_next_clock = strtoul(retaint_str, NULL, 10);
    fprintf (stderr, "Next epoch to retaint: %lu\n", retaint_next_clock);
    retaint_str = p+1;
#endif      
    
#ifdef RECORD_TRACE_INFO
    record_trace_info = KnobRecordTraceInfo.Value();
#endif
    fork_flags_index = 0;   

    /*
     * if there are fork_flags (non-null and len > 0), 
     * and there is a 1 in the fork_flags, we shouldn't start 
     * producing output right away (until we get to the point where
     * we stop following forks). 
     */

    if (fork_flags && strlen(fork_flags) &&
	strstr(fork_flags, "1")) { 

	produce_output = false;
    }

    if (KnobMergeEntries.Value() > 0) {
	num_merge_entries = KnobMergeEntries.Value();
    }

    if (!open_fds) {
        open_fds = new_xray_monitor(sizeof(struct open_info));
    }
    if (!open_socks) {
        open_socks = new_xray_monitor(sizeof(struct socket_info));
    }
    if (!open_x_fds) {
        open_x_fds = new_xray_monitor(0);
    }

#ifndef NO_FILE_OUTPUT
    init_logs();
#endif

    // Determine open file descriptors for filters
    if (splice_output) get_open_file_descriptors();

#ifndef RETAINT
#if defined(USE_NW) || defined(USE_SHMEM)
    // Open a connection to the 64-bit consumer process
    const char* hostname = KnobNWHostname.Value().c_str();
    int port = KnobNWPort.Value();
    
    struct hostent* hp = gethostbyname (hostname);
    if (hp == NULL) {
	fprintf (stderr, "Invalid host %s, errno=%d\n", hostname, h_errno);
	return -1;
    }

    s = socket (AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	fprintf (stderr, "Cannot create socket, errno=%d\n", errno);
	return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy (&addr.sin_addr, hp->h_addr, hp->h_length);

    int tries = 0;
    do {
	rc = connect (s, (struct sockaddr *) &addr, sizeof(addr));
	if (rc < 0) {
	    tries++;
	    usleep(1000);
	}
    } while (rc < 0 && tries <=100); //whats the punishment for increasing tries here? 

    if (rc < 0) {
	fprintf (stderr, "Cannot connect to socket (host %s, port %d), errno=%d\n", hostname, port, errno);
	return -1;
    }

#endif
#endif

    init_taint_structures(group_directory);

    // Try to map the log clock for this epoch
    ppthread_log_clock = map_shared_clock(dev_fd);
    //printf ("Log clock is %p, value is %ld\n", ppthread_log_clock, *ppthread_log_clock);

    //fprintf(stderr, "starting init_slab_allocs\n");
    init_slab_allocs();
    // how about 1000 opened files...ever?
    new_slab_alloc((char *)"OPEN_ALLOC", &open_info_alloc, sizeof(struct open_info), 1000);
    // shouldn't expect for than 100 threads?
    new_slab_alloc((char *)"THREAD_ALLOC", &thread_data_alloc, sizeof(struct thread_data), 100);

    if (!child) {
        // input filters
        init_filters();
        set_filter_inputs(KnobFilterInputs.Value());
        if (filter_input()) {
            for (unsigned i = 0; i < KnobFilterInputFiles.NumberOfValues(); i++) {
                add_input_filter(FILTER_FILENAME,
                        (void *) KnobFilterInputFiles.Value(i).c_str());
            }
            for (unsigned i = 0; i < KnobFilterInputSyscalls.NumberOfValues(); i++) {
                add_input_filter(FILTER_SYSCALL,
                        (void *) KnobFilterInputSyscalls.Value(i).c_str());
            }
            for (unsigned i = 0; i < KnobFilterInputPartFilename.NumberOfValues(); i++) {
                add_input_filter(FILTER_PARTFILENAME,
                        (void *) KnobFilterInputPartFilename.Value(i).c_str());
            }
            for (unsigned i = 0; i < KnobFilterInputRegex.NumberOfValues(); i++) {
                add_input_filter(FILTER_REGEX,
                        (void *) KnobFilterInputRegex.Value(i).c_str());
            }
            for (unsigned i = 0; i < KnobFilterByteRange.NumberOfValues(); i++) {
                add_input_filter(FILTER_BYTERANGE,
                        (void *) KnobFilterByteRange.Value(i).c_str());
            }
            if (filter_read_filename && strlen(filter_read_filename) > 0) {
                build_filters_from_file(filter_read_filename);
            }
        }

        // output filters
	filter_outputs_before = KnobFilterOutputsBefore.Value();
	if (filter_outputs_before) {
	    fprintf (stderr, "Filtering to outputs on or after %lu\n", filter_outputs_before);
	}
        if (trace_x) {
	    set_filter_outputs(1, -1);
	}
    }

    PIN_AddThreadStartFunction(thread_start, 0);
    PIN_AddThreadFiniFunction(thread_fini, 0);
    PIN_AddFiniFunction(fini, 0);

    main_prev_argv = argv;

    TRACE_AddInstrumentFunction (trace_instrumentation, 0);

    // Register a notification handler that is called when the application
    // forks a new process
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);


#ifndef USE_FILE
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, AfterForkInParent, 0);
#endif

    if (trace_x) {
	// Right now, only used when this config variable set
	RTN_AddInstrumentFunction(track_function, 0);
    }

#ifdef RECORD_TRACE_INFO
    if (record_trace_info) init_trace_buf();
#endif

#if 0
    IMG_AddInstrumentFunction (ImageLoad, 0);
#endif

    PIN_AddSyscallExitFunction(instrument_syscall_ret, 0);
#if 0
    RTN_AddInstrumentFunction (routine, 0);
#endif
    PIN_SetSyntaxIntel();

    PIN_StartProgram();

    return 0;
}
