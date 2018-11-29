#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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
#include <poll.h>
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
#include <sys/prctl.h>
#include <bitset>

#include <map>
using namespace std;

#include "util.h" 
#include "list.h"
#include "linkage_common.h"
#include "taint_interface/taint_interface.h"
#include "taint_interface/taint_creation.h"
#include "xray_monitor.h"
#include "xray_token.h"
#include "xray_slab_alloc.h"
#include "splice.h"
#include "taint_nw.h"
#include "recheck_log.h"
#include "mmap_regions.h"

#define PIN_NORMAL         0
#define PIN_ATTACH_RUNNING 1
#define PIN_ATTACH_BLOCKED 2
#define PIN_ATTACH_REDO    4

u_int redo_syscall = 0;

#if defined(USE_NW) || defined(USE_SHMEM)
int s = -1;
#endif

//#define LOGGING_ON
#define LOG_F log_f
#define ERROR_PRINT fprintf

/* Set this to clock value where extra logging should begin */
//#define EXTRA_DEBUG 0
//#define EXTRA_DEBUG_STOP 12506617 
//#define EXTRA_DEBUG_FUNCTION
//9100-9200 //718800-718900

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
#else
 #define LOG_PRINT(x,...);
 #define INSTRUMENT_PRINT(x,...);
 #define PRINTX(x,...);
#endif

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
struct thread_data* previous_thread; // used for tracking thread switching
pid_t first_thread = 0;
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
int xoutput_fd = -1;
unsigned long long inst_count = 0; //this is only used for getting benchmark numbers
unsigned long long total_syscall_cnt = 0; //this is only used for getting benchmark numbers
extern unsigned long handled_jump_divergence;
extern unsigned long handled_index_divergence;
int filter_x = 0;
int filter_inputs = 0;
int print_all_opened_files = 0;
bool function_level_tracking = false;
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
extern map<string, ADDRINT> pthread_operation_addr; 
u_long* ppthread_log_clock = NULL;
u_long filter_outputs_before = 0;  // Only trace outputs starting at this value
const char* check_filename = "/tmp/checks";
extern u_long jump_count;
u_long dumbass_link_addr = 0;
u_long pthread_log_status_addr = 0;
pthread_funcs recall_funcs;

//added for multi-process replay
const char* fork_flags = NULL;
u_int fork_flags_index = 0;
bool produce_output = true; 

struct slab_alloc open_info_alloc;
struct slab_alloc thread_data_alloc;

#if 0
//an old function that buffers slice output
inline void output_slice (struct thread_data* tdata, const char* format, ...) 
{
    char output_slice_buf[512];
    va_list arglist;
    va_start (arglist, format);
    int length = vsnprintf (output_slice_buf, 512, format, arglist);
    va_end (arglist);

    assert (length != 511);  //make sure we don't truncate the message because of buffer size limits
    printf ("%s", output_slice_buf); 
    if (tdata->slice_buffer) { 
        tdata->slice_buffer->push (string(output_slice_buf)); 
        if (tdata->slice_buffer->size() > 1024) {  //write into file
            while (!tdata->slice_buffer->empty()) {  
                string s = tdata->slice_buffer->front(); 
                int ret = write (tdata->slice_output_file, s.c_str(), s.length());
                assert (ret == (int)s.length());
                tdata->slice_buffer->pop ();
            }
            fsync (tdata->slice_output_file); 
        }
    } 
}
#endif

//tdata: the previous thread that has to wait 
static inline void slice_thread_wait (struct thread_data* tdata) 
{
    if (!current_thread->start_tracking) return;
    OUTPUT_SLICE_THREAD (tdata, 0, "pushfd");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    //necessary: preserve registers before function calls
    OUTPUT_SLICE_THREAD (tdata, 0, "push eax");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "push ecx");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "push edx");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "push %d", tdata->record_pid); 
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "call recheck_thread_wait");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "add esp, 4");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);

    OUTPUT_SLICE_THREAD (tdata, 0, "pop edx");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "pop ecx");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "pop eax");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "popfd");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
}

//tdata: the previous thread that has to wakes up the current thread (with record pid as wakeup_record_pid)
static inline void slice_thread_wakeup (struct thread_data* tdata, int wakeup_record_pid) 
{
    if (!current_thread->start_tracking) return;
    OUTPUT_SLICE_THREAD (tdata, 0, "pushfd");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "push eax");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "push ecx");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "push edx");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);

    OUTPUT_SLICE_THREAD (tdata, 0, "push %d", wakeup_record_pid); 
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "call recheck_thread_wakeup");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "add esp, 4");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);

    OUTPUT_SLICE_THREAD (tdata, 0, "pop edx");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "pop ecx");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "pop eax");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
    OUTPUT_SLICE_THREAD (tdata, 0, "popfd");
    OUTPUT_SLICE_INFO_THREAD (tdata, "slice ordering, clock %lu, prev pid %d, next pid %d", *ppthread_log_clock, tdata->record_pid, current_thread->record_pid);
}

static inline void slice_synchronize (struct thread_data* main_thread, struct thread_data* other_thread)
{
    OUTPUT_MAIN_THREAD (main_thread, "pushfd");
    OUTPUT_MAIN_THREAD (main_thread, "push eax");
    OUTPUT_MAIN_THREAD (main_thread, "push ecx");
    OUTPUT_MAIN_THREAD (main_thread, "push edx");
    OUTPUT_MAIN_THREAD (main_thread, "push %d", other_thread->record_pid); 
    OUTPUT_MAIN_THREAD (main_thread, "call recheck_thread_wakeup");
    OUTPUT_MAIN_THREAD (main_thread, "add esp, 4");
    OUTPUT_MAIN_THREAD (main_thread, "push %d", main_thread->record_pid); 
    OUTPUT_MAIN_THREAD (main_thread, "call recheck_thread_wait");
    OUTPUT_MAIN_THREAD (main_thread, "add esp, 4");
    OUTPUT_MAIN_THREAD (main_thread, "pop edx");
    OUTPUT_MAIN_THREAD (main_thread, "pop ecx");
    OUTPUT_MAIN_THREAD (main_thread, "pop eax");
    OUTPUT_MAIN_THREAD (main_thread, "popfd");
}

static inline void main_file_thread_wait (struct thread_data* tdata) 
{
    OUTPUT_MAIN_THREAD (tdata, "pushfd");
    OUTPUT_MAIN_THREAD (tdata, "push eax");
    OUTPUT_MAIN_THREAD (tdata, "push ecx");
    OUTPUT_MAIN_THREAD (tdata, "push edx");
    OUTPUT_MAIN_THREAD (tdata, "push %d", tdata->record_pid); 
    OUTPUT_MAIN_THREAD (tdata, "call recheck_thread_wait");
    OUTPUT_MAIN_THREAD (tdata, "add esp, 4");
    OUTPUT_MAIN_THREAD (tdata, "pop edx");
    OUTPUT_MAIN_THREAD (tdata, "pop ecx");
    OUTPUT_MAIN_THREAD (tdata, "pop eax");
    OUTPUT_MAIN_THREAD (tdata, "popfd");
}

static inline void main_file_thread_wakeup (struct thread_data* tdata, int wakeup_record_pid) 
{
    OUTPUT_MAIN_THREAD (tdata, "pushfd");
    OUTPUT_MAIN_THREAD (tdata, "push eax");
    OUTPUT_MAIN_THREAD (tdata, "push ecx");
    OUTPUT_MAIN_THREAD (tdata, "push edx");
    OUTPUT_MAIN_THREAD (tdata, "push %d", wakeup_record_pid); 
    OUTPUT_MAIN_THREAD (tdata, "call recheck_thread_wakeup");
    OUTPUT_MAIN_THREAD (tdata, "add esp, 4");
    OUTPUT_MAIN_THREAD (tdata, "pop edx");
    OUTPUT_MAIN_THREAD (tdata, "pop ecx");
    OUTPUT_MAIN_THREAD (tdata, "pop eax");
    OUTPUT_MAIN_THREAD (tdata, "popfd");
}

		
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
    "specifies the group for the recheck log and the slice output file (if not specified, then don't generate log and only print slice to stdout)");
KNOB<string> KnobGroupDirectory(KNOB_MODE_WRITEONCE, 
    "pintool", "group_dir", "",
    "the directory for the output files");
KNOB<string> KnobCheckFilename(KNOB_MODE_WRITEONCE, 
    "pintool", "chk", "",
    "a file with allowed control and data flow divergences");
KNOB<bool> KnobFunctionLevel (KNOB_MODE_WRITEONCE, 
        "pintool", "fl", "", 
        "Run the pintool in fine granularities and generated patch-based checkpoints");

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
#endif

static int terminated = 0;
extern int dump_mem_taints (int fd);
extern int dump_reg_taints (int fd, taint_t* pregs, int thread_ndx);
extern int dump_mem_taints_start (int fd);
extern int dump_reg_taints_start (int fd, taint_t* pregs, int thread_ndx);
extern taint_t taint_num;
extern vector<struct ctrl_flow_param> ctrl_flow_params;
extern vector<struct check_syscall> ignored_syscall;
extern map<u_long,syscall_check> syscall_checks;

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
#endif

extern void write_token_finish (int fd);
extern void output_finish (int fd);

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
    fprintf (stderr, "inst count %llu, syscall cnt %llu, handled jump divergence %lu, handled index divergence %lu\n", inst_count, total_syscall_cnt, handled_jump_divergence, handled_index_divergence); 

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
#ifdef TAINT_STATS
#ifndef USE_FILE
    if (tokens_fd != -99999 && outfd != -99999 && s != -99999) { 
#else
    if (tokens_fd != -99999 && outfd != -99999) { 
#endif
	gettimeofday(&end_tv, NULL);
	fprintf (stats_f, "Instructions instrumented: %ld\n", inst_instrumented);
	fprintf (stats_f, "Traces instrumented: %ld\n", traces_instrumented);
	fprintf (stats_f, "Instrument time: %lld us\n", instrument_time);

	fprintf (stats_f, "DIFT began at %ld.%06ld\n", begin_tv.tv_sec, begin_tv.tv_usec);
	fprintf (stats_f, "DIFT ended at %ld.%06ld\n", end_tv.tv_sec, end_tv.tv_usec);

	fprintf (stats_f, "mmap_len %lu\n",mm_len);

	finish_and_print_taint_stats(stats_f);
	fclose (stats_f);
    }

#else
    finish_and_print_taint_stats(stdout);
#endif

    fprintf(stderr, "DIFT done at %ld\n", *ppthread_log_clock);

#ifdef USE_SHMEM
    // Send "done" message to aggregator
    if (s != -99999) {
	int rc = write (s, &group_directory, sizeof(group_directory));
	if (rc != sizeof(group_directory)) {
	    fprintf (stderr, "write of directory failed, rc=%d, errno=%d\n", rc, errno);
	}
    }
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

static inline void detect_slice_ordering (int syscall_num) 
{
    // ignore pthread syscalls, or deterministic system calls that we don't log (e.g. 123, 186, 243, 244)
    if (!(syscall_num == 17 || syscall_num == 31 || syscall_num == 32 || 
                syscall_num == 35 || syscall_num == 44 || syscall_num == 53 || 
                syscall_num == 56 || syscall_num == 58 || syscall_num == 98 || 
                syscall_num == 119 || syscall_num == 123 || syscall_num == 127 ||
                syscall_num == 186 || syscall_num == 243 || syscall_num == 244)) {
        if (current_thread != previous_thread) { 
            //well, a thread switch happens and this thread now executes
            if ((current_thread->ignore_flag && !(*(int *)(current_thread->ignore_flag))) || !current_thread->ignore_flag) {
                //previous thread needs to sleep and wakes up this thread
                slice_thread_wakeup (previous_thread, current_thread->record_pid);
                slice_thread_wait (previous_thread);

                previous_thread = current_thread;
            } else if (current_thread->ignore_flag && (*(int*)(current_thread->ignore_flag))) {
                DEBUG_INFO ("[SLICE_DEBUG] skip syscall for calculating expected clock, sys num %d, pid %d\n", syscall_num, current_thread->record_pid);
            }
        }
    } else { 
        DEBUG_INFO ("[SLICE_DEBUG] skip syscall for calculating expected clock, sys num %d, pid %d\n", syscall_num, current_thread->record_pid);
    }
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
	fprintf (debug_f, "pid %d syscall %d global syscall cnt %lu num %d clock %ld\n", current_thread->record_pid, 
		 current_thread->syscall_cnt, global_syscall_cnt, syscall_num, *ppthread_log_clock);
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

static inline void sys_execve_start(struct thread_data* tdata, char* filename, char** argv, char** envp)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call execve_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	long retval = recheck_execve (tdata->recheck_handle, filename, argv, envp, *ppthread_log_clock);
	if (retval == 0) { // This means exec should not return
	    fw_slice_print_footer (tdata, 0, 0);
	    close_recheck_log (tdata->recheck_handle); 
	}
    }
}

static inline void sys_open_start(struct thread_data* tdata, char* filename, int flags, int mode)
{
    struct open_info* oi = (struct open_info *) malloc (sizeof(struct open_info));
    strncpy(oi->name, filename, OPEN_PATH_LEN);
    oi->fileno = open_file_cnt;
    oi->flags = flags;
    open_file_cnt++;
    tdata->save_syscall_info = (void *) oi;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "push edx");
	OUTPUT_SLICE_INFO ("");
	OUTPUT_SLICE (0, "push ecx");
	OUTPUT_SLICE_INFO ("");
	OUTPUT_SLICE (0, "call open_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	OUTPUT_SLICE (0, "pop ecx");
	OUTPUT_SLICE_INFO ("");
	OUTPUT_SLICE (0, "pop edx");
	OUTPUT_SLICE_INFO ("");
	recheck_open (tdata->recheck_handle, filename, flags, mode, *ppthread_log_clock);
    } 
}

static inline void sys_open_stop(int rc)
{
    if (rc > 0) {
        monitor_add_fd(open_fds, rc, 0, current_thread->save_syscall_info);
    }
    current_thread->save_syscall_info = NULL;
}

static inline void sys_openat_start (struct thread_data* tdata, int dirfd, char* filename, int flags, int mode) {
    struct open_info* oi = (struct open_info*) malloc (sizeof(struct open_info));
    strncpy (oi->name, filename, OPEN_PATH_LEN);
    oi->fileno = open_file_cnt ++;
    oi->flags = flags;
    oi->dirfd = dirfd;
    tdata->save_syscall_info = (void*) oi;
    if (tdata->recheck_handle) { 
	OUTPUT_SLICE (0, "call openat_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
        recheck_openat (tdata->recheck_handle, dirfd, filename, flags, mode, *ppthread_log_clock);
    }
}

static inline void sys_openat_stop (int rc) { 
    return sys_open_stop (rc);
}

static inline void sys_close_start(struct thread_data* tdata, int fd)
{
    tdata->save_syscall_info = (void *) fd;
    if (tdata->recheck_handle) {
	if (!current_thread->ignore_flag || !(*(int *)(current_thread->ignore_flag))) {
	    OUTPUT_SLICE (0, "call close_recheck");
	    OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	    recheck_close (tdata->recheck_handle, fd, *ppthread_log_clock);
	} else {
	    printf ("close occurred during ignore region of the replay code\n");
	}
    }
}

static inline void sys_waitpid_start(struct thread_data* tdata, pid_t pid, int* status, int options)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call waitpid_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_waitpid (tdata->recheck_handle, pid, status, options, *ppthread_log_clock);
    }
}

static inline void sys_dup2_start(struct thread_data* tdata, int oldfd, int newfd)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call dup2_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_dup2 (tdata->recheck_handle, oldfd, newfd, *ppthread_log_clock);
    }
}

static inline void sys_close_stop(int rc)
{
    int fd = (int) current_thread->save_syscall_info;
    // remove the fd from the list of open files
    if (!rc) {
        if (monitor_has_fd(open_fds, fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, fd);
	    free (oi);
            monitor_remove_fd(open_fds, fd);
        } 
	if (monitor_has_fd(open_socks, fd)) {
		monitor_remove_fd(open_socks, fd);
	}
    }
    current_thread->save_syscall_info = 0;
}

static inline void sys_llseek_start(struct thread_data* tdata, u_int fd, u_long offset_high, u_long offset_low, loff_t* result, u_int whence)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call llseek_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_llseek (tdata->recheck_handle, fd, offset_high, offset_low, result, whence, *ppthread_log_clock);
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
    struct read_info* ri = &tdata->op.read_info_cache;
    ri->fd = fd;
    ri->buf = buf;
    ri->size = size;
    ri->clock = *ppthread_log_clock;
    ri->recheck_handle = tdata->recheck_handle;
    tdata->save_syscall_info = (void *) ri;
}

static inline void sys_read_stop(int rc)
{
    int read_fileno = -1;
    struct read_info* ri = (struct read_info*) &current_thread->op.read_info_cache;

    map<u_long,struct syscall_check>::iterator it = syscall_checks.find(ri->clock);
    long max_taint = 0;
    if (it != syscall_checks.end()) {
	printf ("Record found, type=%lu, clock=%lu, value=%ld\n", it->second.type, it->second.clock, it->second.value);
	max_taint = it->second.value;
    }


    if (check_is_syscall_ignored (current_thread->record_pid, current_thread->syscall_cnt)) {
        fprintf (stderr, "Syscall is ignored during rechecking, read syscall, pid %d, index %d, rc %d\n", current_thread->record_pid, current_thread->syscall_cnt, rc);            
        recheck_read_ignore (ri->recheck_handle);
    } else { 
        if (ri->recheck_handle) {
            OUTPUT_SLICE (0, "push edx");
            OUTPUT_SLICE_INFO ("");
            OUTPUT_SLICE (0, "call read_recheck");
            OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
            OUTPUT_SLICE (0, "pop edx");
            OUTPUT_SLICE_INFO ("");
                if (filter_input()) {
                    size_t start = 0;
                    size_t end = 0;
                    if (get_partial_taint_byte_range(current_thread->record_pid, current_thread->syscall_cnt, &start, &end)) {
                        recheck_read (ri->recheck_handle, ri->fd, ri->buf, ri->size, 1, start, end, max_taint, ri->clock);
                        add_modified_mem_for_final_check ((u_long) (ri->buf+start), end-start);
			OUTPUT_TAINT_INFO_THREAD (current_thread, "read %lx %lx", (u_long) ri->buf+start, (u_long) end-start);  
		    } else {
			recheck_read (ri->recheck_handle, ri->fd, ri->buf, ri->size, 0, 0, 0, max_taint, ri->clock);
                    }
                } else {
                    recheck_read (ri->recheck_handle, ri->fd, ri->buf, ri->size, 0, 0, 0, max_taint, ri->clock);
                }
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

        if (current_thread->start_tracking) {
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
            if (rc > 0) clear_mem_taints ((u_long)ri->buf, rc);
            tci.fileno = -1;
            tci.type = TOK_READ_RET;
            if (max_taint > 0) {
                create_taints_from_buffer_unfiltered (ri->buf, max_taint, &tci, tokens_fd);
                create_syscall_retval_taint_unfiltered (&tci, tokens_fd);
            } else {
                create_taints_from_buffer(ri->buf, rc, &tci, tokens_fd, channel_name);
                create_syscall_retval_taint (&tci, tokens_fd, channel_name_ret);
            }
        }
    }

    memset(&current_thread->op.read_info_cache, 0, sizeof(struct read_info));
    current_thread->save_syscall_info = 0;
}

static inline void sys_pread_start(struct thread_data* tdata, int fd, char* buf, int size)
{
    struct read_info* ri = &tdata->op.read_info_cache;
    ri->fd = fd;
    ri->buf = buf;
    tdata->save_syscall_info = (void *) ri;
}

static inline void sys_pread_stop(int rc)
{
    int read_fileno = -1;
    struct read_info* ri = (struct read_info*) &current_thread->op.read_info_cache;

    fprintf (stderr, "[ERROR] sys_pread hasn't been put into recheck log.\n");
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

        if (current_thread->start_tracking) {
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
    }

    memset(&current_thread->op.read_info_cache, 0, sizeof(struct read_info));
    current_thread->save_syscall_info = 0;
}

static inline void taint_syscall_memory_out (const char* sysname, char* buf, u_long size) 
{
    struct taint_creation_info tci;
    if (current_thread->start_tracking == false) return;
    tci.type = TOK_SYSCALL_MEM;
    tci.rg_id = current_thread->rg_id;
    tci.record_pid = current_thread->record_pid;
    tci.syscall_cnt = current_thread->syscall_cnt;
    tci.offset = 0;
    tci.fileno = 0;
    tci.data = 0;
    create_taints_from_buffer_unfiltered (buf, size, &tci, tokens_fd);
    OUTPUT_TAINT_INFO_THREAD (current_thread, "%s %lx %lx", sysname, (u_long)buf, (u_long)size);
    add_modified_mem_for_final_check ((u_long)buf, size);
}

static inline void taint_syscall_retval (const char* sysname)
{
    struct taint_creation_info tci;
    if (current_thread->start_tracking == false) return;
    tci.type = TOK_RETVAL;
    tci.rg_id = current_thread->rg_id;
    tci.record_pid = current_thread->record_pid;
    tci.syscall_cnt = current_thread->syscall_cnt;
    tci.offset = 0;
    tci.fileno = 0;
    tci.data = 0;
    create_syscall_retval_taint_unfiltered (&tci, tokens_fd);
    OUTPUT_TAINT_INFO_THREAD (current_thread, "%s #eax", sysname);
}

static inline void sys_getdents_start(struct thread_data* tdata, unsigned int fd, char* dirp, unsigned int count)
{
    struct getdents64_info* gdi = &tdata->op.getdents64_info_cache;
    gdi->fd = fd;
    gdi->buf = dirp;
    gdi->count = count;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call getdents_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_getdents (tdata->recheck_handle, fd, dirp, count, *ppthread_log_clock);
    }
}

// Can I find this definition as user level?
struct linux_dirent {
    unsigned long        d_ino;
    unsigned long        d_off;
    unsigned short	 d_reclen;
    char		 d_name[1];
};

static void sys_getdents_stop (int rc) 
{
    struct getdents64_info* gdi = &current_thread->op.getdents64_info_cache;
    if (rc > 0) {
	clear_mem_taints ((u_long) gdi->buf, rc); // Output will be verified

	// Except for inodes, which will be tainted (consistent with stat syscalls)
	char* p = gdi->buf; 
	while ((u_long) p - (u_long) gdi->buf < (u_long) rc) {
	    struct linux_dirent* de = (struct linux_dirent *) p;
	    taint_syscall_memory_out ("getdents", (char *) &de->d_ino, sizeof(de->d_ino));
	    if (de->d_reclen <= 0) break;
	    p += de->d_reclen; 
	}
    }
}

static inline void sys_getdents64_start(struct thread_data* tdata, unsigned int fd, char* dirp, unsigned int count)
{
    struct getdents64_info* gdi = &tdata->op.getdents64_info_cache;
    gdi->fd = fd;
    gdi->buf = dirp;
    gdi->count = count;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call getdents64_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_getdents64 (tdata->recheck_handle, fd, dirp, count, *ppthread_log_clock);
    }
}

// Can I find this definition at user level?
struct linux_dirent64 {
	__u64		d_ino;
	__s64		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[0];
};

static void sys_getdents64_stop (int rc) 
{
    struct getdents64_info* gdi = &current_thread->op.getdents64_info_cache;
    if (rc > 0) {
	clear_mem_taints ((u_long) gdi->buf, rc); // Output will be verified
	// Except for inodes, which will be tainted (consistent with stat syscalls)
	char* p = gdi->buf; 
	while ((u_long) p - (u_long) gdi->buf < (u_long) rc) {
	    struct linux_dirent64* de = (struct linux_dirent64 *) p;
	    taint_syscall_memory_out ("getdents64", (char *) &de->d_ino, sizeof(de->d_ino));
	    if (de->d_reclen <= 0) break;
	    p += de->d_reclen; 
	}
    }
}

static inline void sys_readlink_start(struct thread_data* tdata, char* path, char* buf, size_t bufsiz)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call readlink_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_readlink (tdata->recheck_handle, path, buf, bufsiz, *ppthread_log_clock);
    }
}

static void sys_ioctl_start(struct thread_data* tdata, int fd, u_int cmd, char* arg)
{
    struct ioctl_info* ii = &tdata->op.ioctl_info_cache;
    ii->fd = fd;
    ii->buf = arg;
    ii->retval_size = 0;
    ii->cmd = cmd;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call ioctl_recheck");
	OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	ii->retval_size = recheck_ioctl (tdata->recheck_handle, fd, cmd, arg, *ppthread_log_clock);
    }
}

static inline void sys_mkdir_start(struct thread_data* tdata, char* filename, int mode)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call mkdir_recheck");
        OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_mkdir (tdata->recheck_handle, filename, mode, *ppthread_log_clock);
    } 
}

static inline void sys_unlink_start(struct thread_data* tdata, char* filename)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call unlink_recheck");
        OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_unlink (tdata->recheck_handle, filename, *ppthread_log_clock);
    } 
}

static inline void sys_chmod_start(struct thread_data* tdata, char* filename, mode_t mode)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call chmod_recheck");
        OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_chmod (tdata->recheck_handle, filename, mode, *ppthread_log_clock);
    } 
}

static inline void sys_inotify_init1_start(struct thread_data* tdata, int flags)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call inotify_init1_recheck");
        OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_inotify_init1 (tdata->recheck_handle, flags, *ppthread_log_clock);
    } 
}

static inline void sys_inotify_add_watch_start(struct thread_data* tdata, int fd, char* pathname, uint32_t mask)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "call inotify_add_watch_recheck");
        OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
	recheck_inotify_add_watch (tdata->recheck_handle, fd, pathname, mask, *ppthread_log_clock);
    } 
}

static inline void sys_clone_start (struct thread_data* tdata, int flags, pid_t* ptid, pid_t* ctid)  //don't trust the manual page on clone, it's different than the clone syscall
{
    struct clone_info* info = &tdata->op.clone_info_cache;
    int child_pid = -1;
    if (tdata->recheck_handle) {
        recheck_clone (current_thread->recheck_handle, *ppthread_log_clock-1);
    }
    info->flags = flags;
    info->ptid = ptid;
    info->ctid = ctid;
    info->child_pid = child_pid;
}

static inline void sys_clone_stop (int rc) 
{
    struct clone_info* info = &current_thread->op.clone_info_cache;
    pid_t* ptid = info->ptid;
    pid_t* ctid = info->ctid;
    if (current_thread->start_tracking) {
        if (info->flags & (CLONE_VM|CLONE_THREAD|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID)) {
            fprintf (stderr, "A pthread-like clone is called, flags %x, ptid %p, ctid %p, force to wait on the clock\n", info->flags, ptid, ctid);
            //put a fake clone syscall here
            //TODO: should I also call a fake clone at the beginning of the child thread to clear/set ctid value??
            OUTPUT_SLICE (0, "pushfd");
            OUTPUT_SLICE_INFO ("clone");
            OUTPUT_SLICE (0, "push %p", ctid);
            OUTPUT_SLICE_INFO ("clone ctid");
            OUTPUT_SLICE (0, "push %p", ptid);
            OUTPUT_SLICE_INFO ("clone ptid");
            OUTPUT_SLICE (0, "push %d", info->child_pid);
            OUTPUT_SLICE_INFO ("clone record pid");
            OUTPUT_SLICE (0, "call recheck_fake_clone");
            OUTPUT_SLICE_INFO ("clone record pid %d, child pid %d", current_thread->record_pid, rc);
            OUTPUT_SLICE (0, "add esp, 12");
            OUTPUT_SLICE_INFO ("record_pid %d", current_thread->record_pid);
            OUTPUT_SLICE (0, "popfd");
            OUTPUT_SLICE_INFO ("clone");
            taint_syscall_memory_out ("clone", (char*)ptid, sizeof (pid_t));
            taint_syscall_memory_out ("clone", (char*)ctid, sizeof (pid_t));
            taint_syscall_retval ("clone");
        } else {
            fprintf (stderr, "clone with flags %x called\n", info->flags);
        }
    }
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
    if (tdata->recheck_handle) {
	switch (cmd) {
	case F_GETFD:
	    OUTPUT_SLICE(0, "call fcntl64_getfd_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_fcntl64_getfd (tdata->recheck_handle, fd, *ppthread_log_clock);
	    break;
	case F_SETFD:
	    OUTPUT_SLICE(0, "call fcntl64_setfd_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_fcntl64_setfd (tdata->recheck_handle, fd, (int) arg, *ppthread_log_clock);
	    break;
	case F_GETFL:
	    OUTPUT_SLICE(0, "call fcntl64_getfl_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_fcntl64_getfl (tdata->recheck_handle, fd, *ppthread_log_clock);
	    break;
	case F_SETFL:
	    OUTPUT_SLICE(0, "call fcntl64_setfl_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_fcntl64_setfl (tdata->recheck_handle, fd, (long) arg, *ppthread_log_clock);
	    break;
	case F_GETLK:
	    OUTPUT_SLICE(0, "call fcntl64_getlk_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_fcntl64_getlk (tdata->recheck_handle, fd, arg, *ppthread_log_clock);
	    break;
	case F_GETOWN:
	    OUTPUT_SLICE(0, "call fcntl64_getown_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_fcntl64_getown (tdata->recheck_handle, fd, *ppthread_log_clock);
	    break;
	case F_SETOWN:
	    OUTPUT_SLICE(0, "push edx");
	    OUTPUT_SLICE_INFO ("");
	    OUTPUT_SLICE(0, "call fcntl64_setown_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    OUTPUT_SLICE(0, "pop edx");
	    OUTPUT_SLICE_INFO ("");
	    recheck_fcntl64_setown (tdata->recheck_handle, fd, (long) arg, is_reg_arg_tainted (LEVEL_BASE::REG_EDX, 4, 0), *ppthread_log_clock);
	    break;
	default:
	    fprintf (stderr, "[ERROR] fcntl64 cmd %d not yet handled for recheck\n", cmd);
	}
    }
}

static void sys__newselect_start(struct thread_data* tdata, int nfds, fd_set* readfds, fd_set* writefds, 
				 fd_set* exceptfds, struct timeval* timeout)
{
    tdata->op.select_info_cache.nfds = nfds;
    tdata->op.select_info_cache.readfds = readfds;
    tdata->op.select_info_cache.writefds = writefds;
    tdata->op.select_info_cache.exceptfds = exceptfds;
    tdata->op.select_info_cache.timeout = timeout;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call newselect_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck__newselect (tdata->recheck_handle, nfds, readfds, writefds, exceptfds, timeout, *ppthread_log_clock);
    }
}

static void sys__newselect_stop(int rc)
{
    struct select_info* si = &current_thread->op.select_info_cache;
    if (rc >= 0 && si->timeout) {
	taint_syscall_memory_out ("_newselect", (char *) si->timeout, sizeof(struct timeval));
    }
}

static void sys_mmap_start(struct thread_data* tdata, u_long addr, int len, int prot, int fd, int flags)
{
    struct mmap_info* mmi = &tdata->op.mmap_info_cache;
    mmi->addr = addr;
    mmi->length = len;
    mmi->prot = prot;
    mmi->fd = fd;
    mmi->flags = flags;
    tdata->save_syscall_info = (void *) mmi;
    tdata->app_syscall_chk = len + prot; // Pin sometimes makes mmaps during mmap
}

static void print_memory_regions () 
{
    char buf[256];
    string procname=  "/proc/self/maps";
    FILE* file = fopen(procname.c_str(), "r");
    while (!feof(file)) {
        if (fgets (buf, sizeof(buf), file)) {
            printf ("%s", buf);
        }
    }
    fclose(file);
}


static void sys_mmap_stop(int rc)
{

    struct mmap_info* mmi = (struct mmap_info*) current_thread->save_syscall_info;
//    struct timeval mm_st, mm_end; 

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
            if (current_thread->start_tracking) {
                struct taint_creation_info tci;
                tci.rg_id = current_thread->rg_id;
                tci.record_pid = current_thread->record_pid;
                tci.syscall_cnt = current_thread->syscall_cnt;
                tci.offset = 0;
                tci.fileno = read_fileno;
                tci.data = 0;
                tci.type = TOK_MMAP;

                create_taints_from_buffer ((void *) rc, mmi->length, &tci, tokens_fd,
                        channel_name);
            }
        } else {
            fprintf(stderr, "mmap is PROT_EXEC\n");
        }
    }
    current_thread->save_syscall_info = 0;
#else
    mm_len += mmi->length;
    //if there are taints to be cleared, and we aren't a splice_output
    if (!splice_output && taint_num > 1) {
	if (rc > 0 || rc < -1024) clear_mem_taints (rc, mmi->length);
    }

#endif
    if (rc > 0 || rc < -1024) {
        if (current_thread->start_tracking) add_mmap_region (rc, mmi->length, mmi->prot, mmi->flags);
    }
    if (current_thread->start_tracking) {
        printf ("mmap 0x%x size %d, prot %x, flags %x\n", rc, mmi->length, mmi->prot, mmi->flags); 
        print_memory_regions();
    }
}

static inline void sys_write_start(struct thread_data* tdata, int fd, char* buf, size_t count)
{
    struct write_info* wi = &tdata->op.write_info_cache;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE (0, "push edx");
	OUTPUT_SLICE_INFO ("");
	OUTPUT_SLICE(0, "call write_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	OUTPUT_SLICE (0, "pop edx");
	OUTPUT_SLICE_INFO ("");
	recheck_write (tdata->recheck_handle, fd, buf, count, *ppthread_log_clock);
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
	    if (produce_output && current_thread->start_tracking) { 
		output_buffer_result (wi->buf, rc, &tci, outfd);
	    }
	}
    }
}

static inline void sys_writev_start(struct thread_data* tdata, int fd, struct iovec* iov, int count)
{
    struct writev_info* wvi;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call writev_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_writev (tdata->recheck_handle, fd, iov, count, *ppthread_log_clock);
    }
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
			if (produce_output && current_thread->start_tracking) { 
			    output_buffer_result(vi->iov_base, vi->iov_len, &tci, outfd);
			}
			tci.offset += vi->iov_len;
		    }
		}
	    } else {
		for (int i = 0; i < wvi->count; i++) {
		    struct iovec* vi = (wvi->vi + i);
		    if (produce_output && current_thread->start_tracking) { 
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
	OUTPUT_SLICE(0, "call socket_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_socket (tdata->recheck_handle, domain, type, protocol, *ppthread_log_clock);
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
	OUTPUT_SLICE(0, "call connect_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_connect_or_bind (tdata->recheck_handle, sockfd, addr, addrlen, *ppthread_log_clock);
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

        current_thread->save_syscall_info = NULL; // Socket_info owns this now
    }
}

static void sys_getsockname_start(thread_data* tdata, int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call getsockname_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	socklen_t retaddrlen = recheck_getsockname (tdata->recheck_handle, sockfd, addr, addrlen, *ppthread_log_clock);
	if (retaddrlen > 0) clear_mem_taints ((u_long)addr, retaddrlen); 
	clear_mem_taints ((u_long)addrlen, sizeof(socklen_t)); 
    }
}

static void sys_getpeername_start(thread_data* tdata, int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call getpeername_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	socklen_t retaddrlen = recheck_getpeername (tdata->recheck_handle, sockfd, addr, addrlen, *ppthread_log_clock);
	if (retaddrlen > 0) clear_mem_taints ((u_long)addr, retaddrlen); 
	clear_mem_taints ((u_long)addrlen, sizeof(socklen_t)); 
    }
}

static void sys_recv_start(thread_data* tdata, int sockfd, void* buf, size_t len, int flags)
{
    // recv and read are similar so they can share the same info struct
    // recv reads data into place - taint must be specified partially
    struct read_info* ri = (struct read_info*) &tdata->op.read_info_cache;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call recv_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);

	size_t starts[MAX_REGIONS], ends[MAX_REGIONS];
	int regions;
	if (filter_input() && (regions = get_partial_taint_byte_range(current_thread->record_pid, current_thread->syscall_cnt, starts, ends)) > 0) {
	    if (regions > 0) {
		int retaddrlen = recheck_recv (tdata->recheck_handle, sockfd, buf, len, flags, regions, starts, ends, *ppthread_log_clock);
		if (retaddrlen > 0) {
		    clear_mem_taints ((u_long)buf, retaddrlen); 
		    add_modified_mem_for_final_check ((u_long)buf, retaddrlen);
		    for (int i = 0; i < regions; i++) {
			OUTPUT_TAINT_INFO_THREAD (current_thread, "recv %lx %lx", (u_long) buf+starts[i], (u_long) ends[i]-starts[i]);  
		    }
		}
	    }
	} else {
	    int retaddrlen = recheck_recv (tdata->recheck_handle, sockfd, buf, len, flags, 0, 0, 0, *ppthread_log_clock);
	    if (retaddrlen > 0) {
		clear_mem_taints ((u_long)buf, retaddrlen); 
		add_modified_mem_for_final_check ((u_long)buf, retaddrlen);
	    }
	}
    }
    ri->fd = sockfd;
    ri->buf = (char *)buf;
    tdata->save_syscall_info = (void *) ri;
}

static void sys_recv_stop(int rc) 
{
    struct read_info* ri = (struct read_info *) &current_thread->op.read_info_cache;
    LOG_PRINT ("Pid %d syscall recv returns %d\n", PIN_GetPid(), rc);

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

        if (current_thread->start_tracking) {
            tci.rg_id = current_thread->rg_id;
            tci.record_pid = current_thread->record_pid;
            tci.syscall_cnt = current_thread->syscall_cnt;
            tci.offset = 0;
            tci.fileno = read_fileno;
            tci.data = 0;
            tci.type = TOK_RECV;

            create_taints_from_buffer(ri->buf, rc, &tci, tokens_fd, channel_name);
        }
    }
    memset(&current_thread->op.read_info_cache, 0, sizeof(struct read_info));
    current_thread->save_syscall_info = 0;
}

static void sys_recvfrom_start(thread_data* tdata, int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)
{
    // recv and read are similar so they can share the same info struct
    // recv reads data into place - taint must be specified partially
    // recvfrom has two more return values stored in src_addr and addrlen; I'll verify these two return values in recheck_support.c for now 
    // recvfrom must be rechecked at the end of the syscall as there are return values stored in addrlen and src_addr
    struct read_info* ri = (struct read_info*) &tdata->op.read_info_cache;
    ri->fd = sockfd;
    ri->buf = (char *)buf;
    struct recvfrom_info* info = (struct recvfrom_info*) malloc (sizeof(struct recvfrom_info));
    info->sockfd = sockfd;
    info->buf = buf;
    info->len = len;
    info->flags = flags;
    info->src_addr = src_addr;
    info->addrlen = addrlen;
    info->clock = *ppthread_log_clock;
    tdata->save_syscall_info = (void *) info;
}

static void sys_recvfrom_stop(int rc) 
{
    struct read_info* ri = (struct read_info *) &current_thread->op.read_info_cache;
    struct recvfrom_info* info = (struct recvfrom_info*)current_thread->save_syscall_info;
    LOG_PRINT ("Pid %d syscall recvfrom returns %d\n", PIN_GetPid(), rc);
    int sockfd = info->sockfd;
    void* buf = info->buf;
    size_t len = info->len;
    int flags = info->flags;
    struct sockaddr* src_addr = info->src_addr;
    socklen_t* addrlen = info->addrlen;


    if (current_thread->recheck_handle) {
	OUTPUT_SLICE(0, "call recvfrom_recheck");
	OUTPUT_SLICE_INFO("clock %lu", info->clock);

	size_t starts[MAX_REGIONS], ends[MAX_REGIONS];
	int regions;
	if (filter_input() && (regions = get_partial_taint_byte_range(current_thread->record_pid, current_thread->syscall_cnt, starts, ends)) > 0) {
	    if (regions > 0) {
		int retlen = recheck_recvfrom (current_thread->recheck_handle, sockfd, buf, len, flags, src_addr, addrlen, regions, starts, ends, info->clock);
		if (retlen > 0) {
		    clear_mem_taints ((u_long)buf, retlen); 
		    add_modified_mem_for_final_check ((u_long)buf, retlen);
		    for (int i = 0; i < regions; i++) {
			fprintf (stderr, "partial recvfrom taint: %u %u\n", starts[i], ends[i]);
			OUTPUT_TAINT_INFO_THREAD (current_thread, "recvfrom %lx %lx", (u_long) buf+starts[i], (u_long) ends[i]-starts[i]);  
		    }
		}
	    }
	} else {
	    int retlen = recheck_recvfrom (current_thread->recheck_handle, sockfd, buf, len, flags, src_addr, addrlen, 0, 0, 0, info->clock);
	    if (retlen > 0) {
		clear_mem_taints ((u_long)buf, retlen); 
		add_modified_mem_for_final_check ((u_long)buf, retlen);
	    }
	}
        if (addrlen) {
            add_modified_mem_for_final_check ((u_long) src_addr, *addrlen);
            clear_mem_taints ((u_long) src_addr, *addrlen);
            add_modified_mem_for_final_check ((u_long) addrlen, sizeof(socklen_t));
            clear_mem_taints ((u_long) addrlen, sizeof(socklen_t));
        }
    }

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

        if (current_thread->start_tracking) {
            tci.rg_id = current_thread->rg_id;
            tci.record_pid = current_thread->record_pid;
            tci.syscall_cnt = current_thread->syscall_cnt;
            tci.offset = 0;
            tci.fileno = read_fileno;
            tci.data = 0;
            tci.type = TOK_RECV;

            create_taints_from_buffer(ri->buf, rc, &tci, tokens_fd, channel_name);
        }
    }
    memset(&current_thread->op.read_info_cache, 0, sizeof(struct read_info));
    free (current_thread->save_syscall_info);
    current_thread->save_syscall_info = 0;
}


static void sys_recvmsg_start(struct thread_data* tdata, int sockfd, struct msghdr* msg, int flags) 
{
    struct recvmsg_info* rmi;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call recvmsg_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);

	size_t starts[MAX_REGIONS], ends[MAX_REGIONS];
	int regions;
	if (filter_input() && (regions = get_partial_taint_byte_range(current_thread->record_pid, current_thread->syscall_cnt, starts, ends))) {
	    int retlen = recheck_recvmsg (tdata->recheck_handle, sockfd, msg, flags, regions, starts, ends, *ppthread_log_clock);
	    if (retlen > 0) {
		// One byte at a time is simple, but may be a little slow
		u_long bytes_so_far = 0;
		int region_cnt = 0;
		for (u_long i = 0; i < msg->msg_iovlen && bytes_so_far < (u_long) retlen; i++) {
		    for (u_long j = 0; j < msg->msg_iov[i].iov_len && bytes_so_far < (u_long) retlen; j++) {
			if (region_cnt == regions || 
			    (starts[region_cnt] > bytes_so_far || ends[region_cnt] <= bytes_so_far)) {
			    if (region_cnt < regions && ends[region_cnt] <= bytes_so_far) region_cnt++;
			    clear_mem_taints ((u_long) msg->msg_iov[i].iov_base+j, 1);
			} else {
			    OUTPUT_TAINT_INFO_THREAD (current_thread, "recvmsg %lx 1", (u_long) msg->msg_iov[i].iov_base+j);
			}
			add_modified_mem_for_final_check ((u_long) msg->msg_iov[i].iov_base+j, 1);
			bytes_so_far++;
		    }
		}
	    }
	} else {
	    int retlen = recheck_recvmsg (tdata->recheck_handle, sockfd, msg, flags, 0, 0, 0, *ppthread_log_clock);
	    if (retlen > 0) {
		for (u_int i = 0; i < msg->msg_iovlen; i++) {
		    u_int toclear = (msg->msg_iov[i].iov_len < (u_int) retlen) ? msg->msg_iov[i].iov_len : retlen;
		    clear_mem_taints ((u_long) msg->msg_iov[i].iov_base, toclear);
		    add_modified_mem_for_final_check ((u_long) msg->msg_iov[i].iov_base, toclear);
		    retlen -= toclear;
		    if (retlen == 0) break;
		}
		if (retlen > 0) fprintf (stderr, "recvmsg: cannot clear enough bytes\n");
	    }
	}
    }
    rmi = (struct recvmsg_info *) malloc(sizeof(struct recvmsg_info));
    if (rmi == NULL) {
	fprintf (stderr, "Unable to malloc recvmsg_info\n");
	assert (0);
    }
    rmi->fd = sockfd;
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
        if (current_thread->start_tracking) {
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
                create_taints_from_buffer(vi->iov_base, vi->iov_len, &tci, tokens_fd,
                        channel_name);
                tci.offset += vi->iov_len;
            }
        }
    }
    free(rmi);
}

static void sys_sendmsg_start(struct thread_data* tdata, int sockfd, struct msghdr* msg, int flags)
{
    struct sendmsg_info* smi;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call sendmsg_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_sendmsg (tdata->recheck_handle, sockfd, msg, flags, *ppthread_log_clock);
    }
    smi = (struct sendmsg_info *) malloc(sizeof(struct sendmsg_info));
    if (smi == NULL) {
	fprintf (stderr, "Unable to malloc sendmsg_info\n");
	assert (0);
    }
    smi->fd = sockfd;
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
		if (produce_output && current_thread->start_tracking) { 
		    output_buffer_result(vi->iov_base, vi->iov_len, &tci, outfd);
		}
		tci.offset += vi->iov_len;
	    }
	}
    }
    free(smi);
}

static void sys_send_start(struct thread_data* tdata, int sockfd, char* msg, size_t len, int flags)
{
    struct write_info* si;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call send_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_send (tdata->recheck_handle, sockfd, msg, len, flags, *ppthread_log_clock);
    }
    si = (struct write_info *) malloc(sizeof(struct write_info));
    if (si == NULL) {
	fprintf (stderr, "Unable to malloc sendmsg_info\n");
	assert (0);
    }
    si->fd = sockfd;
    si->buf = msg;

    tdata->save_syscall_info = (void *) si;
}

static void sys_send_stop(int rc)
{
    struct write_info* si = (struct write_info *) current_thread->save_syscall_info;
    int channel_fileno = -1;

    if (rc > 0) {
	if (*ppthread_log_clock >= filter_outputs_before) {
	    struct taint_creation_info tci;
	    
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
	    if (produce_output && current_thread->start_tracking) { 
		output_buffer_result (si->buf, rc, &tci, outfd);
	    }
	}
    }
    free(si);
}

static void sys_sendto_start(struct thread_data* tdata, int sockfd, char* msg, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    struct write_info* si;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call sendto_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_sendto (tdata->recheck_handle, sockfd, msg, len, flags, dest_addr, addrlen, *ppthread_log_clock);
    }
    si = (struct write_info *) malloc(sizeof(struct write_info));
    if (si == NULL) {
	fprintf (stderr, "Unable to malloc sendmsg_info\n");
	assert (0);
    }
    si->fd = sockfd;
    si->buf = msg;

    tdata->save_syscall_info = (void *) si;
}

static void sys_sendto_stop(int rc)
{
    struct write_info* si = (struct write_info *) current_thread->save_syscall_info;
    int channel_fileno = -1;

    if (rc > 0) {
	if (*ppthread_log_clock >= filter_outputs_before) {
	    struct taint_creation_info tci;
	    
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
	    if (produce_output && current_thread->start_tracking) { 
		output_buffer_result (si->buf, rc, &tci, outfd);
	    }
	}
    }
    free(si);
}


static void sys_setsockopt_start (struct thread_data* tdata, int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call setsockopt_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_setsockopt (tdata->recheck_handle, sockfd, level, optname, optval, optlen, *ppthread_log_clock);
    }
}

static inline void sys_gettimeofday_start (struct thread_data* tdata, struct timeval* tv, struct timezone *tz) {
	LOG_PRINT ("start to handle gettimeofday, tv %p, tz %p\n", tv, tz);
	struct gettimeofday_info* info = &tdata->op.gettimeofday_info_cache;
	info->tv = tv;
	info->tz = tz;
	tdata->save_syscall_info = (void*) info;
	if (tdata->recheck_handle) {
	    OUTPUT_SLICE(0, "call gettimeofday_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_gettimeofday (tdata->recheck_handle, tv, tz, *ppthread_log_clock);
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

static inline void sys_time_start (struct thread_data* tdata, time_t* t) 
{
    tdata->save_syscall_info = (void*) t;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call time_recheck");
	OUTPUT_SLICE_INFO("%lu", *ppthread_log_clock);
	recheck_time (tdata->recheck_handle, t, *ppthread_log_clock);
    }
}

static inline void sys_time_stop (int rc) 
{
    time_t* t = (time_t*) current_thread->save_syscall_info;
    taint_syscall_retval ("time");
    if (rc >= 0 && t != NULL) taint_syscall_memory_out ("time", (char *) t, sizeof(time_t));
}

static inline void sys_mremap_start (struct thread_data* tdata, void* old_address, size_t old_size, size_t new_size, int flags, void* new_address)
{
    struct mremap_info* mri = (struct mremap_info*) &tdata->op.mremap_info_cache;
    fprintf (stderr, "mremap: old_address 0x%lx old_size 0x%x new_size 0x%x flags 0x%x new_address 0x%lx clock %lu\n", (u_long) old_address, old_size, new_size, flags, (u_long) new_address, *ppthread_log_clock);
    mri->old_address = old_address;
    mri->old_size = old_size;
    mri->new_size = new_size;
}

static inline void sys_mremap_stop (int rc) 
{
    struct mremap_info* mri = (struct mremap_info*) &current_thread->op.mremap_info_cache;
    fprintf (stderr, "mremap: rc 0x%x\n", rc);
    if (rc > 0 || rc < -1024) {
        if (current_thread->start_tracking) { 
            move_mem_taints (rc, mri->new_size, (u_long) mri->old_address, mri->old_size);
            move_mmap_region (rc, mri->new_size, (u_long) mri->old_address, mri->old_size);
        }
    }
}

static inline void sys_clock_gettime_start (struct thread_data* tdata, clockid_t clk_id, struct timespec* tp) { 
    LOG_PRINT ("start to handle clock_gettime %p\n", tp);
    struct clock_gettime_info* info = &tdata->op.clock_gettime_info_cache;
    info->clk_id = clk_id;
    info->tp = tp;
    tdata->save_syscall_info = (void*) info;
    if (tdata->recheck_handle) {
	if (clk_id == CLOCK_MONOTONIC) {
	    // By the definition of CLOCK_MONOTONIC, we should be able to substitute value from recording here
	    struct timespec tpout;
	    int rc = recheck_clock_gettime_monotonic (tdata->recheck_handle, &tpout);
	    OUTPUT_SLICE (0, "mov eax, 0");
	    OUTPUT_SLICE_INFO("(monotonic) clock_gettime at clock %lu", *ppthread_log_clock);
	    if (rc == 0) {
		OUTPUT_SLICE (0, "mov dword ptr[0x%lx], 0x%lx", (u_long) &tp->tv_sec, tpout.tv_sec);
		OUTPUT_SLICE_INFO("(monotonic) clock_gettime at clock %lu", *ppthread_log_clock);
		OUTPUT_SLICE (0, "mov dword ptr[0x%lx], 0x%lx", (u_long) &tp->tv_nsec, tpout.tv_nsec);
		OUTPUT_SLICE_INFO("(monotonic) clock_gettime at clock %lu", *ppthread_log_clock);
		clear_mem_taints((u_long) tp, sizeof(tpout));
		add_modified_mem_for_final_check ((u_long) tp, sizeof(tpout));
	    }
	} else {
	    OUTPUT_SLICE (0, "call clock_gettime_recheck");
	    OUTPUT_SLICE_INFO("%lu", *ppthread_log_clock);
	    recheck_clock_gettime (tdata->recheck_handle, clk_id, tp, *ppthread_log_clock);
	} 
    }
}

static inline void sys_clock_gettime_stop (int rc) 
{ 
    struct clock_gettime_info* ri = (struct clock_gettime_info*) &current_thread->op.clock_gettime_info_cache;
    if (rc == 0 && ri->clk_id != CLOCK_MONOTONIC) {
	taint_syscall_memory_out ("clock_gettime", (char*) ri->tp, sizeof(struct timespec));
    }
}

static inline void sys_clock_getres_start (struct thread_data* tdata, clockid_t clk_id, struct timespec* tp) { 
    LOG_PRINT ("start to handle clock_getres clk_id %d, %p\n", clk_id, tp);
    struct clock_gettime_info* info = &tdata->op.clock_gettime_info_cache; //share the structure with clock_gettime
    info->tp = tp;
    tdata->save_syscall_info = (void*) info;
    if (tdata->recheck_handle) {
        int clock_id_tainted = is_reg_arg_tainted (LEVEL_BASE:: REG_EBX, 4, 0);
        OUTPUT_SLICE (0, "push ebx");
        OUTPUT_SLICE_INFO ("the clockid may be tainted");
	OUTPUT_SLICE (0, "call clock_getres_recheck");
	OUTPUT_SLICE_INFO("%lu", *ppthread_log_clock);
        OUTPUT_SLICE (0, "pop ebx");
	OUTPUT_SLICE_INFO("%lu", *ppthread_log_clock);
	recheck_clock_getres (tdata->recheck_handle, clk_id, tp, clock_id_tainted, *ppthread_log_clock);
    }
}

static inline void sys_clock_getres_stop (int rc) { 
    struct clock_gettime_info* ri = (struct clock_gettime_info*) &current_thread->op.clock_gettime_info_cache;
    if (rc == 0) { 
        taint_syscall_memory_out ("clock_getres", (char*) ri->tp, sizeof(struct timespec));
    }
    DEBUG_INFO ("clock_getres result %ld, %ld\n", ri->tp->tv_sec, ri->tp->tv_nsec);
    memset (&current_thread->op.clock_gettime_info_cache, 0, sizeof(struct clock_gettime_info));
    current_thread->save_syscall_info = 0;
    LOG_PRINT ("Done with clock_getres.\n");
}

static inline void sys_getpid_start (struct thread_data* tdata) {
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call getpid_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_getpid (tdata->recheck_handle, *ppthread_log_clock);
    }
}

static inline void sys_getpid_stop (int rc) 
{
    taint_syscall_retval ("getpid");
}

static inline void sys_gettid_start (struct thread_data* tdata) {
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call gettid_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_gettid (tdata->recheck_handle, *ppthread_log_clock);
    }
}

static inline void sys_gettid_stop (int rc) 
{
    taint_syscall_retval ("gettid");
}

static inline void sys_getpgrp_start (struct thread_data* tdata) 
{    
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call getpgrp_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_getpgrp (tdata->recheck_handle, *ppthread_log_clock);
    }
}

static inline void sys_getpgrp_stop (int rc) 
{
    taint_syscall_retval ("getpgrp");
}

static inline void sys_getuid32_start (struct thread_data* tdata) {
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call getuid32_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_getuid32 (tdata->recheck_handle, *ppthread_log_clock);
    }
}

static inline void sys_geteuid32_start (struct thread_data* tdata) {
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call geteuid32_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_geteuid32 (tdata->recheck_handle, *ppthread_log_clock);
    }
}

static inline void sys_getgid32_start (struct thread_data* tdata) 
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call getgid32_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_getgid32 (tdata->recheck_handle, *ppthread_log_clock);
    }
}

static inline void sys_getegid32_start (struct thread_data* tdata) 
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call getegid32_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_getegid32 (tdata->recheck_handle, *ppthread_log_clock);
    }
}

static inline void sys_getresuid_start (struct thread_data* tdata, uid_t* ruid, uid_t* euid, uid_t* suid) 
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call getresuid_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_getresuid (tdata->recheck_handle, ruid, euid, suid, *ppthread_log_clock);
    }
}

static inline void sys_getresgid_start (struct thread_data* tdata, gid_t* rgid, gid_t* egid, gid_t* sgid) 
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call getresgid_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_getresgid (tdata->recheck_handle, rgid, egid, sgid, *ppthread_log_clock);
    }
}

static inline void sys_setpgid_start (struct thread_data* tdata, pid_t pid, pid_t pgid) {
    if (tdata->recheck_handle) {
	int pid_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_EBX, 4, 0);
	int pgid_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_ECX, 4, 0);
	OUTPUT_SLICE(0, "push ecx");
	OUTPUT_SLICE_INFO ("");
	OUTPUT_SLICE(0, "push ebx");
	OUTPUT_SLICE_INFO ("");
	OUTPUT_SLICE(0, "call setpgid_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	OUTPUT_SLICE(0, "pop ebx");
	OUTPUT_SLICE_INFO ("");
	OUTPUT_SLICE(0, "pop ecx");
	OUTPUT_SLICE_INFO ("");
	recheck_setpgid (tdata->recheck_handle, pid, pgid, pid_tainted, pgid_tainted, *ppthread_log_clock);
    }
}

static inline void sys_set_tid_address_start (struct thread_data* tdata, int* tidptr) 
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call set_tid_address_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_set_tid_address (tdata->recheck_handle, tidptr, *ppthread_log_clock);
    }
    taint_syscall_memory_out ("set_tid_address", (char*)tidptr, sizeof(int));
}

static inline void sys_set_tid_address_stop (int rc) 
{
    taint_syscall_retval ("set_tid_address");
}

static inline void sys_set_robust_list (struct thread_data* tdata, struct robust_list_head* head, size_t len) 
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call set_robust_list_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_set_robust_list (tdata->recheck_handle, head, len, *ppthread_log_clock);
    }
}

static inline void sys_fstat64_start (struct thread_data* tdata, int fd, struct stat64* buf) {
	struct fstat64_info* fsi = (struct fstat64_info*) &current_thread->op.fstat64_info_cache;
	fsi->fd = fd;
	fsi->buf = buf;
	if (tdata->recheck_handle) {
	    OUTPUT_SLICE(0, "call fstat64_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_fstat64 (tdata->recheck_handle, fd, buf, *ppthread_log_clock);
	}
}

static inline void sys_fstat64_stop (int rc) 
{
    struct fstat64_info* fsi = (struct fstat64_info*) &current_thread->op.fstat64_info_cache;
    clear_mem_taints ((u_long)fsi->buf, sizeof(struct stat64));
    if (rc == 0) {
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_ino, sizeof(fsi->buf->st_ino));
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_nlink, sizeof(fsi->buf->st_nlink));
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_rdev, sizeof(fsi->buf->st_rdev));
	//taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_size, sizeof(fsi->buf->st_size));
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_atime, sizeof(fsi->buf->st_atime));
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_ctime, sizeof(fsi->buf->st_ctime));
	taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_mtime, sizeof(fsi->buf->st_mtime));
	//taint_syscall_memory_out ("fstat64", (char *)&fsi->buf->st_blocks, sizeof(fsi->buf->st_blocks));
    }
    LOG_PRINT ("Done with fstat64.\n");
}

static inline void sys_stat64_start (struct thread_data* tdata, char* path, struct stat64* buf) {
	struct stat64_info* si = (struct stat64_info*) &current_thread->op.stat64_info_cache;
	si->buf = buf;
	if (tdata->recheck_handle) {
	    OUTPUT_SLICE(0, "call stat64_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_stat64 (tdata->recheck_handle, path, buf, *ppthread_log_clock);
	}
}

static inline void sys_stat64_stop (int rc) 
{
	struct stat64_info* si = (struct stat64_info*) &current_thread->op.stat64_info_cache;
	clear_mem_taints ((u_long)si->buf, sizeof(struct stat64));
	if (rc == 0) {
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_ino, sizeof(si->buf->st_ino));
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_nlink, sizeof(si->buf->st_nlink));
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_rdev, sizeof(si->buf->st_rdev));
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_atime, sizeof(si->buf->st_atime));
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_ctime, sizeof(si->buf->st_ctime));
	    taint_syscall_memory_out ("stat64", (char *)&si->buf->st_mtime, sizeof(si->buf->st_mtime));
	}
}

static inline void sys_lstat64_start (struct thread_data* tdata, char* path, struct stat64* buf) {
	struct stat64_info* si = (struct stat64_info*) &current_thread->op.stat64_info_cache;
	si->buf = buf;
	if (tdata->recheck_handle) {
	    OUTPUT_SLICE(0, "call lstat64_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_lstat64 (tdata->recheck_handle, path, buf, *ppthread_log_clock);
	}
}

static inline void sys_lstat64_stop (int rc) 
{
	struct stat64_info* si = (struct stat64_info*) &current_thread->op.stat64_info_cache;
	clear_mem_taints ((u_long)si->buf, sizeof(struct stat64));
	if (rc == 0) {
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_ino, sizeof(si->buf->st_ino));
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_nlink, sizeof(si->buf->st_nlink));
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_rdev, sizeof(si->buf->st_rdev));
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_atime, sizeof(si->buf->st_atime));
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_ctime, sizeof(si->buf->st_ctime));
	    taint_syscall_memory_out ("lstat64", (char *)&si->buf->st_mtime, sizeof(si->buf->st_mtime));
	}
}

static inline void sys_pipe_start (struct thread_data* tdata, int pipefd[2]) 
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call pipe_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_pipe (tdata->recheck_handle, pipefd, *ppthread_log_clock);
    }
}

static inline void sys_ugetrlimit_start (struct thread_data* tdata, int resource, struct rlimit* prlim) 
{
	struct ugetrlimit_info* ugri = (struct ugetrlimit_info*) &current_thread->op.ugetrlimit_info_cache;
	ugri->resource = resource;
	ugri->prlim = prlim;
	if (tdata->recheck_handle) {
	    OUTPUT_SLICE(0, "call ugetrlimit_recheck");
	    OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    recheck_ugetrlimit (tdata->recheck_handle, resource, prlim, *ppthread_log_clock);
	}
}

static inline void sys_ugetrlimit_stop (int rc) 
{
	struct ugetrlimit_info* ugri = (struct ugetrlimit_info*) &current_thread->op.ugetrlimit_info_cache;
	clear_mem_taints ((u_long)ugri->prlim, sizeof(struct rlimit));
	LOG_PRINT ("Done with ugetrlimit.\n");
}

static inline void sys_setrlimit_start (struct thread_data* tdata, int resource, struct rlimit* prlim) 
{
    if (is_mem_arg_tainted ((u_long)prlim, sizeof(*prlim))) {
        fprintf (stderr, "[ERROR] sys_setrlimit_start: rlimit is tainted.\n");
    }
    if (tdata->recheck_handle) {
        OUTPUT_SLICE(0, "call setrlimit_recheck");
        OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
        recheck_setrlimit (tdata->recheck_handle, resource, prlim, *ppthread_log_clock);
    }
}

static inline void sys_prlimit64_start (struct thread_data* tdata, pid_t pid, int resource, struct rlimit64* new_limit, struct rlimit64* old_limit) 
{
    struct prlimit64_info* pri = (struct prlimit64_info*) &current_thread->op.prlimit64_info_cache;
    pri->old_limit = old_limit;
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call prlimit64_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_prlimit64 (tdata->recheck_handle, pid, resource, new_limit, old_limit, *ppthread_log_clock);
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
	OUTPUT_SLICE(0, "call uname_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_uname (tdata->recheck_handle, buf, *ppthread_log_clock);
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
	OUTPUT_SLICE(0, "call statfs64_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_statfs64 (tdata->recheck_handle, path, sz, buf, *ppthread_log_clock);
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
	LOG_PRINT ("start to handle getrusage, usage addr %p\n", usage);
	struct getrusage_info* info = &tdata->op.getrusage_info_cache;
	info->usage = usage;
	tdata->save_syscall_info = (void*) info;
}

static inline void sys_getrusage_stop (int rc) {
	struct getrusage_info* ri = (struct getrusage_info*) &current_thread->op.getrusage_info_cache;
	if (rc == 0) {
            if (current_thread->start_tracking) {
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
	}
	memset (&current_thread->op.getrusage_info_cache, 0, sizeof(struct rusage));
	current_thread->save_syscall_info = 0;
	LOG_PRINT ("Done with getrusage\n");
}

static inline void sys_eventfd2_start (struct thread_data* tdata, unsigned int count, int flags) 
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call eventfd2_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_eventfd2 (tdata->recheck_handle, count, flags, *ppthread_log_clock);
    }
}

static inline void sys_poll_start (struct thread_data* tdata, struct pollfd* fds, u_int nfds, int timeout)
{
    if (tdata->recheck_handle) {
        recheck_poll (tdata->recheck_handle, fds, nfds, timeout, *ppthread_log_clock);
    }
}

static inline void sys_poll_stop (long rc)
{
    if (current_thread->recheck_handle) {
        OUTPUT_SLICE(0, "push edx");
        OUTPUT_SLICE_INFO ("");
        OUTPUT_SLICE(0, "call poll_recheck");
        OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
        OUTPUT_SLICE(0, "pop edx");
        OUTPUT_SLICE_INFO ("");
    }
}

static inline void sys_kill_start (struct thread_data* tdata, pid_t pid, int sig)
{
    // Since replay handles signals, we might be OK sending signal to ourselves
    if (!(pid == current_thread->record_pid)) {
	fprintf (stderr, "Sending signal %d to pid %d\n", sig, pid);
    }
}

static inline void sys_futex_start (struct thread_data* tdata, int* uaddr, int op, int val, const struct timespec* timeout, int* uaddr2, int val3)
{
    if ((op&0x3f) == 0x1) { // Futex wait
	// Only get this if single-threaded, in which case it is a no-op!
	fprintf (stderr, "futex uaddr %p op %d val %d timespec %p uaddr2 %p, val3 %d\n", uaddr, op, val, timeout, uaddr2, val3);
    }
}

static inline void sys_rt_sigaction_start (struct thread_data* tdata, int sig, const struct sigaction* act, struct sigaction* oact, size_t sigsetsize)
{
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call rt_sigaction_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock-1);
	recheck_rt_sigaction (tdata->recheck_handle, sig, act, oact, sigsetsize, *ppthread_log_clock-1);
	struct sigaction_info* sfi = (struct sigaction_info*) &current_thread->op.sigaction_info_cache;
	if (oact) {
	    sfi->oact = oact;
	} else {
	    sfi->oact = 0;
	}
    }
}

static inline void sys_rt_sigaction_stop (int rc)
{
    struct sigaction_info* sfi = (struct sigaction_info*) &current_thread->op.sigaction_info_cache;
    //verify instead of tainting
    if (rc == 0 && sfi->oact) {
	//taint_syscall_memory_out ("rt_sigaction", (char *)sfi->oact, 20);
    }
}

static inline void sys_rt_sigprocmask_start (struct thread_data* tdata, int how, sigset_t* set, sigset_t* oset, size_t sigsetsize)
{
    //fprintf (stderr, "pid %d rt_sigprocmask: how %d set %p oset %p size %d set value %llu\n", current_thread->record_pid, how, set, oset, sigsetsize, set?*(uint64_t*) set: 0);
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call rt_sigprocmask_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock-1);
	recheck_rt_sigprocmask (tdata->recheck_handle, how, set, oset, sigsetsize, *ppthread_log_clock-1);
	if (oset) clear_mem_taints ((u_long)oset, sigsetsize);
    }
}

static inline void sys_sched_getaffinity_start (struct thread_data* tdata, pid_t pid, size_t cpusetsize, cpu_set_t* mask) { 
    struct sched_getaffinity_info* info = &tdata->op.sched_getaffinity_info_cache; 
    info->mask = mask;
    info->size = cpusetsize;
    tdata->save_syscall_info = (void*) info;
    if (tdata->recheck_handle) {
        int pid_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_EBX, 4, 0);
        OUTPUT_SLICE (0, "push ebx");
        OUTPUT_SLICE_INFO ("pid is probably tainted");
	OUTPUT_SLICE (0, "call sched_getaffinity_recheck");
	OUTPUT_SLICE_INFO("%lu", *ppthread_log_clock);
        OUTPUT_SLICE (0, "pop ebx");
	OUTPUT_SLICE_INFO("%lu", *ppthread_log_clock);
	recheck_sched_getaffinity (tdata->recheck_handle, pid, cpusetsize, mask, pid_tainted, *ppthread_log_clock);
    }
}

static inline void sys_sched_getaffinity_stop (int rc) { 
    struct sched_getaffinity_info* ri = &current_thread->op.sched_getaffinity_info_cache; 
    if (rc == 0) { 
        clear_mem_taints ((u_long)ri->mask, ri->size); //output will be verified
    }
    memset (&current_thread->op.sched_getaffinity_info_cache, 0, sizeof(struct sched_getaffinity_info));
    current_thread->save_syscall_info = 0;
}

static inline void sys_ftruncate_start (struct thread_data* tdata, u_int fd, u_long length) 
{ 
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call ftruncate_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	recheck_ftruncate (tdata->recheck_handle, fd, length, *ppthread_log_clock);
    }
}

static inline void sys_prctl_start (struct thread_data* tdata, int option, u_long arg2, u_long arg3, u_long arg4, u_long arg5)
{ 
    if (tdata->recheck_handle) {
	OUTPUT_SLICE(0, "call prctl_recheck");
	OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	if (option != PR_GET_NAME && option != PR_SET_NAME) {
	    fprintf (stderr, "prctl with option %d\n", option); // Only verified these options so far
	}
	recheck_prctl (tdata->recheck_handle, option, arg2, arg3, arg4, arg5, *ppthread_log_clock);
    }
}

static inline void sys_shmget_start (struct thread_data* tdata, key_t key, size_t size, int shmflg)
{ 
    fprintf (stderr, "[WARNING]: Calling shmget key 0x%x size 0x%x shmflag 0x%x\n", key, size, shmflg);
    if (tdata->recheck_handle) {
        OUTPUT_SLICE(0, "call shmget_recheck");
        OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
        recheck_shmget (tdata->recheck_handle, key, size, shmflg, *ppthread_log_clock);
    }
}

static inline void sys_shmget_stop (int rc) 
{
    taint_syscall_retval ("shmget");
}

static inline void sys_shmat_start (struct thread_data* tdata, int shmid, void* shmaddr, void* raddr, int shmflg)
{ 
    struct shmat_info* si = &current_thread->op.shmat_info_cache; 
    si->raddr = raddr;

    fprintf (stderr, "[WARNING]: Calling shmat shmid 0x%x shmaddr 0x%lx raddr 0x%lx shmflag 0x%x\n", shmid, (u_long) shmaddr, (u_long) raddr, shmflg);
    if (tdata->recheck_handle) {
        OUTPUT_SLICE (0, "push ecx");
        OUTPUT_SLICE_INFO ("");
        OUTPUT_SLICE (0, "call shmat_recheck");
        OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
        OUTPUT_SLICE (0, "pop ecx");
        OUTPUT_SLICE_INFO ("");
        recheck_shmat (tdata->recheck_handle, shmid, shmaddr, raddr, shmflg, *ppthread_log_clock);
    }
}

static inline void sys_shmat_stop (int rc) 
{
    struct shmat_info* si = &current_thread->op.shmat_info_cache; 
    fprintf (stderr, "sys_shmat returns %d raddr 0x%lx\n", rc, *((u_long *)si->raddr));
}

static inline void sys_ipc_rmid_start (struct thread_data* tdata, int shmid, int cmd)
{ 
    if (tdata->recheck_handle) {
        OUTPUT_SLICE (0, "push ecx");
        OUTPUT_SLICE_INFO ("");
        OUTPUT_SLICE (0, "call ipc_rmid_recheck");
        OUTPUT_SLICE_INFO ("clock %lu", *ppthread_log_clock);
        OUTPUT_SLICE (0, "pop ecx");
        OUTPUT_SLICE_INFO ("");
        recheck_ipc_rmid (tdata->recheck_handle, shmid, cmd, *ppthread_log_clock);
    }
}

static inline void sys_pthread_init (struct thread_data* tdata, int* status, u_long record_hoook, u_long replay_hook, void* user_clock_addr) 
{
    fprintf (stderr, "user-level mapped clock address %p, status %p, newly maped clock %p\n", user_clock_addr, status, ppthread_log_clock);
}

//LINUX kernel
/*
struct pt_regs {
    unsigned long bx;   0
    unsigned long cx;   1
    unsigned long dx;   2
    unsigned long si;   3
    unsigned long di;   4
    unsigned long bp;   5
    unsigned long ax;   6
    unsigned long ds;   7
    unsigned long es;   8
    unsigned long fs;   9
    unsigned long gs;   10
    unsigned long orig_ax;  11
    unsigned long ip;   12
    unsigned long cs;   13
    unsigned long flags;14
    unsigned long sp;   15
    unsigned long ss;   16
};
*/

static inline int get_reg_ckpt_index (REG reg)
{
    switch (reg) { 
        case LEVEL_BASE::REG_EBX: return 0;
        case LEVEL_BASE::REG_ECX: return 1;
        case LEVEL_BASE::REG_EDX: return 2;
        case LEVEL_BASE::REG_ESI: return 3;
        case LEVEL_BASE::REG_EDI: return 4;
        case LEVEL_BASE::REG_EBP: return 5;
        case LEVEL_BASE::REG_EAX: return 6;
        case LEVEL_BASE::REG_EIP: return 12;
        case LEVEL_BASE::REG_EFLAGS: return 14;
        case LEVEL_BASE::REG_ESP: return 15;
        default:
            assert (0);
    }
    return -1;
}

static inline void sys_jumpstart_runtime_start (struct thread_data* data, const CONTEXT* ctx) 
{

}

static inline void sys_jumpstart_runtime_end (long rc, CONTEXT* ctx) {
    if (function_level_tracking && current_thread->start_tracking == false) {
        printf ("jumpstart_runtime slice begins pid %d.\n", getpid());
        fprintf (stderr, "####### jumpstart_runtime slice begins.\n");
        fflush (stdout);
	current_thread->recheck_handle = open_recheck_log (current_thread->rg_id, current_thread->record_pid);
        if (fw_slice_print_header(current_thread->rg_id, current_thread, 1) < 0) {
            fprintf (stderr, "[ERROR] fw_slice_print_header fails.\n");
            return;
        }
        //skip log entries
        recheck_jumpstart_start (current_thread->recheck_handle);
        current_thread->start_tracking = true;
        first_thread = current_thread->record_pid;
    } 
    else if (function_level_tracking && current_thread->start_tracking == true) {
        current_thread->start_tracking = false;
        //sum up the checkpoint and verification set for patch_based_ckpt
        bool* read_reg = current_thread->patch_based_ckpt_info.read_reg;
        char* read_reg_value = current_thread->patch_based_ckpt_info.read_reg_value;
        set<u_long> *write_mem = current_thread->patch_based_ckpt_info.write_mem;
        map<u_long, char>* read_mem = current_thread->patch_based_ckpt_info.read_mem;
        set<int>* write_reg = current_thread->patch_based_ckpt_info.write_reg;
        //checkpoint 
        char ckpt_filename[256];
        snprintf (ckpt_filename, 256, "%s/pckpt", group_directory);
        int fd = open (ckpt_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        assert (fd > 0);
        //regs
        fprintf (stderr, "===== checkpoint reg ====\n");
        write_reg->insert (LEVEL_BASE::REG_ESP);
        write_reg->insert (LEVEL_BASE::REG_EFLAGS);
        
        unsigned int reg_size = write_reg->size();
        int ret = write (fd, (char*) &reg_size, sizeof (unsigned int));
        assert (ret == sizeof (unsigned int)); 

        for (set<int>::iterator iter = write_reg->begin(); iter != write_reg->end(); ++iter) { 
            if (REG_Size ((REG)*iter) == 4) {
                PIN_REGISTER value;
                PIN_GetContextRegval (ctx, (REG) *iter, (UINT8*)&value);
                fprintf (stderr, "%s: %u (%x)\n", REG_StringShort((REG)*iter).c_str(), *((unsigned int*)&value), *((unsigned int*)&value));
                int index = get_reg_ckpt_index ((REG)(*iter)); 
                ret = write (fd, (char*) &index, sizeof(int));
                assert (ret == sizeof(int));
                ret = write (fd, (char*) ((unsigned long*) &value), sizeof(unsigned long));
                assert (ret == sizeof(unsigned long));
            } else {
                int tmp = -1;
                ret = write (fd, (char*) &tmp, sizeof (int));
                assert (ret == sizeof(int));
                ret = write (fd, (char*) &tmp, sizeof (unsigned long));
                assert (ret == sizeof (unsigned long));
                fprintf (stderr, "%s: -----skip-----\n", REG_StringShort ((REG)*iter).c_str());
            }
        }

        //print out  mmap regions
        bitset<0xc0000> write_pages;
        char procname[256], buf[256];
        sprintf (procname, "/proc/%d/maps", getpid());
        FILE* file = fopen(procname, "r");
        while (!feof(file)) {
            if (fgets (buf+2, sizeof(buf)-2, file)) {
                printf ("%s", buf);
                buf[0] = '0'; buf[1] = 'x'; buf[10] = '\0';
                u_long start = strtold(buf, NULL);
                buf[9] = '0'; buf[10] = 'x'; buf[19] = '\0';
                u_long end = strtold(buf+9, NULL);
                if (buf[20] == 'r' || buf[21] == 'w' || buf[22] == 'x') {
                    for (u_long addr = start; addr < end; addr+=PAGE_SIZE) {
                        write_pages.set(addr/PAGE_SIZE, true);
                    }
                } else {
                    //TODO, let's track the deallocated memory regions by munmap and mmap syscalls instead of this heuristic
                    fprintf (stderr, "[TODO] skipping regions.\n");
                }
            }
        }
        fclose(file);
        fflush(stdout);

        fprintf (stderr, "===== checkpoint mem ====\n");
        for (set<u_long>::iterator iter = write_mem->begin(); iter != write_mem->end(); ++iter) { 
            fprintf (stderr, "0x%lx", *iter);
            if (!write_pages.test (*iter/PAGE_SIZE)) {
                fprintf (stderr, " doesn't exist\n");
                continue;
            }
            if (is_existed (*iter) == false) {
                fprintf (stderr, " has been deallocated?  ");
                //continue;
            }
            fprintf (stderr, ": %u\n", (unsigned int)(*(unsigned char*)(*iter)));
            u_long addr = *iter;
            ret = write (fd, (char*) &addr, sizeof (unsigned long));
            assert (ret == sizeof(unsigned long));
            ret = write (fd, (char*) (*iter), sizeof (char));
            assert (ret == sizeof (char));
        }
        close (fd);

        //verifications
        fprintf (stderr, "===== verification reg ==== \n");
        for (unsigned int i = 0; i < sizeof(read_reg)/sizeof(bool); ++i) { 
            if (read_reg[i]) { 
                fprintf (stderr, "%d (%s): %u\n", i, REG_StringShort((REG) (i/REG_SIZE)).c_str(), (unsigned int)read_reg_value[i]);
            }
        }
        fprintf (stderr, "===== verification mem ==== \n");
        for (map<u_long, char>::iterator iter = read_mem->begin(); iter != read_mem->end(); ++iter) {
            fprintf (stderr, "0x%lx: %u\n", iter->first, (unsigned int)(unsigned char) iter->second);
        }
        fprintf (stderr, " ***remember to check the esp ,ebp and eflags; also be careful about ax/al/ah..\n");
        printf ("jumpstart_runtime slice ends.\n");
        fflush (stdout);
        fprintf (stderr, "###### jumpstart_runtime slice ends.\n");
    }
}

void syscall_start(struct thread_data* tdata, int sysnum, ADDRINT syscallarg0, ADDRINT syscallarg1,
		   ADDRINT syscallarg2, ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5,
                   const CONTEXT* ctx)
{ 
    switch (sysnum) {
        case SYS_execve:
	    sys_execve_start (tdata, (char*) syscallarg0, (char**) syscallarg1, (char**) syscallarg2); 
	    break;
        case SYS_ftime:
            sys_pthread_init (tdata, (int*) syscallarg0, (u_long) syscallarg1, (u_long) syscallarg2, (void*) syscallarg3); 
            break;
        case SYS_clone:
            sys_clone_start (tdata, (int) syscallarg2, (pid_t*) syscallarg3, (pid_t*) syscallarg4);
            break;
        case SYS_open:
            sys_open_start(tdata, (char *) syscallarg0, (int) syscallarg1, (int) syscallarg2);
            break;
        case SYS_openat:
            sys_openat_start(tdata, (int) syscallarg0, (char*) syscallarg1, (int) syscallarg2, (int) syscallarg3);
            break;
        case SYS_close:
            sys_close_start(tdata, (int) syscallarg0); 
            break; 
        case SYS_waitpid:
            sys_waitpid_start(tdata, (pid_t) syscallarg0, (int  *) syscallarg1, (int) syscallarg2);
            break;
        case SYS_dup2:
	    sys_dup2_start(tdata, (int) syscallarg0, (int) syscallarg1);
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
        case SYS_getdents:
	    sys_getdents_start(tdata, (unsigned int) syscallarg0, (char *) syscallarg1, (unsigned int) syscallarg2);
	    break;
        case SYS_getdents64:
	    sys_getdents64_start(tdata, (unsigned int) syscallarg0, (char *) syscallarg1, (unsigned int) syscallarg2);
	    break;
        case SYS_ioctl:
	    sys_ioctl_start(tdata, (u_int) syscallarg0, (u_int) syscallarg1, (char *) syscallarg2);
            break;
        case SYS__newselect:
            sys__newselect_start(tdata, (int) syscallarg0, (fd_set *) syscallarg1, (fd_set *) syscallarg2,
				 (fd_set *) syscallarg3, (struct timeval *) syscallarg4);
            break;
        case SYS_mkdir:
            sys_mkdir_start (tdata, (char*) syscallarg0, (int) syscallarg1);
            break;
        case SYS_unlink:
            sys_unlink_start (tdata, (char*) syscallarg0);
            break;
        case SYS_chmod:
	    sys_chmod_start (tdata, (char*) syscallarg0, (mode_t) syscallarg1);
            break;
        case SYS_inotify_init1:
	    sys_inotify_init1_start (tdata, (int) syscallarg0);
	    break;
        case SYS_inotify_add_watch:
	    sys_inotify_add_watch_start (tdata, (int) syscallarg0, (char *) syscallarg1, (uint32_t) syscallarg2);
	    break;
        case SYS_ipc: {
	    u_int call = (u_int) syscallarg0;
            tdata->socketcall = call;
	    switch (call) {
	    case SHMGET:
		sys_shmget_start (tdata, (key_t) syscallarg1, (size_t) syscallarg2, (int) syscallarg3);
		break; 
	    case SHMAT:
		sys_shmat_start (tdata, (int) syscallarg1, (void *) syscallarg2, (void *) syscallarg3, (int) syscallarg4);
		break;
	    case SHMCTL: {
		u_int opcode = (u_int) syscallarg2 & 0xff;
		switch (opcode) {
		case IPC_RMID:
		    sys_ipc_rmid_start (tdata, (int) syscallarg1, (int) syscallarg2);
		    break;
		default:
		    fprintf (stderr, "shmctl shmid %x unhandled opcode %d %d\n", (int) syscallarg1, opcode, IPC_RMID);
		}
		break;
	    }
	    default:
		fprintf (stderr, "Unhandled ipc call type %u\n", call);
		break;
	    }
	    break;
        }
        case SYS_socketcall:
        {
            int call = (int) syscallarg0;
            unsigned long *args = (unsigned long *)syscallarg1;
            tdata->socketcall = call;
            switch (call) {
                case SYS_SOCKET:
                    sys_socket_start(tdata, (int)args[0], (int)args[1], (int)args[2]);
                    break;
                case SYS_CONNECT:
                    sys_connect_start(tdata, (int)args[0], (struct sockaddr *)args[1], (socklen_t)args[2]);
                    break;
                case SYS_RECV:
                    sys_recv_start(tdata, (int)args[0], (void *)args[1], (size_t)args[2], (int)args[3]);
                    break;
                case SYS_RECVMSG:
                    sys_recvmsg_start(tdata, (int)args[0], (struct msghdr *)args[1], (int)args[2]);
                    break;
                case SYS_SENDMSG:
                    sys_sendmsg_start(tdata, (int)args[0], (struct msghdr *)args[1], (int)args[2]);
                    break;
	        case SYS_SENDTO:
                    sys_sendto_start(tdata, (int)args[0], (char *)args[1], (size_t)args[2], (int)args[3], (const struct sockaddr*)args[4], (socklen_t) args[5]);
		    break;
                case SYS_RECVFROM:
                    sys_recvfrom_start(tdata, (int)args[0], (char *)args[1], (size_t)args[2], (int)args[3], (struct sockaddr*)args[4], (socklen_t*) args[5]);
                    break;
	        case SYS_SEND:
                    sys_send_start(tdata, (int)args[0], (char *)args[1], (size_t)args[2], (int)args[3]);
		    break;
                case SYS_BIND:
                    if (tdata->recheck_handle) {
                        OUTPUT_SLICE(0, "call bind_recheck");
			OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
                        recheck_connect_or_bind (tdata->recheck_handle, (int)args[0], (struct sockaddr*)args[1], (socklen_t)args[2], *ppthread_log_clock);
                    }
                    break;
	        case SYS_GETSOCKNAME:
		    sys_getsockname_start (tdata, (int)args[0], (struct sockaddr*)args[1], (socklen_t *)args[2]);
		    break;
	        case SYS_GETPEERNAME:
		    sys_getpeername_start (tdata, (int)args[0], (struct sockaddr*)args[1], (socklen_t *)args[2]);
		    break;
	        case SYS_SETSOCKOPT:
		    sys_setsockopt_start (tdata, (int)args[0], (int)args[1], (int)args[2], (const void*)args[3], (socklen_t)args[4]);
		    break;
                default:
                    fprintf (stderr, "[UNHANDLED] socketcall unhandled %d\n", call);
                    break;
            }
            break;
        }
        case SYS_fcntl64:
	    sys_fcntl64_start (tdata, (int)syscallarg0, (int)syscallarg1,(void *)syscallarg2);
	    break;
        case SYS_mmap:
        case SYS_mmap2:
            sys_mmap_start(tdata, (u_long)syscallarg0, (int)syscallarg1, (int)syscallarg2, (int)syscallarg4, (int)syscallarg3);
            break;
        case SYS_munmap:
            if (current_thread->start_tracking) printf ("munmap 0x%lx size %d\n", (u_long)syscallarg0, (int)syscallarg1); 
            if (current_thread->start_tracking) delete_mmap_region ((u_long)syscallarg0, (int)syscallarg1);
            break;
        case SYS_mprotect:
            if (current_thread->start_tracking) change_mmap_region ((u_long)syscallarg0, (int)syscallarg1, (int)syscallarg2);
            break;
        case SYS_mremap:
	    sys_mremap_start (tdata, (void*)syscallarg0, (size_t)syscallarg1, (size_t)syscallarg2, (int)syscallarg3, (void*)syscallarg4);
            break;
        case SYS_madvise:
            if (current_thread->start_tracking) printf ("madvise 0x%lx size %d, advise %x\n", (u_long)syscallarg0, (int)syscallarg1, (int)syscallarg2); 
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
	case SYS_gettid:
	    sys_gettid_start (tdata);
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
        case SYS_getresuid32:
	    sys_getresuid_start (tdata, (uid_t *) syscallarg0, (uid_t *) syscallarg1, (uid_t *) syscallarg2);
	    break;
        case SYS_getresgid32:
	    sys_getresgid_start (tdata, (gid_t *) syscallarg0, (gid_t *) syscallarg1, (gid_t *) syscallarg2);
	    break;
	case SYS_setpgid:
	    sys_setpgid_start (tdata, (int) syscallarg0, (int) syscallarg1);
	    break;
        case SYS_ugetrlimit:
	    sys_ugetrlimit_start (tdata, (int) syscallarg0, (struct rlimit *) syscallarg1);
	    break;
        case SYS_setrlimit:
	    sys_setrlimit_start (tdata, (int) syscallarg0, (struct rlimit *) syscallarg1);
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
	    sys_set_tid_address_start (tdata, (int*) syscallarg0);
	    break;
      	case SYS_set_robust_list:
	    sys_set_robust_list (tdata, (struct robust_list_head *) syscallarg0, (size_t) syscallarg1);
	    break;
	case SYS_clock_gettime:
	    sys_clock_gettime_start (tdata, (clockid_t) syscallarg0, (struct timespec*) syscallarg1);
	    break;
        case SYS_clock_getres:
	    sys_clock_getres_start (tdata, (clockid_t) syscallarg0, (struct timespec*) syscallarg1);
	    break;
	case SYS_access:
	    if (tdata->recheck_handle) {
		recheck_access (tdata->recheck_handle, (char *) syscallarg0, (int) syscallarg1, *ppthread_log_clock);
		OUTPUT_SLICE(0, "call access_recheck");
		OUTPUT_SLICE_INFO("clock %lu", *ppthread_log_clock);
	    }
	    break;
	case SYS_pipe:
	    sys_pipe_start (tdata, (int*)syscallarg0);
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
        case SYS_eventfd2:
            sys_eventfd2_start (tdata, (u_int) syscallarg0, (int) syscallarg1);
            break;
        case SYS_poll:
	    sys_poll_start (tdata, (struct pollfd *) syscallarg0, (u_int) syscallarg1, (int) syscallarg2);
            break;
        case SYS_kill:
	    sys_kill_start (tdata, (pid_t) syscallarg0, (int) syscallarg1);
            break;
        case SYS_futex:
	    sys_futex_start (tdata, (int *) syscallarg0, (int) syscallarg1, (int) syscallarg2, (struct timespec*) syscallarg3, (int *) syscallarg4, (int) syscallarg5);
	    break;
        case SYS_rt_sigaction:
	    sys_rt_sigaction_start (tdata, (int) syscallarg0, (const struct sigaction *) syscallarg1, (struct sigaction *) syscallarg2, (size_t) syscallarg3);
	    break;
        case SYS_rt_sigprocmask:
	    sys_rt_sigprocmask_start (tdata, (int) syscallarg0, (sigset_t *) syscallarg1, (sigset_t *) syscallarg2, (size_t) syscallarg3);
	    break;
        case SYS_sched_getaffinity:
            sys_sched_getaffinity_start (tdata, (pid_t)syscallarg0, (size_t)syscallarg1, (cpu_set_t*)syscallarg2);
            break;
        case SYS_ftruncate:
            sys_ftruncate_start (tdata, (u_int)syscallarg0, (u_long)syscallarg1);
            break;
        case SYS_nanosleep:
            printf ("skipped syscall nanosleep.\n");
            break;
        case SYS_prctl:
	    sys_prctl_start (tdata, (int) syscallarg0, (u_long) syscallarg1, (u_long) syscallarg2, (u_long) syscallarg3, (u_long) syscallarg4);
	    break;
        case 222:
            sys_jumpstart_runtime_start (tdata, ctx);
            break;
        case SYS_getcwd:
            fprintf (stderr, "[ERROR]getcwd is not handled buffer is %x\n", syscallarg0);
            break;
    }
}

void syscall_end(int sysnum, ADDRINT ret_value, ADDRINT ret_errno, CONTEXT* ctx)
{
    int rc = (int) ret_value;

    detect_slice_ordering (sysnum);

    switch(sysnum) {
        case SYS_clone:
            sys_clone_stop (rc);
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
        case SYS__newselect:
            sys__newselect_stop(rc);
            break;
        case SYS_mmap:
        case SYS_mmap2:
            sys_mmap_stop(rc);
            break;
        case SYS_munmap:
            if (current_thread->start_tracking) print_memory_regions ();
            break;
	case SYS_gettimeofday:
	    sys_gettimeofday_stop(rc);
	    break;
        case SYS_time:
            sys_time_stop (rc);
            break;
        case SYS_mremap:
            sys_mremap_stop (rc);
            break;
        case SYS_getdents:
	    sys_getdents_stop(rc);
	    break;
        case SYS_getdents64:
	    sys_getdents64_stop(rc);
	    break;
        case SYS_ioctl:
	    sys_ioctl_stop(rc);
	    break;
	case SYS_getpid:
	    sys_getpid_stop(rc);
	    break;
	case SYS_gettid:
	    sys_gettid_stop(rc);
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
        case SYS_clock_getres:
	    sys_clock_getres_stop(rc);
	    break;
        case SYS_sched_getaffinity:
            sys_sched_getaffinity_stop (rc);
            break;
        case SYS_poll:
            sys_poll_stop (rc);
            break;
        case SYS_rt_sigaction:
            sys_rt_sigaction_stop (rc);
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
                    sys_recv_stop(rc);
                    break;
                case SYS_RECVMSG:
                    sys_recvmsg_stop(rc);
		    break;
                case SYS_SENDMSG:
                    sys_sendmsg_stop(rc);
                    break;
                case SYS_SENDTO:
                    sys_sendto_stop(rc);
                    break;
                case SYS_RECVFROM:
                    sys_recvfrom_stop (rc);
                    break;
    	        case SYS_SEND:
		    sys_send_stop(rc);
		    break;
            }
            current_thread->socketcall = 0;
            break;
        }
        case SYS_ipc: {
	    switch (current_thread->socketcall) {
	    case SHMGET:
		sys_shmget_stop (rc);
		break;
	    case SHMAT:
		sys_shmat_stop (rc);
		break;
	    }
            current_thread->socketcall = 0;
	    break;
	}
        case 222:
            sys_jumpstart_runtime_end(rc, ctx);
            break;

    }
    //Note: the checkpoint is always taken after a syscall and ppthread_log_clock should be the next expected clock
    if (*ppthread_log_clock >= checkpoint_clock) { 

	fprintf(stderr, "%d: finish generating slice and calling try_to_exit\n", PIN_GetTid());

	// First, restore memory addresses  //this will be done on the first thread
	if (current_thread->record_pid != first_thread) {
            for (map<pid_t, struct thread_data*>::iterator iter = active_threads.begin(); iter != active_threads.end(); ++iter) { 
                if (iter->first == first_thread) { 
                    //wait for the ckpt thread to wake first thread up
                    slice_synchronize (current_thread, iter->second);
                    OUTPUT_MAIN_THREAD (iter->second, "jmp restore_mem");
                    //then first thread sleeps and let the ckpt thread continue
                    OUTPUT_MAIN_THREAD (iter->second, "restore_mem_done:");
                    main_file_thread_wakeup (iter->second, current_thread->record_pid);	
                    main_file_thread_wait (iter->second);	                       
                }
            }
        } else { 
            OUTPUT_MAIN_THREAD (current_thread, "jmp restore_mem");
            OUTPUT_MAIN_THREAD (current_thread, "restore_mem_done:");
        }

	// Second, adjust pthread status - because we may call pthread functions in the next step
	if (pthread_log_status_addr) {
	    OUTPUT_MAIN_THREAD (current_thread, "mov dword ptr [0x%lx], 3", pthread_log_status_addr); // Reset the pthread_log_status to PTHREAD_LOG_OFF
	}
	if (dumbass_link_addr) {
	    OUTPUT_MAIN_THREAD (current_thread, "mov dword ptr [0x%lx], 3", dumbass_link_addr); // Reset the dumbass link pthread_log_status to PTHREAD_LOG_OFF
	}

        // Third, wake up other threads so that they can restore their pthread state
	// Wait for them to respond so that we know that they are done
        for (map<pid_t, struct thread_data*>::iterator iter = active_threads.begin(); iter != active_threads.end(); ++iter) { 
            if (iter->second != current_thread) {
		// We do this in the main c file since slice c file has returned at this point
		slice_synchronize (current_thread, iter->second);

		sync_my_pthread_state (iter->second);
		main_file_thread_wakeup (iter->second, current_thread->record_pid);
	    }
        }

	// Fourth, restore pthread state for this thread and readjust jiggled mem protections
	sync_my_pthread_state (current_thread);
	OUTPUT_MAIN_THREAD (current_thread, "call upprotect_mem");

	// Fifth, another barrier, so that all threads resume execution only when memory state is
	// completely restored
        for (map<pid_t, struct thread_data*>::iterator iter = active_threads.begin(); iter != active_threads.end(); ++iter) { 
            if (iter->second != current_thread) {
		slice_synchronize (current_thread, iter->second);               // Main thread wakes and waits for ack

                main_file_thread_wait (iter->second);	                        // This waits to be woken
		main_file_thread_wakeup (iter->second, current_thread->record_pid);	// And this sends the ack

		fw_slice_print_footer (iter->second, 0, 0);
	    }
	}

	if (rc == -1) {
	    fprintf (stderr, "I think I should change sysret %d to %d when I see rc=-1 and errno=%d - is this right???\n", rc, -ret_errno, ret_errno);
	    rc = -ret_errno;
	}
	fw_slice_print_footer (current_thread, 1, rc); // Do we care about errno here

#ifndef OPTIMIZED
        count_mem_taints();
#endif

	//stop tracing after this 
	int calling_dd = dift_done ();
	while (!calling_dd || is_pin_attaching(dev_fd)) {
		usleep (1000);
	}
	try_to_exit(dev_fd, PIN_GetPid());
	PIN_ExitApplication(0); 
    }
}

// called before every application system call
static void instrument_syscall(ADDRINT syscall_num, 
			ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2,
			ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5,
                        const CONTEXT* ctx
                        )
{   
    int sysnum = (int) syscall_num;

    // Because of Pin restart issues, this function alone has to use PIN thread-specific data
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    tdata->sysnum = sysnum;
    tdata->syscall_in_progress = true;

    if (sysnum == 31) {
	tdata->ignore_flag = (u_long) syscallarg1;
    }
    if (sysnum == 56) {
	if (pthread_log_status_addr != 0 && pthread_log_status_addr != (u_long) syscallarg0) {
	    fprintf (stderr, "[ERROR] pthread log status address getting set multiple times - need collection(!)'\n");
	}
	pthread_log_status_addr = (u_long) syscallarg0;
    }
    if (sysnum == 58) {
	if (dumbass_link_addr != 0 && dumbass_link_addr != (u_long) syscallarg0) {
	    fprintf (stderr, "[ERROR] dumbass link address getting set multiple times - need collection(!)'\n");
	}
	dumbass_link_addr = (u_long) syscallarg0;
    }
    if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || 
	sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	check_clock_before_syscall (dev_fd, (int) syscall_num);
    }
    if (sysnum == 252) dift_done();
    
    if (segment_length && *ppthread_log_clock >= segment_length) {
	// Done with this replay - do exit stuff now because we may not get clean unwind

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
    detect_slice_ordering (sysnum);
	
    syscall_start(tdata, sysnum, syscallarg0, syscallarg1, syscallarg2, 
		  syscallarg3, syscallarg4, syscallarg5, ctx);
    
    tdata->app_syscall = syscall_num;
}

static void syscall_after_redo (ADDRINT ip)
{
    if (redo_syscall) {
	u_long rc, len, retval;
	int syscall_to_redo = check_for_redo(dev_fd);
	if (syscall_to_redo == 192) {
	    redo_syscall--;
	    retval = redo_mmap (dev_fd, &rc, &len);
	    if (retval) fprintf (stderr, "redo_mmap failed, rc=%ld\n", retval);
	    clear_mem_taints (rc, len);
	    current_thread->app_syscall = 0;  
	}
	else if(syscall_to_redo == 91) { 
	    redo_syscall--;
	    retval = redo_munmap (dev_fd);
	    fprintf(stderr, "running the redo_munmap!\n");
	    if (retval) fprintf (stderr, "redo_mmap failed, rc=%ld\n", retval);
	    current_thread->app_syscall = 0;
	}      
    } else if (current_thread->app_syscall == 999) {
	check_clock_after_syscall (dev_fd);
	current_thread->app_syscall = 0;  
    }
}

static void instrument_syscall_ret(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    if (current_thread->app_syscall != 999) current_thread->app_syscall = 0;

    ADDRINT ret_value = PIN_GetSyscallReturn(ctxt, std);
    if (current_thread->sysnum == SYS_gettid) {
	// Pin "helpfully" changes the return value to the replay tid - change it back here
	PIN_SetContextReg (ctxt, LEVEL_BASE::REG_EAX, current_thread->record_pid);
    }

    if (!(segment_length && *ppthread_log_clock > segment_length)) {
	ADDRINT ret_errno = 0;
	if (ret_value == (ADDRINT) -1) {
	    ret_errno = PIN_GetSyscallErrno(ctxt, std);
	}
	syscall_end(current_thread->sysnum, ret_value, ret_errno, ctxt);
    }

    if (current_thread->syscall_in_progress) {
	// reset the syscall number after returning from system call
	increment_syscall_cnt (current_thread->sysnum);
	current_thread->syscall_in_progress = false;
    }
    ++ total_syscall_cnt;

    // The first syscall returns twice 
    if (global_syscall_cnt > 1) { 
	current_thread->sysnum = 0;
    }
}

// Trivial analysis routine to pass its argument back in an IfCall 
// so that we can use it to control the next piece of instrumentation.
static ADDRINT returnArg (BOOL arg)
{
    return arg;
}

#ifdef OPTIMIZED
#define SLAB_SIZE (1024*1024)
static inline char* get_copy_of_disasm (INS ins) 
{ 
    static char* slab = NULL;
    static int slab_bytes = 0;

    if (slab == NULL || slab_bytes > SLAB_SIZE-256) {
	slab = (char *) malloc(SLAB_SIZE);
	slab_bytes = 0;
    }
    string s = INS_Disassemble(ins);
    char* p = strcpy (slab+slab_bytes, s.c_str());
    slab_bytes += s.length()+1;
    return p;
}
#else
static inline char* get_copy_of_disasm (INS ins) { 
	const char* tmp = INS_Disassemble (ins).c_str();
	return strdup (tmp);
}
#endif

static inline void put_copy_of_disasm (char* str) { 
	//TODO memory leak
}

#define SETUP_BASE_INDEX(base_reg,index_reg) \
    int t_base_reg = 0;			     \
    int t_index_reg = 0;		     \
    int base_reg_size = 0;		     \
    int index_reg_size = 0;		     \
    int base_reg_u8 = 0;		     \
    int index_reg_u8 = 0;			     \
    IARG_TYPE base_reg_value_type = IARG_UINT32;      \
    IARG_TYPE index_reg_value_type = IARG_UINT32;     \
    if (REG_valid(base_reg)) {			      \
	t_base_reg = translate_reg (base_reg);	      \
	base_reg_size = REG_Size (base_reg);	      \
	base_reg_u8 = REG_is_Upper8 (base_reg);	      \
	base_reg_value_type = IARG_REG_VALUE;	      \
    }						      \
    if (REG_valid(index_reg)) {			      \
	t_index_reg = translate_reg (index_reg);      \
	index_reg_size = REG_Size (index_reg);	      \
	index_reg_u8 = REG_is_Upper8 (index_reg);     \
	index_reg_value_type = IARG_REG_VALUE;	      \
    }

#define PASS_BASE_INDEX	 IARG_ADDRINT, t_base_reg,	\
	IARG_UINT32, base_reg_size,			\
	base_reg_value_type, base_reg,			\
	IARG_UINT32, base_reg_u8,			\
	IARG_ADDRINT, t_index_reg,			\
	IARG_UINT32, index_reg_size,			\
	index_reg_value_type, index_reg,		\
	IARG_UINT32, index_reg_u8			

static inline void fw_slice_src_reg (INS ins, REG srcreg) 
{ 
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_reg),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(srcreg), 
		   IARG_UINT32, REG_Size(srcreg),
		   IARG_REG_CONST_REFERENCE, srcreg, 
		   IARG_UINT32, REG_is_Upper8(srcreg),
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_fpureg (INS ins, REG srcreg, int fp_stack_change) 
{
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_fpureg),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(srcreg), 
		   IARG_UINT32, REG_Size(srcreg),
                   IARG_CONST_CONTEXT,
		   IARG_UINT32, REG_is_Upper8(srcreg),
                   IARG_ADDRINT, fp_stack_change,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_fpureg2mem (INS ins, REG srcreg, REG base_reg, REG index_reg, int fp_stack_change) 
{
    SETUP_BASE_INDEX(base_reg, index_reg);
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_fpureg2mem),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(srcreg), 
		   IARG_UINT32, REG_Size(srcreg),
                   IARG_CONST_CONTEXT,
		   IARG_UINT32, REG_is_Upper8(srcreg),
		   IARG_MEMORYWRITE_EA,
		   IARG_UINT32, INS_MemoryWriteSize(ins),
                   IARG_ADDRINT, fp_stack_change,
		   PASS_BASE_INDEX,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_reg2mem (INS ins, REG srcreg, uint32_t src_regsize, REG base_reg, REG index_reg)  
{
    SETUP_BASE_INDEX(base_reg, index_reg);
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_reg2mem),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(srcreg), 
		   IARG_UINT32, src_regsize,
		   IARG_REG_CONST_REFERENCE, srcreg, 
		   IARG_UINT32, REG_is_Upper8(srcreg),
		   IARG_MEMORYWRITE_EA,
		   IARG_UINT32, INS_MemoryWriteSize(ins),
		   PASS_BASE_INDEX,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_mem (INS ins, REG base_reg, REG index_reg)  
{
    char* str = get_copy_of_disasm (ins);
    SETUP_BASE_INDEX(base_reg, index_reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_mem),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_MEMORYREAD_EA,
		   IARG_UINT32, INS_MemoryReadSize(ins),
		   PASS_BASE_INDEX,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_memflag (INS ins, REG base_reg, REG index_reg, int mask)  
{
    char* str = get_copy_of_disasm (ins);
    SETUP_BASE_INDEX(base_reg, index_reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_memflag),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_MEMORYREAD_EA,
		   IARG_UINT32, INS_MemoryReadSize(ins),
		   PASS_BASE_INDEX,
		   IARG_UINT32, mask,
		   IARG_REG_VALUE, REG_EFLAGS, 
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_mem2fpureg (INS ins, REG base_reg, REG index_reg, int fp_stack_change) 
{
    char* str = get_copy_of_disasm (ins);
    SETUP_BASE_INDEX(base_reg, index_reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(fw_slice_mem2fpureg),
            IARG_FAST_ANALYSIS_CALL,
            IARG_INST_PTR,
            IARG_PTR, str,
            IARG_MEMORYREAD_EA,
            IARG_UINT32, INS_MemoryReadSize(ins),
            IARG_CONST_CONTEXT, 
            IARG_ADDRINT, fp_stack_change, 
            PASS_BASE_INDEX,
            IARG_END);
    put_copy_of_disasm (str);
}

//If we move an imm value to an memory address, we still need to verify the base and index registers if they're tainted. Therefore, at least the verifications need to be in the slice
static inline void fw_slice_src_dst_mem (INS ins, REG base_reg, REG index_reg)  
{
    char* str = get_copy_of_disasm (ins);
    SETUP_BASE_INDEX(base_reg, index_reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_2mem),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_MEMORYWRITE_EA,
		   IARG_UINT32, INS_MemoryReadSize(ins),
		   PASS_BASE_INDEX,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_regreg (INS ins, REG dstreg, REG srcreg) 
{ 
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_regreg),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(dstreg),
		   IARG_UINT32, REG_Size(dstreg),
		   IARG_REG_CONST_REFERENCE, dstreg, 
		   IARG_UINT32, REG_is_Upper8(dstreg),
		   IARG_UINT32, translate_reg(srcreg),
		   IARG_UINT32, REG_Size(srcreg),
		   IARG_REG_CONST_REFERENCE, srcreg, 
		   IARG_UINT32, REG_is_Upper8(srcreg),
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_regregflag (INS ins, REG dstreg, REG srcreg, int mask) 
{ 
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_regregflag),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(dstreg),
		   IARG_UINT32, REG_Size(dstreg),
		   IARG_REG_CONST_REFERENCE, dstreg, 
		   IARG_UINT32, REG_is_Upper8(dstreg),
		   IARG_UINT32, translate_reg(srcreg),
		   IARG_UINT32, REG_Size(srcreg),
		   IARG_REG_CONST_REFERENCE, srcreg, 
		   IARG_UINT32, REG_is_Upper8(srcreg),
		   IARG_UINT32, mask,
		   IARG_REG_VALUE, REG_EFLAGS, 
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_fpuregfpureg (INS ins, REG dstreg, REG srcreg, int fp_stack_change) 
{ 
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_fpuregfpureg),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(dstreg),
		   IARG_UINT32, REG_Size(dstreg),
		   IARG_UINT32, REG_is_Upper8(dstreg),
		   IARG_UINT32, translate_reg(srcreg),
		   IARG_UINT32, REG_Size(srcreg),
                   IARG_CONST_CONTEXT,
		   IARG_UINT32, REG_is_Upper8(srcreg),
                   IARG_ADDRINT, fp_stack_change,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_regmem (INS ins, REG reg, uint32_t reg_size,  IARG_TYPE mem_ea, uint32_t memsize, REG base_reg, REG index_reg) 
{ 
    char* str = get_copy_of_disasm (ins);
    SETUP_BASE_INDEX(base_reg, index_reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_memreg),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_ADDRINT, translate_reg(reg), 
		   IARG_UINT32, reg_size,
		   IARG_REG_CONST_REFERENCE, reg, 
		   IARG_UINT32, REG_is_Upper8(reg),
		   mem_ea, 
		   IARG_UINT32, memsize,
		   PASS_BASE_INDEX,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_fpuregmem (INS ins, REG reg, uint32_t reg_size,  IARG_TYPE mem_ea, uint32_t memsize, REG base_reg, REG index_reg, int fp_stack_change) 
{ 
    char* str = get_copy_of_disasm (ins);
    SETUP_BASE_INDEX(base_reg, index_reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_memfpureg),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_ADDRINT, translate_reg(reg), 
		   IARG_UINT32, reg_size,
                   IARG_CONST_CONTEXT,
		   IARG_UINT32, REG_is_Upper8(reg),
		   mem_ea, 
		   IARG_UINT32, memsize,
                   IARG_UINT32, fp_stack_change,
		   PASS_BASE_INDEX,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_flag (INS ins, uint32_t mask) 
{ 
    char* str = get_copy_of_disasm (ins);

    if (INS_IsIndirectBranchOrCall(ins) && mask == 0) {
	if (INS_OperandIsReg(ins, 0)) {
	    REG reg = INS_OperandReg(ins, 0);
	    INS_InsertCall(ins, IPOINT_BEFORE,
			   AFUNPTR(fw_slice_jmp_reg),
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_ADDRINT, translate_reg(reg),
			   IARG_UINT32, REG_Size(reg),
			   IARG_UINT32, REG_is_Upper8(reg),
			   IARG_BRANCH_TARGET_ADDR,
			   IARG_END);
	} else if (INS_OperandIsMemory(ins, 0)) {
	    INS_InsertCall(ins, IPOINT_BEFORE,
			   AFUNPTR(fw_slice_jmp_mem),
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_MEMORYREAD_EA,
			   IARG_UINT32, INS_MemoryReadSize(ins),
			   IARG_BRANCH_TARGET_ADDR,
			   IARG_END);
	}
    } else {
	if (str[0] == 'j' && strncmp(str, "jmp", 3)) {
	    INS_InsertCall(ins, IPOINT_BEFORE,
			   AFUNPTR(fw_slice_condjump),
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_UINT32, mask,
			   IARG_BRANCH_TAKEN,
			   IARG_BRANCH_TARGET_ADDR,
			   IARG_CONST_CONTEXT, 
			   IARG_END);
	} else {
	    INS_InsertCall(ins, IPOINT_BEFORE,
			   AFUNPTR(fw_slice_flag),
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_UINT32, mask,
			   IARG_END);
	}
    }
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_regflag (INS ins, REG reg, uint32_t mask) 
{ 
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_regflag),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(reg),
		   IARG_UINT32, REG_Size(reg),
		   IARG_REG_CONST_REFERENCE, reg, 
		   IARG_UINT32, REG_is_Upper8(reg),
		   IARG_UINT32, mask,
		   IARG_REG_VALUE, REG_EFLAGS, 
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_flag2mem (INS ins, uint32_t mask, REG base_reg, REG index_reg) { 
    char* str = get_copy_of_disasm (ins);
    SETUP_BASE_INDEX(base_reg, index_reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_flag2mem),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, mask,
		   IARG_MEMORYWRITE_EA,
		   IARG_UINT32, INS_MemoryWriteSize(ins),
		   PASS_BASE_INDEX,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_regregreg (INS ins, REG dstreg, REG srcreg, REG countreg) 
{ 
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_regregreg),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(dstreg),
		   IARG_UINT32, translate_reg(srcreg),
		   IARG_UINT32, translate_reg(countreg),
		   IARG_UINT32, REG_Size(dstreg),
		   IARG_UINT32, REG_Size (srcreg),
		   IARG_UINT32, REG_Size (countreg),
		   IARG_REG_CONST_REFERENCE, dstreg, 
		   IARG_REG_CONST_REFERENCE, srcreg, 
		   IARG_REG_CONST_REFERENCE, countreg, 
		   IARG_UINT32, REG_is_Upper8(dstreg),
		   IARG_UINT32, REG_is_Upper8(srcreg),
		   IARG_UINT32, REG_is_Upper8(countreg),
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline void fw_slice_src_regregmem (INS ins, REG reg1, uint32_t reg1_size, REG reg2, uint32_t reg2_size, IARG_TYPE mem_ea, uint32_t memsize, REG base_reg, REG index_reg) 
{
    char* str = get_copy_of_disasm (ins);
    SETUP_BASE_INDEX(base_reg, index_reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_memregreg),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_ADDRINT, translate_reg (reg1), 
		   IARG_UINT32, reg1_size,
		   IARG_REG_CONST_REFERENCE, reg1, 
		   IARG_UINT32, REG_is_Upper8(reg1),
		   IARG_ADDRINT, translate_reg (reg2), 
		   IARG_UINT32, reg2_size,
		   IARG_REG_CONST_REFERENCE, reg2, 
		   IARG_UINT32, REG_is_Upper8(reg2),
		   mem_ea, 
		   IARG_UINT32, memsize,
		   PASS_BASE_INDEX,
		   IARG_END);
    put_copy_of_disasm (str);
}

//only use this for CMOV  with index tool enabled
static inline void fw_slice_src_regmemflag_cmov (INS ins, REG dest_reg, IARG_TYPE mem_ea, uint32_t memsize, uint32_t flag, REG base_reg, REG index_reg) 
{ 
    char* str = get_copy_of_disasm (ins);
    SETUP_BASE_INDEX(base_reg, index_reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_regmemflag_cmov),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_ADDRINT, translate_reg(dest_reg),
		   IARG_UINT32, REG_Size(dest_reg),
		   IARG_REG_REFERENCE, dest_reg,
		   IARG_UINT32, REG_is_Upper8(dest_reg),
		   mem_ea, 
		   IARG_UINT32, memsize,
		   IARG_UINT32, flag,
		   IARG_EXECUTING,
		   PASS_BASE_INDEX,
		   IARG_END);

    put_copy_of_disasm (str);
}

static inline void fw_slice_src_regflag_cmov (INS ins, uint32_t mask, REG dst, REG src, uint32_t size) 
{
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_regregflag_cmov),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_ADDRINT, translate_reg(dst),
		   IARG_UINT32, REG_Size(dst),
		   IARG_REG_CONST_REFERENCE, dst, 
		   IARG_UINT32, REG_is_Upper8(dst),
		   IARG_ADDRINT, translate_reg(src),
		   IARG_REG_CONST_REFERENCE, src, 
		   IARG_UINT32, REG_is_Upper8(src),
		   IARG_UINT32, mask,
		   IARG_EXECUTING,
		   IARG_END);
    put_copy_of_disasm (str);
}

static inline UINT32 get_reg_off (REG reg)
{
    int treg = translate_reg((int)reg);
    UINT32 reg_offset = treg * REG_SIZE;
    if (REG_is_Upper8(reg)) reg_offset += 1;
    return reg_offset;
}

static void instrument_taint_reg2reg (INS ins, REG dstreg, REG srcreg, int extend)
{
    UINT32 dst_regsize = REG_Size(dstreg);
    UINT32 src_regsize = REG_Size(srcreg);

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

static void instrument_taint_fpureg2fpureg (INS ins, REG dstreg, REG srcreg)
{
    assert (REG_is_st (dstreg));
    assert (REG_is_st (srcreg));
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(taint_fpureg2fpureg),
            IARG_FAST_ANALYSIS_CALL,
            IARG_UINT32, dstreg, //no need to translate_reg
            IARG_UINT32, srcreg,
            IARG_UINT32, REG_Size (dstreg),
            IARG_CONST_CONTEXT, 
            IARG_ADDRINT, INS_Opcode(ins),
            IARG_END);
}

static void instrument_taint_reg2mem(INS ins, REG reg, int extend)
{
    UINT32 regsize = REG_Size(reg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

    if (extend && memsize > regsize) {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_reg2mem_ext_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_MEMORYWRITE_EA,
		       IARG_UINT32, memsize,
		       IARG_UINT32, get_reg_off(reg),
		       IARG_UINT32, regsize,
		       IARG_END);
    } else {
	UINT32 size = (regsize < memsize) ? regsize : memsize;
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_reg2mem_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_MEMORYWRITE_EA,
		       IARG_UINT32, get_reg_off(reg),
		       IARG_UINT32, size,
		       IARG_END);
    }
}

static void instrument_taint_mix_fpureg2mem (INS ins, REG reg) 
{
    UINT32 regsize = REG_Size(reg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR (taint_mix_fpureg2mem),
            IARG_FAST_ANALYSIS_CALL,
            IARG_MEMORYWRITE_EA,
            IARG_UINT32, memsize,
            IARG_UINT32, reg,
            IARG_UINT32, regsize,
            IARG_CONST_CONTEXT,
            IARG_END);
}

#define SETUP_BASE_INDEX_TAINT			\
    UINT32 base_reg_off = 0;			\
    UINT32 base_reg_size = 0;                   \
    UINT32 index_reg_off = 0;                   \
    UINT32 index_reg_size = 0;			\
    if (REG_valid(base_reg)) {			\
	base_reg_off = get_reg_off (base_reg);	\
	base_reg_size = REG_Size (base_reg);	\
    }						\
    if (REG_valid(index_reg)) {			\
        index_reg_off = get_reg_off (index_reg);    \
	index_reg_size = REG_Size (index_reg); \
    } 

#define PASS_BASE_INDEX_TAINT       \
        IARG_UINT32, base_reg_off, \
	IARG_UINT32, base_reg_size, \
	IARG_UINT32, index_reg_off, \
	IARG_UINT32, index_reg_size

static void instrument_taint_mem2reg (INS ins, REG dstreg, int extend, REG base_reg = LEVEL_BASE::REG_INVALID(), REG index_reg = LEVEL_BASE::REG_INVALID())
{
    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryReadSize(ins);
    UINT32 size = (regsize < memsize) ? regsize : memsize;

    SETUP_BASE_INDEX_TAINT;

    if (extend && regsize > memsize) {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_mem2reg_ext_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_MEMORYREAD_EA,
		       IARG_UINT32, get_reg_off (dstreg),
		       IARG_UINT32, size,
		       PASS_BASE_INDEX_TAINT,
		       IARG_END);
    } else {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_mem2reg_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_MEMORYREAD_EA,
		       IARG_UINT32, get_reg_off (dstreg),
		       IARG_UINT32, size,
		       PASS_BASE_INDEX_TAINT,
		       IARG_END);
    }
}

static inline void instrument_taint_mem2fpureg (INS ins, REG dstreg, REG base_reg = LEVEL_BASE::REG_INVALID(), REG index_reg = LEVEL_BASE::REG_INVALID())
{
    SETUP_BASE_INDEX_TAINT;
    assert (REG_is_st (dstreg));
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(taint_mem2fpureg_offset),
            IARG_FAST_ANALYSIS_CALL,
            IARG_MEMORYREAD_EA,
            IARG_UINT32, get_reg_off (dstreg),
            IARG_UINT32, INS_MemoryReadSize(ins),
            PASS_BASE_INDEX_TAINT,
            IARG_CONST_CONTEXT, 
            IARG_ADDRINT, INS_Opcode (ins),
            IARG_END);
}

static void instrument_taint_load_mem2fpureg (INS ins, REG dstreg, REG base_reg = LEVEL_BASE::REG_INVALID(), REG index_reg = LEVEL_BASE::REG_INVALID())
{
    SETUP_BASE_INDEX_TAINT;
    assert (REG_is_st (dstreg));
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(taint_load_mem2fpureg_offset),
            IARG_FAST_ANALYSIS_CALL,
            IARG_MEMORYREAD_EA,
            IARG_UINT32, get_reg_off (dstreg),
            IARG_UINT32, INS_MemoryReadSize(ins),
            PASS_BASE_INDEX_TAINT,
            IARG_CONST_CONTEXT, 
            IARG_END);
}

static void instrument_taint_mem2mem (INS ins)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_mem2mem),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_MEMORYREAD_EA,
		   IARG_MEMORYWRITE_EA,
		   IARG_UINT32, INS_MemoryReadSize(ins),
		   IARG_END);
}

// Mix values in register: implies partial taint -> full taint
// Example: shr eax, 5
static inline void instrument_taint_mix_reg (INS ins, REG reg, int set_flags, int clear_flags)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_mix_reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(reg),
		   IARG_UINT32, REG_Size(reg),
		   IARG_UINT32, set_flags, 
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

static inline void instrument_taint_mix_reg2reg (INS ins, REG dstreg, REG srcreg, int set_flags, int clear_flags)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_mix_reg2reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(dstreg),
		   IARG_UINT32, REG_Size(dstreg),
		   IARG_UINT32, get_reg_off(srcreg),
		   IARG_UINT32, REG_Size(srcreg),
		   IARG_UINT32, set_flags, 
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

static inline void instrument_taint_mix_fpureg2fpureg (INS ins, REG dstreg, REG srcreg)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_mix_fpureg2fpureg),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, dstreg, 
		   IARG_UINT32, REG_Size(dstreg),
		   IARG_UINT32, srcreg, 
		   IARG_UINT32, REG_Size(srcreg),
                   IARG_CONST_CONTEXT, 
		   IARG_END);
}


static inline void instrument_taint_mix_regreg2reg (INS ins, REG dstreg, REG srcreg1, REG srcreg2, int set_flags, int clear_flags)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_mix_regreg2reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(dstreg),
		   IARG_UINT32, REG_Size(dstreg),
		   IARG_UINT32, get_reg_off(srcreg1),
		   IARG_UINT32, REG_Size(srcreg1),
		   IARG_UINT32, get_reg_off(srcreg2),
		   IARG_UINT32, REG_Size(srcreg2),
		   IARG_UINT32, set_flags, 
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

static inline void instrument_taint_mix_mem (INS ins, int set_flags, int clear_flags, REG base_reg = LEVEL_BASE::REG_INVALID(), REG index_reg = LEVEL_BASE::REG_INVALID())
{ 
    SETUP_BASE_INDEX_TAINT;
    INS_InsertCall (ins, IPOINT_BEFORE,
		    AFUNPTR (taint_mix_mem),
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_MEMORYWRITE_EA,
		    IARG_UINT32, INS_MemoryWriteSize(ins),
		    IARG_UINT32, set_flags, 
		    IARG_UINT32, clear_flags,
		    PASS_BASE_INDEX_TAINT,
		    IARG_END);
}

static inline void instrument_taint_mix_mem2reg (INS ins, REG dstreg, int set_flags, int clear_flags, REG base_reg, REG index_reg)
{ 
    SETUP_BASE_INDEX_TAINT;
    INS_InsertCall (ins, IPOINT_BEFORE,
		    AFUNPTR (taint_mix_mem2reg),
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_MEMORYREAD_EA,
		    IARG_UINT32, INS_MemoryReadSize(ins),
		    IARG_UINT32, get_reg_off(dstreg),
		    IARG_UINT32, REG_Size(dstreg),
		    IARG_UINT32, set_flags, 
		    IARG_UINT32, clear_flags,
		    PASS_BASE_INDEX_TAINT,
		    IARG_END);
}

static inline void instrument_taint_mix_reg2mem (INS ins, REG reg, int set_flags, int clear_flags) 
{ 
    INS_InsertCall (ins, IPOINT_BEFORE,
		    AFUNPTR (taint_mix_reg2mem_offset),
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_MEMORYWRITE_EA,
		    IARG_UINT32, INS_MemoryWriteSize(ins),
		    IARG_UINT32, get_reg_off(reg),
		    IARG_UINT32, REG_Size(reg),
		    IARG_UINT32, set_flags, 
		    IARG_UINT32, clear_flags,
		    IARG_END);
}

static inline void instrument_taint_mix_fpuregmem2fpureg (INS ins, REG src_reg, REG dst_reg, REG base_reg = LEVEL_BASE::REG_INVALID(), REG index_reg = LEVEL_BASE::REG_INVALID())
{
    SETUP_BASE_INDEX_TAINT;
    INS_InsertCall (ins, IPOINT_BEFORE,
		    AFUNPTR (taint_mix_fpuregmem2fpureg),
		    IARG_FAST_ANALYSIS_CALL,
                    IARG_MEMORYREAD_EA,
		    IARG_UINT32, INS_MemoryReadSize(ins),
                    IARG_UINT32, src_reg,
                    IARG_UINT32, REG_Size (src_reg),
                    IARG_UINT32, dst_reg, 
                    IARG_UINT32, REG_Size (dst_reg),
                    IARG_CONST_CONTEXT, 
                    PASS_BASE_INDEX_TAINT,
                    IARG_END);
}

static inline void instrument_taint_add_reg2reg (INS ins, REG dstreg, REG srcreg, int set_flags, int clear_flags)
{
    UINT32 dst_regsize = REG_Size(dstreg);
    UINT32 src_regsize = REG_Size(srcreg);
    UINT32 size = (dst_regsize < src_regsize) ? dst_regsize : src_regsize;

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_add_reg2reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(dstreg),
		   IARG_UINT32, get_reg_off(srcreg),
		   IARG_UINT32, size,
		   IARG_UINT32, set_flags, 
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

static inline void instrument_taint_add_regflag2reg (INS ins, REG dstreg, REG srcreg, int mask, int set_flags, int clear_flags)
{
    UINT32 dst_regsize = REG_Size(dstreg);
    UINT32 src_regsize = REG_Size(srcreg);
    UINT32 size = (dst_regsize < src_regsize) ? dst_regsize : src_regsize;

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_add_regflag2reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(dstreg),
		   IARG_UINT32, get_reg_off(srcreg),
		   IARG_UINT32, size,
		   IARG_UINT32, mask,
		   IARG_UINT32, set_flags, 
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

static void instrument_taint_add_reg2esp (INS ins, REG srcreg, int set_flags, int clear_flags)
{
    UINT32 src_regsize = REG_Size(srcreg);
    assert (src_regsize <= 4);

    // Verify - so not part of slice
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_add_reg2esp),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_UINT32, srcreg,
		   IARG_UINT32, src_regsize,
		   IARG_REG_VALUE, srcreg, 
		   IARG_UINT32, REG_is_Upper8 (srcreg), 
		   IARG_UINT32, set_flags, 
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

static void instrument_taint_clear_reg (INS ins, REG reg, int set_flags, int clear_flags)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_clear_reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(reg), 
		   IARG_UINT32, REG_Size(reg),
		   IARG_UINT32, set_flags,
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

static void instrument_taint_clear_mem (INS ins)
{
    INS_InsertCall (ins, IPOINT_BEFORE, 
            AFUNPTR (clear_mem_taints),
            IARG_MEMORYWRITE_EA, 
            IARG_UINT32, INS_MemoryWriteSize(ins), 
            IARG_END);
}

static void instrument_taint_clear_fpureg (INS ins, REG reg, int set_flags, int clear_flags, int is_load)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_clear_fpureg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(reg), 
		   IARG_UINT32, REG_Size(reg),
		   IARG_UINT32, set_flags,
		   IARG_UINT32, clear_flags,
                   IARG_CONST_CONTEXT, 
                   IARG_UINT32, is_load,
		   IARG_END);
}

static void instrument_taint_add_reg2mem (INS ins, REG srcreg, int set_flags, int clear_flags)
{
    UINT32 regsize = REG_Size(srcreg);
    UINT32 memsize = INS_MemoryReadSize(ins);
    UINT32 size = (regsize < memsize) ? regsize : memsize;

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_add_reg2mem_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_MEMORYREAD_EA,
		   IARG_UINT32, get_reg_off(srcreg), 
		   IARG_UINT32, size,
		   IARG_UINT32, set_flags,
		   IARG_UINT32, clear_flags,
		   IARG_END);
}

static void instrument_taint_add_mem2reg (INS ins, REG dstreg, int set_flags, int clear_flags, REG base_reg = LEVEL_BASE::REG_INVALID(), REG index_reg = LEVEL_BASE::REG_INVALID())
{
    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryReadSize(ins);
    UINT32 size = (regsize < memsize) ? regsize : memsize;

    SETUP_BASE_INDEX_TAINT;
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_add_mem2reg_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_MEMORYREAD_EA,
		   IARG_UINT32, get_reg_off(dstreg),
		   IARG_UINT32, size,
		   IARG_UINT32, set_flags,
		   IARG_UINT32, clear_flags,
		   PASS_BASE_INDEX_TAINT,
		   IARG_END);
}

static void instrument_taint_immval2mem(INS ins, REG base_reg = LEVEL_BASE::REG_INVALID(), REG index_reg = LEVEL_BASE::REG_INVALID())
{
    SETUP_BASE_INDEX_TAINT;
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_immval2mem),
		   IARG_FAST_ANALYSIS_CALL,
                   IARG_INST_PTR,
		   IARG_MEMORYWRITE_EA, 
		   IARG_UINT32, INS_MemoryWriteSize(ins),
                   PASS_BASE_INDEX_TAINT,
		   IARG_END);
}

static void inline instrument_taint_mem2flag (INS ins, uint32_t set_mask, uint32_t clear_mask, REG base_reg = LEVEL_BASE::REG_INVALID(), REG index_reg = LEVEL_BASE::REG_INVALID())
{
    SETUP_BASE_INDEX_TAINT;

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_mem2flag),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_MEMORYREAD_EA,
		   IARG_UINT32, INS_MemoryReadSize(ins),
		   IARG_UINT32, set_mask, 
		   IARG_UINT32, clear_mask,
		   PASS_BASE_INDEX_TAINT,
		   IARG_END);
}

static void inline instrument_taint_memflag2memflags (INS ins, uint32_t mask, uint32_t set_mask, uint32_t clear_mask, REG base_reg, REG index_reg)
{
    SETUP_BASE_INDEX_TAINT;

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_memflag2memflags),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_MEMORYREAD_EA,
		   IARG_UINT32, INS_MemoryReadSize(ins),
		   IARG_UINT32, mask,
		   IARG_UINT32, set_mask, 
		   IARG_UINT32, clear_mask,
		   PASS_BASE_INDEX_TAINT,
		   IARG_END);
}

static void inline instrument_taint_reg2flag (INS ins, REG reg, uint32_t set_mask, uint32_t clear_mask)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_reg2flag_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(reg), 
		   IARG_UINT32, REG_Size(reg),
		   IARG_UINT32, set_mask, 
		   IARG_UINT32, clear_mask,
		   IARG_END);
}

static void instrument_clear_flag (INS ins, uint32_t mask) 
{ 
    INS_InsertCall (ins, IPOINT_BEFORE,
		    AFUNPTR(clear_flag_taint),
		    IARG_FAST_ANALYSIS_CALL, 
		    IARG_UINT32, mask,
		    IARG_END);
}

static void instrument_move_string(INS ins)
{
    char* str = get_copy_of_disasm (ins); 
    if (INS_HasRealRep(ins)) {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(fw_slice_string_move),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_INST_PTR,
		       IARG_PTR, str,
		       IARG_MEMORYREAD_EA,
		       IARG_MEMORYWRITE_EA,
		       IARG_REG_VALUE, REG_EFLAGS, 
		       IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
		       IARG_REG_VALUE, LEVEL_BASE::REG_EDI,
		       IARG_REG_VALUE, LEVEL_BASE::REG_ESI,
		       IARG_UINT32, INS_MemoryOperandSize (ins,0),
		       IARG_FIRST_REP_ITERATION,
		       IARG_END);
	INS_InsertCall (ins, IPOINT_BEFORE, 
			AFUNPTR(taint_string_move),
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_MEMORYWRITE_EA,
			IARG_UINT32, INS_MemoryOperandSize (ins,0),
			IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
			IARG_FIRST_REP_ITERATION,
			IARG_END);
    } else {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(fw_slice_string_move),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_INST_PTR,
		       IARG_PTR, str,
		       IARG_MEMORYREAD_EA,
		       IARG_MEMORYWRITE_EA,
		       IARG_REG_VALUE, REG_EFLAGS, 
		       IARG_UINT32, 1,
		       IARG_REG_VALUE, LEVEL_BASE::REG_EDI,
		       IARG_REG_VALUE, LEVEL_BASE::REG_ESI,
		       IARG_UINT32, INS_MemoryOperandSize (ins,0),
		       IARG_UINT32, SPECIAL_VAL_NO_REP,
		       IARG_END);
	INS_InsertCall (ins, IPOINT_BEFORE, 
			AFUNPTR(taint_string_move),
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_MEMORYWRITE_EA,
			IARG_UINT32, INS_MemoryOperandSize (ins,0),
			IARG_UINT32, 1,
			IARG_UINT32, SPECIAL_VAL_NO_REP,
			IARG_END);
    }
    put_copy_of_disasm (str);
}

static void instrument_compare_string(INS ins, uint32_t mask)
{
    UINT32 size = INS_OperandWidth(ins, 0) / 8;
    char* str = get_copy_of_disasm (ins); 

    assert (size == 1);
    assert (INS_RepPrefix(ins));

    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_string_compare),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_MEMORYREAD_EA,
		   IARG_MEMORYREAD2_EA,
		   IARG_REG_VALUE, REG_EFLAGS, 
		   IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
		   IARG_REG_VALUE, LEVEL_BASE::REG_EDI,
		   IARG_REG_VALUE, LEVEL_BASE::REG_ESI,
		   IARG_UINT32, INS_MemoryOperandSize (ins,0),
		   IARG_FIRST_REP_ITERATION,
		   IARG_END);
    INS_InsertCall (ins, IPOINT_BEFORE, 
		    AFUNPTR(taint_string_compare),
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_MEMORYREAD_EA,
		    IARG_MEMORYREAD2_EA,
		    IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
		    IARG_FIRST_REP_ITERATION,
		    IARG_END);
}

static void instrument_scan_string(INS ins, uint32_t mask)
{
    UINT32 size = INS_OperandWidth(ins, 0) / 8;
    assert (size == 1);  // Need to handle more general sizes
    assert(size == INS_MemoryOperandSize(ins, 0));

    assert (INS_HasRealRep(ins));
    UINT32 rep_type = REP_TYPE_E;
    if (INS_RepPrefix(ins)) {
	rep_type = REP_TYPE;
    } else if (INS_RepnePrefix(ins)) {
	rep_type = REP_TYPE_NE;
    }

    char* str = get_copy_of_disasm (ins);
    INS_InsertCall (ins, IPOINT_BEFORE, 
		    (AFUNPTR) fw_slice_string_scan,
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_INST_PTR,
		    IARG_PTR, str,
		    IARG_MEMORYREAD_EA,
		    IARG_REG_VALUE, REG_EFLAGS, 
		    IARG_REG_VALUE, LEVEL_BASE::REG_AL,
		    IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
		    IARG_REG_VALUE, LEVEL_BASE::REG_EDI,
		    IARG_FIRST_REP_ITERATION,
		    IARG_UINT32, rep_type,
		    IARG_END);
    INS_InsertCall (ins, IPOINT_BEFORE, 
		    (AFUNPTR) taint_string_scan,
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_MEMORYREAD_EA,
		    IARG_REG_VALUE, LEVEL_BASE::REG_AL,
		    IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
		    IARG_FIRST_REP_ITERATION,
		    IARG_UINT32, rep_type,
		    IARG_END);
    put_copy_of_disasm (str);
}

static void instrument_store_string(INS ins)
{
    UINT32 size = INS_OperandWidth(ins, 0) / 8;
    assert(size == INS_MemoryOperandSize(ins, 0));

    char* str = get_copy_of_disasm (ins);
    if (INS_RepPrefix(ins)) {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(fw_slice_string_store),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_INST_PTR,
		       IARG_PTR, str,
		       IARG_MEMORYWRITE_EA,
		       IARG_REG_VALUE, REG_EFLAGS, 
		       IARG_REG_CONST_REFERENCE, LEVEL_BASE::REG_EAX,
		       IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
		       IARG_REG_VALUE, LEVEL_BASE::REG_EDI,
		       IARG_UINT32, INS_MemoryOperandSize (ins,0),
		       IARG_FIRST_REP_ITERATION,
		       IARG_END);
	INS_InsertCall (ins, IPOINT_BEFORE, 
			AFUNPTR(taint_string_store),
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_UINT32, INS_MemoryOperandSize (ins,0),
			IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
			IARG_FIRST_REP_ITERATION,
			IARG_END);
    } else {
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(fw_slice_string_store),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_INST_PTR,
		       IARG_PTR, str,
		       IARG_MEMORYWRITE_EA,
		       IARG_REG_VALUE, REG_EFLAGS, 
		       IARG_REG_CONST_REFERENCE, LEVEL_BASE::REG_EAX,
		       IARG_UINT32, 1,
		       IARG_REG_VALUE, LEVEL_BASE::REG_EDI,
		       IARG_UINT32, INS_MemoryOperandSize (ins,0),
		       IARG_UINT32, SPECIAL_VAL_NO_REP,
		       IARG_END);
	INS_InsertCall (ins, IPOINT_BEFORE, 
			AFUNPTR(taint_string_store),
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_UINT32, INS_MemoryOperandSize (ins,0),
			IARG_UINT32, 1,
			IARG_UINT32, SPECIAL_VAL_NO_REP,
			IARG_END);
    } 
}

//TODO: for repz, we probably need the exact number of iterations, which is supported with scan_string
static void instrument_load_string(INS ins)
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
	instrument_taint_mem2reg (ins, LEVEL_BASE::REG_EAX, 0);
    } else {
        /* Ugh we don't know the address until runtime, so this is the
         * best we can do at instrumentation time. */
	instrument_taint_mem2reg (ins, LEVEL_BASE::REG_EAX, 0);
    }
}

TAINTSIGN pcmpestri_reg_mem (ADDRINT ip, char* ins_str, uint32_t reg1, PIN_REGISTER* reg1content, u_long mem_loc2, uint32_t size1, uint32_t size2) { 
	char str1[17] = {0};
	char str2[17] = {0};
	if (reg1content) strncpy (str1, (char*) reg1content, 16);
	if (mem_loc2) strncpy (str2, (char*) mem_loc2, 16);

        fw_slice_pcmpistri_reg_mem (ip, ins_str, reg1, mem_loc2, size1, size2, (char*)reg1content);
	taint_regmem2flag_pcmpxstri (reg1, mem_loc2, 0, size1, size2, 0);
}
TAINTSIGN pcmpestri_reg_reg (ADDRINT ip, char* ins_str, uint32_t reg1, PIN_REGISTER* reg1content, uint32_t reg2, PIN_REGISTER* reg2content, uint32_t size1, uint32_t size2) {
	char str1[17] = {0};
	char str2[17] = {0};
	if (reg1content) strncpy (str1, (char*) reg1content, 16);
	if (reg2content) strncpy (str2, (char*) reg2content, 16);
        fw_slice_pcmpistri_reg_reg (ip, ins_str, reg1, reg2, size1, size2, (char*)reg1content, (char*)reg2content);
	taint_regmem2flag_pcmpxstri (reg1, 0, reg2, size1, size2, 0);
}

//INPUT: EAX, EDX, two operands
//OUTPUT: ECX, FLAGS
static void instrument_pcmpestri (INS ins) { 
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

        fw_slice_pcmpistri_reg_mem (ip, ins_str, reg1, mem_loc2, size1, size2, (char*) reg1content);
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
	fw_slice_pcmpistri_reg_reg (ip, ins_str, reg1, reg2, size1, size2, (char *) reg1content, (char *) reg2content);
	taint_regmem2flag_pcmpxstri (reg1, 0, reg2, size1, size2, 1);
}

//INPUT: EAX, EDX, two operands
//OUTPUT: ECX, FLAGS
static void instrument_pcmpistri (INS ins) 
{ 
    int reg1;
    int reg2;

    if (INS_OperandIsMemory(ins, 1)) { 
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
    } else { 
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
    }
}

static void instrument_xchg (INS ins)
{
    int op1reg = INS_OperandIsReg(ins, 0);
    int op2reg = INS_OperandIsReg(ins, 1);
    if (op1reg && op2reg) {
        REG reg1 = INS_OperandReg(ins, 0);
        REG reg2 = INS_OperandReg(ins, 1);
	fw_slice_src_regreg (ins, reg1, reg2);
        INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_xchg_reg2reg_offset),
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, get_reg_off(reg1),
			IARG_UINT32, get_reg_off(reg2),
			IARG_UINT32, REG_Size(reg1),
			IARG_END);
    } else {
	REG reg = op1reg ? INS_OperandReg(ins, 0) : INS_OperandReg(ins, 1);
        REG base_reg = op1reg ? INS_OperandMemoryBaseReg(ins, 1) : INS_OperandMemoryBaseReg(ins, 0);
        REG index_reg = op1reg ? INS_OperandMemoryIndexReg(ins, 1) : INS_OperandMemoryIndexReg(ins, 0);
        UINT32 addrsize = INS_MemoryReadSize(ins);
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYWRITE_EA, addrsize, base_reg, index_reg);
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_xchg_memreg),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_MEMORYREAD_EA,
		       IARG_UINT32, get_reg_off(reg),
		       IARG_UINT32, addrsize,
		       IARG_END);
    }
}

static void instrument_cmpxchg (INS ins)
{
    int op1reg = INS_OperandIsReg(ins, 0);
    REG srcreg = INS_OperandReg (ins, 1);
    REG cmpreg = INS_OperandReg (ins, 2);
    uint32_t size = REG_Size (srcreg);

    if (op1reg) {
	REG dstreg = INS_OperandReg (ins, 0);
	fw_slice_src_regregreg (ins, dstreg, srcreg, cmpreg);
	INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_cmpxchg_reg),
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, cmpreg,
			IARG_REG_VALUE, dstreg,
			IARG_UINT32, translate_reg(dstreg),
			IARG_UINT32, translate_reg(srcreg),
			IARG_UINT32, size,
			IARG_END);
    } else {
        REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_regregmem (ins, cmpreg, size, srcreg, size, IARG_MEMORYREAD_EA, size, base_reg, index_reg);
	INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_cmpxchg_mem),
			IARG_FAST_ANALYSIS_CALL,
			IARG_REG_VALUE, cmpreg,
			IARG_MEMORYREAD_EA,
			IARG_UINT32, translate_reg(srcreg),
			IARG_UINT32, size,
			IARG_END);
    }
}

static void instrument_mov (INS ins) 
{
    if (INS_IsMemoryRead(ins)) {
	// (src) operand is memory...destination must be a register
        REG dst_reg = INS_OperandReg(ins, 0);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
	fw_slice_src_mem (ins, base_reg, index_reg);
	instrument_taint_mem2reg (ins, dst_reg, 0, base_reg, index_reg);
    } else if(INS_IsMemoryWrite(ins)) {
        if(INS_OperandIsReg(ins, 1)) {
            //mov register to memory location
	    REG reg = INS_OperandReg(ins, 1);
            REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
            REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	    fw_slice_src_reg2mem (ins, reg, REG_Size(reg), base_reg, index_reg);
	    instrument_taint_reg2mem (ins, reg, 0);
        } else {
            //move immediate to memory location
            REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
            REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
            //verification for base&index
            fw_slice_src_dst_mem (ins, base_reg, index_reg);
            instrument_taint_immval2mem(ins, base_reg, index_reg);
        }
    } else {
	REG dstreg = INS_OperandReg(ins, 0);
        if(!INS_OperandIsReg(ins, 1)) {
            //mov immediate value into register
	    instrument_taint_clear_reg (ins, dstreg, -1, -1);
        } else {
            //mov one reg val into another
	    REG reg = INS_OperandReg(ins, 1);
            if (REG_is_seg(reg) || REG_is_seg(dstreg)) return; // ignore segment registers for now
	    fw_slice_src_reg (ins, reg);
            instrument_taint_reg2reg(ins, dstreg, reg, 0);
        }
    }
}

static void instrument_pinsrb (INS ins) 
{
    REG dstreg = INS_OperandReg(ins, 0);
    if (INS_OperandIsMemory(ins, 1)) {
	// Move byte from mem to specified byte of the xmm register
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
	SETUP_BASE_INDEX_TAINT;
	fw_slice_src_mem (ins, base_reg, index_reg);
	uint32_t imm = INS_OperandImmediate(ins, 2);
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_mem2reg_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_MEMORYREAD_EA,
		       IARG_UINT32, get_reg_off (dstreg)+imm, 
		       IARG_UINT32, 1,
		       PASS_BASE_INDEX_TAINT,
		       IARG_END);
    } else {
	assert (0);
    }
}

/* 
 * Instrument a move that extends if the dst is smaller than src.
 *
 * Dst: register/memory
 * Src: register/memory
 * */
static void instrument_movx (INS ins)
{
    int op1mem = INS_OperandIsMemory(ins, 0);
    int op2mem = INS_OperandIsMemory(ins, 1);
    int op1reg = INS_OperandIsReg(ins, 0);
    int op2reg = INS_OperandIsReg(ins, 1);

    if (op1reg && op2reg) {
        REG dst_reg = INS_OperandReg(ins, 0);
        REG src_reg = INS_OperandReg(ins, 1);
	fw_slice_src_reg (ins, src_reg);
        instrument_taint_reg2reg(ins, dst_reg, src_reg, 1);
    } else if (op1reg && op2mem) {
        REG dst_reg = INS_OperandReg(ins, 0);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
	fw_slice_src_mem (ins, base_reg, index_reg);
	instrument_taint_mem2reg (ins, dst_reg, 1, base_reg, index_reg);
    } else if (op1mem && op2reg) {
        REG src_reg = INS_OperandReg(ins, 1);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_reg2mem (ins, src_reg, REG_Size(src_reg), base_reg, index_reg);
        instrument_taint_reg2mem (ins, src_reg, 1);
    } else {
	assert (0);
    }
} 

static void instrument_cmov(INS ins, uint32_t mask)
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
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        fw_slice_src_regmemflag_cmov (ins, reg, IARG_MEMORYREAD_EA, addrsize, mask, base_reg, index_reg); 
        INS_InsertCall (ins, IPOINT_BEFORE,
			AFUNPTR(taint_cmov_mem2reg),
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, mask, 
			IARG_UINT32, translate_reg (reg),
			IARG_MEMORYREAD_EA,
			IARG_UINT32, REG_Size(reg),
			IARG_EXECUTING,
			IARG_END);
#ifdef TRACK_READONLY_REGION
        //here I still merge taints of index/base registers in
        //But the assumption here is these two merges only take effect on memory access to read-only regions. For access to non readonly regions, base and index register are untainted during forward slicing as we'll verify them
        if (REG_valid(base_reg)) instrument_taint_add_reg2reg (ins, reg, base_reg, -1, -1);
        if (REG_valid(index_reg)) instrument_taint_add_reg2reg (ins, reg, index_reg, -1, -1);
#endif
    } else if(ismemwrite) {
	assert (0);//shouldn't happen for cmov
    } else {
        if(immval) {
	    assert (0);// shouldn't happen
        } else {
            //reg to reg
            assert(REG_Size(reg) == REG_Size(dstreg));
            assert (!REG_is_Upper8(reg));
            assert (!REG_is_Upper8(dstreg));
	    
            INSTRUMENT_PRINT(log_f, "instrument cmov is src reg: %d into dst reg: %d\n", reg, dstreg); 
	    fw_slice_src_regflag_cmov (ins, mask, dstreg, reg, REG_Size(reg));
            INS_InsertCall (ins, IPOINT_BEFORE,
			    AFUNPTR(taint_cmov_reg2reg),
			    IARG_FAST_ANALYSIS_CALL,
			    IARG_UINT32, mask, 
			    IARG_UINT32, translate_reg(dstreg),
			    IARG_UINT32, translate_reg(reg), 
			    IARG_UINT32, REG_Size(dstreg),
			    IARG_EXECUTING,
			    IARG_END);
        }
    }
}

//This function doesn't handle RCR and RCL
static void instrument_rotate(INS ins)
{
    int op2imm = INS_OperandIsImmediate (ins, 1);
    int set_flags = 0;
    int clear_flags = 0;
    
    if (op2imm && (INS_OperandImmediate (ins, 1)) == 1) {
	set_flags |= OF_FLAG;
    } else {
	clear_flags |= OF_FLAG;
    }
    if (INS_OperandIsReg (ins, 0)) { 
	REG reg = INS_OperandReg (ins, 0);
	if (op2imm) {
	    fw_slice_src_reg (ins, reg);
	    instrument_taint_mix_reg (ins, reg, set_flags, clear_flags);
	} else {
	    REG reg2 = INS_OperandReg (ins, 1);
	    fw_slice_src_regreg (ins, reg, reg2);
	    instrument_taint_mix_reg2reg (ins, reg, reg2, set_flags, clear_flags);
	}
    } else { 
	uint32_t size = INS_MemoryWriteSize (ins);
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	if (op2imm) {
	    fw_slice_src_mem (ins, base_reg, index_reg);
	    instrument_taint_mix_mem (ins, set_flags, clear_flags, base_reg, index_reg);
	} else {
	    REG reg = INS_OperandReg (ins, 1);
	    fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYWRITE_EA, size, base_reg, index_reg);
	    instrument_taint_mix_reg2mem (ins, reg, set_flags, clear_flags); 
	}
    }
}

static void instrument_shift(INS ins)
{
    int count = INS_OperandCount(ins);
    
    // Note: last operand is EFLAGS register
    if(count == 2) {
        assert (0);
    } else if (count == 3) {
	if (INS_OperandIsReg(ins, 0)) {
	    REG reg = INS_OperandReg(ins, 0);
	    if (INS_OperandIsReg(ins, 1)) {
		REG reg2 = INS_OperandReg(ins, 1);
		fw_slice_src_regreg (ins, reg, reg2);
		instrument_taint_mix_reg2reg(ins, reg, reg2, CF_FLAG|ZF_FLAG|SF_FLAG|PF_FLAG, AF_FLAG);
	    } else {
		fw_slice_src_reg (ins, reg);
		instrument_taint_mix_reg (ins, reg, CF_FLAG|ZF_FLAG|SF_FLAG|PF_FLAG, AF_FLAG);
	    }
	} else {
	    REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	    REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	    if (INS_OperandIsReg(ins, 1)) {
		REG reg = INS_OperandReg(ins, 1);
		fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYWRITE_EA, INS_MemoryWriteSize(ins), base_reg, index_reg);
		instrument_taint_mix_reg2mem (ins, reg, CF_FLAG|ZF_FLAG|SF_FLAG|PF_FLAG, AF_FLAG);
	    } else {
		fw_slice_src_mem (ins, base_reg, index_reg);
                instrument_taint_mix_mem (ins, CF_FLAG|ZF_FLAG|SF_FLAG|PF_FLAG, AF_FLAG);
	    }
	}
    } else if (count == 4) {
        if (INS_OperandIsReg(ins, 2)) {
            if (INS_OperandIsReg(ins, 0)) {
		REG dstreg = INS_OperandReg(ins, 0);
		REG reg2 = INS_OperandReg(ins, 1);
		REG reg3 = INS_OperandReg(ins, 2);
		fw_slice_src_regregreg (ins, dstreg, reg2, reg3);
                instrument_taint_mix_regreg2reg(ins, dstreg, reg2, reg3, CF_FLAG|ZF_FLAG|SF_FLAG|PF_FLAG, AF_FLAG);
	    } else {
		printf ("Unhanded shift: %s\n", INS_Disassemble(ins).c_str()); // Legit to shift memory address 
		assert (0);
	    }
        } else {
            if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
		REG dstreg = INS_OperandReg(ins, 0);
		REG reg2 = INS_OperandReg(ins, 1);
		fw_slice_src_regreg (ins, dstreg, reg2);
		instrument_taint_mix_reg2reg (ins, dstreg, reg2, CF_FLAG|ZF_FLAG|SF_FLAG|PF_FLAG, AF_FLAG);
	    } else {
		printf ("Unhanded shift: %s\n", INS_Disassemble(ins).c_str()); // Legit to shift memory address 
		assert (0);
	    }
	}
    }
}

static void instrument_lea(INS ins)
{
    REG dstreg = INS_OperandReg(ins, 0);
    REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
    REG index_reg = INS_OperandMemoryIndexReg(ins, 1);

    if (REG_valid (index_reg) && !REG_valid(base_reg)) {
        // This is a nummeric calculation in disguise
	fw_slice_src_reg (ins, index_reg);
        INSTRUMENT_PRINT (log_f, "LEA: index reg is %d(%s) base reg invalid, dst %d(%s)\n",
                index_reg, REG_StringShort(index_reg).c_str(),
                dstreg, REG_StringShort(dstreg).c_str());
        assert(REG_Size(index_reg) == REG_Size(dstreg));
	instrument_taint_reg2reg (ins, dstreg, index_reg, 0);
    } else if(REG_valid(base_reg) && REG_valid (index_reg)) {
	fw_slice_src_regreg (ins, base_reg, index_reg);
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
	fw_slice_src_reg (ins, base_reg);
        INSTRUMENT_PRINT (log_f, "LEA: base reg is %d(%s) index reg invalid, dst %d(%s)\n",
                base_reg, REG_StringShort(base_reg).c_str(),
                dstreg, REG_StringShort(dstreg).c_str());
        assert(REG_Size(base_reg) == REG_Size(dstreg));
	instrument_taint_reg2reg (ins, dstreg, base_reg, 0);
    } else { 
	instrument_taint_clear_reg (ins, dstreg, -1, -1);
    }
}

static void instrument_push(INS ins)
{
    if (INS_OperandIsImmediate(ins, 0)) {
	instrument_taint_immval2mem (ins);
    } else if (INS_OperandIsReg(ins, 0)) {
        REG reg = INS_OperandReg(ins, 0);
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(fw_slice_push_reg),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_INST_PTR,
		       IARG_UINT32, translate_reg(reg), 
		       IARG_REG_CONST_REFERENCE, reg, 
		       IARG_UINT32, REG_is_Upper8(reg),
		       IARG_MEMORYWRITE_EA,
		       IARG_UINT32, INS_MemoryWriteSize(ins),
		       IARG_END);
	instrument_taint_reg2mem (ins, reg, 0);
    } else {
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	SETUP_BASE_INDEX(base_reg, index_reg);
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(fw_slice_push_mem),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_INST_PTR,
		       IARG_MEMORYREAD_EA,
		       IARG_MEMORYWRITE_EA,
		       IARG_UINT32, INS_MemoryWriteSize(ins),
		       PASS_BASE_INDEX,
		       IARG_END);
	instrument_taint_mem2mem (ins);
    }
}

static void instrument_pop(INS ins)
{
    if (INS_OperandIsMemory(ins, 0)) {
        REG base_reg = INS_OperandMemoryBaseReg (ins, 0);
        REG index_reg = INS_OperandMemoryIndexReg (ins, 0);
        SETUP_BASE_INDEX (base_reg, index_reg);
        char* ins_str = get_copy_of_disasm (ins);
        INS_InsertCall (ins, IPOINT_BEFORE, 
                AFUNPTR (fw_slice_pop_mem), 
                IARG_FAST_ANALYSIS_CALL, 
                IARG_INST_PTR, 
                IARG_PTR, ins_str, 
                IARG_MEMORYREAD_EA, 
                IARG_MEMORYWRITE_EA, 
                IARG_UINT32, INS_MemoryReadSize(ins), 
                PASS_BASE_INDEX, 
                IARG_END);
        instrument_taint_mem2mem (ins);
        put_copy_of_disasm (ins_str);
    } else if (INS_OperandIsReg(ins, 0)) {
	REG reg = INS_OperandReg(ins, 0);
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(fw_slice_pop_reg),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_INST_PTR,
		       IARG_UINT32, translate_reg(reg),
		       IARG_MEMORYREAD_EA,
		       IARG_UINT32, INS_MemoryReadSize(ins),
		       IARG_END);
	instrument_taint_mem2reg (ins, reg, 0, LEVEL_BASE::REG_INVALID(), LEVEL_BASE::REG_INVALID());
    }
}

static void instrument_leave (INS ins) { 
    USIZE addrsize = INS_MemoryReadSize (ins);
    assert (addrsize == 4); //only care about 32bit for now
    fw_slice_src_regmem (ins, LEVEL_BASE::REG_EBP, 4, IARG_MEMORYREAD_EA, 4, LEVEL_BASE::REG_INVALID(), LEVEL_BASE::REG_INVALID());
    instrument_taint_reg2reg (ins, LEVEL_BASE::REG_ESP, LEVEL_BASE::REG_EBP, 0);
    instrument_taint_mem2reg (ins, LEVEL_BASE::REG_EBP, 0);
}

static void instrument_sahf (INS ins) {
    fw_slice_src_reg (ins, LEVEL_BASE::REG_AH);
    instrument_taint_reg2flag (ins, LEVEL_BASE::REG_AH, 0, 0);
}

static void instrument_addorsub(INS ins, int set_flags, int clear_flags)
{
    OPCODE opcode = INS_Opcode(ins);
    int op1mem = INS_OperandIsMemory(ins, 0);
    int op2mem = INS_OperandIsMemory(ins, 1);
    int op1reg = INS_OperandIsReg(ins, 0);
    int op2reg = INS_OperandIsReg(ins, 1);
    int op2imm = INS_OperandIsImmediate(ins, 1);

    if((op1mem && op2reg)) {
        REG reg = INS_OperandReg(ins, 1);
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins), base_reg, index_reg);
        instrument_taint_add_reg2mem(ins, reg, set_flags, clear_flags);
    } else if(op1reg && op2mem) {
        REG reg = INS_OperandReg(ins, 0);
	REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins), base_reg, index_reg);
        instrument_taint_add_mem2reg(ins, reg, set_flags, clear_flags, base_reg, index_reg);
    } else if(op1reg && op2reg) {
        REG dstreg = INS_OperandReg(ins, 0);
        REG reg = INS_OperandReg(ins, 1);

        if((opcode == XED_ICLASS_SUB || opcode == XED_ICLASS_XOR || opcode == XED_ICLASS_PXOR || opcode == XED_ICLASS_XORPS) && (dstreg == reg)) {
	    fw_slice_src_regreg (ins, dstreg, reg);
	    instrument_taint_clear_reg (ins, dstreg, set_flags, clear_flags);
        } else {
	    if (dstreg == LEVEL_BASE::REG_ESP) {
		// Special case: don't taint esp - instead verify other register is the same
		instrument_taint_add_reg2esp(ins, reg, set_flags, clear_flags);
	    } else {
		fw_slice_src_regreg (ins, dstreg, reg);
		instrument_taint_add_reg2reg(ins, dstreg, reg, set_flags, clear_flags);
	    }
        }
    } else if(op1mem && op2imm) {
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_mem (ins, base_reg, index_reg);
	instrument_taint_mem2flag (ins, set_flags, clear_flags, base_reg, index_reg);
    } else if(op1reg && op2imm){
        REG reg = INS_OperandReg(ins, 0);
	fw_slice_src_reg (ins, reg);
	instrument_taint_reg2flag (ins, reg, set_flags, clear_flags);
    } else {
	assert (0);
    }
}

/* static */
void instrument_sbb (INS ins)
{
    int op1mem = INS_OperandIsMemory(ins, 0);
    int op2mem = INS_OperandIsMemory(ins, 1);
    int op1reg = INS_OperandIsReg(ins, 0);
    int op2reg = INS_OperandIsReg(ins, 1);
    int op2imm = INS_OperandIsImmediate(ins, 1);

    if((op1mem && op2reg)) {
        REG reg = INS_OperandReg(ins, 1);
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins), base_reg, index_reg);
        instrument_taint_add_reg2mem(ins, reg, OF_FLAG|SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG|CF_FLAG, 0);
    } else if(op1reg && op2mem) {
        REG reg = INS_OperandReg(ins, 0);
	REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins), base_reg, index_reg);
        instrument_taint_add_mem2reg(ins, reg, OF_FLAG|SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG|CF_FLAG, 0, base_reg, index_reg);
    } else if(op1reg && op2reg) {
        REG dstreg = INS_OperandReg(ins, 0);
        REG reg = INS_OperandReg(ins, 1);
	if (dstreg == reg) {
	    fw_slice_src_flag (ins, CF_FLAG); 
	    INS_InsertCall(ins, IPOINT_BEFORE,
			   AFUNPTR(taint_flag2regflags),
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_UINT32, translate_reg(dstreg),
			   IARG_UINT32, CF_FLAG, 
			   IARG_UINT32, REG_Size(reg),
			   IARG_UINT32, OF_FLAG|SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG|CF_FLAG,
			   IARG_END);
        } else {
	    fw_slice_src_regregflag (ins, dstreg, reg, CF_FLAG);
	    instrument_taint_add_regflag2reg(ins, dstreg, reg, CF_FLAG, OF_FLAG|SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG|CF_FLAG, 0);
        }
    } else if(op1mem && op2imm) {
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_memflag (ins, base_reg, index_reg, CF_FLAG);
	instrument_taint_memflag2memflags (ins, CF_FLAG, OF_FLAG|SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG|CF_FLAG, 0, base_reg, index_reg);
    } else if(op1reg && op2imm){
        REG reg = INS_OperandReg(ins, 0);
	fw_slice_src_regflag (ins, reg, CF_FLAG); 
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_regflag2regflags),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_UINT32, translate_reg(reg),
		       IARG_UINT32, CF_FLAG, 
		       IARG_UINT32, REG_Size(reg),
		       IARG_UINT32, OF_FLAG|SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG|CF_FLAG,
		       IARG_END);
    } else {
	assert (0);
    }
}

/* Divide has 3 operands.
 *
 *  r/m, AX, AL/H/X <- quotient, AH <- remainder
 * */
static void instrument_div(INS ins)
{
    if (INS_IsMemoryRead(ins)) {
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
        // Register translations
        int msb_treg, lsb_treg, dst1_treg, dst2_treg;
        UINT32 addrsize = INS_MemoryReadSize(ins);
        switch (addrsize) {
            case 1:
                // mem_loc is Divisor
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX); // Dividend
                dst1_treg = translate_reg(LEVEL_BASE::REG_AL); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_AH); // Remainder
		fw_slice_src_regmem (ins, LEVEL_BASE::REG_AX, 2, IARG_MEMORYREAD_EA, 1, base_reg, index_reg);
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

		fw_slice_src_regregmem (ins, LEVEL_BASE::REG_DX, 2, LEVEL_BASE::REG_AX, 2, IARG_MEMORYREAD_EA, 2, base_reg, index_reg);
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
		fw_slice_src_regregmem (ins, LEVEL_BASE::REG_EDX, 4, LEVEL_BASE::REG_EAX, 4, IARG_MEMORYREAD_EA, 4, base_reg, index_reg);
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
		fw_slice_src_regreg (ins, LEVEL_BASE::REG_AX, src_reg);
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
		fw_slice_src_regregreg (ins, src_reg, LEVEL_BASE::REG_DX, LEVEL_BASE::REG_AX);
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
		fw_slice_src_regregreg (ins, src_reg, LEVEL_BASE::REG_EDX, LEVEL_BASE::REG_EAX);
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

static void instrument_mul(INS ins)
{
    INSTRUMENT_PRINT (log_f, "mul instruction: %s\n", INS_Disassemble(ins).c_str());
    if (INS_IsMemoryRead(ins)) {
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
        int lsb_dst_treg, msb_dst_treg;
        int src_treg;
        UINT32 addrsize;

        addrsize = INS_MemoryReadSize(ins);
        switch (addrsize) {
            case 1:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_AX);
                src_treg = translate_reg(LEVEL_BASE::REG_AL);
		fw_slice_src_regmem (ins, LEVEL_BASE::REG_AL, 1, IARG_MEMORYREAD_EA, addrsize, base_reg, index_reg);
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
		fw_slice_src_regmem (ins, LEVEL_BASE::REG_AX, 2, IARG_MEMORYREAD_EA, addrsize, base_reg, index_reg);
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
		fw_slice_src_regmem (ins, LEVEL_BASE::REG_EAX, 4, IARG_MEMORYREAD_EA, addrsize, base_reg, index_reg);
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
		fw_slice_src_regreg (ins, LEVEL_BASE::REG_AL, src2_reg), 
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
		fw_slice_src_regreg (ins, LEVEL_BASE::REG_AX, src2_reg);
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
		fw_slice_src_regreg(ins, LEVEL_BASE::REG_EAX, src2_reg);
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
static void instrument_imul(INS ins)
{
    int count = INS_OperandCount(ins);
    if (count == 3) {
        //format: imul r32, r/m32  (r32 = r32*r/m32)
        REG dst_reg = INS_OperandReg(ins, 0);
        if (INS_IsMemoryRead(ins)) {
	    REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
	    REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
	    fw_slice_src_regmem (ins, dst_reg, REG_Size(dst_reg), IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins), base_reg, index_reg);
	    instrument_taint_add_mem2reg (ins, dst_reg, CF_FLAG|OF_FLAG, SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG);
        } else {
            REG src_reg = INS_OperandReg(ins, 1);
	    fw_slice_src_regreg (ins, dst_reg, src_reg);
	    instrument_taint_add_reg2reg (ins, dst_reg, src_reg, CF_FLAG|OF_FLAG, SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG);
        }
    } else if (count == 4) {
        if (INS_OperandIsImmediate (ins, 2)) {
            REG dst_reg = INS_OperandReg(ins, 0);
            if (INS_IsMemoryRead(ins)) {	
		//format: imul r32, m32, imm32 (r32=m32*imm32)
		REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
		REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
		fw_slice_src_mem (ins, base_reg, index_reg);
		instrument_taint_mem2reg (ins, dst_reg, 0, base_reg, index_reg);
            } else {
		//format: imul r32, r32, imm32 (dstreg=srcreg*imm32)
                REG src_reg = INS_OperandReg(ins, 1);
		fw_slice_src_reg (ins, src_reg);
		instrument_taint_reg2reg (ins, dst_reg, src_reg, 0);
            }
        } else { 
	    //format: imul r/m32 (EDX:EAX = EAX*r/m32), same as mul
            instrument_mul (ins);
        }
    } else {
	assert (0);
    }
}

static void instrument_call_near (INS ins)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_call_near),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_REG_VALUE, LEVEL_BASE::REG_ESP, 
		   IARG_END);
}

static void instrument_call_far (INS ins)
{
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_call_far),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_REG_VALUE, LEVEL_BASE::REG_ESP, 
		   IARG_END);
}

static void instrument_palignr(INS ins)
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
	REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYREAD_EA, addrsize, base_reg, index_reg);

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

	fw_slice_src_regreg (ins, reg, reg2);
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

static void instrument_psrldq(INS ins)
{
    assert(INS_OperandIsReg(ins, 0));
    assert(INS_OperandIsImmediate(ins, 1));
    int treg = translate_reg(INS_OperandReg(ins, 0));
    int shift = INS_OperandImmediate(ins, 1);
    fw_slice_src_reg (ins, INS_OperandReg(ins, 0));

    INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(shift_reg_taint_right),
                    IARG_UINT32, treg,
                    IARG_UINT32, shift,
                    IARG_END);
}

static void instrument_pmovmskb(INS ins)
{
    int src_treg;
    int dst_treg;

    assert(INS_OperandIsReg(ins, 0));
    assert(INS_OperandIsReg(ins, 1));
    assert(REG_Size(INS_OperandReg(ins, 0)) == 4);
    assert(REG_Size(INS_OperandReg(ins, 1)) == 16);

    dst_treg = translate_reg(INS_OperandReg(ins, 0));
    src_treg = translate_reg(INS_OperandReg(ins, 1));
    fw_slice_src_reg (ins, INS_OperandReg(ins, 1));

    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(taint_mask_reg2reg),
            IARG_FAST_ANALYSIS_CALL,
            IARG_UINT32, dst_treg,
            IARG_UINT32, src_treg,
            IARG_END);
}

inline static void instrument_taint_regmem2flag (INS ins, REG reg, uint32_t set_flags, uint32_t clear_flags) 
{
    INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_regmem2flag),
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_MEMORYREAD_EA,
		    IARG_UINT32, INS_MemoryReadSize(ins),
		    IARG_UINT32, get_reg_off(reg),
		    IARG_UINT32, REG_Size(reg),
		    IARG_UINT32, set_flags, 
		    IARG_UINT32, clear_flags,
		    IARG_END);
}

inline static void instrument_taint_regreg2flag (INS ins, REG dst_reg, REG src_reg, uint32_t set_flags, uint32_t clear_flags) 
{
    INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_regreg2flag_offset),
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_UINT32, get_reg_off(dst_reg),
		    IARG_UINT32, REG_Size(dst_reg),	
		    IARG_UINT32, get_reg_off(src_reg),
		    IARG_UINT32, REG_Size(src_reg),	
		    IARG_UINT32, set_flags, 
		    IARG_UINT32, clear_flags,
		    IARG_END);
}

static void instrument_test_or_cmp (INS ins, uint32_t set_mask, uint32_t clear_mask)
{
    bool op1mem = INS_OperandIsMemory(ins, 0);
    bool op1reg = INS_OperandIsReg(ins, 0);
    bool op2reg = INS_OperandIsReg(ins, 1);
    bool op2imm = INS_OperandIsImmediate(ins, 1);
    bool op2mem = INS_OperandIsMemory(ins, 1);
    if((op1mem && op2reg) || (op1reg && op2mem)) { //ordering doesn't matter
	REG reg = op1reg ? INS_OperandReg(ins, 0) : INS_OperandReg(ins, 1);
	REG basereg = op1reg ? INS_OperandMemoryBaseReg(ins, 1) : INS_OperandMemoryBaseReg(ins, 0);
	REG indexreg = op1reg ? INS_OperandMemoryIndexReg(ins, 1) : INS_OperandMemoryIndexReg(ins, 0);
	UINT32 memsize = INS_MemoryReadSize(ins);
	UINT32 regsize = REG_Size(reg);
	fw_slice_src_regmem (ins, reg, regsize, IARG_MEMORYREAD_EA, memsize, basereg, indexreg);
	instrument_taint_regmem2flag (ins, reg, set_mask, clear_mask);
    } else if (op1reg && op2reg) {
        REG dstreg = INS_OperandReg(ins, 0);
        REG srcreg = INS_OperandReg(ins, 1);
	fw_slice_src_regreg (ins, dstreg, srcreg);
	instrument_taint_regreg2flag (ins, dstreg, srcreg, set_mask, clear_mask);
   } else if (op1mem && op2imm) {
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_mem (ins, base_reg, index_reg);
	instrument_taint_mem2flag (ins, set_mask, clear_mask, base_reg, index_reg);
    } else if (op1reg && op2imm) {
	REG reg = INS_OperandReg (ins, 0);
	fw_slice_src_reg(ins, reg);
	instrument_taint_reg2flag (ins, reg, set_mask, clear_mask);
    } else {
        fprintf(stderr, "unknown combination of CMP ins: %s\n", INS_Disassemble(ins).c_str());
	assert (0);
    }
}

static void instrument_jump (INS ins, uint32_t flags) 
{
    fw_slice_src_flag (ins, flags);
    INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_jump),
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_REG_VALUE, REG_EFLAGS,
		    IARG_UINT32, flags, 
		    IARG_ADDRINT, INS_Address(ins),
		    IARG_BRANCH_TAKEN,
		    IARG_END);
}

static void instrument_jump_ecx (INS ins) 
{
    REG reg = INS_OperandReg (ins, 1);
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(fw_slice_condregjump),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(reg), 
		   IARG_UINT32, REG_Size(reg),
		   IARG_BRANCH_TAKEN,
		   IARG_BRANCH_TARGET_ADDR,
		   IARG_CONST_CONTEXT, 
		   IARG_END);
    INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_jump_ecx),
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
		    IARG_UINT32, REG_Size(reg),
		    IARG_INST_PTR,
		    IARG_BRANCH_TAKEN,
		    IARG_END);
    put_copy_of_disasm (str);
}

static void instrument_not (INS ins) 
{ 
    if (INS_OperandIsReg (ins, 0)) { 
	REG reg = INS_OperandReg(ins, 0);
	fw_slice_src_reg (ins, reg);
    } else { 
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_mem (ins, base_reg, index_reg);
	// Don't handle range verifications for writes yet */
    } 
}

static void instrument_incdec_neg (INS ins, int set_flags, int clear_flags) 
{
    if (INS_OperandIsMemory (ins, 0)) { 
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_mem (ins, base_reg, index_reg);
	instrument_taint_mix_mem (ins, set_flags, clear_flags, base_reg, index_reg);
    } else {
	REG reg = INS_OperandReg(ins, 0);
	fw_slice_src_reg (ins, reg);
	instrument_taint_mix_reg (ins, reg, set_flags, clear_flags);
    } 
}

static void instrument_set (INS ins, uint32_t mask) 
{ 
    if (INS_IsMemoryWrite(ins)) {
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_flag2mem (ins, mask, base_reg, index_reg);
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_flag2mem),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_MEMORYWRITE_EA,
		       IARG_UINT32,mask, 
		       IARG_UINT32, 1,
		       IARG_END);
    } else { 
	fw_slice_src_flag (ins, mask);
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_flag2reg),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_UINT32, translate_reg(INS_OperandReg(ins, 0)),
		       IARG_UINT32, mask, 
		       IARG_UINT32, 1,
		       IARG_END);
    }
}

static void instrument_bt (INS ins) 
{ 
    int op1reg = INS_OperandIsReg (ins, 0);
    int op2reg = INS_OperandIsReg (ins, 1);
    int op1mem = INS_OperandIsMemory (ins, 0);
    int op2imm = INS_OperandIsImmediate (ins, 1);
    if (op1reg && op2reg) { 
	REG dst_reg = INS_OperandReg(ins, 0);
	REG src_reg = INS_OperandReg(ins, 1);
	fw_slice_src_regreg (ins, dst_reg, src_reg);
	instrument_taint_regreg2flag (ins, dst_reg, src_reg, CF_FLAG, 0);
    } else if (op1mem && op2reg) { 
	REG reg = INS_OperandReg(ins, 1);
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_regmem (ins, reg, REG_Size(reg), IARG_MEMORYREAD_EA, INS_MemoryReadSize(ins), base_reg, index_reg);
	instrument_taint_regmem2flag (ins, reg, CF_FLAG, 0);
    } else if (op1reg && op2imm) { 
	REG reg = INS_OperandReg (ins, 0);
	fw_slice_src_reg(ins, reg);
	instrument_taint_reg2flag(ins, reg, CF_FLAG, 0);
    } else if (op1mem && op2imm) { 
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
	fw_slice_src_mem (ins, base_reg, index_reg);
	instrument_taint_mem2flag (ins, CF_FLAG, 0, base_reg, index_reg);
    }
}

static void instrument_bit_scan (INS ins) 
{ 
    REG dstreg = INS_OperandReg(ins, 0);
    if (INS_IsMemoryRead(ins)) {
	REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        fw_slice_src_mem (ins, base_reg, index_reg);
	instrument_taint_mix_mem2reg (ins, dstreg, ZF_FLAG, 0, base_reg, index_reg);
    } else {
        REG srcreg = INS_OperandReg (ins, 1);
        fw_slice_src_reg (ins, srcreg);
	INS_InsertCall(ins, IPOINT_BEFORE,
		       AFUNPTR(taint_mixmov_reg2reg_offset),
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_UINT32, get_reg_off(dstreg),
		       IARG_UINT32, REG_Size(dstreg),
		       IARG_UINT32, get_reg_off(srcreg),
		       IARG_UINT32, REG_Size(srcreg),
		       IARG_UINT32, ZF_FLAG,
		       IARG_UINT32, 0,
		       IARG_END);
    }
}

static void instrument_fpu_load (INS ins) 
{
    assert (INS_OperandCount(ins) >= 2);
    REG dst_reg = INS_OperandReg (ins, 0);
    if (INS_OperandIsMemory(ins, 1)) {	
	REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        fw_slice_src_mem2fpureg (ins, base_reg, index_reg, FP_PUSH);
        //these instructions convert interger/float/double/bcd into double extended format here
        instrument_taint_load_mem2fpureg (ins, dst_reg, base_reg, index_reg);
    } else {
        REG src_reg = INS_OperandReg (ins, 1);
        fw_slice_src_fpureg (ins, src_reg, FP_PUSH);
        instrument_taint_fpureg2fpureg (ins, dst_reg, src_reg);
    }
}

static void instrument_fpu_store (INS ins)
{
    assert (INS_OperandCount(ins) >= 2);
    REG src_reg = INS_OperandReg (ins, 1);
    int fp_stack_change = FP_NO_STACK_CHANGE;
    if (INS_Opcode (ins) == XED_ICLASS_FSTP || INS_Opcode (ins) == XED_ICLASS_FBSTP || INS_Opcode (ins) == XED_ICLASS_FISTP || INS_Opcode(ins) == XED_ICLASS_FISTTP)
        fp_stack_change = FP_POP;
    
    if (INS_IsMemoryWrite(ins)) {	
	REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
	REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
        fw_slice_src_fpureg2mem (ins, src_reg, base_reg, index_reg, fp_stack_change);
        instrument_taint_mix_fpureg2mem (ins, src_reg);
        //because of the convertion from double-precision
    } else {
        fw_slice_src_fpureg (ins, src_reg, fp_stack_change);
        REG dst_reg = INS_OperandReg (ins, 0);
        assert (REG_is_st (dst_reg)); //per the intel manual
        instrument_taint_fpureg2fpureg (ins, dst_reg, src_reg);
    }
    if (INS_Opcode(ins) == XED_ICLASS_FSTP || INS_Opcode (ins) == XED_ICLASS_FBSTP || INS_Opcode (ins) == XED_ICLASS_FISTP /*|| INS_Opcode (ins) == XED_ICLASS_FISTTP not sure about this one??*/) {
        //these instructions empty st(0)
        instrument_taint_clear_fpureg (ins, REG_ST0, -1, -1, 0);
    }
}

static void instrument_fpu_cmov (INS ins, int flags) 
{
    REG dstreg = INS_OperandReg (ins, 0);
    REG srcreg = INS_OperandReg (ins, 1);
    char* str = get_copy_of_disasm (ins);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(fw_slice_fpu_cmov),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_INST_PTR,
		   IARG_PTR, str,
		   IARG_UINT32, translate_reg(dstreg),
		   IARG_UINT32, REG_Size(dstreg),
		   IARG_UINT32, translate_reg(srcreg),
		   IARG_UINT32, REG_Size(srcreg),
                   IARG_CONST_CONTEXT,
                   IARG_UINT32, flags,
		   IARG_EXECUTING,
		   IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_fpu_cmov),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, translate_reg(dstreg),
		   IARG_UINT32, translate_reg(srcreg),
		   IARG_UINT32, REG_Size(srcreg),
                   IARG_CONST_CONTEXT,
		   IARG_EXECUTING,
                   IARG_UINT32, flags,
		   IARG_END);
    put_copy_of_disasm (str);
}

static void instrument_fpu_onereg_calc (INS ins)
{
    REG reg = INS_OperandReg (ins, 0);
    fw_slice_src_fpureg (ins, reg, FP_NO_STACK_CHANGE);
    INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_mix_fpureg),
		    IARG_FAST_ANALYSIS_CALL,
		    IARG_UINT32, reg,
		    IARG_UINT32, REG_Size(reg),
		    IARG_CONST_CONTEXT, 
		    IARG_END);
}

static void instrument_fpu_calc (INS ins, int fp_stack_change)
{
    if (INS_IsMemoryRead(ins)) {
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        REG dst_reg = INS_OperandReg (ins, 0);
        fw_slice_src_fpuregmem (ins, dst_reg, REG_Size(dst_reg), IARG_MEMORYREAD_EA, INS_MemoryReadSize (ins), base_reg, index_reg, fp_stack_change);
        instrument_taint_mix_fpuregmem2fpureg (ins, dst_reg, dst_reg, base_reg, index_reg);
    } else if (INS_OperandIsReg (ins, 1)) {
        REG dst_reg = INS_OperandReg (ins, 0);
        REG src_reg = INS_OperandReg (ins, 1);
        fw_slice_src_fpuregfpureg (ins, dst_reg, src_reg, fp_stack_change);
        instrument_taint_mix_fpureg2fpureg (ins, dst_reg, src_reg);
    } else { 
        assert (0);
    }
    if (fp_stack_change == FP_POP) { 
        instrument_taint_clear_fpureg (ins, REG_ST0, -1, -1, 0);
    }
}

static void instrument_fpu_cmp (INS ins, int fp_stack_change) 
{
    if (INS_OperandIsReg (ins, 1)) { 
        REG dst_reg = INS_OperandReg (ins, 0);
        REG src_reg = INS_OperandReg (ins, 1);
        fw_slice_src_fpuregfpureg (ins, dst_reg, src_reg, fp_stack_change);
        INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_fpuregfpureg2flag),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, dst_reg, 
		   IARG_UINT32, src_reg, 
		   IARG_UINT32, REG_Size(dst_reg),
                   IARG_CONST_CONTEXT, 
                   IARG_UINT32, fp_stack_change,
                   IARG_UINT32, ZF_FLAG|PF_FLAG|CF_FLAG, 
                   IARG_UINT32, OF_FLAG|SF_FLAG|AF_FLAG,
		   IARG_END);
    } else {
        assert (0);
    }
    if (fp_stack_change == FP_POP) { 
        instrument_taint_clear_fpureg (ins, REG_ST0, -1, -1, 0);
    }
}

static void instrument_fpu_exchange (INS ins)
{
    int op1reg = INS_OperandIsReg(ins, 0);
    int op2reg = INS_OperandIsReg(ins, 1);
    if (op1reg && op2reg) {
        REG reg1 = INS_OperandReg(ins, 0);
        REG reg2 = INS_OperandReg(ins, 1);
	fw_slice_src_fpuregfpureg (ins, reg1, reg2, FP_NO_STACK_CHANGE);
        INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(taint_xchg_fpureg2fpureg),
			IARG_FAST_ANALYSIS_CALL,
                        IARG_UINT32, reg1, 
                        IARG_UINT32, reg2, 
			IARG_UINT32, REG_Size(reg1),
                        IARG_CONST_CONTEXT,
			IARG_END);
    } else
        assert (0);
}

static void instrument_cwde (INS ins) 
{
    fw_slice_src_reg (ins, LEVEL_BASE::REG_AX);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_mix_cwde),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_END);
}

static void instrument_bswap (INS ins) 
{
    REG reg = INS_OperandReg(ins, 0);    
    fw_slice_src_reg (ins, reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
		   AFUNPTR(taint_bswap_offset),
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_UINT32, get_reg_off(reg),
		   IARG_END);
}

static void instrument_ldmxcsr (INS ins)
{
    //here I assume the mem value to be loaded into mxcsr is not tainted, so ldmxcsr and stmscr don't need to be included in the slice
    INS_InsertCall(ins, IPOINT_BEFORE, 
            AFUNPTR(taint_ldmxcsr_check),
            IARG_FAST_ANALYSIS_CALL, 
            IARG_MEMORYREAD_EA, 
            IARG_END);
}

void PIN_FAST_ANALYSIS_CALL debug_print_inst (ADDRINT ip, char* ins, u_long mem_loc1, u_long mem_loc2, ADDRINT value1, ADDRINT value2, ADDRINT value3, const CONTEXT* ctx)
{
#ifdef EXTRA_DEBUG
    if (*ppthread_log_clock < EXTRA_DEBUG) return;
#endif
#ifdef EXTRA_DEBUG_STOP
    if (*ppthread_log_clock >= EXTRA_DEBUG_STOP) return;
#endif
    //if (current_thread->ctrl_flow_info.index > 20000) return; 
    bool print_me = true;

#if 0
    #define ADDR_TO_CHECK 0x86a4dc1
    static u_char old_val = 0xe3; // random - just to see initial value please
    if (*((u_char *) ADDR_TO_CHECK) != old_val) {
	printf ("New value for 0x%x: 0x%02x old value 0x%02x clock %lu\n", ADDR_TO_CHECK, *((u_char *) ADDR_TO_CHECK), old_val, *ppthread_log_clock);
	old_val = *((u_char *) ADDR_TO_CHECK);
	print_me = true;
    }
    static int old_taint = 0;
    int new_taint = is_mem_arg_tainted(ADDR_TO_CHECK, 1);
    if (new_taint != old_taint) {
	printf ("New taint for %x: %d old taint %d clock %lu\n", ADDR_TO_CHECK, new_taint, old_taint, *ppthread_log_clock);
	old_taint = new_taint;
	print_me = true;
    }
#endif

    if (print_me) {
	printf ("#%x %s, clock %ld, pid %d bb %lld, mem loc %lx %lx\n", ip, ins, *ppthread_log_clock, current_thread->record_pid, current_thread->ctrl_flow_info.index, mem_loc1, mem_loc2);
	PIN_LockClient();
	if (IMG_Valid(IMG_FindByAddress(ip))) {
	    printf ("%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));
	}
	PIN_UnlockClient();
	printf ("eax tainted? %d ebx tainted? %d ecx tainted? %d edx tainted? %d ebp tainted? %d esp tainted? %d\n", 
		is_reg_arg_tainted (LEVEL_BASE::REG_EAX, 4, 0), is_reg_arg_tainted (LEVEL_BASE::REG_EBX, 4, 0), is_reg_arg_tainted (LEVEL_BASE::REG_ECX, 4, 0), 
		is_reg_arg_tainted (LEVEL_BASE::REG_EDX, 4, 0), is_reg_arg_tainted (LEVEL_BASE::REG_EBP, 4, 0), is_reg_arg_tainted (LEVEL_BASE::REG_ESP, 4, 0));
        printf ("ecx value %u edx %u esp %u\n", value1, value2, value3);
        printf ("jump_diverge index %lu\n", jump_count);

	PIN_REGISTER value;
	PIN_GetContextRegval (ctx, REG_FPSW, (UINT8*)&value);
	int top =  (int) ((*value.word >> 11 ) & 0x7);
	printf ("fpu taints top %d thr %d: %d %d %d %d %d %d %d %d -> ", top, current_thread->slice_fp_top,
		is_reg_arg_tainted (LEVEL_BASE::REG_ST0, 10, 0),
		is_reg_arg_tainted (LEVEL_BASE::REG_ST1, 10, 0),
		is_reg_arg_tainted (LEVEL_BASE::REG_ST2, 10, 0),
		is_reg_arg_tainted (LEVEL_BASE::REG_ST3, 10, 0),
		is_reg_arg_tainted (LEVEL_BASE::REG_ST4, 10, 0),
		is_reg_arg_tainted (LEVEL_BASE::REG_ST5, 10, 0),
		is_reg_arg_tainted (LEVEL_BASE::REG_ST6, 10, 0),
		is_reg_arg_tainted (LEVEL_BASE::REG_ST7, 10, 0));
	printf ("(76543210) %d%d%d%d%d%d%d%d\n",
		is_reg_arg_tainted ((7 + top)%8 + LEVEL_BASE::REG_ST0, 10, 0), 
		is_reg_arg_tainted ((6 + top)%8 + LEVEL_BASE::REG_ST0, 10, 0), 
		is_reg_arg_tainted ((5 + top)%8 + LEVEL_BASE::REG_ST0, 10, 0), 
		is_reg_arg_tainted ((4 + top)%8 + LEVEL_BASE::REG_ST0, 10, 0), 
		is_reg_arg_tainted ((3 + top)%8 + LEVEL_BASE::REG_ST0, 10, 0), 
		is_reg_arg_tainted ((2 + top)%8 + LEVEL_BASE::REG_ST0, 10, 0), 
		is_reg_arg_tainted ((1 + top)%8 + LEVEL_BASE::REG_ST0, 10, 0), 
		is_reg_arg_tainted ((0 + top)%8 + LEVEL_BASE::REG_ST0, 10, 0));
	printf ("\n");
	fflush (stdout);
    }
}

#ifdef EXTRA_DEBUG
static void debug_print (INS ins) 
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
			   IARG_REG_VALUE, LEVEL_BASE::REG_ECX, 			
			   IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
			   IARG_REG_VALUE, LEVEL_BASE::REG_ESP, 			
			   IARG_CONST_CONTEXT,
			   IARG_END);
	} else if ((mem1read && !mem2read) || (!mem1read && mem2read)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)debug_print_inst, 
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_MEMORYREAD_EA, 
			   IARG_MEMORYWRITE_EA,
			   IARG_REG_VALUE, LEVEL_BASE::REG_ECX, 			
			   IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
			   IARG_REG_VALUE, LEVEL_BASE::REG_ESP, 			
			   IARG_CONST_CONTEXT,
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
			   IARG_REG_VALUE, LEVEL_BASE::REG_ECX, 			
			   IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
			   IARG_REG_VALUE, LEVEL_BASE::REG_ESP, 			
			   IARG_CONST_CONTEXT,
			   IARG_END);
	} else {
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)debug_print_inst, 
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR,
			   IARG_PTR, str,
			   IARG_MEMORYWRITE_EA, 
			   IARG_ADDRINT, 0,
			   IARG_REG_VALUE, LEVEL_BASE::REG_ECX, 			
			   IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
			   IARG_REG_VALUE, LEVEL_BASE::REG_ESP, 			
			   IARG_CONST_CONTEXT,
			   IARG_END);
	}
    } else { 
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)debug_print_inst, 
		       IARG_FAST_ANALYSIS_CALL,
		       IARG_INST_PTR,
		       IARG_PTR, str,
		       IARG_ADDRINT, 0,
		       IARG_ADDRINT, 0,
		       IARG_REG_VALUE, LEVEL_BASE::REG_ECX, 			
		       IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
			   IARG_REG_VALUE, LEVEL_BASE::REG_ESP, 			
		       IARG_CONST_CONTEXT,
		       IARG_END);
    }
}
#endif

void instruction_instrumentation(INS ins, void *v)
{
    OPCODE opcode;
    UINT32 category;
    int instrumented = 0;
    int slice_handled = 0;
    int rep_handled = 0;

#ifdef TAINT_STATS
    inst_instrumented++;
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
                IARG_CONST_CONTEXT,
                IARG_END);
	slice_handled = 1;
    } 

    opcode = INS_Opcode(ins);
    category = INS_Category(ins);

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
	    instrument_addorsub(ins, SF_FLAG|ZF_FLAG|PF_FLAG, OF_FLAG|CF_FLAG|AF_FLAG);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_ADD:
	case XED_ICLASS_SUB:
	case XED_ICLASS_ADC:
	    instrument_addorsub(ins, SF_FLAG|ZF_FLAG|PF_FLAG|OF_FLAG|CF_FLAG|AF_FLAG, 0);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_SBB:
	    instrument_sbb (ins);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_DIV:
	case XED_ICLASS_IDIV:
	    instrument_div(ins);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_MUL:
	    instrument_mul(ins);
	    slice_handled = 1;
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
	case XED_ICLASS_PMAXUB:
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
	    instrument_addorsub(ins, -1, -1);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_PCMPEQB:
	case XED_ICLASS_PCMPEQW:
	case XED_ICLASS_PCMPEQD:
	case XED_ICLASS_PCMPGTB:
	case XED_ICLASS_PCMPGTW:
	case XED_ICLASS_PCMPGTD:
	case XED_ICLASS_PCMPGTQ:
	    instrument_addorsub(ins, -1, -1);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_PINSRB:
	    instrument_pinsrb(ins);
	    slice_handled = 1;
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
	    instrument_pmovmskb(ins);
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
	case XED_ICLASS_INC:
	case XED_ICLASS_DEC:
	    instrument_incdec_neg (ins, OF_FLAG|SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG, 0);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_NEG:
	    instrument_incdec_neg (ins, CF_FLAG|OF_FLAG|SF_FLAG|ZF_FLAG|AF_FLAG|PF_FLAG, 0);
	    slice_handled = 1;
	    break;
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
	case XED_ICLASS_BSF:
	case XED_ICLASS_BSR:
	    instrument_bit_scan (ins);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_TEST:
	    instrument_test_or_cmp(ins, SF_FLAG|ZF_FLAG|PF_FLAG, CF_FLAG|OF_FLAG|AF_FLAG);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_CMP:
	    instrument_test_or_cmp(ins, SF_FLAG|ZF_FLAG|PF_FLAG|CF_FLAG|OF_FLAG|AF_FLAG, 0);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_PTEST:
	    instrument_test_or_cmp(ins, ZF_FLAG | CF_FLAG, OF_FLAG|AF_FLAG|PF_FLAG|SF_FLAG);
	    slice_handled = 1;
	    break;
	    //for the following 4 cases, refer to move_string
	case XED_ICLASS_CMPSB:
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
	    instrument_jump (ins, ZF_FLAG);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_JZ:
	    instrument_jump (ins, ZF_FLAG);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_JMP:
	    instrument_jump (ins, 0);
	    slice_handled = 1;
	    break;
        case XED_ICLASS_JB:
        case XED_ICLASS_JNB:
	    instrument_jump (ins, CF_FLAG);
	    slice_handled = 1;
	    break;
        case XED_ICLASS_JBE:
        case XED_ICLASS_JNBE:
	    instrument_jump (ins, CF_FLAG|ZF_FLAG);
	    slice_handled = 1;
	    break;
        case XED_ICLASS_JL:
        case XED_ICLASS_JNL:
	    instrument_jump (ins, SF_FLAG|OF_FLAG);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_JLE:
        case XED_ICLASS_JNLE: 
	    instrument_jump (ins, ZF_FLAG|SF_FLAG|OF_FLAG);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_JNO:
        case XED_ICLASS_JO:
	    instrument_jump (ins, OF_FLAG);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_JNP:
        case XED_ICLASS_JP:
	    instrument_jump (ins, PF_FLAG);
	    slice_handled = 1;
	    break;
        case XED_ICLASS_JNS:
        case XED_ICLASS_JS:
	    instrument_jump (ins, SF_FLAG);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_JRCXZ:
	    /* Could also be jecxz */
	    instrument_jump_ecx (ins);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_NOT:
	    instrument_not (ins);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_LEAVE:
	    instrument_leave (ins);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_CLD:
	case XED_ICLASS_STD:
	    //fw_slice_src_flag (ins, DF_FLAG);
	    instrument_clear_flag (ins, DF_FLAG);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_SAHF:
	    instrument_sahf (ins);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_BT:
	    instrument_bt (ins);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_CPUID:
	    // ignore this instruction
	    slice_handled = 1;
	    break;
	case XED_ICLASS_PUSHFD:
	    fw_slice_src_flag2mem (ins, uint32_t(-1), LEVEL_BASE::REG_INVALID(), LEVEL_BASE::REG_INVALID());
	    INS_InsertCall (ins, IPOINT_BEFORE, 
			    AFUNPTR(taint_pushfd), 
			    IARG_FAST_ANALYSIS_CALL, 
			    IARG_MEMORYWRITE_EA, 
			    IARG_UINT32, INS_MemoryWriteSize(ins),
			    IARG_END);
	    slice_handled = 1;
	    break;
	case XED_ICLASS_POPFD:
	    fw_slice_src_mem (ins, LEVEL_BASE::REG_INVALID(), LEVEL_BASE::REG_INVALID());
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
	case XED_ICLASS_FBLD:
	    instrument_fpu_load (ins);
	    slice_handled = 1;
	    break;
            case XED_ICLASS_FLDZ:
	case XED_ICLASS_FLD1:
	case XED_ICLASS_FLDL2T:
            case XED_ICLASS_FLDL2E:
            case XED_ICLASS_FLDPI:
            case XED_ICLASS_FLDLG2:
            case XED_ICLASS_FLDLN2:
                instrument_taint_clear_fpureg (ins, INS_OperandReg (ins, 0), -1, -1, 1);
                slice_handled = 1;
                break;
            case XED_ICLASS_FFREE:
                instrument_taint_clear_fpureg (ins, INS_OperandReg (ins, 0), -1, -1, 0);
                slice_handled = 1;
                break;
            case XED_ICLASS_FST:
            case XED_ICLASS_FSTP:
            case XED_ICLASS_FISTP:
            case XED_ICLASS_FIST:
            case XED_ICLASS_FBSTP:
            case XED_ICLASS_FISTTP:
                instrument_fpu_store (ins);
                slice_handled = 1;
                break;
            case XED_ICLASS_FMULP:
            case XED_ICLASS_FADDP:
            case XED_ICLASS_FSUBP:
            case XED_ICLASS_FSUBRP:
            case XED_ICLASS_FDIVP:
            case XED_ICLASS_FDIVRP:
	    case XED_ICLASS_FPATAN:
	    case XED_ICLASS_FYL2X:
	    case XED_ICLASS_FYL2XP1:
                instrument_fpu_calc (ins, FP_POP);
                slice_handled = 1;
                break;
            case XED_ICLASS_FINCSTP:
                {
                    //ignore this currently as we should have handled the stack top mismatch problem (mismatch between slice and original execution)
                    /*
                    char* str = get_copy_of_disasm (ins);
                    INS_InsertCall (ins, IPOINT_BEFORE , 
                            AFUNPTR (fw_slice_fpu_incstp), 
                            IARG_FAST_ANALYSIS_CALL, 
                            IARG_INST_PTR,
                            IARG_PTR, str, 
                            IARG_CONST_CONTEXT, 
                            IARG_END);
                    put_copy_of_disasm (str);*/
                    slice_handled = 1;
                }
                break;
            case XED_ICLASS_FNSTSW:
            case XED_ICLASS_FNSTCW:
                if (INS_OperandIsMemory (ins, 0)) { 
                    instrument_taint_clear_mem (ins);
                } else { 
                    instrument_taint_clear_reg (ins, INS_OperandReg (ins, 0), -1, -1);
                }
                slice_handled = 1;
                break;
            case XED_ICLASS_FMUL:
            case XED_ICLASS_FIMUL:
            case XED_ICLASS_FADD:
            case XED_ICLASS_FSUB:
            case XED_ICLASS_FSUBR:
            case XED_ICLASS_FISUB:
            case XED_ICLASS_FISUBR:
            case XED_ICLASS_FDIV:
            case XED_ICLASS_FDIVR:
            case XED_ICLASS_FIDIV:
            case XED_ICLASS_FIDIVR:
	    case XED_ICLASS_FSCALE:
                instrument_fpu_calc (ins, FP_NO_STACK_CHANGE);
                slice_handled = 1;
                break;
            case XED_ICLASS_FXCH:
                instrument_fpu_exchange (ins);
                slice_handled = 1;
                break;
            case XED_ICLASS_FCOMI:
            case XED_ICLASS_FUCOMI:
                instrument_fpu_cmp (ins, FP_NO_STACK_CHANGE);
                slice_handled = 1;
                break;
            case XED_ICLASS_FCOMIP:
            case XED_ICLASS_FUCOMIP:
                instrument_fpu_cmp (ins, FP_POP);
                slice_handled = 1;
                break;
            //FCOM/FCOMP/FCOMPP,FUCOM/FUCOMP/FUCOMPP  only affect fpu flags, not eflags; so just pop fpu stack if necessary
            case XED_ICLASS_FCOM:
            case XED_ICLASS_FUCOM:
                //slice_handled = 1;
                break;
	    case XED_ICLASS_F2XM1:
	    case XED_ICLASS_FABS:
	    case XED_ICLASS_FCHS:
	    case XED_ICLASS_FRNDINT:
	    case XED_ICLASS_FSQRT:
   	    case XED_ICLASS_FCOS:
   	    case XED_ICLASS_FSIN:
		instrument_fpu_onereg_calc (ins);
		slice_handled = 1;
		break;
            case XED_ICLASS_FCOMP:
            case XED_ICLASS_FUCOMP:
            case XED_ICLASS_FCOMPP:
            case XED_ICLASS_FUCOMPP:
                INSTRUMENT_PRINT(log_f, "[INFO] FPU inst: %s, op_count %u\n", INS_Disassemble(ins).c_str(), INS_OperandCount(ins));
		// These only work because we are not allowing any FPU registers to become tainted - if we do, then we need to support all of these
                break;
            case XED_ICLASS_FCMOVBE:
            case XED_ICLASS_FCMOVNBE:
		instrument_fpu_cmov (ins, CF_FLAG|ZF_FLAG);
                slice_handled = 1;
		break;
            case XED_ICLASS_FCMOVE:
            case XED_ICLASS_FCMOVNE:
		instrument_fpu_cmov (ins, ZF_FLAG);
                slice_handled = 1;
		break;
            case XED_ICLASS_FCMOVB:
            case XED_ICLASS_FCMOVNB:
		instrument_fpu_cmov (ins, CF_FLAG);
                slice_handled = 1;
		break;
	    case XED_ICLASS_FWAIT:
            case XED_ICLASS_FLDCW:
	    case XED_ICLASS_PREFETCHNTA:
                //ignored
                slice_handled = 1;
                break;
   	    case XED_ICLASS_CWDE:
		instrument_cwde (ins);
		slice_handled = 1;
		break;
   	    case XED_ICLASS_BSWAP:
		instrument_bswap (ins);
		slice_handled = 1;
		break;
            case XED_ICLASS_LDMXCSR:
                instrument_ldmxcsr (ins);
                slice_handled = 1;
                break;
            case XED_ICLASS_STMXCSR:
                instrument_taint_clear_mem (ins);
                slice_handled = 1;
                break;
            case XED_ICLASS_CDQ:
                instrument_taint_reg2reg (ins, LEVEL_BASE::REG_EDX, LEVEL_BASE::REG_EAX, 0);
                fw_slice_src_reg (ins, LEVEL_BASE::REG_EAX);
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
		    // Seems like we should include in slice and taint eax/edx registers
		    fprintf (stderr, "We encountered a rdtsc instruction at %x: \n", INS_Address(ins));
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
	ERROR_PRINT (stderr, "[NOOP] ERROR: instruction %s is not handled for forward slicing, address %#x\n", INS_Disassemble(ins).c_str(), (unsigned)INS_Address(ins));
    }
	
}

static void instrument_ctrl_flow_track_inst_dest (INS ins) 
{ 
    uint32_t operand_count = INS_OperandCount (ins);
    if (INS_IsCall (ins)) {
        fprintf (stderr, "instrument_ctrl_flow_track_inst_dest: we might have a call instruction on potential diverged branch. Make sure both branches make the same call inst\n");
        return;
    }
    for (uint32_t i = 0; i<operand_count; ++i) { 
        if (INS_OperandWritten (ins, i)) { 
            if (INS_OperandIsReg (ins, i)) {
                REG reg = INS_OperandReg (ins, i);
                assert (REG_valid(reg));
                if (reg == LEVEL_BASE::REG_EIP && INS_IsBranchOrCall (ins)) { 
                    //ignore ip register
                } else if (reg == LEVEL_BASE::REG_EFLAGS) {
                    //as the eflag reg is almost certainly modified by some instruction in a basic block (which the jump at the bb exit probably uses), I'll always put eflags in the store set
                    //so it's safe to ignore it here
                } else { 
                    INS_InsertCall (ins, IPOINT_BEFORE, 
                            AFUNPTR(ctrl_flow_print_inst_dest_reg),
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_INST_PTR,
                            IARG_UINT32, reg, //for control flow handling: I don't think we need translate_reg here, as it doesn't matter if we put both EAX and AL in the store set; value restore and taint should be correct even if they're restored twice for certain bytes in one register; 
                            IARG_REG_REFERENCE, reg,
                            IARG_END);
                }
            } else if (INS_OperandIsMemory (ins, i)) { 
                REG base_reg = INS_OperandMemoryBaseReg(ins, i);
                REG index_reg = INS_OperandMemoryIndexReg(ins, i);
                SETUP_BASE_INDEX (base_reg, index_reg);
                INS_InsertCall (ins, IPOINT_BEFORE, 
                        AFUNPTR(ctrl_flow_print_inst_dest_mem), 
                        IARG_FAST_ANALYSIS_CALL,
                        IARG_INST_PTR, 
                        IARG_MEMORYWRITE_EA, 
                        IARG_UINT32, INS_MemoryWriteSize(ins),
                        PASS_BASE_INDEX,
                        IARG_END);
            } else if (INS_OperandIsBranchDisplacement (ins, i)) {
                assert (0);
            } else if (INS_OperandIsAddressGenerator(ins, i)) {
                assert (0);
            } else {
                //what else operand can be????
                if (INS_IsRet (ins)) {
                    //RET can be safely ignored as we always verify the control flow
                } else if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) {
                } else 
		    fprintf (stderr, " instrument_ctrl_flow_track_inst_dest: unkonwn operand?????? %s\n", INS_Disassemble(ins).c_str());
            }
        } 
    }
}

static void print_all_operands (INS ins) { 
    uint32_t operand_count = INS_OperandCount (ins);
    printf ("[print_dest] %s, operand count %u\n", INS_Disassemble(ins).c_str(), operand_count);
    for (uint32_t i = 0; i<operand_count; ++i) { 
        bool implicit = INS_OperandIsImplicit (ins, i);
        if (INS_OperandIsReg (ins, i)) {
            REG reg = INS_OperandReg (ins, i);
            assert (REG_valid(reg));
            if (reg == LEVEL_BASE::REG_EIP && INS_IsBranchOrCall (ins)) { 
                //ignore ip register
                printf ("      --- EIP implicit? %d, operand reg %d\n", implicit, INS_OperandReg (ins, i));
            } else if (reg == LEVEL_BASE::REG_EFLAGS) {
                printf ("      --- EFLAGS implicit? %d, operand reg %d\n", implicit, INS_OperandReg (ins, i));
            } else { 
                printf ("      --- implicit? %d, pos %d, operand reg %d\n", implicit, i, INS_OperandReg (ins, i));
            }
        } else if (INS_OperandIsMemory (ins, i)) { 
            printf ("      --- implicit? %d, operand mem pos %d, base %d, index %d\n", implicit, i, INS_OperandMemoryBaseReg (ins, i), INS_OperandMemoryIndexReg(ins, i));
        } else if (INS_OperandIsBranchDisplacement (ins, i)) {
            printf ("      --- implicit? %d, branch displacement.\n", implicit);
        } else if (INS_OperandIsAddressGenerator(ins, i)) {
            printf ("      --- implicit? %d, address generator\n", implicit);
        } else if (INS_OperandIsFixedMemop (ins, i)) { 
            printf ("      --- implicit? %d, fixed memoop pos %d\n", implicit, i);
        } else {
            printf ("      --- unknown operand read?%d write?%d, pos %d\n", INS_OperandRead(ins, i), INS_OperandWritten(ins, i), i);
            //what else operand can be????
            if (INS_IsRet (ins)) {
                printf ("    ---- RET inst.\n");
            } else if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) {
                printf ("    ---- stack read/write inst.\n");
            } 
        }
    }

}

static void instrument_track_patch_based_ckpt (INS ins) 
{ 
    uint32_t operand_count = INS_OperandCount (ins);
    if (INS_IsCall (ins)) {
        //TODO: what effects should we consider for patch_based_ckpt with call instructions? 
        //fprintf (stderr, "instrument_track_patch_based_ckpt: we might have a call instruction on potential diverged branch. Make sure both branches make the same call inst\n");
        return;
    }
    set<REG> readRegs;
    set<REG> writtenRegs; 
    //first check the number of read operands and written operands
    //Note: sometimes the same operand is both read and written
    for (uint32_t i = 0; i<operand_count; ++i) { 
        if (INS_OperandWritten (ins, i)) { 
            if (INS_OperandIsReg (ins, i)) {
                REG reg = INS_OperandReg (ins, i);
                assert (REG_valid(reg));
                if (REG_is_st (reg))
                    printf ("instrument_track_patch_based_ckpt: fpu reg for inst %s\n", INS_Disassemble(ins).c_str());
                else if (reg != LEVEL_BASE::REG_EFLAGS)
                    writtenRegs.insert (reg);
            }
            else if (INS_OperandIsMemory (ins, i)) { 
                //add base and index registers
                REG base_reg = INS_OperandMemoryBaseReg(ins, i);
                REG index_reg = INS_OperandMemoryIndexReg(ins, i);
                if (REG_valid (base_reg)) readRegs.insert (base_reg);
                if (REG_valid (index_reg)) readRegs.insert (index_reg);
            } else if (INS_OperandIsBranchDisplacement (ins, i)) {
                assert (0);
            } else if (INS_OperandIsAddressGenerator(ins, i)) {
                assert (0);
            } else {
                //what else operand can be????
                if (INS_IsRet (ins)) {


                    //TODO: I still want to make sure these instrucionts doesn't have more than 1 unknow operands
                    
                    
                    //RET can be safely ignored as we always verify the control flow
                } else if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) {
                } else if (INS_IsStringop (ins)) {
                } else {
                    string dis = INS_Disassemble (ins); 
                    if (dis[0] == 'f') continue; //ignore fpu instructions; these operands doesn't matter 
                    fprintf (stderr, " instrument_track_patch_based_ckpt: unkonwn operand?????? %s at pos %d, operand_count %d\n", dis.c_str(), i, operand_count);
                    print_all_operands (ins);
                }
            }
        } 
        if (INS_OperandRead (ins, i)) {
            if (INS_OperandIsReg (ins, i)) {
                REG reg = INS_OperandReg (ins, i);
                if (!REG_valid (reg)) {
                    fprintf (stderr, "instrument_track_patch_based_ckpt: Invalid read reg operand?? for inst %s\n", INS_Disassemble(ins).c_str());
                } else if (REG_is_st (reg)) {
                    printf ("instrument_track_patch_based_ckpt: fpu reg for inst %s\n", INS_Disassemble(ins).c_str());
                } else {
                    if (reg != LEVEL_BASE::REG_EFLAGS)
                        readRegs.insert (reg);
                }
            } else if (INS_OperandIsMemory (ins, i)) {
                //add base and index registers
                REG base_reg = INS_OperandMemoryBaseReg(ins, i);
                REG index_reg = INS_OperandMemoryIndexReg(ins, i);
                if (REG_valid (base_reg)) readRegs.insert (base_reg);
                if (REG_valid (index_reg)) readRegs.insert (index_reg);
            } else if (INS_OperandIsImmediate (ins, i)) {
                //do nothing
            } else if (INS_OperandIsAddressGenerator (ins, i)) {
                REG base_reg = INS_OperandMemoryBaseReg(ins, i);
                REG index_reg = INS_OperandMemoryIndexReg(ins, i);
                if (REG_valid (base_reg)) readRegs.insert (base_reg);
                if (REG_valid (index_reg)) readRegs.insert (index_reg);
            } else { 
                if (INS_IsRet (ins)) {


                    //TODO: I still want to make sure these instrucionts doesn't have more than 1 unknow operands
                    
                    
                    //RET can be safely ignored as we always verify the control flow
                } else if (INS_IsStackRead(ins) || INS_IsStackWrite(ins)) {
                } else if (INS_OperandIsBranchDisplacement (ins, i)) {
                } else if (INS_OperandIsFixedMemop (ins, i)) {
                    fprintf (stderr, "Fixed memoop at pos %d for %s\n", i, INS_Disassemble(ins).c_str());
                } else if (INS_OperandIsAddressGenerator(ins, i)) {
                    assert (0);
                } else if (INS_IsStringop (ins)) {
                } else {
                    string dis = INS_Disassemble (ins); 
                    if (dis[0] == 'f') continue; //ignore fpu instructions; these operands doesn't matter 
		    fprintf (stderr, "implicit?%d unknown operand at pos %d?????? %s, ip %x, operand_count %d\n", INS_OperandIsImplicit (ins, i), i, dis.c_str(), INS_Address(ins), operand_count);
                    print_all_operands (ins);
                }
            }
        }

    }

    //now instrument all regs 
    vector<REG> regs(readRegs.begin(), readRegs.end());
    int read = 1;
            for (int i = 0; i < 2; ++i) { 
            switch (regs.size()) {
                case 1: 
                    INS_InsertPredicatedCall (ins, IPOINT_BEFORE, 
                            AFUNPTR (log_inst_reg1),
                            IARG_FAST_ANALYSIS_CALL, 
                            IARG_INST_PTR,
                            IARG_UINT32, read, 
                            IARG_UINT32, regs[0], 
                            IARG_UINT32, get_reg_off(regs[0]),
                            IARG_UINT32, REG_Size(regs[0]), 
                            IARG_REG_REFERENCE, regs[0],
                            IARG_END);
                    break;
                case 2:
                    INS_InsertPredicatedCall (ins, IPOINT_BEFORE, 
                            AFUNPTR (log_inst_reg2),
                            IARG_FAST_ANALYSIS_CALL, 
                            IARG_INST_PTR,
                            IARG_UINT32, read, 
                            IARG_UINT32, regs[0], 
                            IARG_UINT32, get_reg_off(regs[0]),
                            IARG_UINT32, REG_Size(regs[0]), 
                            IARG_REG_REFERENCE, regs[0],
                            IARG_UINT32, regs[1],
                            IARG_UINT32, get_reg_off(regs[1]),
                            IARG_UINT32, REG_Size(regs[1]), 
                            IARG_REG_REFERENCE, regs[1],
                            IARG_END);
                    break;
                case 3:
                    INS_InsertPredicatedCall (ins, IPOINT_BEFORE, 
                            AFUNPTR (log_inst_reg3),
                            IARG_FAST_ANALYSIS_CALL, 
                            IARG_INST_PTR,
                            IARG_UINT32, read, 
                            IARG_UINT32, regs[0],
                            IARG_UINT32, get_reg_off(regs[0]),
                            IARG_UINT32, REG_Size(regs[0]), 
                            IARG_REG_REFERENCE, regs[0],
                            IARG_UINT32, regs[1],
                            IARG_UINT32, get_reg_off(regs[1]),
                            IARG_UINT32, REG_Size(regs[1]), 
                            IARG_REG_REFERENCE, regs[1],
                            IARG_UINT32, regs[2],
                            IARG_UINT32, get_reg_off(regs[2]),
                            IARG_UINT32, REG_Size(regs[2]), 
                            IARG_REG_REFERENCE, regs[2],
                            IARG_END);
                    break;
                case 4:
                    INS_InsertPredicatedCall (ins, IPOINT_BEFORE, 
                            AFUNPTR (log_inst_reg4),
                            IARG_FAST_ANALYSIS_CALL, 
                            IARG_INST_PTR,
                            IARG_UINT32, read, 
                            IARG_UINT32, regs[0],
                            IARG_UINT32, get_reg_off(regs[0]),
                            IARG_UINT32, REG_Size(regs[0]), 
                            IARG_REG_REFERENCE, regs[0],
                            IARG_UINT32, regs[1],
                            IARG_UINT32, get_reg_off(regs[1]),
                            IARG_UINT32, REG_Size(regs[1]), 
                            IARG_REG_REFERENCE, regs[1],
                            IARG_UINT32, regs[2],
                            IARG_UINT32, get_reg_off(regs[2]),
                            IARG_UINT32, REG_Size(regs[2]), 
                            IARG_REG_REFERENCE, regs[2],
                            IARG_UINT32, regs[3],
                            IARG_UINT32, get_reg_off(regs[3]),
                            IARG_UINT32, REG_Size(regs[3]), 
                            IARG_REG_REFERENCE, regs[3],
                            IARG_END);
                    break;
                case 5:
                    INS_InsertPredicatedCall (ins, IPOINT_BEFORE, 
                            AFUNPTR (log_inst_reg5),
                            IARG_FAST_ANALYSIS_CALL, 
                            IARG_INST_PTR,
                            IARG_UINT32, read, 
                            IARG_UINT32, regs[0],
                            IARG_UINT32, get_reg_off(regs[0]),
                            IARG_UINT32, REG_Size(regs[0]), 
                            IARG_REG_REFERENCE, regs[0],
                            IARG_UINT32, regs[1],
                            IARG_UINT32, get_reg_off(regs[1]),
                            IARG_UINT32, REG_Size(regs[1]), 
                            IARG_REG_REFERENCE, regs[1],
                            IARG_UINT32, regs[2],
                            IARG_UINT32, get_reg_off(regs[2]),
                            IARG_UINT32, REG_Size(regs[2]), 
                            IARG_REG_REFERENCE, regs[2],
                            IARG_UINT32, regs[3],
                            IARG_UINT32, get_reg_off(regs[3]),
                            IARG_UINT32, REG_Size(regs[3]), 
                            IARG_REG_REFERENCE, regs[3],
                            IARG_UINT32, regs[4],
                            IARG_UINT32, get_reg_off(regs[4]),
                            IARG_UINT32, REG_Size(regs[4]), 
                            IARG_REG_REFERENCE, regs[4],
                            IARG_END);
                    break;
                default:
                    if (regs.size() == 0 && (INS_IsStackRead (ins) || INS_IsStackWrite (ins))) break;
                    if (readRegs.size () + writtenRegs.size() == 0) {
                        //fprintf (stderr, "There is no reg operand for inst %s???\n", INS_Disassemble(ins).c_str());
                    } else {
                        if (regs.size() != 0)
                            fprintf (stderr, "total of %d %s operands for %s\n", regs.size(), read?"read":"write", INS_Disassemble(ins).c_str());
                    }
            }
            regs.clear();
            regs.insert (regs.begin(), writtenRegs.begin(), writtenRegs.end());
            read = 0;
        }
    //instrument mem reads
    //TODO: We might want to eliminate this extra instrumentation and do this work on each fw_slice_XXX function
    //Of course this requires some work to modify 20 functions, but may be more efficient; and may be more accurate (or maybe not? depends on how you define accuracy) for REP instructions since fw_slice_strnig_XX capture the upper bound of all input memory while the below method only capture the actual input memory
    if (INS_IsMemoryRead (ins)) {
        if (INS_HasMemoryRead2 (ins)) { 
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)log_inst_src_mem2,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_INST_PTR,
                    IARG_MEMORYREAD_EA, 
                    IARG_MEMORYREAD2_EA, 
                    IARG_UINT32, INS_MemoryReadSize(ins),
                    IARG_END);
        } else { 
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    (AFUNPTR)log_inst_src_mem1,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_INST_PTR,
                    IARG_MEMORYREAD_EA, 
                    IARG_UINT32, INS_MemoryReadSize(ins),
                    IARG_END);
        }
    }
    if (INS_IsMemoryWrite (ins)) { 
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                (AFUNPTR)log_inst_dest_mem,
                IARG_FAST_ANALYSIS_CALL,
                IARG_INST_PTR,
                IARG_MEMORYWRITE_EA, 
                IARG_UINT32, INS_MemoryWriteSize(ins),
                IARG_END);
    }
}

void PIN_FAST_ANALYSIS_CALL count_instruction ()
{
    ++inst_count;
}

void trace_instrumentation(TRACE trace, void* v)
{
    struct timeval tv_end, tv_start;

    gettimeofday (&tv_start, NULL);
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after_redo, IARG_INST_PTR, IARG_END);

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        INS tail = BBL_InsTail (bbl);
        char* str = get_copy_of_disasm (tail);
        INS_InsertCall (tail, IPOINT_BEFORE, (AFUNPTR) monitor_control_flow_tail, 
			IARG_FAST_ANALYSIS_CALL,
			IARG_INST_PTR, 
			IARG_PTR, str, 
			IARG_BRANCH_TAKEN,
			IARG_CONST_CONTEXT,
			IARG_END);

        put_copy_of_disasm (str);
	bool track_this_bb = false;
	for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
#ifdef EXTRA_DEBUG
	  debug_print (ins);
#endif
	    if (current_thread->ctrl_flow_info.merge_insts->find(INS_Address(ins)) != current_thread->ctrl_flow_info.merge_insts->end()) {
		INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR) monitor_merge_point,
				IARG_FAST_ANALYSIS_CALL, 
				IARG_INST_PTR, 
				IARG_PTR, str, 
				IARG_BRANCH_TAKEN,
				IARG_CONST_CONTEXT,
				IARG_END);
	    }

            if (function_level_tracking) 
                instrument_track_patch_based_ckpt (ins);

            if (track_this_bb || current_thread->ctrl_flow_info.insts_instrumented->find(INS_Address(ins)) != current_thread->ctrl_flow_info.insts_instrumented->end()) {
                instrument_ctrl_flow_track_inst_dest (ins);
		track_this_bb = true;
            }

#ifndef OPTIMIZED
            INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(count_instruction), 
                    IARG_FAST_ANALYSIS_CALL, 
                    IARG_END);
#endif

	    instruction_instrumentation (ins, NULL);
	}
    }
    gettimeofday (&tv_end, NULL);

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

static void destroy_ctrl_flow_info (struct thread_data* tdata)
{
    if (tdata->ctrl_flow_info.diverge_point) delete tdata->ctrl_flow_info.diverge_point;
    if (tdata->ctrl_flow_info.diverge_inst) delete tdata->ctrl_flow_info.diverge_inst;
    if (tdata->ctrl_flow_info.store_set_reg) delete tdata->ctrl_flow_info.store_set_reg;
    if (tdata->ctrl_flow_info.store_set_mem) delete tdata->ctrl_flow_info.store_set_mem;
    if (tdata->ctrl_flow_info.alt_branch_store_set_reg) delete tdata->ctrl_flow_info.alt_branch_store_set_reg;
    if (tdata->ctrl_flow_info.alt_branch_store_set_mem) delete tdata->ctrl_flow_info.alt_branch_store_set_mem;
    if (tdata->ctrl_flow_info.merge_insts) delete tdata->ctrl_flow_info.merge_insts;
    if (tdata->ctrl_flow_info.insts_instrumented) delete tdata->ctrl_flow_info.insts_instrumented;
    if (tdata->ctrl_flow_info.tracked_orig_path) delete tdata->ctrl_flow_info.tracked_orig_path;
    if (tdata->ctrl_flow_info.handled_tags) delete tdata->ctrl_flow_info.handled_tags;
}

static void init_ctrl_flow_info (struct thread_data* ptdata)
{
   ptdata->ctrl_flow_info.diverge_point = new std::deque<struct ctrl_flow_block_info>();
   ptdata->ctrl_flow_info.diverge_inst = new std::map<u_long,struct ctrl_flow_block_info>();
   ptdata->ctrl_flow_info.clock = 0;
   ptdata->ctrl_flow_info.index = 0;
   ptdata->ctrl_flow_info.store_set_reg = new std::set<uint32_t> ();
   ptdata->ctrl_flow_info.store_set_mem = new std::map<u_long, struct ctrl_flow_origin_value> ();
   ptdata->ctrl_flow_info.alt_branch_store_set_reg = new vector<set<uint32_t> > ();
   ptdata->ctrl_flow_info.alt_branch_store_set_mem = new vector<map<u_long, struct ctrl_flow_origin_value> >();
   ptdata->ctrl_flow_info.merge_insts = new std::set<uint32_t> ();
   ptdata->ctrl_flow_info.insts_instrumented = new std::set<uint32_t> ();
   ptdata->ctrl_flow_info.is_rolled_back = false;
   ptdata->ctrl_flow_info.is_in_original_branch = false;
   ptdata->ctrl_flow_info.is_in_branch_first_inst = false;
   ptdata->ctrl_flow_info.is_in_diverged_branch = false;
   ptdata->ctrl_flow_info.alt_path_index  = 0;
   ptdata->ctrl_flow_info.is_nested_jump = false;
   ptdata->ctrl_flow_info.is_tracking_orig_path = false;
   ptdata->ctrl_flow_info.tracked_orig_path = new deque<struct ctrl_flow_branch_info>();
   ptdata->ctrl_flow_info.swap_index = -1;
   ptdata->ctrl_flow_info.is_orig_path_tracked = false;
   ptdata->ctrl_flow_info.handled_tags = new multimap<int, bool>();

   struct ctrl_flow_block_info index;
   int alt_path_index = -1; //which alt path we are in
   index.ip = 0;
   for (vector<struct ctrl_flow_param>::iterator iter=ctrl_flow_params.begin(); iter != ctrl_flow_params.end(); ++iter) { 
       struct ctrl_flow_param i = *iter;
       //fprintf (stderr, "ip %x type %d pid %d, current pid %d, alt_branch_count %d\n", i.ip, i.type, i.pid, ptdata->record_pid, i.alt_branch_count);
       if (i.pid == ptdata->record_pid || i.pid == -1) {
           if (i.type == CTRL_FLOW_BLOCK_TYPE_DIVERGENCE) {
               index.clock = i.clock;
               index.index = i.index;
	       index.ip = i.ip; 
               assert (index.ip != 0);
	       index.orig_taken = (i.branch_flag == 't');
	       index.extra_loop_iterations = -1;
	       index.orig_path_nonempty = false;
               index.alt_path_nonempty.resize (i.alt_branch_count);
               index.alt_path_count = i.alt_branch_count;
               index.alt_path.resize (i.alt_branch_count);
               struct ctrl_flow_branch_info in;
               in.ip = i.ip;
               in.branch_flag = i.branch_flag;
               in.tag = -1;
               index.orig_path.push (in);
               for (int j = 0; j<i.alt_branch_count; ++j) {
                   while (!index.alt_path[j].empty()) index.alt_path[j].pop();
                   index.alt_path_nonempty[j] = false;
               }
	       index.iter_count = i.iter_count;
          } else if (i.type == CTRL_FLOW_BLOCK_TYPE_MERGE) { 
	       index.merge_ip = i.ip;
	       if (i.pid == -1) {
		   if (index.ip == 0) {
		       fprintf (stderr, "merge entry without preceeding diverge entry\n");
		   } else {
		       // Add wild card divergence
                       //fprintf (stderr, "add wildcard ip %lx\n", index.ip);
		       ptdata->ctrl_flow_info.diverge_inst->insert (make_pair(index.ip, index));
		   }
	       } else {
		   ptdata->ctrl_flow_info.diverge_point->push_back (index);
	       }
	       ptdata->ctrl_flow_info.merge_insts->insert(i.ip);
	       index.ip = 0;
               while (!index.orig_path.empty()) index.orig_path.pop();
               index.alt_path.clear();
               alt_path_index = -1;
           } else if (i.type == CTRL_FLOW_BLOCK_TYPE_INSTRUMENT_ORIG) {
	       if (index.ip == 0) {
		   fprintf (stderr, "Orig path entry without preceeding diverge entry\n");
	       } else {
		   ptdata->ctrl_flow_info.insts_instrumented->insert(i.ip);	
		   if (i.branch_flag != '-') {
                       struct ctrl_flow_branch_info in;
                       in.ip = i.ip;
                       in.branch_flag = i.branch_flag;
                       in.tag = i.tag;
		       index.orig_path.push(in);
		   } 
		   index.orig_path_nonempty = true;
	       }
           } else if (i.type == CTRL_FLOW_POSSIBLE_PATH_BEGIN) {
               ++alt_path_index;
               //always push the divergence block into the alternative path
               //If we have several alternative paths, some of them may take the same direction at the divergence point as the original path
               assert (i.branch_flag != '-');
               struct ctrl_flow_branch_info in;
               in.ip = i.ip;
               in.tag = -1;
               in.branch_flag = i.branch_flag;
               index.alt_path[alt_path_index].push(in);
           } else if (i.type == CTRL_FLOW_BLOCK_TYPE_INSTRUMENT_ALT) {
               if (alt_path_index < 0) { 
                   fprintf (stderr, "Alt path index is not set.\n");
               }
	       if (index.ip == 0) {
		   fprintf (stderr, "Alt path entry without preceeding diverge entry\n");
	       } else {
		   ptdata->ctrl_flow_info.insts_instrumented->insert(i.ip);
		   if (i.branch_flag != '-') {
                       struct ctrl_flow_branch_info in;
                       in.ip = i.ip;
                       in.branch_flag = i.branch_flag;
                       in.tag = i.tag;
		       index.alt_path[alt_path_index].push(in);
		   }
		   index.alt_path_nonempty[alt_path_index] = true;
	       }
	   }
       }
   }
}

void init_patch_based_ckpt_info (struct thread_data* tdata)
{
    struct patch_based_ckpt_info* info = &tdata->patch_based_ckpt_info;
    memset (info->read_reg, 0, sizeof(info->read_reg));
    memset (info->read_reg_value, 0, sizeof(info->read_reg_value));
    info->write_reg = new set<int>();
    info->write_mem = new set<u_long>();
    info->read_mem = new map<u_long, char>();
}

void destroy_patch_based_ckpt_info (struct thread_data* tdata) 
{
    struct patch_based_ckpt_info* info = &tdata->patch_based_ckpt_info;
    if (info->write_reg) delete info->write_reg;
    if (info->write_mem) delete info->write_mem;
    if (info->read_mem) delete info->read_mem;
}

void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PRINTX(stderr, "%d,%d:AfterForkInChild\n", PIN_GetPid(),get_record_pid());
    fprintf (stderr, "AfterForkInChild called, threadid %d current_thread %p addr %p\n", threadid, current_thread, &current_thread);

    /* Do some of the things we would normally do in thread_start here */
    current_thread->threadid = threadid;
    current_thread->record_pid = get_record_pid();
    if (!function_level_tracking) {
        if (recheck_group) {
            current_thread->recheck_handle = open_recheck_log (recheck_group, current_thread->record_pid);
        } else {
            current_thread->recheck_handle = NULL;
        }	
        if (fw_slice_print_header(recheck_group, current_thread, 0) < 0) {
            fprintf (stderr, "[ERROR] fw_slice_print_header fails.\n");
            return;
        }
        current_thread->start_tracking = true;
    } else { 
        current_thread->start_tracking = false;
        current_thread->recheck_handle = NULL;
    }

    /* Some of these should be global, not per-thread */
    current_thread->saved_flag_taints = new std::stack<struct flag_taints>();
    init_ctrl_flow_info (current_thread);
    init_patch_based_ckpt_info (current_thread);

    current_thread->syscall_cnt = 0; //not ceratin that this is right anymore.. 

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

    }
    else { 
	PRINTX(stderr, "\tfollowing parent\n");
    }
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
    if (!function_level_tracking) {
        if (recheck_group) {
            ptdata->recheck_handle = open_recheck_log (recheck_group, ptdata->record_pid);
        } else {
            ptdata->recheck_handle = NULL;
        }	
        //ptdata->slice_buffer = new queue<string>();
        if (fw_slice_print_header(recheck_group, ptdata, !first_thread) < 0) {
            fprintf (stderr, "[ERROR] fw_slice_print_header fails.\n");
            return;
        }
        ptdata->start_tracking = true; //start to track from the beginning
    } else {
        ptdata->start_tracking = false; //start to track until we encounter sys_jumpstart_runtime
        ptdata->recheck_handle = NULL;
    }

    ptdata->saved_flag_taints = new std::stack<struct flag_taints>();
    init_ctrl_flow_info (ptdata);
    init_patch_based_ckpt_info (ptdata);

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

    if (first_thread == 0) {
#ifdef EXEC_INPUTS
        int acc = 0;
        char** args;
        struct taint_creation_info tci;
#endif

        //PIN_AddFollowChildProcessFunction(follow_child, ptdata);
        first_thread = ptdata->record_pid;
        if (!ptdata->syscall_cnt) {
            ptdata->syscall_cnt = 1;
        }
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

#if 0
	// Experimental
	// Patch environment variables here
	char target_str[] = "DBUS_SESSION_BUS_ADDRESS=";
	char* env_start = (char *) 0xbffff481;
	char* env_end = (char *) 0xbfffffee;
	char* env = env_start;
	while (env < env_end) {
	    if (*env == '\0') break;
	    if (!strncmp(env, target_str, strlen(target_str))) {
		fprintf (stderr, "DBUS_SESSION_BUS_ADDRESS at %p\n", env);
		if (env) fprintf (stderr, "DBUS_SESSION_BUS_ADDRESS is %s\n", env);
		struct taint_creation_info tci;
		tci.rg_id = ptdata->rg_id;
		tci.record_pid = ptdata->record_pid;
		tci.syscall_cnt = 0;
		tci.offset = 0;
		tci.fileno = 0;
		tci.data = 0;
		tci.type = 0;
		create_taints_from_buffer_unfiltered (env+strlen(target_str), strlen(env)+1-strlen(target_str), &tci, tokens_fd);
		printf ("create taints: %p, %d, %p, %d\n", env+strlen(target_str), strlen(env)+1-strlen(target_str), &tci, tokens_fd);
		printf ("0xbfffffe6 tainted: %d value: %x\n", is_mem_arg_tainted(0xbffffeff, 1), *((u_char *) 0xbffffeff));
		break;
	    } else {
		env += strlen(env)+1;
	    }
	}
#endif

#if 0
        //xdou: test 
        //try to taint the last argument
        int acc = 0;
        char** args;
        struct taint_creation_info tci;

        fprintf(stderr, "This is only for testing\n");
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
            if (*(args + 1) == NULL) {
                fprintf (stderr, "taint this arg %p, len %d\n", arg, strlen(arg));
                create_taints_from_buffer_unfiltered(arg, strlen(arg) + 1, &tci, tokens_fd);
            }
            acc += strlen(arg) + 1;
            args += 1;
        }
        //end test
#endif

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
    //slice ordering
    if (!function_level_tracking) {
        if (*ppthread_log_clock != 0) {
            //this is the first thread that executes
            if (*ppthread_log_clock <=2) { 
                previous_thread = current_thread;
                //init clock values for the first thread
                OUTPUT_SLICE (0, "pushfd");
                OUTPUT_SLICE_INFO ("slice ordering clock %lu", *ppthread_log_clock);
                //init mutex and condition var 
                OUTPUT_SLICE (0, "call recheck_wait_init");
                OUTPUT_SLICE_INFO ("slice ordering clock %lu", *ppthread_log_clock);
                OUTPUT_SLICE (0, "popfd");
                OUTPUT_SLICE_INFO ("slice ordering clock %lu", *ppthread_log_clock);
            } else {
                //init for other threads
                OUTPUT_SLICE (0, "pushfd"); 
                OUTPUT_SLICE_INFO ("slice ordering clock %lu", *ppthread_log_clock);
                OUTPUT_SLICE (0, "call recheck_wait_proc_init"); 
                OUTPUT_SLICE_INFO ("slice ordering clock %lu", *ppthread_log_clock);
                OUTPUT_SLICE (0, "popfd");
                OUTPUT_SLICE_INFO ("slice ordering clock %lu", *ppthread_log_clock);
                //wait until it should start
                slice_thread_wait (current_thread);
            }
        }
    }
}

void thread_fini (THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, threadid);

    //TODO: we need to call this function if the thread ends earlier before the checkpoint clock?
    //and we also need to make sure this thread wakes up other necessary threads
    active_threads.erase(tdata->record_pid);
    if (tdata->recheck_handle) close_recheck_log (tdata->recheck_handle);
    if (tdata->slice_output_file) {
        fclose (tdata->slice_output_file);
        fprintf (stderr, "[BUG] well the slice_output_file is not closed before the thread_fini? A thread finishes before the checkpoint clock?\n");
        tdata->slice_output_file = NULL;
    }
    if (tdata->slice_buffer) delete tdata->slice_buffer;
    destroy_ctrl_flow_info (tdata);
    destroy_patch_based_ckpt_info (current_thread);
}

void PIN_FAST_ANALYSIS_CALL print_function_name (char* name)
{
#ifdef EXTRA_DEBUG
    if (*ppthread_log_clock < EXTRA_DEBUG) return;
#endif
#ifdef EXTRA_DEBUG_STOP
    if (*ppthread_log_clock >= EXTRA_DEBUG_STOP) return;
#endif
    printf ("[debug function call enter] %s\n", name);
    fflush (stdout);
}

void PIN_FAST_ANALYSIS_CALL print_function_name_and_params (char* name, uint32_t arg1)
{
#ifdef EXTRA_DEBUG
    if (*ppthread_log_clock < EXTRA_DEBUG) return;
#endif
#ifdef EXTRA_DEBUG_STOP
    if (*ppthread_log_clock >= EXTRA_DEBUG_STOP) return;
#endif
    printf ("[CODE] %s\n", (char*)arg1);
}


void before_pthread_replay (ADDRINT rtn_addr, ADDRINT type, ADDRINT check)
{
    //fprintf (stderr, "[DEBUG] before pthread_replay for %d, type %u, check %u, clock %lu\n", current_thread->record_pid, type, check, *ppthread_log_clock);
}

void after_pthread_replay (ADDRINT ret) 
{
    //fprintf (stderr, "[DEBUG] after pthread_replay for %d, ret %d, clock %lu\n", current_thread->record_pid, ret, *ppthread_log_clock);
    if (current_thread != previous_thread) { 
        //well, a thread switch happens and this thread now executes
        //previous thread needs to sleep and wakes up this thread
        slice_thread_wakeup (previous_thread, current_thread->record_pid);
        slice_thread_wait (previous_thread);

        previous_thread = current_thread;
    }
}

#if 0
void before_malloc (ADDRINT bytes)
{
    OUTPUT_TAINT_INFO_THREAD (current_thread, "_libc_malloc thread %d clock %lu bytes %d", current_thread->record_pid, *ppthread_log_clock, bytes);
}

void after_malloc (ADDRINT ret) 
{
    OUTPUT_TAINT_INFO_THREAD (current_thread, "_libc_malloc thread %d clock %lu reutrns 0x%x", current_thread->record_pid, *ppthread_log_clock, ret);
}

void before_int_malloc (ADDRINT av, ADDRINT bytes)
{
    OUTPUT_TAINT_INFO_THREAD (current_thread, "_int_malloc thread %d clock %lu av %x bytes %d", current_thread->record_pid, *ppthread_log_clock, av, bytes);
}

void after_int_malloc (ADDRINT ret) 
{
    OUTPUT_TAINT_INFO_THREAD (current_thread, "_int_malloc thread %d clock %lu reutrns 0x%x", current_thread->record_pid, *ppthread_log_clock, ret);
}
#endif

void untracked_pthread_function (ADDRINT name) 
{
    fprintf (stderr, "untracked pthread operation %s, record pid %d\n", (char*) name, current_thread->record_pid);
}

//TODO: I think this could be super slow; it may be faster to hash the string and use switch statements 
void routine (RTN rtn, VOID* v)
{ 
    const char *name = RTN_Name(rtn).c_str();
#ifdef EXTRA_DEBUG_FUNCTION
    RTN_Open(rtn);
    RTN_InsertCall (rtn, IPOINT_BEFORE, (AFUNPTR) print_function_name, 
            IARG_FAST_ANALYSIS_CALL, 
            IARG_PTR, strdup (name), 
            IARG_END);
#if 0
    if (strcmp(name, "_ZN11CodeletMarkC2ERP25InterpreterMacroAssemblerPKcN9Bytecodes4CodeE") == 0)
    {
        RTN_InsertCall (rtn, IPOINT_BEFORE, (AFUNPTR) print_function_name_and_params,
                IARG_FAST_ANALYSIS_CALL, 
                IARG_PTR, strdup (name), 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_END);
    }
#endif
    RTN_Close(rtn);
#endif
    //some pthread_replay/record functions have two definitions, one in libc and the other in libpthread; makes pin and me confused for a while...
    if (IMG_Name(IMG_FindByAddress(RTN_Address(rtn))).find("libpthread") == string::npos) {
        return;
    }
    if (!strcmp (name, "pthread_log_replay")) {
        RTN_Open(rtn);
#if 0
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)before_pthread_replay,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_END);
#endif
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)after_pthread_replay,
                IARG_FUNCRET_EXITPOINT_VALUE,  
                IARG_END);
        RTN_Close(rtn);
    } else if (!strncmp (name, "pthread_", 8) || !strncmp (name, "__pthread_", 10) || !strncmp (name, "lll_", 4) || strstr (name, "_sem_")) {
        RTN_Open(rtn);
        if (!strcmp (name, "__pthread_mutex_lock") || !strcmp (name, "pthread_mutex_lock")) {
	    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_pthread_mutex_lock, 
                           IARG_FUNCRET_EXITPOINT_VALUE,
                           IARG_ADDRINT, 0,
			    IARG_END);
            pthread_operation_addr["pthread_mutex_lock"] = RTN_Address(rtn);
        } else if (!strcmp (name, "pthread_log_mutex_lock")) {
	    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_pthread_mutex_lock, 
                           IARG_ADDRINT, 0,
                           IARG_ADDRINT, 1,
			    IARG_END);
            pthread_operation_addr["pthread_log_mutex_lock"] = RTN_Address(rtn);
        } else if (!strcmp (name, "__pthread_mutex_trylock") || !strcmp (name, "pthread_mutex_trylock")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_pthread_mutex_trylock, 
                           IARG_FUNCRET_EXITPOINT_VALUE,
                           IARG_ADDRINT, 0,
                           IARG_END);
            pthread_operation_addr["pthread_mutex_trylock"] = RTN_Address(rtn);
        } else if (!strcmp (name, "pthread_log_mutex_trylock")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_pthread_mutex_trylock, 
                           IARG_FUNCRET_EXITPOINT_VALUE,
                           IARG_ADDRINT, 1,
			    IARG_END);
            pthread_operation_addr["pthread_log_mutex_trylock"] = RTN_Address(rtn);
        } else if (!strcmp (name, "pthread_log_mutex_unlock") || !strcmp (name, "__pthread_mutex_unlock") || !strcmp (name, "pthread_mutex_unlock")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_pthread_mutex_unlock, 
                           IARG_ADDRINT, 0,
			    IARG_END);
        } else if (!strcmp (name, "pthread_mutex_destroy")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_pthread_mutex_destroy, 
                           IARG_FUNCRET_EXITPOINT_VALUE,
			    IARG_END);
        } else if (!strcmp (name, "pthread_cond_timedwait")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_cond_timedwait_before,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_pthread_cond_timedwait_after, 
                    IARG_ADDRINT, RTN_Address(rtn), 
                    IARG_END);
            pthread_operation_addr["pthread_cond_timedwait"] = RTN_Address(rtn);
        } else if (!strcmp (name, "pthread_cond_wait")) { //it will shared the same tracking function with cond_timedwait
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_cond_timedwait_before,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_ADDRINT, UINT_MAX, //a value won't be used
                    IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_pthread_cond_timedwait_after, 
                    IARG_ADDRINT, RTN_Address(rtn), 
                    IARG_END);
            pthread_operation_addr["pthread_cond_wait"] = RTN_Address(rtn);
        } else if (!strcmp (name, "pthread_log_lll_wait_tid")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_lll_wait_tid_before,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_pthread_lll_wait_tid_after, 
                    IARG_ADDRINT, RTN_Address(rtn), 
                    IARG_END);
            pthread_operation_addr["pthread_log_lll_wait_tid"] = RTN_Address(rtn);
        } else if (!strcmp (name, "pthread_log_lll_lock")) { 
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_lll_lock_before,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_lll_lock_after, 
                    IARG_END);
            pthread_operation_addr["pthread_log_lll_lock"] = RTN_Address(rtn);
        } else if (!strcmp (name, "pthread_log_lll_unlock")) { 
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_lll_lock_before,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_lll_unlock_after, 
                    IARG_END);
        } else if (!strcmp (name, "__pthread_rwlock_wrlock") || !strcmp (name, "pthread_rwlock_wrlock")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_rwlock_wrlock, 
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);
            pthread_operation_addr["pthread_rwlock_wrlock"] = RTN_Address(rtn);
        } else if (!strcmp (name, "__pthread_rwlock_rdlock") || !strcmp (name, "pthread_rwlock_rdlock")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_rwlock_rdlock, 
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);
            pthread_operation_addr["pthread_rwlock_rdlock"] = RTN_Address(rtn);
        } else if (!strcmp (name, "__pthread_rwlock_unlock") || !strcmp (name, "pthread_rwlock_unlock")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_rwlock_unlock, 
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);
        } else if (!strcmp (name, "pthread_rwlock_destroy")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)track_pthread_mutex_params_1,
			   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			   IARG_END);
            RTN_InsertCall (rtn, IPOINT_AFTER, (AFUNPTR) track_rwlock_destroy,
                           IARG_FUNCRET_EXITPOINT_VALUE,
			    IARG_END);
#ifndef OPTIMIZED
        } else if (!strcmp (name, "pthread_create") || 
		   !strcmp (name, "pthread_equal") ||
		   !strcmp (name, "pthread_log_full") ||
		   !strcmp (name, "pthread_log_stat") || 
		   !strcmp (name, "pthread_log_alloc") || 
		   !strcmp (name, "pthread_log_debug") || 
		   !strcmp (name, "pthread_log_block") || 
		   !strcmp (name, "pthread_sysign") ||
		   !strcmp (name+strlen(name)-4, "_rep") ||
		   !strcmp (name, "__pthread_initialize_minimal") || 
		   !strcmp (name, "pthread_getspecific") || 
		   !strcmp (name, "__pthread_getspecific") || 
		   !strcmp (name, "__pthread_setspecific") ||
		   !strcmp (name, "pthread_self") ||
		   !strncmp (name, "pthread_mutexattr", 17) || 
		   !strncmp (name, "__pthread_mutexattr", 19) || 
		   !strncmp (name, "pthread_attr", 12)  || 
		   !strcmp (name, "__pthread_mutex_init") || 
		   !strcmp (name, "pthread_rwlock_init") ||
		   !strcmp (name, "__pthread_once") || 
		   !strcmp (name, "pthread_once") || 
		   !strcmp (name, "pthread_sigmask") || 
		   !strcmp (name, "pthread_self") || 
		   !strcmp (name, "pthread_getattr_np") || 
		   !strcmp (name, "pthread_getaffinity_np") || 
		   !strcmp (name, "__pthread_key_create") ||
		   !strcmp (name, "pthread_cond_init") || 
		   !strncmp (name, "pthread_condattr", 16) || 
		   !strcmp (name, "pthread_cond_broadcast") || 
		   !strcmp (name, "pthread_cond_signal") || 
		   !strcmp (name, "pthread_cond_destroy") || 
                   !strcmp (name, "__pthread_once_internal") ||
		   !strcmp (name, "__pthread_register_cancel") || 
		   !strcmp (name, "__pthread_unregister_cancel") || 
		   !strcmp (name, "__pthread_enable_asynccancel") || 
		   !strcmp (name, "__pthread_disable_asynccancel")) {
            printf ("ignored pthread operation %s\n", name);
        } else {
            RTN_InsertCall (rtn, IPOINT_BEFORE, (AFUNPTR) untracked_pthread_function, 
			    IARG_PTR, name, 
			    IARG_END);
#endif
        }
        RTN_Close(rtn);
    }
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

int get_open_file_descriptors ()
{
    struct open_fd ofds[4096];
    long rc = get_open_fds (dev_fd, ofds, 4096);
    if (rc < 0) {
	fprintf (stderr, "get_open_file_desciptors returns %ld\n", rc);
	return rc;
    }

    for (long i = 0; i < rc; i++) {
	if (ofds[i].type == OPEN_FD_TYPE_FILE) {
	    struct open_info* oi = (struct open_info *) malloc (sizeof(struct open_info));
	    strcpy (oi->name, ofds[i].channel);
	    oi->flags = 0;
	    oi->fileno = 0;
	    monitor_add_fd(open_fds, ofds[i].fd, 0, oi);
	} else if (ofds[i].type == OPEN_FD_TYPE_SOCKET) {
	    struct socket_info* si = (struct socket_info *) malloc (sizeof(struct socket_info));
	    si->domain = ofds[i].data;
	    si->type = -1;
	    si->protocol = -1;
	    si->fileno = -1; 
	    si->ci = NULL;
	    monitor_add_fd(open_socks, ofds[i].fd, 0, si);
	}
    }
    return 0;
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
        if (errno != EEXIST) {
            fprintf(stderr, "could not make directory %s\n", group_directory);
            exit(-1);
        }
    }
#endif

    // Read in command line args
    print_all_opened_files = KnobRecordOpenedFiles.Value();
    function_level_tracking = KnobFunctionLevel.Value();
    filter_read_filename = KnobFilterReadFile.Value().c_str();
    segment_length = KnobSegmentLength.Value();
    splice_output = KnobSpliceOutput.Value();
    all_output = KnobAllOutput.Value();
    fork_flags = KnobForkFlags.Value().c_str();
    checkpoint_clock = KnobCheckpointClock.Value();
    if (checkpoint_clock == 0) 
	    checkpoint_clock = UINT_MAX;
    recheck_group = KnobRecheckGroup.Value();
    check_filename = KnobCheckFilename.Value().c_str();

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

    init_taint_structures(group_directory, check_filename);

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

    init_mmap_region ();

    PIN_AddSyscallExitFunction(instrument_syscall_ret, 0);
    RTN_AddInstrumentFunction (routine, 0);
    PIN_SetSyntaxIntel();
    PIN_StartProgram();

    return 0;
}
