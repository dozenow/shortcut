#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <syscall.h>
#include "util.h"
#include <sys/wait.h>
#include <sys/time.h>
#include <iostream>

#define COMPACT

#define OP_CALL             0
#define OP_RETURN           1
#define OP_SYSCALL          2
#define OP_RELREAD          3
#define OP_RELWRITE         4
#define OP_RELREAD2         5
#define OP_BRANCH_TAKEN     6
#define OP_BRANCH_NOT_TAKEN 7
#define OP_JMP_INDIRECT     8

struct thread_data* current_thread; // Always points to thread-local data (changed by kernel on context switch)
u_long print_stop = 1000000;
u_long* ppthread_log_clock = NULL;

KNOB<string> KnobPrintStop(KNOB_MODE_WRITEONCE, "pintool", "s", "10000000", "syscall print stop");
#ifdef COMPACT
KNOB<string> KnobFilename(KNOB_MODE_WRITEONCE, "pintool", "f", "/tmp/bb.out", "output filename");
#endif

long global_syscall_cnt = 0;
/* Toggle between which syscall count to use */
#define SYSCALL_CNT tdata->syscall_cnt
// #define SYSCALL_CNT global_syscall_cnt

#ifdef COMPACT
#define BUF_SIZE 256*1024
u_long buffer[BUF_SIZE];
u_long buf_cnt = 0;
int buf_fd = -1;

static int init_buffer (const char* filename) 
{
    buf_fd = open (filename, O_CREAT | O_TRUNC | O_WRONLY | O_LARGEFILE, 0644);
    if (buf_fd < 0) {
	fprintf (stderr, "Cannot open %s\n", filename);
	return buf_fd;
    }
    return 0;
}

static void flush_buffer ()
{
    long rc = write (buf_fd, buffer, buf_cnt*sizeof(u_long));
    if (rc != (long) (buf_cnt*sizeof(u_long))) {
	fprintf (stderr, "Cannot write to buffer, rc=%ld not %ld\n", rc, buf_cnt*sizeof(u_long));
	exit (0);
    }
    buf_cnt = 0;
}

static inline void write_to_buffer (u_long val)
{
    buffer[buf_cnt++] = val;
    if (buf_cnt == BUF_SIZE) {
	flush_buffer ();
    }
}

#endif

struct thread_data {
    u_long app_syscall;     // Per thread address for specifying pin vs. non-pin system calls
    u_long app_syscall_chk; // Per thread address for helping disambiguate pin vs. non-pin system calls with same app_sycall
    int    record_pid; 	    // per thread record pid
    int    syscall_cnt;	    // per thread count of syscalls
    int    sysnum;	    // current syscall number
    u_long ignore_flag;
};

int child = 0;

int fd; // File descriptor for the replay device
TLS_KEY tls_key; // Key for accessing TLS. 

int get_record_pid(void);

inline void increment_syscall_cnt (struct thread_data* ptdata, int syscall_num)
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
    }
}

void inst_syscall_end(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata != current_thread) printf ("tdata %p current_thread %p\n", tdata, current_thread);

    if (current_thread) {
	if (current_thread->app_syscall != 999) current_thread->app_syscall = 0;
    } else {
	fprintf (stderr, "inst_syscall_end: NULL current_thread\n");
    }	

    increment_syscall_cnt(current_thread, current_thread->sysnum);
    // reset the syscall number after returning from system call
    current_thread->sysnum = 0;
    increment_syscall_cnt(current_thread, current_thread->sysnum);
}

static void sys_mmap_start(struct thread_data* tdata, u_long addr, int len, int prot, int fd)
{
    tdata->app_syscall_chk = len + prot; // Pin sometimes makes mmaps during mmap
}

void syscall_start(struct thread_data* tdata, int sysnum, ADDRINT syscallarg0, ADDRINT syscallarg1,
		   ADDRINT syscallarg2, ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{
    switch (sysnum) {
        case SYS_mmap:
        case SYS_mmap2:
            sys_mmap_start(tdata, (u_long)syscallarg0, (int)syscallarg1, (int)syscallarg2, (int)syscallarg4);
            break;
    }
}

// called before every application system call
void PIN_FAST_ANALYSIS_CALL set_address_one(ADDRINT syscall_num, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2,
					    ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata != current_thread) printf ("sao: tdata %p current_thread %p\n", tdata, current_thread);
    if (tdata) {
	int sysnum = (int) syscall_num;

#ifdef COMPACT
	write_to_buffer (OP_SYSCALL);
	write_to_buffer (*ppthread_log_clock);
#else	
	printf ("%ld Pid %d, tid %d, (record pid %d), %d: syscall num is %d\n", global_syscall_cnt, PIN_GetPid(), PIN_GetTid(), tdata->record_pid, tdata->syscall_cnt, (int) syscall_num);
	fflush (stdout);
#endif

	if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	    check_clock_before_syscall (fd, (int) syscall_num);
	}
	tdata->app_syscall = syscall_num;
	tdata->sysnum = syscall_num;
    } else {
	fprintf (stderr, "set_address_one: NULL current_thread\n");
    }

    syscall_start(tdata, syscall_num, syscallarg0, syscallarg1, syscallarg2, 
		  syscallarg3, syscallarg4, syscallarg5);
}

void syscall_after (ADDRINT ip)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata != current_thread) printf ("sa: tdata %p current_thread %p\n", tdata, current_thread);
    if (current_thread) {
	if (current_thread->app_syscall == 999) {
	    if (check_clock_after_syscall (fd) == 0) {
	    } else {
		fprintf (stderr, "Check clock failed\n");
	    }
	    current_thread->app_syscall = 0;  
	}
    } else {
	fprintf (stderr, "syscall_after: NULL current_thread\n");
    }
    //Note: the checkpoint is always taken after a syscall and ppthread_log_clock should be the next expected clock
    if (*ppthread_log_clock >= print_stop) { 
#ifdef COMPACT
	flush_buffer();
#endif
        fprintf (stderr, "exit.\n");
        try_to_exit (fd, PIN_GetPid());
        PIN_ExitApplication(0);
    }
}

void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    int record_pid;
    if (tdata != current_thread) printf ("afic: tdata %p current_thread %p\n", tdata, current_thread);
    printf ("AfterForkInChild\n");
    record_pid = get_record_pid();
    printf ("get record id %d\n", record_pid);
    current_thread->record_pid = record_pid;

    // reset syscall index for thread
    current_thread->syscall_cnt = 0;
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

void PIN_FAST_ANALYSIS_CALL trace_bbl (ADDRINT ip)
{
#ifdef COMPACT
    write_to_buffer (ip);
#else
    printf ("%x   ", ip);
    PIN_LockClient();
    if (IMG_Valid(IMG_FindByAddress(ip))) {
	printf("%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));
    } else {
	printf("unknown\n");
    }
    PIN_UnlockClient();
#endif
}

void PIN_FAST_ANALYSIS_CALL trace_bbl_stutters (ADDRINT ip, uint32_t first_iter)
{
#ifdef COMPACT
    if (first_iter) write_to_buffer (ip);
#else
    printf ("%x   ", ip);
    PIN_LockClient();
    if (IMG_Valid(IMG_FindByAddress(ip))) {
	printf("%s -- img %s static %#x (stutters %d)\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip), first_iter);
    } else {
	printf("unknown\n");
    }
    PIN_UnlockClient();
#endif
}

#ifdef COMPACT
void PIN_FAST_ANALYSIS_CALL trace_relread (uint32_t memloc)
{
    write_to_buffer (OP_RELREAD);
    write_to_buffer (memloc);
}

void PIN_FAST_ANALYSIS_CALL trace_relwrite (uint32_t memloc)
{
    write_to_buffer (OP_RELWRITE);
    write_to_buffer (memloc);
}

void PIN_FAST_ANALYSIS_CALL trace_relread2 (uint32_t memloc)
{
    write_to_buffer (OP_RELREAD2);
    write_to_buffer (memloc);
}

void PIN_FAST_ANALYSIS_CALL trace_relread_stutters (uint32_t memloc, uint32_t first_iter)
{
    if (first_iter) {
	write_to_buffer (OP_RELREAD);
	write_to_buffer (memloc);
    }
}

void PIN_FAST_ANALYSIS_CALL trace_relwrite_stutters (uint32_t memloc, uint32_t first_iter)
{
    if (first_iter) {
	write_to_buffer (OP_RELWRITE);
	write_to_buffer (memloc);
    }
}

void PIN_FAST_ANALYSIS_CALL trace_relread2_stutters (uint32_t memloc, uint32_t first_iter)
{
    if (first_iter) {
	write_to_buffer (OP_RELREAD2);
	write_to_buffer (memloc);
    }
}

void PIN_FAST_ANALYSIS_CALL trace_branch (ADDRINT ip, uint32_t taken)
{
    write_to_buffer (taken ? OP_BRANCH_TAKEN : OP_BRANCH_NOT_TAKEN);
    write_to_buffer (ip);
}

void PIN_FAST_ANALYSIS_CALL trace_jmp_reg (ADDRINT ip, uint32_t value)
{
    write_to_buffer (OP_JMP_INDIRECT);
    write_to_buffer (ip);
    write_to_buffer (value);
}

void PIN_FAST_ANALYSIS_CALL trace_jmp_mem (ADDRINT ip, ADDRINT loc)
{
    write_to_buffer (OP_JMP_INDIRECT);
    write_to_buffer (ip);
    write_to_buffer (*((u_int *) loc));
}

#else
void PIN_FAST_ANALYSIS_CALL trace_relread (ADDRINT ip, uint32_t memloc)
{
    printf ("Instruction %x reads memory location %x\n", ip, memloc);
}

void PIN_FAST_ANALYSIS_CALL trace_relwrite (ADDRINT ip, uint32_t memloc)
{
    printf ("Instruction %x writes memory location %x\n", ip, memloc);
}

void PIN_FAST_ANALYSIS_CALL trace_relread2 (ADDRINT ip, uint32_t memloc)
{
    printf ("Instruction %x reads memory location %x\n", ip, memloc);
}

void PIN_FAST_ANALYSIS_CALL trace_branch (ADDRINT ip, uint32_t taken)
{
    printf ("Instruction %x branch taken=%d\n", ip, taken);
}

void trace_relread_stutters (ADDRINT ip, uint32_t memloc, uint32_t first_iter) 
{
    trace_relread(ip,memloc);
}

void trace_relwrite_stutters (ADDRINT ip, uint32_t memloc, uint32_t first_iter) 
{
    trace_relwrite(ip,memloc);
}

void trace_relread2_stutters (ADDRINT ip, uint32_t memloc, uint32_t first_iter) 
{
    trace_relread2(ip,memloc);
}
#endif


void track_trace(TRACE trace, void* data)
{
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
	if (INS_Stutters(BBL_InsHead(bbl))) {
	    BBL_InsertCall(bbl, IPOINT_BEFORE, AFUNPTR(trace_bbl_stutters), 
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR, 
			   IARG_FIRST_REP_ITERATION,
			   IARG_END);

	} else {
	    BBL_InsertCall(bbl, IPOINT_BEFORE, AFUNPTR(trace_bbl), 
			   IARG_FAST_ANALYSIS_CALL,
			   IARG_INST_PTR, 
			   IARG_END);
	}
	for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
	    if(INS_IsSyscall(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(set_address_one), 
			       IARG_FAST_ANALYSIS_CALL,
			       IARG_SYSCALL_NUMBER, 
			       IARG_SYSARG_VALUE, 0, 
			       IARG_SYSARG_VALUE, 1,
			       IARG_SYSARG_VALUE, 2,
			       IARG_SYSARG_VALUE, 3,
			       IARG_SYSARG_VALUE, 4,
			       IARG_SYSARG_VALUE, 5,
			       IARG_END);
	    }
	    if (INS_IsBranch(ins)) {
		if (INS_Opcode(ins) == XED_ICLASS_JMP) {
		    if (INS_IsIndirectBranchOrCall(ins)) {
			if (INS_OperandIsReg(ins, 0)) {
			    REG reg = INS_OperandReg(ins, 0);
			    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_jmp_reg), 
					   IARG_FAST_ANALYSIS_CALL,
					   IARG_INST_PTR,
					   IARG_REG_VALUE, reg,
					   IARG_END);
			} else {
			    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_jmp_mem), 
					   IARG_FAST_ANALYSIS_CALL,
					   IARG_INST_PTR,
					   IARG_MEMORYREAD_EA,
					   IARG_END);
			}
		    }
		} else {
		    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_branch), 
				   IARG_FAST_ANALYSIS_CALL,
				   IARG_INST_PTR,
				   IARG_BRANCH_TAKEN,
				   IARG_END);
		}
	    }
	    if (INS_MemoryBaseReg(ins) != LEVEL_BASE::REG_INVALID() || INS_MemoryIndexReg(ins) != LEVEL_BASE::REG_INVALID()) {
		if (INS_Stutters(BBL_InsHead(bbl))) {
		    if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relread_stutters), 
				       IARG_FAST_ANALYSIS_CALL,
#ifndef COMPACT				   
				       IARG_INST_PTR,
#endif
				       IARG_MEMORYREAD_EA,
				       IARG_FIRST_REP_ITERATION,
				       IARG_END);
			if (INS_HasMemoryRead2(ins)) {
			    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relread2_stutters), 
					   IARG_FAST_ANALYSIS_CALL,
#ifndef COMPACT				   
					   IARG_INST_PTR,
#endif
					   IARG_MEMORYREAD2_EA,
					   IARG_FIRST_REP_ITERATION,
					   IARG_END);
			}
		    }
		    if (INS_IsMemoryWrite(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relwrite_stutters), 
				       IARG_FAST_ANALYSIS_CALL,
#ifndef COMPACT				   
				       IARG_INST_PTR,
#endif
				       IARG_MEMORYWRITE_EA,
				       IARG_FIRST_REP_ITERATION,
				       IARG_END);
		    }
		} else {
		    if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relread), 
				       IARG_FAST_ANALYSIS_CALL,
#ifndef COMPACT				   
				       IARG_INST_PTR,
#endif
				       IARG_MEMORYREAD_EA,
				       IARG_END);
			if (INS_HasMemoryRead2(ins)) {
			    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relread2), 
					   IARG_FAST_ANALYSIS_CALL,
#ifndef COMPACT				   
					   IARG_INST_PTR,
#endif
					   IARG_MEMORYREAD2_EA,
					   IARG_END);
			}
		    }
		    if (INS_IsMemoryWrite(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relwrite), 
				       IARG_FAST_ANALYSIS_CALL,
#ifndef COMPACT				   
				       IARG_INST_PTR,
#endif
				       IARG_MEMORYWRITE_EA,
				       IARG_END);
		    }
		}
	    }
	}
    }
}

BOOL follow_child(CHILD_PROCESS child, void* data)
{
    char** argv;
    char** prev_argv = (char**)data;
    int index = 0;

    printf ("following child...\n");

    /* the format of pin command would be:
     * pin_binary -follow_execv -t pin_tool new_addr*/
    int new_argc = 5;
    argv = (char**)malloc(sizeof(char*) * new_argc);

    argv[0] = prev_argv[index++];
    argv[1] = (char *) "-follow_execv";
    while(strcmp(prev_argv[index], "-t")) index++;
    argv[2] = prev_argv[index++];
    argv[3] = prev_argv[index++];
    argv[4] = (char *) "--";

    CHILD_PROCESS_SetPinCommandLine(child, new_argc, argv);

    printf("returning from follow child\n");
    printf("pin my pid is %d\n", PIN_GetPid());
    printf("%d is application thread\n", PIN_IsApplicationThread());

    return TRUE;
}

#ifdef COMPACT
void PIN_FAST_ANALYSIS_CALL before_function_call (ADDRINT ip)
{
    write_to_buffer (OP_CALL);
    write_to_buffer (ip);
}

void PIN_FAST_ANALYSIS_CALL after_function_call ()
{
    write_to_buffer (OP_RETURN);
}
#else
void PIN_FAST_ANALYSIS_CALL before_function_call(ADDRINT name, ADDRINT rtn_addr)
{
    printf("Before call to %s (%#x)\n", (char *) name, rtn_addr);
}

void PIN_FAST_ANALYSIS_CALL after_function_call(ADDRINT name, ADDRINT rtn_addr)
{
    printf("After call to %s (%#x)\n", (char *) name, rtn_addr);
}
#endif

void routine (RTN rtn, VOID *v)
{
#ifndef COMPACT
    const char *name = RTN_Name(rtn).c_str();
#endif
    RTN_Open(rtn);

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)before_function_call,
		   IARG_FAST_ANALYSIS_CALL,
#ifdef COMPACT
		   IARG_INST_PTR,
#else
		   IARG_PTR, name, 
		   IARG_ADDRINT, RTN_Address(rtn), 
#endif
		   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)after_function_call,
		   IARG_FAST_ANALYSIS_CALL,
#ifndef COMPACT
		   IARG_PTR, name, 
		   IARG_ADDRINT, RTN_Address(rtn), 
#endif
		   IARG_END);

    RTN_Close(rtn);
}

int get_record_pid()
{
    //calling kernel for this replay thread's record log
    int record_log_id;

    record_log_id = get_log_id (fd);
    if (record_log_id == -1) {
        int pid = PIN_GetPid();
        fprintf(stderr, "Could not get the record pid from kernel, pid is %d\n", pid);
        return pid;
    }
    return record_log_id;
}

void thread_start (THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    struct thread_data* ptdata;

    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    assert (ptdata);
    ptdata->app_syscall = 0;
    ptdata->record_pid = get_record_pid();
    //   get_record_group_id(dev_fd, &(ptdata->rg_id));

    PIN_SetThreadData (tls_key, ptdata, threadid);

    int thread_ndx;
    long thread_status = set_pin_addr (fd, (u_long) &(ptdata->app_syscall), (u_long) &(ptdata->app_syscall_chk), 
				       ptdata, (void **) &current_thread, &thread_ndx);
    /*
     * DON'T PUT SYSCALLS ABOVE THIS POINT! 
     */

    if (thread_status < 2) {
	current_thread = ptdata;
    }
    //fprintf (stderr,"Thread %d gets rc %ld ndx %d from set_pin_addr\n", ptdata->record_pid, thread_status, thread_ndx);
}

void thread_fini (THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    struct thread_data* ptdata;
    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    printf("Pid %d (recpid %d, tid %d) thread fini\n", PIN_GetPid(), ptdata->record_pid, PIN_GetTid());
#ifdef COMPACT
    flush_buffer();
#endif
}

int main(int argc, char** argv) 
{    
    int rc;

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

    // Intialize the replay device
    rc = devspec_init (&fd);
    if (rc < 0) return rc;

    // Obtain a key for TLS storage
    tls_key = PIN_CreateThreadDataKey(0);

#ifdef COMPACT
    if (init_buffer (KnobFilename.Value().c_str()) < 0) return -1;
#endif

    print_stop = atoi(KnobPrintStop.Value().c_str());
    
    // Try to map the log clock for this epoch
    ppthread_log_clock = map_shared_clock(fd);
    if (ppthread_log_clock == NULL) return -1;

    PIN_AddThreadStartFunction(thread_start, 0);
    PIN_AddThreadFiniFunction(thread_fini, 0);
    PIN_AddFollowChildProcessFunction(follow_child, argv);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
    PIN_AddSyscallExitFunction(inst_syscall_end, 0);
    RTN_AddInstrumentFunction (routine, 0);
    TRACE_AddInstrumentFunction (track_trace, 0);
    PIN_StartProgram();

    return 0;
}
