#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <syscall.h>
#include "util.h"
#include <sys/wait.h>
#include <sys/time.h>
#include <iostream>
#include <unordered_set>
#include <unordered_map>
using namespace std;

#include "mmap_regions.h"

//#define DPRINT printf
#define DPRINT(x,...) 

struct cf_diverge {
    u_long divergence;
    u_long merge;
    bool orig_taken;
    bool orig_branch;
    bool alt_branch;
};

/* Globals */
struct thread_data* current_thread; // Always points to thread-local data (changed by kernel on context switch)
unsigned long print_stop = 100000000;
unsigned int inst_start = 0;
int child = 0;
int fd; // File descriptor for the replay device
TLS_KEY tls_key; // Key for accessing TLS. 
unordered_map<u_long, struct cf_diverge> divergences;
unordered_set<u_long> merges;
u_long need_merge = 0;

KNOB<string> KnobPrintStop(KNOB_MODE_WRITEONCE, "pintool", "s", "1000000000", "clock to stop");
KNOB<unsigned int> KnobInstStart(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "start at this instruction");
KNOB<string> KnobChecksFile(KNOB_MODE_WRITEONCE, "pintool", "c", "", "checks file");

u_long* ppthread_log_clock = NULL; //clock value

struct ctrl_flow_info { 
    uint64_t count;
    uint32_t bbl_addr;
    u_long last_clock;
};

struct thread_data {
    u_long app_syscall;     // Per thread address for specifying pin vs. non-pin system calls
    u_long app_syscall_chk; // Per thread address for helping disambiguate pin vs. non-pin system calls with same app_sycall
    int    record_pid; 	    // per thread record pid
    int    syscall_cnt;	    // per thread count of syscalls
    int    sysnum;	    // current syscall number
    u_long ignore_flag;
    int    len, prot, flags; // For mmap region info
    struct ctrl_flow_info  ctrl_flow_info;
};

int get_record_pid(void);

static int terminated = 0;
//In here we need to mess with stuff for if we are no longer following this process
static int trace_done ()
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
    return 1; //we are the one that acutally did the dift done
}

void syscall_start(struct thread_data* tdata, int sysnum, ADDRINT syscallarg0, ADDRINT syscallarg1,
		   ADDRINT syscallarg2, ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{ 
    switch (sysnum) {
        case SYS_mmap:
        case SYS_mmap2:
	    tdata->len = syscallarg1;
	    tdata->prot = syscallarg2;
	    tdata->flags = syscallarg4;
	    tdata->app_syscall_chk = tdata->len + tdata->prot; // Pin sometimes makes mmaps during mmap
	    break;
        case SYS_munmap:
            delete_mmap_region ((u_long)syscallarg0, (int)syscallarg1);
            break;
        case SYS_mprotect:
            change_mmap_region ((u_long)syscallarg0, (int)syscallarg1, (int)syscallarg2);
            break;
    }
}

void syscall_end(int sysnum, ADDRINT retval)
{
    int rc = retval;
    switch(sysnum) {
        case SYS_mmap:
        case SYS_mmap2:
	    if (rc > 0 || rc < -1024) {
		add_mmap_region (rc, current_thread->len, current_thread->prot, current_thread->flags);
	    }
            break;
    }
}

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
		current_thread->syscall_cnt++;
	    }
	} else {
	    current_thread->syscall_cnt++;
	}
    }

    if (*ppthread_log_clock > print_stop) { 
        int calling_dd = trace_done ();
        while (!calling_dd || is_pin_attaching(fd)) {
		usleep (1000);
	}
	try_to_exit(fd, PIN_GetPid());
	PIN_ExitApplication(0); 
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

    ADDRINT ret_value = PIN_GetSyscallReturn(ctxt, std);
    if (*ppthread_log_clock <= print_stop) { 
	syscall_end(current_thread->sysnum, ret_value);
    }

    increment_syscall_cnt(current_thread, current_thread->sysnum);
    // reset the syscall number after returning from system call
    current_thread->sysnum = 0;
    increment_syscall_cnt(current_thread, current_thread->sysnum);
}

// called before every application system call
void set_address_one(ADDRINT syscall_num, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2,
		     ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata != current_thread) printf ("sao: tdata %p current_thread %p\n", tdata, current_thread);
    if (tdata) {
	int sysnum = (int) syscall_num;
	
	//printf ("%lu Pid %d, tid %d, (record pid %d), %d: syscall num is %d\n", *ppthread_log_clock, PIN_GetPid(), PIN_GetTid(), tdata->record_pid, tdata->syscall_cnt, (int) syscall_num);

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

#define TAINTSIGN void PIN_FAST_ANALYSIS_CALL
TAINTSIGN monitor_control_flow_head (ADDRINT ip)
{
    ++ current_thread->ctrl_flow_info.count;
    DPRINT ("New basic block at %x: %lld\n", ip, current_thread->ctrl_flow_info.count);
    if (*ppthread_log_clock != current_thread->ctrl_flow_info.last_clock) {
        current_thread->ctrl_flow_info.last_clock = *ppthread_log_clock;
        current_thread->ctrl_flow_info.count = 0;
    }
}

TAINTSIGN monitor_stutter (ADDRINT ip)
{
    printf ("[STUTTER]0x%x #%llu,%lu (clock)\n", ip, current_thread->ctrl_flow_info.count, *ppthread_log_clock);
}

TAINTSIGN monitor_read (ADDRINT ip, ADDRINT ea, UINT32 len)
{
    printf ("[READ]0x%x, 0x%x, #%llu,%lu (clock), ro %d\n", ip, ea, current_thread->ctrl_flow_info.count, *ppthread_log_clock, is_readonly (ea, len));
}

TAINTSIGN monitor_read2 (ADDRINT ip, ADDRINT ea, ADDRINT ea2, UINT32 len)
{
    printf ("[READ2]0x%x, 0x%x, #%llu,%lu (clock), ro %d\n", ip, ea2, current_thread->ctrl_flow_info.count, *ppthread_log_clock, is_readonly (ea, len));
}

TAINTSIGN monitor_write (ADDRINT ip, ADDRINT ea)
{
    printf ("[WRITE]0x%x, 0x%x, #%llu,%lu (clock)\n", ip, ea, current_thread->ctrl_flow_info.count, *ppthread_log_clock);
}

TAINTSIGN monitor_cf_merge (ADDRINT ip, BOOL taken)
{
    if (ip == need_merge) {
	printf ("[MERGE]0x%x, #%llu,%lu (clock)\n", ip, current_thread->ctrl_flow_info.count, *ppthread_log_clock);
	need_merge = 0;
    }
}

TAINTSIGN monitor_cf_diverge (ADDRINT ip, BOOL taken, UINT32 merge, BOOL is_loop, BOOL taken_has_insts)
{
    //printf ("taken_has_insts %d taken %d\n", taken_has_insts, taken);
    bool is_null_branch = is_loop && ((taken_has_insts && !taken) || (!taken_has_insts && taken));
    printf ("[DIVERGE]0x%x branch %d, #%llu,%lu (clock) merge %x loop %d null branch %d\n", ip, taken, current_thread->ctrl_flow_info.count, *ppthread_log_clock, merge, is_loop, is_null_branch);
    if (!is_null_branch) need_merge = merge;
}

#ifdef EXTRA_DEBUG
TAINTSIGN jnf_debug_r (ADDRINT ip, char* ins, u_long mem_loc, u_long mem_size, ADDRINT eax_val, ADDRINT ecx_val, ADDRINT edx_val) 
{
    if (*ppthread_log_clock == 5130 && current_thread->ctrl_flow_info.count < 20000) {
	printf ("[DEBUG] ip %x %s clock %ld bb %lld: mem read 0x%lx has value 0x%lx, eax 0x%x, ecx 0x%x edx 0x%x\n", 
		ip, ins, *ppthread_log_clock, current_thread->ctrl_flow_info.count, mem_loc, *((u_long *) mem_loc), eax_val, ecx_val, edx_val);
    }
}

TAINTSIGN jnf_debug_w (ADDRINT ip, char* ins, u_long mem_loc, u_long mem_size, ADDRINT eax_val, ADDRINT ecx_val, ADDRINT edx_val) 
{
    if (*ppthread_log_clock == 5130 && current_thread->ctrl_flow_info.count < 20000) {
	printf ("[DEBUG] ip %x %s clock %ld bb %lld: mem write 0x%lx has value 0x%lx, eax 0x%x, ecx 0x%x edx 0x%x\n", 
		ip, ins, *ppthread_log_clock, current_thread->ctrl_flow_info.count, mem_loc, *((u_long *) mem_loc), eax_val, ecx_val, edx_val);
    }
}

static inline char* get_copy_of_disasm (INS ins) { 
	const char* tmp = INS_Disassemble (ins).c_str();
	char* str = NULL;
	assert (tmp != NULL);
	str = (char*) malloc (strlen (tmp) + 1);
	assert (str != NULL);
	strcpy (str, tmp);
	return str;
}
#endif

void track_trace(TRACE trace, void* data)
{
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        INS head = BBL_InsHead (bbl);
        INS_InsertCall (head, IPOINT_BEFORE, (AFUNPTR) monitor_control_flow_head, 
			IARG_FAST_ANALYSIS_CALL, 
			IARG_INST_PTR,
			IARG_END);

	for (INS ins = head; INS_Valid(ins); ins = INS_Next(ins)) {
#ifdef EXTRA_DEBUG
	    char* str = get_copy_of_disasm (ins);
	    if (INS_IsMemoryRead(ins)) {
		INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(jnf_debug_r),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR, 
				IARG_PTR, str, 
				IARG_MEMORYREAD_EA,
				IARG_MEMORYREAD_SIZE,
				IARG_REG_VALUE, LEVEL_BASE::REG_EAX, 			
				IARG_REG_VALUE, LEVEL_BASE::REG_ECX, 			
				IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
				IARG_END);
	    } else if (INS_IsMemoryWrite(ins)) {
		INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(jnf_debug_w),
				IARG_FAST_ANALYSIS_CALL,
				IARG_INST_PTR, 
				IARG_PTR, str, 
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE,
				IARG_REG_VALUE, LEVEL_BASE::REG_EAX, 			
				IARG_REG_VALUE, LEVEL_BASE::REG_ECX, 			
				IARG_REG_VALUE, LEVEL_BASE::REG_EDX, 			
				IARG_END);
	    }
#endif
	    if (INS_Address(ins) == inst_start) {
		if (INS_IsMemoryRead(ins)) {
		    if (INS_HasMemoryRead2(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(monitor_read2), 
				       IARG_FAST_ANALYSIS_CALL,
				       IARG_INST_PTR, 
				       IARG_MEMORYREAD_EA,
				       IARG_MEMORYREAD2_EA,
				       IARG_MEMORYREAD_SIZE,
				       IARG_END);
		    } else {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(monitor_read), 
				       IARG_FAST_ANALYSIS_CALL,
				       IARG_INST_PTR, 
				       IARG_MEMORYREAD_EA,
				       IARG_MEMORYREAD_SIZE,
				       IARG_END);
		    }
		} else if (INS_IsMemoryWrite(ins)) {
		    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(monitor_write), 
				   IARG_FAST_ANALYSIS_CALL,
				   IARG_INST_PTR, 
				   IARG_MEMORYWRITE_EA,
				   IARG_END);
		}

	    }
	    if (INS_Stutters(ins)) {
		INS_InsertCall (ins, IPOINT_BEFORE, AFUNPTR(monitor_stutter),
				IARG_INST_PTR, 
				IARG_END);

	    }
	    if (merges.find(INS_Address(ins)) != merges.end()) {
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(monitor_cf_merge),
			       IARG_FAST_ANALYSIS_CALL,
			       IARG_INST_PTR,
			       IARG_BRANCH_TAKEN,
			       IARG_END);
	    }
	    auto iter = divergences.find(INS_Address(ins));
	    if (iter != divergences.end()) {
		struct cf_diverge cfd = iter->second;
		bool is_loop = false;
		bool taken_has_insts = false;
		if (cfd.merge == cfd.divergence) {
		    is_loop = true;
		    taken_has_insts = false;
		    //printf ("Instruction %x orig taken %d orig branch %d alt branch %d\n", INS_Address(ins), cfd.orig_taken, cfd.orig_branch, cfd.alt_branch);
		    if (cfd.orig_taken && cfd.orig_branch) {
			taken_has_insts = true;
		    } 
		    if (!cfd.orig_taken && cfd.alt_branch) {
			taken_has_insts = true;
		    }
		}
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(monitor_cf_diverge),
			       IARG_FAST_ANALYSIS_CALL,
			       IARG_INST_PTR,
			       IARG_BRANCH_TAKEN,
			       IARG_UINT32, cfd.merge,
			       IARG_BOOL, is_loop,
			       IARG_BOOL, taken_has_insts,
			       IARG_END);
	    }
	    if (INS_IsSyscall(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(set_address_one), 
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

#if 0
void before_function_call(ADDRINT name, ADDRINT rtn_addr, ADDRINT arg0)
{
    if (tracing) {
	if (inst_start) {
	    if (subroutine == "") {
		//printf("Before call to %s (%#x)\n", (char *) name, rtn_addr);
		subroutine = (char *) name;
	    }
	}
    }
}

void after_function_call(ADDRINT name, ADDRINT rtn_addr, ADDRINT ret)
{
    if (tracing) {
	if (inst_start) {
	    if (subroutine != "") {
		if (subroutine == (char *) name) {
		    //printf("After call to %s (%#x)\n", (char *) name, rtn_addr);
		    subroutine = "";
		}
	    } else {
		printf("[END] bbl trace - function return\n");
		tracing = 0;
	    }
	}
    }
}

void routine (RTN rtn, VOID *v)
{
    const char *name;

    name = RTN_Name(rtn).c_str();

    RTN_Open(rtn);

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)before_function_call,
		   IARG_PTR, name, 
		   IARG_ADDRINT, RTN_Address(rtn), 
		   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)after_function_call,
		   IARG_PTR, name, IARG_ADDRINT, RTN_Address(rtn), 
		   IARG_FUNCRET_EXITPOINT_VALUE,  
		   IARG_END);

    RTN_Close(rtn);
}
#endif

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
    ptdata->ctrl_flow_info.count = 0;
    ptdata->ctrl_flow_info.bbl_addr = 0;
    ptdata->ctrl_flow_info.last_clock = 0;

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
    //free resources in thread_data if necessary
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    printf("Pid %d (recpid %d, tid %d) thread fini\n", PIN_GetPid(), ptdata->record_pid, PIN_GetTid());
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

    // Read in knob parameters
    print_stop = atoi(KnobPrintStop.Value().c_str());
    inst_start = KnobInstStart.Value();

    string checks_file = KnobChecksFile.Value();
    struct cf_diverge cfd;
    if (checks_file != "") {
	FILE* file = fopen (checks_file.c_str(), "r");
	while (!feof(file)) {
	    char line[256];
	    if (fgets (line, sizeof(line), file)) {
		if (strstr (line, "ctrl_diverge")) {
		    char* p = strstr (line, " ");
		    if (p) {
			*p = '\0';
			p++;
			cfd.divergence = strtoul(line, 0, 16);
			char* ptaken;
			ptaken = strstr (p, "orig_branch");
			if (ptaken) {
			    ptaken += 12;
			    cfd.orig_taken = (*ptaken == 't');
			    DPRINT ("addr %lx orig_branch %c taken %d\n", cfd.divergence, *ptaken, cfd.orig_taken);
			} else {
			    fprintf (stderr, "malformed diverge line: %s", p);
			    return -1;
			}
			cfd.orig_branch = cfd.alt_branch = false;
		    }
		} else if (strstr (line, "ctrl_merge")) {
		    char* p = strstr (line, " ");
		    if (p) {
			*p = '\0';
			u_long merge = strtoul(line, 0, 16); 
			cfd.merge = merge;
			divergences[cfd.divergence] = cfd;
			merges.insert(merge);
		    }
		} else if (strstr (line, "ctrl_block_instrument_alt")) {
		    cfd.alt_branch = true;
		} else if (strstr (line, "ctrl_block_instrument_orig")) {
		    cfd.orig_branch = true;
		}
	    }
	}
	fclose (file);
    }

    ppthread_log_clock = map_shared_clock(fd);
    
    PIN_AddThreadStartFunction(thread_start, 0);
    PIN_AddThreadFiniFunction(thread_fini, 0);
    PIN_AddFollowChildProcessFunction(follow_child, argv);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
    TRACE_AddInstrumentFunction (track_trace, 0);
    PIN_AddSyscallExitFunction(inst_syscall_end, 0);
    init_mmap_region ();
    PIN_StartProgram();

    return 0;
}
