// The log format here is still a bit chatty and the performance is disk-bound.
// We could implement a tighter encoding (1-byte opcodes), but gzip of the data
// on the fly is another option.

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
#include <map>
#include <unordered_set>
using namespace std;

#define DPRINT(...)
#define MYASSERT(c)
#define OP_CHECK(val) get_value()
//#define DPRINT printf
//#define MYASSERT assert
//#define OP_CHECK(val) { u_long lval = get_value(); if (lval != val) { printf ("Expected %lx got %d syscall %ld bb_cnt %ld\n", lval, val, *ppthread_log_clock, bb_cnt); assert (0); } }

#define OP_CALL             0
#define OP_RETURN           1
#define OP_SYSCALL          2
#define OP_RELREAD          3
#define OP_RELWRITE         4
#define OP_RELREAD2         5
#define OP_BRANCH_TAKEN     6
#define OP_BRANCH_NOT_TAKEN 7

struct thread_data* current_thread; // Always points to thread-local data (changed by kernel on context switch)
u_long print_stop = 1000000;
u_long* ppthread_log_clock = NULL;

KNOB<string> KnobPrintStop(KNOB_MODE_WRITEONCE, "pintool", "s", "10000000", "syscall print stop");
KNOB<string> KnobFilename(KNOB_MODE_WRITEONCE, "pintool", "f", "/tmp/bb.out", "output filename");

long global_syscall_cnt = 0;
/* Toggle between which syscall count to use */
#define SYSCALL_CNT tdata->syscall_cnt
// #define SYSCALL_CNT global_syscall_cnt

struct index_div {
    u_long addr;
    bool   is_write;
    u_long value;
};

#define BUF_SIZE 256*1024
u_long buffer[BUF_SIZE+4096], dev_buffer[BUF_SIZE+1024];
int logfd, ndx, bufsize, devndx, prev_ndx, deviation_ip, deviation_taken; 
map<u_long, struct index_div> indexes;
u_long prev_bb, bb_cnt = 0;
bool deviation;
bool debug_on;

static void print_results ()
{
    for (auto iter = indexes.begin(); iter != indexes.end(); ++iter) {
	printf ("0x%lx %s %lu\n", iter->second.addr, iter->second.is_write ? "rangev_write" : "rangev", 
		iter->second.value);
    }
}

static void get_values ()
{
    long rc = read (logfd, buffer, sizeof(buffer));
    if (rc < 0) {
	fprintf (stderr, "file read fails\n");
	exit (1);
    }
    if (rc == 0) {
	fprintf (stderr, "no more values in file\n");
	exit (1);
    }
    ndx = 0;
    bufsize = rc/sizeof(u_long);
}

static inline u_long get_value ()
{
    if (ndx == bufsize) get_values();
    return (buffer[ndx++]);
}

static inline u_long skip_to_end ()
{
    int skip_ndx = ndx;
    u_long val;

    DPRINT ("skip to end from ndx %d prev bb is %lu\n", ndx, prev_bb);
    do {
	if (skip_ndx >= bufsize-1) {
	    // Overflow
	    assert (bufsize <= BUF_SIZE+4096);
	    long rc = read(logfd, buffer+bufsize, 4096);
	    if (rc < 0) {
		fprintf (stderr, "oveflow: file read fails\n");
		exit (1);
	    }
	    if (rc == 0) {
		fprintf (stderr, "overflow: no more values in file\n");
		exit (1);
	    }
	    bufsize += rc/sizeof(u_long);
	}
	assert (skip_ndx < bufsize); // Eventually, will need to handle overflow
	val = buffer[skip_ndx];
	if (val >= OP_RELREAD && val <= OP_BRANCH_NOT_TAKEN) {
	    skip_ndx++; // Skip over memory logging
	}
	skip_ndx++;
    } while (val > 2 && val != prev_bb);
    DPRINT ("stop at ndx %d value %lu\n", skip_ndx, val);

    return (skip_ndx);
}


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
    if (tdata) {
	int sysnum = (int) syscall_num;

	u_long op = get_value();
	if (op != 2) {
	    fprintf (stderr, "Expected syscall, got value %lx\n", op);
	    exit (1);
	}
	
	u_long clock = get_value();
	if (clock != *ppthread_log_clock) {
	    fprintf (stderr, "Expected syscall clock %ld, got value %ld\n", *ppthread_log_clock, clock);
	}
	bb_cnt = 0;

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
    if (current_thread->app_syscall == 999) {
	if (check_clock_after_syscall (fd)) {
	    fprintf (stderr, "Check clock failed\n");
	}
	current_thread->app_syscall = 0;  
    }

    //Note: the checkpoint is always taken after a syscall and ppthread_log_clock should be the next expected clock
    if (*ppthread_log_clock >= print_stop) { 
        fprintf (stderr, "exit.\n");
	print_results();
        try_to_exit (fd, PIN_GetPid());
        PIN_ExitApplication(0);
    }
}

void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    int record_pid;
    if (tdata != current_thread) printf ("afic: tdata %p current_thread %p\n", tdata, current_thread);
    record_pid = get_record_pid();
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

static void extract_basic_blocks (u_long* buf, int end, bool is_devbuf, 
				  map<u_long,u_long>& bb, unordered_set<u_long>& splits)

{
    u_long start_bb;

    for (int i = 0; i < end; i++) {
	u_long val = buf[i];
	DPRINT ("%d: %lx\n", i, val);
	if (val >= OP_RELREAD && val <= OP_RELREAD2) {
	    DPRINT ("%d: %lx\n", i+1, buf[i+1]);
	    i++;
	    if (is_devbuf) {
		DPRINT ("%d: %lx\n", i+1, buf[i+1]);
		i++;
	    }
	} else if (val == OP_BRANCH_TAKEN || val == OP_BRANCH_NOT_TAKEN) {
	    u_long end_bb = buf[i+1];
	    DPRINT ("%d: %lx\n", i+1, end_bb);
	    DPRINT ("BB %lx-%lx\n", start_bb, end_bb);
	    auto iter = bb.find(end_bb);
	    if (iter == bb.end()) {
		bb[end_bb] = start_bb;
	    } else {
		DPRINT ("conflict\n");
		if (start_bb == bb[end_bb]) {
		    DPRINT ("agree\n");
		} else if (start_bb < bb[end_bb]) {
		    bb[bb[end_bb]] = start_bb; /* Split this bb */
		    splits.insert(bb[end_bb]);
		} else {
		    bb[start_bb] = bb[end_bb]; /* Split existing block */
		    bb[end_bb] = start_bb;
		    splits.insert(start_bb);
		}
	    }
	    i++;
	} else if (val > OP_BRANCH_NOT_TAKEN) {
	    start_bb = val;
	}
    }
}

static void print_bb (u_long start_bb, u_long end_bb, u_long* new_buf, int& new_ndx,
		      map<u_long,u_long>& bb) 
{
    if (start_bb == bb[end_bb]) {
	new_buf[new_ndx++] = start_bb;
    } else {
	print_bb (start_bb, bb[end_bb], new_buf, new_ndx, bb);
	new_buf[new_ndx++] = bb[end_bb];
    }
}

static void build_new_bb_list (u_long* old_buf, int end, u_long* new_buf, int& new_ndx, bool is_devbuf, map<u_long,u_long>& bb)
{
    u_long start_bb = 0;

    for (int i = 0; i < end; i++) {
	u_long val = old_buf[i];
	if (val >= OP_RELREAD && val <= OP_RELREAD2) {
	    i++; 
	    if (is_devbuf) i++;
	} else if (val == OP_BRANCH_TAKEN || val == OP_BRANCH_NOT_TAKEN) {
	    u_long end_bb = old_buf[i+1];
	    print_bb (start_bb, end_bb, new_buf, new_ndx, bb);
	    new_buf[new_ndx++] = val;
	    new_buf[new_ndx++] = end_bb;
	    start_bb = 0;
	    i++;
	} else if (val < OP_RELREAD) {
	    if (start_bb) {
		new_buf[new_ndx++] = start_bb;
		start_bb = 0;
	    }
	    new_buf[new_ndx++] = val;
	} else {
	    if (start_bb) {
		// This happens sometimes when BB ends in a call - yuk - Pin!
		new_buf[new_ndx++] = start_bb;
	    }
	    start_bb = val;
	}
    }
    if (start_bb) {
	new_buf[new_ndx++] = start_bb;
    }

    for (int i = 0; i < new_ndx; i++) {
	DPRINT ("New list %d: %lx\n", i, new_buf[i]);
    }
}

static inline void handle_index_diverge (ADDRINT ip, uint32_t memloc, u_long logaddr, bool is_write)
{
    printf ("Memory access type write at ip %x clock %lu bb %lu differs: addr %x vs. %lx\n", ip, *ppthread_log_clock, bb_cnt, memloc, logaddr);
    u_long diff = memloc > logaddr ? memloc-logaddr : logaddr-memloc;
    auto iter = indexes.find(ip);
    if (iter == indexes.end()) {
	index_div rw;
	rw.addr = ip;
	rw.is_write = is_write;
	rw.value = diff;
	indexes[ip] = rw;
    } else {
	if (diff > iter->second.value) {
	    iter->second.value = diff;
	}
    }
}

void find_best_match ()
{
    map<u_long,u_long> bb; /* End -> Start */
    unordered_set<u_long> splits;

    // Read in sufficient records from file to do comparison
    int end_ndx = skip_to_end ();

    // Split basic blocks to get correct values, and construct traces for comparison
    DPRINT ("prev ndx is %d, end ndx is %d\n", prev_ndx, end_ndx);
    extract_basic_blocks (buffer+prev_ndx, end_ndx-prev_ndx, false, bb, splits);
    DPRINT ("dev ndx is %d\n", devndx);
    extract_basic_blocks (dev_buffer, devndx, true, bb, splits);

    u_long buffer1[1024], buffer2[1024];
    int bufend1 = 0, bufend2 = 0;
    build_new_bb_list (buffer+prev_ndx, end_ndx-prev_ndx, buffer1, bufend1, false, bb);
    build_new_bb_list (dev_buffer, devndx, buffer2, bufend2, true, bb);

    // Now find the best match (lowest total # of basic blocks 
    int best_i = -1, best_j = -1, best_val = INT_MAX;
    int skip_i = 0;
    for (int i = 0; i < bufend1; i++) {
	int start_j;
	if (i == 0) {
	    start_j = 1;
	} else {
	    start_j = 0;
	}
	while (buffer1[i] >= OP_BRANCH_TAKEN && buffer1[i] <= OP_BRANCH_NOT_TAKEN) {
	    i += 2;
	    skip_i += 2;
	}
	int skip_j = 0;
	for (int j = start_j; j < bufend2; j++) {
	    while (buffer2[j] >= OP_BRANCH_TAKEN && buffer2[j] <= OP_BRANCH_NOT_TAKEN) {
		j += 2;
		skip_j += 2;
	    }
	    if (i-skip_i + j-skip_j >= best_val) break;
	    if (buffer1[i] == buffer2[j]) {
	      DPRINT ("Match at index %d/%d (%d/%d): %lx\n", i-skip_i, j-skip_j, i, j, buffer1[i]);
		best_i = i; 
		best_j = j; 
		best_val = i-skip_i+j-skip_j;
		break;
	    }
	}
    }

    if (best_val == INT_MAX) {
	fprintf (stderr, "deviation at %x bb %lx syscall %ld is too large to handle\n", deviation_ip, bb_cnt, *ppthread_log_clock);
	exit (1);
    }

    // Spit out the deviation for the checks file
    int iter = (buffer1[0] == buffer1[best_i] || buffer2[0] == buffer2[best_j]);
    printf ("0x%x ctrl_diverge -1,%ld,%ld orig_branch %c iter %d\n", 
	    deviation_ip, *ppthread_log_clock, bb_cnt, deviation_taken ? 't' : 'n', iter);

    int skip1 = 0;
    bool first = true;
    for (int i = 1; i < best_i; i++) {
	while (buffer1[i] >= OP_BRANCH_TAKEN && buffer1[i] <= OP_BRANCH_NOT_TAKEN) {
	    if (!first) {
		if (buffer1[i] == OP_BRANCH_TAKEN) {
		    printf ("0x%lx ctrl_block_instrument_orig branch t\n", buffer1[i+1]);
		} else if (buffer1[i] == OP_BRANCH_NOT_TAKEN) {
		    printf ("0x%lx ctrl_block_instrument_orig branch n\n", buffer1[i+1]);
		}
	    } 
	    i += 2;
	    skip1 += 2;
	}
	first = false;
	if (i < best_i) printf ("0x%lx ctrl_block_instrument_orig branch -\n", buffer1[i]);
    }

    first = true;
    int skip2 = 0;
    for (int i = 1; i < best_j; i++) {
	while (buffer2[i] >= OP_BRANCH_TAKEN && buffer2[i] <= OP_BRANCH_NOT_TAKEN) {
	    if (!first) {
		if (buffer2[i] == OP_BRANCH_TAKEN) {
		    printf ("0x%lx ctrl_block_instrument_alt branch t\n", buffer2[i+1]);
		} else if (buffer2[i] == OP_BRANCH_NOT_TAKEN) {
		    printf ("0x%lx ctrl_block_instrument_alt branch n\n", buffer2[i+1]);
		}
	    }
	    i += 2;
	    skip2 += 2;
	}
	first = false;
	if (i < best_j) printf ("0x%lx ctrl_block_instrument_alt branch -\n", buffer2[i]);
    }

    u_long new_bb_cnt = bb_cnt + best_i - skip1;
    bool loop1 = false, loop2 = false;
    u_long target_val = buffer1[best_i];
    if (buffer1[0] == buffer1[best_i] && best_i) {
	// Loop
	printf ("0x%lx ctrl_block_instrument_orig branch -\n", buffer1[best_i]);	
	printf ("0x%x ctrl_merge -1,%ld,%ld\n", deviation_ip, *ppthread_log_clock, new_bb_cnt);
	loop1 = true;
    } else if (buffer2[0] == buffer2[best_j]) {
	// Loop
	printf ("0x%lx ctrl_block_instrument_alt branch -\n", buffer2[best_j]);	
	printf ("0x%x ctrl_merge -1,%ld,%ld\n", deviation_ip, *ppthread_log_clock, new_bb_cnt);
	loop2 = true;
    } else {
	printf ("0x%lx ctrl_merge -1,%ld,%ld\n", buffer1[best_i], *ppthread_log_clock, new_bb_cnt);
    }

    // Find the correct index to restart comparison
    DPRINT ("Extra log records: %d\n", end_ndx - best_i);
    DPRINT ("Extra deviation log records: %d\n", devndx - best_j);
    if (best_i && splits.count(target_val)) {
	DPRINT ("target was split\n");
	// Because of split bbs, target may not be in list - make it end of bb, call, or return
	for (int i = best_i+1; i < bufend1; i++) {
	    if (buffer1[i] == OP_BRANCH_TAKEN || buffer1[i] == OP_BRANCH_NOT_TAKEN) {
		target_val = buffer1[i+1];
		break;
	    } else if (buffer1[i] <= OP_RETURN) {
		target_val = buffer1[i+1];
		break;
	    }
	}
    }
    DPRINT ("Search for value %lx in deviation buffer\n", target_val);

    int i, j;
    for (i = 0; i < devndx; i++) {
	if (dev_buffer[i] == target_val) {
	    if (loop2) {
		loop2 = false;
	    } else {
		DPRINT ("Occurs at index %d\n", i);
		break;
	    }
	}
    }
    assert (i != devndx);

    DPRINT ("Search for value %lx in original original buffer\n", target_val);
    bool loop1_check = loop1;
    for (j = prev_ndx; j < end_ndx; j++) {
	if (buffer[j] > OP_BRANCH_NOT_TAKEN) {
	    // Update this because we might have another deviation
	    prev_ndx = j;
	    prev_bb = buffer[j];
	}
	if (buffer[j] == target_val) {
	    if (loop1) {
		loop1 = false;
	    } else {
		if (loop1_check) {
		    // May need to load into buffer
		    DPRINT ("Checking deviation: %d %lx\n", j+1, buffer[j+1]);
		    while (buffer[j+1] >= OP_RELREAD && buffer[j+1] <= OP_RELREAD2) {
			j += 2;  // These won't be in deviation buffer so skip
		    }
		}
		DPRINT ("Occurs at index %d/%d\n", j, j-prev_ndx);
		break;
	    }
	}
    }
    assert (j != end_ndx);

    ndx = j+1;
    bb_cnt = new_bb_cnt;
    for (i = i+1; i < devndx; i++, ndx++) {
	DPRINT ("Records: %d:%lx vs. %d:%lx\n", ndx, buffer[ndx], i, dev_buffer[i]);
	if ((buffer[ndx] == OP_BRANCH_TAKEN && dev_buffer[i] == OP_BRANCH_NOT_TAKEN) ||
	    (buffer[ndx] == OP_BRANCH_NOT_TAKEN && dev_buffer[i] == OP_BRANCH_TAKEN)) {
	    DPRINT ("Another deviation at indexes %d %d\n", ndx, i);
	    deviation_ip = dev_buffer[i+1];
	    deviation_taken = (buffer[ndx] == OP_BRANCH_TAKEN);
	    if (i != 1) {
		/* Compact the deviation buffer */
		dev_buffer[0] = prev_bb;
		for (j = i; j < devndx; j++) {
		    dev_buffer[j-i+1] = dev_buffer[j];
		}
		devndx = devndx-i+1;
	    }
	    return find_best_match();
	}
	assert (buffer[ndx] == dev_buffer[i]);
	if (buffer[ndx] >= OP_RELREAD && buffer[ndx] <= OP_BRANCH_NOT_TAKEN) {
	    if (buffer[ndx] >= OP_RELREAD && buffer[ndx] <= OP_RELREAD2) {
		if (buffer[ndx+1] != dev_buffer[i+2]) {
		    handle_index_diverge (dev_buffer[i+1], dev_buffer[i+2], buffer[ndx+1], (buffer[ndx] == OP_RELWRITE));
		}
		i++;
	    }
	    ndx++;
	    i++;
	} else if (buffer[ndx] > OP_BRANCH_NOT_TAKEN) {
	    prev_ndx = ndx;
	    prev_bb = buffer[ndx];
	    bb_cnt++;
	}
    }
    deviation = false;
    debug_on = true;
    DPRINT ("BB cnt is now %lu\n", bb_cnt);
}

static void PIN_FAST_ANALYSIS_CALL trace_bbl (ADDRINT ip)
{
    if (deviation) {
	dev_buffer[devndx++] = ip;
	assert (devndx < BUF_SIZE);
	if (ip == prev_bb) find_best_match ();
	return;
    }

    bb_cnt++;
    prev_ndx = ndx;
    prev_bb = get_value();
    MYASSERT (prev_bb == ip);
}

static void PIN_FAST_ANALYSIS_CALL trace_bbl_stutters (ADDRINT ip, uint32_t first_iter)
{
    if (first_iter) {
	if (deviation) {
	    dev_buffer[devndx++] = ip;
	    assert (devndx < BUF_SIZE);
	    if (ip == prev_bb) find_best_match ();
	    return;
	}

	prev_ndx = ndx;
	prev_bb = get_value();
	MYASSERT (prev_bb == ip);
    }
    bb_cnt++;
}

static void PIN_FAST_ANALYSIS_CALL trace_relread (ADDRINT ip, uint32_t memloc)
{
    if (deviation) {
	dev_buffer[devndx++] = OP_RELREAD;
	dev_buffer[devndx++] = ip;
	dev_buffer[devndx++] = memloc;
	assert (devndx < BUF_SIZE);
	return;
    }

    OP_CHECK (OP_RELREAD);

    u_long logaddr = get_value();
    if (logaddr != memloc) {
	handle_index_diverge(ip, memloc, logaddr, false);
    }
}

static void PIN_FAST_ANALYSIS_CALL trace_relwrite (ADDRINT ip, uint32_t memloc)
{
    if (deviation) {
	dev_buffer[devndx++] = OP_RELWRITE;
	dev_buffer[devndx++] = ip;
	dev_buffer[devndx++] = memloc;
	assert (devndx < BUF_SIZE);
	return;
    }

    OP_CHECK (OP_RELWRITE);

    u_long logaddr = get_value();
    if (logaddr != memloc) {
	handle_index_diverge(ip, memloc, logaddr, true);
    }
}

static void PIN_FAST_ANALYSIS_CALL trace_relread2 (ADDRINT ip, uint32_t memloc)
{
    if (deviation) {
	dev_buffer[devndx++] = OP_RELREAD2;
	dev_buffer[devndx++] = ip;
	dev_buffer[devndx++] = memloc;
	assert (devndx < BUF_SIZE);
	return;
    }

    OP_CHECK (OP_RELREAD2);

    u_long logaddr = get_value();
    if (logaddr != memloc) {
	handle_index_diverge(ip, memloc, logaddr, false);
    }
}

static void PIN_FAST_ANALYSIS_CALL trace_relread_stutters (ADDRINT ip, uint32_t memloc, uint32_t first_iter)
{
    if (first_iter) trace_relread (ip, memloc);
}

static void PIN_FAST_ANALYSIS_CALL trace_relwrite_stutters (ADDRINT ip, uint32_t memloc, uint32_t first_iter)
{
    if (first_iter) trace_relwrite (ip, memloc);
}

static void PIN_FAST_ANALYSIS_CALL trace_relread2_stutters (ADDRINT ip, uint32_t memloc, uint32_t first_iter)
{
    if (first_iter) trace_relread2 (ip, memloc);
}

static void PIN_FAST_ANALYSIS_CALL trace_branch (ADDRINT ip, uint32_t taken)
{
    if (deviation) {
	dev_buffer[devndx++] = taken ? OP_BRANCH_TAKEN : OP_BRANCH_NOT_TAKEN;
	dev_buffer[devndx++] = ip;
	assert (devndx < BUF_SIZE);
	return;
    }

    u_long op = get_value();
    MYASSERT (op == OP_BRANCH_TAKEN || op == OP_BRANCH_NOT_TAKEN);

    OP_CHECK(ip);

    u_long logtaken = (op == OP_BRANCH_TAKEN);
    if (taken != logtaken) {
	dev_buffer[0] = prev_bb;
	dev_buffer[1] = taken ? OP_BRANCH_TAKEN : OP_BRANCH_NOT_TAKEN;
	dev_buffer[2] = ip;
	devndx = 3;
	deviation_ip = ip;
	deviation_taken = logtaken;
	deviation = true;
    }
}

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
		    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_branch), 
				   IARG_FAST_ANALYSIS_CALL,
				   IARG_INST_PTR,
				   IARG_BRANCH_TAKEN,
				   IARG_END);
	    }
	    if (INS_MemoryBaseReg(ins) != LEVEL_BASE::REG_INVALID() || INS_MemoryIndexReg(ins) != LEVEL_BASE::REG_INVALID()) {
		if (INS_Stutters(BBL_InsHead(bbl))) {
		    if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relread_stutters), 
				       IARG_FAST_ANALYSIS_CALL,
				       IARG_INST_PTR,
				       IARG_MEMORYREAD_EA,
				       IARG_FIRST_REP_ITERATION,
				       IARG_END);
			if (INS_HasMemoryRead2(ins)) {
			    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relread2_stutters), 
					   IARG_FAST_ANALYSIS_CALL,
					   IARG_INST_PTR,
					   IARG_MEMORYREAD2_EA,
					   IARG_FIRST_REP_ITERATION,
					   IARG_END);
			}
		    }
		    if (INS_IsMemoryWrite(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relwrite_stutters), 
				       IARG_FAST_ANALYSIS_CALL,
				       IARG_INST_PTR,
				       IARG_MEMORYWRITE_EA,
				       IARG_FIRST_REP_ITERATION,				       
				       IARG_END);
		    }
		} else {
		    if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relread), 
				       IARG_FAST_ANALYSIS_CALL,
				       IARG_INST_PTR,
				       IARG_MEMORYREAD_EA,
				       IARG_END);
			if (INS_HasMemoryRead2(ins)) {
			    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relread2), 
					   IARG_FAST_ANALYSIS_CALL,
					   IARG_INST_PTR,
					   IARG_MEMORYREAD2_EA,
					   IARG_END);
			}
		    }
		    if (INS_IsMemoryWrite(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(trace_relwrite), 
				       IARG_FAST_ANALYSIS_CALL,
				       IARG_INST_PTR,
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

    return TRUE;
}

static void PIN_FAST_ANALYSIS_CALL before_function_call(ADDRINT rtn_addr)
{
    if (deviation) {
	dev_buffer[devndx++] = 0;
	assert (devndx < BUF_SIZE);
	find_best_match ();
	return;
    }

    u_long op = get_value();
    if (op != 0) {
	fprintf (stderr, "before_function_call: got op %lx\n", op);
	exit (1);
    }
}

static void PIN_FAST_ANALYSIS_CALL after_function_call(ADDRINT rtn_addr)
{
    if (deviation) {
	dev_buffer[devndx++] = 1;
	assert (devndx < BUF_SIZE);
	find_best_match ();
	return;
    }

    u_long op = get_value();
    if (op != 1) {
	fprintf (stderr, "after_function_call: got op %lx\n", op);
	exit (1);
    }
}

void routine (RTN rtn, VOID *v)
{
    RTN_Open(rtn);

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)before_function_call,
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_ADDRINT, RTN_Address(rtn), 
		   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)after_function_call,
		   IARG_FAST_ANALYSIS_CALL,
		   IARG_ADDRINT, RTN_Address(rtn), 
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
}

void thread_fini (THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    struct thread_data* ptdata;
    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
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

    string logfilename = KnobFilename.Value();
    print_stop = atoi(KnobPrintStop.Value().c_str());
    
    // Try to map the log clock for this epoch
    ppthread_log_clock = map_shared_clock(fd);

    logfd = open (logfilename.c_str(), O_RDONLY | O_LARGEFILE);
    if (logfd < 0) {
	fprintf (stderr, "Unable to open %s\n", logfilename.c_str());
	return logfd;
    }
    ndx = 0;
    bufsize = 0;

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
