#ifndef TRACK_PTHREAD_H
#define TRACK_PTHREAD_H

#include "pin.H"
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "linkage_common.h"

#define COND_BEFORE_WAIT        5
#define COND_AFTER_WAIT         6
#define LLL_WAIT_TID_BEFORE     7
#define LLL_WAIT_TID_AFTER      8

struct mutex_state {
    pid_t pid; //current holder
    int lock_count; // Can be >1 for recursive locks
    int is_libc_lock; //pthread_log_mutex_lock actually use libc lock
};

struct lll_lock_state {
    pid_t pid; //current holder
    ADDRINT type; //private or not
};

struct wait_state {
    int pid; //current holder
    int state; //state
    int wait_counter;
    ADDRINT mutex;
    ADDRINT abstime;
};

void track_pthread_mutex_params_1 (ADDRINT mutex);
void track_pthread_mutex_lock (int retval, int is_libc_lock);
void track_pthread_mutex_trylock (ADDRINT retval, int is_libc_lock);
void track_pthread_mutex_unlock (int retval);
void track_pthread_mutex_destroy (int retval);

void track_pthread_cond_timedwait_before (ADDRINT cond, ADDRINT mutex, ADDRINT abstime);
void track_pthread_cond_timedwait_after (ADDRINT rtn_addr);

void track_pthread_lll_wait_tid_before (ADDRINT tid);
void track_pthread_lll_wait_tid_after (ADDRINT rtn_addr);
void track_lll_lock_before (ADDRINT plock, ADDRINT type);
void track_lll_lock_after ();
void track_lll_unlock_after ();

void sync_pthread_state (struct thread_data* tdata);
void sync_my_pthread_state (struct thread_data* tdata);

//#define PTHREAD_DEBUG(x,...)
#define PTHREAD_DEBUG(x...) fprintf(stderr, x)

#endif
