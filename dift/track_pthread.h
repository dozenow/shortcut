#ifndef TRACK_PTHREAD_H
#define TRACK_PTHREAD_H

#include "pin.H"
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "linkage_common.h"

#define RWLOCK_UNLOCKED         0
#define RWLOCK_READ_LOCKED      1
#define RWLOCK_WRITE_LOCKED     2

#define LLL_WAIT_TID_BEFORE     7
#define LLL_WAIT_TID_AFTER      8

struct pthread_funcs {
    u_long mutex_lock;
    u_long rwlock_rdlock;
    u_long rwlock_wrlock;
};

struct mutex_state {
    pid_t pid; //current holder
    int lock_count; // Can be >1 for recursive locks
};

struct rwlock_state {
    int state;     //state
    set<int> pids; // current holder(s)
};

struct wait_state {
    int pid; //current holder
    int state; //state
    ADDRINT mutex;
    ADDRINT abstime;
};

void track_pthread_mutex_params_1 (ADDRINT mutex);
void track_pthread_mutex_lock ();
void track_pthread_mutex_trylock (ADDRINT retval);
void track_pthread_mutex_unlock ();
void track_pthread_mutex_destroy ();

void track_pthread_rwlock_wrlock ();
void track_pthread_rwlock_rdlock ();
void track_pthread_rwlock_unlock ();

void track_pthread_cond_wait_before (ADDRINT cond, ADDRINT mutex);
void track_pthread_cond_wait_after (void);

void track_pthread_lll_wait_tid_before (ADDRINT tid);
void track_pthread_lll_wait_tid_after (ADDRINT rtn_addr);

void sync_pthread_state (struct thread_data* tdata, struct pthread_funcs* recall_funcs);
void sync_my_pthread_state (struct thread_data* tdata, struct pthread_funcs* recall_funcs);

#define PTHREAD_DEBUG(x,...)

#endif
