#ifndef TRACK_PTHREAD_H
#define TRACK_PTHREAD_H

#include "pin.H"
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "linkage_common.h"

//note: currently, we take checkpoints at the end of a syscall; therefore, only synchronous pthread calls (lock, wait, etc.) have BEFOER and AFTER states. 
#define MUTEX_INIT              0
#define MUTEX_DESTROY           1
#define MUTEX_BEFORE_LOCK       2
#define MUTEX_AFTER_LOCK        3
#define MUTEX_UNLOCK            4
#define COND_BEFORE_WAIT        5
#define COND_AFTER_WAIT         6
#define LLL_WAIT_TID_BEFORE     7
#define LLL_WAIT_TID_AFTER      8
struct mutex_state {
    int pid; //current holder
    int state; //state
    ADDRINT field; //additional parameters we need to log
};

struct wait_state {
    int pid; //current holder
    int state; //state
    ADDRINT mutex;
    ADDRINT abstime;
};

void track_pthread_mutex_params_1 (ADDRINT mutex);
void track_pthread_mutex_params_2 (ADDRINT mutex, ADDRINT attr);
void track_pthread_mutex_init (ADDRINT rtn_addr);
void track_pthread_mutex_lock_before (char* name, ADDRINT rtn_addr, ADDRINT mutex);
void track_pthread_mutex_lock_after (char* name, ADDRINT rtn_addr);
void track_pthread_mutex_unlock (ADDRINT rtn_addr);
void track_pthread_mutex_destroy (ADDRINT rtn_addr);
void track_pthread_cond_timedwait_before (ADDRINT cond, ADDRINT mutex, ADDRINT abstime);
void track_pthread_cond_timedwait_after (ADDRINT rtn_addr);

void track_pthread_lll_wait_tid_before (ADDRINT tid);
void track_pthread_lll_wait_tid_after (ADDRINT rtn_addr);


#endif
