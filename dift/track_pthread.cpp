#include "track_pthread.h"
#include <map>
using namespace std;

extern struct thread_data* current_thread;
map<ADDRINT, struct mutex_state*> active_mutex; //I need to replace this with a thread-safe STL library
map<ADDRINT, struct cond_state*> active_cond; //I need to replace this with a thread-safe STL library

void track_pthread_mutex_params_2 (ADDRINT mutex, ADDRINT attr) 
{
    current_thread->pthread_info.mutex_info_cache.mutex = mutex;
    current_thread->pthread_info.mutex_info_cache.attr = attr;
}

void track_pthread_mutex_params_1 (ADDRINT mutex) 
{
    current_thread->pthread_info.mutex_info_cache.mutex = mutex;
}

void track_pthread_mutex_init (ADDRINT rtn_addr)
{
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    ADDRINT attr = current_thread->pthread_info.mutex_info_cache.attr;
    struct mutex_state* state = (struct mutex_state*) malloc (sizeof(struct mutex_state));
    state->pid = current_thread->record_pid;
    state->state = MUTEX_INIT;
    active_mutex[mutex] = state;
    if (attr != 0) {
        fprintf (stderr, " pthread_mutex_init with ATTR, not handled yet.\n");
    }
}

void track_pthread_mutex_lock_before (ADDRINT mutex) 
{
    current_thread->pthread_info.mutex_info_cache.mutex = mutex;
    printf ("record pid %d, before lock %p\n", current_thread->record_pid, (void*)mutex);
    if (active_mutex.find (mutex) != active_mutex.end()) {
        struct mutex_state* state = active_mutex[mutex];
        state->pid = current_thread->record_pid;
        if (state->state != MUTEX_AFTER_LOCK)  //someone is holding the lock
                state->state = MUTEX_BEFORE_LOCK;
    } else { 
        struct mutex_state* state = (struct mutex_state*) malloc (sizeof(struct mutex_state));
        state->pid = current_thread->record_pid;
        if (state->state != MUTEX_AFTER_LOCK) //someone is holding the lock
            state->state = MUTEX_BEFORE_LOCK; 
        active_mutex[mutex] = state;
        fprintf (stderr, "unfound mutex to lock\n");
    }
}

void track_pthread_mutex_lock_after (ADDRINT rtn_addr)
{
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    printf ("record pid %d, after lock %p\n", current_thread->record_pid, (void*)mutex);
    struct mutex_state* state = active_mutex[mutex];
    state->pid = current_thread->record_pid;
    if (state->state == MUTEX_AFTER_LOCK) {  //we have a deadlock?
        fprintf (stderr, "[ERROR] we have a deadlock in the original program or do we have unsupported unlock pthread operation?\n");
    }
    state->state = MUTEX_AFTER_LOCK;
}

//well, this function doesn't change the proper state; e.g., we cannot change from MUTEX_AFTER_LOCK to MUTEX_BEFORE_LOCK
static inline void change_mutex_state (ADDRINT mutex, int mutex_state) 
{
    struct mutex_state* state = NULL; 
    if (active_mutex.find (mutex) != active_mutex.end()) {
        state = active_mutex[mutex];
    } else { 
        fprintf (stderr, "unfound mutex to unlock, pid %d, lock %p\n", current_thread->record_pid, (void*) mutex);
    }
    state->pid = current_thread->record_pid;

    state->state = mutex_state;
}

static inline void change_cond_state (ADDRINT cond, int cond_state, ADDRINT mutex, ADDRINT abstime)
{
    struct cond_state* state = NULL;
    if (active_cond.find (cond) != active_cond.end()) {
        state = active_cond[cond];
    } else { 
        state = (struct cond_state*) malloc (sizeof(struct cond_state));
        fprintf (stderr, "uninitialized cond %p\n", (void*) cond);
    }
    state->pid = current_thread->record_pid;
    state->state = cond_state;
    state->mutex = mutex;
    state->abstime = abstime;
    active_cond[cond] = state;
}

void track_pthread_mutex_unlock (ADDRINT rtn_addr)
{   
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    printf ("record pid %d, unlock %p\n", current_thread->record_pid, (void*)mutex);
    change_mutex_state (mutex, MUTEX_UNLOCK);
}

void track_pthread_mutex_destroy (ADDRINT rtn_addr)
{
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    struct mutex_state* state = active_mutex[mutex];
    free (state);
    active_mutex.erase (mutex);
}

void track_pthread_cond_timedwait_before (ADDRINT cond, ADDRINT mutex, ADDRINT abstime)
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    cache->mutex = mutex;
    cache->cond = cond;
    cache->abstime = abstime;
    printf ("record pid %d, before cond_timedwait lock %p, cond %p\n", current_thread->record_pid, (void*)mutex, (void*) cond);
    //change_mutex_state (mutex, MUTEX_UNLOCK):
    change_cond_state (cond, COND_BEFORE_WAIT, mutex, abstime);
}

void track_pthread_cond_timedwait_after (ADDRINT rtn_addr) 
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    printf ("record pid %d, after cond_timedwait lock %p, cond %p\n", current_thread->record_pid, (void*)cache->mutex, (void*) cache->cond);
    //change_mutex_state (mutex, MUTEX_AFTER_LOCK);
    change_cond_state (cache->cond, COND_AFTER_WAIT, cache->mutex, cache->abstime);
}
