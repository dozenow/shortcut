#include "track_pthread.h"
#include <map>
using namespace std;

extern struct thread_data* current_thread;

// Synchronization data structures that may need to be recreated
map<ADDRINT, struct mutex_state> active_mutex; 


//the key is the address of conditional variable or tid
map<ADDRINT, struct wait_state*> active_wait; //I need to replace this with a thread-safe STL library

void track_pthread_mutex_params_1 (ADDRINT mutex) 
{
    current_thread->pthread_info.mutex_info_cache.mutex = mutex;
}

void track_pthread_mutex_lock ()
{
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    PTHREAD_DEBUG ("record pid %d, mutex lock %p\n", current_thread->record_pid, (void*) mutex);
    if (active_mutex.find(mutex) == active_mutex.end()) {
	struct mutex_state state;
	state.lock_count = 1; // Use this to handle recursive locks
	state.pid = current_thread->record_pid;
	active_mutex[mutex] = state;
    }  else {
	struct mutex_state& state = active_mutex[mutex];
	if (state.lock_count > 0 && state.pid != current_thread->record_pid) {
	    fprintf (stderr, "[ERROR] different locker so not a recursive lock: %x\n", mutex);
	}
	state.pid = current_thread->record_pid;
	state.lock_count++;
    }
}

void track_pthread_mutex_trylock (ADDRINT retval)
{
    PTHREAD_DEBUG ("record pid %d, mutex trylock %p retval %d\n", current_thread->record_pid, (void*) mutex, retval);
    if (retval == 0) track_pthread_mutex_lock ();
}

void track_pthread_mutex_unlock ()
{   
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    PTHREAD_DEBUG ("record pid %d, mutex unlock %p\n", current_thread->record_pid, (void*) mutex);
    struct mutex_state& state = active_mutex[mutex];
    state.lock_count--;
}

void track_pthread_mutex_destroy ()
{
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    active_mutex.erase (mutex);
}

static inline void change_wait_state (ADDRINT wait, int wait_state, ADDRINT mutex, ADDRINT abstime)
{
    struct wait_state* state = NULL;
    if (active_wait.find (wait) != active_wait.end()) {
        state = active_wait[wait];
    } else { 
        state = (struct wait_state*) malloc (sizeof(struct wait_state));
    }
    state->pid = current_thread->record_pid;
    state->state = wait_state;
    state->mutex = mutex;
    state->abstime = abstime;
    active_wait[wait] = state;
}

static inline void destroy_wait_state (ADDRINT wait)
{
    struct wait_state* state = active_wait[wait];
    assert (state != NULL);
    free (state);
    active_wait.erase (wait);
}

void track_pthread_cond_timedwait_before (ADDRINT cond, ADDRINT mutex, ADDRINT abstime)
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    cache->mutex = mutex;
    cache->cond = cond;
    cache->abstime = abstime;
    PTHREAD_DEBUG ("record pid %d, before cond_timedwait lock %p, cond %p\n", current_thread->record_pid, (void*)mutex, (void*) cond);
    //change_mutex_state (mutex, MUTEX_UNLOCK):
    change_wait_state (cond, COND_BEFORE_WAIT, mutex, abstime);
}

void track_pthread_cond_timedwait_after (ADDRINT rtn_addr) 
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    PTHREAD_DEBUG ("record pid %d, after cond_timedwait lock %p, cond %p\n", current_thread->record_pid, (void*)cache->mutex, (void*) cache->cond);
    //change_mutex_state (mutex, MUTEX_AFTER_LOCK);
    //change_cond_state (cache->cond, COND_AFTER_WAIT, cache->mutex, cache->abstime);
    destroy_wait_state (cache->cond);
}

void track_pthread_lll_wait_tid_before (ADDRINT tid)
{
    PTHREAD_DEBUG ("record pid %d, before lll_wait_tid %p\n", current_thread->record_pid, (void*)tid);
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    cache->tid = tid;
    change_wait_state (tid, LLL_WAIT_TID_BEFORE, 0, 0);
}

void track_pthread_lll_wait_tid_after (ADDRINT rtn_addr)
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    PTHREAD_DEBUG ("record pid %d, after lll_wait_tid %p\n", current_thread->record_pid, (void*)cache->tid);
    //change_wait_tid_state (tid, LLL_WAIT_TID_AFTER);
    destroy_wait_state (cache->tid);
}

void sync_pthread_state (struct thread_data* tdata)
{
    for (map<ADDRINT, struct mutex_state>::iterator iter = active_mutex.begin(); iter != active_mutex.end(); ++iter) { 
        if (iter->second.lock_count > 0 && iter->second.pid == tdata->record_pid) { 
	    fprintf (stderr, "calling pthread_mutex_lock on lock 0x%x\n", iter->first);
	    for (int i = 0; i < iter->second.lock_count; i++) {
		OUTPUT_SLICE_THREAD (tdata, 0, "push 0x%x", iter->first);
		OUTPUT_SLICE_INFO_THREAD (tdata, "");
		OUTPUT_SLICE_THREAD (tdata, 0, "call pthread_mutex_lock_shim");
		OUTPUT_SLICE_INFO_THREAD (tdata, "");
		OUTPUT_SLICE_THREAD (tdata, 0, "add esp, 4");
		OUTPUT_SLICE_INFO_THREAD (tdata, "");
	    }
        }
    }

#if 0
    for (map<ADDRINT, struct wait_state*>::iterator iter = active_wait.begin(); iter != active_wait.end(); ++iter) { 
        if (iter->second->pid == tdata->record_pid) { 
            DEBUG_INFO ("       pid %d wait on  %x state %d\n", iter->second->pid, iter->first, iter->second->state);
            OUTPUT_SLICE_THREAD (tdata, 0, "pushfd");
            OUTPUT_SLICE_INFO_THREAD (tdata, "re-create pthread state, clock %lu, pid %d", *ppthread_log_clock, tdata->record_pid);
            switch (iter->second->state) { 
                case COND_BEFORE_WAIT: 
                    //normally, the mutex should already be held by this thread
                    print_function_call_inst (tdata, "pthread_cond_timedwait", 3, iter->first, iter->second->mutex, iter->second->abstime);
                    break;
                case LLL_WAIT_TID_BEFORE:
                    print_function_call_inst (tdata, "pthread_log_lll_wait_tid", 1, iter->first);
                    break;
                default: 
                    PTHREAD_DEBUG (stderr, "unhandled pthread operation.\n");
            }
            OUTPUT_SLICE_THREAD (tdata, 0, "popfd");
            OUTPUT_SLICE_INFO_THREAD (tdata, "re-create pthread state, clock %lu, pid %d", *ppthread_log_clock, tdata->record_pid);
        }
    }
#endif
}

// Mostly the same, but writes to main c file instead of slice file - doesn't wakup when done
void sync_my_pthread_state (struct thread_data* tdata)
{
    for (map<ADDRINT, struct mutex_state>::iterator iter = active_mutex.begin(); iter != active_mutex.end(); ++iter) { 
        if (iter->second.lock_count > 0 && iter->second.pid == tdata->record_pid) { 
	    for (int i = 0; i < iter->second.lock_count; i++) {
		OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
		OUTPUT_MAIN_THREAD (tdata, "call pthread_mutex_lock");
		OUTPUT_MAIN_THREAD (tdata, "add esp, 4");
	    }
        }
    }
}

