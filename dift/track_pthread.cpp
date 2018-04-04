#include "track_pthread.h"
#include <map>
using namespace std;

extern struct thread_data* current_thread;

// Synchronization data structures that may need to be recreated
map<ADDRINT, struct mutex_state> active_mutex; 
map<ADDRINT, struct lll_lock_state> active_lll_lock; 
//the key is the address of conditional variable or tid
map<ADDRINT, struct wait_state*> active_wait; //I need to replace this with a thread-safe STL library

map<string, ADDRINT> pthread_operation_addr; //pthread function name -> function addr

void track_pthread_mutex_params_1 (ADDRINT mutex) 
{
    current_thread->pthread_info.mutex_info_cache.mutex = mutex;
}

void track_pthread_mutex_lock (int retval, int is_libc_lock)
{
    if (retval != 0) { 
        fprintf (stderr, "---pthread_mutex_lock has non-zero return %d\n", retval);
        return;
    }
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    PTHREAD_DEBUG ("record pid %d, mutex lock %p\n", current_thread->record_pid, (void*) mutex);
    if (active_mutex.find(mutex) == active_mutex.end()) {
	struct mutex_state state;
	state.lock_count = 1; // Use this to handle recursive locks
	state.pid = current_thread->record_pid;
        state.is_libc_lock = is_libc_lock;
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

void track_pthread_mutex_trylock (ADDRINT retval, int is_libc_lock)
{
    PTHREAD_DEBUG ("record pid %d, mutex trylock %p retval %d\n", current_thread->record_pid, (void*) current_thread->pthread_info.mutex_info_cache.mutex, retval);
    if (retval == 0) track_pthread_mutex_lock (retval, is_libc_lock);
}

void track_pthread_mutex_unlock (int retval)
{   
    if (retval != 0) { 
        fprintf (stderr, "---pthread_mutex_unlock has non-zero return %d\n", retval);
        return;
    }
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    PTHREAD_DEBUG ("record pid %d, mutex unlock %p\n", current_thread->record_pid, (void*) mutex);
    struct mutex_state& state = active_mutex[mutex];
    state.lock_count--;
}

void track_pthread_mutex_destroy (int retval)
{
    if (retval != 0) { 
        fprintf (stderr, "---pthread_mutex_destroy has non-zero return %d\n", retval);
        return;
    }
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
        state->wait_counter = 0;
    }
    state->pid = current_thread->record_pid;
    state->state = wait_state;
    state->mutex = mutex;
    state->abstime = abstime;
    ++state->wait_counter;
    active_wait[wait] = state;
}

static inline void destroy_wait_state (ADDRINT wait)
{
    struct wait_state* state = active_wait[wait];
    assert (state != NULL);
    -- state->wait_counter;
    if (state->wait_counter == 0) { 
        free (state);
        active_wait.erase (wait);
    }
}

void track_pthread_cond_timedwait_before (ADDRINT cond, ADDRINT mutex, ADDRINT abstime)
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    cache->mutex = mutex;
    cache->cond = cond;
    cache->abstime = abstime;
    PTHREAD_DEBUG ("record pid %d, before cond_(timed)wait lock %p, cond %p\n", current_thread->record_pid, (void*)mutex, (void*) cond);
    //unlock
    struct mutex_state& state = active_mutex[mutex];
    state.lock_count--;

    change_wait_state (cond, COND_BEFORE_WAIT, mutex, abstime);
}

void track_pthread_cond_timedwait_after (ADDRINT rtn_addr) 
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    PTHREAD_DEBUG ("record pid %d, after cond_(timed)wait lock %p, cond %p\n", current_thread->record_pid, (void*)cache->mutex, (void*) cache->cond);
    //lock again
    struct mutex_state& state = active_mutex[cache->mutex];
    if (state.lock_count > 0 && state.pid != current_thread->record_pid) {
        fprintf (stderr, "[ERROR] different locker so not a recursive lock: %x\n", cache->mutex);
    }
    state.pid = current_thread->record_pid;
    state.lock_count++;

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
    destroy_wait_state (cache->tid);
}

void track_lll_lock_before (ADDRINT plock, ADDRINT type)
{
    struct lll_lock_info_cache* cache = &current_thread->pthread_info.lll_lock_info_cache;
    cache->plock = plock;
    cache->type = type;
}

void track_lll_lock_after ()
{
    struct lll_lock_info_cache* cache = &current_thread->pthread_info.lll_lock_info_cache;
    PTHREAD_DEBUG ("record pid %d, lll lock %p\n", current_thread->record_pid, (void*) cache->plock);
    if (active_lll_lock.find(cache->plock) == active_lll_lock.end()) {
	struct lll_lock_state state;
	state.pid = current_thread->record_pid;
        state.type = cache->type;
	active_lll_lock[cache->plock] = state;
    }  else {
	struct lll_lock_state& state = active_lll_lock[cache->plock];
	if ((state.pid && state.pid != current_thread->record_pid) || (state.type && state.type != cache->type)) {
	    fprintf (stderr, "[ERROR] different locker for lll lock: %x, type %d\n", cache->plock, cache->type);
	}
	state.pid = current_thread->record_pid;
        state.type = cache->type;
    }
}

void track_lll_unlock_after ()
{
    struct lll_lock_info_cache* cache = &current_thread->pthread_info.lll_lock_info_cache;
    struct lll_lock_state& state = active_lll_lock[cache->plock];
    state.pid = 0;
    state.type = 0;
}

void sync_pthread_state (struct thread_data* tdata)
{
    assert (0); //don't use this function; use the other one
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
    OUTPUT_MAIN_THREAD (tdata, "pushfd /*start to re-create pthread states*/");
    OUTPUT_MAIN_THREAD (tdata, "push eax /*start to re-create pthread states*/"); //used for indirect calls

    //mutex states
    for (map<ADDRINT, struct mutex_state>::iterator iter = active_mutex.begin(); iter != active_mutex.end(); ++iter) { 
        if (iter->second.lock_count > 0 && iter->second.pid == tdata->record_pid) { 
	    for (int i = 0; i < iter->second.lock_count; i++) {
                if (iter->second.is_libc_lock == 1) {
                    OUTPUT_MAIN_THREAD (tdata, "mov eax, 0x%x", pthread_operation_addr["pthread_log_mutex_lock"]);
                } else {
                    OUTPUT_MAIN_THREAD (tdata, "mov eax, 0x%x", pthread_operation_addr["pthread_mutex_lock"]);
                }
		OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
		OUTPUT_MAIN_THREAD (tdata, "call eax /*pthread%smutex_lock*/", iter->second.is_libc_lock?"_log_":"_");
		OUTPUT_MAIN_THREAD (tdata, "add esp, 4");
	    }
        }
    }
    //lll lock states
    for (map<ADDRINT, struct lll_lock_state>::iterator iter = active_lll_lock.begin(); iter != active_lll_lock.end(); ++iter) { 
        if (iter->second.pid == tdata->record_pid) { 
            fprintf (stderr, "re-constructing pthread_log_lll_lock; not fully tested; please manually inspect the exslice main c file.\n");
            OUTPUT_MAIN_THREAD (tdata, "mov eax, 0x%x", pthread_operation_addr["pthread_log_lll_lock"]);
            OUTPUT_MAIN_THREAD (tdata, "push %d", iter->second.type);
            OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
            OUTPUT_MAIN_THREAD (tdata, "call eax /*pthread_log_lll_lock*/");
            OUTPUT_MAIN_THREAD (tdata, "add esp, 8");
        }
    }
    //wait state
    for (map<ADDRINT, struct wait_state*>::iterator iter = active_wait.begin(); iter != active_wait.end(); ++iter) { 
        if (iter->second->pid == tdata->record_pid) { 
            bool timedwait = (iter->second->abstime == UINT_MAX);
            if (iter->second->state == COND_BEFORE_WAIT) { 
                //check if the mutex is held by another thread
                map<ADDRINT, struct mutex_state>::iterator mutex_state = active_mutex.find(iter->second->mutex);
                if (mutex_state != active_mutex.end()) { 
                    if (mutex_state->second.pid != tdata->record_pid) { 
                        fprintf (stderr, "[ERROR] the mutex in cond_wait is held by another thread. cannot init.\n");
                    } else { 
                        fprintf (stderr, "[ERROR] this thread is still holding the mutex (for cond_wait)??\n");
                    }
                    continue;
                }
                fprintf (stderr, "re-constructing pthread_cond_XXXwait; not fully tested; please manually inspect the exslice main c file.\n");
                if (timedwait) { 
                    OUTPUT_MAIN_THREAD (tdata, "mov eax, 0x%x", pthread_operation_addr["pthread_cond_timedwait"]);
                    OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->second->abstime);
                    OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->second->mutex);
                    OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
                    OUTPUT_MAIN_THREAD (tdata, "call eax /*pthread_cond_timedwait*/");
                    OUTPUT_MAIN_THREAD (tdata, "add esp, 12");
                } else { 
                    OUTPUT_MAIN_THREAD (tdata, "mov eax, 0x%x", pthread_operation_addr["pthread_cond_wait"]);
                    OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->second->mutex);
                    OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
                    OUTPUT_MAIN_THREAD (tdata, "call eax /*pthread_cond_wait*/");
                    OUTPUT_MAIN_THREAD (tdata, "add esp, 8");
                }
            } else if (iter->second->state == LLL_WAIT_TID_BEFORE) { 
                fprintf (stderr, "re-constructing pthread_lll_wait_tid; not fully tested; please manually inspect the exslice main c file.\n");
                OUTPUT_MAIN_THREAD (tdata, "mov eax, 0x%x", pthread_operation_addr["pthread_log_lll_wait_tid"]);
                OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
                OUTPUT_MAIN_THREAD (tdata, "call eax /*pthread_log_lll_wait_tid/");
                OUTPUT_MAIN_THREAD (tdata, "add esp, 12");
            }
        }
    }

    OUTPUT_MAIN_THREAD (tdata, "pop eax /*start to re-create pthread states*/"); //used for indirect calls
    OUTPUT_MAIN_THREAD (tdata, "popfd /*start to re-create pthread states*/");
}

