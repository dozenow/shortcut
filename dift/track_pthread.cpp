#include "track_pthread.h"
#include <map>
using namespace std;

#define LPRINT(x,...)

extern struct thread_data* current_thread;

// Synchronization data structures that may need to be recreated
map<ADDRINT, struct mutex_state> active_mutex; 
map<ADDRINT, struct lll_lock_state> active_lll_lock; 
//the key is the address of conditional variable or tid
map<ADDRINT, struct wait_state*> active_wait; //I need to replace this with a thread-safe STL library

map<string, ADDRINT> pthread_operation_addr; //pthread function name -> function addr
map<ADDRINT, struct rwlock_state> active_rwlock;

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
    LPRINT ("record pid %d, mutex lock %p\n", current_thread->record_pid, (void*) mutex);
    if (active_mutex.find(mutex) == active_mutex.end()) {
	struct mutex_state state;
	state.lock_count = 1; // Use this to handle recursive locks
	state.pid = current_thread->record_pid;
        state.is_libc_lock = is_libc_lock;
	active_mutex[mutex] = state;
	LPRINT ("\tpid %d count %d\n", state.pid, state.lock_count);
    }  else {
	struct mutex_state& state = active_mutex[mutex];
	if (state.pid == current_thread->record_pid) {
	    state.lock_count++;
	} else {
	    state.pid = current_thread->record_pid;
	    state.lock_count = 1;
	}
	LPRINT ("\tpid %d count %d\n", state.pid, state.lock_count);
    }
}

void track_pthread_mutex_trylock (ADDRINT retval, int is_libc_lock)
{
    LPRINT ("record pid %d, mutex trylock %p retval %d\n", current_thread->record_pid, (void*) current_thread->pthread_info.mutex_info_cache.mutex, retval);
    if (retval == 0) track_pthread_mutex_lock (retval, is_libc_lock);
}

void track_pthread_mutex_unlock (int retval)
{   
    if (retval != 0) { 
        fprintf (stderr, "---pthread_mutex_unlock has non-zero return %d\n", retval);
        return;
    }
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    LPRINT ("record pid %d, mutex unlock %p\n", current_thread->record_pid, (void*) mutex);
    struct mutex_state& state = active_mutex[mutex];
    if (state.pid == current_thread->record_pid) {
	state.lock_count--;
	if (state.lock_count == 0) state.pid = 0;
    }
    LPRINT ("\tpid %d count %d\n", state.pid, state.lock_count);
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
    LPRINT ("record pid %d, before cond_(timed)wait lock %p, cond %p\n", current_thread->record_pid, (void*)mutex, (void*) cond);
    // We are releasing the lock
    struct mutex_state& state = active_mutex[mutex];
    if (state.pid == current_thread->record_pid) {
	state.lock_count = 0;
	state.pid = 0;
    } else {
	fprintf (stderr, "Pid %d calling cond_wait without mutex? %lx\n", current_thread->record_pid, (u_long) mutex);
    }
    change_wait_state (cond, COND_BEFORE_WAIT, mutex, abstime);
}

void track_pthread_cond_timedwait_after (ADDRINT rtn_addr) 
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    LPRINT ("record pid %d, after cond_(timed)wait lock %p, cond %p\n", current_thread->record_pid, (void*)cache->mutex, (void*) cache->cond);
    //lock again
    struct mutex_state& state = active_mutex[cache->mutex];
    //if (state.lock_count > 0 && state.pid != current_thread->record_pid) {
        //fprintf (stderr, "[ERROR] cond_wait: different locker so not a recursive lock: %x, previous pid %d current pid %d; sometimes this is a correct behavior if there is a mutex_lock from another thread right before this cond_wait\n", cache->mutex, state.pid, current_thread->record_pid);
    //}
    state.pid = current_thread->record_pid;
    state.lock_count = 1;

    destroy_wait_state (cache->cond);
}

void track_pthread_lll_wait_tid_before (ADDRINT tid)
{
    LPRINT ("record pid %d, before lll_wait_tid %p\n", current_thread->record_pid, (void*)tid);
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    cache->tid = tid;
    change_wait_state (tid, LLL_WAIT_TID_BEFORE, 0, 0);
}

void track_pthread_lll_wait_tid_after (ADDRINT rtn_addr)
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    LPRINT ("record pid %d, after lll_wait_tid %p\n", current_thread->record_pid, (void*)cache->tid);
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
    LPRINT ("record pid %d, lll lock %p\n", current_thread->record_pid, (void*) cache->plock);
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

void sync_pthread_state (struct thread_data* tdata, struct pthread_funcs* recall_funcs)
{
    assert (0); //don't use this function; use the other one
#if 0
    for (map<ADDRINT, struct mutex_state>::iterator iter = active_mutex.begin(); iter != active_mutex.end(); ++iter) { 
        if (iter->second.lock_count > 0 && iter->second.pid == tdata->record_pid) { 
	    for (int i = 0; i < iter->second.lock_count; i++) {
		LPRINT ("calling pthread_mutex_lock on lock 0x%x\n", iter->first);
		OUTPUT_SLICE_THREAD (tdata, 0, "push 0x%x", iter->first);
		OUTPUT_SLICE_INFO_THREAD (tdata, "");
		OUTPUT_SLICE_THREAD (tdata, 0, "push 0x%lx", recall_funcs->mutex_lock);
		OUTPUT_SLICE_INFO_THREAD (tdata, "");
		OUTPUT_SLICE_THREAD (tdata, 0, "call pthread_mutex_lock_shim");
		OUTPUT_SLICE_INFO_THREAD (tdata, "");
		OUTPUT_SLICE_THREAD (tdata, 0, "add esp, 8");
		OUTPUT_SLICE_INFO_THREAD (tdata, "");
	    }
        }
    }
    for (map<ADDRINT, struct rwlock_state>::iterator iter = active_rwlock.begin(); iter != active_rwlock.end(); ++iter) { 
	if (iter->second.state == RWLOCK_READ_LOCKED && (iter->second.pids.find(tdata->record_pid) != iter->second.pids.end())) { 
	    LPRINT ("calling pthread_rwlock_rdlock on lock 0x%x\n", iter->first);
	    OUTPUT_SLICE_THREAD (tdata, 0, "push 0x%x", iter->first);
	    OUTPUT_SLICE_INFO_THREAD (tdata, "");
	    OUTPUT_SLICE_THREAD (tdata, 0, "push 0x%lx", recall_funcs->rwlock_rdlock);
	    OUTPUT_SLICE_INFO_THREAD (tdata, "");
	    OUTPUT_SLICE_THREAD (tdata, 0, "call pthread_rwlock_rdlock_shim");
	    OUTPUT_SLICE_INFO_THREAD (tdata, "");
	    OUTPUT_SLICE_THREAD (tdata, 0, "add esp, 8");
	    OUTPUT_SLICE_INFO_THREAD (tdata, "");
        }
	if (iter->second.state == RWLOCK_WRITE_LOCKED && iter->second.pids.find(tdata->record_pid) != iter->second.pids.end()) { 
	    LPRINT ("calling pthread_rwlock_wrlock on lock 0x%x\n", iter->first);
	    OUTPUT_SLICE_THREAD (tdata, 0, "push 0x%x", iter->first);
	    OUTPUT_SLICE_INFO_THREAD (tdata, "");
	    OUTPUT_SLICE_THREAD (tdata, 0, "push 0x%lx", recall_funcs->rwlock_wrlock);
	    OUTPUT_SLICE_INFO_THREAD (tdata, "");
	    OUTPUT_SLICE_THREAD (tdata, 0, "call pthread_rwlock_wrlock_shim");
	    OUTPUT_SLICE_INFO_THREAD (tdata, "");
	    OUTPUT_SLICE_THREAD (tdata, 0, "add esp, 8");
	    OUTPUT_SLICE_INFO_THREAD (tdata, "");
        }
    }
#endif
}

void track_rwlock_rdlock (int retval)
{
    if (retval != 0) {
        fprintf (stderr, "---pthread_rwlock_rdlock has non-zero return %d\n", retval);
        return;
    }
    ADDRINT rwlock = current_thread->pthread_info.mutex_info_cache.mutex;
    LPRINT ("record pid %d, rwlock %p rdlock\n", current_thread->record_pid, (void*) rwlock);
    if (active_rwlock.find(rwlock) == active_rwlock.end()) {
	struct rwlock_state state;
        state.readers.insert (current_thread->record_pid);
        state.is_write_locked = 0;
        state.write_lock_pid = 0;
	active_rwlock[rwlock] = state;
    }  else {
	struct rwlock_state& state = active_rwlock[rwlock];
	if (state.is_write_locked) {
	    fprintf (stderr, "[ERROR] different locker so not a recursive lock (rwlock rdlock): %x, previous pid %d current pid %d\n", rwlock, state.write_lock_pid, current_thread->record_pid);
	}
        state.readers.insert (current_thread->record_pid);
    }
}

void track_rwlock_wrlock (int retval)
{
    if (retval != 0) {
        fprintf (stderr, "---pthread_rwlock_wrlock has non-zero return %d\n", retval);
        return;
    }
    ADDRINT rwlock = current_thread->pthread_info.mutex_info_cache.mutex;
    LPRINT ("record pid %d, rwlock %p wrlock\n", current_thread->record_pid, (void*) rwlock);
    if (active_rwlock.find(rwlock) == active_rwlock.end()) {
	struct rwlock_state state;
        state.readers.insert (current_thread->record_pid);
        state.is_write_locked = 1;
        state.write_lock_pid = current_thread->record_pid;
	active_rwlock[rwlock] = state;
    }  else {
	struct rwlock_state& state = active_rwlock[rwlock];
	if (state.is_write_locked || state.readers.size() > 0) {
	    fprintf (stderr, "[ERROR] different locker so not a recursive lock (rwlock rdlock): %x, previous pid %d current pid %d, reader count %d\n", rwlock, state.write_lock_pid, current_thread->record_pid, state.readers.size());
	}
        state.is_write_locked = 1;
        state.write_lock_pid = current_thread->record_pid;
    }
}

void track_rwlock_unlock (int retval) 
{
    if (retval != 0) { 
        fprintf (stderr, "---pthread_rwlock_unlock has non-zero return %d\n", retval);
        return;
    }
    ADDRINT rwlock = current_thread->pthread_info.mutex_info_cache.mutex;
    LPRINT ("record pid %d, rwlock unlock %p\n", current_thread->record_pid, (void*) rwlock);
    struct rwlock_state& state = active_rwlock[rwlock];
    if (state.is_write_locked) { 
        if (state.write_lock_pid != current_thread->record_pid) {
            fprintf (stderr, "[ERROR] release a rwlock_wrlock without holding it? could just be a weird thread scheduling in replay\n");
        } else {
            state.is_write_locked = 0;
            state.write_lock_pid = 0;
        }
    } else { 
        state.readers.erase (current_thread->record_pid);
    }
}

void track_rwlock_destroy (int retval)
{
    if (retval != 0) { 
        fprintf (stderr, "---pthread_rwlock_destroy has non-zero return %d\n", retval);
        return;
    }
    ADDRINT rwlock = current_thread->pthread_info.mutex_info_cache.mutex;
    active_rwlock.erase (rwlock);
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

    //rwlock states
    for (map<ADDRINT, struct rwlock_state>::iterator iter = active_rwlock.begin(); iter != active_rwlock.end(); ++iter) { 
        if (iter->second.is_write_locked && iter->second.write_lock_pid == tdata->record_pid) {
            OUTPUT_MAIN_THREAD (tdata, "mov eax, 0x%x", pthread_operation_addr["pthread_rwlock_wrlock"]);
            OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
            OUTPUT_MAIN_THREAD (tdata, "call eax /*pthread_rwlock_wrlock*/");
            OUTPUT_MAIN_THREAD (tdata, "add esp, 4");
        } else if (iter->second.readers.count (tdata->record_pid)) {
            OUTPUT_MAIN_THREAD (tdata, "mov eax, 0x%x", pthread_operation_addr["pthread_rwlock_rdlock"]);
            OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
            OUTPUT_MAIN_THREAD (tdata, "call eax /*pthread_rwlock_rdlock*/");
            OUTPUT_MAIN_THREAD (tdata, "add esp, 4");
        }
    }


    //we probably don't need to reconstruct the wait states, as if the thread is waiting, it will eventually call the pthread function in the eglibc and we fixed the state there

    OUTPUT_MAIN_THREAD (tdata, "pop eax /*start to re-create pthread states*/"); //used for indirect calls
    OUTPUT_MAIN_THREAD (tdata, "popfd /*start to re-create pthread states*/");
}

