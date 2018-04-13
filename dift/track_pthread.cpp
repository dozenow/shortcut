#include "track_pthread.h"
#include <map>
using namespace std;

#define LPRINT(x,...)

extern struct thread_data* current_thread;

// Synchronization data structures that may need to be recreated
map<ADDRINT, struct mutex_state> active_mutex; 
map<ADDRINT, struct rwlock_state> active_rwlock; 

//the key is the address of conditional variable or tid
map<ADDRINT, struct wait_state*> active_wait; //I need to replace this with a thread-safe STL library

void track_pthread_mutex_params_1 (ADDRINT mutex) 
{
    current_thread->pthread_info.mutex_info_cache.mutex = mutex;
}

void track_pthread_mutex_lock ()
{
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    LPRINT ("record pid %d, mutex lock %p\n", current_thread->record_pid, (void*) mutex);
    if (active_mutex.find(mutex) == active_mutex.end()) {
	struct mutex_state state;
	state.lock_count = 1; // Use this to handle recursive locks
	state.pid = current_thread->record_pid;
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

void track_pthread_mutex_trylock (ADDRINT retval)
{
    LPRINT ("record pid %d: retval %d\n", current_thread->record_pid, retval);
    if (retval == 0) track_pthread_mutex_lock ();
}

void track_pthread_mutex_unlock ()
{   
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    LPRINT ("record pid %d, mutex unlock %p\n", current_thread->record_pid, (void*) mutex);
    struct mutex_state& state = active_mutex[mutex];
    if (state.pid == current_thread->record_pid) {
	state.lock_count--;
	if (state.lock_count == 0) state.pid = 0;
    }
    LPRINT ("\tpid %d count %d\n", state.pid, state.lock_count);
}

void track_pthread_mutex_destroy ()
{
    ADDRINT mutex = current_thread->pthread_info.mutex_info_cache.mutex;
    active_mutex.erase (mutex);
}

void track_pthread_rwlock_wrlock ()
{
    ADDRINT rwlock = current_thread->pthread_info.mutex_info_cache.mutex;
    LPRINT ("pid %d write locking %x\n", current_thread->record_pid, rwlock);
    struct rwlock_state& state = active_rwlock[rwlock];
    if (state.state == RWLOCK_WRITE_LOCKED) {  
	fprintf (stderr, "[ERROR] we are not handling recursive rwlocks\n");
    }
    state.state = RWLOCK_WRITE_LOCKED;
    state.pids.insert(current_thread->record_pid);
}

void track_pthread_rwlock_rdlock ()
{
    ADDRINT rwlock = current_thread->pthread_info.mutex_info_cache.mutex;
    LPRINT ("pid %d read locking %x\n", current_thread->record_pid, rwlock);
    struct rwlock_state& state = active_rwlock[rwlock];
    if (state.pids.find(current_thread->record_pid) != state.pids.end()) {  
	fprintf (stderr, "[ERROR] we are not handling recursive rwlocks\n");
    }
    state.state = RWLOCK_READ_LOCKED;
    state.pids.insert(current_thread->record_pid);
}

void track_pthread_rwlock_unlock ()
{
    ADDRINT rwlock = current_thread->pthread_info.mutex_info_cache.mutex;
    LPRINT ("pid %d unlocking %x\n", current_thread->record_pid, rwlock);
    struct rwlock_state& state = active_rwlock[rwlock];
    if (state.pids.find(current_thread->record_pid) == state.pids.end()) {  
	fprintf (stderr, "[ERROR] cannot find rwlock being unlocked\n");
    } else {
	state.pids.erase(current_thread->record_pid);
	if (state.pids.empty()) {
	    state.state = RWLOCK_UNLOCKED;
	}
    }
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

void track_pthread_cond_wait_before (ADDRINT cond, ADDRINT mutex)
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    cache->mutex = mutex;
    cache->cond = cond;
    LPRINT ("record pid %d before cond_wait lock %p cond %p\n", current_thread->record_pid, (void*)mutex, (void*) cond);
    // We are releasing the lock
    struct mutex_state& state = active_mutex[mutex];
    if (state.pid == current_thread->record_pid) {
	state.lock_count = 0;
	state.pid = 0;
    } else {
	fprintf (stderr, "Pid %d calling cond_wait without mutex? %lx\n", current_thread->record_pid, (u_long) mutex);
    }
}

void track_pthread_cond_wait_after (void) 
{
    struct wait_info_cache *cache = &current_thread->pthread_info.wait_info_cache;
    LPRINT ("record pid %d, after cond_wait lock %p, cond %p\n", current_thread->record_pid, (void*)cache->mutex, (void*) cache->cond);
    // We reacquired the lock
    struct mutex_state& state = active_mutex[cache->mutex];
    state.lock_count = 1;
    state.pid = current_thread->record_pid;
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

void sync_pthread_state (struct thread_data* tdata, struct pthread_funcs* recall_funcs)
{
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
}

// Mostly the same, but writes to main c file instead of slice file - doesn't wakup when done
void sync_my_pthread_state (struct thread_data* tdata, struct pthread_funcs* recall_funcs)
{
    for (map<ADDRINT, struct mutex_state>::iterator iter = active_mutex.begin(); iter != active_mutex.end(); ++iter) { 
        if (iter->second.lock_count > 0 && iter->second.pid == tdata->record_pid) { 
	    for (int i = 0; i < iter->second.lock_count; i++) {
		LPRINT ("calling pthread_mutex_lock on lock 0x%x\n", iter->first);
		OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
		OUTPUT_MAIN_THREAD (tdata, "push 0x%lx", recall_funcs->mutex_lock);
		OUTPUT_MAIN_THREAD (tdata, "call pthread_mutex_lock_shim");
		OUTPUT_MAIN_THREAD (tdata, "add esp, 8");
	    }
        }
    }

    for (map<ADDRINT, struct rwlock_state>::iterator iter = active_rwlock.begin(); iter != active_rwlock.end(); ++iter) { 
	if (iter->second.state == RWLOCK_READ_LOCKED && (iter->second.pids.find(tdata->record_pid) != iter->second.pids.end())) { 
	    LPRINT ("calling pthread_rwlock_rdlock on lock 0x%x\n", iter->first);
	    OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
	    OUTPUT_MAIN_THREAD (tdata, "push 0x%lx", recall_funcs->rwlock_rdlock);
	    OUTPUT_MAIN_THREAD (tdata, "call pthread_rwlock_rdlock_shim");
	    OUTPUT_MAIN_THREAD (tdata, "add esp, 8");
        }
	if (iter->second.state == RWLOCK_WRITE_LOCKED && iter->second.pids.find(tdata->record_pid) != iter->second.pids.end()) { 
	    LPRINT ("calling pthread_rwlock_wrlock on lock 0x%x\n", iter->first);
	    OUTPUT_MAIN_THREAD (tdata, "push 0x%x", iter->first);
	    OUTPUT_MAIN_THREAD (tdata, "push 0x%lx", recall_funcs->rwlock_wrlock);
	    OUTPUT_MAIN_THREAD (tdata, "call pthread_rwlock_wrlock_shim");
	    OUTPUT_MAIN_THREAD (tdata, "add esp, 8");
        }
    }
}

