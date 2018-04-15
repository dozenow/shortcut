#include <sys/types.h>

#ifndef __USE_LARGEFILE64
#  define __USE_LARGEFILE64
#endif
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <sys/prctl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
// Note assert requires locale, which does not work with our hacked libc - don't use it */

#include "../dift/recheck_log.h"
#include "taintbuf.h"

#define REORDERING

static struct go_live_clock* go_live_clock;

#define MAX_THREAD_NUM 99

#define PRINT_DEBUG
#define PRINT_VALUES
#define PRINT_TO_LOG
//#define SLICE_VM_DUMP
//#define PRINT_SCHEDULING
//#define PRINT_TIMING

#ifdef PRINT_VALUES
static char logbuf[4096];
#endif

#define SIGPROCMAKS_HACK
// This pauses for a while to let us see what went wrong
#define DELAY
//#define DELAY sleep(2);
#ifdef PRINT_TIMING
unsigned long long success_syscalls[512];
unsigned long long failed_syscalls[512];
unsigned long long success_functions[512];
struct timeval global_start_time_tv;
struct timeval global_end_time_tv;
struct timeval global_start_time_tv_func;
struct timeval global_end_time_tv_func;

inline void start_timing (void) 
{ 
    syscall(SYS_gettimeofday, &global_start_time_tv, NULL);
}

inline void end_timing (int syscall_num, int retval) 
{ 
    unsigned long time;
    syscall (SYS_gettimeofday, &global_end_time_tv, NULL);
    time = global_end_time_tv.tv_usec;
    if (global_end_time_tv.tv_usec < global_start_time_tv.tv_usec) {
        time += 1000000;
    }
    time -= global_start_time_tv.tv_usec;
    if (retval >= 0) { 
        success_syscalls[syscall_num] += time;
    } else { 
        failed_syscalls[syscall_num] += time;
    }
}

inline void start_timing_func (void) 
{ 
    syscall(SYS_gettimeofday, &global_start_time_tv_func, NULL);
}

inline void end_timing_func (int syscall_num) 
{ 
    unsigned long time;
    syscall (SYS_gettimeofday, &global_end_time_tv_func, NULL);
    time = global_end_time_tv_func.tv_usec;
    if (global_end_time_tv_func.tv_usec < global_start_time_tv_func.tv_usec) {
        time += 1000000;
    }
    time -= global_start_time_tv_func.tv_usec;
    success_functions[syscall_num] += time;
}

inline void print_timings (void)
{
    int i = 0;
    struct timeval tv;

    syscall (SYS_gettimeofday, &tv, NULL);
    fprintf (stderr, "successed syscalls %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
    for (i=0; i<512; ++i) { 
        if (success_syscalls[i]) { 
            fprintf (stderr, "%d:%llu\n", i, success_syscalls[i]);
        }
    }
    fprintf (stderr, "failed syscalls\n");
    for (i=0; i<512; ++i) { 
        if (failed_syscalls[i]) { 
            fprintf (stderr, "%d:%llu\n", i, failed_syscalls[i]);
        }
    }
}
#else
#define start_timing(x)
#define end_timing(x,y)
#define start_timing_func(x)
#define end_timing_func(x)
#endif

static char buf[8*1024*1024];
static char tmpbuf[1024*1024];
static char taintbuf_filename[256];
#ifdef PRINT_VALUES
static char slicelog_filename[256];
#endif
static char* bufptr = buf;

struct cfopened {
    int is_open_cache_file;
    struct open_retvals orv;
    loff_t verified_pos;
};

#define MAX_FDS 4096
static struct cfopened *cache_files_opened; 
static struct cfopened cache_files_opened_content[MAX_FDS]; //one of these structures will be shared by all threads; in the future we may put this into a shared map region

static char taintbuf[1024*1024];
static u_long taintndx = 0;
static u_long last_clock = 0;

static void add_to_taintbuf (struct recheck_entry* pentry, short rettype, void* values, u_long size)
{
    if (taintndx + sizeof(struct taint_retval) + size > sizeof(taintbuf)) {
	fprintf (stderr, "taintbuf full\n");
	abort();
    }
    struct taint_retval* rv = (struct taint_retval *) &taintbuf[taintndx];
    rv->syscall = pentry->sysnum;
    rv->clock = pentry->clock;
    rv->rettype = rettype;
    rv->size = size;
    taintndx += sizeof (struct taint_retval);
    memcpy (&taintbuf[taintndx], values, size);
    taintndx += size;
}

static int dump_taintbuf (u_long diverge_type, u_long diverge_ndx)
{
    long rc;
    int i;

    if (go_live_clock == NULL) { 
        fprintf (stderr, "cannot dump_taintbuf\n");
        return -1;
    }

    // We need to dump ALL the taintbufs for every slice here - this will only work 
    // for multithreaded apps - not for multiprocess.
    for (i = 0; i < go_live_clock->num_threads; i++) {
	char dump_filename[256];
	struct taintbuf_hdr hdr;
	int fd;

	if (go_live_clock->process_map[i].taintbuf && *go_live_clock->process_map[i].taintndx) {
	    sprintf (dump_filename, "%s%d", taintbuf_filename, go_live_clock->process_map[i].record_pid);
	    fd = open (dump_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	    if (fd < 0) {
		fprintf (stderr, "Cannot open taint buffer dump file, filename %s\n", dump_filename);
		return fd;
	    }
	    
	    hdr.diverge_type = diverge_type;
	    hdr.diverge_ndx = diverge_ndx;
	    hdr.last_clock = last_clock;
	    rc = write (fd, &hdr, sizeof(hdr));
	    if (rc != sizeof(hdr)) {
		fprintf (stderr, "Tried to write %d byte header to taint buffer file, rc=%ld\n", sizeof(hdr), rc);
		return -1;
	    }

	    rc = write (fd, go_live_clock->process_map[i].taintbuf, *go_live_clock->process_map[i].taintndx);
	    if (rc != *go_live_clock->process_map[i].taintndx) {
		fprintf (stderr, "Tried to write %ld bytes to taint buffer file, rc=%ld\n", 
			 *go_live_clock->process_map[i].taintndx, rc);
		return -1;
	    }

	    close (fd);
	}
    }

    return 0;
}

void recheck_start(char* filename, void* clock_addr, pid_t record_pid)
{
    int rc, i, fd;
    struct timeval tv;

    start_timing_func ();
    syscall (SYS_gettimeofday, &tv, NULL);
#if 0
    fprintf (stderr, "recheck_start time %ld.%06ld, recheckfile %s, recheckfilename %p(%p), clock_addr %p(%p), %p record pid %d\n", 
	     tv.tv_sec, tv.tv_usec, filename, filename, &filename, clock_addr, &clock_addr, (void*)(*(long*) filename), record_pid);
#endif

    if (clock_addr)
        go_live_clock = clock_addr;
    else {
        fprintf (stderr, "Running a single-threaded program and has no shared clock page?\n");
        go_live_clock = NULL;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
	fprintf (stderr, "Cannot open recheck file\n");
	return;
    }
    rc = read (fd, buf, sizeof(buf));
    if (rc <= 0) {
	fprintf (stderr, "Cannot read recheck file\n");
	return;
    }
    close (fd);

    // Update shared data with taintbuf info
    if (go_live_clock) {
        //try to figure out the cache_files_opened address
        //if there are multi threads, there should be only one shared by all
        if (go_live_clock->cache_file_structure == NULL) { 
           if (__sync_bool_compare_and_swap (&go_live_clock->cache_file_structure, NULL, cache_files_opened_content)) {
               //fprintf (stderr, "This thread sets up the cache_file_opened to address %p, %p\n", go_live_clock->cache_file_structure, cache_files_opened_content);
           }
        } else { 
            //fprintf (stderr, "This thread will use the shared cache_file_opened %p\n", go_live_clock->cache_file_structure);
        }
        cache_files_opened = go_live_clock->cache_file_structure;
        for (i = 0; i < go_live_clock->num_threads; i++) {
            if (go_live_clock->process_map[i].record_pid == record_pid) {
                go_live_clock->process_map[i].taintbuf = taintbuf;
                go_live_clock->process_map[i].taintndx = &taintndx;
                break;
            } 
        }
    } else { 
        cache_files_opened = cache_files_opened_content;
    }

    for (i = 0; i < MAX_FDS; i++) {
	cache_files_opened[i].is_open_cache_file = 0;
    }

    strcpy(taintbuf_filename, filename);
    for (i = strlen(taintbuf_filename)-1; i >= 0; i--) {
	if (taintbuf_filename[i] == '/') {
	    // Will postpend pids for each thread if dumping taint buffer
	    strcpy (&taintbuf_filename[i+1], "taintbuf.");
	    break;
	}
    }

#ifdef PRINT_VALUES
#ifdef PRINT_TO_LOG
    strcpy(slicelog_filename, filename);
    for (i = strlen(slicelog_filename)-1; i >= 0; i--) {
	if (slicelog_filename[i] == '/') {
	    // This will leave the pid appended to filename
	    memcpy (slicelog_filename+i+1, "slicelg", 7); 
	    break;
	}
    }
    fd = open (slicelog_filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);    
    if (fd < 0) {
	fprintf (stderr, "Error opening slice log %s\n", slicelog_filename);
    } else {
	close (fd);
    }
#endif
#endif
#ifdef PRINT_TIMING
    memset (success_syscalls, 0, sizeof(unsigned long long)*512);
    memset (failed_syscalls, 0, sizeof(unsigned long long)*512);
    memset (success_functions, 0, sizeof(unsigned long long)*512);
#endif
    end_timing_func (0);
}

#ifdef PRINT_TO_LOG
#define LPRINT(args...) { int fd;					\
	sprintf (logbuf, args);						\
	fd = open (slicelog_filename, O_WRONLY|O_APPEND, 0644);		\
	if (fd >= 0) {							\
	    if (write (fd, logbuf, strlen(logbuf))			\
		!= strlen(logbuf)) {					\
		fprintf (stderr, "cannot write to log %s\n",		\
			 slicelog_filename);				\
	    }								\
	    close (fd);							\
	} else {							\
	    fprintf (stderr, "cannot log to %s\n", slicelog_filename);	\
	}								\
    }
#else
#define LPRINT(x,...)
#endif

#ifdef PRINT_DEBUG
#define DPRINT LPRINT
#else
#define DPRINT(x,...)
#endif

void print_value (u_long foo) 
{
    fprintf (stderr, "print_value: %lu (0x%lx)\n", foo, foo);
}

void exit_slice (long is_ckpt_thread, long retval)
{
#ifdef SLICE_VM_DUMP
    // For debugging memory differeces
    dump_taintbuf (DIVERGE_DEBUG, 0);
#endif
    syscall(350, 1, is_ckpt_thread, retval); // Call into kernel to mark complete slice
    fprintf (stderr, "handle_exit_slice: should not get here\n");
    abort();
}

void handle_mismatch()
{
    //TODO: uncomment these lines
    //dump_taintbuf (DIVERGE_MISMATCH, 0);
    fprintf (stderr, "[MISMATCH] exiting.\n\n\n");
    LPRINT ("[MISMATCH] exiting.\n\n\n");
#ifdef PRINT_VALUES
    fflush (stdout);
#endif
    /*DELAY;
    syscall(350, 2, taintbuf_filename); // Call into kernel to recover transparently
    fprintf (stderr, "handle_mismatch: should not get here\n");
    abort();*/
}

void handle_jump_diverge()
{
    int i;
    dump_taintbuf (DIVERGE_JUMP, *((u_long *) ((u_long) &i + 32)));
    fprintf (stderr, "[MISMATCH] tid %ld control flow diverges at %ld.\n\n\n", syscall (SYS_gettid), *((u_long *) ((u_long) &i + 32)));
#ifdef PRINT_VALUES
    fflush (stderr);
#endif
    DELAY;
    syscall(350, 2, taintbuf_filename); // Call into kernel to recover transparently
    fprintf (stderr, "handle_jump_diverge: should not get here\n");
    abort();
}

void handle_delayed_jump_diverge()
{
    int i;
    dump_taintbuf (DIVERGE_JUMP_DELAYED, *((u_long *) ((u_long) &i + 32)));
    fprintf (stderr, "[MISMATCH] control flow delayed divergence");
#ifdef PRINT_VALUES
    fflush (stderr);
#endif
    DELAY;
    syscall(350, 2, taintbuf_filename); // Call into kernel to recover transparently
    fprintf (stderr, "handle_jump_diverge: should not get here\n");
    abort();
}

void handle_index_diverge(u_long foo, u_long bar, u_long baz, u_long quux)
{
    int i;
    dump_taintbuf (DIVERGE_INDEX, *((u_long *) ((u_long) &i + 32)));
    fprintf (stderr, "[MISMATCH] tid %ld index diverges at 0x%lx.\n\n\n", syscall (SYS_gettid), *((u_long *) ((u_long) &i + 32)));
    DELAY;
    syscall(350, 2, taintbuf_filename); // Call into kernel to recover transparently
    fprintf (stderr, "handle_index_diverge: should not get here\n");
    abort ();
}

static inline void print_opened_files (int max_fd)
{
    int i = 0;
    printf ("----dumping opened files\n");
    for (i = 3; i<=max_fd; ++i) {
        char proclnk[256];
        char filename[256];
        int r = 0;

        sprintf(proclnk, "/proc/self/fd/%d", i);
        r = readlink(proclnk, filename, 255);
        if (r < 0)
        {
            printf ("      file descript %d is not opened\n", i);
        } else { 
            filename[r] = '\0';
            printf ("      file descript %d, filename %s\n", i, filename);
        }
    }

}

static inline void check_retval (const char* name, u_long clock, int expected, int actual) {
    if (actual >= 0){
	if (expected != actual) {
	    fprintf (stderr, "[MISMATCH] retval for %s at clock %ld expected %d ret %d\n", name, clock, expected, actual);
	    LPRINT ("[MISMATCH] retval for %s at clock %ld expected %d ret %d\n", name, clock, expected, actual);
            //if divergence happens on open, check what files are currently opened
            if (!strcmp (name, "open")) { 
                int max = expected > actual?expected:actual;
                print_opened_files (max);
            }
	    handle_mismatch();
	}
    } else {
	if (expected != -1*(errno)) {
	    fprintf (stderr, "[MISMATCH] retval for %s at clock %ld expected %d ret %d\n", name, clock, expected, -1*(errno));
	    handle_mismatch();
	}  
    }
}

void partial_read (struct recheck_entry* pentry, struct read_recheck* pread, char* newdata, char* olddata, int is_cache_file, long total_size) { 
#ifdef PRINT_VALUES
    //only verify bytes not in this range
    int pass = 1;
    LPRINT ("partial read: %d %d %ld\n", pread->partial_read_start, pread->partial_read_end, total_size);
#endif
    if (pread->partial_read_start > 0) { 
        if (memcmp (newdata, olddata, pread->partial_read_start)) {
            printf ("[MISMATCH] read returns different values for partial read: before start\n");
            handle_mismatch();
#ifdef PRINT_VALUES
	    pass = 0;
#endif
        }
    }
    if(pread->partial_read_end > total_size) {
	    printf ("[BUG] partial_read_end out of boundary.\n");
            pread->partial_read_end = total_size;
    }
    if (pread->partial_read_end < total_size) { 
	    if (is_cache_file == 0) {
		    if (memcmp (newdata+pread->partial_read_end, olddata+pread->partial_read_end, total_size-pread->partial_read_end)) {
			    printf ("[MISMATCH] read returns different values for partial read: after end\n");
			    handle_mismatch();
#ifdef PRINT_VALUES
			    pass = 0;
#endif
		    }
	    } else { 
		    //for cached files, we only have the data that needs to be verified
		    if (memcmp (newdata+pread->partial_read_end, olddata+pread->partial_read_start, total_size-pread->partial_read_end)) {
			    printf ("[MISMATCH] read returns different values for partial read: after end\n");
			    handle_mismatch();
#ifdef PRINT_VALUES
			    pass = 0;
#endif
		    }
	    }
    }
    //copy other bytes to the actual address
    memcpy (pread->buf+pread->partial_read_start, newdata+pread->partial_read_start, pread->partial_read_end-pread->partial_read_start);
    add_to_taintbuf (pentry, RETBUF, newdata, total_size);
#ifdef PRINT_VALUES
    if (pass) {
	LPRINT ("partial_read: pass.\n");
    } else {
	LPRINT ("partial_read: verification fails.\n");
    }
#endif
}

long read_recheck (size_t count)
{
    char cachefilename[256];
    int pcachefilefd;
    struct recheck_entry* pentry;
    struct read_recheck* pread;
    u_int is_cache_file = 0;
    size_t use_count;
    int rc, i;
    start_timing_func ();

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pread = (struct read_recheck *) bufptr;
    char* readData = bufptr+sizeof(*pread);
    bufptr += pentry->len;

    if (pread->has_retvals) {
	is_cache_file = *((u_int *)readData);
	readData += sizeof(u_int);
    }
#ifdef PRINT_VALUES
    LPRINT ( "read: has ret vals %d ", pread->has_retvals);
    if (pread->has_retvals) {
	LPRINT ( "is_cache_file: %x ", is_cache_file);
    }
    LPRINT ( "fd %d buf %lx count %d/%d tainted? %d readlen %d returns %ld max %ld clock %lu\n", 
	     pread->fd, (u_long) pread->buf, pread->count, count, pread->is_count_tainted, pread->readlen, pentry->retval, pread->max_bound, pentry->clock);
#endif

    if (pread->is_count_tainted) {
	use_count = count;
    } else {
	use_count = pread->count;
    }

    if ((is_cache_file&IS_PIPE)==IS_PIPE) {
	readData += sizeof(uint64_t) + sizeof(int);
    }
    if ((is_cache_file&CACHE_MASK) && pentry->retval >= 0) {
	struct stat64 st;
	if (!cache_files_opened[pread->fd].is_open_cache_file) {
	    printf ("[BUG] cache file should be opened but it is not, fd should be %d\n", pread->fd);
#ifdef PRINT_VALUES
            //this could happen for mutli-threaded program as the cache_files_opened is not a shared structure between threads: FIXME  laster
	    LPRINT ("[BUG] cache file should be opened but it is not, fd should be %d, clock %lu\n", pread->fd, pentry->clock);
            print_opened_files (pread->fd +3);
#endif
	    handle_mismatch();
	}
        if (!pread->partial_read) {
            if (fstat64 (pread->fd, &st) < 0) {
                LPRINT ("[MISMATCH] cannot fstat file\n");
                handle_mismatch ();
            }
            if (st.st_mtim.tv_sec == cache_files_opened[pread->fd].orv.mtime.tv_sec &&
                    st.st_mtim.tv_nsec == cache_files_opened[pread->fd].orv.mtime.tv_nsec) {
		// Adjust file position for read we didn't do
		if (lseek(pread->fd, pentry->retval, SEEK_CUR) < 0) {
		    LPRINT ("[MISMATCH] lseek after read failed\n");
		    handle_mismatch();
		}
            } else {
                DPRINT ("[WARNING] - read file times mismatch but checking actual file content to see if it still matches\n");
		DPRINT ("[WARNING] - dev %lx ino %lx file system time %ld.%ld cache time %ld.%ld\n", st.st_mtim.tv_sec, st.st_mtim.tv_nsec, 
			cache_files_opened[pread->fd].orv.dev, cache_files_opened[pread->fd].orv.ino,
			cache_files_opened[pread->fd].orv.mtime.tv_sec, cache_files_opened[pread->fd].orv.mtime.tv_nsec);

		start_timing();

		rc = syscall(SYS_read, pread->fd, tmpbuf, use_count);
		check_retval ("read", pentry->clock, pentry->retval, rc);

		sprintf (cachefilename, "/replay_cache/%lx_%lx_%ld_%ld", 
			 cache_files_opened[pread->fd].orv.dev, 
			 cache_files_opened[pread->fd].orv.ino, 
			 cache_files_opened[pread->fd].orv.mtime.tv_sec, 
			 cache_files_opened[pread->fd].orv.mtime.tv_nsec);
		pcachefilefd = syscall (SYS_open, cachefilename, O_RDONLY);
		if (pcachefilefd < 0) {
		    DPRINT ("[INFO] cannot open cache file %s on read time mismatch, pcachefilfd, errno = %d\n", cachefilename, errno);
		    sprintf (cachefilename, "/replay_cache/%lx_%lx", 
			     cache_files_opened[pread->fd].orv.dev, 
			     cache_files_opened[pread->fd].orv.ino);
		    pcachefilefd = syscall (SYS_open, cachefilename, O_RDONLY);
		    if (pcachefilefd < 0) {
			LPRINT ("[MISMATCH] cannot open cache file %s on read time mismatch, pcachefilfd, errno=%d\n", cachefilename, errno);
			handle_mismatch();
		    }
		}

		rc = syscall(SYS_pread64, pcachefilefd, tmpbuf+use_count, use_count, cache_files_opened[pread->fd].verified_pos);
		check_retval ("read (cache file)", pentry->clock, pentry->retval, rc);
		if (rc > 0) cache_files_opened[pread->fd].verified_pos += rc;

		if (syscall(SYS_close, pcachefilefd) != 0) {
		    LPRINT ("[MISMATCH] cannot close cache file on read time mismatch\n");
		    handle_mismatch();
		}

		end_timing (SYS_read, rc);

		if (rc > 0) {
		    if (memcmp (tmpbuf, tmpbuf+use_count, rc)) {
			LPRINT ("[MISMATCH] read returns different values - read/expected:\n");
			for (i = 0; i < rc; i++) {
			    if (tmpbuf[i] != tmpbuf[use_count+i]) LPRINT ("*");
			    LPRINT ("%02x/%02x ", tmpbuf[i]&0xff, readData[i]&0xff);
			    if (i%16 == 15) LPRINT ("\n");
			}
			LPRINT ("\n");
			handle_mismatch();
		    }
		}
            }
        } else {
            //read the new content that will be verified
            start_timing();
            rc = syscall(SYS_read, pread->fd, tmpbuf, use_count);
            end_timing (SYS_read, rc);
	    if (rc != pentry->retval) {
		LPRINT ("[ERROR] retval %d instead of %ld for partial read\n", rc, pentry->retval);
		handle_mismatch();
	    }
	    partial_read (pentry, pread, tmpbuf, (char*)pread+sizeof(*pread)+pread->readlen, 1, rc);
        }
    } else {
	if (pentry->retval > (long) sizeof(tmpbuf)) {
	    LPRINT ("[ERROR] retval %ld is greater than temp buf size %d\n", pentry->retval, sizeof(tmpbuf));
	    handle_mismatch();
	}
	if (use_count > (long) sizeof(tmpbuf)) {
	    LPRINT ("[ERROR] count %d is greater than temp buf size %d\n", use_count, sizeof(tmpbuf));
	    handle_mismatch();
	}
        start_timing();
	rc = syscall(SYS_read, pread->fd, tmpbuf, use_count);
        end_timing (SYS_read, rc);
	if (pread->max_bound > 0) {
	    if (rc > pread->max_bound) {
		LPRINT ("[MISMATCH] read expected up to %d bytes, actually read %ld at clock %ld\n", 
			rc, pread->max_bound, pentry->clock);
		handle_mismatch();
	    } 
	    if (rc > 0) {
		// Read allowed to return different values b/c they are tainted in slice
		// So we copy to the slice address space
		memcpy (pread->buf, tmpbuf, rc);
		add_to_taintbuf (pentry, RETVAL, &rc, sizeof(long));
		add_to_taintbuf (pentry, RETBUF, tmpbuf, rc);
	    }
	} else {
	    check_retval ("read", pentry->clock, pentry->retval, rc);
	    if (!pread->partial_read) {
		if (rc > 0) {
		    if (memcmp (tmpbuf, readData, rc)) {
			LPRINT ("[MISMATCH] read returns different values\n");
			LPRINT ("[MISMATCH] read returns different values - read/expected:\n");
			for (i = 0; i < rc; i++) {
			    if (tmpbuf[i] != readData[i]) LPRINT ("*");
			    LPRINT ("%02x/%02x ", tmpbuf[i]&0xff, readData[i]&0xff);
			    if (i%16 == 15) LPRINT ("\n");
			}
			LPRINT ("\n");
			handle_mismatch();
		    }
		}
	    } else {
		partial_read (pentry, pread, tmpbuf, readData, 0, rc);
	    }
	}
    }
    end_timing_func (SYS_read);
    return pentry->retval;
}

inline void print_buffer (u_char* buffer, int len)
{
    int i;
    LPRINT ("{");
    for (i = 0; i < len; i++) { 
	u_char ch = buffer[i];
	if (ch >= 32 && ch <= 126) {
	    LPRINT ("%c", ch);
	} else {
	    LPRINT ("\\%o", ch);
	}
    }
    LPRINT ("}\n");
}

#ifdef PRINT_DEBUG
inline void print_buffer_hex (u_char* buffer, int len)
{
    int i;
    LPRINT ("{");
    for (i = 0; i < len; i++) { 
	LPRINT ("%02x", buffer[i]);
    }
    LPRINT ("}\n");
}
#endif

#ifdef REORDERING
static u_char reorderbuf[65536];
static u_char* reorderin = reorderbuf;
static u_char* reorderout = reorderbuf;
static int reorderfd = 0;

static int get_message_length (u_char* buffer, int buflen) 
{
    if (buffer[0] == 0x1) {
	if (buflen >= 4) {
	    return 32 + 4 * (*(u_int *)(buffer+4));
	} else {
	    return -1;
	}
    } else {
	return 32;
    }
}

#ifdef PRINT_DEBUG
static void print_reorder_buffer ()
{
    int i;
    u_char* p = reorderout;
    LPRINT ("Reorder buffer:\n");
    while (p < reorderin) {
	int msglen = get_message_length (p, reorderin-p);
	LPRINT ("{");
	for (i = 0; i < msglen; i++) {
	    LPRINT ("%02x", p[i]&0xff);
	}
	LPRINT ("}\n");
	p +=  msglen;
    }
}
#endif

static int is_same_message (u_char* msg1, int len1, u_char* msg2, int len2)
{
    int mlen1 = get_message_length(msg1, len1);
    int mlen2 = get_message_length(msg2, len2);

    if (mlen1 < 0 || mlen2 < 0) {
	LPRINT("is_same_message: len too short\n");
	return 0;
    }
    if (mlen1 != mlen2) return 0;
    if (msg1[0] != msg2[0]) return 0;
    if (msg1[0] == 0x1c || msg1[0] == 0x15) {
	if (memcmp(msg1, msg2, 2) || memcmp(msg1+4, msg2+4, 8) || memcmp (msg1+16, msg2+16, 16)) return 0;
	return 1;
    } else if (msg1[0] == 0xa1) {
	if (memcmp(msg1, msg2, 2) || memcmp(msg1+4, msg2+4, 12) || memcmp (msg1+24, msg2+24, 8)) return 0;
	return 1;
    } else if (msg1[0] != 0x1) {
	// Generic event message
	if (memcmp(msg1, msg2, 2) || memcmp(msg1+4, msg2+4, 28)) return 0;
	return 1;
    } else {
	// Response should be in order
	return 1;
    }
}

static int has_different_message (u_char* buf1, int len1, u_char* buf2, int len2, int* poffset)
{
    *poffset = 0;
    do {
	int mlen1 = get_message_length(buf1+*poffset, len1-*poffset);
	int mlen2 = get_message_length(buf2+*poffset, len2-*poffset);
	if (mlen1 < 0 || mlen2 < 0) {
	    return 1;
	}
	if (mlen1 != mlen2) {
	    return 1;
	}
	if (!is_same_message(buf1+*poffset, len1-*poffset, buf2+*poffset, len2-*poffset)) {
	    return 1;
	}
	*poffset += mlen1;
    } while (*poffset < len2);
    return 0;
}

static u_char* have_matching_message (u_char* msg, int len)
{
    u_char* p = reorderout;
    while (p < reorderin) {
	int msglen = get_message_length (p, reorderin-p);
	if (is_same_message (p, reorderin-p, msg, len)) return p;
	p += msglen;
    }
    return NULL;
}

static void reorder_sequence (u_char* msg, u_char* reference, int len)
{
    int bytes_processed = 0;
    while (bytes_processed < len) {
	if (msg[bytes_processed+2] != reference[bytes_processed+2]) {
	    LPRINT ("Sequence # %d observed - changed to %d\n", msg[bytes_processed+2], reference[bytes_processed+2]);
	    msg[bytes_processed+2] = reference[bytes_processed+2];	
	}
	int msglen = get_message_length (msg+bytes_processed, len-bytes_processed);
	if (msglen <= 0) break;
	bytes_processed += msglen;
    } 
}

#endif

long recv_recheck ()
{
    struct recheck_entry* pentry;
    struct recv_recheck* precv;
#ifdef REORDERING
    u_char* match;
#endif
    long rc;
    int offset, i;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    precv = (struct recv_recheck *) bufptr;
    char* recvData = bufptr + sizeof(struct recv_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("recv: sockfd %d buf %p len %d flags %d returns %ld clock %lu buffer offset %ld\n", 
	    precv->sockfd, precv->buf, precv->len, precv->flags, pentry->retval, pentry->clock, (u_long) precv - (u_long) buf);
#endif

    if (pentry->retval == -EAGAIN) {
	errno = EAGAIN;
	return -1;
    }

    u_long block[6];
    block[0] = precv->sockfd;

    // Keep receiving until we get enough bytes
    u_long bytes_received = 0;
    do {
	block[1] = (u_long) precv->buf + bytes_received;
	if (pentry->retval > 0 && pentry->retval - bytes_received < precv->len) {
	    block[2] = pentry->retval - bytes_received;
	} else {
	    block[2] = precv->len;
	}
	block[3] = precv->flags;

	int tries = 0;
	do {
	    start_timing();
	    rc = syscall(SYS_socketcall, SYS_RECV, &block);
	    DPRINT ("recv: returns %ld errno %d\n", rc, errno);
	    end_timing (SYS_socketcall, rc);
	    if (rc == -1 && errno == 11 && pentry->retval > 0) {
		tries++;
		DPRINT ("recv: try again?\n");
#ifdef REORDERING
#ifdef PRINT_DEBUG
		if (bytes_received > 0) {
		    DPRINT ("have so far: ");
		    print_buffer_hex (precv->buf, bytes_received);
		} 
		DPRINT ("want:        ");
		print_buffer_hex ((u_char *) recvData+bytes_received, pentry->retval-bytes_received);
		print_reorder_buffer();
		if (have_matching_message ((u_char *) recvData+bytes_received, pentry->retval-bytes_received)) {
		    DPRINT ("matching message found\n");
		}
		DPRINT ("reorderin: %lx reorderout %lx reorderout[0] %02x recvData[] %02x\n", (u_long) reorderin, (u_long) reorderout, reorderout[0], recvData[bytes_received]);
#endif
		match = have_matching_message((u_char *) recvData+bytes_received, pentry->retval-bytes_received);
		if (match != NULL) {
		    DPRINT ("saved it from before\n");
		    int msglen = get_message_length (match, (u_long) reorderin - (u_long) match);
		    DPRINT ("message length is %d\n", msglen);
		    memcpy (precv->buf+bytes_received, match, msglen);
		    memcpy (precv->buf+bytes_received+2, recvData+bytes_received+2, 2); // Seqeunce # from X protocol
		    memset (match, 0, msglen); // Mark message as used
		    while (*reorderout == '\0' && reorderout != reorderin) reorderout++; // Garbage collect old messages
		    rc = msglen;
		} else {
#endif
		    LPRINT ("recv: sleeping for %d us\n", 500*(2<<(tries-1)));
		    usleep (500*(2<<(tries-1)));
#ifdef REORDERING
		}
#endif
	    }
	} while (rc == -1 && errno == 11 && pentry->retval > 0 && tries <= 10);

	if (rc <= 0) break;
	bytes_received += rc;

#ifdef REORDERING	
	/*** have we received a message out of order? */
	/* XXX - Should specify which syscalls can be reordered and patter for recognizing ooo messages */
	while (pentry->clock >= 762000 && bytes_received > 0 && has_different_message ((u_char *) recvData, pentry->retval, (u_char *) precv->buf, bytes_received, &offset)) {
	    int i, msglen;
#ifdef PRINT_DEBUG
	    DPRINT ("buffer has spurious message\n");
	    print_buffer_hex (precv->buf+offset, bytes_received-offset);
#endif	    
	    msglen = get_message_length (precv->buf+offset, bytes_received-offset);
	    if (msglen > 0) {
		if (reorderfd == 0) {
		    reorderfd = precv->sockfd;
		} else if (reorderfd != precv->sockfd) {
		    LPRINT ("[ERROR]: cannot handle multiple reorderfds\n");
		    handle_mismatch();
		}
		if (bytes_received-offset < msglen) {
		    int tries = 0;
		    DPRINT ("Partial message is in the buffer\n");
		    memcpy (reorderin, precv->buf+offset, bytes_received-offset);
		    while (bytes_received-offset < msglen && tries < 10) {
			block[1] = (u_long) (reorderin + bytes_received-offset);
			block[2] = msglen - (bytes_received-offset);
			block[3] = 0;
			start_timing();
			rc = syscall(SYS_socketcall, SYS_RECV, &block);
			DPRINT ("reorder recv: returns %ld errno %d\n", rc, errno);
			end_timing (SYS_socketcall, rc);	
			tries++;
			if (rc == -1 && errno == 11) {
			    LPRINT ("recv reorder: sleeping for %d us\n", 500*(2<<(tries-1)));
			    usleep (500*(2<<(tries-1)));
			} else if (rc < 0) {
			    LPRINT ("Cannot get more bytes on reorder recv, rc=%ld, errno=%d\n", rc, errno);
			    handle_mismatch();
			} else {
			    bytes_received += rc;
			}
		    }
		} else {
		    memcpy (reorderin, precv->buf+offset, msglen);
		    for (i = 0; i < bytes_received-offset-msglen; i++) {
			((u_char *)precv->buf)[i+offset] = ((u_char *)precv->buf)[i+msglen+offset];
		    }
		}
	    } else {
		LPRINT ("Cannot determine message length\n");
		handle_mismatch();
	    }

	    reorderin += msglen;
	    bytes_received -= msglen;
	}
#endif
    } while (bytes_received < pentry->retval || pentry->retval < 0);

    if (rc < 0) check_retval ("recv", pentry->clock, pentry->retval, rc);

    if (rc > 0) {
#ifdef PRINT_DEBUG
	print_buffer_hex (precv->buf, pentry->retval);
	print_buffer_hex ((u_char *) recvData, pentry->retval);
#endif
#ifdef REORDERING
	reorder_sequence (precv->buf, (u_char *) recvData, pentry->retval);
#endif
	DPRINT ("About to compare %p and %p partial_read_cnt %d\n", precv->buf, recvData, precv->partial_read_cnt);
	if (precv->partial_read_cnt > 0) {
	    u_long bytes_so_far = 0;
	    int i;
	    for (i = 0; i < precv->partial_read_cnt; i++) {
		if (precv->partial_read_starts[i] > bytes_so_far) {
		    if (memcmp (precv->buf+bytes_so_far, recvData+bytes_so_far, precv->partial_read_starts[i]-bytes_so_far)) {
			int j;
			LPRINT ("[MISMATCH] partial recv %lu start %d returns different values - read/expected:\n", pentry->clock, i);
			for (j = bytes_so_far; j < precv->partial_read_starts[i]; j++) {
			    if (((char *)precv->buf)[j] != recvData[j]) {
				LPRINT ("%d ", j);
			    }
			}
			LPRINT ("\n");
			handle_mismatch();
		    }
		} 
		bytes_so_far = precv->partial_read_ends[i];
	    }
	    if (precv->partial_read_ends[precv->partial_read_cnt-1] < pentry->retval) {
		if (memcmp (precv->buf+precv->partial_read_ends[precv->partial_read_cnt-1], 
			    recvData+precv->partial_read_ends[precv->partial_read_cnt-1], 
			    pentry->retval-precv->partial_read_ends[precv->partial_read_cnt-1])) {
		    LPRINT ("[MISMATCH] partial recv %lu end returns different values - read/expected:\n", pentry->clock);
		    for (i = precv->partial_read_ends[precv->partial_read_cnt-1]; i < pentry->retval; i++) {
			if (((char *)precv->buf)[i] != recvData[i]) LPRINT ("%d ", i);
		    }
		    handle_mismatch();
		}
	    }
	    add_to_taintbuf (pentry, RETBUF, precv->buf, pentry->retval);
	} else {
	    if (memcmp (precv->buf, recvData, pentry->retval)) {
		LPRINT ("[MISMATCH] recv %lu returns different values - read/expected:\n", pentry->clock);
		if (memcmp (precv->buf, recvData, pentry->retval)) {
		    for (i = 0; i < pentry->retval; i++) {
			LPRINT ("%02x/%02x ", ((char *)precv->buf)[i]&0xff, recvData[i]&0xff);
			if (i%16 == 15) LPRINT ("\n");
		    }
		    LPRINT ("\n");
		    for (i = 0; i < pentry->retval; i++) {
			if (((char *)precv->buf)[i] != recvData[i]) LPRINT ("%d ", i);
		    }
		    LPRINT ("\n");
		    handle_mismatch();
		}
	    }
	}
    }
    end_timing_func (SYS_socketcall);

    return pentry->retval;
}

long recvfrom_recheck ()
{
    struct recheck_entry* pentry;
    struct recvfrom_recheck* precv;
    struct sockaddr* ret_sockaddr = NULL;
    socklen_t ret_addrlen = 0;
    long rc;
    int i;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    precv = (struct recvfrom_recheck *) bufptr;
    if (precv->addrlen_value) {
        ret_sockaddr = (struct sockaddr*) (bufptr + sizeof (struct recvfrom_recheck));
        ret_addrlen= precv->addrlen_value;
    }
    char* recvData = bufptr + sizeof(struct recvfrom_recheck) + precv->addrlen_value;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("recvfrom: sockfd %d buf %p len %d flags %d returns %ld clock %lu buffer offset %ld, returned addrlen %d\n", 
	    precv->sockfd, precv->buf, precv->len, precv->flags, pentry->retval, pentry->clock, (u_long) precv - (u_long) buf, precv->addrlen_value);
#endif

    if (pentry->retval == -EAGAIN) {
	errno = EAGAIN;
	return -1;
    }

    u_long block[6];
    block[0] = precv->sockfd;

    // Keep receiving until we get enough bytes
    u_long bytes_received = 0;
    do {
	block[1] = (u_long) precv->buf + bytes_received;
	if (pentry->retval > 0 && pentry->retval - bytes_received < precv->len) {
	    block[2] = pentry->retval - bytes_received;
	} else {
	    block[2] = precv->len;
	}
	block[3] = precv->flags;
        block[4] = (u_long) tmpbuf;
        block[5] = (u_long) &ret_addrlen;

	int tries = 0;
	do {
	    start_timing();
	    rc = syscall(SYS_socketcall, SYS_RECV, &block);
	    DPRINT ("recvfrom: returns %ld errno %d\n", rc, errno);
	    end_timing (SYS_socketcall, rc);
	    if (rc == -1 && errno == 11 && pentry->retval > 0) {
		tries++;
		DPRINT ("recvfrom: try again?\n");
		    usleep (1000);
	    }
	} while (rc == -1 && errno == 11 && pentry->retval > 0 && tries <= 5);

	if (rc <= 0) break;
	bytes_received += rc;

    } while (bytes_received < pentry->retval || pentry->retval < 0);

    if (rc < 0) check_retval ("recvfrom", pentry->clock, pentry->retval, rc);

    if (rc > 0) {
#ifdef PRINT_DEBUG
	print_buffer_hex (precv->buf, pentry->retval);
	print_buffer_hex ((u_char *) recvData, pentry->retval);
#endif

	DPRINT ("About to compare %p and %p partial_read_cnt %d\n", precv->buf, recvData, precv->partial_read_cnt);
	if (precv->partial_read_cnt > 0) {
	    u_long bytes_so_far = 0;
	    int i;
	    for (i = 0; i < precv->partial_read_cnt; i++) {
		if (precv->partial_read_starts[i] > bytes_so_far) {
		    if (memcmp (precv->buf+bytes_so_far, recvData+bytes_so_far, precv->partial_read_starts[i]-bytes_so_far)) {
			int j;
			LPRINT ("[MISMATCH] partial recvfrom %lu start %d returns different values - read/expected:\n", pentry->clock, i);
			for (j = bytes_so_far; j < precv->partial_read_starts[i]; j++) {
			    if (((char *)precv->buf)[j] != recvData[j]) {
				LPRINT ("%d ", j);
			    }
			}
			LPRINT ("\n");
			handle_mismatch();
		    }
		} 
		bytes_so_far = precv->partial_read_ends[i];
	    }
	    if (precv->partial_read_ends[precv->partial_read_cnt-1] < pentry->retval) {
		if (memcmp (precv->buf+precv->partial_read_ends[precv->partial_read_cnt-1], 
			    recvData+precv->partial_read_ends[precv->partial_read_cnt-1], 
			    pentry->retval-precv->partial_read_ends[precv->partial_read_cnt-1])) {
		    LPRINT ("[MISMATCH] partial recvfrom %lu end returns different values - read/expected:\n", pentry->clock);
		    for (i = precv->partial_read_ends[precv->partial_read_cnt-1]; i < pentry->retval; i++) {
			if (((char *)precv->buf)[i] != recvData[i]) LPRINT ("%d ", i);
		    }
		    handle_mismatch();
		}
	    }
	    add_to_taintbuf (pentry, RETBUF, precv->buf, pentry->retval);
	} else {
	    if (memcmp (precv->buf, recvData, pentry->retval)) {
		LPRINT ("[MISMATCH] recvfrom %lu returns different values - read/expected:\n", pentry->clock);
		if (memcmp (precv->buf, recvData, pentry->retval)) {
		    for (i = 0; i < pentry->retval; i++) {
			LPRINT ("%02x/%02x ", ((char *)precv->buf)[i], recvData[i]);
			if (i%16 == 15) LPRINT ("\n");
		    }
		    LPRINT ("\n");
		    for (i = 0; i < pentry->retval; i++) {
			if (((char *)precv->buf)[i] != recvData[i]) LPRINT ("%d ", i);
		    }
		    LPRINT ("\n");
		    handle_mismatch();
		}
	    }
	}
#ifdef PRINT_DEBUG
        LPRINT ("returedn addrlen size is %d\n", ret_addrlen);
        print_buffer_hex ((u_char*) ret_sockaddr, precv->addrlen_value);
        print_buffer_hex ((u_char*) tmpbuf, precv->addrlen_value);
        {
            int i = 0;
            for (; i<ret_addrlen; ++i) {
                LPRINT ("tmp[%d] = %d;\n", i, tmpbuf[i]);
            }
        }
#endif
        //Now compare the returned src_addr and addrlen
        if (precv->addrlen_value > 0) { 
            if (precv->addrlen_value != ret_addrlen || memcmp (tmpbuf, ret_sockaddr, precv->addrlen_value)) { 
                LPRINT ("[MISMATCH] recvfrom has different returned sockaddr or addrlen is different, recorded addrlen %d current addrlen %d\n", precv->addrlen_value, ret_addrlen);
#ifdef PRINT_DEBUG
                print_buffer_hex ((u_char*) tmpbuf, precv->addrlen_value);
                print_buffer_hex ((u_char*) ret_sockaddr, precv->addrlen_value);
#endif
                handle_mismatch();
            }
        }
    }
    end_timing_func (SYS_socketcall);

    return pentry->retval;
}


long recvmsg_recheck ()
{
    struct recheck_entry* pentry;
    struct recvmsg_recheck* precvmsg;
    u_long to_cmp;
    int rc, i;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    precvmsg = (struct recvmsg_recheck *) bufptr;
    char* data = bufptr + sizeof (struct recvmsg_recheck);
    struct msghdr* phdr = (struct msghdr *) data;
    data += sizeof(struct msghdr);
    phdr->msg_iov = (struct iovec *) data;
    data += sizeof(struct iovec)*phdr->msg_iovlen;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("recvmsg: sockfd %d msg %lx flags %x returns %ld partial %d clock %lu\n", 
	    precvmsg->sockfd, (u_long) precvmsg->msg, precvmsg->flags, pentry->retval, 
	    precvmsg->partial_read_cnt, pentry->clock);
#endif

    if (pentry->retval == -EAGAIN) {
	errno = EAGAIN;
	return -1;
    }

#ifdef PRINT_VALUES
    LPRINT ("recvmsg: namelen %d iovlen %d controllen %d\n", 
	    phdr->msg_namelen, phdr->msg_iovlen, phdr->msg_controllen);
#endif

    u_long block[6];
    block[0] = precvmsg->sockfd;
    block[1] = (u_long) phdr;
    block[2] = precvmsg->flags;

    if (pentry->retval > 0) {
	int i, gone_over = 0;
	u_long total = 0;
	DPRINT ("expect %ld bytes\n", pentry->retval);
	for (i = 0; i < phdr->msg_iovlen; i++) {
	    total += phdr->msg_iov[i].iov_len;
	    DPRINT ("bytes buf %d at %x: %ld total %ld\n", i, phdr->msg_iov[i].iov_len, (u_long) phdr->msg_iov[i].iov_base, total);
	    if (gone_over) {
		phdr->msg_iov[i].iov_len = 0;
	    } else {
		if (total > pentry->retval) {
		    phdr->msg_iov[i].iov_len -= (total - pentry->retval);
		    gone_over = 1;
		}
	    }
	    DPRINT ("buf %d: now %d\n", i, phdr->msg_iov[i].iov_len);
	}
    }
	 

    start_timing();
    rc = syscall(SYS_socketcall, SYS_RECVMSG, &block);
    end_timing (SYS_socketcall, rc);

    if (pentry->retval > 0 && rc > 0 && rc < pentry->retval) {
	int tries = 0;
	DPRINT ("recvmsg received %d bytes, expected %ld - iovlen %d base[0] %d\n", rc, pentry->retval, phdr->msg_iovlen, phdr->msg_iov[0].iov_len);
	while (phdr->msg_iovlen == 1 && tries <= 10 && rc < pentry->retval) {
	    long extra_rc = syscall(SYS_read, precvmsg->sockfd, phdr->msg_iov[0].iov_base+rc, pentry->retval-rc);
	    DPRINT ("read returns %ld errno %d\n", extra_rc, errno);
	    if (extra_rc > 0) rc += extra_rc;
#ifdef PRINT_DEBUG
	    DPRINT ("received %ld extra bytes\n", extra_rc);
	    print_buffer (phdr->msg_iov[0].iov_base, rc);
#endif
	    tries++;
	    if (extra_rc == -1 && errno == 11) {
		LPRINT ("recvmsg: sleeping for %d us\n", 500*(2<<(tries-1)));
		usleep (500*(2<<(tries-1)));
	    }
	}
    }    

    check_retval ("recvmsg", pentry->clock, pentry->retval, rc);
    if (rc >= 0) {
	struct recvmsg_retvals* pretvals = (struct recvmsg_retvals *) data;
	data += sizeof(struct recvmsg_retvals);
#ifdef PRINT_VALUES
	LPRINT ("namelen %d controllen %ld flags %x\n", pretvals->msg_namelen, pretvals->msg_controllen,
		pretvals->msg_flags);
	{
	    long to_print;
	    long printed = 0;
	    for (i = 0; i < phdr->msg_iovlen && printed < rc; i++) {
		to_print = rc-printed;
		if (phdr->msg_iov[i].iov_len < to_print) to_print = phdr->msg_iov[i].iov_len;
		print_buffer (phdr->msg_iov[i].iov_base, to_print);
		print_buffer_hex (phdr->msg_iov[i].iov_base, to_print);
		printed += to_print;
	    }
	}
#endif
	if (pretvals->msg_namelen != phdr->msg_namelen) {
	    fprintf (stderr, "recvmsg returns namelen %d instead of %d\n", phdr->msg_namelen, pretvals->msg_namelen);
	    handle_mismatch();
	}
	if (pretvals->msg_controllen != phdr->msg_controllen) {
	    fprintf (stderr, "recvmsg returns controllen %d instead of %ld\n", phdr->msg_controllen, pretvals->msg_controllen);
	    handle_mismatch();
	}
	if (pretvals->msg_flags != phdr->msg_flags) {
	    fprintf (stderr, "recvmsg returns controllen %d instead of %d\n", phdr->msg_flags, pretvals->msg_flags);
	    handle_mismatch();
	}
	if (pretvals->msg_namelen > 0) {
	    if (memcmp(data, phdr->msg_name, phdr->msg_namelen)) {
		fprintf (stderr, "recvmsg returns different name: %s instead of %s\n", data, (char *) phdr->msg_name);
		handle_mismatch();
	    }
	}
	if (pretvals->msg_controllen > 0) {
	    if (memcmp(data, phdr->msg_control, phdr->msg_controllen)) {
		fprintf (stderr, "recvmsg returns different control: %s instead of %s\n", data, (char *) phdr->msg_control);
		handle_mismatch();
	    }
	}
	if (precvmsg->partial_read_cnt > 0) {
	    u_long compared = 0;
	    int j, mismatch = 0;
	    int region_cnt = 0;
	    DPRINT ("First region is %d-%d\n", precvmsg->partial_read_starts[0], 
		    precvmsg->partial_read_ends[0]);
	    for (i = 0; i < phdr->msg_iovlen && compared < rc; i++) {
		for (j = 0; j < phdr->msg_iov[i].iov_len && compared < rc; j++) {
		    if (region_cnt == precvmsg->partial_read_cnt || 
			(compared < precvmsg->partial_read_starts[region_cnt] || 
			 compared >= precvmsg->partial_read_ends[region_cnt])) {
			if (region_cnt < precvmsg->partial_read_cnt && 
			    compared >= precvmsg->partial_read_ends[region_cnt]) {
			    region_cnt++;
			    if (region_cnt == precvmsg->partial_read_cnt) {
				DPRINT ("No more regions\n");
			    } else {
				DPRINT ("Next region is %d-%d\n", precvmsg->partial_read_starts[region_cnt], 
					precvmsg->partial_read_ends[region_cnt]);
			    }
			}
			if (data[compared] != ((char *) phdr->msg_iov[i].iov_base)[j]) {
			    LPRINT("byte %lu iovec %u offset %u differs\n", compared, i, j);
			    mismatch = 1;
			}
		    }
		    tmpbuf[compared] = ((char *) phdr->msg_iov[i].iov_base)[j];
		    compared++;
		}
	    }
	    add_to_taintbuf (pentry, RETBUF, tmpbuf, compared);
	    if (mismatch) handle_mismatch();
	} else {
	    int remaining_data = rc;
	    for (i = 0; i < phdr->msg_iovlen; i++) {
		to_cmp = phdr->msg_iov[i].iov_len;
		if (rc < to_cmp) to_cmp = rc;
		if (memcmp (phdr->msg_iov[i].iov_base, data, to_cmp)) {
		    u_int j;
		    LPRINT ("recvmsg differs in data in iov %d\n", i);
		    print_buffer (phdr->msg_iov[i].iov_base, to_cmp);
		    print_buffer ((u_char *) data, to_cmp);
		    for (j = 0; j < to_cmp; j++) {
			if (((char *) phdr->msg_iov[i].iov_base)[j] != data[j]) {
			    LPRINT ("%d ", j);
			}
		    }
		    LPRINT ("differs\n");
		    handle_mismatch();
		}
		data += to_cmp;
		remaining_data -= to_cmp;
	    }
	}
    }
    end_timing_func (SYS_socketcall);
    return rc;
}

// Copy any tainted values to the input buffer and return it
static inline char* fill_taintedbuf(char* indata, char* slicebuf, u_long len)
{
    u_long i;
    char* tainted = indata;
    char* origbuf = indata + len;

    for (i = 0; i < len; i++) {
	if (tainted[i]) {
	    origbuf[i] = slicebuf[i];
	}
    }

    return origbuf;
}

long write_recheck (size_t count)
{
    struct recheck_entry* pentry;
    struct write_recheck* pwrite;
    char* data;
    int rc;
    size_t use_count;
    char* writedata;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pwrite = (struct write_recheck *) bufptr;
    data = bufptr + sizeof(struct write_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "write: fd %d buf %lx count %d/%d tainted? %d rc %ld clock %lu\n", pwrite->fd, (u_long) pwrite->buf, pwrite->count, count, pwrite->is_count_tainted, pentry->retval, pentry->clock);
#endif
    if (pwrite->fd == 99999) return pwrite->count;  // Debugging fd - ignore
    if (cache_files_opened[pwrite->fd].is_open_cache_file) {
	printf ("[ERROR] Should not be writing to a cache file\n");
	handle_mismatch();
    }
    writedata = fill_taintedbuf (data, (char *) pwrite->buf, pwrite->count);

    if (pwrite->is_count_tainted) {
	use_count = count;
    } else {
	use_count = pwrite->count;
    }

    start_timing();
    rc = syscall(SYS_write, pwrite->fd, writedata, use_count);
    end_timing(SYS_write, rc);
    check_retval ("write", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_write);
    return rc;
}

long writev_recheck ()
{
    struct recheck_entry* pentry;
    struct writev_recheck* pwritev;
    char* data;
    int rc, i;
    struct iovec* piovec;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pwritev = (struct writev_recheck *) bufptr;
    data = bufptr + sizeof(struct writev_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("writev: fd %d iov %p iovcnt %d rc %ld clock %lu\n", pwritev->fd, pwritev->iov, pwritev->iovcnt, pentry->retval, pentry->clock);
#endif
    if (cache_files_opened[pwritev->fd].is_open_cache_file) {
	printf ("[ERROR] Should not be writing to a cache file\n");
	handle_mismatch();
    }
    piovec = (struct iovec *) data;
#ifdef PRINT_VALUES
    for (i = 0; i < pwritev->iovcnt; i++) {
	LPRINT ("writev: iov_len %d is %d\n", i, piovec[i].iov_len);
    }
#endif
    data += pwritev->iovcnt * sizeof(struct iovec);
    for (i = 0; i < pwritev->iovcnt; i++) {
	piovec[i].iov_base = fill_taintedbuf (data, piovec[i].iov_base, piovec[i].iov_len);
	data += piovec[i].iov_len*2;
#ifdef PRINT_VALUES
	print_buffer ((u_char *) piovec[i].iov_base, piovec[i].iov_len);
#endif
    }

    start_timing();
    rc = syscall(SYS_writev, pwritev->fd, piovec, pwritev->iovcnt);
    end_timing(SYS_writev, rc);
    check_retval ("writev", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_writev);
    return rc;
}

long send_recheck ()
{
    struct recheck_entry* pentry;
    struct send_recheck* psend;
    char* data;
    char* psendbuf;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psend = (struct send_recheck *) bufptr;
    data = bufptr + sizeof(struct send_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "send: sockfd %d buf %p len %d flags %d rc %ld clock %lu\n", psend->sockfd, psend->buf, psend->len, psend->flags, pentry->retval, pentry->clock);
#endif

    psendbuf = fill_taintedbuf (data, psend->buf, psend->len);

    u_long block[6];
    block[0] = psend->sockfd;
    block[1] = (u_long) psendbuf;
    block[2] = psend->len;
    block[3] = psend->flags;
    start_timing();
    rc = syscall(SYS_socketcall, SYS_SEND, &block);
    end_timing(SYS_socketcall, rc);
    check_retval ("send", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_socketcall);
    return rc;
}

long sendto_recheck ()
{
    struct recheck_entry* pentry;
    struct sendto_recheck* psend;
    char* data;
    struct sockaddr* dest_addr;
    char* psendbuf;
    char* sockaddrbuf = NULL;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psend = (struct sendto_recheck *) bufptr;
    dest_addr = (struct sockaddr*) (bufptr + sizeof(struct sendto_recheck));
    data = (char*)dest_addr + psend->addrlen * 2;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "sendto: sockfd %d buf %p len %d flags %d rc %ld sockaddr %x addrlen %d clock %lu\n", psend->sockfd, psend->buf, psend->len, psend->flags, pentry->retval, (int )psend->dest_addr, psend->addrlen, pentry->clock);
#endif

    if (psend->dest_addr)
        sockaddrbuf = fill_taintedbuf ((char*) dest_addr, (char*) psend->dest_addr, psend->addrlen);
    psendbuf = fill_taintedbuf (data, psend->buf, psend->len);

#ifdef PRINT_DEBUG
    LPRINT ("sendto sockaddr:\n");
    print_buffer_hex ((u_char*) sockaddrbuf, psend->addrlen);
    LPRINT ("sendto content:\n");
    print_buffer_hex ((u_char*) psendbuf, psend->len);
#endif
    u_long block[6];
    block[0] = psend->sockfd;
    block[1] = (u_long) psendbuf;
    block[2] = psend->len;
    block[3] = psend->flags;
    block[4] = (u_long) sockaddrbuf;
    block[5] = psend->addrlen;
    start_timing();
    rc = syscall(SYS_socketcall, SYS_SENDTO, &block);
    end_timing(SYS_socketcall, rc);
    check_retval ("sendto", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_socketcall);
    return rc;
}

long sendmsg_recheck ()
{
    struct recheck_entry* pentry;
    struct sendmsg_recheck* psendmsg;
    struct msghdr * pmsg;
    char* data;
    u_int i;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psendmsg = (struct sendmsg_recheck *) bufptr;
    data = bufptr + sizeof(struct sendmsg_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "sendmsg: sockfd %d msg %p flags %d rc %ld clock %lu\n", psendmsg->sockfd, psendmsg->msg, psendmsg->flags, pentry->retval, pentry->clock);
#endif

    pmsg = (struct msghdr *) data;
    data += sizeof(struct msghdr);
    pmsg->msg_name = data;
    data += pmsg->msg_namelen;
    pmsg->msg_iov = (struct iovec *) data;
    data += pmsg->msg_iovlen*sizeof(struct iovec);
    for (i = 0; i < pmsg->msg_iovlen; i++) {
#ifdef PRINT_VALUES
	{
	    int j;
	    LPRINT ("sendmsg: iov %d\n", i);
	    for (j = 0; j < pmsg->msg_iov[i].iov_len; j++) {
		LPRINT ("%d", (*(data+pmsg->msg_iov[i].iov_len+j) != 0));
	    }
	    LPRINT ("\n");
	}
#endif	
	pmsg->msg_iov[i].iov_base = fill_taintedbuf (data, pmsg->msg_iov[i].iov_base, pmsg->msg_iov[i].iov_len);
#ifdef PRINT_VALUES
	print_buffer((u_char *) pmsg->msg_iov[i].iov_base, pmsg->msg_iov[i].iov_len);
	print_buffer_hex((u_char *) pmsg->msg_iov[i].iov_base, pmsg->msg_iov[i].iov_len);
#endif
	data += pmsg->msg_iov[i].iov_len*2;
    }
    pmsg->msg_control = fill_taintedbuf (data, pmsg->msg_control, pmsg->msg_controllen);

    u_long block[6];
    block[0] = psendmsg->sockfd;
    block[1] = (u_long) pmsg;
    block[2] = psendmsg->flags;
    start_timing();
    rc = syscall(SYS_socketcall, SYS_SENDMSG, &block);
    end_timing(SYS_socketcall, rc);
    check_retval ("sendmsg", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_socketcall);
    return rc;
}

long open_recheck (int flags, int mode)
{
    struct recheck_entry* pentry;
    struct open_recheck* popen;
    int use_flags, use_mode, rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    popen = (struct open_recheck *) bufptr;
    char* fileName = bufptr+sizeof(struct open_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "open: filename %s flags %x/%x tainted %d mode %x/%x tainted? %d", fileName, popen->flags, flags, popen->is_flags_tainted, popen->mode, mode, popen->is_mode_tainted);
    if (popen->has_retvals) {
	LPRINT ( " dev %ld ino %ld mtime %ld.%ld", popen->retvals.dev, popen->retvals.ino, 
	       popen->retvals.mtime.tv_sec, popen->retvals.mtime.tv_nsec); 
    }
    LPRINT ( " rc %ld clock %lu, bufptr %p, buf %p\n", pentry->retval, pentry->clock, bufptr, buf);
#endif

    if (popen->is_flags_tainted) {
	use_flags = flags;
    } else {
	use_flags = popen->flags;
    }
    if (popen->is_mode_tainted) {
	use_mode = mode;
    } else {
	use_mode = popen->mode;
    }

    start_timing();
    rc = syscall(SYS_open, fileName, use_flags, use_mode);
    end_timing (SYS_open, rc);
    check_retval ("open", pentry->clock, pentry->retval, rc);
    if (rc >= MAX_FDS) abort ();
    if (rc >= 0 && popen->has_retvals) {
	cache_files_opened[rc].is_open_cache_file = 1;
	cache_files_opened[rc].orv = popen->retvals;
	cache_files_opened[rc].verified_pos = 0;
    }
    end_timing_func (SYS_open);
    return rc;
}

long openat_recheck ()
{
    struct recheck_entry* pentry;
    struct openat_recheck* popen;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    popen = (struct openat_recheck *) bufptr;
    char* fileName = bufptr+sizeof(struct openat_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "openat: dirfd %d filename %s flags %x mode %d rc %ld clock %lu\n", popen->dirfd, fileName, popen->flags, popen->mode, pentry->retval, pentry->clock);
#endif
    start_timing();
    rc = syscall(SYS_openat, popen->dirfd, fileName, popen->flags, popen->mode);
    end_timing (SYS_openat, rc);
    check_retval ("openat", pentry->clock, pentry->retval, rc);
    if  (rc >= MAX_FDS) abort ();
    end_timing_func (SYS_openat);
    return rc;
}

long waitpid_recheck ()
{
    struct recheck_entry* pentry;
    struct waitpid_recheck* pwaitpid;
    int status, rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pwaitpid = (struct waitpid_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES 
    LPRINT ("waitpid: pid_t %d status %p val %d options %d clock %lu\n", pwaitpid->pid, pwaitpid->status, pwaitpid->statusval, pwaitpid->options, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_waitpid, pwaitpid->pid, &status, pwaitpid->options);
    end_timing (SYS_waitpid, rc);
    check_retval ("waitpid", pentry->clock, pentry->retval, rc);
    if (rc <= 0) {
	if (status != pwaitpid->statusval) {
	    fprintf (stderr, "waitpid: expected status %d, got %d\n", status, *pwaitpid->status);
	    handle_mismatch();
	}
    }
    end_timing_func (SYS_waitpid);
    return rc;
}

long close_recheck ()
{
    struct recheck_entry* pentry;
    struct close_recheck* pclose;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pclose = (struct close_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES 
    LPRINT ("close: fd %d clock %lu\n", pclose->fd, pentry->clock);
#endif

    if (pclose->fd >= MAX_FDS) abort();
    start_timing();
    rc = syscall(SYS_close, pclose->fd);
    end_timing (SYS_close, rc);
    cache_files_opened[pclose->fd].is_open_cache_file = 0;
    check_retval ("close", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_close);
    return rc;
}

long dup2_recheck ()
{
    struct recheck_entry* pentry;
    struct dup2_recheck* pdup2;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pdup2 = (struct dup2_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES 
    LPRINT ("dup2: oldfd %d newfd %d clock %lu\n", pdup2->oldfd, pdup2->newfd, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_dup2, pdup2->oldfd, pdup2->newfd);
    end_timing (SYS_dup2, rc);
    cache_files_opened[pdup2->newfd].is_open_cache_file = cache_files_opened[pdup2->oldfd].is_open_cache_file;
    check_retval ("dup2", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_dup2);
    return rc;
}

long access_recheck ()
{
    struct recheck_entry* pentry;
    struct access_recheck* paccess;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    paccess = (struct access_recheck *) bufptr;
    char* accessName = bufptr+sizeof(*paccess);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("acccess: mode %d pathname %s rc %ld clock %lu\n", paccess->mode, accessName, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_access, accessName, paccess->mode);
    end_timing(SYS_access, rc);
    check_retval ("access", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_access);
    return rc;
}

long stat64_alike_recheck (char* syscall_name, int syscall_num)
{
    struct recheck_entry* pentry;
    struct stat64_recheck* pstat64;
    struct stat64 st;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pstat64 = (struct stat64_recheck *) bufptr;
    char* pathName = bufptr+sizeof(struct stat64_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "%s: rc %ld pathname %s buf %lx ", syscall_name, pentry->retval, pathName, (u_long) pstat64->buf);
    if (pstat64->has_retvals) {
	LPRINT ( "%s retvals: st_dev %llu st_ino %llu st_mode %d st_nlink %d st_uid %d st_gid %d st_rdev %llu "
	       "st_size %lld st_atime %ld st_mtime %ld st_ctime %ld st_blksize %ld st_blocks %lld clock %lu\n",
	       syscall_name, pstat64->retvals.st_dev, pstat64->retvals.st_ino, pstat64->retvals.st_mode, pstat64->retvals .st_nlink, pstat64->retvals.st_uid,pstat64->retvals .st_gid,
	       pstat64->retvals.st_rdev, pstat64->retvals.st_size, pstat64->retvals .st_atime, pstat64->retvals.st_mtime, pstat64->retvals.st_ctime, pstat64->retvals.st_blksize,
		 pstat64->retvals.st_blocks, pentry->clock); 
    } else {
	LPRINT ( "no return values clock %ld\n", pentry->clock);
    }
#endif

    start_timing();
    rc = syscall(syscall_num, pathName, &st);
    end_timing (syscall_num, rc);
    check_retval (syscall_name, pentry->clock, pentry->retval, rc);
    if (pstat64->has_retvals) {
	if (st.st_dev != pstat64->retvals.st_dev) {
	    printf ("[MISMATCH] %s dev does not match %llu vs. recorded %llu\n", syscall_name, st.st_dev, pstat64->retvals.st_dev);
	    handle_mismatch();
	}
#if 0
	if (st.st_ino != pstat64->retvals.st_ino) {
	    printf ("[MISMATCH] stat64 ino does not match %llu vs. recorded %llu\n", st.st_ino, pstat64->retvals.st_ino);
	    handle_mismatch();
	}
#endif
	if (st.st_mode != pstat64->retvals.st_mode) {
	    printf ("[MISMATCH] %s mode does not match %d vs. recorded %d\n", syscall_name, st.st_mode, pstat64->retvals.st_mode);
	    handle_mismatch();
	}
#if 0
	if (st.st_nlink != pstat64->retvals.st_nlink) {
	    printf ("[MISMATCH] %s nlink does not match %d vs. recorded %d\n",syscall_name,  st.st_nlink, pstat64->retvals.st_nlink);
	    handle_mismatch();
	}
#endif
	if (st.st_uid != pstat64->retvals.st_uid) {
	    printf ("[MISMATCH] %s uid does not match %d vs. recorded %d\n", syscall_name, st.st_uid, pstat64->retvals.st_uid);
	    handle_mismatch();
	}
	if (st.st_gid != pstat64->retvals.st_gid) {
	    printf ("[MISMATCH] %s gid does not match %d vs. recorded %d\n", syscall_name, st.st_gid, pstat64->retvals.st_gid);
	    handle_mismatch();
	}
#if 0
	if (st.st_rdev != pstat64->retvals.st_rdev) {
	    printf ("[MISMATCH] %s rdev does not match %llu vs. recorded %llu\n", syscall_name, st.st_rdev, pstat64->retvals.st_rdev);
	    handle_mismatch();
	}
#endif
	if (st.st_size != pstat64->retvals.st_size) {
	    printf ("[MISMATCH] %s size does not match %lld vs. recorded %lld\n", syscall_name, st.st_size, pstat64->retvals.st_size);
	    handle_mismatch();
	}
#if 0
	if (st.st_mtime != pstat64->retvals.st_mtime) {
	    printf ("[MISMATCH] stat64 mtime does not match %ld vs. recorded %ld\n", st.st_mtime, pstat64->retvals.st_mtime);
	    handle_mismatch();
	}
	if (st.st_ctime != pstat64->retvals.st_ctime) {
	    printf ("[MISMATCH] stat64 ctime does not match %ld vs. recorded %ld\n", st.st_ctime, pstat64->retvals.st_ctime);
	    handle_mismatch();
	}
#endif
	/* Assume atime will be handled by tainting since it changes often */
	((struct stat64 *) pstat64->buf)->st_ino = st.st_ino;
	((struct stat64 *) pstat64->buf)->st_nlink = st.st_nlink;
	((struct stat64 *) pstat64->buf)->st_rdev = st.st_rdev;
	//((struct stat64 *) pstat64->buf)->st_size = st.st_size;
	((struct stat64 *) pstat64->buf)->st_mtime = st.st_mtime;
	((struct stat64 *) pstat64->buf)->st_ctime = st.st_ctime;
	((struct stat64 *) pstat64->buf)->st_atime = st.st_atime;
	//((struct stat64 *) pstat64->buf)->st_blocks = st.st_blocks;
	add_to_taintbuf (pentry, STAT64_INO, &st.st_ino, sizeof(st.st_ino));
	add_to_taintbuf (pentry, STAT64_NLINK, &st.st_nlink, sizeof(st.st_nlink));
	add_to_taintbuf (pentry, STAT64_RDEV, &st.st_rdev, sizeof(st.st_rdev));
	add_to_taintbuf (pentry, STAT64_MTIME, &st.st_mtime, sizeof(st.st_mtime));
	add_to_taintbuf (pentry, STAT64_CTIME, &st.st_ctime, sizeof(st.st_ctime));
	add_to_taintbuf (pentry, STAT64_ATIME, &st.st_atime, sizeof(st.st_atime));
	if (st.st_blksize != pstat64->retvals.st_blksize) {
	    printf ("[MISMATCH] %s blksize does not match %ld vs. recorded %ld\n", syscall_name, st.st_blksize, pstat64->retvals.st_blksize);
	    handle_mismatch();
	}
	if (st.st_blocks != pstat64->retvals.st_blocks) {
	    printf ("[MISMATCH] %s blocks does not match %lld vs. recorded %lld\n", syscall_name, st.st_blocks, pstat64->retvals.st_blocks);
	    handle_mismatch();
	}
    }
    end_timing_func (syscall_num);
    return rc;
}

long stat64_recheck () { 
    return stat64_alike_recheck ("stat64", SYS_stat64);
}

long lstat64_recheck () { 
    return stat64_alike_recheck ("lstat64", SYS_lstat64);
}

long fstat64_recheck ()
{
    struct recheck_entry* pentry;
    struct fstat64_recheck* pfstat64;
    struct stat64 st;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pfstat64 = (struct fstat64_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fstat64: rc %ld fd %d buf %lx ", pentry->retval, pfstat64->fd, (u_long) pfstat64->buf);
    if (pfstat64->has_retvals) {
	LPRINT ( "st_dev %llu st_ino %llu st_mode %d st_nlink %d st_uid %d st_gid %d st_rdev %llu "
	       "st_size %lld st_atime %ld st_mtime %ld st_ctime %ld st_blksize %ld st_blocks %lld clock %lu\n",
	       pfstat64->retvals.st_dev, pfstat64->retvals.st_ino, pfstat64->retvals.st_mode, pfstat64->retvals .st_nlink, pfstat64->retvals.st_uid,pfstat64->retvals .st_gid,
	       pfstat64->retvals.st_rdev, pfstat64->retvals.st_size, pfstat64->retvals .st_atime, pfstat64->retvals.st_mtime, pfstat64->retvals.st_ctime, pfstat64->retvals.st_blksize,
		 pfstat64->retvals.st_blocks, pentry->clock); 
    } else {
	LPRINT ( "no return values clock %lu\n", pentry->clock);
    }
#endif

    start_timing();
    rc = syscall(SYS_fstat64, pfstat64->fd, &st);
    end_timing (SYS_fstat64, rc);
    check_retval ("fstat64", pentry->clock, pentry->retval, rc);
    if (pfstat64->has_retvals) {
	if (st.st_dev != pfstat64->retvals.st_dev) {
	    printf ("[MISMATCH] fstat64 dev does not match %llu vs. recorded %llu\n", st.st_dev, pfstat64->retvals.st_dev);
	    handle_mismatch();
	}
#if 0
	if (st.st_ino != pfstat64->retvals.st_ino) {
	    printf ("[MISMATCH] fstat64 ino does not match %llu vs. recorded %llu\n", st.st_ino, pfstat64->retvals.st_ino);
	    handle_mismatch();
	}
#endif
	if (st.st_mode != pfstat64->retvals.st_mode) {
	    printf ("[MISMATCH] fstat64 mode does not match %d vs. recorded %d\n", st.st_mode, pfstat64->retvals.st_mode);
	    handle_mismatch();
	}
#if 0
	if (st.st_nlink != pfstat64->retvals.st_nlink) {
	    printf ("[MISMATCH] fstat64 nlink does not match %d vs. recorded %d\n", st.st_nlink, pfstat64->retvals.st_nlink);
	    handle_mismatch();
	}
#endif
	if (st.st_uid != pfstat64->retvals.st_uid) {
	    printf ("[MISMATCH] fstat64 uid does not match %d vs. recorded %d\n", st.st_uid, pfstat64->retvals.st_uid);
	    handle_mismatch();
	}
	if (st.st_gid != pfstat64->retvals.st_gid) {
	    printf ("[MISMATCH] fstat64 gid does not match %d vs. recorded %d\n", st.st_gid, pfstat64->retvals.st_gid);
	    handle_mismatch();
	}
#if 0
	if (st.st_rdev != pfstat64->retvals.st_rdev) {
	    printf ("[MISMATCH] fstat64 rdev does not match %llu vs. recorded %llu\n", st.st_rdev, pfstat64->retvals.st_rdev);
	    handle_mismatch();
	}
#endif
	if (st.st_size != pfstat64->retvals.st_size) {
	    printf ("[MISMATCH] fstat64 size does not match %lld vs. recorded %lld\n", st.st_size, pfstat64->retvals.st_size);
	    handle_mismatch();
	}
#if 0
	if (st.st_mtime != pfstat64->retvals.st_mtime) {
	    printf ("[MISMATCH] fstat64 mtime does not match %ld vs. recorded %ld\n", st.st_mtime, pfstat64->retvals.st_mtime);
	    handle_mismatch();
	}
	if (st.st_ctime != pfstat64->retvals.st_ctime) {
	    printf ("[MISMATCH] fstat64 ctime does not match %ld vs. recorded %ld\n", st.st_ctime, pfstat64->retvals.st_ctime);
	    handle_mismatch();
	}
#endif
	/* Assume inode, atime, mtime, ctime will be handled by tainting since it changes often */
	((struct stat64 *) pfstat64->buf)->st_ino = st.st_ino;
	((struct stat64 *) pfstat64->buf)->st_nlink = st.st_nlink;
	((struct stat64 *) pfstat64->buf)->st_rdev = st.st_rdev;
	//((struct stat64 *) pfstat64->buf)->st_size = st.st_size;
	((struct stat64 *) pfstat64->buf)->st_mtime = st.st_mtime;
	((struct stat64 *) pfstat64->buf)->st_ctime = st.st_ctime;
	((struct stat64 *) pfstat64->buf)->st_atime = st.st_atime;
	//((struct stat64 *) pfstat64->buf)->st_blocks = st.st_blocks;
	add_to_taintbuf (pentry, STAT64_INO, &st.st_ino, sizeof(st.st_ino));
	add_to_taintbuf (pentry, STAT64_NLINK, &st.st_nlink, sizeof(st.st_nlink));
	add_to_taintbuf (pentry, STAT64_RDEV, &st.st_rdev, sizeof(st.st_rdev));
	add_to_taintbuf (pentry, STAT64_MTIME, &st.st_mtime, sizeof(st.st_mtime));
	add_to_taintbuf (pentry, STAT64_CTIME, &st.st_ctime, sizeof(st.st_ctime));
	add_to_taintbuf (pentry, STAT64_ATIME, &st.st_atime, sizeof(st.st_atime));
	if (st.st_blksize != pfstat64->retvals.st_blksize) {
	    printf ("[MISMATCH] fstat64 blksize does not match %ld vs. recorded %ld\n", st.st_blksize, pfstat64->retvals.st_blksize);
	    handle_mismatch();
	}
	if (st.st_blocks != pfstat64->retvals.st_blocks) {
	    printf ("[MISMATCH] fstat64 blocks does not match %lld vs. recorded %lld\n", st.st_blocks, pfstat64->retvals.st_blocks);
	    handle_mismatch();
	}
    }
    end_timing_func (SYS_fstat64);
    return rc;
}

long fcntl64_getfd_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_getfd_recheck* pgetfd;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pgetfd = (struct fcntl64_getfd_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fcntl64 getfd: fd %d rc %ld clock %lu\n", pgetfd->fd, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_fcntl64, pgetfd->fd, F_GETFD);
    end_timing (SYS_fcntl64, rc);
    check_retval ("fcntl64 getfd", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_fcntl64);
    return rc;
}

long fcntl64_setfd_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_setfd_recheck* psetfd;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psetfd = (struct fcntl64_setfd_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fcntl64 setfd: fd %d arg %d rc %ld clock %lu\n", psetfd->fd, psetfd->arg, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_fcntl64, psetfd->fd, F_SETFD, psetfd->arg);
    end_timing (SYS_fcntl64, rc);
    check_retval ("fcntl64 setfd", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_fcntl64);
    return rc;
}

long fcntl64_getfl_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_getfl_recheck* pgetfl;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pgetfl = (struct fcntl64_getfl_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fcntl64 getfl: fd %d rc %ld clock %lu\n", pgetfl->fd, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_fcntl64, pgetfl->fd, F_GETFL);
    end_timing (SYS_fcntl64, rc);
    check_retval ("fcntl64 getfl", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_fcntl64);
    return rc;
}

long fcntl64_setfl_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_setfl_recheck* psetfl;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psetfl = (struct fcntl64_setfl_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fcntl64 setfl: fd %d flags %lx rc %ld clock %lu\n", psetfl->fd, psetfl->flags, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_fcntl64, psetfl->fd, F_SETFL, psetfl->flags);
    end_timing (SYS_fcntl64, rc);
    check_retval ("fcntl64 setfl", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_fcntl64);
    return rc;
}

long fcntl64_getlk_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_getlk_recheck* pgetlk;
    struct flock fl;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pgetlk = (struct fcntl64_getlk_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fcntl64 getlk: fd %d arg %lx rc %ld clock %lu\n", pgetlk->fd, (u_long) pgetlk->arg, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_fcntl64, pgetlk->fd, F_GETLK, &fl);
    end_timing (SYS_fcntl64, rc);
    check_retval ("fcntl64 getlk", pentry->clock, pentry->retval, rc);
    if (pgetlk->has_retvals) {
	if (memcmp(&fl, &pgetlk->flock, sizeof(fl))) {
	    printf ("[MISMATCH] fcntl64 getlk does not match\n");
	    handle_mismatch();
	}
    }
    end_timing_func (SYS_fcntl64);
    return rc;
}

long fcntl64_getown_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_getown_recheck* pgetown;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pgetown = (struct fcntl64_getown_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("fcntl64 getown: fd %d rc %ld clock %lu\n", pgetown->fd, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_fcntl64, pgetown->fd, F_GETOWN);
    end_timing(SYS_fcntl64, rc);
    check_retval ("fcntl64 getown", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_fcntl64);
    return rc;
}

long fcntl64_setown_recheck (long owner)
{
    struct recheck_entry* pentry;
    struct fcntl64_setown_recheck* psetown;
    long use_owner;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psetown = (struct fcntl64_setown_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fcntl64 setown: fd %d owner %lx rc %ld clock %lu\n", psetown->fd, psetown->owner, pentry->retval, pentry->clock);
#endif

    if (psetown->is_owner_tainted) {
	use_owner = owner; 
    } else {
	use_owner = psetown->owner;
    }

    start_timing();
    rc = syscall(SYS_fcntl64, psetown->fd, F_SETOWN, use_owner);
    end_timing (SYS_fcntl64, rc);
    check_retval ("fcntl64 setown", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_fcntl64);
    return rc;
}

long ugetrlimit_recheck ()
{
    struct recheck_entry* pentry;
    struct ugetrlimit_recheck* pugetrlimit;
    struct rlimit rlim;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pugetrlimit = (struct ugetrlimit_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "ugetrlimit: resource %d rlimit %ld %ld rc %ld clock %lu\n", pugetrlimit->resource, pugetrlimit->rlim.rlim_cur, pugetrlimit->rlim.rlim_max, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_ugetrlimit, pugetrlimit->resource, &rlim);
    end_timing (SYS_ugetrlimit, rc);
    check_retval ("ugetrlimit", pentry->clock, pentry->retval, rc);
    if (memcmp(&rlim, &pugetrlimit->rlim, sizeof(rlim))) {
	printf ("[MISMATCH] ugetrlimit does not match: returns %ld %ld, while in recheck log %ld %ld, on resource %d\n", rlim.rlim_cur, rlim.rlim_max, pugetrlimit->rlim.rlim_cur, pugetrlimit->rlim.rlim_max, pugetrlimit->resource);
	handle_mismatch();
    }
    end_timing_func (SYS_ugetrlimit);
    return rc;
}

long setrlimit_recheck ()
{
    struct recheck_entry* pentry;
    struct setrlimit_recheck* psetrlimit;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psetrlimit = (struct setrlimit_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "setrlimit: resource %d rlimit %ld %ld rc %ld clock %lu\n", psetrlimit->resource, psetrlimit->rlim.rlim_cur, psetrlimit->rlim.rlim_max, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_setrlimit, psetrlimit->resource, &psetrlimit->rlim);
    end_timing (SYS_setrlimit, rc);
    check_retval ("setrlimit", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_setrlimit);
    return rc;
}

long uname_recheck ()
{
    struct recheck_entry* pentry;
    struct uname_recheck* puname;
    struct utsname uname;
    int rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    puname = (struct uname_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "uname: sysname %s nodename %s release %s version %s machine %s rc %ld clock %lu\n", 
	     puname->utsname.sysname, puname->utsname.nodename, puname->utsname.release, puname->utsname.version, puname->utsname.machine, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_uname, &uname);
    end_timing (SYS_uname, rc);
    check_retval ("uname", pentry->clock, pentry->retval, rc);

    if (memcmp(&uname.sysname, &puname->utsname.sysname, sizeof(uname.sysname))) {
	fprintf (stderr, "[MISMATCH] uname sysname does not match: %s\n", uname.sysname);
	handle_mismatch();
    }
    if (memcmp(&uname.nodename, &puname->utsname.nodename, sizeof(uname.nodename))) {
	fprintf (stderr, "[MISMATCH] uname nodename does not match: %s\n", uname.nodename);
	handle_mismatch();
    }
    if (memcmp(&uname.release, &puname->utsname.release, sizeof(uname.release))) {
	fprintf (stderr, "[MISMATCH] uname release does not match: %s\n", uname.release);
	handle_mismatch();
    }
    /* Assume version will be handled by tainting since it changes often */
#ifdef PRINT_VALUES
    LPRINT ( "Buffer is %lx\n", (u_long) puname->buf);
    LPRINT ( "Copy to version buffer at %lx\n", (u_long) &((struct utsname *) puname->buf)->version);
#endif
    memcpy (&((struct utsname *) puname->buf)->version, &puname->utsname.version, sizeof(puname->utsname.version));
    add_to_taintbuf (pentry, UNAME_VERSION, &puname->utsname.version, sizeof(puname->utsname.version));
    if (memcmp(&uname.machine, &puname->utsname.machine, sizeof(uname.machine))) {
	fprintf (stderr, "[MISMATCH] uname machine does not match: %s\n", uname.machine);
	handle_mismatch();
    }
    end_timing_func (SYS_uname);
    return rc;
}

long statfs64_recheck ()
{
    struct recheck_entry* pentry;
    struct statfs64_recheck* pstatfs64;
    struct statfs64 st;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pstatfs64 = (struct statfs64_recheck *) bufptr;
    char* path = bufptr+sizeof(struct statfs64_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "statfs64: path %s size %u type %d bsize %d blocks %lld bfree %lld bavail %lld files %lld ffree %lld fsid %d %d namelen %d frsize %d rc %ld clock %lu\n", path, pstatfs64->sz,
	   pstatfs64->statfs.f_type, pstatfs64->statfs.f_bsize, pstatfs64->statfs.f_blocks, pstatfs64->statfs.f_bfree, pstatfs64->statfs.f_bavail, pstatfs64->statfs.f_files, 
	     pstatfs64->statfs.f_ffree, pstatfs64->statfs.f_fsid.__val[0], pstatfs64->statfs.f_fsid.__val[1], pstatfs64->statfs.f_namelen, pstatfs64->statfs.f_frsize, pentry->retval, pentry->clock);
#endif

    start_timing();
    rc = syscall(SYS_statfs64, path, pstatfs64->sz, &st);
    end_timing (SYS_statfs64, rc);
    check_retval ("statfs64", pentry->clock, pentry->retval, rc);
    if (rc == 0) {
	if (pstatfs64->statfs.f_type != st.f_type) {
	    fprintf (stderr, "[MISMATCH] statfs64 f_type does not match: %d\n", st.f_type);
	    handle_mismatch();
	}
	if (pstatfs64->statfs.f_bsize != st.f_bsize) {
	    fprintf (stderr, "[MISMATCH] statfs64 f_bsize does not match: %d\n", st.f_bsize);
	    handle_mismatch();
	}
	if (pstatfs64->statfs.f_blocks != st.f_blocks) {
	    fprintf (stderr, "[MISMATCH] statfs64 f_blocks does not match: %lld\n", st.f_blocks);
	    handle_mismatch();
	}
	/* Assume free and available blocks handled by tainting */
	pstatfs64->buf->f_bfree = st.f_bfree;
	add_to_taintbuf (pentry, STATFS64_BFREE, &pstatfs64->buf->f_bfree, sizeof (pstatfs64->buf->f_bfree));
	pstatfs64->buf->f_bavail = st.f_bavail;
	add_to_taintbuf (pentry, STATFS64_BAVAIL, &pstatfs64->buf->f_bavail, sizeof (pstatfs64->buf->f_bavail));
	if (pstatfs64->statfs.f_files != st.f_files) {
	    fprintf (stderr, "[MISMATCH] statfs64 f_bavail does not match: %lld\n", st.f_files);
	    handle_mismatch();
	}
	/* Assume free files handled by tainting */
	pstatfs64->buf->f_ffree = st.f_ffree;
	add_to_taintbuf (pentry, STATFS64_FFREE, &pstatfs64->buf->f_ffree, sizeof (pstatfs64->buf->f_ffree));
	if (pstatfs64->statfs.f_fsid.__val[0] != st.f_fsid.__val[0] || pstatfs64->statfs.f_fsid.__val[1] != st.f_fsid.__val[1]) {
	    fprintf (stderr, "[MISMATCH] statfs64 f_fdid does not match: %d %d\n", st.f_fsid.__val[0],  st.f_fsid.__val[1]);
	    handle_mismatch();
	}
	if (pstatfs64->statfs.f_namelen != st.f_namelen) {
	    fprintf (stderr, "[MISMATCH] statfs64 f_namelen does not match: %d\n", st.f_namelen);
	    handle_mismatch();
	}
	if (pstatfs64->statfs.f_frsize != st.f_frsize) {
	    fprintf (stderr, "[MISMATCH] statfs64 f_frsize does not match: %d\n", st.f_frsize);
	    handle_mismatch();
	}
    }
    end_timing_func (SYS_statfs64);
    return rc;
}

long gettimeofday_recheck () { 
    struct recheck_entry* pentry;
    struct gettimeofday_recheck *pget;
    struct timeval tv;
    struct timezone tz;
    int rc;
    
    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pget = (struct gettimeofday_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "gettimeofday: pointer tv %lx tz %lx clock %lu bufptr %p, buf %p\n", (long) pget->tv_ptr, (long) pget->tz_ptr, pentry->clock, bufptr, buf);
#endif
    start_timing();
    rc = syscall (SYS_gettimeofday, &tv, &tz);
    end_timing (SYS_gettimeofday, rc);
    check_retval ("gettimeofday", pentry->clock, pentry->retval, rc);
    
    if (pget->tv_ptr) { 
	memcpy (pget->tv_ptr, &tv, sizeof(struct timeval));
	add_to_taintbuf (pentry, GETTIMEOFDAY_TV, &tv, sizeof(struct timeval));
    }
    if (pget->tz_ptr) { 
	memcpy (pget->tz_ptr, &tz, sizeof(struct timezone));
	add_to_taintbuf (pentry, GETTIMEOFDAY_TZ, &tz, sizeof(struct timezone));
    }
    end_timing_func (SYS_gettimeofday);
    return rc;
}

long clock_gettime_recheck () 
{
    struct recheck_entry* pentry;
    struct clock_getx_recheck *pget;
    struct timespec tp;
    long rc;
    
    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pget = (struct clock_getx_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("clock_gettime: clockid %d, tp %p clock %lu\n", pget->clk_id, pget->tp, pentry->clock);
#endif
    start_timing();
    rc = syscall (SYS_clock_gettime, pget->clk_id, &tp);
    end_timing (SYS_clock_gettime, rc);
    check_retval ("clock_gettime", pentry->clock, pentry->retval, rc);
    
    if (pget->tp) {
        memcpy (pget->tp, &tp, sizeof(tp));
        add_to_taintbuf (pentry, CLOCK_GETTIME, &tp, sizeof(tp));
    }
    end_timing_func (SYS_clock_gettime);
    return rc;
}

long clock_getres_recheck (int clock_id) 
{
    struct recheck_entry* pentry;
    struct clock_getx_recheck *pget;
    clockid_t clk_id;
    struct timespec tp;
    long rc;
    
    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pget = (struct clock_getx_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("clock_getres: clockid %d, id tainted? %d, new clock id %d, tp %p clock %lu\n", pget->clk_id, pget->clock_id_tainted, clock_id, pget->tp, pentry->clock);
#endif
    if (pget->clock_id_tainted) { 
        clk_id = clock_id;
    } else { 
        clk_id = pget->clk_id;
    }
    start_timing();
    rc = syscall (SYS_clock_getres, clk_id, &tp);
    end_timing (SYS_clock_getres, rc);
    check_retval ("clock_getres", pentry->clock, pentry->retval, rc);
    
    if (pget->tp) {
        memcpy (pget->tp, &tp, sizeof(tp));
        add_to_taintbuf (pentry, CLOCK_GETRES, &tp, sizeof(tp));
    }
    end_timing_func (SYS_clock_getres);
    return rc;
}

long time_recheck () { 
    struct recheck_entry* pentry;
    struct time_recheck *pget;
    int rc;
    
    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pget = (struct time_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("time: pointer t %x clock %lu\n", (int)(pget->t), pentry->clock);
#endif
    start_timing();
    rc = syscall (SYS_time, pget->t);
    end_timing (SYS_time, rc);
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(long));
    if (rc >= 0 && pget->t) add_to_taintbuf (pentry, RETBUF, pget->t, sizeof(time_t));
    end_timing_func (SYS_time);
    return rc;
}

long prlimit64_recheck ()
{
    struct recheck_entry* pentry;
    struct prlimit64_recheck* prlimit;
    struct rlimit64 rlim;
    struct rlimit64* prlim;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    prlimit = (struct prlimit64_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "prlimit64: pid %d resource %d new limit %lx old limit %lx rc %ld clock %lu\n", prlimit->pid, prlimit->resource, 
	     (u_long) prlimit->new_limit, (u_long) prlimit->old_limit, pentry->retval, pentry->clock);
    if (prlimit->has_retvals) {
	LPRINT ( "old soft limit: %lld hard limit %lld\n", prlimit->retparams.rlim_cur, prlimit->retparams.rlim_max);
    }
#endif
    if (prlimit->old_limit) {
	prlim = &rlim;
	rlim.rlim_cur = rlim.rlim_max = 0;
    } else {
	prlim = NULL;
    }
    start_timing();
    rc = syscall(SYS_prlimit64, prlimit->pid, prlimit->resource, prlimit->new_limit, prlim);
    end_timing (SYS_prlimit64, rc);
    check_retval ("prlimit64", pentry->clock, pentry->retval, rc);
    if (prlimit->has_retvals) {
	if (prlimit->retparams.rlim_cur != rlim.rlim_cur) {
	    printf ("[MISMATCH] prlimit64 soft limit does not match: %lld\n", rlim.rlim_cur);
	}
	if (prlimit->retparams.rlim_max != rlim.rlim_max) {
	    printf ("[MISMATCH] prlimit64 hard limit does not match: %lld\n", rlim.rlim_max);
	}
    }
    end_timing_func (SYS_prlimit64);
    return rc;
}

long setpgid_recheck (int pid, int pgid)
{
    struct recheck_entry* pentry;
    struct setpgid_recheck* psetpgid;
    pid_t use_pid, use_pgid;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psetpgid = (struct setpgid_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "setpgid: pid tainted? %d record pid %d passed pid %d pgid tainted? %d record pgid %d passed pgid %d clock %lu\n", 
	     psetpgid->is_pid_tainted, psetpgid->pid, pid, psetpgid->is_pgid_tainted, psetpgid->pgid, pgid, pentry->clock);
#endif 
    if (psetpgid->is_pid_tainted) {
	use_pid = pid; 
    } else {
	use_pid = psetpgid->pid;
    }
    if (psetpgid->is_pgid_tainted) {
	use_pgid = pgid; 
    } else {
	use_pgid = psetpgid->pgid;
    }

    start_timing();
    rc = syscall(SYS_setpgid, use_pid, use_pgid);
    end_timing(SYS_setpgid, rc);
    check_retval ("setpgid", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_setpgid);
    return rc;
}

long readlink_recheck ()
{
    struct recheck_entry* pentry;
    struct readlink_recheck* preadlink;
    char* linkdata;
    char* path;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    preadlink = (struct readlink_recheck *) bufptr;
    if (pentry->retval > 0) {
	linkdata = bufptr+sizeof(struct readlink_recheck);
	path = linkdata + pentry->retval;
    } else {
	linkdata = NULL;
	path = bufptr+sizeof(struct readlink_recheck);
    }
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "readlink: buf %p size %d ", preadlink->buf, preadlink->bufsiz);
    if (pentry->retval) {
	int i;
	LPRINT ( "linkdata ");
	for (i = 0; i < pentry->retval; i++) {
	    LPRINT ( "%c", linkdata[i]);
	}
	LPRINT ( " ");
    }
    LPRINT ( "path %s rc %ld clock %lu\n", path, pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_readlink, path, tmpbuf, preadlink->bufsiz);
    end_timing (SYS_readlink, rc);
    check_retval ("readlink", pentry->clock, pentry->retval, rc);
    if (rc > 0) {
	if (memcmp(tmpbuf, linkdata, pentry->retval)) {
	    printf ("[MISMATCH] readdata returns link data %s\n", linkdata);
	    handle_mismatch();
	}
    }
    end_timing_func (SYS_readlink);
    return rc;
}

long socket_recheck ()
{
    struct recheck_entry* pentry;
    struct socket_recheck* psocket;
    u_long block[6];
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psocket = (struct socket_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "socket: domain %d type %x protocol %d rc %ld clock %lu\n", psocket->domain, psocket->type, psocket->protocol, pentry->retval, pentry->clock);
#endif 

    block[0] = psocket->domain;
    block[1] = psocket->type;
    block[2] = psocket->protocol;
    start_timing();
    rc = syscall(SYS_socketcall, SYS_SOCKET, &block);
    end_timing (SYS_socketcall, rc);
    check_retval ("socket", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_socketcall);
    return rc;
}

long setsockopt_recheck ()
{
    struct recheck_entry* pentry;
    struct setsockopt_recheck* psetsockopt;
    u_long block[6];
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psetsockopt = (struct setsockopt_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "setsockopt: sockfd %d level %d optname %d optval %p optlen %d rc %ld clock %lu\n", 
	     psetsockopt->sockfd, psetsockopt->level, psetsockopt->optname, psetsockopt->optval, psetsockopt->optlen, pentry->retval, pentry->clock);
#endif 

    block[0] = psetsockopt->sockfd;
    block[1] = psetsockopt->level;
    block[2] = psetsockopt->optname;
    block[3] = (u_long) psetsockopt->optval;
    block[4] = psetsockopt->optlen;
    start_timing();
    rc = syscall(SYS_socketcall, SYS_SETSOCKOPT, &block);
    end_timing (SYS_socketcall, rc);
    check_retval ("setsockopt", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_socketcall);
    return rc;
}

static inline long connect_or_bind_recheck (int call, char* call_name)
{
    struct recheck_entry* pentry;
    struct connect_recheck* pconnect;
    u_long block[6];
    char* inaddr;
    char* addr;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pconnect = (struct connect_recheck *) bufptr;
    addr = bufptr+sizeof(struct connect_recheck);
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "%s: sockfd %d addlen %d rc %ld clock %lu\n", call_name, pconnect->sockfd, pconnect->addrlen, pentry->retval, pentry->clock);
#endif 
    inaddr = fill_taintedbuf (addr, (char *) pconnect->addr, pconnect->addrlen);

#ifdef PRINT_DEBUG
    print_buffer_hex ((u_char*) inaddr, pconnect->addrlen);
#endif

    block[0] = pconnect->sockfd;
    block[1] = (u_long) inaddr;
    block[2] = pconnect->addrlen;
    start_timing();
    rc = syscall(SYS_socketcall, call, &block);
    end_timing (SYS_socketcall, rc);
    check_retval (call_name, pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_socketcall);
    return rc;
}

long connect_recheck () { 
    return connect_or_bind_recheck (SYS_CONNECT, "connect");
}

long bind_recheck () {
    return connect_or_bind_recheck (SYS_BIND, "bind");
}

long getsockname_recheck (int call)
{
    struct recheck_entry* pentry;
    struct getsockname_recheck* pgetsockname;
    u_long block[6];
    socklen_t retlen;
    char* addr;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pgetsockname = (struct getsockname_recheck *) bufptr;
    addr = bufptr+sizeof(struct getsockname_recheck);
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "getsockname: sockfd %d addr %p addlen %p rc %ld clock %lu\n", 
	     pgetsockname->sockfd, pgetsockname->addr, pgetsockname->addrlen, pentry->retval, pentry->clock);
#endif 
    block[0] = pgetsockname->sockfd;
    block[1] = (u_long) tmpbuf;
    retlen = pgetsockname->addrlenval;
    block[2] = (u_long) &retlen;
    start_timing();
    rc = syscall(SYS_socketcall, SYS_GETSOCKNAME, &block);
    end_timing (SYS_socketcall, rc);
    check_retval ("getsockname", pentry->clock, pentry->retval, rc);
    if (rc > 0) {
	if (retlen != pgetsockname->arglen) {
	    LPRINT ("getsockname: address length return mismatch: %d vs %ld\n", retlen, pgetsockname->arglen);
	    handle_mismatch();
	}
	if (memcmp(addr, tmpbuf, pgetsockname->arglen)) {
	    LPRINT ("getsockname: address is different %s vs %s\n", addr, tmpbuf);
	    handle_mismatch();
	}
    }
    end_timing_func (SYS_socketcall);
    return rc;
}

long getpeername_recheck (int call)
{
    struct recheck_entry* pentry;
    struct getpeername_recheck* pgetpeername;
    u_long block[6];
    socklen_t retlen;
    char* addr;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pgetpeername = (struct getpeername_recheck *) bufptr;
    addr = bufptr+sizeof(struct getpeername_recheck);
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "getpeername: sockfd %d addr %p addlen %p rc %ld clock %lu\n", 
	     pgetpeername->sockfd, pgetpeername->addr, pgetpeername->addrlen, pentry->retval, pentry->clock);
#endif 
    block[0] = pgetpeername->sockfd;
    block[1] = (u_long) tmpbuf;
    retlen = pgetpeername->addrlenval;
    block[2] = (u_long) &retlen;
    start_timing();
    rc = syscall(SYS_socketcall, SYS_GETPEERNAME, &block);
    end_timing (SYS_socketcall, rc);
    check_retval ("getpeername", pentry->clock, pentry->retval, rc);
    if (rc > 0) {
	if (retlen != pgetpeername->arglen) {
	    LPRINT ("getpeername: address length return mismatch: %d vs %ld\n", retlen, pgetpeername->arglen);
	    handle_mismatch();
	}
	if (memcmp(addr, tmpbuf, pgetpeername->arglen)) {
	    LPRINT ("getpeername: address is different %s vs %s\n", addr, tmpbuf);
	    handle_mismatch();
	}
    }
    end_timing_func (SYS_socketcall);
    return rc;
}

long getpid_recheck ()
{
    long rc;
    struct recheck_entry* pentry = (struct recheck_entry *) bufptr;
    start_timing_func ();
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;

#ifdef PRINT_VALUES
    LPRINT ( "getpid: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_getpid);
    end_timing (SYS_getpid, rc);
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(rc));
    end_timing_func (SYS_getpid);
    return rc;
}

long gettid_recheck ()
{
    long rc;
    struct recheck_entry* pentry = (struct recheck_entry *) bufptr;
    start_timing_func ();
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;

#ifdef PRINT_VALUES
    LPRINT ( "gettid: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_gettid);
    end_timing (SYS_gettid, rc);
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(rc));
    end_timing_func (SYS_gettid);
    return rc;
}

long getpgrp_recheck ()
{
    long rc;
    struct recheck_entry* pentry = (struct recheck_entry *) bufptr;
    start_timing_func ();
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;

#ifdef PRINT_VALUES
    LPRINT ("getpgrp: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc =  syscall(SYS_getpgrp);
    end_timing(SYS_getpgrp, rc);
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(rc));
    end_timing_func (SYS_getpgrp);
    return rc;
}

long getuid32_recheck ()
{
    struct recheck_entry* pentry;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;

#ifdef PRINT_VALUES
    LPRINT ( "getuid32: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_getuid32);
    end_timing (SYS_getuid32, rc);
    check_retval ("getuid32", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_getuid32);
    return rc;
}

long geteuid32_recheck ()
{
    struct recheck_entry* pentry;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;

#ifdef PRINT_VALUES
    LPRINT ( "geteuid32: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_geteuid32);
    end_timing (SYS_geteuid32, rc);
    check_retval ("geteuid32", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_geteuid32);
    return rc;
}

long getgid32_recheck ()
{
    struct recheck_entry* pentry;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;

#ifdef PRINT_VALUES
    LPRINT ( "getgid32: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_getgid32);
    end_timing(SYS_getgid32, rc);
    check_retval ("getgid32", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_getgid32);
    return rc;
}

long getegid32_recheck ()
{
    struct recheck_entry* pentry;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;

#ifdef PRINT_VALUES
    LPRINT ( "getegid32: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_getegid32);
    check_retval ("getegid32", pentry->clock, pentry->retval, rc);
    end_timing(SYS_getegid32, rc);
    end_timing_func (SYS_getegid32);
    return rc;
}

long getresuid_recheck ()
{
    struct recheck_entry* pentry;
    uid_t ruid, euid, suid;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    struct getresuid_recheck* pgetresuid = (struct getresuid_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "getresuid: ruid %p=%d euid %p=%d guid %p=%d rc %ld clock %lu\n", 
	     pgetresuid->ruid, pgetresuid->ruidval, pgetresuid->euid, pgetresuid->euidval, pgetresuid->suid, pgetresuid->suidval, pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_getresuid32, &ruid, &euid, &suid);
    check_retval ("getresuid", pentry->clock, pentry->retval, rc);
    if (rc >= 0) {
	if (ruid != pgetresuid->ruidval) {
	    fprintf (stderr, "getresuid: expected ruid %d, got %d\n", pgetresuid->ruidval, ruid);
	    handle_mismatch();
	}
	if (euid != pgetresuid->euidval) {
	    fprintf (stderr, "getresuid: expected euid %d, got %d\n", pgetresuid->euidval, euid);
	    handle_mismatch();
	}
	if (suid != pgetresuid->suidval) {
	    fprintf (stderr, "getresuid: expected suid %d, got %d\n", pgetresuid->suidval, suid);
	    handle_mismatch();
	}
    }
    end_timing(SYS_getresuid32, rc);
    end_timing_func (SYS_getresuid32);
    return rc;
}

long getresgid_recheck ()
{
    struct recheck_entry* pentry;
    uid_t rgid, egid, sgid;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    struct getresgid_recheck* pgetresgid = (struct getresgid_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "getresgid: rgid %p=%d egid %p=%d ggid %p=%d rc %ld clock %lu\n", 
	     pgetresgid->rgid, pgetresgid->rgidval, pgetresgid->egid, pgetresgid->egidval, pgetresgid->sgid, pgetresgid->sgidval, pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_getresgid32, &rgid, &egid, &sgid);
    check_retval ("getresgid", pentry->clock, pentry->retval, rc);
    if (rc >= 0) {
	if (rgid != pgetresgid->rgidval) {
	    fprintf (stderr, "getresgid: expected rgid %d, got %d\n", pgetresgid->rgidval, rgid);
	    handle_mismatch();
	}
	if (egid != pgetresgid->egidval) {
	    fprintf (stderr, "getresgid: expected egid %d, got %d\n", pgetresgid->egidval, egid);
	    handle_mismatch();
	}
	if (sgid != pgetresgid->sgidval) {
	    fprintf (stderr, "getresgid: expected sgid %d, got %d\n", pgetresgid->sgidval, sgid);
	    handle_mismatch();
	}
    }
    end_timing(SYS_getresgid32, rc);
    end_timing_func (SYS_getresgid32);
    return rc;
}

long llseek_recheck ()
{
    struct recheck_entry* pentry;
    struct llseek_recheck* pllseek;
    loff_t off;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock; 
    pllseek = (struct llseek_recheck *) bufptr;
    bufptr += pentry->len;
   
#ifdef PRINT_VALUES
    LPRINT ( "llseek: fd %u high offset %lx low offset %lx whence %u rc %ld clock %lu", pllseek->fd, pllseek->offset_high, pllseek->offset_low, pllseek->whence, pentry->retval, pentry->clock);
    if (pentry->retval >= 0) {
	LPRINT ( "off %llu\n", pllseek->result);
    } else {
	LPRINT ( "\n");
    }
#endif 

    start_timing();
    rc = syscall(SYS__llseek, pllseek->fd, pllseek->offset_high, pllseek->offset_low, &off, pllseek->whence);
    end_timing (SYS__llseek, rc);
    check_retval ("llseek", pentry->clock, pentry->retval, rc);
    if (rc >= 0 && off != pllseek->result) {
	printf ("[MISMATCH] llseek returns offset %llu\n", off);
	handle_mismatch();
    }
    end_timing_func (SYS__llseek);
    return rc;
}

long ioctl_recheck ()
{
    struct recheck_entry* pentry;
    struct ioctl_recheck* pioctl;
    char* addr;
    char* inarg;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pioctl = (struct ioctl_recheck *) bufptr;
    addr = bufptr+sizeof(struct ioctl_recheck);
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "ioctl: fd %u cmd %x dir %x size %x arg %lx arglen %ld rc %ld clock %lu\n", pioctl->fd, pioctl->cmd, pioctl->dir, pioctl->size, (u_long) pioctl->arg, pioctl->arglen, pentry->retval, pentry->clock);
#endif 

    if (pioctl->dir == _IOC_WRITE) {
        start_timing();
	rc = syscall(SYS_ioctl, pioctl->fd, pioctl->cmd, tmpbuf);
        end_timing(SYS_ioctl, rc);
	check_retval ("ioctl", pentry->clock, pentry->retval, rc);
	// Right now we are tainting buffer
	memcpy (pioctl->arg, tmpbuf, pioctl->arglen);
	add_to_taintbuf (pentry, RETBUF, tmpbuf, pioctl->arglen);
#ifdef PRINT_VALUES
	if (pioctl->cmd == 0x5413) {
	  short* ps = (short *) &tmpbuf;
	  LPRINT ("window size is %d %d\n", ps[0], ps[1]);
	}
#endif
    } else if (pioctl->dir == _IOC_READ) {
	if (pioctl->size) {
	    inarg = fill_taintedbuf (addr, pioctl->arg, pioctl->size);
	} else {
	    inarg = pioctl->arg;
	}
        start_timing();
	rc = syscall(SYS_ioctl, pioctl->fd, pioctl->cmd, inarg);
        end_timing (SYS_ioctl, rc);
	check_retval ("ioctl", pentry->clock, pentry->retval, rc);
    } else {
	printf ("[ERROR] ioctl_recheck only handles ioctl dir _IOC_WRITE and _IOC_READ for now\n");
    }
    end_timing_func (SYS_ioctl);
    return rc;
}

// Can I find this definition as user level?
struct linux_dirent {
    unsigned long        d_ino;
    unsigned long        d_off;
    unsigned short	 d_reclen;
    char		 d_name[1];
};

long getdents_recheck ()
{
    struct recheck_entry* pentry;
    struct getdents64_recheck* pgetdents;
    char* dents;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pgetdents = (struct getdents64_recheck *) bufptr;
    if (pgetdents->arglen > 0) {
	dents = bufptr+sizeof(struct getdents64_recheck);
    }
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "getdents: fd %u buf %p count %u arglen %ld rc %ld clock %lu\n", pgetdents->fd, pgetdents->buf, pgetdents->count, pgetdents->arglen, pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_getdents, pgetdents->fd, tmpbuf, pgetdents->count);
    end_timing (SYS_getdents, rc);
    check_retval ("getdents", pentry->clock, pentry->retval, rc);
    if (rc > 0) {
	int compared = 0;
	char* p = dents; 
	char* c = tmpbuf;
	while (compared < rc) {
	    struct linux_dirent* prev = (struct linux_dirent *) p;
	    struct linux_dirent* curr = (struct linux_dirent *) c;
	    memcpy (pgetdents->buf + ((u_long) &curr->d_ino - (u_long) tmpbuf), &curr->d_ino, sizeof(curr->d_ino)); // Copy inode to buffer
	    if (prev->d_off != curr->d_off || prev->d_reclen != curr->d_reclen || strcmp(prev->d_name, curr->d_name)) {
		LPRINT ("{MISMATCH] getdents: offset %ld vs. %ld\t", prev->d_off, curr->d_off);
		LPRINT ("reclen %d vs. %d\t", prev->d_reclen, curr->d_reclen);
		LPRINT ("name %s vs. %s\t", prev->d_name, curr->d_name);
		handle_mismatch();
	    }
	    // Hack - copy bytes from prev. recording to taintbuf - really should fix replay system instead
	    memcpy (c + sizeof(struct linux_dirent) + strlen(curr->d_name), 
		    p + sizeof(struct linux_dirent) + strlen(curr->d_name),
		    curr->d_reclen-sizeof(struct linux_dirent)-strlen(curr->d_name));
	    if (prev->d_reclen <= 0) break;
	    p += prev->d_reclen; c += curr->d_reclen; compared += prev->d_reclen;
	}
	add_to_taintbuf (pentry, RETBUF, tmpbuf, rc);
    }
    end_timing_func (SYS_getdents);
    return rc;
}

// Can I find this definition at user level?
struct linux_dirent64 {
	__u64		d_ino;
	__s64		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[0];
};

long getdents64_recheck ()
{
    struct recheck_entry* pentry;
    struct getdents64_recheck* pgetdents64;
    char* dents;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pgetdents64 = (struct getdents64_recheck *) bufptr;
    if (pgetdents64->arglen > 0) {
	dents = bufptr+sizeof(struct getdents64_recheck);
    }
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "getdents64: fd %u buf %p count %u arglen %ld rc %ld clock %lu\n", pgetdents64->fd, pgetdents64->buf, pgetdents64->count, pgetdents64->arglen, pentry->retval, pentry->clock);
#endif 
    start_timing();
    rc = syscall(SYS_getdents64, pgetdents64->fd, tmpbuf, pgetdents64->count);
    end_timing (SYS_getdents64, rc);
    check_retval ("getdents64", pentry->clock, pentry->retval, rc);
    if (rc > 0) {
	int compared = 0;
	char* p = dents; 
	char* c = tmpbuf;
	while (compared < rc) {
	    struct linux_dirent64* prev = (struct linux_dirent64 *) p;
	    struct linux_dirent64* curr = (struct linux_dirent64 *) c;
	    memcpy (pgetdents64->buf + ((u_long) &curr->d_ino - (u_long) tmpbuf), &curr->d_ino, sizeof(curr->d_ino)); // Copy inode to buffer
	    if (prev->d_off != curr->d_off ||prev->d_reclen != curr->d_reclen || prev->d_type != curr->d_type || strcmp(prev->d_name, curr->d_name)) {
		printf ("{MISMATCH] getdetnts64: offset %lld vs. %lld\t", prev->d_off, curr->d_off);
		printf ("reclen %d vs. %d\t", prev->d_reclen, curr->d_reclen);
		printf ("name %s vs. %s\t", prev->d_name, curr->d_name);
		printf ("type %d vs. %d\n", prev->d_type, curr->d_type);
		handle_mismatch();
	    }
	    // Hack - copy bytes from prev. recording to taintbuf - really should fix replay system instead
	    memcpy (c + sizeof(struct linux_dirent64) + strlen(curr->d_name), 
		    p + sizeof(struct linux_dirent64) + strlen(curr->d_name),
		    curr->d_reclen-sizeof(struct linux_dirent64)-strlen(curr->d_name));
	    if (prev->d_reclen <= 0) break;
	    p += prev->d_reclen; c += curr->d_reclen; compared += prev->d_reclen;
	}
	add_to_taintbuf (pentry, RETBUF, tmpbuf, rc);
    }
    end_timing_func (SYS_getdents64);
    return rc;
}

long eventfd2_recheck ()
{
    struct recheck_entry* pentry;
    struct eventfd2_recheck* peventfd2;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    peventfd2 = (struct eventfd2_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("eventfd2: count %u flags %x rc %ld clock %lu\n", peventfd2->count, peventfd2->flags, pentry->retval, pentry->clock);
#endif 

    start_timing();
    rc = syscall(SYS_eventfd2, peventfd2->count, peventfd2->flags);
    end_timing(SYS_eventfd2, rc);
    check_retval ("eventfd2", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_eventfd2);
    return rc;
}

long poll_recheck (int timeout)
{
    struct recheck_entry* pentry;
    struct poll_recheck* ppoll;
    struct pollfd* fds;
    struct pollfd* pollbuf = (struct pollfd *) tmpbuf;
    short* revents;
    int rc, use_timeout, tries = 0;
    u_int i;
#ifdef REORDERING
    int reorder_data_in_fd = -1;
#endif

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    ppoll = (struct poll_recheck *) bufptr;
    fds = (struct pollfd *) (bufptr + sizeof (struct poll_recheck));
    revents = (short *) (bufptr + sizeof (struct poll_recheck) + ppoll->nfds*sizeof(struct pollfd));
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("poll: buf %lx nfds %u timeout %d rc %ld", (u_long) ppoll->buf, ppoll->nfds, ppoll->timeout, pentry->retval);
    if (pentry->retval > 0) {
	for (i = 0; i < ppoll->nfds; i++) {
	    LPRINT ("\tfd %d events %x revents %x", fds[i].fd, fds[i].events, revents[i]);
	}
    }
    LPRINT (" clock %lu\n", pentry->clock);
#endif 

    // Note: it is somewhat unclear that we should execute poll at all as this only affect timings.  I'm not
    // sure that I understand the implications of this, though. So, eexcuting it for now...

    if (ppoll->is_timeout_tainted) {
	use_timeout = timeout;
    } else {
	use_timeout = ppoll->timeout;
    }

#ifdef REORDERING
    if (pentry->retval > 0 && reorderin != reorderout) {
	DPRINT ("poll: checking reordered fd %d?\n", reorderfd);
	for (i = 0; i < ppoll->nfds; i++) {
	    if (reorderfd == fds[i].fd && (revents[i]&POLLIN)) {
		DPRINT ("poll: some data available in reorder buffer, set timeout to zero\n");
		reorder_data_in_fd = i;
		use_timeout = 0;
		break;
	    }
	}
    }
#endif

    memcpy (tmpbuf, fds, ppoll->nfds*sizeof(struct pollfd));

    do {
	if (tries > 0) {
	    LPRINT ("poll: sleeping for %d us\n", 500*(2<<(tries-1)));
	    usleep (500*(2<<(tries-1)));
	}

	start_timing();
	rc = syscall(SYS_poll, pollbuf, ppoll->nfds, use_timeout);
	end_timing(SYS_poll, rc);
	
#ifdef REORDERING
	if (reorder_data_in_fd >= 0) {
	    if (!(pollbuf[i].revents&POLLIN)) {
		DPRINT ("Marking reordered fd %d as having data\n", pollbuf[i].fd);
		if (pollbuf[i].revents == 0) rc += 1;
		pollbuf[i].revents |= POLLIN;
	    }
	}
#endif

	if (rc > 0) {
	    for (i = 0; i < ppoll->nfds; i++) {
		DPRINT ("\tfd %d events %x returns revents %x\n", pollbuf[i].fd, pollbuf[i].events, pollbuf[i].revents);
		
		// OK to pretend that data is not ready to read for async channel
		if ((pollbuf[i].revents&POLLIN)&&!(revents[i]&POLLIN)) {
		    DPRINT ("Pretend POLLIN not ready on fd %d\n", pollbuf[i].fd);
		    pollbuf[i].revents &= 0xfffe;
		    if (pollbuf[i].revents == 0) rc--;
		}
	    }
	}
	tries++;
    } while (rc > 0 && rc < pentry->retval && tries < 10);

#ifdef PRINT_DEBUG
    DPRINT ("poll now returning %d\n", rc);
    check_retval ("poll", pentry->clock, pentry->retval, rc);
    if (rc > 0) {
	for (i = 0; i < ppoll->nfds; i++) {
	    if (pollbuf[i].revents != revents[i]) {
		fprintf (stderr, "[MISMATCH] poll index %d: fd %d revents returns 0x%x expected 0x%x\n", i, fds[i].fd, pollbuf[i].revents, revents[i]);
	    }
	}
    }
#endif

    end_timing_func (SYS_poll);
    return rc;
}

// JNF: This is completely wrong - will need to re-write entirely (sigh)
long newselect_recheck ()
{
    struct recheck_entry* pentry;
    struct newselect_recheck* pnewselect;
    fd_set* readfds = NULL;
    fd_set* writefds = NULL;
    fd_set* exceptfds = NULL;
    struct timeval* use_timeout;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pnewselect = (struct newselect_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("newselect: nfds %d readfds %lx writefds %lx exceptfds %lx timeout %lx (tainted? %d) rc %ld clock %lu\n", pnewselect->nfds, (u_long) pnewselect->preadfds,
	    (u_long) pnewselect->pwritefds, (u_long) pnewselect->pexceptfds, (u_long) pnewselect->ptimeout, pnewselect->is_timeout_tainted, pentry->retval, pentry->clock);
#endif 

    if (pnewselect->preadfds) readfds = &pnewselect->readfds;
    if (pnewselect->pwritefds) readfds = &pnewselect->writefds;
    if (pnewselect->pexceptfds) readfds = &pnewselect->exceptfds;
    if (pnewselect->is_timeout_tainted) {
	use_timeout = pnewselect->ptimeout;
	LPRINT ("use_timeout is %lx %lx\n", pnewselect->ptimeout->tv_sec, pnewselect->ptimeout->tv_usec);
    } else {
	use_timeout = &pnewselect->timeout;
	LPRINT ("use_timeout is %lx %lx\n", pnewselect->timeout.tv_sec, pnewselect->timeout.tv_usec);
    }

    start_timing();
    rc = syscall(SYS__newselect, pnewselect->nfds, readfds, writefds, exceptfds, use_timeout);
    end_timing(SYS__newselect, rc);
    check_retval ("select", pentry->clock, pentry->retval, rc);
    if (readfds && memcmp (&pnewselect->readfds, readfds, pnewselect->setsize)) {
	printf ("[MISMATCH] select returns different readfds\n");
	handle_mismatch();
    }
    if (writefds && memcmp (&pnewselect->writefds, writefds, pnewselect->setsize)) {
	printf ("[MISMATCH] select returns different writefds\n");
	handle_mismatch();
    }
    if (exceptfds && memcmp (&pnewselect->exceptfds, exceptfds, pnewselect->setsize)) {
	printf ("[MISMATCH] select returns different exceptfds\n");
	handle_mismatch();
    }
    if (pnewselect->is_timeout_tainted) {
	add_to_taintbuf (pentry, NEWSELECT_TIMEOUT, use_timeout, sizeof(struct timeval));
    }
    end_timing_func (SYS__newselect);
    return rc;
}

long set_robust_list_recheck ()
{
    struct recheck_entry* pentry;
    struct set_robust_list_recheck* pset_robust_list;
    int rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pset_robust_list = (struct set_robust_list_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("set_robust_list: head %lx len %u rc %ld clock %lu\n", (u_long) pset_robust_list->head, pset_robust_list->len, pentry->retval, pentry->clock);
#endif 

    start_timing();
    rc = syscall(SYS_set_robust_list, pset_robust_list->head, pset_robust_list->len);
    end_timing(SYS_set_robust_list, rc);
    check_retval ("set_robust_list", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_set_robust_list);
    return rc;
}

long set_tid_address_recheck ()
{
    struct recheck_entry* pentry;
    struct set_tid_address_recheck* pset_tid_address;
    long rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pset_tid_address = (struct set_tid_address_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("set_tid_address: tidptr %lx rc %ld clock %lu\n", (u_long) pset_tid_address->tidptr, pentry->retval, pentry->clock);
#endif 

    start_timing();
    rc = syscall(SYS_set_tid_address, pset_tid_address->tidptr); 
    end_timing(SYS_set_tid_address, rc);
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(rc));
    end_timing_func (SYS_set_tid_address);
    return rc;
}

long rt_sigaction_recheck ()
{
    struct recheck_entry* pentry;
    struct rt_sigaction_recheck* prt_sigaction;
    struct sigaction* pact = NULL;
    struct sigaction* poact = NULL;
    char* data;
    long rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    prt_sigaction = (struct rt_sigaction_recheck *) bufptr;
    data = bufptr+sizeof(struct rt_sigaction_recheck);
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("rt_sigaction: sig %d act %lx oact %lx sigsetsize %d rc %ld clock %lu\n", prt_sigaction->sig, (u_long) prt_sigaction->act, (u_long) prt_sigaction->oact, prt_sigaction->sigsetsize, pentry->retval, pentry->clock);
#endif 

    if (prt_sigaction->act) pact = (struct sigaction *) data;
#if 0 //this was tainted
    rc = syscall(SYS_rt_sigaction, prt_sigaction->sig, pact, prt_sigaction->oact, prt_sigaction->sigsetsize); 
    start_timing();
    check_retval ("rt_sigaction", pentry->clock, pentry->retval, rc);
    end_timing(SYS_rt_sigaction, rc);
    if (prt_sigaction->oact && rc == 0) {
	//add_to_taintbuf (pentry, SIGACTION_ACTION, prt_sigaction->oact, 20);
    }
#endif
    if (prt_sigaction->oact) poact = (struct sigaction *) tmpbuf;
    start_timing();
    rc = syscall(SYS_rt_sigaction, prt_sigaction->sig, pact, poact, prt_sigaction->sigsetsize);
    check_retval ("rt_sigaction", pentry->clock, pentry->retval, rc);
    end_timing(SYS_rt_sigaction, rc);
    if (prt_sigaction->oact) {
        if (prt_sigaction->act) {
            if (memcmp (tmpbuf, data+20, 20)) {
                u_long* pn = (u_long *) tmpbuf;
                u_long* po = (u_long *) (data+20);
                int i;
                printf ("[MISMATCH] sigaction returns different values\n");
                for (i = 0; i < 5; i++) {
                    printf ("%lx vs. %lx (addr %p)", pn[i], po[i], &po[i]);
                }
                printf ("\n");
                handle_mismatch();
            }
        } else {
            if (memcmp (tmpbuf, data, 20)) {
                u_long* pn = (u_long *) tmpbuf;
                u_long* po = (u_long *) data;
                int i;
                printf ("[MISMATCH] sigaction returns different values (no set)\n");
                for (i = 0; i < 5; i++) {
                    printf ("%lx vs. %lx ", pn[i], po[i]);
                }
                printf ("\n");
                handle_mismatch();
            }
        }
    }

    end_timing_func (SYS_rt_sigaction);
    return rc;
}

long rt_sigprocmask_recheck ()
{
    struct recheck_entry* pentry;
    struct rt_sigprocmask_recheck* prt_sigprocmask;
    sigset_t* pset = NULL;
    sigset_t* poset = NULL;
    char* data;
    long rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    prt_sigprocmask = (struct rt_sigprocmask_recheck *) bufptr;
    data = bufptr+sizeof(struct rt_sigprocmask_recheck);
    bufptr += pentry->len;
    
    if (prt_sigprocmask->set) pset = (sigset_t *) data;
    if (prt_sigprocmask->oset) poset = (sigset_t *) tmpbuf;

#ifdef PRINT_VALUES
    LPRINT ("rt_sigprocmask: how %d set %lx oset %lx sigsetsize %d rc %ld clock %lu setvalue %llu\n", prt_sigprocmask->how, (u_long) prt_sigprocmask->set, 
	    (u_long) prt_sigprocmask->oset, prt_sigprocmask->sigsetsize, pentry->retval, pentry->clock, pset==NULL?0:*(__u64*)pset);
    fflush (stdout);
#endif 

    start_timing();
    rc = syscall(SYS_rt_sigprocmask, prt_sigprocmask->how, pset, poset, prt_sigprocmask->sigsetsize); 
    end_timing(SYS_rt_sigprocmask, rc);
    check_retval ("rt_sigprocmask", pentry->clock, pentry->retval, rc);
    if (prt_sigprocmask->oset) {
	if (prt_sigprocmask->set) {
	    if (memcmp (tmpbuf, data+prt_sigprocmask->sigsetsize, prt_sigprocmask->sigsetsize)) {
		printf ("[MISMATCH] sigprocmask returns different values %llx instead of expected %llx\n", *(__u64*)tmpbuf, *(__u64*)(data + prt_sigprocmask->sigsetsize));
		handle_mismatch();
	    }
	} else {
	    if (memcmp (tmpbuf, data, prt_sigprocmask->sigsetsize)) {
		printf ("[MISMATCH] sigprocmask returns different values %llx instead of expected %llx (no set)\n", *(__u64*)tmpbuf, *(__u64*)data);
#ifdef PRINT_VALUES
		LPRINT ("[MISMATCH] sigprocmask returns different values %llx instead of expected %llx (no set)\n", *(__u64*)tmpbuf, *(__u64*)data);
#endif
#ifdef SIGPROCMAKS_HACK
                //this hack was because the child inherits its parent's sigmask on clone, but we didn't do it in the slice... FIXME later
                printf ("HACK:: manually fixing sigmask\n");
                if (syscall (SYS_rt_sigprocmask, prt_sigprocmask->how, (sigset_t*) data, NULL, 8)) { 
                    printf ("    sigmask fix fails....\n");
                }
#else 
		handle_mismatch();
#endif
	    }
	}
    }
    end_timing_func (SYS_rt_sigprocmask);
    return rc;
}

long mkdir_recheck ()
{
    struct recheck_entry* pentry;
    struct mkdir_recheck* pmkdir;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pmkdir = (struct mkdir_recheck *) bufptr;
    char* fileName = bufptr+sizeof(struct mkdir_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "mkdir: filename %s mode %d", fileName, pmkdir->mode);
    LPRINT ( " rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif
    start_timing();
    rc = syscall(SYS_mkdir, fileName, pmkdir->mode);
    end_timing (SYS_mkdir, rc);
    check_retval ("mkdir", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_mkdir);
    return rc;
}

long unlink_recheck ()
{
    struct recheck_entry* pentry;
#ifdef PRINT_VALUES
    struct unlink_recheck* punlink;
#endif
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
#ifdef PRINT_VALUES
    punlink = (struct unlink_recheck *) bufptr;
#endif
    char* pathname = bufptr+sizeof(struct unlink_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "unlink: pathname %p %s rc %ld clock %lu\n", punlink->pathname, pathname, pentry->retval, pentry->clock);
#endif
    start_timing();
    rc = syscall(SYS_unlink, pathname);
    end_timing (SYS_unlink, rc);
    check_retval ("unlink", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_unlink);
    return rc;
}

long chmod_recheck ()
{
    struct recheck_entry* pentry;
    struct chmod_recheck* pchmod;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pchmod = (struct chmod_recheck *) bufptr;
    char* pathname = bufptr+sizeof(struct chmod_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "chmod: pathname %p %s mode %x rc %ld clock %lu\n", pchmod->pathname, pathname, pchmod->mode, pentry->retval, pentry->clock);
#endif
    start_timing();
    rc = syscall(SYS_chmod, pathname, pchmod->mode);
    end_timing (SYS_chmod, rc);
    check_retval ("chmod", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_chmod);
    return rc;
}

long inotify_init1_recheck ()
{
    struct recheck_entry* pentry;
    struct inotify_init1_recheck* pinotify_init1;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pinotify_init1 = (struct inotify_init1_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "inotify_init1: flags %d rc %ld clock %lu\n", pinotify_init1->flags, pentry->retval, pentry->clock);
#endif
    start_timing();
    rc = syscall(SYS_inotify_init1, pinotify_init1->flags);
    end_timing (SYS_inotify_init1, rc);
    check_retval ("inotify_init1", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_inotify_init1);
    return rc;
}

long inotify_add_watch_recheck ()
{
    struct recheck_entry* pentry;
    struct inotify_add_watch_recheck* pinotify_add_watch;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pinotify_add_watch = (struct inotify_add_watch_recheck *) bufptr;
    char* pathname = bufptr+sizeof(struct inotify_add_watch_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "inotify_add_watch: fd %d pathname %lx %s mask %d rc %ld clock %lu\n", pinotify_add_watch->fd, (u_long) pinotify_add_watch->pathname, 
	     pathname,  pinotify_add_watch->mask, pentry->retval, pentry->clock);
#endif
    start_timing();
    rc = syscall(SYS_inotify_add_watch, pinotify_add_watch->fd, pathname, pinotify_add_watch->mask);
    end_timing (SYS_inotify_add_watch, rc);
    check_retval ("inotify_add_watch", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_inotify_add_watch);
    return rc;
}

long sched_getaffinity_recheck (int pid)
{
    struct recheck_entry* pentry;
    struct sched_getaffinity_recheck* psched;
    pid_t use_pid;
    long rc;

    start_timing_func ();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    psched = (struct sched_getaffinity_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "sched_getaffinity: pid tainted? %d record pid %d passed pid %d clock %lu\n", 
	     psched->is_pid_tainted, psched->pid, pid, pentry->clock);
#endif 
    if (psched->is_pid_tainted) {
	use_pid = pid; 
    } else {
	use_pid = psched->pid;
    }

    start_timing();
    rc = syscall(SYS_sched_getaffinity, use_pid, psched->cpusetsize, tmpbuf);
    end_timing(SYS_sched_getaffinity, rc);
    check_retval ("sched_getaffinity", pentry->clock, pentry->retval, rc);
    if (rc == 0) {
        if (memcmp (tmpbuf, psched->mask, psched->cpusetsize)) {
            printf ("[MISMATCH] sched_getaffinity returns different cpu mask.\n");
            handle_mismatch ();
        }
    }
    end_timing_func (SYS_sched_getaffinity);
    return rc;
}

int ftruncate_recheck ()
{
    struct recheck_entry* pentry;
    struct ftruncate_recheck* pftruncate;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pftruncate = (struct ftruncate_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "ftruncate: fd %u length %lu", pftruncate->fd, pftruncate->length);
    LPRINT ( " rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif
    start_timing();
    rc = syscall(SYS_ftruncate, pftruncate->fd, pftruncate->length);
    end_timing (SYS_ftruncate, rc);
    check_retval ("ftruncate", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_ftruncate);
    return rc;
}

long prctl_recheck ()
{
    struct recheck_entry* pentry;
    struct prctl_recheck* pprctl;
    char* params;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pprctl = (struct prctl_recheck *) bufptr;
    params = bufptr + sizeof(struct prctl_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("prctl: option %d arg2 %lu arg3 %lu arg4 %lu arg5 %lurc %ld clock %lu\n", 
	    pprctl->option, pprctl->arg2, pprctl->arg3, pprctl->arg4, pprctl->arg5, pentry->retval, pentry->clock);
#endif
    start_timing();
    if (pprctl->option == PR_SET_NAME) {
	rc = syscall(SYS_prctl, pprctl->option, params);
    } else if (pprctl->option == PR_GET_NAME) {
	rc = syscall(SYS_prctl, pprctl->option, tmpbuf, pprctl->arg3, pprctl->arg4, pprctl->arg5);
    } else {
	rc = syscall(SYS_prctl, pprctl->option, pprctl->arg2, pprctl->arg3, pprctl->arg4, pprctl->arg5);
    }
    end_timing (SYS_prctl, rc);
    check_retval ("prctl", pentry->clock, pentry->retval, rc);
    if (pprctl->option == PR_GET_NAME) {
	if (memcmp(params, tmpbuf, 16)) {
	    fprintf (stderr, "prctl getname returns name %16s instead of %16s\n", tmpbuf, params);
	    handle_mismatch ();
	}
    }
    end_timing_func (SYS_prctl);
    return rc;
}

long pipe_recheck ()
{
    struct recheck_entry* pentry;
    struct pipe_recheck* ppipe;
    int pipefd[2];
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    ppipe = (struct pipe_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("pipe: pipe %p values %d %d rc %ld clock %lu\n", 
	    ppipe->pipefd, ppipe->piperet[0], ppipe->piperet[1], pentry->retval, pentry->clock);
#endif
    start_timing();
    rc = syscall(SYS_pipe, &pipefd);
    end_timing (SYS_pipe, rc);
    check_retval ("pipe", pentry->clock, pentry->retval, rc);
    if (rc == 0) {
	if (pipefd[0] != ppipe->piperet[0] || pipefd[1] != ppipe->piperet[1]) {
	    fprintf (stderr, "pipe: received fds %d %d vs. exepcted %d %d\n", pipefd[0], pipefd[1], ppipe->piperet[0], ppipe->piperet[1]);
	    handle_mismatch();
	}
    }
    end_timing_func (SYS_pipe);
    return rc;
}

int shmget_recheck ()
{
    struct recheck_entry* pentry;
    struct shmget_recheck* pshmget;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pshmget = (struct shmget_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "shmget: key_t 0x%x size 0x%x shmflag 0x%x rc %ld clock %lu\n", pshmget->key, pshmget->size, pshmget->shmflg, pentry->retval, pentry->clock);
#endif
    start_timing();
    rc = syscall(SYS_ipc, SHMGET, pshmget->key, pshmget->size, pshmget->shmflg);
    end_timing (SYS_ipc, rc);
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(long));
    end_timing_func (SYS_ipc);
    return rc;
}

int shmat_recheck (int shmid)
{
    struct recheck_entry* pentry;
    struct shmat_recheck* pshmat;
    int use_shmid;
    u_long raddr;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    pshmat = (struct shmat_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("shmat: shmid 0x%x tainted? %d (0x%x) addr 0x%lx raddr 0x%lx raddr value 0x%lx shmflag 0x%x rc %ld clock %lu\n", 
	    pshmat->shmid, pshmat->is_shmid_tainted, shmid, (u_long) pshmat->shmaddr, (u_long) pshmat->raddr, (u_long) pshmat->raddrval, pshmat->shmflg, pentry->retval, pentry->clock);
#endif

    if (pshmat->is_shmid_tainted) {
	use_shmid = shmid;
    } else {
	use_shmid = pshmat->shmid;
    }

    start_timing();
    rc = syscall(SYS_munmap, pshmat->raddrval, pshmat->size);
    if (rc != 0) LPRINT ("shmat: munmap of preallocation failed\n");
    rc = syscall(SYS_ipc, SHMAT, use_shmid, 0, &raddr, pshmat->shmflg);
    end_timing (SYS_ipc, rc);
    check_retval ("shmat", pentry->clock, pentry->retval, rc);
    if (pshmat->raddr && raddr != pshmat->raddrval) {
	LPRINT ("shmat: raddr difference at address %lx: %lx expected %lx returned\n", (u_long) pshmat->raddr, pshmat->raddrval, raddr);
    }
    end_timing_func (SYS_ipc);
    return rc;
}

int ipc_rmid_recheck (int shmid)
{
    struct recheck_entry* pentry;
    struct ipc_rmid_recheck* prmid;
    int use_shmid;
    long rc;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    prmid = (struct ipc_rmid_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("shmctl rmid: shmid 0x%x tainted? %d (0x%x) cmd %d rc %ld clock %lu\n", 
	    prmid->shmid, prmid->is_shmid_tainted, shmid, prmid->cmd, pentry->retval, pentry->clock);
#endif

    if (prmid->is_shmid_tainted) {
	use_shmid = shmid;
    } else {
	use_shmid = prmid->shmid;
    }

    start_timing();
    rc = syscall(SYS_ipc, SHMCTL, use_shmid, prmid->cmd);
    end_timing (SYS_ipc, rc);
    check_retval ("shmctl rmid", pentry->clock, pentry->retval, rc);
    end_timing_func (SYS_ipc);
    return rc;
}

void recheck_wait_init ()
{
    if (go_live_clock) {
#ifdef PRINT_SCHEDULING
        int pid = syscall(SYS_gettid);
        printf ("Pid %d recheck_wait_clock_init: %lu mutex %p\n", pid, go_live_clock->slice_clock, &go_live_clock->mutex);
#endif
        go_live_clock->mutex = 0;
        __sync_sub_and_fetch (&go_live_clock->wait_for_other_threads, 1);
        while (go_live_clock->wait_for_other_threads) { 
            //wait until all threads are ready for slice execution
            //just use busy waiting here as it shouldn't take a long time
        }
#ifdef PRINT_SCHEDULING
        printf ("Pid %d recheck_wait_clock_init: all threads are ready to continue!\n", pid);
#endif
    }
}

void recheck_wait_proc_init ()
{
    if (go_live_clock) { 
#ifdef PRINT_SCHEDULING
        int pid = syscall (SYS_gettid);
        printf ("Pid %d recheck_wait_clock_proc_init: this thread is ready to continue\n", pid);
#endif
        __sync_sub_and_fetch (&go_live_clock->wait_for_other_threads, 1);
    }
}

void recheck_thread_wait (int record_pid)
{
    if (go_live_clock) {
        struct go_live_process_map* process_map = go_live_clock->process_map;
        int i = 0;
        struct go_live_process_map* p = NULL;
        int value = 0;
        int fail = 1;
#ifdef PRINT_SCHEDULING
        int pid = syscall(SYS_gettid);
        int actual_pid = 0;
#endif
        while (i < MAX_THREAD_NUM) {
            if (record_pid == process_map[i].record_pid) {
                p = &process_map[i];
                fail = 0;
#ifdef PRINT_SCHEDULING
                actual_pid = process_map[i].current_pid;
#endif
                break;
            }
            if (!process_map[i].record_pid) break;
            ++i;
        }
        if (fail) fprintf (stderr, "recheck_thread_wait cannot find the record_pid????\n");
#ifdef PRINT_SCHEDULING
        printf ("Pid %d call recheck_thread_wait, record_pid %d, addr %p, actual pid %d.\n", pid, record_pid, &p->wait, actual_pid);
        fflush (stdout);
#endif
        value = __sync_sub_and_fetch (&p->value, 1); 
        if (value < 0) {
            syscall (SYS_futex, &p->wait, FUTEX_WAIT, p->wait, NULL, NULL, 0);
        }
    }
}

void recheck_thread_wakeup (int record_pid)
{
    if (go_live_clock) {
        struct go_live_process_map* process_map = go_live_clock->process_map;
        int i = 0;
        struct go_live_process_map* p = NULL;
        int fail = 1;
        int value = 0;
#ifdef PRINT_SCHEDULING
        int actual_pid = 0;
        int pid = syscall(SYS_gettid);
#endif
        while (i < MAX_THREAD_NUM) {
            if (record_pid == process_map[i].record_pid) {
                p = &process_map[i];
#ifdef PRINT_SCHEDULING
                actual_pid = process_map[i].current_pid;
#endif
                fail = 0;
                break;
            }
            if (!process_map[i].record_pid) break;
            ++i;
        }
        if (fail) fprintf (stderr, "recheck_thread_wakeup cannot find the record_pid????\n");
#ifdef PRINT_SCHEDULING
        printf ("Pid %d call recheck_thread_wakeup, to wakeup %d (record_pid), %d (actual pid), addr %p\n", pid, record_pid, actual_pid, &p->wait);
        fflush (stdout);
#endif
        value = __sync_add_and_fetch (&p->value, 1);
        if (value <=0) {
            while (syscall (SYS_futex, &p->wait, FUTEX_WAKE, 1, NULL, NULL, 0) < 1)
                ;
        }
    }
}

int recheck_fake_clone (pid_t record_pid, pid_t* ptid, pid_t* ctid) 
{
    struct recheck_entry* pentry;

    start_timing_func();
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    last_clock = pentry->clock;
    bufptr += pentry->len;

    if (go_live_clock) {
        struct go_live_process_map* process_map = go_live_clock->process_map;
        int i = 0;
        pid_t ret = 0;
        int fail = 1;
        while (i < MAX_THREAD_NUM) {
            if (record_pid == process_map[i].record_pid) {
                ret = process_map[i].current_pid;
                fail = 0;
                break;
            }
            if (!process_map[i].record_pid) break;
            ++i;
        }
        if (fail) fprintf (stderr, "recheck_fake_clone cannot find the record_pid????\n");
#ifdef PRINT_VALUES
        LPRINT ("Pid %ld fake_clone ptid %p(original value %d), ctid %p(original value %d), record pid %d, children pid %d clock %ld\n", syscall(SYS_gettid), ptid, *ptid, ctid, *ctid, record_pid, ret, pentry->clock);
#endif
	// JNF - XXX - really should only do this if the appropriate flags are set  //xdou: yes, in the linkage pintool, this fake_clone function is only generated when appropriate flags are set
        *ptid = ret;
        *ctid = ret;
#ifdef PRINT_VALUES
        LPRINT ("fake_clone ptid now has value %d, ctid %d\n", *ptid, *ctid);
#endif
	add_to_taintbuf (pentry, RETVAL, &ret, sizeof(long));
        return ret;
    } else 
        return 0;
}

#if 0  //xdou: have an another redundant implementation, so this one is commented out for now
void pthread_mutex_lock_shim (int (*fn)(pthread_mutex_t *), pthread_mutex_t* mutex)
{
#ifdef PRINT_VALUES
    int i;
    LPRINT ("pthread_mutex_lock_shim mutex=%lx\n", (u_long) mutex);
    for (i = 0; i < 24; i += 4) {
	LPRINT ("address %lx: value %lx\n", (u_long) mutex+i, *((u_long *)((u_long) mutex + i)));
    }
#endif
    fn (mutex);
#ifdef PRINT_VALUES
    for (i = 0; i < 24; i += 4) {
	LPRINT ("address %lx: value %lx\n", (u_long) mutex+i, *((u_long *)((u_long) mutex + i)));
    }
#endif
}
void pthread_rwlock_rdlock_shim (int (*fn)(pthread_rwlock_t *), pthread_rwlock_t* rwlock)
{
#ifdef PRINT_VALUES
    int i;
    LPRINT ("pthread_rwlock_rdlock_shim rwlock=%lx\n", (u_long) rwlock);
    for (i = 0; i < 32; i += 4) {
	LPRINT ("address %lx: value %lx\n", (u_long) rwlock+i, *((u_long *)((u_long) rwlock + i)));
    }
#endif
    fn (rwlock);
#ifdef PRINT_VALUES
    for (i = 0; i < 32; i += 4) {
	LPRINT ("address %lx: value %lx\n", (u_long) rwlock+i, *((u_long *)((u_long) rwlock + i)));
    }
#endif
}

void pthread_rwlock_wrlock_shim (int (*fn)(pthread_rwlock_t *), pthread_rwlock_t* rwlock)
{
#ifdef PRINT_VALUES
    int i;
    LPRINT ("pthread_rwlock_wrlock_shim rwlock=%lx\n", (u_long) rwlock);
    for (i = 0; i < 32; i += 4) {
	LPRINT ("address %lx: value %lx\n", (u_long) rwlock+i, *((u_long *)((u_long) rwlock + i)));
    }
#endif
    fn (rwlock);
#ifdef PRINT_VALUES
    for (i = 0; i < 32; i += 4) {
	LPRINT ("address %lx: value %lx\n", (u_long) rwlock+i, *((u_long *)((u_long) rwlock + i)));
    }
#endif
}
#endif
