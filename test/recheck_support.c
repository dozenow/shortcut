#include <sys/types.h>

#ifndef __USE_LARGEFILE64
#  define __USE_LARGEFILE64
#endif
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <poll.h>
// Note assert requires locale, which does not work with our hacked libc - don't use it */

#include "../dift/recheck_log.h"
#include "taintbuf.h"

#define PRINT_VALUES
#define PRINT_TO_LOG

#ifdef PRINT_VALUES
char logbuf[4096];
int logfd;
#endif

char buf[1024*1024];
char tmpbuf[1024*1024];
char* bufptr = buf;

struct cfopened {
    int is_open_cache_file;
    struct open_retvals orv;
};

#define MAX_FDS 4096
struct cfopened cache_files_opened[MAX_FDS];

char taintbuf[1024*1024];
long taintndx = 0;

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

static int dump_taintbuf ()
{
    int fd = open ("/tmp/taintbuf", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
	fprintf (stderr, "Cannot open taint buffer file\n");
	return fd;
    }
    
    long rc = write (fd, taintbuf, taintndx);
    if (rc != taintndx) {
	fprintf (stderr, "Tried to write %ld bytes to taint buffer file, rc=%ld\n", taintndx, rc);
	return -1;
    }

    close (fd);
    return 0;
}

void recheck_start(char* filename)
{
    int rc, i, fd;

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

    for (i = 0; i < MAX_FDS; i++) {
	cache_files_opened[i].is_open_cache_file = 0;
    }

#ifdef PRINT_VALUES
#ifdef PRINT_TO_LOG
    fd = open ("/tmp/slice_log", O_RDWR|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) {
	fprintf (stderr, "Cannot open log file\n");
	return;
    }
    rc = dup2 (fd,1023);
    if (rc < 0) {
	fprintf (stderr, "Cannot dup log file descriptor\n");
	return;
    }
    close(fd);
#endif
#endif
}

#ifdef PRINT_TO_LOG
#define LPRINT(args...) sprintf (logbuf, args); write(1023, logbuf, strlen(logbuf));
#else
#define LPRINT printf
#endif

void handle_mismatch()
{
    static int cnt = 0;
    cnt++;
    //if (cnt < 10) sleep (3); // Just so we notice it for now
    dump_taintbuf ();
    abort();
}

void handle_jump_diverge()
{
    int i;
    fprintf (stderr, "[MISMATCH] control flow diverges at %ld.\n", *((u_long *) ((u_long) &i + 32)));
    dump_taintbuf ();
    abort();
}

void handle_index_diverge(u_long foo)
{
    int i;
    fprintf (stderr, "[MISMATCH] index diverges at 0x%lx.\n", *((u_long *) ((u_long) &i + 32)));
    dump_taintbuf ();
    abort ();
}

static inline void check_retval (const char* name, int expected, int actual) {
    if (actual >= 0){
	if (expected != actual) {
	    fprintf (stderr, "[MISMATCH] retval for %s expected %d ret %d\n", name, expected, actual);
	    handle_mismatch();
	}
    } else {
	if (expected != -1*(errno)){
	    fprintf (stderr, "[MISMATCH] retval for %s expected %d ret %d\n", name, expected, -1*(errno));
	    handle_mismatch();
	}  
    }
}

void partial_read (struct read_recheck* pread, char* newdata, char* olddata, int is_cache_file, long total_size) { 
#ifdef PRINT_VALUES
    //only verify bytes not in this range
    int pass = 1;
    LPRINT ("partial read: %d %d\n", pread->partial_read_start, pread->partial_read_end);
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
#ifdef PRINT_VALUES
    if (pass) {
	LPRINT ("partial_read: pass.\n");
    } else {
	LPRINT ("partial_read: verification fails.\n");
    }
#endif
}

void read_recheck (size_t count)
{
    struct recheck_entry* pentry;
    struct read_recheck* pread;
    u_int is_cache_file = 0;
    size_t use_count;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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
    LPRINT ( "fd %d buf %lx count %d/%d tainted? %d readlen %d returns %ld clock %lu\n", pread->fd, (u_long) pread->buf, pread->count, count, pread->is_count_tainted, pread->readlen, pentry->retval, pentry->clock);
#endif

    if (pread->is_count_tainted) {
	use_count = count;
    } else {
	use_count = pread->count;
    }

    if (is_cache_file && pentry->retval >= 0) {
	struct stat64 st;
	if (!cache_files_opened[pread->fd].is_open_cache_file) {
	    printf ("[BUG] cache file should be opened but it is not\n");
	    handle_mismatch();
	}
        if (!pread->partial_read) {
            if (fstat64 (pread->fd, &st) < 0) {
                printf ("[MISMATCH] cannot fstat file\n");
                handle_mismatch ();
            }
            if (st.st_mtim.tv_sec == cache_files_opened[pread->fd].orv.mtime.tv_sec &&
                    st.st_mtim.tv_nsec == cache_files_opened[pread->fd].orv.mtime.tv_nsec) {
                if (lseek(pread->fd, pentry->retval, SEEK_CUR) < 0) {
                    printf ("[MISMATCH] lseek after read failed\n");
                    handle_mismatch();
                }
            } else {
                printf ("[BUG] - file times mismatch but counld check actual file content to see if it still matches\n");
                handle_mismatch();
            }
        } else {
            //read the new content that will be verified
            rc = syscall(SYS_read, pread->fd, tmpbuf, use_count);
	    if (rc != use_count) abort();
	    partial_read (pread, tmpbuf, (char*)pread+sizeof(*pread)+pread->readlen, 1, rc);
        }
    } else {
	if (pentry->retval > (long) sizeof(tmpbuf)) {
	    printf ("[ERROR] retval %ld is greater than temp buf size %d\n", pentry->retval, sizeof(tmpbuf));
	    handle_mismatch();
	}
	if (use_count > (long) sizeof(tmpbuf)) {
	    printf ("[ERROR] count %d is greater than temp buf size %d\n", use_count, sizeof(tmpbuf));
	    handle_mismatch();
	}
	rc = syscall(SYS_read, pread->fd, tmpbuf, use_count);
	check_retval ("read", pentry->retval, rc);
        if (!pread->partial_read) {
	    if (rc > 0) {
		if (memcmp (tmpbuf, readData, rc)) {
		    printf ("[MISMATCH] read returns different values\n");
		    printf ("---\n%s\n---\n%s\n---\n", tmpbuf, readData);
		    handle_mismatch();
		}
	    }
        } else {
            partial_read (pread, tmpbuf, readData, 0, rc);
	}
    }
}

void write_recheck ()
{
    struct recheck_entry* pentry;
    struct write_recheck* pwrite;
    char* data;
    int rc, i;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pwrite = (struct write_recheck *) bufptr;
    data = bufptr + sizeof(struct write_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "write: fd %d buf %lx count %d rc %ld clock %lu\n", pwrite->fd, (u_long) pwrite->buf, pwrite->count, pentry->retval, pentry->clock);
#endif
    if (pwrite->fd == 99999) return;  // Debugging fd - ignore
    if (cache_files_opened[pwrite->fd].is_open_cache_file) {
	printf ("[ERROR] Should not be writing to a cache file\n");
	handle_mismatch();
    }
    char* tainted = data;
    char* outbuf = data + pwrite->count;
    for (i = 0; i < pwrite->count; i++) {
	if (!tainted[i]) ((char *)(pwrite->buf))[i] = outbuf[i];
    }

    rc = syscall(SYS_write, pwrite->fd, pwrite->buf, pwrite->count);
    check_retval ("write", pentry->retval, rc);
}

void open_recheck ()
{
    struct recheck_entry* pentry;
    struct open_recheck* popen;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    popen = (struct open_recheck *) bufptr;
    char* fileName = bufptr+sizeof(struct open_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "open: filename %s flags %x mode %d", fileName, popen->flags, popen->mode);
    if (popen->has_retvals) {
	LPRINT ( " dev %ld ino %ld mtime %ld.%ld", popen->retvals.dev, popen->retvals.ino, 
	       popen->retvals.mtime.tv_sec, popen->retvals.mtime.tv_nsec); 
    }
    LPRINT ( " rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif
    rc = syscall(SYS_open, fileName, popen->flags, popen->mode);
    check_retval ("open", pentry->retval, rc);
    if (rc >= MAX_FDS) abort ();
    if (rc >= 0 && popen->has_retvals) {
	cache_files_opened[rc].is_open_cache_file = 1;
	cache_files_opened[rc].orv = popen->retvals;
    }
}

void openat_recheck ()
{
    struct recheck_entry* pentry;
    struct openat_recheck* popen;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    popen = (struct openat_recheck *) bufptr;
    char* fileName = bufptr+sizeof(struct openat_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "openat: dirfd %d filename %s flags %x mode %d rc %ld clock %lu\n", popen->dirfd, fileName, popen->flags, popen->mode, pentry->retval, pentry->clock);
#endif
    rc = syscall(SYS_openat, popen->dirfd, fileName, popen->flags, popen->mode);
    check_retval ("openat", pentry->retval, rc);
    if  (rc >= MAX_FDS) abort ();
}

void close_recheck ()
{
    struct recheck_entry* pentry;
    struct close_recheck* pclose;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pclose = (struct close_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES 
    LPRINT ("close: fd %d\n clock %lu", pclose->fd, pentry->clock);
#endif

    if (pclose->fd >= MAX_FDS) abort();
    rc = syscall(SYS_close, pclose->fd);
    cache_files_opened[pclose->fd].is_open_cache_file = 0;
    check_retval ("close", pentry->retval, rc);
}

void access_recheck ()
{
    struct recheck_entry* pentry;
    struct access_recheck* paccess;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    paccess = (struct access_recheck *) bufptr;
    char* accessName = bufptr+sizeof(*paccess);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("acccess: mode %d pathname %s rc %ld clock %lu\n", paccess->mode, accessName, pentry->retval, pentry->clock);
#endif

    rc = syscall(SYS_access, accessName, paccess->mode);
    check_retval ("access", pentry->retval, rc);
}

void stat64_alike_recheck (char* syscall_name, int syscall_num)
{
    struct recheck_entry* pentry;
    struct stat64_recheck* pstat64;
    struct stat64 st;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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

    rc = syscall(syscall_num, pathName, &st);
    check_retval (syscall_name, pentry->retval, rc);
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
	if (st.st_nlink != pstat64->retvals.st_nlink) {
	    printf ("[MISMATCH] %s nlink does not match %d vs. recorded %d\n",syscall_name,  st.st_nlink, pstat64->retvals.st_nlink);
	    handle_mismatch();
	}
	if (st.st_uid != pstat64->retvals.st_uid) {
	    printf ("[MISMATCH] %s uid does not match %d vs. recorded %d\n", syscall_name, st.st_uid, pstat64->retvals.st_uid);
	    handle_mismatch();
	}
	if (st.st_gid != pstat64->retvals.st_gid) {
	    printf ("[MISMATCH] %s gid does not match %d vs. recorded %d\n", syscall_name, st.st_gid, pstat64->retvals.st_gid);
	    handle_mismatch();
	}
	if (st.st_rdev != pstat64->retvals.st_rdev) {
	    printf ("[MISMATCH] %s rdev does not match %llu vs. recorded %llu\n", syscall_name, st.st_rdev, pstat64->retvals.st_rdev);
	    handle_mismatch();
	}
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
	((struct stat64 *) pstat64->buf)->st_mtime = st.st_mtime;
	((struct stat64 *) pstat64->buf)->st_ctime = st.st_ctime;
	((struct stat64 *) pstat64->buf)->st_atime = st.st_atime;
	add_to_taintbuf (pentry, STAT64_INO, &st.st_ino, sizeof(st.st_ino));
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
}

void stat64_recheck () { 
    stat64_alike_recheck ("stat64", SYS_stat64);
}

void lstat64_recheck () { 
    stat64_alike_recheck ("lstat64", SYS_lstat64);
}

void fstat64_recheck ()
{
    struct recheck_entry* pentry;
    struct fstat64_recheck* pfstat64;
    struct stat64 st;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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

    rc = syscall(SYS_fstat64, pfstat64->fd, &st);
    check_retval ("fstat64", pentry->retval, rc);
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
	if (st.st_nlink != pfstat64->retvals.st_nlink) {
	    printf ("[MISMATCH] fstat64 nlink does not match %d vs. recorded %d\n", st.st_nlink, pfstat64->retvals.st_nlink);
	    handle_mismatch();
	}
	if (st.st_uid != pfstat64->retvals.st_uid) {
	    printf ("[MISMATCH] fstat64 uid does not match %d vs. recorded %d\n", st.st_uid, pfstat64->retvals.st_uid);
	    handle_mismatch();
	}
	if (st.st_gid != pfstat64->retvals.st_gid) {
	    printf ("[MISMATCH] fstat64 gid does not match %d vs. recorded %d\n", st.st_gid, pfstat64->retvals.st_gid);
	    handle_mismatch();
	}
	if (st.st_rdev != pfstat64->retvals.st_rdev) {
	    printf ("[MISMATCH] fstat64 rdev does not match %llu vs. recorded %llu\n", st.st_rdev, pfstat64->retvals.st_rdev);
	    handle_mismatch();
	}
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
	((struct stat64 *) pfstat64->buf)->st_mtime = st.st_mtime;
	((struct stat64 *) pfstat64->buf)->st_ctime = st.st_ctime;
	((struct stat64 *) pfstat64->buf)->st_atime = st.st_atime;
	add_to_taintbuf (pentry, STAT64_INO, &st.st_ino, sizeof(st.st_ino));
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
}

void fcntl64_getfl_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_getfl_recheck* pgetfl;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pgetfl = (struct fcntl64_getfl_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fcntl64 getfl: fd %d rc %ld clock %lu\n", pgetfl->fd, pentry->retval, pentry->clock);
#endif

    rc = syscall(SYS_fcntl64, pgetfl->fd, F_GETFL);
    check_retval ("fcntl64 getfl", pentry->retval, rc);
}

void fcntl64_setfl_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_setfl_recheck* psetfl;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    psetfl = (struct fcntl64_setfl_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fcntl64 setfl: fd %d flags %lx rc %ld clock %lu\n", psetfl->fd, psetfl->flags, pentry->retval, pentry->clock);
#endif

    rc = syscall(SYS_fcntl64, psetfl->fd, F_SETFL, psetfl->flags);
    check_retval ("fcntl64 setfl", pentry->retval, rc);
}

void fcntl64_getlk_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_getlk_recheck* pgetlk;
    struct flock fl;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pgetlk = (struct fcntl64_getlk_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "fcntl64 getlk: fd %d arg %lx rc %ld clock %lu\n", pgetlk->fd, (u_long) pgetlk->arg, pentry->retval, pentry->clock);
#endif

    rc = syscall(SYS_fcntl64, pgetlk->fd, F_GETLK, &fl);
    check_retval ("fcntl64 getlk", pentry->retval, rc);
    if (pgetlk->has_retvals) {
	if (memcmp(&fl, &pgetlk->flock, sizeof(fl))) {
	    printf ("[MISMATCH] fcntl64 getlk does not match\n");
	    handle_mismatch();
	}
    }
}

void fcntl64_getown_recheck ()
{
    struct recheck_entry* pentry;
    struct fcntl64_getown_recheck* pgetown;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pgetown = (struct fcntl64_getown_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ("fcntl64 getown: fd %d rc %ld clock %lu\n", pgetown->fd, pentry->retval, pentry->clock);
#endif

    rc = syscall(SYS_fcntl64, pgetown->fd, F_GETOWN);
    check_retval ("fcntl64 getown", pentry->retval, rc);
}

void fcntl64_setown_recheck (long owner)
{
    struct recheck_entry* pentry;
    struct fcntl64_setown_recheck* psetown;
    long use_owner;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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

    rc = syscall(SYS_fcntl64, psetown->fd, F_SETOWN, use_owner);
    check_retval ("fcntl64 setown", pentry->retval, rc);
}

void ugetrlimit_recheck ()
{
    struct recheck_entry* pentry;
    struct ugetrlimit_recheck* pugetrlimit;
    struct rlimit rlim;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pugetrlimit = (struct ugetrlimit_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "ugetrlimit: resource %d rlimit %ld %ld rc %ld clock %lu\n", pugetrlimit->resource, pugetrlimit->rlim.rlim_cur, pugetrlimit->rlim.rlim_max, pentry->retval, pentry->clock);
#endif

    rc = syscall(SYS_ugetrlimit, pugetrlimit->resource, &rlim);
    check_retval ("ugetrlimit", pentry->retval, rc);
    if (memcmp(&rlim, &pugetrlimit->rlim, sizeof(rlim))) {
	printf ("[MISMATCH] ugetrlimit does not match: returns %ld %ld\n", rlim.rlim_cur, rlim.rlim_max);
	handle_mismatch();
    }
}

void uname_recheck ()
{
    struct recheck_entry* pentry;
    struct uname_recheck* puname;
    struct utsname uname;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    puname = (struct uname_recheck *) bufptr;
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "uname: sysname %s nodename %s release %s version %s machine %s rc %ld clock %lu\n", 
	     puname->utsname.sysname, puname->utsname.nodename, puname->utsname.release, puname->utsname.version, puname->utsname.machine, pentry->retval, pentry->clock);
#endif

    rc = syscall(SYS_uname, &uname);
    check_retval ("uname", pentry->retval, rc);

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
}

void statfs64_recheck ()
{
    struct recheck_entry* pentry;
    struct statfs64_recheck* pstatfs64;
    struct statfs64 st;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pstatfs64 = (struct statfs64_recheck *) bufptr;
    char* path = bufptr+sizeof(struct statfs64_recheck);
    bufptr += pentry->len;

#ifdef PRINT_VALUES
    LPRINT ( "statfs64: path %s size %u type %d bsize %d blocks %lld bfree %lld bavail %lld files %lld ffree %lld fsid %d %d namelen %d frsize %d rc %ld clock %lu\n", path, pstatfs64->sz,
	   pstatfs64->statfs.f_type, pstatfs64->statfs.f_bsize, pstatfs64->statfs.f_blocks, pstatfs64->statfs.f_bfree, pstatfs64->statfs.f_bavail, pstatfs64->statfs.f_files, 
	     pstatfs64->statfs.f_ffree, pstatfs64->statfs.f_fsid.__val[0], pstatfs64->statfs.f_fsid.__val[1], pstatfs64->statfs.f_namelen, pstatfs64->statfs.f_frsize, pentry->retval, pentry->clock);
#endif

    rc = syscall(SYS_statfs64, path, pstatfs64->sz, &st);
    check_retval ("statfs64", pentry->retval, rc);
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
}

void gettimeofday_recheck () { 
	struct recheck_entry* pentry;
	struct gettimeofday_recheck *pget;
	struct timeval tv;
	struct timezone tz;
	int rc;

	pentry = (struct recheck_entry *) bufptr;
	bufptr += sizeof(struct recheck_entry);
	pget = (struct gettimeofday_recheck *) bufptr;
	bufptr += pentry->len;

#ifdef PRINT_VALUES
	LPRINT ( "gettimeofday: pointer tv %lx tz %lx clock %lu\n", (long) pget->tv_ptr, (long) pget->tz_ptr, pentry->clock);
#endif
	rc = syscall (SYS_gettimeofday, &tv, &tz);
	check_retval ("gettimeofday", pentry->retval, rc);

	if (pget->tv_ptr) { 
		memcpy (pget->tv_ptr, &tv, sizeof(struct timeval));
		add_to_taintbuf (pentry, GETTIMEOFDAY_TV, &tv, sizeof(struct timeval));
	}
	if (pget->tz_ptr) { 
		memcpy (pget->tz_ptr, &tz, sizeof(struct timezone));
		add_to_taintbuf (pentry, GETTIMEOFDAY_TZ, &tz, sizeof(struct timezone));
	}
}

long time_recheck () { 
    struct recheck_entry* pentry;
    struct time_recheck *pget;
    int rc;
    
    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pget = (struct time_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    printf ("time: pointer t %x clock %lu\n", (int)(pget->t), pentry->clock);
#endif
    rc = syscall (SYS_time, pget->t);
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(long));
    if (rc >= 0 && pget->t) add_to_taintbuf (pentry, RETBUF, pget->t, sizeof(time_t));
    return rc;
}

void prlimit64_recheck ()
{
    struct recheck_entry* pentry;
    struct prlimit64_recheck* prlimit;
    struct rlimit64 rlim;
    struct rlimit64* prlim;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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
    rc = syscall(SYS_prlimit64, prlimit->pid, prlimit->resource, prlimit->new_limit, prlim);
    check_retval ("prlimit64", pentry->retval, rc);
    if (prlimit->has_retvals) {
	if (prlimit->retparams.rlim_cur != rlim.rlim_cur) {
	    printf ("[MISMATCH] prlimit64 soft limit does not match: %lld\n", rlim.rlim_cur);
	}
	if (prlimit->retparams.rlim_max != rlim.rlim_max) {
	    printf ("[MISMATCH] prlimit64 hard limit does not match: %lld\n", rlim.rlim_max);
	}
    }
}

void setpgid_recheck (int pid, int pgid)
{
    struct recheck_entry* pentry;
    struct setpgid_recheck* psetpgid;
    pid_t use_pid, use_pgid;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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

    rc = syscall(SYS_setpgid, use_pid, use_pgid);
    check_retval ("setpgid", pentry->retval, rc);
}

void readlink_recheck ()
{
    struct recheck_entry* pentry;
    struct readlink_recheck* preadlink;
    char* linkdata;
    char* path;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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
    rc = syscall(SYS_readlink, path, tmpbuf, preadlink->bufsiz);
    check_retval ("readlink", pentry->retval, rc);
    if (rc > 0) {
	if (memcmp(tmpbuf, linkdata, pentry->retval)) {
	    printf ("[MISMATCH] readdata returns link data %s\n", linkdata);
	    handle_mismatch();
	}
    }
}

void socket_recheck ()
{
    struct recheck_entry* pentry;
    struct socket_recheck* psocket;
    u_long block[6];
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    psocket = (struct socket_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "socket: domain %d type %d protocol %d rc %ld clock %lu\n", psocket->domain, psocket->type, psocket->protocol, pentry->retval, pentry->clock);
#endif 

    block[0] = psocket->domain;
    block[1] = psocket->type;
    block[2] = psocket->protocol;
    rc = syscall(SYS_socketcall, SYS_SOCKET, &block);
    check_retval ("socket", pentry->retval, rc);
}

inline void process_taintmask (char* mask, u_long size, char* buffer)
{
    u_long i;
    char* outbuf = mask + size;
    for (i = 0; i < size; i++) {
	if (!mask[i]) buffer[i] = outbuf[i];
    }
}

inline void connect_or_bind_recheck (int call, char* call_name)
{
    struct recheck_entry* pentry;
    struct connect_recheck* pconnect;
    u_long block[6];
    char* addr;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pconnect = (struct connect_recheck *) bufptr;
    addr = bufptr+sizeof(struct connect_recheck);
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "%s: sockfd %d addlen %d rc %ld clock %lu\n", call_name, pconnect->sockfd, pconnect->addrlen, pentry->retval, pentry->clock);
#endif 
    process_taintmask(addr, pconnect->addrlen, (char *) pconnect->addr);

    block[0] = pconnect->sockfd;
    block[1] = (u_long) pconnect->addr;
    block[2] = pconnect->addrlen;
    rc = syscall(SYS_socketcall, call, &block);
    check_retval (call_name, pentry->retval, rc);
}

void connect_recheck () { 
    connect_or_bind_recheck (SYS_CONNECT, "connect");
}

void bind_recheck () {
    connect_or_bind_recheck (SYS_BIND, "bind");
}

long getpid_recheck ()
{
    long rc;
    struct recheck_entry* pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);

#ifdef PRINT_VALUES
    LPRINT ( "getpid: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    rc = syscall(SYS_getpid);
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(rc));
    return rc;
}

long getpgrp_recheck ()
{
    long rc;
    struct recheck_entry* pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);

#ifdef PRINT_VALUES
    LPRINT ("getpgrp: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    rc =  syscall(SYS_getpgrp);
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(rc));
    return rc;
}

void getuid32_recheck ()
{
    struct recheck_entry* pentry;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);

#ifdef PRINT_VALUES
    LPRINT ( "getuid32: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    rc = syscall(SYS_getuid32);
    check_retval ("getuid32", pentry->retval, rc);
}

void geteuid32_recheck ()
{
    struct recheck_entry* pentry;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);

#ifdef PRINT_VALUES
    LPRINT ( "geteuid32: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    rc = syscall(SYS_geteuid32);
    check_retval ("geteuid32", pentry->retval, rc);
}

void getgid32_recheck ()
{
    struct recheck_entry* pentry;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);

#ifdef PRINT_VALUES
    LPRINT ( "getgid32: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    rc = syscall(SYS_getgid32);
    check_retval ("getgid32", pentry->retval, rc);
}

void getegid32_recheck ()
{
    struct recheck_entry* pentry;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);

#ifdef PRINT_VALUES
    LPRINT ( "getegid32: rc %ld clock %lu\n", pentry->retval, pentry->clock);
#endif 
    rc = syscall(SYS_getegid32);
    check_retval ("getegid32", pentry->retval, rc);
}

void llseek_recheck ()
{
    struct recheck_entry* pentry;
    struct llseek_recheck* pllseek;
    loff_t off;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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

    rc = syscall(SYS__llseek, pllseek->fd, pllseek->offset_high, pllseek->offset_low, &off, pllseek->whence);
    check_retval ("llseek", pentry->retval, rc);
    if (rc >= 0 && off != pllseek->result) {
	printf ("[MISMATCH] llseek returns offset %llu\n", off);
	handle_mismatch();
    }
}

void ioctl_recheck ()
{
    struct recheck_entry* pentry;
    struct ioctl_recheck* pioctl;
    char* addr;
    int rc, i;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pioctl = (struct ioctl_recheck *) bufptr;
    addr = bufptr+sizeof(struct ioctl_recheck);
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "ioctl: fd %u cmd %x dir %x size %x arg %lx arglen %ld rc %ld clock %lu\n", pioctl->fd, pioctl->cmd, pioctl->dir, pioctl->size, (u_long) pioctl->arg, pioctl->arglen, pentry->retval, pentry->clock);
#endif 

    if (pioctl->dir == _IOC_WRITE) {
	rc = syscall(SYS_ioctl, pioctl->fd, pioctl->cmd, tmpbuf);
	check_retval ("ioctl", pentry->retval, rc);
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
	    char* tainted = addr;
	    char* outbuf = addr + pioctl->size;
	    for (i = 0; i < pioctl->size; i ++) {
		if (!tainted[i]) pioctl->arg[i] = outbuf[i];
	    }
	}
	rc = syscall(SYS_ioctl, pioctl->fd, pioctl->cmd, pioctl->arg);
	check_retval ("ioctl", pentry->retval, rc);
    } else {
	printf ("[ERROR] ioctl_recheck only handles ioctl dir _IOC_WRITE and _IOC_READ for now\n");
    }
}

// Can I find this definition at user level?
struct linux_dirent64 {
	__u64		d_ino;
	__s64		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[0];
};

void getdents64_recheck ()
{
    struct recheck_entry* pentry;
    struct getdents64_recheck* pgetdents64;
    char* dents;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pgetdents64 = (struct getdents64_recheck *) bufptr;
    if (pgetdents64->arglen > 0) {
	dents = bufptr+sizeof(struct getdents64_recheck);
    }
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ( "getdents64: fd %u buf %p count %u arglen %ld rc %ld clock %lu\n", pgetdents64->fd, pgetdents64->buf, pgetdents64->count, pgetdents64->arglen, pentry->retval, pentry->clock);
#endif 
    rc = syscall(SYS_getdents64, pgetdents64->fd, tmpbuf, pgetdents64->count);
    check_retval ("getdents64", pentry->retval, rc);
    if (rc > 0) {
	int compared = 0;
	char* p = dents; 
	char* c = tmpbuf;
	while (compared < rc) {
	    struct linux_dirent64* prev = (struct linux_dirent64 *) p;
	    struct linux_dirent64* curr = (struct linux_dirent64 *) c;
	    if (prev->d_ino != curr->d_ino || prev->d_off != curr->d_off ||
		prev->d_reclen != curr->d_reclen || prev->d_type != curr->d_type ||
		strcmp(prev->d_name, curr->d_name)) {
		printf ("{MISMATCH] getdetnts64: inode %llu vs. %llu\t", prev->d_ino, curr->d_ino);
		printf ("offset %lld vs. %lld\t", prev->d_off, curr->d_off);
		printf ("reclen %d vs. %d\t", prev->d_reclen, curr->d_reclen);
		printf ("name %s vs. %s\t", prev->d_name, curr->d_name);
		printf ("type %d vs. %d\n", prev->d_type, curr->d_type);
		handle_mismatch();
	    }
	    if (prev->d_reclen <= 0) break;
	    p += prev->d_reclen; c += curr->d_reclen; compared += prev->d_reclen;
	}
    }
}

void eventfd2_recheck ()
{
    struct recheck_entry* pentry;
    struct eventfd2_recheck* peventfd2;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    peventfd2 = (struct eventfd2_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("eventfd2: count %u flags %x rc %ld clock %lu\n", peventfd2->count, peventfd2->flags, pentry->retval, pentry->clock);
#endif 

    rc = syscall(SYS_eventfd2, peventfd2->count, peventfd2->flags);
    check_retval ("eventfd2", pentry->retval, rc);
}

void poll_recheck ()
{
    struct recheck_entry* pentry;
    struct poll_recheck* ppoll;
    struct pollfd* fds;
    struct pollfd* pollbuf = (struct pollfd *) tmpbuf;
    short* revents;
    int rc;
    u_int i;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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

    memcpy (tmpbuf, fds, ppoll->nfds*sizeof(struct pollfd));
    rc = syscall(SYS_poll, pollbuf, ppoll->nfds, ppoll->timeout);
    if (rc > 0) {
	for (i = 0; i < ppoll->nfds; i++) {
	    LPRINT ("\tfd %d events %x returns revents %x\n", pollbuf[i].fd, pollbuf[i].events, pollbuf[i].revents);
	}
    }
    check_retval ("poll", pentry->retval, rc);
    if (rc > 0) {
	for (i = 0; i < ppoll->nfds; i++) {
	    if (pollbuf[i].revents != revents[i]) {
		printf ("{MISMATCH] poll index %d: fd %d revents returns %x\t", i, fds[i].fd, pollbuf[i].revents);
	    }
	}
    }
}

void newselect_recheck ()
{
    struct recheck_entry* pentry;
    struct newselect_recheck* pnewselect;
    fd_set* readfds = NULL;
    fd_set* writefds = NULL;
    fd_set* exceptfds = NULL;
    struct timeval* use_timeout;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
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

    rc = syscall(SYS__newselect, pnewselect->nfds, readfds, writefds, exceptfds, use_timeout);
    check_retval ("select", pentry->retval, rc);
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
}

void set_robust_list_recheck ()
{
    struct recheck_entry* pentry;
    struct set_robust_list_recheck* pset_robust_list;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pset_robust_list = (struct set_robust_list_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("set_robust_list: head %lx len %u rc %ld clock %lu\n", (u_long) pset_robust_list->head, pset_robust_list->len, pentry->retval, pentry->clock);
#endif 

    rc = syscall(SYS_set_robust_list, pset_robust_list->head, pset_robust_list->len);
    check_retval ("set_robust_list", pentry->retval, rc);
}

long set_tid_address_recheck ()
{
    struct recheck_entry* pentry;
    struct set_tid_address_recheck* pset_tid_address;
    long rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pset_tid_address = (struct set_tid_address_recheck *) bufptr;
    bufptr += pentry->len;
    
#ifdef PRINT_VALUES
    LPRINT ("set_tid_address: tidptr %lx rc %ld clock %lu\n", (u_long) pset_tid_address->tidptr, pentry->retval, pentry->clock);
#endif 

    rc =  syscall(SYS_set_tid_address, pset_tid_address->tidptr); 
    add_to_taintbuf (pentry, RETVAL, &rc, sizeof(rc));
    return rc;
}

