#include <sys/types.h>

#ifndef __USE_LARGEFILE64
#  define __USE_LARGEFILE64
#endif
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

#include "../dift/recheck_log.h"

#define PRINT_VALUES

char buf[1024*1024];
char tmpbuf[1024*1024];
char* bufptr = buf;

struct cfopened {
    int is_open_cache_file;
    struct open_retvals orv;
};

#define MAX_FDS 4096
struct cfopened cache_files_opened[MAX_FDS];

void recheck_start(char* filename)
{
    int rc, i, fd;
    int index = -64;

    printf ("filename is %s, %p\n", filename, filename);
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
}

void handle_mismatch()
{
    sleep (5); // Just so we notice it for now
}

static inline void check_retval (const char* name, int expected, int actual) {
    if (actual >= 0){
	if (expected != actual) {
	    printf ("[MISMATCH] retval for %s expected %d ret %d\n", name, expected, actual);
	    handle_mismatch();
	}
    } else {
	if (expected != -1*(errno)){
	    printf ("[MISMATCH] retval for %s expected %d ret %d\n", name, expected, -1*(errno));
	    handle_mismatch();
	}  
    }
}

void read_recheck ()
{
    struct recheck_entry* pentry;
    struct read_recheck* pread;
    u_int is_cache_file = 0;
    int rc;

    pentry = (struct recheck_entry *) bufptr;
    bufptr += sizeof(struct recheck_entry);
    pread = (struct read_recheck *) bufptr;
    char* readData = buf+sizeof(*pread);
    bufptr += pentry->len;

    if (pread->has_retvals) {
	is_cache_file = *((u_int *)readData);
    }
#ifdef PRINT_VALUES
    printf("read: has ret vals %d\n", pread->has_retvals);
    if (pread->has_retvals) {
	printf ("is_cache_file: %x\n", is_cache_file);
    }
    printf("fd %d\n", pread->fd);
    printf("buf %p\n", pread->buf);
    printf("count %d\n", pread->count);
    printf("readlen %d\n", pread->readlen);
#endif
    if (is_cache_file && pentry->retval >= 0) {
	struct stat64 st;
	if (!cache_files_opened[pread->fd].is_open_cache_file) {
	    printf ("[BUG] cache file should be opened but it is not\n");
	    handle_mismatch();
	}
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
	assert (pentry->retval < sizeof(tmpbuf));
	assert ((*pread).count < sizeof(tmpbuf));
	rc = syscall(SYS_read,(*pread).fd, tmpbuf, (*pread).count);
	check_retval ("read", pentry->retval, rc);
	if (rc > 0) {
	    if (memcmp (buf, readData, rc)) {
		printf ("[MISMATCH] read returns different values\n");
		handle_mismatch();
	    }
	}
    }
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
    printf("open: has ret vals %d\n", popen->has_retvals);
    printf("flags %x\n", popen->flags);
    printf("mode %d\n", popen->mode);
    printf("filename %s\n", fileName);
    if (popen->has_retvals) {
	printf("retvals: dev %ld ino %ld mtime %ld.%ld \n", popen->retvals.dev, popen->retvals.ino, 
	       popen->retvals.mtime.tv_sec, popen->retvals.mtime.tv_nsec); 
    }
#endif
    rc = syscall(SYS_open, fileName, popen->flags, popen->mode);
    check_retval ("open", pentry->retval, rc);
    assert (rc < MAX_FDS);
    if (rc >= 0 && popen->has_retvals) {
	cache_files_opened[rc].is_open_cache_file = 1;
	cache_files_opened[rc].orv = popen->retvals;
    }
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
    printf("close: fd %d\n", pclose->fd);
#endif

    assert (pclose->fd < MAX_FDS);
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
    printf("acccess: mode %d pathname %s\n", paccess->mode, accessName);
#endif

    rc = syscall(SYS_access, accessName, paccess->mode);
    check_retval ("access", pentry->retval, rc);
}

void stat64_recheck ()
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
    printf("stat64: has ret vals %d\n", pstat64->has_retvals);
    if (pstat64->has_retvals) {
	printf("stat64 retvals: st_dev %llu st_ino %llu st_mode %d st_nlink %d st_uid %d st_gid %d st_rdev %llu "
	       "st_size %lld st_atime %ld st_mtime %ld st_ctime %ld st_blksize %ld st_blocks %lld\n",
	       pstat64->retvals.st_dev, pstat64->retvals.st_ino, pstat64->retvals.st_mode, pstat64->retvals .st_nlink, pstat64->retvals.st_uid,pstat64->retvals .st_gid,
	       pstat64->retvals.st_rdev, pstat64->retvals.st_size, pstat64->retvals .st_atime, pstat64->retvals.st_mtime, pstat64->retvals.st_ctime, pstat64->retvals.st_blksize,
	       pstat64->retvals.st_blocks); 
    }
    printf("buf %p\n", pstat64->buf);
    printf("pathname %s\n", pathName);
#endif

    rc = syscall(SYS_stat64, pathName, &st);
    check_retval ("stat64", pentry->retval, rc);
    if (pstat64->has_retvals) {
	if (st.st_dev != pstat64->retvals.st_dev) {
	    printf ("[MISMATCH] stat64 dev does not match %llu vs. recorded %llu\n", st.st_dev, pstat64->retvals.st_dev);
	    handle_mismatch();
	}
	if (st.st_ino != pstat64->retvals.st_ino) {
	    printf ("[MISMATCH] stat64 ino does not match %llu vs. recorded %llu\n", st.st_ino, pstat64->retvals.st_ino);
	    handle_mismatch();
	}
	if (st.st_mode != pstat64->retvals.st_mode) {
	    printf ("[MISMATCH] stat64 mode does not match %d vs. recorded %d\n", st.st_mode, pstat64->retvals.st_mode);
	    handle_mismatch();
	}
	if (st.st_nlink != pstat64->retvals.st_nlink) {
	    printf ("[MISMATCH] stat64 nlink does not match %d vs. recorded %d\n", st.st_nlink, pstat64->retvals.st_nlink);
	    handle_mismatch();
	}
	if (st.st_uid != pstat64->retvals.st_uid) {
	    printf ("[MISMATCH] stat64 uid does not match %d vs. recorded %d\n", st.st_uid, pstat64->retvals.st_uid);
	    handle_mismatch();
	}
	if (st.st_gid != pstat64->retvals.st_gid) {
	    printf ("[MISMATCH] stat64 gid does not match %d vs. recorded %d\n", st.st_gid, pstat64->retvals.st_gid);
	    handle_mismatch();
	}
	if (st.st_rdev != pstat64->retvals.st_rdev) {
	    printf ("[MISMATCH] stat64 rdev does not match %llu vs. recorded %llu\n", st.st_rdev, pstat64->retvals.st_rdev);
	    handle_mismatch();
	}
	if (st.st_size != pstat64->retvals.st_size) {
	    printf ("[MISMATCH] stat64 size does not match %lld vs. recorded %lld\n", st.st_size, pstat64->retvals.st_size);
	    handle_mismatch();
	}
	if (st.st_mtime != pstat64->retvals.st_mtime) {
	    printf ("[MISMATCH] stat64 mtime does not match %ld vs. recorded %ld\n", st.st_mtime, pstat64->retvals.st_mtime);
	    handle_mismatch();
	}
	if (st.st_ctime != pstat64->retvals.st_ctime) {
	    printf ("[MISMATCH] stat64 ctime does not match %ld vs. recorded %ld\n", st.st_ctime, pstat64->retvals.st_ctime);
	    handle_mismatch();
	}
	/* Assume atime will be handled by tainting since it changes often */
	if (st.st_blksize != pstat64->retvals.st_blksize) {
	    printf ("[MISMATCH] stat64 blksize does not match %ld vs. recorded %ld\n", st.st_blksize, pstat64->retvals.st_blksize);
	    handle_mismatch();
	}
	if (st.st_blocks != pstat64->retvals.st_blocks) {
	    printf ("[MISMATCH] stat64 blocks does not match %lld vs. recorded %lld\n", st.st_blocks, pstat64->retvals.st_blocks);
	    handle_mismatch();
	}
    }
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
    printf("fstat64: has ret vals %d\n", pfstat64->has_retvals);
    if (pfstat64->has_retvals) {
	printf("fstat64 retvals: st_dev %llu st_ino %llu st_mode %d st_nlink %d st_uid %d st_gid %d st_rdev %llu "
	       "st_size %lld st_atime %ld st_mtime %ld st_ctime %ld st_blksize %ld st_blocks %lld\n",
	       pfstat64->retvals.st_dev, pfstat64->retvals.st_ino, pfstat64->retvals.st_mode, pfstat64->retvals .st_nlink, pfstat64->retvals.st_uid,pfstat64->retvals .st_gid,
	       pfstat64->retvals.st_rdev, pfstat64->retvals.st_size, pfstat64->retvals .st_atime, pfstat64->retvals.st_mtime, pfstat64->retvals.st_ctime, pfstat64->retvals.st_blksize,
	       pfstat64->retvals.st_blocks); 
    }
    printf("buf %p\n", pfstat64->buf);
    printf("fd %d\n", pfstat64->fd);
#endif

    rc = syscall(SYS_fstat64, pfstat64->fd, &st);
    check_retval ("fstat64", pentry->retval, rc);
    if (pfstat64->has_retvals) {
	if (st.st_dev != pfstat64->retvals.st_dev) {
	    printf ("[MISMATCH] fstat64 dev does not match %llu vs. recorded %llu\n", st.st_dev, pfstat64->retvals.st_dev);
	    handle_mismatch();
	}
	if (st.st_ino != pfstat64->retvals.st_ino) {
	    printf ("[MISMATCH] fstat64 ino does not match %llu vs. recorded %llu\n", st.st_ino, pfstat64->retvals.st_ino);
	    handle_mismatch();
	}
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
	if (st.st_mtime != pfstat64->retvals.st_mtime) {
	    printf ("[MISMATCH] fstat64 mtime does not match %ld vs. recorded %ld\n", st.st_mtime, pfstat64->retvals.st_mtime);
	    handle_mismatch();
	}
	if (st.st_ctime != pfstat64->retvals.st_ctime) {
	    printf ("[MISMATCH] fstat64 ctime does not match %ld vs. recorded %ld\n", st.st_ctime, pfstat64->retvals.st_ctime);
	    handle_mismatch();
	}
	/* Assume atime will be handled by tainting since it changes often */
	((struct stat64 *) pfstat64->buf)->st_atime = st.st_atime;
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
    printf("ugetrlimit: resource %d rlimit %ld %ld rc %ld\n", pugetrlimit->resource, pugetrlimit->rlim.rlim_cur,
	   pugetrlimit->rlim.rlim_max, pentry->retval);
#endif

    rc = syscall(SYS_ugetrlimit, pugetrlimit->resource, &rlim);
    check_retval ("ugetrlimit", pentry->retval, rc);
    if (memcmp(&rlim, &pugetrlimit->rlim, sizeof(rlim))) {
	fprintf (stderr, "[MISMATCH] ugetrlimit does not match: returns %ld %ld\n", rlim.rlim_cur, rlim.rlim_max);
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
    printf("uname: sysname %s nodename %s release %s version %s machine %s rc %ld\n", 
	   puname->utsname.sysname, puname->utsname.nodename, puname->utsname.release, puname->utsname.version, 
	   puname->utsname.machine, pentry->retval);
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
    memcpy (&((struct utsname *) puname->buf)->version, &puname->utsname.version, sizeof(puname->utsname.version));
    if (memcmp(&uname.machine, &puname->utsname.machine, sizeof(uname.machine))) {
	fprintf (stderr, "[MISMATCH] uname machine does not match: %s\n", uname.machine);
	handle_mismatch();
    }
}

