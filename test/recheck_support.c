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
    static cnt = 0;
    cnt++;
    if (cnt < 3) sleep (5); // Just so we notice it for now
}

void handle_jump_diverge()
{
    fprintf (stderr, "[MISMATCH] control flow diverges.\n");
    //fail hardly
    exit(-1);
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

void partial_read (struct read_recheck* pread, char* newdata, char* olddata, int is_cache_file, long total_size) { 
    //only verify bytes not in this range
    int pass = 1;
    printf("partial read: %d %d\n", pread->partial_read_start, pread->partial_read_end);
    if (pread->partial_read_start > 0) { 
        if (memcmp (newdata, olddata, pread->partial_read_start)) {
            printf ("[MISMATCH] read returns different values for partial read: before start\n");
            handle_mismatch();
	    pass = 0;
        }
    }
    if(pread->partial_read_end > total_size) 
	    printf ("[BUG] partial_read_end out of boundary.\n");
    if (pread->partial_read_end < total_size) { 
	    if (is_cache_file == 0) {
		    if (memcmp (newdata+pread->partial_read_end, olddata+pread->partial_read_end, total_size-pread->partial_read_end)) {
			    printf ("[MISMATCH] read returns different values for partial read: after end\n");
			    handle_mismatch();
			    pass = 0;
		    }
	    } else { 
		    //for cached files, we only have the data that needs to be verified
		    if (memcmp (newdata+pread->partial_read_end, olddata+pread->partial_read_start, total_size-pread->partial_read_end)) {
			    printf ("[MISMATCH] read returns different values for partial read: after end\n");
			    handle_mismatch();
			    pass = 0;
		    }
	    }
    }
    //copy other bytes to the actual address
    memcpy (pread->buf+pread->partial_read_start, newdata+pread->partial_read_start, pread->partial_read_end-pread->partial_read_start);
    if (pass) printf ("partial_read: pass.\n");
    else printf ("partial_read: verification fails.\n");
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
    char* readData = bufptr+sizeof(*pread);
    bufptr += pentry->len;

    if (pread->has_retvals) {
	is_cache_file = *((u_int *)readData);
	readData += sizeof(u_int);
    }
#ifdef PRINT_VALUES
    printf("read: has ret vals %d ", pread->has_retvals);
    if (pread->has_retvals) {
	printf ("is_cache_file: %x ", is_cache_file);
    }
    printf("fd %d buf %lx count %d readlen %d returns %ld\n", pread->fd, (u_long) pread->buf, pread->count, pread->readlen, pentry->retval);
#endif
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
            rc = syscall(SYS_read, pread->fd, tmpbuf, pread->count);
            assert (rc == pread->count);
	    partial_read (pread, tmpbuf, (char*)pread+sizeof(*pread)+pread->readlen, 1, rc);
        }
    } else {
	assert (pentry->retval < sizeof(tmpbuf));
	assert ((*pread).count < sizeof(tmpbuf));
	rc = syscall(SYS_read,(*pread).fd, tmpbuf, (*pread).count);
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
    printf("buf %lx\n", (u_long) pstat64->buf);
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
    printf("buf %lx\n", (u_long) pfstat64->buf);
    printf("fd %d\n", pfstat64->fd);
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
	((struct stat64 *) pfstat64->buf)->st_mtime = st.st_atime;
	((struct stat64 *) pfstat64->buf)->st_ctime = st.st_atime;
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
    printf ("Buffer is %lx\n", (u_long) puname->buf);
    printf ("Copy to version buffer at %lx\n", (u_long) &((struct utsname *) puname->buf)->version);
    memcpy (&((struct utsname *) puname->buf)->version, &puname->utsname.version, sizeof(puname->utsname.version));
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
    printf("statfs64: path %s size %u type %d bsize %d blocks %lld bfree %lld bavail %lld files %lld ffree %lld fsid %d %d namelen %d frsize %d rc %ld\n", path, pstatfs64->sz,
	   pstatfs64->statfs.f_type, pstatfs64->statfs.f_bsize, pstatfs64->statfs.f_blocks, pstatfs64->statfs.f_bfree, pstatfs64->statfs.f_bavail, pstatfs64->statfs.f_files, 
	   pstatfs64->statfs.f_ffree, pstatfs64->statfs.f_fsid.__val[0], pstatfs64->statfs.f_fsid.__val[1], pstatfs64->statfs.f_namelen, pstatfs64->statfs.f_frsize, pentry->retval);
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
	printf ("Buffer is %lx\n", (u_long) pstatfs64->buf);
	printf ("Copy to version buffer at %lx\n", (u_long) &pstatfs64->buf->f_bfree);
	pstatfs64->buf->f_bfree = st.f_bfree;
	printf ("Copy to version buffer at %lx\n", (u_long) &pstatfs64->buf->f_bavail);
	pstatfs64->buf->f_bavail = st.f_bavail;
	if (pstatfs64->statfs.f_files != st.f_files) {
	    fprintf (stderr, "[MISMATCH] statfs64 f_bavail does not match: %lld\n", st.f_files);
	    handle_mismatch();
	}
	/* Assume free files handled by tainting */
	printf ("Copy to version buffer at %lx\n", (u_long) &pstatfs64->buf->f_ffree);
	pstatfs64->buf->f_ffree = st.f_ffree;
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
    printf("prlimit64: pid %d resource %d new limit %lx old limit %lx rc %ld\n", prlimit->pid, prlimit->resource, 
	   (u_long) prlimit->new_limit, (u_long) prlimit->old_limit, pentry->retval);
    if (prlimit->has_retvals) {
	printf("old soft limit: %lld hard limit %lld\n", prlimit->retparams.rlim_cur, prlimit->retparams.rlim_max);
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

