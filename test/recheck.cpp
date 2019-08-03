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
#include <sys/syscall.h>
#include <assert.h>

#include "recheck.h"
#include "../dift/recheck_log.h"

#include <map>
using namespace std;

#define PRINT_VALUES /* Use this to print out values in recheck log */

map<int,open_retvals> cache_files_opened;

static inline int check_retval (const char* name, int expected, int actual) {
    if (actual >= 0){
	if (expected != actual) {
	    printf ("[MISMATCH] retval for %s expected %d ret %d\n", name, expected, actual);
	    return -1;
	}
    } else {
	if (expected != -1*(errno)){
	    printf ("[MISMATCH] retval for %s expected %d ret %d\n", name, expected, -1*(errno));
	    return -1;
	}  
    }
    return 0;
}

static int recheck_stat64 (struct recheck_entry* pentry, struct stat64_recheck* pstat64)
{
    struct stat64 st;
    int rc;
    char* pathName = (char *) pstat64 + sizeof(struct stat64_recheck);
#ifdef PRINT_VALUES
    printf("has ret vals %d\n", pstat64->has_retvals);
    if (pstat64->has_retvals) {
	//to verify just a memcpr from struct pointer to new struct pointer
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
    if (check_retval ("stat64", pentry->retval, rc) < 0) return -1;
    if (pstat64->has_retvals) {
	if (st.st_dev != pstat64->retvals.st_dev) {
	    printf ("[MISMATCH] stat64 dev does not match %llu vs. recorded %llu\n", st.st_dev, pstat64->retvals.st_dev);
	    return -1;
	}
	if (st.st_ino != pstat64->retvals.st_ino) {
	    printf ("[MISMATCH] stat64 ino does not match %llu vs. recorded %llu\n", st.st_ino, pstat64->retvals.st_ino);
	    return -1;
	}
	if (st.st_mode != pstat64->retvals.st_mode) {
	    printf ("[MISMATCH] stat64 mode does not match %d vs. recorded %d\n", st.st_mode, pstat64->retvals.st_mode);
	    return -1;
	}
	if (st.st_nlink != pstat64->retvals.st_nlink) {
	    printf ("[MISMATCH] stat64 nlink does not match %d vs. recorded %d\n", st.st_nlink, pstat64->retvals.st_nlink);
	    return -1;
	}
	if (st.st_uid != pstat64->retvals.st_uid) {
	    printf ("[MISMATCH] stat64 uid does not match %d vs. recorded %d\n", st.st_uid, pstat64->retvals.st_uid);
	    return -1;
	}
	if (st.st_gid != pstat64->retvals.st_gid) {
	    printf ("[MISMATCH] stat64 gid does not match %d vs. recorded %d\n", st.st_gid, pstat64->retvals.st_gid);
	    return -1;
	}
	if (st.st_rdev != pstat64->retvals.st_rdev) {
	    printf ("[MISMATCH] stat64 rdev does not match %llu vs. recorded %llu\n", st.st_rdev, pstat64->retvals.st_rdev);
	    return -1;
	}
	if (st.st_size != pstat64->retvals.st_size) {
	    printf ("[MISMATCH] stat64 size does not match %lld vs. recorded %lld\n", st.st_size, pstat64->retvals.st_size);
	    return -1;
	}
	if (st.st_mtime != pstat64->retvals.st_mtime) {
	    printf ("[MISMATCH] stat64 mtime does not match %s vs. recorded %s\n", ctime(&st.st_mtime), ctime(&pstat64->retvals.st_mtime));
	    return -1;
	}
	if (st.st_ctime != pstat64->retvals.st_ctime) {
	    printf ("[MISMATCH] stat64 ctime does not match %s vs. recorded %s\n", ctime(&st.st_ctime), ctime(&pstat64->retvals.st_ctime));
	    return -1;
	}
	/* Assume atime will be handled by tainting since it changes often */
	if (st.st_blksize != pstat64->retvals.st_blksize) {
	    printf ("[MISMATCH] stat64 blksize does not match %ld vs. recorded %ld\n", st.st_blksize, pstat64->retvals.st_blksize);
	    return -1;
	}
	if (st.st_blocks != pstat64->retvals.st_blocks) {
	    printf ("[MISMATCH] stat64 blocks does not match %lld vs. recorded %lld\n", st.st_blocks, pstat64->retvals.st_blocks);
	    return -1;
	}
    }
    return 0;
}

static int recheck_fstat64 (struct recheck_entry* pentry, struct fstat64_recheck* pstat64)
{
    struct stat64 st;
    int rc;
    char* pathName = (char *) pstat64 + sizeof(struct fstat64_recheck);
#ifdef PRINT_VALUES
    printf("has ret vals %d\n", pstat64->has_retvals);
    if (pstat64->has_retvals) {
	//to verify just a memcpr from struct pointer to new struct pointer
	printf("fstat64 retvals: st_dev %llu st_ino %llu st_mode %d st_nlink %d st_uid %d st_gid %d st_rdev %llu "
	       "st_size %lld st_atime %s st_mtime %ld st_ctime %ld st_blksize %ld st_blocks %lld\n",
	       pstat64->retvals.st_dev, pstat64->retvals.st_ino, pstat64->retvals.st_mode, pstat64->retvals .st_nlink, pstat64->retvals.st_uid,pstat64->retvals .st_gid,
	       pstat64->retvals.st_rdev, pstat64->retvals.st_size, ctime(&pstat64->retvals.st_atime), pstat64->retvals.st_mtime, pstat64->retvals.st_ctime, pstat64->retvals.st_blksize,
	       pstat64->retvals.st_blocks); 
    }
    printf("buf %p\n", pstat64->buf);
    printf("fd %d\n", pstat64->fd);
#endif
    rc = syscall(SYS_fstat64, pstat64->fd, &st);
    if (check_retval ("fstat64", pentry->retval, rc) < 0) return -1;
    if (pstat64->has_retvals) {
	if (st.st_dev != pstat64->retvals.st_dev) {
	    printf ("[MISMATCH] fstat64 dev does not match %llu vs. recorded %llu\n", st.st_dev, pstat64->retvals.st_dev);
	    return -1;
	}
	if (st.st_ino != pstat64->retvals.st_ino) {
	    printf ("[MISMATCH] fstat64 ino does not match %llu vs. recorded %llu\n", st.st_ino, pstat64->retvals.st_ino);
	    return -1;
	}
	if (st.st_mode != pstat64->retvals.st_mode) {
	    printf ("[MISMATCH] fstat64 mode does not match %d vs. recorded %d\n", st.st_mode, pstat64->retvals.st_mode);
	    return -1;
	}
	if (st.st_nlink != pstat64->retvals.st_nlink) {
	    printf ("[MISMATCH] fstat64 nlink does not match %d vs. recorded %d\n", st.st_nlink, pstat64->retvals.st_nlink);
	    return -1;
	}
	if (st.st_uid != pstat64->retvals.st_uid) {
	    printf ("[MISMATCH] fstat64 uid does not match %d vs. recorded %d\n", st.st_uid, pstat64->retvals.st_uid);
	    return -1;
	}
	if (st.st_gid != pstat64->retvals.st_gid) {
	    printf ("[MISMATCH] fstat64 gid does not match %d vs. recorded %d\n", st.st_gid, pstat64->retvals.st_gid);
	    return -1;
	}
	if (st.st_rdev != pstat64->retvals.st_rdev) {
	    printf ("[MISMATCH] fstat64 rdev does not match %llu vs. recorded %llu\n", st.st_rdev, pstat64->retvals.st_rdev);
	    return -1;
	}
	if (st.st_size != pstat64->retvals.st_size) {
	    printf ("[MISMATCH] fstat64 size does not match %lld vs. recorded %lld\n", st.st_size, pstat64->retvals.st_size);
	    return -1;
	}
	if (memcmp(&st.st_mtime, &pstat64->retvals.st_mtime, sizeof(st.st_mtime))) {
	    printf ("[MISMATCH] fstat64 mtime does not match %ld vs %ld\n", st.st_mtime, pstat64->retvals.st_mtime);
	    printf ("%s", ctime(&st.st_mtime));
	    printf ("%s", ctime(&pstat64->retvals.st_mtime));
	    return -1;
	}
	if (st.st_ctime != pstat64->retvals.st_ctime) {
	    printf ("[MISMATCH] fstat64 ctime does not match %s vs. recorded %s\n", ctime(&st.st_ctime), ctime(&pstat64->retvals.st_ctime));
	    return -1;
	}
	/* Assume atime will be handled by tainting since it changes often */
	if (st.st_blksize != pstat64->retvals.st_blksize) {
	    printf ("[MISMATCH] fstat64 blksize does not match %ld vs. recorded %ld\n", st.st_blksize, pstat64->retvals.st_blksize);
	    return -1;
	}
	if (st.st_blocks != pstat64->retvals.st_blocks) {
	    printf ("[MISMATCH] fstat64 blocks does not match %lld vs. recorded %lld\n", st.st_blocks, pstat64->retvals.st_blocks);
	    return -1;
	}
    }
    return 0;
}

int do_recheck (char* recheck_filename)
{
    int fd, rc;
    struct recheck_entry entry;
    char buf[100000];
    struct access_recheck access1;
   
    int count;
   
    //this fileDescriptor is all alone for the dup2 fd recheck bug fix
    int hermitfd = 1023;

    rc = (syscall(SYS_fcntl, hermitfd, F_GETFD));
    //dup2 to 1023 reval of sys_fcntl assert to make sure hermitfd (which is 1023) is not currently used
    assert(rc < 0);
   

    fd = open (recheck_filename, O_RDONLY);
    if (fd < 0) {
	perror ("open");
	return fd;
    }

    rc = syscall(SYS_dup2, fd, hermitfd);
    close (fd);

    do {
	rc = read (hermitfd, &entry, sizeof(entry));
	if (rc != sizeof(entry)) {
	    if (rc == 0) break;
	    perror ("read");
	    return rc;
	}
#ifdef PRINT_VALUES	
	printf ("\nsysnum %d retval %ld len %d\n", entry.sysnum, entry.retval, entry.len);
#endif
	if (entry.len > sizeof(buf)) {
	    fprintf (stderr, "recheck entry is %d bytes - seems too large\n", entry.len);
	    return -1;
	}
	
	rc = read (hermitfd, buf, entry.len);
	if (rc != entry.len) {	
	    perror ("read data");
	    return rc;
	}

	switch(entry.sysnum) {
	case SYS_access: /* 33 */
	  {
	    struct access_recheck* paccess;
	    
	    paccess = (struct access_recheck*) buf;
	    char* accessName = buf+sizeof(*paccess);
#ifdef PRINT_VALUES
	    printf("mode %d\n", paccess->mode);
	    printf("pathname %s\n", accessName);
#endif
	    rc = syscall(SYS_access, accessName, paccess->mode);
	   
	    check_retval ("access", entry.retval,rc);

	    break;
	  }
	case SYS_open: /* 5 */
	{
	    struct open_recheck* popen;

	    popen = (struct open_recheck*) buf;
	    char* fileName = buf+sizeof(struct open_recheck);
#ifdef PRINT_VALUES
	    printf("has ret vals %d\n", popen->has_retvals);
	    printf("retvals: dev %ld ino %ld mtime %ld.%ld \n", popen->retvals.dev, popen->retvals.ino, 
		   popen->retvals.mtime.tv_sec, popen->retvals.mtime.tv_nsec); 
	    printf("flags %d\n", popen->flags);
	    printf("mode %d\n", popen->mode);
	    printf("filename %s\n", fileName);
#endif
	    assert (entry.retval != 1023); /* Oops - we are using this for the recheck log */
	    rc = syscall(SYS_open, fileName, popen->flags, popen->mode);
	    check_retval ("open", entry.retval, rc);
	    if (rc >= 0 && popen->has_retvals) {
		cache_files_opened[rc] = popen->retvals;
	    }
	    break;
	  }
	case SYS_stat64: /* 195 */
	{
	    rc = recheck_stat64 (&entry, (struct stat64_recheck *) buf);
	    break;
	}
	case SYS_fstat64: /* 197 */
	{
	    rc = recheck_fstat64 (&entry, (struct fstat64_recheck *) buf);
	    break;
	} 
	case SYS_read: /* 3 */
	  {
	    struct read_recheck* pread;
	    u_int is_cache_file = 0;

	    pread = (struct read_recheck*)buf;
	    char* readData = buf+sizeof(*pread);
	    if (pread->has_retvals) {
		is_cache_file = *((u_int *)readData);
	    }
#ifdef PRINT_VALUES
	    printf("has ret vals %d\n", pread->has_retvals);
	    printf ("is_cache_file: %x\n", is_cache_file);
	    printf("fd %d\n", pread->fd);
	    printf("buf %p\n", pread->buf);
	    printf("count %d\n", pread->count);
	    printf("readlen %d\n", pread->readlen);
	    printf("vari length read data buffer %s\n", readData);
#endif
	    if (is_cache_file && entry.retval >= 0) {
		struct stat64 st;
		if (fstat64 (pread->fd, &st) < 0) {
		    printf ("[MISMATCH] cannot fstat file\n");
		}
		if (st.st_mtim.tv_sec == cache_files_opened[pread->fd].mtime.tv_sec &&
		    st.st_mtim.tv_nsec == cache_files_opened[pread->fd].mtime.tv_nsec) {
		    if (lseek(pread->fd, entry.retval, SEEK_CUR) < 0) {
			printf ("[MISMATCH] lseek after read failed\n");
		    }
		} else {
		    printf ("[BUG] - file times mismatch but counld check actual file content to see if it still matches\n");
		}

	    } else {
		assert (entry.retval < sizeof(buf));
		assert ((*pread).count < sizeof(buf));
		rc = syscall(SYS_read,(*pread).fd, buf, (*pread).count);
		check_retval ("read", entry.retval, rc);
		if (rc > 0) {
		    if (memcmp (buf, readData, rc)) {
			printf ("[MISMATCH] read returns different values\n");
		    }
		}
	    }

	    break;
	  }
	case SYS_close: /* 6 */
	  {
	    struct close_recheck* pclose;
	    pclose = (struct close_recheck*)buf;
#ifdef PRINT_VALUES 
	    printf("fd %d\n", pclose->fd);
#endif
	    rc = syscall(SYS_close, pclose->fd);
	    check_retval ("close", entry.retval, rc);
	    break;
	  }
	  //sys_write parse data
	case 4:
	  {
	    //does sys_write need/possible to be rechecked?
	    break;
	  }
	default: 
	  {
	    printf ("[BUG] unhandled recheck syscall %d\n", entry.sysnum);
	  }
	}
	
    } while (1);
    
    close (hermitfd);

    return 0;
}
