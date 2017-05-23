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

//#define PRINT_VALUES /* Use this to print out values in recheck log */

map<int,open_retvals> cache_files_opened;

static inline void check_retval (const char* name, int expected, int actual) {
    if (actual >= 0){
	if (expected != actual) {
	    printf ("[MISMATCH] retval for %s expected %d ret %d\n", name, expected, actual);
	}
    } else {
	if (expected != -1*(errno)){
	    printf ("[MISMATCH] retval for %s expected %d ret %d\n", name, expected, -1*(errno));
	}  
    }
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
	    struct stat64_recheck* pstat64;
	    pstat64 = (struct stat64_recheck*)buf;
	    char* pathName = buf+sizeof(*pstat64);
#ifdef PRINT_VALUES
	    printf("has ret vals %d\n",(*pstat64).has_retvals);
	    //to verify just a memcpr from struct pointer to new struct pointer
	    printf("stat64 retvals: st_dev %llu st_ino %llu st_mode %d st_nlink %d st_uid %d st_gid %d st_rdev %llu st_size %lld st_atime %ld st_mtime %ld st_ctime %ld st_blksize %ld st_blocks %lld\n",
		   pstat64->retvals.st_dev, pstat64->retvals.st_ino, pstat64->retvals.st_mode, pstat64->retvals .st_nlink, pstat64->retvals.st_uid,pstat64->retvals .st_gid,
		   pstat64->retvals.st_rdev, pstat64->retvals.st_size, pstat64->retvals .st_atime, pstat64->retvals.st_mtime, pstat64->retvals.st_ctime, pstat64->retvals.st_blksize,
		   pstat64->retvals.st_blocks); 
	    printf("buf %p\n", pstat64->buf);
	    printf("pathname %s\n", pathName);
#endif
	    rc = syscall(SYS_stat64, pathName, (*pstat64).buf);
	    check_retval ("stat64", entry.retval, rc);

	    break;
	  }
	case SYS_fstat64: /* 197 */
	  {
	    struct fstat64_recheck* pfstat64;
	    pfstat64 = (struct fstat64_recheck*)buf;
#ifdef PRINT_VALUES 	
	    printf("has ret vals %d\n",(*pfstat64).has_retvals);
	    //how to retrieve the actual return values from the retval struct?
	    printf("fstat64 retvals: st_dev %llu st_ino %llu st_mode %d st_nlink %d st_uid %d st_gid %d st_rdev %llu st_size %lld st_atime %ld st_mtime %ld st_ctime %ld st_blksize %ld st_blocks %lld\n",
		   pfstat64->retvals.st_dev, pfstat64->retvals.st_ino, pfstat64->retvals.st_mode, pfstat64->retvals .st_nlink, pfstat64->retvals.st_uid,pfstat64->retvals .st_gid,
		   pfstat64->retvals.st_rdev, pfstat64->retvals.st_size, pfstat64->retvals .st_atime, pfstat64->retvals.st_mtime, pfstat64->retvals.st_ctime, pfstat64->retvals.st_blksize,
		   pfstat64->retvals.st_blocks); 
	    printf("buf %p\n",(*pfstat64).buf);
	    printf("fd %d\n",(*pfstat64).fd);
#endif 
	    rc = syscall(SYS_fstat64,(*pfstat64).fd, (*pfstat64).buf);
	    check_retval ("fstat64", entry.retval, rc);

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
