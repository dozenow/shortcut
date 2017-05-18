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

#include "../dift/recheck_log.h"

static inline void check_retval (const char* name, int expected, int actual) {
  if (actual >= 0){
   if (expected != actual) {
    printf ("[MISMATCH] retval for %s expected %d ret %d\n", name, expected, actual);
   }
  }
  else{
    if (expected != -1*(errno)){
      printf ("[MISMATCH] retval for %s expected %d ret %d\n", name, expected, -1*(errno));
    }  
  }
}

int main (int argc, char* argv[])
{
    int fd, rc;
    struct recheck_entry entry;
    char buf[10000];
    struct access_recheck access1;
   
    int count;
   
    //this fileDescriptor is all alone for the dup2 fd recheck bug fix
    int hermitfd;
    hermitfd = 1023;

    rc = (syscall(SYS_fcntl, hermitfd, F_DUPFD,(1024)));
     //dup2 to 1023 assert that hermitfd (which is 1023) is never used
    assert(rc < 0);
   

    fd = open (argv[1], O_RDONLY);
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
	
	printf ("\nsysnum %d retval %ld len %d\n", entry.sysnum, entry.retval, entry.len);
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
	  //sys_access parse data
	case 33:
	  {
	    struct access_recheck* paccess;
	    //struct access_recheck = accessinst;

	    paccess = (struct access_recheck*)buf;
	    char* accessName = buf+sizeof(*paccess);
	    printf("mode %d\n",(*paccess).mode);
	    printf("pathname %s\n", accessName);

	    rc = syscall(SYS_access, accessName, (*paccess).mode);
	   
	    //printf("return code %d\n", rc);
	    check_retval ("access", entry.retval,rc);

	    break;
	  }
	  //sys_open parse data
	case 5:
	  {
	    struct open_recheck* popen;

	    popen = (struct open_recheck*)buf;
	    char* fileName = buf+sizeof(*popen);
	    printf("has ret vals %d\n",(*popen).has_retvals);
	    printf("retvals: dev %d ino %d mtime %d \n",((*popen).retvals).dev,((*popen).retvals).ino,((*popen).retvals).mtime); 
	    printf("flags %d\n",(*popen).flags);
	    printf("mode %d\n",(*popen).mode);
	    printf("filename %s\n", fileName);

	    //because we have recheck log open the rc from this is higher than it should be by 1 
	    rc = syscall(SYS_open, fileName, (*popen).flags, (*popen).mode);
	    //printf("return code %d\n", rc);
	    check_retval ("open", entry.retval, rc);

	    break;
	  }
	  //sys_stat64 parse data
	case 195:
	  {
	    struct stat64_recheck* pstat64;

	    pstat64 = (struct stat64_recheck*)buf;
	    char* pathName = buf+sizeof(*pstat64);
	    printf("has ret vals %d\n",(*pstat64).has_retvals);
	    //to verify just a memcpr from struct pointer to new struct pointer
	    printf("struct64 retvals: st_dev %d st_ino %d st_mode %d st_nlink %d st_uid %d st_gid %d st_rdev %d st_size %d st_atime %d st_mtime %d st_ctime %d st_blksize %d st_blocks %d\n",((*pstat64).retvals).st_dev,((*pstat64).retvals).st_ino,((*pstat64).retvals).st_mode,((*pstat64).retvals).st_nlink,((*pstat64).retvals).st_uid,((*pstat64).retvals).st_gid,((*pstat64).retvals).st_rdev,((*pstat64).retvals).st_size,((*pstat64).retvals).st_atime,((*pstat64).retvals).st_mtime,((*pstat64).retvals).st_ctime,((*pstat64).retvals).st_blksize,((*pstat64).retvals).st_blocks); 
	    printf("buf %p\n",(*pstat64).buf);
	    printf("pathname %s\n", pathName);

	    rc = syscall(SYS_stat64, pathName, (*pstat64).buf);
	    //printf("return code %d\n", rc);
	    check_retval ("stat64", entry.retval, rc);

	    break;
	  }
	  //sys_fstat64 parse data
	case 197:
	  {
	    struct fstat64_recheck* pfstat64;

	    pfstat64 = (struct fstat64_recheck*)buf;

	    //?hack to fix fd dup2 fix side effects
	    //(*pfstat64).fd = hermitfd;

	
	    printf("has ret vals %d\n",(*pfstat64).has_retvals);
	    //how to retrieve the actual return values from the retval struct?
	    printf("fstruct64 retvals: st_dev %d st_ino %d st_mode %d st_nlink %d st_uid %d st_gid %d st_rdev %d st_size %d st_atime %d st_mtime %d st_ctime %d st_blksize %d st_blocks %d\n",((*pfstat64).retvals).st_dev,((*pfstat64).retvals).st_ino,((*pfstat64).retvals).st_mode,((*pfstat64).retvals).st_nlink,((*pfstat64).retvals).st_uid,((*pfstat64).retvals).st_gid,((*pfstat64).retvals).st_rdev,((*pfstat64).retvals).st_size,((*pfstat64).retvals).st_atime,((*pfstat64).retvals).st_mtime,((*pfstat64).retvals).st_ctime,((*pfstat64).retvals).st_blksize,((*pfstat64).retvals).st_blocks); 
	    printf("buf %p\n",(*pfstat64).buf);
	    printf("fd %d\n",(*pfstat64).fd);
	    //printf("pathname %s\n", pathName);

	    rc = syscall(SYS_fstat64,(*pfstat64).fd, (*pfstat64).buf);
	    // printf("return code %d errno %d\n", rc,errno);
	    check_retval ("fstat64", entry.retval, rc);

	    break;
	  } 
	  //sys_read parse data
	case 3:
	  {
	    struct read_recheck* pread;

	    pread = (struct read_recheck*)buf;
	    char* readData = buf+sizeof(*pread);
	    printf("has ret vals %d\n",(*pread).has_retvals);
	    
	    printf("fd %d\n",(*pread).fd);
	    printf("buf %p\n",(*pread).buf);
	    printf("count %d\n",(*pread).count);
	    printf("readlen %d\n",(*pread).readlen);
	    printf("vari length read data buffer %s\n", readData);

	    rc = syscall(SYS_read,(*pread).fd, (*pread).buf, (*pread).count);
	    //printf("return code %d\n", rc);
	    check_retval ("read", entry.retval, rc);

	    break;
	  }
	  //sys_close parse data
	case 6:
	  {
	    struct close_recheck* pclose;

	    pclose = (struct close_recheck*)buf;
	    //char* pathName = buf+sizeof(*pclose);
	    printf("fd %d\n",(*pclose).fd);

	    rc = syscall(SYS_close,(*pclose).fd);
	    //printf("return code %d\n", rc);
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
