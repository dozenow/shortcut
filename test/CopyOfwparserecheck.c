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

#include "../dift/recheck_log.h"

int main (int argc, char* argv[])
{
    int fd, rc;
    struct recheck_entry entry;
    char buf[10000];
    struct access_recheck access1;
    struct open_recheck open1;
    int count;

    fd = open (argv[1], O_RDONLY);
    if (fd < 0) {
	perror ("open");
	return fd;
    }
    
    do {
	rc = read (fd, &entry, sizeof(entry));
	if (rc != sizeof(entry)) {
	    if (rc == 0) break;
	    perror ("read");
	    return rc;
	}
	
	//printf ("helloWorld1\n");
	//printf("rc= %d sizeof(entry)= %zu\n",  rc, sizeof(entry));
	//printf ("sysnum %d retval %ld len %d pathname %s\n", entry.sysnum, entry.retval, entry.len, entry.pathname);
	
	printf ("sysnum %d retval %ld len %d mode %d\n", entry.sysnum, entry.retval, entry.len,entry.mode);
	if (entry.len > sizeof(buf)) {
	    fprintf (stderr, "recheck entry is %d bytes - seems too large\n", entry.len);
	    return -1;
	}
	/*
	rc = read (fd, buf, entry.len);
	if (rc != entry.len) {	
	    perror ("read data");
	    return rc;
	}
	*/

	if (entry.sysnum == 33){
	  rc = read (fd, &access1, entry.len);
	  printf ("realMode %d \n", access1.mode);
	}
	if (entry.sysnum == 5){
          rc = read (fd, &access, entry.len);
          printf ("has_retvals %d \n", open1.has_retvals);
        }

	/*
	count=entry.len;
	int i = 0;
	for ( i=0; i < count; i++) {
	  printf("%c", buf[i]);
	}
	printf("\n");
	*/
    } while (1);
    
    close (fd);

    return 0;
}
