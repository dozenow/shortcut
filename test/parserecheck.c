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
	printf ("sysnum %d retval %ld len %d\n", entry.sysnum, entry.retval, entry.len);
	if (entry.len > sizeof(buf)) {
	    fprintf (stderr, "recheck entry is %d bytes - seems too large\n", entry.len);
	    return -1;
	}
	rc = read (fd, buf, entry.len);
	if (rc != entry.len) {	
	    perror ("read data");
	    return rc;
	}
    } while (1);
    
    close (fd);

    return 0;
}
