#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

#include "parseklib.h"

int main (int argc, char* argv[])
{
    u_long syscall = 0;
    struct klogfile *log = parseklog_open(argv[1]);
    if (!log) {
	fprintf(stderr, "%s doesn't appear to be a valid log file!\n", argv[1]);
	return -1;
    }
    while (parseklog_read_next_chunk(log) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL) {
	    if (res->psr.sysnum == SYS_socketcall) {
		if (res->retparams_size > 0 && (*(int *) res->retparams) == SYS_RECV) {
		    if (res->retval > 0) {
			printf ("syscall %lu clock %lu %lu retval %ld\n", syscall, res->start_clock, res->stop_clock, res->retval);
			struct recvfrom_retvals* pretvals = (struct recvfrom_retvals *) res->retparams;
			u_char* pbuf = (u_char *) &pretvals->buf;
			for (long i = 0; i < res->retval; i++) {
			    printf ("%02x", pbuf[i] & 0xff);
			}
			printf ("\n");
		    }
		}
	    }
	syscall++;
	}
    }

    return 0;
}
