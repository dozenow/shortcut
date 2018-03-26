#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <assert.h>
#include <dirent.h>

#include "parseklib.h"

using namespace std;

#if 0
struct ptaint {
    u_long start;
    u_long end;
};

struct pcmp {
    bool operator() (const ptaint& p1, const ptaint& p2) const {
	return p1.start < p2.start;
    }
};

map<u_long,map<u_long,vector<ptaint>>> ptaints;

void read_filters (char* filename)
{
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
	fprintf (stderr, "Cannot open filter file: %s\n", filename);
	exit (1);
    }

    while (!feof(file)) {
	u_long pid, syscall;
	struct ptaint pt;
	if (fscanf (file, "-b %ld,%ld,%ld,%ld\n", &pid, &syscall, &pt.start, &pt.end) == 4) {
	    ptaints[pid][syscall].push_back(pt);
	}
    }
    fclose (file);
}
#endif

static int get_msglen(u_char* pbuf, u_long syscall, int start)
{
    if (pbuf[start] == 0x1) {
	return 32 + 4 * (*(u_int *)(pbuf+4));
    } else {
	if (pbuf[start] == 0x1c) {
	    printf ("filter syscall %lu,%d,%d\n", syscall,start+12,start+16);
	}
	return 32;
    }
}

void print_msgs (char* klogfilename)
{
    struct klogfile *log = parseklog_open(klogfilename);
    if (!log) {
	fprintf(stderr, "%s doesn't appear to be a valid log file!\n", klogfilename);
	exit (1);
    }

    u_long syscall = 0;
    u_long rbytes = 0;
    while (parseklog_read_next_chunk(log) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL) {
	    if (res->psr.sysnum == SYS_socketcall) {
		if (res->retval > 0 && res->retparams_size > 0) {
		    int call = *((int *) res->retparams);
		    if (call == SYS_RECV) {
			printf ("syscall %lu clock %lu %lu call %d retval %ld bytes so far %ld\n", syscall, res->start_clock, res->stop_clock, call, res->retval, rbytes);
			struct recvfrom_retvals* pretvals = (struct recvfrom_retvals *) res->retparams;
			u_char* pbuf = (u_char *) &pretvals->buf;

			int msglen = get_msglen(pbuf, syscall, 0);

			printf ("{");
			for (long i = 0; i < res->retval; i++) {
			    if (msglen == 0) {
				printf ("}\n{");
				msglen = get_msglen(pbuf, syscall, i);
			    }
			    printf ("%02x", pbuf[i] & 0xff);
			    msglen--;
			}
			printf ("}\n");
			rbytes += res->retval;
		    }
		}
	    }
	syscall++;
	}
    }

    parseklog_close(log);
}

int main (int argc, char* argv[])
{
    print_msgs (argv[1]);

    return 0;
}
