#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <assert.h>
#include <dirent.h>

#include "parseklib.h"

#include <map>
#include <vector>
using namespace std;

struct ptaint {
    u_long start;
    u_long end;
    bool   marked;
};

struct pcmp {
    bool operator() (const ptaint& p1, const ptaint& p2) const {
	return p1.start < p2.start;
    }
};

int my_pid;

FILE* filters_out = NULL;
FILE* responses_out = NULL;

map<u_long,map<u_long,vector<ptaint>>> ptaints;

void read_filters (char* filename)
{
    char filtername[256];
    strcpy (filtername, filename);
    for (int i = strlen(filtername); i >= 0; i--) {
	if (filtername[i] == '/') {
	    my_pid = atoi(filtername+i+1+8);
	    strcpy (filtername+i+1, "filters");
	    break;
	}
    }

    FILE* file = fopen(filtername, "r");
    if (file == NULL) {
	fprintf (stderr, "Cannot open filter file: %s\n", filtername);
	exit (1);
    }

    while (!feof(file)) {
	u_long pid, syscall;
	struct ptaint pt;
	pt.marked = false;
	if (fscanf (file, "-b %ld,%ld,%ld,%ld\n", &pid, &syscall, &pt.start, &pt.end) == 4) {
	    ptaints[pid][syscall].push_back(pt);
	}
    }
    fclose (file);
}

struct response {
    u_long syscall;
    u_long start;
    u_long end;
    u_long number;
};
vector<response> responses;

int response_num = 0;

static int get_msglen(u_char* pbuf, u_long syscall, u_long start)
{
    if (pbuf[start] == 0x1) {
	int len = 32 + 4 * (*(u_int *)(pbuf+start+4));
	response_num++;

	struct response res;
	res.syscall = syscall;
	res.start = start;
	res.end = start+len;
	res.number = response_num;
	responses.push_back(res);

	return len;
    } else {
	u_long startoff = 0;
	u_long endoff = 0;
	if (pbuf[start] == 0x1c || pbuf[start] == 0x15) {
	    startoff = start+12;
	    endoff = start+16;
	} else if (pbuf[start] == 0xa1) {
	    startoff = start+16;
	    endoff = start+24;
	}
	if (startoff) {
	    if (filters_out) {
		fprintf (filters_out, "-b %d,%ld,%ld,%ld\n", my_pid, syscall,startoff,endoff);
	    }
	    printf ("filter syscall %lu,%ld,%ld\n", syscall,startoff,endoff);
	    auto sysentry = ptaints[my_pid].find(syscall);
	    if (sysentry == ptaints[my_pid].end()) {
		printf ("syscall %lu not found for pid %d\n", syscall, my_pid);
	    } else {
		bool found = false;
		for (auto it = sysentry->second.begin(); it != sysentry->second.end(); it++) {
		    if (it->start == startoff && it->end == endoff) {
			it->marked = true;
			found = true;
			break;
		    } 
		}
		if (!found) {
		    printf ("not found!\n");
		}
	    }
	}
	return 32;
    }
}

void print_msgs (char* klogfilename)
{
    struct klogfile *log = parseklog_open(klogfilename);
    int recv_num = 0;

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
			recv_num++;
			printf ("syscall %lu clock %lu %lu call %d retval %ld bytes so far %ld\n", syscall, res->start_clock, res->stop_clock, call, res->retval, rbytes);
			struct recvfrom_retvals* pretvals = (struct recvfrom_retvals *) res->retparams;
			u_char* pbuf = (u_char *) &pretvals->buf;

			int msglen;
			if (recv_num <= 2) {
			    msglen = res->retval;
			} else {
			    msglen = get_msglen(pbuf, syscall, 0);
			}

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
    for (auto sit = ptaints[my_pid].begin(); sit != ptaints[my_pid].end(); sit++) {
	for (auto fit = sit->second.begin(); fit != sit->second.end(); fit++) {
	    if (!fit->marked) {
		printf ("syscall %lu begin %ld end %ld marked %d\n", sit->first, fit->start, fit->end, fit->marked);
		for (auto rit = responses.begin(); rit != responses.end(); rit++) {
		    if (rit->syscall == sit->first && rit->start <= fit->start && rit->end >= fit->end) {
			printf ("\tresponse number %ld start %ld end %ld\n", rit->number, rit->start, rit->end);
			if (responses_out) fprintf (responses_out, "%d,%ld,%ld,%ld\n", my_pid, rit->number, fit->start, fit->end);
		    }
		}
	    }
	}
    }
}

int main (int argc, char* argv[])
{
    if (argc > 2 && !strcmp(argv[2], "-f")) {
	filters_out = fopen ("/tmp/filters", "w");
	responses_out = fopen ("/tmp/responses", "w");
    }

    read_filters (argv[1]);
    print_msgs (argv[1]);

    if (filters_out) fclose(filters_out);

    return 0;
}
