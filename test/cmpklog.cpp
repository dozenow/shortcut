#include <stdio.h>
#include <syscall.h>

#include <iostream>
using namespace std;

#include "parseklib.h"

int main (int argc, char* argv[])
{
    struct klogfile *log1, *log2;
    int index = 0;

    log1 = parseklog_open(argv[1]);
    if (!log1) {
	fprintf(stderr, "%s doesn't appear to be a valid log file!\n", argv[0]);
	return -1;
    }
    log2 = parseklog_open(argv[2]);
    if (!log2) {
	fprintf(stderr, "%s doesn't appear to be a valid log file!\n", argv[1]);
	return -1;
    }

    parseklog_read_next_chunk(log1);
    parseklog_read_next_chunk(log2);
    struct klog_result* res1 = parseklog_get_next_psr_from_chunk (log1);
    struct klog_result* res2 = parseklog_get_next_psr_from_chunk (log2);
    while (res1 && res2) {
	if (res1->psr.sysnum != res2->psr.sysnum) {
	    printf ("sysnum differs: %d vs. %d\n", res1->psr.sysnum, res2->psr.sysnum);
	    return -1;
	} else if (res1->psr.flags != res2->psr.flags) {
	    printf ("syscall %d index %d flags differ: %d vs. %d\n", 
		    res1->psr.sysnum, index, res1->psr.flags, res2->psr.flags);
	    return -1;
	} else if (res1->start_clock != res2->start_clock) {
	    printf ("syscall %d index %d start clocks differ: %ld vs. %ld\n", 
		    res1->psr.sysnum, index, res1->start_clock, res2->start_clock);
	    return -1;
	} else if (res1->stop_clock != res2->stop_clock) {
	    printf ("syscall %d index %d stop clocks differ: %ld vs. %ld\n", 
		    res1->psr.sysnum, index, res1->stop_clock, res2->stop_clock);
	    return -1;
	} else if (!!res1->signal != !!res2->signal) {
	    printf ("syscall %d index %d signals differ: %d vs. %d\n", 
		    res1->psr.sysnum, index, !!res1->signal, !!res2->signal);
	    return -1;
	} else if (res1->retval != res2->retval) {
	    printf ("syscall %d index %d retvals differ: %ld vs. %ld\n", 
		    res1->psr.sysnum, index, res1->retval, res2->retval);
	} else if (res1->retparams_size != res2->retparams_size) {
	    printf ("syscall %d index %d retparam sizes differ: %d vs. %d\n", 
		    res1->psr.sysnum, index, res1->retparams_size, res2->retparams_size);
	    return -1;
	} else if (res1->retparams_size > 0) {
	    if (memcmp(res1->retparams, res2->retparams, res1->retparams_size)) {
		printf ("syscall %d index %d retparams differ\n", res1->psr.sysnum, index);
	    }
	}

	index++;
	res1 = parseklog_get_next_psr_from_chunk (log1);
	res2 = parseklog_get_next_psr_from_chunk (log2);
    }
    if (res1 || res2) {
	printf ("Different numbers of syscalls\n");
	return -1;
    }

    return 0;
}
