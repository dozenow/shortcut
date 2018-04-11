#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <assert.h>
#include <dirent.h>

#include "parseklib.h"

#include <map>
#include <vector>
#include <set>

using namespace std;


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

void gen_offsets (char* dir, u_long pid, map<u_long,vector<ptaint>> pidtaints, set<ptaint,pcmp>& gtaints)
{
    char klogfilename[256];
    sprintf (klogfilename, "%s/klog.id.%ld", dir, pid);
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
		    if (call == SYS_RECV || call == SYS_RECVMSG) {
			printf ("syscall %lu clock %lu %lu call %d retval %ld bytes so far %ld\n", syscall, res->start_clock, res->stop_clock, call, res->retval, rbytes);
			auto siter = pidtaints.find(syscall);
			if (siter != pidtaints.end()) {
			    vector<ptaint> pts = pidtaints[syscall];
			    printf ("has partial taints!\n");
			    for (auto it : pts) {
				assert (it.end <= (u_long) res->retval);
				struct ptaint gtaint;
				gtaint.start = rbytes+it.start;
				gtaint.end = rbytes+it.end;
				gtaints.insert(gtaint);
			    }
			}
#if 0			
			struct recvfrom_retvals* pretvals = (struct recvfrom_retvals *) res->retparams;
			u_char* pbuf = (u_char *) &pretvals->buf;
			for (long i = 0; i < res->retval; i++) {
			    printf ("%02x", pbuf[i] & 0xff);
			}
			printf ("\n");
#endif
			rbytes += res->retval;
		    }
		}
	    }
	syscall++;
	}
    }

    parseklog_close(log);
}

void write_filters (FILE* file, char* dir, u_long new_pid, set<ptaint,pcmp>& gtaints)
{
    char klogfilename[256];
    sprintf (klogfilename, "%s/klog.id.%ld", dir, new_pid);
    struct klogfile *log = parseklog_open(klogfilename);
    if (!log) {
	fprintf(stderr, "%s doesn't appear to be a valid log file!\n", klogfilename);
	exit (1);
    }

    u_long syscall = 0;
    u_long rbytes = 0;
    auto iter = gtaints.begin();
    while (parseklog_read_next_chunk(log) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL) {
	    if (res->psr.sysnum == SYS_socketcall) {
		if (res->retval > 0 && res->retparams_size > 0) {
		    int call = *((int *) res->retparams);
		    if (call == SYS_RECV || call == SYS_RECVMSG) {
			printf ("syscall %lu clock %lu %lu call %d retval %ld bytes so far %ld\n", syscall, res->start_clock, res->stop_clock, call, res->retval, rbytes);
			while (iter != gtaints.end() && !(iter->end <= rbytes) 
			       && !(iter->start >= rbytes + res->retval)) {
			    printf ("partial taint global start %ld end %ld\n", iter->start, iter->end);
			    if (iter->end-rbytes > (u_long) res->retval) {
				printf ("past end\n");
				if (iter->start < rbytes) {
				    fprintf (file, "-b %ld,%ld,0,%ld\n", new_pid, syscall, res->retval);
				} else {
				    fprintf (file, "-b %ld,%ld,%ld,%ld\n", new_pid, syscall, iter->start-rbytes, res->retval);
				}
				break;
			    } else {
				if (iter->start < rbytes) {
				    fprintf (file, "-b %ld,%ld,0,%ld\n", new_pid, syscall, iter->end-rbytes);
				} else {
				    fprintf (file, "-b %ld,%ld,%ld,%ld\n", new_pid, syscall, iter->start-rbytes, iter->end-rbytes);
				}
				iter++;
			    }
			}
			rbytes += res->retval;
		    }
		}
	    }
	syscall++;
	}
    }

    parseklog_close(log);    
}

void getpids (char* dirname, set<u_long>& pidset)
{
    DIR* dirp = opendir (dirname);
    if (dirp == NULL) {
	fprintf (stderr, "Cannot open dir: %s\n", dirname);
	exit (1);
    }

    struct dirent* dp;
    while ((dp = readdir (dirp)) != NULL) {
	if (!strncmp (dp->d_name, "klog.id.", 8)) {
	    u_long pid = strtoul(dp->d_name+8, NULL, 0);
	    pidset.insert(pid);
	}
    }
    closedir (dirp);
}

void matchpids (set<u_long>& oldpidset, set<u_long>& newpidset, map<u_long,u_long>& pidmap)
{
    if (oldpidset.size() != newpidset.size()) {
	fprintf (stderr, "Error: different numbers of pids\n");
    }

    for (auto oit = oldpidset.begin(), nit = newpidset.begin(); oit != oldpidset.end() && nit != newpidset.end(); oit++, nit++) {
	pidmap[*oit] = *nit;
    }
}

int main (int argc, char* argv[])
{
    char filterfilename[256];
    strcpy (filterfilename, argv[1]);
    strcat (filterfilename, "/filters");
    read_filters (filterfilename);

    sprintf (filterfilename, "%s/filters", argv[2]);
    FILE* file = fopen(filterfilename, "w");
    if (file == NULL) {
	fprintf (stderr, "Cannot open filter file: %s\n", filterfilename);
	exit (1);
    }
    
    set<u_long> oldpidset, newpidset;
    map<u_long,u_long> pidmap;
    getpids(argv[1], oldpidset);
    getpids(argv[2], newpidset);
    matchpids (oldpidset, newpidset, pidmap);

    for (auto piditer : ptaints) {
	set<ptaint, pcmp> gtaints;

	printf ("pid %ld\n", piditer.first);
	gen_offsets (argv[1], piditer.first, piditer.second, gtaints);
	for (auto it: gtaints) {
	    printf ("%ld %ld\n", it.start, it.end);
	}
	printf ("%ld %ld\n", piditer.first, pidmap[piditer.first]);
	write_filters (file, argv[2], pidmap[piditer.first], gtaints);
    }

    fclose(file);

    return 0;
}
