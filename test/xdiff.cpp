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


struct streamtaint {
    u_long start;
    u_long end;
};

struct pcmp {
    bool operator() (const streamtaint& p1, const streamtaint& p2) const {
	return p1.start < p2.start;
    }
};

map<u_long,map<u_long,vector<streamtaint>>> streamtaints;

void read_filters (char* filename)
{
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
	fprintf (stderr, "Cannot open filter file: %s\n", filename);
	exit (1);
    }

    while (!feof(file)) {
	u_long pid, syscall;
	struct streamtaint pt;
	if (fscanf (file, "-b %ld,%ld,%ld,%ld\n", &pid, &syscall, &pt.start, &pt.end) == 4) {
	    streamtaints[pid][syscall].push_back(pt);
	}
    }
    fclose (file);
}

static int get_msglen(u_char* pbuf, u_long syscall, u_long start)
{
    if (pbuf[start] == 0x1) {
	return 32 + 4 * (*(u_int *)(pbuf+start+4));
    } else {
	return 32;
    }
}

void gen_offsets (char* dir, u_long pid, map<u_long,vector<streamtaint>> pidtaints, set<streamtaint,pcmp>& gtaints, map<int,streamtaint>& ctaints)
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
    int cmd_num = 0;
    int recv_num = 0;
    while (parseklog_read_next_chunk(log) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL) {
	    if (res->psr.sysnum == SYS_socketcall) {
		if (res->retval > 0 && res->retparams_size > 0) {
		    int call = *((int *) res->retparams);
		    if (call == SYS_RECV) {
			recv_num++;
			struct recvfrom_retvals* pretvals = (struct recvfrom_retvals *) res->retparams;
			u_char* pbuf = (u_char *) &pretvals->buf;
			u_long bytes_read = 0;

			while (bytes_read < (u_long) res->retval) {
			    int msglen;
			    if (recv_num <= 2) {
				msglen = res->retval;
			    } else {
				msglen = get_msglen(pbuf, syscall, bytes_read);
			    }

			    if (pbuf[bytes_read] == 0x01) {
				//printf ("cmd %d syscall %ld\n", cmd_num, syscall);
				auto siter = pidtaints.find(syscall);
				if (siter != pidtaints.end()) {
				    //printf ("syscall %ld has partial taints\n", syscall);
				    vector<streamtaint> pts = pidtaints[syscall];
				    for (auto it : pts) {
					if (it.start >= bytes_read && it.end <= bytes_read+msglen) {
					    streamtaint staint;
					    staint.start = it.start;
					    staint.end = it.end;
					    ctaints[cmd_num] = staint;
					    printf ("Old command num %d: pid %ld syscall %ld begin %ld end %ld\n", cmd_num, pid, syscall, it.start, it.end);
					}
				    }
				}
				cmd_num++;
			    }

			    bytes_read += msglen;
			}
			
		    } else if (call == SYS_RECVMSG) {
			auto siter = pidtaints.find(syscall);
			if (siter != pidtaints.end()) {
			    vector<streamtaint> pts = pidtaints[syscall];
			    for (auto it : pts) {
				assert (it.end <= (u_long) res->retval);
				struct streamtaint gtaint;
				gtaint.start = rbytes+it.start;
				gtaint.end = rbytes+it.end;
				gtaints.insert(gtaint);
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

void write_filters (FILE* file, char* dir, u_long new_pid, set<streamtaint,pcmp>& gtaints, map<int,streamtaint>& ctaints)
{
    int recv_num = 0;

    char klogfilename[256];
    sprintf (klogfilename, "%s/klog.id.%ld", dir, new_pid);
    struct klogfile *log = parseklog_open(klogfilename);
    if (!log) {
	fprintf(stderr, "%s doesn't appear to be a valid log file!\n", klogfilename);
	exit (1);
    }

    u_long syscall = 0;
    u_long rbytes = 0;
    int cmd_num = 0;
    auto iter = gtaints.begin();
    while (parseklog_read_next_chunk(log) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL) {
	    if (res->psr.sysnum == SYS_socketcall) {
		if (res->retval > 0 && res->retparams_size > 0) {
		    int call = *((int *) res->retparams);
		    if (call == SYS_RECVMSG) {
			while (iter != gtaints.end() && !(iter->end <= rbytes) 
			       && !(iter->start >= rbytes + res->retval)) {
			    if (iter->end-rbytes > (u_long) res->retval) {
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
		    if (call == SYS_RECV) {
			recv_num++;
			struct recvfrom_retvals* pretvals = (struct recvfrom_retvals *) res->retparams;
			u_char* pbuf = (u_char *) &pretvals->buf;
			u_long bytes_read = 0;

			while (bytes_read < (u_long) res->retval) {
			    int msglen;
			    if (recv_num <= 2) {
				msglen = res->retval;
			    } else {
				msglen = get_msglen(pbuf, syscall, bytes_read);
			    }

			    u_long startoff = 0;
			    u_long endoff = 0;
			    if (pbuf[bytes_read] == 0x1c || pbuf[bytes_read] == 0x15) {
				startoff = bytes_read+12;
				endoff = bytes_read+16;
			    } else if (pbuf[bytes_read] == 0xa1) {
				startoff = bytes_read+16;
				endoff = bytes_read+24;
			    } else if (pbuf[bytes_read] == 0x01) {
				auto it = ctaints.find(cmd_num);
				if (it != ctaints.end()) {
				    startoff = bytes_read+it->second.start;
				    endoff = bytes_read+it->second.end;
				}
				printf ("cmd num %d is syscall %ld start %ld end %ld\n", cmd_num, syscall, bytes_read, bytes_read+msglen);
				cmd_num++;
			    }

			    if (startoff) {
				fprintf (file, "-b %ld,%ld,%ld,%ld\n", new_pid, syscall, startoff, endoff);
			    }

			    bytes_read += msglen;
			}
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

    for (auto piditer : streamtaints) {
	set<streamtaint, pcmp> gtaints;
	map<int, streamtaint> ctaints;

	printf ("pid %ld\n", piditer.first);
	gen_offsets (argv[1], piditer.first, piditer.second, gtaints, ctaints);
#if 0
	for (auto it: gtaints) {
	    printf ("%ld %ld\n", it.start, it.end);
	}
	printf ("%ld %ld\n", piditer.first, pidmap[piditer.first]);
#endif
	write_filters (file, argv[2], pidmap[piditer.first], gtaints, ctaints);
    }

    fclose(file);

    return 0;
}
