#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <string>
#include <stack>
#include <iostream>
using namespace std;

//#define DEBUG

#ifdef DEBUG
#define DPRINT printf
#else
#define DPRINT(x,...)
#endif

int find_addr (u_long inst, const char* rwname, u_long clock, unsigned long long bb, int loop_iter, u_long& addr)
{
    static FILE* file = NULL;

    char branch_start[64];
    sprintf (branch_start, "b_%ld_%lld_%d_that_branch_execute_and_taint:", clock, bb, loop_iter);

    if (!file) {
	char filename[256];
	strcpy (filename, rwname);
	char* p = strstr (filename, "last_altex");
	if (p == NULL) {
	    fprintf (stdout, "Malformed filename: %s\n", rwname);
	    return -1;
	}
	strcpy (p, "pinout");
	file = fopen (filename, "r");
	if (file == NULL) {
	    fprintf (stderr, "Cannot open %s\n", filename);
	    return -1;
	}
    }

    // First find beginning of target alternate branch
    char target[256];
    sprintf (target, "comes with %lx", inst);
    while (!feof(file)) {
	char line[256];
	if (fgets (line, 256, file) == NULL) break;
	if (strstr (line, branch_start)) {
	    // Found alternate branch start - now find the push line
	    while (!feof(file)) {
		if (fgets (line, 256, file) == NULL) break;
		if (strstr (line, "[SLICE_VERIFICATION] push 0x")) {
		    if (strstr (line, target)) {
			char* p = strstr (line, "expected address");
			if (p) {
			    addr = strtoul(p+16, 0, 16);
			    DPRINT ("expected address 0x%lx\n", addr);
			    return 0;
			} else {
			    char* p = strstr (line, "expected range");
			    if (p) {
				u_long from, to;
				if (sscanf (p, "expected range %lx to %lx", &from, &to) == 2) {
				    DPRINT ("expected range 0x%lx to 0x%lx addr %lx\n", from, to, (from+to)/2);
				    addr = (from+to)/2;
				    return 0;
				} else {
				    fprintf (stderr, "find_addr: malformed push line: %s\n", line);
				    return -1;
				}
			    } else {
				fprintf (stderr, "find_addr: malformed push line: %s\n", line);
				return -1;
			    }
			}
		    }
		}
	    }
	    fprintf (stderr, "find_addr: premature end of file in alt branch\n");
	    return -1;
	}
    }
    fprintf (stderr, "find_addr: premature end of file\n");
    return -1;
}

int handle_loop (FILE* file, u_long target_inst, unsigned long long start_bb, unsigned long long& extra_bb, int skew, const char* rwname, int& max_read, int& max_write) 
{
    int iter_count = 1;

    while (!(feof(file))) {
	char line[256];
	if (fgets (line, 256, file) == NULL) {
	    fprintf (stderr, "handle_loop: premature end of file\n");
	    return -1;
	}

	DPRINT("loop: %s", line);

	u_long inst, clock, merge;
	int taken, loop, null;
	unsigned long long bb;
	if (!strncmp(line, "[DIVERGE]", 9)) {
	    if (sscanf (line, "[DIVERGE]0x%lx branch %d, #%lld,%ld (clock) merge %lx loop %d null branch %d", &inst, &taken, &bb, &clock, &merge, &loop, &null) == 7) {
		if (inst == target_inst && loop && null) {
		    //printf ("Reached the end of the loop\n");
		    extra_bb = bb - start_bb;
		    return 0;
		}
	    }
	} else if (!strncmp(line, "[READ]", 6)) {
	    u_long inst, ea, clock;
	    unsigned long long bb;
	    if (sscanf (line, "[READ]0x%lx, 0x%lx, #%lld,%ld", &inst, &ea, &bb, &clock) == 4) {
		DPRINT ("Read in loop at address %lx bb %lld clock %ld: %lx\n", inst, start_bb+skew, clock, ea);
		u_long exp_addr;
		if (find_addr (inst, rwname, clock, start_bb+skew, iter_count++, exp_addr) < 0) return -1;
		DPRINT ("Expected address is %lx actual addr %lx\n", exp_addr, ea);
		if (exp_addr != ea) {
		    if (ea > exp_addr) {
			DPRINT ("Difference is %ld\n", ea - exp_addr);
			if ((long) (ea-exp_addr) > max_read) max_read = ea-exp_addr;
		    } else {
			DPRINT ("Difference is %ld\n", exp_addr - ea);
			if ((long) (exp_addr-ea) > max_read) max_read = exp_addr-ea;
		    }
		}
	    }
	} else if (!strncmp(line, "[WRITE]", 7)) {
	    u_long inst, ea, clock;
	    unsigned long long bb;
	    if (sscanf (line, "[WRITE]0x%lx, 0x%lx, #%lld,%ld", &inst, &ea, &bb, &clock) == 4) {
		DPRINT ("Write in loop at address %lx bb %lld clock %ld: %lx\n", inst, start_bb+skew, clock, ea);
		u_long exp_addr;
		if (find_addr (inst, rwname, clock, start_bb+skew, iter_count++, exp_addr) < 0) return -1;
		if (exp_addr != ea) {
		    if (ea > exp_addr) {
			if ((long) (ea-exp_addr) > max_write) max_write = ea-exp_addr;
		    } else {
			if ((long) (exp_addr-ea) > max_write) max_write = exp_addr-ea;
		    }
		}
	    }
	}
    }

    fprintf (stderr, "handle_loop: premature end of file\n");
    return -1;
}

int main (int argc, char* argv[])
{
    FILE* file1 = fopen (argv[1], "r");
    if (file1 == NULL) {
	fprintf (stderr, "Cannot open %s, errno=%d\n", argv[1], errno);
	return -1;
    }

    FILE* file2 = fopen (argv[2], "r");
    if (file1 == NULL) {
	fprintf (stderr, "Cannot open %s, errno=%d\n", argv[2], errno);
	return -1;
    }

    u_long addr;
    int max_read = 0;
    int max_write = 0;
    stack<u_long> divergences;
    long skew = 0;

    while (!(feof(file1) && feof(file2))) {
	char line1[256], line2[256];
	char* p1 = fgets (line1, 256, file1);
	char* p2 = fgets (line2, 256, file2);
	if (p1 == NULL && p2 == NULL) break;
	if (p1 == NULL) {
	    fprintf (stderr, "Cannot read from %s but read %s from %s - presumably cf divergence follows\n", argv[1], line2, argv[2]);
	    break;
	}
	if (p2 == NULL) {
	    fprintf (stderr, "Cannot read from %s but read %s from %s - presumably cf divergence follows\n", argv[2], line1, argv[1]);
	    break;
	}

	while (!strncmp(line1,"[STUTTER]", 9)) {
	    skew += 1;
	    DPRINT ("Stutter in %s skew now %ld: %s\n", argv[1], skew, line1);
	    p1 = fgets (line1, 256, file1);
	    if (p1 == NULL) {
		fprintf (stderr, "Cannot read from %s but read %s from %s - presumably cf divergence follows\n", argv[1], line2, argv[2]);
		break;
	    }
	    if (!strncmp(line1, "New basic block", 15)) {
		p1 = fgets (line1, 256, file1);
		if (p1 == NULL) {
		    fprintf (stderr, "Cannot read from %s but read %s from %s - presumably cf divergence follows\n", argv[1], line2, argv[2]);
		    break;
		}
	    }		
	}

	while (!strncmp(line2,"[STUTTER]", 9)) {
	    skew -= 1;
	    DPRINT ("Stutter in %s skew now %ld: %s\n", argv[2], skew, line2);
	    p2 = fgets (line2, 256, file2);
	    if (p2 == NULL) {
		fprintf (stderr, "Cannot read from %s but read %s from %s - presumably cf divergence follows\n", argv[2], line1, argv[1]);
		break;
	    }
	    if (!strncmp(line2, "New basic block", 15)) {
		p2 = fgets (line2, 256, file2);
		if (p2 == NULL) {
		    fprintf (stderr, "Cannot read from %s but read %s from %s - presumably cf divergence follows\n", argv[2], line1, argv[1]);
		    break;
		}
	    }		
	}

	DPRINT ("%s%s\n", line1, line2);

	if (!strncmp(line1, "[MERGE]", 7)) {

	    if (strncmp(line2, "[MERGE]", 7)) {
		fprintf (stderr, "Unexpected merge:\n%s%s", line1, line2);
		return -1;
	    }

	    u_long inst1, inst2;
	    unsigned long long bb1, bb2;
	    u_long clock1, clock2;
	    if (sscanf (line1, "[MERGE]0x%lx, #%lld,%ld", &inst1, &bb1, &clock1) == 3 &&
		sscanf (line2, "[MERGE]0x%lx, #%lld,%ld", &inst2, &bb2, &clock2) == 3) {
		if (inst1 != inst2) {
		    fprintf (stderr, "Difference in merge:\n%s%s", line1, line2);
		    return -1;
		}
		if (clock1 != clock2) {
		    fprintf (stderr, "Difference in clock at merge:\n%s%s", line1, line2);
		    return -1;
		}
		if (bb1 != bb2+skew) {
		    if (divergences.top() == inst1) {
			DPRINT ("Divergence led to bb skew of %ld\n", (long) bb2 - (long) bb1);
			skew = (long) bb2 - (long) bb1;
		    } else {
			fprintf (stderr, "Unexpected difference in bb at merge\n%s%s (skew %ld) - presumably cd divergence follows", line1, line2, skew);
			break;
		    }
		}
	    } else {
		fprintf (stderr, "Malformed line: %s%s\n", line1, line2);
		return -1;
	    }

	} else if (!strncmp(line1, "[DIVERGE]", 9)) {

	    if (strncmp(line2, "[DIVERGE]", 9)) {
		fprintf (stderr, "Unexpected divergence:\n%s%s", line1, line2);
		return -1;
	    }

	    u_long inst1, inst2;
	    int taken1, taken2;
	    unsigned long long bb1, bb2;
	    u_long clock1, clock2;
	    u_long merge1, merge2;
	    int loop1, loop2, null1, null2;
	    if (sscanf (line1, "[DIVERGE]0x%lx branch %d, #%lld,%ld (clock) merge %lx loop %d null branch %d", &inst1, &taken1, &bb1, &clock1, &merge1, &loop1, &null1) == 7 &&
		sscanf (line2, "[DIVERGE]0x%lx branch %d, #%lld,%ld (clock) merge %lx loop %d null branch %d", &inst2, &taken2, &bb2, &clock2, &merge2, &loop2, &null2) == 7) {
		if (inst1 != inst2) {
		    fprintf (stderr, "Unexpected divergence:\n%s%s", line1, line2);
		    return -1;
		}
		if (merge1 != merge2) {
		    fprintf (stderr, "Unexpected difference in merge at divergence\n%s%s", line1, line2);
		    return -1;
		}
		if (bb1 != bb2+skew || clock1 != clock2) {
		    fprintf (stderr, "Unexpected difference in clock at divergence - probably later cf divergence\n%s%s", line1, line2);
		    break;
		}
		if (taken1 != taken2) {
		    DPRINT ("Divergence at inst 0x%lx clock %ld bb %lld\n", inst1, clock1, bb1);
		    if (loop1 && null1) {
			unsigned long long extra_bb;
			handle_loop (file2, inst1, bb2, extra_bb, skew, argv[2], max_read, max_write);
			skew -= extra_bb;
			DPRINT ("Skew is now %ld\n", skew);
		    } else if (loop2 && null2) {
			unsigned long long extra_bb;
			handle_loop (file1, inst2, bb1, extra_bb, 0, argv[1], max_read, max_write);
			skew += extra_bb;
			DPRINT ("Skew is now %ld\n", skew);
		    } else {
			divergences.push(merge1);
		    }
		}

	    } else {
		fprintf (stderr, "Malformed line: %s%s\n", line1, line2);
		return -1;
	    }

	} else if (!strncmp(line1, "[READ]",6)) {

	    if (strncmp(line2, "[READ]", 6)) {
		fprintf (stderr, "Unexpected write:\n%s%s", line1, line2);
		return -1;
	    }

	    u_long inst1, inst2;
	    u_long ea1, ea2;
	    unsigned long long bb1, bb2;
	    u_long clock1, clock2;
	    if (sscanf (line1, "[READ]0x%lx, 0x%lx, #%lld,%ld", &inst1, &ea1, &bb1, &clock1) == 4 &&
		sscanf (line2, "[READ]0x%lx, 0x%lx, #%lld,%ld", &inst2, &ea2, &bb2, &clock2) == 4) {

		if (inst1 != inst2) {
		    fprintf (stderr, "Unexpected difference in instruction at read:\n%s%s", line1, line2);
		    return -1;
		}
		addr = inst1;

		if (bb1 != bb2+skew || clock1 != clock2) {
		    fprintf (stderr, "Unexpected difference in clock at read - probably later cf divergence\n%s%s", line1, line2);
		    break;
		}
		if (ea1 != ea2) {
		  DPRINT ("Read at address %lx bb %lld clock %ld: %lx vs %lx, diff is %ld\n", inst1, bb1, clock1, ea1, ea2, ea1-ea2);
		    if (ea1 > ea2) {
			if ((long) (ea1-ea2) > max_read) max_read = ea1-ea2;
		    } else {
			if ((long) (ea2-ea1) > max_read) max_read = ea2-ea1;
		    }
		}
	    } else {
		fprintf (stderr, "Malformed line: %s%s\n", line1, line2);
		return -1;
	    }

	} else if (!strncmp(line1,"[WRITE]",7)) {

	    if (strncmp(line2, "[WRITE]", 7)) {
		fprintf (stderr, "Unexpected write:\n%s%s", line1, line2);
		return -1;
	    }

	    u_long inst1, inst2;
	    u_long ea1, ea2;
	    unsigned long long bb1, bb2;
	    u_long clock1, clock2;
	    if (sscanf (line1, "[WRITE]0x%lx, 0x%lx, #%lld,%ld", &inst1, &ea1, &bb1, &clock1) == 4 &&
		sscanf (line2, "[WRITE]0x%lx, 0x%lx, #%lld,%ld", &inst2, &ea2, &bb2, &clock2) == 4) {

		if (inst1 != inst2) {
		    fprintf (stderr, "Unexpected difference in instruction at write:\n%s%s", line1, line2);
		    return -1;
		}
		addr = inst1;

		if (bb1 != bb2+skew || clock1 != clock2) {
		    fprintf (stderr, "Unexpected difference in bb at write - presumably cf divergence\n%s%s (skew=%ld)", line1, line2, skew);
		    break;
		}
		DPRINT ("Write at address %lx bb %lld clock %ld: %lx vs %lx\n", inst1, bb1, clock1, ea1, ea2);
		if (ea1 != ea2) {
		    if (ea1 > ea2) {
			if ((long) (ea1-ea2) > max_write) max_write = ea1-ea2;
		    } else {
			if ((long) (ea2-ea1) > max_write) max_write = ea2-ea1;
		    }
		}
	    } else {
		fprintf (stderr, "Malformed line: %s%s\n", line1, line2);
		return -1;
	    }

	} else {
	    //printf ("Unrecognized line: %s%s\n", line1, line2);
	}
    }

    fclose(file1);
    fclose(file2);

    if (max_read == 0 && max_write == 0) {
	fprintf (stderr, "No divergence found\n");
	return -1;
    }

    if (max_read > 0) {
	printf ("0x%lx rangev %d\n", addr, max_read);
    }
    if (max_write > 0) {
	printf ("0x%lx rangev_write %d\n", addr, max_write);
    }

#ifdef DEBUG
    return 1;
#else
    return 0;
#endif
}
