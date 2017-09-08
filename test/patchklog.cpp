#include <sys/types.h>
#ifndef __USE_LARGEFILE64
#  define __USE_LARGEFILE64
#endif
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <stdio.h>
#include <syscall.h>
#include <assert.h>

#include <iostream>
using namespace std;

#include "parseklib.h"
#include "taintbuf.h"
#include "util.h"

#define DPRINT

void print_usage(FILE *out, char *progname) {
	fprintf(out, "Usage: %s [-h] logfile\n", progname);
}

void print_help(char *progname) {
	print_usage(stdout, progname);
	printf(" -h       Prints this dialog\n");
}

static void handle_retval (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;

    if (trv->rettype == RETVAL) {
	rc = read (fd, &res->retval, sizeof(long));
	assert (rc == sizeof(long));
    } else {
	assert (0);
    }
}

static void handle_retbuf (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;

    if (trv->rettype == RETBUF) {
	rc = read (fd, (char *) res->retparams + sizeof(long), trv->size);
	assert (rc == trv->size);
    } else {
	assert (0);
    }
}

static void handle_read (int fd, struct taint_retval* trv, struct klog_result* res) 
{
    char* newentry = (char *) malloc (trv->size + sizeof(u_int));
    assert (newentry);
    *((u_int *) newentry) = 0; // Not a cached file
    int rc = read (fd, newentry + sizeof(u_int), trv->size);
    assert (rc == trv->size);
    free (res->retparams); 
    res->retparams_size = trv->size + sizeof(u_int);
    res->retparams = newentry;
}

static void handle_stat64 (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;

    if (trv->rettype == STAT64_INO) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_ino, sizeof(((struct stat64 *) res->retparams)->st_ino));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_ino));
    } else if (trv->rettype == STAT64_NLINK) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_nlink, sizeof(((struct stat64 *) res->retparams)->st_nlink));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_nlink));
    } else if (trv->rettype == STAT64_SIZE) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_size, sizeof(((struct stat64 *) res->retparams)->st_size));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_size));
    } else if (trv->rettype == STAT64_MTIME) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_mtime, sizeof(((struct stat64 *) res->retparams)->st_mtime));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_mtime));
    } else if (trv->rettype == STAT64_CTIME) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_ctime, sizeof(((struct stat64 *) res->retparams)->st_ctime));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_ctime));
    } else if (trv->rettype == STAT64_ATIME) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_atime, sizeof(((struct stat64 *) res->retparams)->st_atime));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_atime));
    } else if (trv->rettype == STAT64_BLOCKS) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_blocks, sizeof(((struct stat64 *) res->retparams)->st_blocks));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_blocks));
    } else {
	assert (0);
    }
}

static void handle_uname (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;

    if (trv->rettype == UNAME_VERSION) {
	rc = read (fd, &((struct utsname *) res->retparams)->version, sizeof(((struct utsname *) res->retparams)->version));
	assert (rc == sizeof(((struct utsname *) res->retparams)->version));
    } else {
	assert (0);
    }
}

static void handle_statfs64 (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;
    
    if (trv->rettype == STATFS64_BFREE) {
	rc = read (fd, &((struct statfs64 *) res->retparams)->f_bfree, sizeof(((struct statfs64 *) res->retparams)->f_bfree));
	assert (rc == sizeof(((struct statfs64 *) res->retparams)->f_bfree));
    } else if (trv->rettype == STATFS64_BAVAIL) {
	rc = read (fd, &((struct statfs64 *) res->retparams)->f_bavail, sizeof(((struct statfs64 *) res->retparams)->f_bavail));
	assert (rc == sizeof(((struct statfs64 *) res->retparams)->f_bavail));
    } else if (trv->rettype == STATFS64_FFREE) {
	rc = read (fd, &((struct statfs64 *) res->retparams)->f_ffree, sizeof(((struct statfs64 *) res->retparams)->f_ffree));
	assert (rc == sizeof(((struct statfs64 *) res->retparams)->f_ffree));
    } else {
	assert (0);
    }
}
    
static void handle_gettimeofday (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;
    
    if (trv->rettype == GETTIMEOFDAY_TV) {
	rc = read (fd, &((struct gettimeofday_retvals *) res->retparams)->tv, sizeof(((struct gettimeofday_retvals *) res->retparams)->tv));
	assert (rc == sizeof(((struct gettimeofday_retvals *) res->retparams)->tv));
    } else if (trv->rettype == GETTIMEOFDAY_TZ) {
	rc = read (fd, &((struct gettimeofday_retvals *) res->retparams)->tz, sizeof(((struct gettimeofday_retvals *) res->retparams)->tz));
	assert (rc == sizeof(((struct gettimeofday_retvals *) res->retparams)->tz));
    } else {
	assert (0);
    }
}
    
static void handle_newselect (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;
    
    if (trv->rettype == NEWSELECT_TIMEOUT) {
	rc = read (fd, (char *) res->retparams + res->retparams_size-sizeof(struct timeval), sizeof(struct timeval));
	assert (rc == sizeof(struct timeval));
    } else {
	assert (0);
    }
}

int main(int argc, char **argv) 
{
    struct klogfile *log;
    int count;
    
    int opt;
    while ((opt = getopt(argc, argv, "h:")) != -1) {
	switch (opt) {
	case 'h':
	    print_help(argv[0]);
	    exit(EXIT_SUCCESS);
	default:
	    print_usage(stderr, argv[0]);
	    exit(EXIT_FAILURE);
	}
    }
    
    if (argc - optind != 1) {
	print_usage(stderr, argv[0]);
	exit(EXIT_FAILURE);
    }
    
    log = parseklog_open(argv[optind]);
    if (!log) {
	fprintf(stderr, "%s doesn't appear to be a valid log file!\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    // Figure out replay dir
    string klogfile = argv[optind];
    size_t found = klogfile.find_last_of("/");
    string dir = klogfile.substr(0,found);

    // Do we want to allow for multiple taintbuf files per recording?
    string taintbuf = dir + "/taintbuf";
    int tfd = open(taintbuf.c_str(), O_RDONLY, 0);
    if (tfd < 0) {
	fprintf (stderr, "Cannot read tainted vaules file\n");
	return tfd;
    }

    // Create directory for the patched run
    string pinoutname = dir + "/pinout";
    string recpidstr = klogfile.substr(klogfile.find_last_of(".")+1);
    string klogname = klogfile.substr(found+1);
    string last_altex = dir + "/last_altex";
    char buf[4096];
    long rc = readlink (last_altex.c_str(), buf, sizeof(buf));
    u_long altno = 0;
    if (rc < 0) {
	printf ("No alternate paths yet %s,errno=%d\n", last_altex.c_str(), errno);
    } else {
	rc = unlink (last_altex.c_str());
	if (rc != 0) fprintf (stderr, "Cannot unlink symlink %s\n", last_altex.c_str());
    }

    char altdirname[256];
    do {
	sprintf (altdirname, "%s/altex_%lu", dir.c_str(), altno);
	rc = mkdir (altdirname, 0777);
	if (rc && errno == EEXIST) {
	    altno++;
	}
    } while (rc && errno == EEXIST);
    if (rc) {
	fprintf (stderr, "Cannot create alternate path directory: %s\n", altdirname);
	return rc;
    }
    char newklogpath[256];
    sprintf (newklogpath, "%s/%s", altdirname, klogname.c_str());
      
    // Open a file to write the result to
    int destfd = open (newklogpath, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (destfd < 0) {
	fprintf (stderr, "Could not open output file,rc=%d", destfd);
	return -1;
    }
    
    rc = symlink (altdirname, last_altex.c_str());
    if (rc != 0) fprintf (stderr, "Cannot create last_altex symlink from %s to %s,errno=%d\n", altdirname, last_altex.c_str(), errno);

    char newfile[256];
    char oldfile[256];
    sprintf (oldfile, "%s/mlog", dir.c_str());
    sprintf (newfile, "%s/mlog", altdirname);
    rc = symlink (oldfile, newfile);
    if (rc != 0) fprintf (stderr, "Cannot create mlog symlink\n");

    sprintf (oldfile, "%s/ckpt", dir.c_str());
    sprintf (newfile, "%s/ckpt", altdirname);
    rc = symlink (oldfile, newfile);
    if (rc != 0) fprintf (stderr, "Cannot create ckpt symlink\n");

    // Read in header
    struct taintbuf_hdr hdr;
    if (read (tfd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
	fprintf (stderr, "Cannot read taintbuf header\n");
	return -1;
    }
    printf ("Divergence type %lu index %lu clock %lu\n", hdr.diverge_type, hdr.diverge_ndx, hdr.last_clock);

    struct taint_retval trv;
    if (read (tfd, &trv, sizeof(trv)) != sizeof(trv)) {
	fprintf (stderr, "Cannot read tainted retval\n");
	return -1;
    }
    DPRINT ("Next syscall is %d clock %ld type %d\n", trv.syscall, trv.clock, trv.rettype);

    u_long resume_clock = 0; // Try to learn where to stop the resume for later processing
    while ((count = parseklog_read_next_chunk(log)) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL) {
	    if (res->start_clock > hdr.last_clock && resume_clock == 0) {
		resume_clock = res->start_clock;  // We should stop here
	    }
	    while (res->start_clock == trv.clock) {
		assert (res->psr.sysnum == trv.syscall);
		switch (trv.syscall) {
		case SYS_read:
		    handle_read (tfd, &trv, res);
		    break;
		case SYS_stat64:
		case SYS_fstat64:
		case SYS_lstat64:
		    handle_stat64 (tfd, &trv, res);
		    break;
		case SYS_set_tid_address:
		case SYS_getpgrp:
		    handle_retval (tfd, &trv, res);
		    break;
		case SYS_ioctl:
		    handle_retbuf (tfd, &trv, res);
		    break;
		case SYS_uname:
		    handle_uname (tfd, &trv, res);
		    break;
		case SYS_statfs64:
		    handle_statfs64 (tfd, &trv, res);
		    break;
		case SYS_gettimeofday:
		    handle_gettimeofday (tfd, &trv, res);
		    break;
		case SYS__newselect:
		    handle_newselect (tfd, &trv, res);
		    break;
		default:
		    printf ("syscall %d unhandled\n", trv.syscall);
		    return -1;
		}
		long rc = read (tfd, &trv, sizeof(trv));
		if (rc == 0) {
		    res->start_clock = 99999; // Skip to end
		} else if (rc != sizeof(trv)) {
		    fprintf (stderr, "Cannot read tainted retval, rc = %ld\n", rc);
		    return -1;
		} else {
		    DPRINT ("Next syscall is %d clock %ld type %d\n", trv.syscall, trv.clock, trv.rettype);
		}
	    }
	}
	DPRINT ("Writing chunk\n");
	parseklog_write_chunk(log, destfd);
    }

    parseklog_close(log);
    close (destfd);
    close (tfd);

    if (hdr.diverge_type == DIVERGE_JUMP) {
	printf ("Looking for jump index %lu\n", hdr.diverge_ndx);

	// Try to find the nth jump in the file
	int fd = open (pinoutname.c_str(), O_RDONLY);
	if (fd < 0) {
	    fprintf (stderr, "Cannot open pinout file %s, errno=%d\n", pinoutname.c_str(), errno);
	    return fd;
	}

	struct stat st;
	rc = fstat (fd, &st);
	if (rc < 0) {
	    fprintf (stderr, "Cannot stat pinout file, errno=%d\n", errno);
	    return rc;
	}

	char* p = (char *) mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
	    fprintf (stderr, "Cannot map pinout file, errno=%d\n", errno);
	    return -1;
	}

	close(fd);

	u_long jump_count = 0;
	char address[64];
	for (u_long i = 0; i < st.st_size; i++) {
	    if (p[i] == '#' && p[i+1] == 'j') {
		if (jump_count == hdr.diverge_ndx) {
		    u_long start = i-2;
		    while (p[start] != '#') start--;
		    start = start+1;
		    u_long end = i-1;
		    strcpy(address, "0x");
		    memcpy(address+2, p+start, end-start);
		    address[end-start+2] = '\0';
		    printf ("address: %s\n", address);
		    break;
		}
		jump_count++;
	    }
	}

	printf ("Should resume from clock %lu and stop at %lu\n", hdr.last_clock, resume_clock);

	// For replay runs below
	fd = open ("/dev/spec0", O_RDWR);
	if (fd < 0) {
	    perror("open /dev/spec0");
	    return fd;
	}

	// Now let's run the pin tools for the original and the alteteed runs to gather bbl data
	// Alternate first
	pid_t cpid = fork ();
	if (cpid == 0) {
	    // Redirect output to a file
	    char outfilename[256];
	    sprintf (outfilename, "%s/altpath_bbs", altdirname);
	    int fd = open (outfilename, O_CREAT | O_TRUNC | O_RDWR, 0644);
	    if (fd < 0) {
		fprintf (stderr, "Cannot open %s, errno=%d\n", outfilename, errno);
		return fd;
	    }
	    rc = dup2 (fd, 1);
	    if (rc < 0) {
		fprintf (stderr, "Cannot dup2 outfile, errno=%d\n", errno);
		return fd;
	    }
	    close(fd);

	    char attach_offset[64];
	    sprintf (attach_offset, "--attach_offset=%s,%lu", recpidstr.c_str(), hdr.last_clock);
	    rc = execl("./resume", "resume", "-p", altdirname, "--pthread", "../eglibc-2.15/prefix/lib", attach_offset, NULL);
	    fprintf (stderr, "execl of resume failed, rc=%ld, errno=%d\n", rc, errno);
	    return -1;
	} 

	// Wait until we can attach pin
	do {
	    rc = get_attach_status (fd, cpid);
	} while (rc <= 0);

	// Now run the bbl tool
	pid_t mpid = fork();
	if (mpid == 0) {
	    const char* args[256];
	    char cpids[64], end_str[64];
	    u_int argcnt = 0;

	    args[argcnt++] = "pin";
	    args[argcnt++] = "-pid";
	    sprintf (cpids, "%d", cpid);
	    args[argcnt++] = cpids;
	    args[argcnt++] = "-t";
	    args[argcnt++] = "../dift/obj-ia32/ctrl_flow_bb_trace.so";
	    args[argcnt++] = "-i";
	    args[argcnt++] = address;
	    args[argcnt++] = "-s";
	    sprintf (end_str, "%lu", resume_clock);
	    args[argcnt++] = end_str;
	    args[argcnt++] = NULL;
	    rc = execv ("../../pin/pin", (char **) args);
	    fprintf (stderr, "execv of pin ctrl flow tool failed, rc=%ld, errno=%d\n", rc, errno);
	    return -1;
	}
	
	wait_for_replay_group(fd, cpid);

	int status;
	rc = waitpid (cpid, &status, 0);
	if (rc < 0) {
	    fprintf (stderr, "waitpid returns %ld, errno %d for pid %d\n", rc, errno, cpid);
	}

	// Now original
	cpid = fork ();
	if (cpid == 0) {
	    // Redirect output to a file
	    char outfilename[256];
	    sprintf (outfilename, "%s/origpath_bbs", altdirname);
	    int fd = open (outfilename, O_CREAT | O_TRUNC | O_RDWR, 0644);
	    if (fd < 0) {
		fprintf (stderr, "Cannot open %s, errno=%d\n", outfilename, errno);
		return fd;
	    }
	    rc = dup2 (fd, 1);
	    if (rc < 0) {
		fprintf (stderr, "Cannot dup2 outfile, errno=%d\n", errno);
		return fd;
	    }
	    close(fd);

	    char attach_offset[64];
	    sprintf (attach_offset, "--attach_offset=%s,%lu", recpidstr.c_str(), hdr.last_clock);
	    rc = execl("./resume", "resume", "-p", dir.c_str(), "--pthread", "../eglibc-2.15/prefix/lib", attach_offset, NULL);
	    fprintf (stderr, "execl of resume failed, rc=%ld, errno=%d\n", rc, errno);
	    return -1;
	} 

	// Wait until we can attach pin
	do {
	    rc = get_attach_status (fd, cpid);
	} while (rc <= 0);

	// Now run the bbl tool
	mpid = fork();
	if (mpid == 0) {
	    const char* args[256];
	    char cpids[64], end_str[64];
	    u_int argcnt = 0;

	    args[argcnt++] = "pin";
	    args[argcnt++] = "-pid";
	    sprintf (cpids, "%d", cpid);
	    args[argcnt++] = cpids;
	    args[argcnt++] = "-t";
	    args[argcnt++] = "../dift/obj-ia32/ctrl_flow_bb_trace.so";
	    args[argcnt++] = "-i";
	    args[argcnt++] = address;
	    args[argcnt++] = "-s";
	    sprintf (end_str, "%lu", resume_clock);
	    args[argcnt++] = end_str;
	    args[argcnt++] = NULL;
	    rc = execv ("../../pin/pin", (char **) args);
	    fprintf (stderr, "execv of pin ctrl flow tool failed, rc=%ld, errno=%d\n", rc, errno);
	    return -1;
	}
	
	wait_for_replay_group(fd, cpid);

	rc = waitpid (cpid, &status, 0);
	if (rc < 0) {
	    fprintf (stderr, "waitpid returns %ld, errno %d for pid %d\n", rc, errno, cpid);
	}

    }

    return 0;
}

