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
#include <dirent.h>

#include <iostream>
using namespace std;

#include "parseklib.h"
#include "taintbuf.h"
#include "util.h"

//#define DPRINT printf
#define DPRINT(x,...)

void print_usage(FILE *out, char *progname) {
	fprintf(out, "Usage: %s [-h]\n", progname);
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
    if (trv->rettype == RETVAL) {
	int rc = read (fd, &res->retval, sizeof(long));
	DPRINT ("read rc is %ld\n", res->retval);
	assert (rc == sizeof(long));
    } else {
	char* newentry = (char *) malloc (trv->size + sizeof(u_int));
	assert (newentry);
	*((u_int *) newentry) = 0; // Not a cached file
	int rc = read (fd, newentry + sizeof(u_int), trv->size);
	assert (rc == trv->size);
	free (res->retparams); 
	res->retparams_size = trv->size + sizeof(u_int);
	res->retparams = newentry;
	DPRINT ("read buffer replaced\n");
    }
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
    } else if (trv->rettype == STAT64_RDEV) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_rdev, sizeof(((struct stat64 *) res->retparams)->st_rdev));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_rdev));
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

static void handle_rt_sigaction (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;

    if (trv->rettype == SIGACTION_ACTION) {
	rc = read (fd, res->retparams, 20);
	assert (rc == 20);
    } else {
	assert (0);
    }
}

int patch_klog (string recheck_filename)
{
    // Figure out replay dir
    size_t found = recheck_filename.find_last_of("/");
    string dir = recheck_filename.substr(0,found);

    string taintbuf_filename = dir + "/taintbuf";
    int tfd = open(taintbuf_filename.c_str(), O_RDONLY, 0);
    if (tfd < 0) {
	fprintf (stderr, "Cannot read tainted vaules file: %s\n", taintbuf_filename.c_str());
	return tfd;
    }

    // Create alternate directory for the patched run
    char altdirname[256];
    u_long altno = 0;
    string last_altex = dir + "/last_altex";
    char buf[4096];

    long rc = readlink (last_altex.c_str(), buf, sizeof(buf));
    if (rc >= 0) {
	if (unlink (last_altex.c_str()) < 0) fprintf (stderr, "Cannot unlink symlink %s\n", last_altex.c_str());
    } else {
	sscanf (buf, "altex_%lu", &altno);
    }

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

    rc = symlink (altdirname, last_altex.c_str());
    if (rc != 0) fprintf (stderr, "Cannot create last_altex symlink from %s to %s,errno=%d\n", altdirname, last_altex.c_str(), errno);

    // Determine the klog name - for now we assume only one klog file
    DIR* dirp = opendir (dir.c_str());
    if (dirp == NULL) {
	fprintf (stderr, "Cannot open dir: %s\n", dir.c_str());
	return -1;
    }

    struct dirent* dp;
    int klog_files = 0;
    string klogfilename;
    while ((dp = readdir (dirp)) != NULL) {
	if (!strncmp (dp->d_name, "klog.id.", 8)) {
	    klog_files++;
	    if (klog_files > 1) {
		fprintf (stderr, "Oops: don't handle multiple klog files yet!");
		return -1;
	    }
	    klogfilename = dp->d_name;
	}

    }

    closedir (dirp);
    if (klog_files == 0) {
	fprintf (stderr, "Cannot fild a klog file in dir: %s\n", dir.c_str());
	return -1;
    }

    // Open a file to write the result to
    char newklogpath[256], klogpath[256];
    sprintf (klogpath, "%s/%s", dir.c_str(), klogfilename.c_str());
    sprintf (newklogpath, "%s/%s", altdirname, klogfilename.c_str());
    int destfd = open (newklogpath, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (destfd < 0) {
	fprintf (stderr, "Could not open klog output file %s, rc=%d", newklogpath, destfd);
	return -1;
    }
      
    // Copy other files to new directory
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

    // First things in the recheck file is the divergence info
    struct taintbuf_hdr hdr;
    if (read (tfd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
	fprintf (stderr, "Cannot read taintbuf header\n");
	return -1;
    }
    printf ("Divergence type %lu index %lu clock %lu\n", hdr.diverge_type, hdr.diverge_ndx, hdr.last_clock);

    // Now read through the recheck output - these are syscall results that changed from recording
    struct taint_retval trv;
    if (read (tfd, &trv, sizeof(trv)) != sizeof(trv)) {
	fprintf (stderr, "Cannot read tainted retval\n");
	return -1;
    }
    DPRINT ("Next syscall is %d clock %ld type %d\n", trv.syscall, trv.clock, trv.rettype);

    struct klogfile *log = parseklog_open(klogpath);
    if (!log) {
	fprintf(stderr, "%s doesn't appear to be a valid log file!\n", klogpath);
	exit(EXIT_FAILURE);
    }

    while (parseklog_read_next_chunk(log) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL) {
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
		case SYS_rt_sigaction:
		    handle_rt_sigaction (tfd, &trv, res);
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

    // Patch complete - now execute up to the last syscall 
    char recover_syscall[64], recover_pid[64];
    sprintf (recover_syscall, "--recover_at=%lu", hdr.last_clock);
    sprintf (recover_pid, "--recover_pid=%d", getpid());
    pid_t cpid = fork ();
    if (cpid == 0) {
	rc = execl("./resume", "resume", last_altex.c_str(), "--pthread", "../eglibc-2.15/prefix/lib", recover_syscall, recover_pid, NULL);
	fprintf (stderr, "execl of resume failed, rc=%ld, errno=%d\n", rc, errno);
	return -1;
    } 

    return cpid;
}

int main(int argc, char **argv) 
{
    char recheck_filename[256];
    
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
    
    if (argc - optind != 0) {
	print_usage(stderr, argv[0]);
	exit(EXIT_FAILURE);
    }
    
    // For now, the daemon will be single-threaded - just call into the kernel and get some work
    while (1) {

	DPRINT ("Registering for upcall\n");
	syscall (350, 3, recheck_filename);
	DPRINT ("Received upcall for file %s\n", recheck_filename);

	// Generate the patched klog file
	long rc = patch_klog (recheck_filename);
	DPRINT ("Patch klog returns %ld\n", rc);

	// Let the kernel know that we succeeded (or failed - boo!)
	syscall (350, 4, recheck_filename, rc);
    }

    return 0;
}
