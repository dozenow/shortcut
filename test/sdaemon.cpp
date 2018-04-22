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
#include <map>
using namespace std;

#include "parseklib.h"
#include "taintbuf.h"
#include "util.h"
#include <time.h>

//#define DPRINT printf
#define DPRINT(x,...)
//#define PRINT_TIME

map<long,long> clone_map;

void print_usage(FILE *out, char *progname) {
	fprintf(out, "Usage: %s [-fh]\n", progname);
}

void print_help(char *progname) {
	print_usage(stdout, progname);
	printf(" -f filename  Process one file then terminate\n");
	printf(" -h           Prints this dialog\n");
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

static void handle_clone (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;

    if (trv->rettype == RETVAL) {
	long prev_retval = res->retval;
	rc = read (fd, &res->retval, sizeof(long));
	clone_map[prev_retval] = res->retval;
	DPRINT ("mapping %ld to pid %ld\n", prev_retval, res->retval);
	assert (rc == sizeof(long));
    } else {
	assert (0);
    }
}

static void handle_retbuf (int fd, struct taint_retval* trv, struct klog_result* res)
{
    u_long rc;

    if (trv->rettype == RETBUF) {
	rc = read (fd, (char *) res->retparams + sizeof(long), trv->size);
	assert (rc == trv->size);
    } else {
	assert (0);
    }
}

static void handle_time (int fd, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == RETVAL) {
	u_long rc = read (fd, &res->retval, sizeof(long));
	assert (rc == sizeof(long));
    } else {
	u_long rc = read (fd, (char *) res->retparams, sizeof(time_t));
	assert (rc == sizeof(time_t));
    }
}

static void handle_gettid (int fd, struct taint_retval* trv, struct klog_result* res) 
{
    if (trv->rettype == RETVAL) {
	u_long rc = read (fd, &res->retval, sizeof(long));
	assert (rc == sizeof(long));
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
	u_long rc = read (fd, newentry + sizeof(u_int), trv->size);
	assert (rc == trv->size);
	free (res->retparams); 
	res->retparams_size = trv->size + sizeof(u_int);
	res->retparams = newentry;
	DPRINT ("read buffer replaced\n");
    }
}

static void handle_getdents (int fd, struct taint_retval* trv, struct klog_result* res) 
{
    assert (trv->rettype == RETBUF);
    int rc = read (fd, (char *) res->retparams, res->retval);
    DPRINT ("getdents rc is %ld\n", res->retval);
    assert (rc == res->retval);
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

static void handle_clock_gettime (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;
    
    if (trv->rettype == CLOCK_GETTIME) {
	rc = read (fd, (char *) res->retparams, sizeof (struct timespec));
	assert (rc == sizeof(struct timespec));
    } else {
	assert (0);
    }
}
    
static void handle_clock_getres (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;
    
    if (trv->rettype == CLOCK_GETRES) {
	rc = read (fd, (char *) res->retparams, sizeof (struct timespec));
	assert (rc == sizeof(struct timespec));
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

static void handle_socketcall (int fd, struct taint_retval* trv, struct klog_result* res)
{
    long rc;
    int* pcall = (int *) res->retparams;

    switch (*pcall) {
    case SYS_RECV: {
	struct recvfrom_retvals *precv = (struct recvfrom_retvals *) res->retparams;
	rc = read (fd, &precv->buf, res->retval);	
	printf ("Read %ld bytes for recv, pos=%ld\n", rc, lseek(fd, 0, SEEK_CUR));
	assert (rc == res->retval);
	break;
    }
    case SYS_RECVMSG: {
	struct recvmsg_retvals *precvmsg = (struct recvmsg_retvals *) res->retparams;
	char* data = (char *) res->retparams + sizeof (struct recvmsg_retvals) + precvmsg->msg_namelen + precvmsg->msg_controllen;
	rc = read (fd, data, res->retval);	
	printf ("Read %ld bytes for recvmsg, pos=%ld\n", rc, lseek(fd, 0, SEEK_CUR));
	assert (rc == res->retval);
	break;
    }
    default:
	fprintf (stderr, "Socketcall %d not handled in sdaemon\n", *pcall);
	break;
    }
}

int handle_one_klog (string dir, char* altdirname, char* klogfilename, u_long* plast_clock)
{
    DPRINT ("Considering klog %s in directory %s\n", klogfilename, dir.c_str());

    // First check if there is a taintbuf
    char* pid = klogfilename + 8;
    char taintbuf_path[256];
    sprintf (taintbuf_path, "%s/taintbuf.%s", dir.c_str(), pid);
    
    int tfd = open (taintbuf_path, O_RDONLY);
    if (tfd < 0) {
	char newfile[256], oldfile[256];

	// Just symlink the klog file to the new directory - unmodified
	if (errno != ENOENT) fprintf (stderr, "Could not open tainted valued file %s, errno=%d\n", taintbuf_path, errno);
	sprintf (oldfile, "%s/%s", dir.c_str(), klogfilename);
	sprintf (newfile, "%s/%s", altdirname, klogfilename);
	int rc = symlink (oldfile, newfile);
	if (rc != 0) fprintf (stderr, "Cannot create symlink for %s\n", klogfilename);
	return rc;
    }

    DPRINT ("Opened taintbuf %s\n", taintbuf_path);

    // Open a file to write the result to
    char newklogpath[256], klogpath[256];
    sprintf (klogpath, "%s/%s", dir.c_str(), klogfilename);
    sprintf (newklogpath, "%s/%s", altdirname, klogfilename);
    int destfd = open (newklogpath, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (destfd < 0) {
	fprintf (stderr, "Could not open klog output file %s, rc=%d", newklogpath, destfd);
	return -1;
    }
      
    DPRINT ("Opened output file %s\n", newklogpath);

    // First things in the recheck file is the divergence info
    struct taintbuf_hdr hdr;
    if (read (tfd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
	fprintf (stderr, "Cannot read taintbuf header\n");
	return -1;
    }
    printf ("Divergence type %lu index %lu clock %lu\n", hdr.diverge_type, hdr.diverge_ndx, hdr.last_clock);
    *plast_clock = hdr.last_clock;

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
	return -1;
    }

    bool no_more_records = false;
    while (parseklog_read_next_chunk(log) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL) {
	    DPRINT ("Start clock is %lu sysnum is %d\n", res->start_clock, res->psr.sysnum);
	    if (res->start_clock < trv.clock) continue; // No modifications for this record
	    while (res->start_clock >= trv.clock && !no_more_records) {
		DPRINT ("Match on clock %lu,%lu syscall %d,%d\n", res->start_clock, trv.clock, res->psr.sysnum, trv.syscall);
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
		case SYS_ipc:
		    handle_retval (tfd, &trv, res);
		    break;
		case SYS_clone:
		    handle_clone (tfd, &trv, res);
		    break;
		case SYS_ioctl:
		    handle_retbuf (tfd, &trv, res);
		    break;
		case SYS_time:
		    handle_time (tfd, &trv, res);
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
		case SYS_clock_gettime:
		    handle_clock_gettime (tfd, &trv, res);
		    break;
		case SYS_socketcall:
		    handle_socketcall (tfd, &trv, res);
		    break;
                case SYS_gettid:
                    handle_gettid (tfd, &trv, res);
                    break;
                case SYS_clock_getres:
                    handle_clock_getres (tfd, &trv, res);
                    break;
		case SYS_getdents:
		case SYS_getdents64:
		    handle_getdents (tfd, &trv, res);
		    break;
		default:
		    fprintf (stderr, "syscall %d unhandled\n", trv.syscall);
		    return -1;
		}
		long rc = read (tfd, &trv, sizeof(trv));
		if (rc == 0) {
		    DPRINT ("No more modification records\n");
		    no_more_records = true;
		} else if (rc != sizeof(trv)) {
		    fprintf (stderr, "Cannot read tainted retval, rc = %ld\n", rc);
		    return -1;
		} else {
		    DPRINT ("Next syscall is %d clock %ld type %d\n", trv.syscall, trv.clock, trv.rettype);
		}
	    }
	}
	parseklog_write_chunk(log, destfd);
    }
    parseklog_close(log);
    close (destfd);
    close (tfd);

    return 0;
}

int patch_klog (string recheck_filename)
{
    // Figure out replay dir
    size_t found = recheck_filename.find_last_of("/");
    string dir = recheck_filename.substr(0,found);

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
    u_long last_clock = 0; 
    char newfile[256], oldfile[256];
    while ((dp = readdir (dirp)) != NULL) {
	if (!strncmp (dp->d_name, "klog.id.", 8)) {
	    handle_one_klog (dir, altdirname, dp->d_name, &last_clock);
	}
	if (!strncmp (dp->d_name, "ulog.id.", 8) ||
	    !strcmp(dp->d_name, "mlog") || 
	    !strcmp(dp->d_name, "ckpt")) {
	    sprintf (oldfile, "%s/%s", dir.c_str(), dp->d_name);
	    sprintf (newfile, "%s/%s", altdirname, dp->d_name);
	    rc = symlink (oldfile, newfile);
	    if (rc != 0) fprintf (stderr, "Cannot create symlink for %s\n", dp->d_name);
	}
    }

    closedir (dirp);

    // Handle renaming log files - do this in two steps to avoid conflicts
    for (auto it: clone_map) {
	char oldfile[256], newfile[256];
	sprintf (oldfile, "%s/klog.id.%ld", altdirname, it.first);
	sprintf (newfile, "%s/tklog.id.%ld", altdirname, it.second);
	rc = rename (oldfile, newfile);
	if (rc != 0) fprintf (stderr, "Cannot rename %s to %s\n", oldfile, newfile);
	sprintf (oldfile, "%s/ulog.id.%ld", altdirname, it.first);
	sprintf (newfile, "%s/tulog.id.%ld", altdirname, it.second);
	rc = rename (oldfile, newfile);
	if (rc != 0) fprintf (stderr, "Cannot rename %s to %s\n", oldfile, newfile);
    }

    for (auto it: clone_map) {
	char oldfile[256], newfile[256];
	sprintf (oldfile, "%s/tklog.id.%ld", altdirname, it.second);
	sprintf (newfile, "%s/klog.id.%ld", altdirname, it.second);
	rc = rename (oldfile, newfile);
	if (rc != 0) fprintf (stderr, "Cannot rename %s to %s\n", oldfile, newfile);
	sprintf (oldfile, "%s/tulog.id.%ld", altdirname, it.second);
	sprintf (newfile, "%s/ulog.id.%ld", altdirname, it.second);
	rc = rename (oldfile, newfile);
	if (rc != 0) fprintf (stderr, "Cannot rename %s to %s\n", oldfile, newfile);
    }
    
    DPRINT ("Done with directory\n");
#ifdef PRINT_TIME
        struct timespec tp;
        clock_gettime (CLOCK_REALTIME, &tp);
        fprintf (stderr, "Start to replay %ld.%09ld\n", tp.tv_sec, tp.tv_nsec);
#endif

    // Patch complete - now execute up to the last syscall 
    char recover_syscall[64], recover_pid[64];
    sprintf (recover_syscall, "--recover_at=%lu", last_clock);
    sprintf (recover_pid, "--recover_pid=%d", getpid());
    pid_t cpid = fork ();
    if (cpid == 0) {
	rc = execl("./resume", "resume", last_altex.c_str(), "--pthread", "../eglibc-2.15/prefix/lib", recover_syscall, recover_pid, NULL);
	fprintf (stderr, "execl of resume failed, rc=%ld, errno=%d\n", rc, errno);
	return -1;
    } 

    DPRINT ("Done creating new checkpoint\n");

    return cpid;
}

int main(int argc, char **argv) 
{
    char recheck_filename[256]; // List of names - terminated with final NULL
    char* filename = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "hf:")) != -1) {
	switch (opt) {
	case 'h':
	    print_help(argv[0]);
	    exit(EXIT_SUCCESS);
	case 'f':
	    filename = optarg;
	    break;
	default:
	    print_usage(stderr, argv[0]);
	    exit(EXIT_FAILURE);
	}
    }
    
    if (argc - optind != 0) {
	print_usage(stderr, argv[0]);
	exit(EXIT_FAILURE);
    }
    
    if (filename) {
	fprintf (stderr, "Patching one directory: %s\n", filename);
	long rc = patch_klog (filename);
	fprintf (stderr, "Patch klog returns %ld\n", rc);
	return rc;
    }

    // For now, the daemon will be single-threaded - just call into the kernel and get some work
    while (1) {

	fprintf (stderr, "Registering for upcall\n");
	syscall (350, 3, recheck_filename);
	fprintf (stderr, "Received upcall for file %s\n", recheck_filename);
#ifdef PRINT_TIME
        struct timespec tp;
        clock_gettime (CLOCK_REALTIME, &tp);
        fprintf (stderr, "Start to patchlog %ld.%09ld\n", tp.tv_sec, tp.tv_nsec);
#endif
	// Generate the patched klog file
	long rc = patch_klog (recheck_filename);
	fprintf (stderr, "Patch klog returns %ld\n", rc);

	// Let the kernel know that we succeeded (or failed - boo!)
	syscall (350, 4, recheck_filename, rc);
    }

    return 0;
}
