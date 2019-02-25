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
#include "../linux-lts-quantal-3.5.0/include/linux/replay_configs.h"

#define DPRINT printf
//#define DPRINT(x,...)
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

static void handle_retval (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == RETVAL) {
	memcpy (&res->retval, tbptr, sizeof(long));
	tbptr += sizeof(long);
    } else {
	assert (0);
    }
}

static void handle_clone (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == RETVAL) {
	long prev_retval = res->retval;
	memcpy (&res->retval, tbptr, sizeof(long));
	tbptr += sizeof(long);
	clone_map[prev_retval] = res->retval;
	DPRINT ("mapping %ld to pid %ld\n", prev_retval, res->retval);
    } else {
	assert (0);
    }
}

static void handle_retbuf (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == RETBUF) {
	memcpy ((char *) res->retparams + sizeof(long), tbptr, trv->size);
	tbptr += trv->size;
    } else {
	assert (0);
    }
}

static void handle_time (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == RETVAL) {
	memcpy (&res->retval, tbptr, sizeof(long));
	tbptr += sizeof(long);
    } else {
	memcpy (&res->retparams, tbptr, sizeof(time_t));
	tbptr += sizeof(time_t);
    }
}

static void handle_gettid (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == RETVAL) {
	memcpy (&res->retval, tbptr, sizeof(long));
	tbptr += sizeof(long);
    } else {
        assert (0);
    }
}

static void handle_read (char*& tbptr, struct taint_retval* trv, struct klog_result* res) 
{
    if (trv->rettype == RETVAL) {
	memcpy (&res->retval, tbptr, sizeof(long));
	tbptr += sizeof(long);
    } else {
	char* newentry = (char *) malloc (trv->size + sizeof(u_int));
	assert (newentry);
	*((u_int *) newentry) = 0; // Not a cached file
	memcpy (newentry + sizeof(u_int), tbptr, trv->size);
	tbptr += trv->size;
	//free (res->retparams); 
	res->retparams_size = trv->size + sizeof(u_int);
	res->retparams = newentry;
	DPRINT ("read buffer replaced\n");
    }
}

static void handle_getdents (char*& tbptr, struct taint_retval* trv, struct klog_result* res) 
{
    assert (trv->rettype == RETBUF);
    memcpy ((char *) res->retparams, tbptr, res->retval);
    tbptr += res->retval;
    DPRINT ("getdents rc is %ld\n", res->retval);
}

static void handle_stat64 (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == STAT64_INO) {
	memcpy (&((struct stat64 *) res->retparams)->st_ino, tbptr, sizeof(((struct stat64 *) res->retparams)->st_ino));
	tbptr += sizeof(((struct stat64 *) res->retparams)->st_ino);
    } else if (trv->rettype == STAT64_NLINK) {
	memcpy (&((struct stat64 *) res->retparams)->st_nlink, tbptr, sizeof(((struct stat64 *) res->retparams)->st_nlink));
	tbptr += sizeof(((struct stat64 *) res->retparams)->st_nlink);
    } else if (trv->rettype == STAT64_SIZE) {
	memcpy (&((struct stat64 *) res->retparams)->st_size, tbptr, sizeof(((struct stat64 *) res->retparams)->st_size));
	tbptr += sizeof(((struct stat64 *) res->retparams)->st_size);
    } else if (trv->rettype == STAT64_MTIME) {
	memcpy (&((struct stat64 *) res->retparams)->st_mtime, tbptr, sizeof(((struct stat64 *) res->retparams)->st_mtime));
	tbptr += sizeof(((struct stat64 *) res->retparams)->st_mtime);
    } else if (trv->rettype == STAT64_CTIME) {
	memcpy (&((struct stat64 *) res->retparams)->st_ctime, tbptr, sizeof(((struct stat64 *) res->retparams)->st_ctime));
	tbptr += sizeof(((struct stat64 *) res->retparams)->st_ctime);
    } else if (trv->rettype == STAT64_ATIME) {
	memcpy (&((struct stat64 *) res->retparams)->st_atime, tbptr, sizeof(((struct stat64 *) res->retparams)->st_atime));
	tbptr += sizeof(((struct stat64 *) res->retparams)->st_atime);
    } else if (trv->rettype == STAT64_BLOCKS) {
	memcpy (&((struct stat64 *) res->retparams)->st_blocks, tbptr, sizeof(((struct stat64 *) res->retparams)->st_blocks));
	tbptr += sizeof(((struct stat64 *) res->retparams)->st_blocks);
    } else if (trv->rettype == STAT64_RDEV) {
	memcpy (&((struct stat64 *) res->retparams)->st_rdev, tbptr, sizeof(((struct stat64 *) res->retparams)->st_rdev));
	tbptr += sizeof(((struct stat64 *) res->retparams)->st_rdev);
    } else {
	assert (0);
    }
}

static void handle_uname (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == UNAME_VERSION) {
	memcpy (&((struct utsname *) res->retparams)->version, tbptr, sizeof(((struct utsname *) res->retparams)->version));
	tbptr += sizeof(((struct utsname *) res->retparams)->version);
    } else {
	assert (0);
    }
}

static void handle_statfs64 (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == STATFS64_BFREE) {
	memcpy (&((struct statfs64 *) res->retparams)->f_bfree, tbptr, sizeof(((struct statfs64 *) res->retparams)->f_bfree));
	tbptr += sizeof(((struct statfs64 *) res->retparams)->f_bfree);
    } else if (trv->rettype == STATFS64_BAVAIL) {
	memcpy (&((struct statfs64 *) res->retparams)->f_bavail, tbptr, sizeof(((struct statfs64 *) res->retparams)->f_bavail));
	tbptr += sizeof(((struct statfs64 *) res->retparams)->f_bavail);
    } else if (trv->rettype == STATFS64_FFREE) {
	memcpy (&((struct statfs64 *) res->retparams)->f_ffree, tbptr, sizeof(((struct statfs64 *) res->retparams)->f_ffree));
	tbptr += sizeof(((struct statfs64 *) res->retparams)->f_ffree);
    } else {
	assert (0);
    }
}
    
static void handle_gettimeofday (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == GETTIMEOFDAY_TV) {
	memcpy (&((struct gettimeofday_retvals *) res->retparams)->tv, tbptr, sizeof(((struct gettimeofday_retvals *) res->retparams)->tv));
	tbptr += sizeof(((struct gettimeofday_retvals *) res->retparams)->tv);
    } else if (trv->rettype == GETTIMEOFDAY_TZ) {
	memcpy (&((struct gettimeofday_retvals *) res->retparams)->tz, tbptr, sizeof(((struct gettimeofday_retvals *) res->retparams)->tz));
	tbptr += sizeof(((struct gettimeofday_retvals *) res->retparams)->tz);
    } else {
	assert (0);
    }
}
    
static void handle_clock_gettime (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == CLOCK_GETTIME) {
	memcpy ((char *) res->retparams, tbptr, sizeof (struct timespec));
	tbptr += sizeof (struct timespec);
    } else {
	assert (0);
    }
}
    
static void handle_clock_getres (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == CLOCK_GETRES) {
	memcpy ((char *) res->retparams, tbptr, sizeof (struct timespec));
	tbptr += sizeof (struct timespec);
    } else {
	assert (0);
    }
}
    
static void handle_newselect (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == NEWSELECT_TIMEOUT) {
	memcpy ((char *) res->retparams + res->retparams_size-sizeof(struct timeval), tbptr, sizeof(struct timeval));
	tbptr += sizeof(struct timeval);
    } else {
	assert (0);
    }
}

static void handle_rt_sigaction (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    if (trv->rettype == SIGACTION_ACTION) {
	memcpy (res->retparams, tbptr, 20);
	tbptr += 20;
    } else {
	assert (0);
    }
}

static void handle_socketcall (char*& tbptr, struct taint_retval* trv, struct klog_result* res)
{
    int* pcall = (int *) res->retparams;

    switch (*pcall) {
    case SYS_RECV: {
	struct recvfrom_retvals *precv = (struct recvfrom_retvals *) res->retparams;
	memcpy (&precv->buf, tbptr, res->retval);
	tbptr += res->retval;
	break;
    }
    case SYS_RECVMSG: {
	struct recvmsg_retvals *precvmsg = (struct recvmsg_retvals *) res->retparams;
	char* data = (char *) res->retparams + sizeof (struct recvmsg_retvals) + precvmsg->msg_namelen + precvmsg->msg_controllen;
	memcpy (data, tbptr, res->retval);
	tbptr += res->retval;
	break;
    }
    default:
	fprintf (stderr, "Socketcall %d not handled in sdaemon\n", *pcall);
	break;
    }
}

static char* map_taintbuf (int fd, u_long& size) 
{
    struct stat st;

    int rc = fstat (fd, &st);
    if (rc < 0) {
	fprintf (stderr, "Cannot stat taintbuf\n");
	return NULL;
    }
    size = st.st_size;
    
    char* p = (char *) mmap (0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
	fprintf (stderr, "Cannot map taintbuf size %ld\n", size);
	return NULL;
    }

    return p;
}

int handle_one_klog (string dir, char* altdirname, char* klogfilename, u_long* plast_clock)
{
    DPRINT ("Considering klog %s in directory %s\n", klogfilename, dir.c_str());

    // First check if there is a taintbuf
    char* pid = klogfilename + 8;
    char taintbuf_path[256];
    sprintf (taintbuf_path, "%s/taintbuf.%s", dir.c_str(), pid);
    if (access (taintbuf_path, R_OK)) {
        fprintf (stderr, "Note: cannot find corresponding taintbuf file for klog %s. This could be a correct behavior if you're accelerating fine-grained code regions\n", klogfilename);
        return -1;
    }
    
    int tfd = open (taintbuf_path, O_RDONLY);
    if (tfd < 0) {
	char newfile[256], oldfile[256];
        fprintf (stderr, "cannot open file %s for klog %s\n", taintbuf_path, klogfilename);

	// Just symlink the klog file to the new directory - unmodified
	if (errno != ENOENT) fprintf (stderr, "Could not open tainted valued file %s, errno=%d\n", taintbuf_path, errno);
	sprintf (oldfile, "%s/%s", dir.c_str(), klogfilename);
	sprintf (newfile, "%s/%s", altdirname, klogfilename);
	int rc = symlink (oldfile, newfile);
	if (rc != 0) fprintf (stderr, "Cannot create symlink for %s\n", klogfilename);
	return rc;
    }
    
    u_long tbsize = 0;
    char* tbbegin = map_taintbuf (tfd, tbsize);
    char* tbptr = tbbegin;
    char* tbend = tbbegin + tbsize;
    DPRINT ("Opened taintbuf %s\n", taintbuf_path);

    // Open a file to write the result to
    char newklogpath[256], klogpath[256];
    sprintf (klogpath, "%s/%s", dir.c_str(), klogfilename);
    sprintf (newklogpath, "%s/%s", altdirname, klogfilename);

    // First things in the recheck file is the divergence info
    struct taintbuf_hdr* phdr = (struct taintbuf_hdr *) tbptr;
    tbptr += sizeof (struct taintbuf_hdr);
    printf ("Divergence type %lu index %lu clock %lu\n", phdr->diverge_type, phdr->diverge_ndx, phdr->last_clock);
    *plast_clock = phdr->last_clock;

    // Now read through the recheck output - these are syscall results that changed from recording
    struct taint_retval* ptrv = (struct taint_retval *) tbptr;
    tbptr += sizeof (struct taint_retval);
    DPRINT ("Next syscall is %d clock %ld type %d\n", ptrv->syscall, ptrv->clock, ptrv->rettype);

    if (tbptr >= tbend) {
	fprintf (stderr, "Cannot read tainted retval, at the end\n");
        *plast_clock = 2;
	char newfile[256], oldfile[256];
	// Just symlink the klog file to the new directory - unmodified
	sprintf (oldfile, "%s/%s", dir.c_str(), klogfilename);
	sprintf (newfile, "%s/%s", altdirname, klogfilename);
	int rc = symlink (oldfile, newfile);
	if (rc != 0) fprintf (stderr, "Cannot create symlink for %s\n", klogfilename);
	return rc;
    }

    int destfd = open (newklogpath, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (destfd < 0) {
	fprintf (stderr, "Could not open klog output file %s, rc=%d", newklogpath, destfd);
	return -1;
    }
      
    DPRINT ("Opened output file %s\n", newklogpath);

    struct klogfile *log = parseklog_open(klogpath);
    if (!log) {
	fprintf(stderr, "%s doesn't appear to be a valid log file!\n", klogpath);
	return -1;
    }

    bool no_more_records = false;
    while (parseklog_read_next_chunk(log) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL && !no_more_records) {
	    if (res->start_clock < ptrv->clock) continue; // No modifications for this record
	    DPRINT ("Start clock is %lu sysnum is %d\n", res->start_clock, res->psr.sysnum);
	    while (res->start_clock >= ptrv->clock && !no_more_records) {
		DPRINT ("Match on clock %lu,%lu syscall %d,%d\n", res->start_clock, ptrv->clock, res->psr.sysnum, ptrv->syscall);
		assert (res->psr.sysnum == ptrv->syscall);
		switch (ptrv->syscall) {
		case SYS_read:
		    handle_read (tbptr, ptrv, res);
		    break;
		case SYS_stat64:
		case SYS_fstat64:
		case SYS_lstat64:
		    handle_stat64 (tbptr, ptrv, res);
		    break;
		case SYS_set_tid_address:
		case SYS_getpgrp:
		case SYS_ipc:
		    handle_retval (tbptr, ptrv, res);
		    break;
		case SYS_clone:
		    handle_clone (tbptr, ptrv, res);
		    break;
		case SYS_ioctl:
		    handle_retbuf (tbptr, ptrv, res);
		    break;
		case SYS_time:
		    handle_time (tbptr, ptrv, res);
		    break;
		case SYS_uname:
		    handle_uname (tbptr, ptrv, res);
		    break;
		case SYS_statfs64:
		    handle_statfs64 (tbptr, ptrv, res);
		    break;
		case SYS_gettimeofday:
		    handle_gettimeofday (tbptr, ptrv, res);
		    break;
		case SYS__newselect:
		    handle_newselect (tbptr, ptrv, res);
		    break;
		case SYS_rt_sigaction:
		    handle_rt_sigaction (tbptr, ptrv, res);
		    break;
		case SYS_clock_gettime:
		    handle_clock_gettime (tbptr, ptrv, res);
		    break;
		case SYS_clock_getres:
		    handle_clock_getres (tbptr, ptrv, res);
		    break;
		case SYS_socketcall:
		    handle_socketcall (tbptr, ptrv, res);
		    break;
                case SYS_gettid:
		    handle_gettid (tbptr, ptrv, res);
                    break;
		case SYS_getdents:
		case SYS_getdents64:
		    handle_getdents (tbptr, ptrv, res);
		    break;
		default:
		    fprintf (stderr, "syscall %d unhandled\n", ptrv->syscall);
		    return -1;
		}
		if (tbptr >= tbend) {
		    DPRINT ("No more modification records tbptr %p tbend %p\n", tbptr, tbend);
		    no_more_records = true;
		} else {
		    ptrv = (struct taint_retval *) tbptr;
		    tbptr += sizeof (struct taint_retval);
		    DPRINT ("Next syscall is %d clock %ld type %d tbptr %p tbend %p\n", ptrv->syscall, ptrv->clock, ptrv->rettype, tbptr, tbend);
		}
	    }
	}
	parseklog_write_chunk(log, destfd);
    }
    parseklog_close(log);
    close (destfd);
    munmap (tbbegin, tbsize);
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
    u_long last_clock = 2; //this should be a valid clock number in the case no valid clock is returned from handle_one_klog; 0 is not a valid stop clock for any syscall; 
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

#ifdef JUMPSTART_ROLLBACK_WITH_FORK 
    //wakeup the rollback process and let it replay
    //the wakeup will be done the syscall 350 with mode = 4
    
    DPRINT ("Done creating new checkpoint\n");
    return last_clock;
#else 
    // Patch complete - now execute up to the last syscall 
    char recover_syscall[64], recover_pid[64];
    sprintf (recover_syscall, "--recover_at=%lu", last_clock);
    sprintf (recover_pid, "--recover_pid=%d", getpid());
    pid_t cpid = fork ();
    if (cpid == 0) {
        DPRINT ("calling resume\n");
	rc = execl("./resume", "resume", last_altex.c_str(), "--pthread", "../eglibc-2.15/prefix/lib", recover_syscall, recover_pid, NULL);
	fprintf (stderr, "execl of resume failed, rc=%ld, errno=%d\n", rc, errno);
	return -1;
    } 

    DPRINT ("Done creating new checkpoint\n");

    return cpid;
#endif
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
        //currently, single-threaded program may call taintbuf file as "taintbuf."
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
