#include <sys/types.h>
#ifndef __USE_LARGEFILE64
#  define __USE_LARGEFILE64
#endif
#include <sys/stat.h>
#include <sys/utsname.h>

#include <stdio.h>
#include <syscall.h>
#include <assert.h>

#include "parseklib.h"
#include "taintbuf.h"

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

static void handle_stat64 (int fd, struct taint_retval* trv, struct klog_result* res)
{
    int rc;

    if (trv->rettype == STAT64_INO) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_ino, sizeof(((struct stat64 *) res->retparams)->st_ino));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_ino));
    } else if (trv->rettype == STAT64_MTIME) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_mtime, sizeof(((struct stat64 *) res->retparams)->st_mtime));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_mtime));
    } else if (trv->rettype == STAT64_CTIME) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_ctime, sizeof(((struct stat64 *) res->retparams)->st_ctime));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_ctime));
    } else if (trv->rettype == STAT64_ATIME) {
	rc = read (fd, &((struct stat64 *) res->retparams)->st_atime, sizeof(((struct stat64 *) res->retparams)->st_atime));
	assert (rc == sizeof(((struct stat64 *) res->retparams)->st_atime));
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
    //struct klog_result *res;
    
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

    int tfd = open("/tmp/taintbuf", O_RDONLY, 0);
    if (tfd < 0) {
	fprintf (stderr, "Cannot read tainted vaules file\n");
	return tfd;
    }

    // Open a file to write the result to
    int destfd = open ("/tmp/patchlog", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (destfd < 0) {
	fprintf (stderr, "Could not open output file,rc=%d", destfd);
	return -1;
    }
    
    struct taint_retval trv;
    if (read (tfd, &trv, sizeof(trv)) != sizeof(trv)) {
	fprintf (stderr, "Cannot read tainted retval\n");
	return -1;
    }
    printf ("Next syscall is %d clock %ld type %d\n", trv.syscall, trv.clock, trv.rettype);

    while ((count = parseklog_read_next_chunk(log)) > 0) {
	struct klog_result* res;
	while ((res = parseklog_get_next_psr_from_chunk (log)) != NULL) {
	    while (res->start_clock == trv.clock) {
		assert (res->psr.sysnum == trv.syscall);
		switch (trv.syscall) {
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
		    printf ("Next syscall is %d clock %ld type %d\n", trv.syscall, trv.clock, trv.rettype);
		}
	    }
	}
	printf ("Writing chunk\n");
	parseklog_write_chunk(log, destfd);
    }

    parseklog_close(log);
    close (destfd);
    close (tfd);
    return 0;
}

