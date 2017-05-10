#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "recheck_log.h"

struct recheck_handle {
    struct klogfile *log;
    int recheckfd;
};

struct recheck_handle* open_recheck_log (u_long record_grp, pid_t record_pid)
{
    char klog_filename[512];
    char recheck_filename[512];

    sprintf (klog_filename, "/replay_logdb/rec_%lu/klog.id.%d", record_grp, record_pid);
    sprintf (recheck_filename, "/tmp/recheck.%d", record_pid);

    struct recheck_handle* handle = (struct recheck_handle *) malloc(sizeof(struct recheck_handle));
    if (handle == NULL) {
	fprintf (stderr, "Cannot allocate recheck handle\n");
	return NULL;
    }

    handle->log = parseklog_open(klog_filename);
    if (handle->log == NULL) return NULL;

    handle->recheckfd = open (recheck_filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (handle->recheckfd < 0) {
	fprintf (stderr, "Cannot open recheck log\n");
	return NULL;
    }

    return handle;
}

int close_recheck_log (struct recheck_handle* handle)
{
    close (handle->recheckfd);
    parseklog_close(handle->log);
    free(handle);

    return 0;
}

static int write_header_into_recheck_log (int recheckfd, int sysnum, long retval, int len) 
{ 
    struct recheck_entry entry;
    int rc = 0;

    entry.sysnum = sysnum;
    entry.retval = retval;
    entry.len = len;
    
    rc = write (recheckfd, (void*) &entry, sizeof(entry));
    if (rc != sizeof(entry)) { 
	fprintf (stderr, "Wrtiting header to recheck log fails\n");
	return -1;
    }
    return 0;
}

static int write_data_into_recheck_log (int recheckfd, void* buf, int len)
{
    int rc = write (recheckfd, buf, len);
    if (rc != len) { 
	fprintf (stderr, "Wrtiting data to recheck log fails\n");
	return -1;
    }
    return 0;
}

static struct klog_result* skip_to_syscall (struct recheck_handle* handle, int syscall) 
{
    struct klog_result* res;

    do {
	res = parseklog_get_next_psr(handle->log);
	printf ("Index %lld syscall %d\n", res->index, res->psr.sysnum);
    } while (res->psr.sysnum != syscall);

    return res;
}

int recheck_read (struct recheck_handle* handle, int fd, void* buf, size_t count)
{
    struct read_recheck rrchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_read);

    if (res->psr.flags & SR_HAS_RETPARAMS) {
	rrchk.has_retvals = 1;
	rrchk.readlen = res->retparams_size;
    } else {
	rrchk.has_retvals = 0;
	rrchk.readlen = 0;
    }
    write_header_into_recheck_log (handle->recheckfd, SYS_read, res->retval, sizeof (struct read_recheck) + rrchk.readlen);
    rrchk.fd = fd;
    rrchk.buf = buf;
    rrchk.count = count;
    write_data_into_recheck_log (handle->recheckfd, &rrchk, sizeof(rrchk));
    if (rrchk.readlen) write_data_into_recheck_log (handle->recheckfd, res->retparams, rrchk.readlen);

    return 0;
}

int recheck_open (struct recheck_handle* handle, char* filename, int flags, int mode)
{
    struct open_recheck orchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_open);

    write_header_into_recheck_log (handle->recheckfd, SYS_open, res->retval, sizeof (struct open_recheck) + strlen(filename) + 1);
    if (res->psr.flags & SR_HAS_RETPARAMS) {
	orchk.has_retvals = 1;
	memcpy (&orchk.retvals, res->retparams, sizeof(orchk.retvals));
    } else {
	orchk.has_retvals = 0;
    }
    orchk.flags = flags;
    orchk.mode = mode;
    write_data_into_recheck_log (handle->recheckfd, &orchk, sizeof(orchk));
    write_data_into_recheck_log (handle->recheckfd, filename, strlen(filename)+1);

    return 0;
}

int recheck_close (struct recheck_handle* handle, int fd)
{
    struct close_recheck crchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_close);

    write_header_into_recheck_log (handle->recheckfd, SYS_close, res->retval, sizeof (struct close_recheck));
    crchk.fd = fd;
    write_data_into_recheck_log (handle->recheckfd, &crchk, sizeof(crchk));

    return 0;
}

int recheck_access (struct recheck_handle* handle, char* pathname, int mode)
{
    struct access_recheck archk;
    struct klog_result *res = skip_to_syscall (handle, SYS_access);

    write_header_into_recheck_log (handle->recheckfd, SYS_access, res->retval, sizeof (struct access_recheck) + strlen(pathname) + 1);
    archk.mode = mode;
    write_data_into_recheck_log (handle->recheckfd, &archk, sizeof(archk));
    write_data_into_recheck_log (handle->recheckfd, pathname, strlen(pathname)+1);

    return 0;
}

int recheck_stat64 (struct recheck_handle* handle, char* pathname, void* buf)
{
    struct stat64_recheck srchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_stat64);

    write_header_into_recheck_log (handle->recheckfd, SYS_stat64, res->retval, sizeof (struct stat64_recheck) + strlen(pathname) + 1);
    if (res->psr.flags & SR_HAS_RETPARAMS) {
	srchk.has_retvals = 1;
	memcpy (&srchk.retvals, res->retparams, sizeof(srchk.retvals));
    } else {
	srchk.has_retvals = 0;
    }
    srchk.buf = buf;
    write_data_into_recheck_log (handle->recheckfd, &srchk, sizeof(srchk));
    write_data_into_recheck_log (handle->recheckfd, pathname, strlen(pathname)+1);

    return 0;
}

int recheck_fstat64 (struct recheck_handle* handle, int fd, void* buf)
{
    struct fstat64_recheck srchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_fstat64);

    write_header_into_recheck_log (handle->recheckfd, SYS_fstat64, res->retval, sizeof (struct fstat64_recheck));
    if (res->psr.flags & SR_HAS_RETPARAMS) {
	srchk.has_retvals = 1;
	memcpy (&srchk.retvals, res->retparams, sizeof(srchk.retvals));
    } else {
	srchk.has_retvals = 0;
    }
    srchk.fd = fd;
    srchk.buf = buf;
    write_data_into_recheck_log (handle->recheckfd, &srchk, sizeof(srchk));

    return 0;
}

