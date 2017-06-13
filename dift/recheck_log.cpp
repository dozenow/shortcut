#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syscall.h>
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>


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

static int write_data_into_recheck_log (int recheckfd, const void* buf, int len)
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
	if (res->psr.sysnum != syscall) {  //debugging: print out all skipped syscall
		switch (res->psr.sysnum) {
			case 45:  break;
			case 91:  break;
			case 125: break;
			case 192: break;
			case 174: break;
			default:
				fprintf (stderr, "[POTENTIAL UNHANDLED SYSCALL] skip_to_syscall: syscall %d, index %lld is skipped.\n", res->psr.sysnum , res->index); 
		}
	}
    } while (res->psr.sysnum != syscall);

    return res;
}

long calculate_partial_read_size (int is_cache_file, int partial_read, size_t start, size_t end, long total_size) { 
	if (partial_read == 0) return 0;
	if (is_cache_file == 0) return 0;
	else {
		long result = 0;
		if (start > 0) result += start;
		if ((long)end > total_size) { 
			fprintf (stderr, "[BUG] end size > total_size ???????\n");
		}
		if ((long)end < total_size) result += total_size-end;
		fprintf (stderr, "calculate_partial_read_size: size is %ld\n", result);
		return  result;
	}
}

int recheck_read (struct recheck_handle* handle, int fd, void* buf, size_t count, int partial_read, size_t partial_read_start, size_t partial_read_end)
{
    struct read_recheck rrchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_read);
    int is_cache_file = 0;

    if (res->psr.flags & SR_HAS_RETPARAMS) {
	rrchk.has_retvals = 1;
	rrchk.readlen = res->retparams_size;
	is_cache_file = *(unsigned int*)res->retparams;
    } else {
	rrchk.has_retvals = 0;
	rrchk.readlen = 0;
    }
    write_header_into_recheck_log (handle->recheckfd, SYS_read, res->retval, sizeof (struct read_recheck) + rrchk.readlen + calculate_partial_read_size(is_cache_file, partial_read, partial_read_start, partial_read_end, res->retval));
    rrchk.fd = fd;
    rrchk.buf = buf;
    rrchk.count = count;
    if (partial_read) { 
	    rrchk.partial_read = 1;
	    rrchk.partial_read_start = partial_read_start;
	    rrchk.partial_read_end = partial_read_end;
    } else 
	    rrchk.partial_read = 0;

    write_data_into_recheck_log (handle->recheckfd, &rrchk, sizeof(rrchk));
    if (rrchk.readlen) write_data_into_recheck_log (handle->recheckfd, res->retparams, rrchk.readlen);
    //put the content that we need to verify into the recheck log, so that we don't have to deal with cached files in the recheck logic (which requires sprintf causing segfault)
    if (partial_read && is_cache_file) { 
	    if (partial_read_start > 0) 
		    write_data_into_recheck_log (handle->recheckfd, (char*)buf, partial_read_start);
	    if ((long)partial_read_end < res->retval) 
		    write_data_into_recheck_log (handle->recheckfd, (char*)buf+partial_read_end, res->retval-partial_read_end);
    }

    return 0;
}

//sys_write wiP
int recheck_write (struct recheck_handle* handle, int fd, void* buf, size_t count)
{
    struct write_recheck wrchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_write);

    if (res->psr.flags & SR_HAS_RETPARAMS) {
	wrchk.has_retvals = 1;
	wrchk.writelen = res->retparams_size;
    } else {
	wrchk.has_retvals = 0;
	wrchk.writelen = 0;
    }
    write_header_into_recheck_log (handle->recheckfd, SYS_write, res->retval, sizeof (struct write_recheck) + wrchk.writelen);
    wrchk.fd = fd;
    wrchk.buf = buf;
    wrchk.count = count;
    write_data_into_recheck_log (handle->recheckfd, &wrchk, sizeof(wrchk));
    if (wrchk.writelen) write_data_into_recheck_log (handle->recheckfd, res->retparams, wrchk.writelen);

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

int recheck_ugetrlimit (struct recheck_handle* handle, int resource, struct rlimit* prlim)
{
    struct ugetrlimit_recheck ugchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_ugetrlimit);

    write_header_into_recheck_log (handle->recheckfd, SYS_ugetrlimit, res->retval, sizeof (struct ugetrlimit_recheck));
    ugchk.resource = resource;
    memcpy (&ugchk.rlim, res->retparams, sizeof(ugchk.rlim));
    write_data_into_recheck_log (handle->recheckfd, &ugchk, sizeof(ugchk));

    return 0;
}

int recheck_uname (struct recheck_handle* handle, struct utsname* buf)
{
    struct uname_recheck uchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_uname);

    write_header_into_recheck_log (handle->recheckfd, SYS_uname, res->retval, sizeof (struct uname_recheck));
    uchk.buf = buf;
    memcpy (&uchk.utsname, res->retparams, sizeof(uchk.utsname));
    write_data_into_recheck_log (handle->recheckfd, &uchk, sizeof(uchk));

    return 0;
}

int recheck_statfs64 (struct recheck_handle* handle, const char* path, size_t sz, struct statfs64* buf)
{
    struct statfs64_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_statfs64);

    write_header_into_recheck_log (handle->recheckfd, SYS_statfs64, res->retval, sizeof (struct statfs64_recheck) + strlen(path) + 1);
    schk.sz = sz;
    schk.buf = buf;
    memcpy (&schk.statfs, res->retparams, sizeof(schk.statfs));
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));
    write_data_into_recheck_log (handle->recheckfd, path, strlen(path)+1);

    return 0;
}

int recheck_gettimeofday (struct recheck_handle* handle, struct timeval* tv, struct timezone* tz) {
    struct gettimeofday_recheck chk;
    struct klog_result* res = skip_to_syscall (handle, SYS_gettimeofday);

    write_header_into_recheck_log (handle->recheckfd, SYS_gettimeofday, res->retval, sizeof(struct gettimeofday_recheck));
    chk.tv_ptr = tv;
    chk.tz_ptr = tz;
    write_data_into_recheck_log (handle->recheckfd, &chk, sizeof(chk));
    
    return 0;
}

int recheck_prlimit64 (struct recheck_handle* handle, pid_t pid, int resource, struct rlimit64* new_limit, struct rlimit64* old_limit)
{
    struct prlimit64_recheck pchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_prlimit64);
    write_header_into_recheck_log (handle->recheckfd, SYS_prlimit64, res->retval, sizeof (struct prlimit64_recheck));
    pchk.pid = pid;
    pchk.resource = resource;
    pchk.new_limit = new_limit;
    pchk.old_limit = old_limit;
    if (res->psr.flags & SR_HAS_RETPARAMS) {
	pchk.has_retvals = 1;
	memcpy (&pchk.retparams, res->retparams, sizeof(pchk.retparams));
    } else {
	pchk.has_retvals = 0;
    }
    write_data_into_recheck_log (handle->recheckfd, &pchk, sizeof(pchk));

    return 0;
}

int recheck_setpgid (struct recheck_handle* handle, pid_t pid, pid_t pgid, int is_pid_tainted, int is_pgid_tainted)
{
    struct setpgid_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_setpgid);
    write_header_into_recheck_log (handle->recheckfd, SYS_setpgid, res->retval, sizeof (struct setpgid_recheck));
    schk.pid = pid;
    schk.pgid = pgid;
    schk.is_pid_tainted = is_pid_tainted;
    schk.is_pgid_tainted = is_pgid_tainted;
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));

    return 0;
}

int recheck_readlink (struct recheck_handle* handle, char* path, char* buf, size_t bufsiz)
{
    struct readlink_recheck rchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_readlink);
    u_long size = sizeof(readlink_recheck) + strlen(path) + 1;
    if (res->retval > 0) size += res->retval;
    write_header_into_recheck_log (handle->recheckfd, SYS_readlink, res->retval, size);
    rchk.buf = buf;
    rchk.bufsiz = bufsiz;
    write_data_into_recheck_log (handle->recheckfd, &rchk, sizeof(rchk));
    if (res->retval > 0) write_data_into_recheck_log (handle->recheckfd, res->retparams, res->retval);
    write_data_into_recheck_log (handle->recheckfd, path, strlen(path)+1);

    return 0;
}

int recheck_socket (struct recheck_handle* handle, int domain, int type, int protocol)
{
    struct socket_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);
    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, sizeof (struct socket_recheck));
    schk.domain = domain;
    schk.type = type;
    schk.protocol = protocol;
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));

    return 0;
}

int recheck_connect (struct recheck_handle* handle, int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    struct connect_recheck cchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);
    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, sizeof (struct connect_recheck)+addrlen);
    cchk.sockfd = sockfd;
    cchk.addrlen = addrlen;
    write_data_into_recheck_log (handle->recheckfd, &cchk, sizeof(cchk));
    write_data_into_recheck_log (handle->recheckfd, addr, addrlen);

    return 0;
}

int recheck_getuid32 (struct recheck_handle* handle)
{
    struct klog_result *res = skip_to_syscall (handle, SYS_getuid32);
    write_header_into_recheck_log (handle->recheckfd, SYS_getuid32, res->retval, 0);

    return 0;
}

int recheck_llseek (struct recheck_handle* handle, u_int fd, u_long offset_high, u_long offset_low, loff_t* result, u_int whence)
{
    struct llseek_recheck rchk;
    struct klog_result *res = skip_to_syscall (handle, SYS__llseek);
    write_header_into_recheck_log (handle->recheckfd, SYS__llseek, res->retval, sizeof(rchk));
    rchk.fd = fd;
    rchk.offset_high = offset_high;
    rchk.offset_low = offset_low;
    if (res->retval >= 0) rchk.result = *((loff_t *) res->retparams);
    rchk.whence = whence;
    write_data_into_recheck_log (handle->recheckfd, &rchk, sizeof(rchk));

    return 0;
}

static inline void decode_ioctl (u_int cmd, u_int* pdir, u_int* psize)
{
    /* Some ioctls don't follow convention, so we need to hard-code them.
       I stole this from replay.c and it should be kept up to date with kernel. */
    int dir, size;

    switch (cmd) {
    case TCSBRK:
    case TCSBRKP:
    case TIOCSBRK:
    case TIOCCBRK:
    case TCFLSH:
    case TIOCEXCL:
    case TIOCNXCL:
    case TIOCSCTTY:
    case FIOCLEX:
    case FIONCLEX:
    case TIOCCONS:
    case TIOCNOTTY:
    case TIOCVHANGUP:
    case TIOCSERCONFIG:
    case TIOCSERGWILD:
    case TIOCSERSWILD:
    case TIOCMIWAIT:
		dir = _IOC_NONE;
		size = 0;
 		break;
    case TIOCSTI:
	dir = _IOC_READ;
	size = sizeof(char);
	break;
    case TIOCLINUX:
	dir = _IOC_READ | _IOC_WRITE;
	size = sizeof(char);
	break;
    case FIONBIO:
    case FIOASYNC:
	/*case FIBMAP:*/
    case TCXONC:
    case TIOCMBIS:
    case TIOCMBIC:
    case TIOCMSET:
    case TIOCSSOFTCAR:
    case TIOCPKT:
    case TIOCSETD:
	dir = _IOC_READ;
	size = sizeof(int);
	break;
    case TIOCOUTQ:
	/*case FIGETBSZ:*/
    case FIONREAD:
    case TIOCMGET:
    case TIOCGSOFTCAR:
    case TIOCGETD:
    case TIOCSERGETLSR:
	dir = _IOC_WRITE;
	size = sizeof(int);
	break;
    case FIOQSIZE:
	dir = _IOC_WRITE;
	size = sizeof(loff_t);
	break;
    case TCGETA:
    case TCGETS:
	dir = _IOC_WRITE;
	size = sizeof(struct termios);
	break;
    case TCSETA:
    case TCSETS:
    case TCSETAW:
    case TCSETAF:
    case TCSETSW:
    case TCSETSF:
	dir = _IOC_READ;
	size = sizeof(struct termios);
	break;
    case TIOCGSID:
	dir = _IOC_WRITE;
	size = sizeof(pid_t);
	break;
    case TIOCGPGRP:
	dir = _IOC_WRITE;
	size = sizeof(pid_t);
	break;
    case TIOCSPGRP:
	dir = _IOC_READ;
	size = sizeof(pid_t);
	break;
    case TIOCGWINSZ:
	dir = _IOC_WRITE;
	size = sizeof(struct winsize);
	break;
    case TIOCSWINSZ:
	dir = _IOC_READ;
	size = sizeof(struct winsize);
	break;
#if 0
    case TIOCGSERIAL:
	dir = _IOC_WRITE;
	size = sizeof(struct serial_struct);
	break;
    case TIOCSSERIAL:
	dir = _IOC_READ;
	size = sizeof(struct serial_struct);
	break;
    case TIOCGRS485:
	dir = _IOC_WRITE;
	size = sizeof(struct serial_rs485);
	break;
    case TIOCSRS485:
	dir = _IOC_READ;
	size = sizeof(struct serial_rs485);
	break;
    case TCGETX:
	dir = _IOC_WRITE;
	size = sizeof(struct termiox);
	break;
    case TCSETX:
    case TCSETXW:
    case TCSETXF:
	dir = _IOC_READ;
	size = sizeof(struct termiox);
	break;
#endif
    case TIOCGLCKTRMIOS:
	dir = _IOC_WRITE;
	size = sizeof(struct termios);
	break;
    case TIOCSLCKTRMIOS:
	dir = _IOC_READ;
	size = sizeof(struct termios);
	break;
#if 0
    case TIOCGICOUNT:
	dir = _IOC_WRITE;
	size = sizeof(struct serial_icounter_struct);
	break;
#endif
    default:
	/* Generic */
	printf ("[WARNING] Recording generic ioctl cmd %x\n", cmd);
	dir  = _IOC_DIR(cmd);
	size = _IOC_SIZE(cmd);
	if (dir == _IOC_NONE || size == 0) {
	    printf ("[ERROR] Generic IOCTL cmd %x has no data! This probably needs special handling!\n", cmd);
	    dir = _IOC_NONE;
	    size = 0;
	}
	break;
    }
    *pdir = dir;
    *psize = size;
}

int recheck_ioctl (struct recheck_handle* handle, u_int fd, u_int cmd, char* arg)
{
    struct ioctl_recheck ichk;
    struct klog_result *res = skip_to_syscall (handle, SYS_ioctl);

    /* I would trust the kernel size here */
    decode_ioctl (cmd, &ichk.dir, &ichk.size);
    printf ("ioctl: fd %d cmd %x dir %x retparams size %d\n", fd, cmd, ichk.dir, res->retparams_size);
    write_header_into_recheck_log (handle->recheckfd, SYS_ioctl, res->retval, sizeof(ichk)+res->retparams_size-sizeof(u_long));
    ichk.fd = fd;
    ichk.cmd = cmd;
    ichk.arg = arg;
    if (res->retparams_size > 0) {
	ichk.arglen = *((u_long *) res->retparams);
    } else {
	ichk.arglen = 0;
    }
    write_data_into_recheck_log (handle->recheckfd, &ichk, sizeof(ichk));
    if (ichk.arglen > 0) write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams+sizeof(u_long), ichk.arglen);

    return ichk.arglen;
}
