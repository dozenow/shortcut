#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syscall.h>
#include <unistd.h>
#include <poll.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/termios.h>
#include <sys/prctl.h>
#include <sys/uio.h>

#include "taint_interface/taint_interface.h"
#include "recheck_log.h"

struct recheck_handle {
    struct klogfile *log;
    int recheckfd;
};

struct recheck_handle* open_recheck_log (int threadid, u_long record_grp, pid_t record_pid)
{
    char klog_filename[512];
    char recheck_filename[512];

    sprintf (klog_filename, "/replay_logdb/rec_%lu/klog.id.%d", record_grp, record_pid);
    sprintf (recheck_filename, "/replay_logdb/rec_%lu/recheck.%d", record_grp, record_pid);

    struct recheck_handle* handle = (struct recheck_handle *) malloc(sizeof(struct recheck_handle));
    if (handle == NULL) {
	fprintf (stderr, "Cannot allocate recheck handle\n");
	return NULL;
    }

    handle->log = parseklog_open(klog_filename);
    if (handle->log == NULL) {
	fprintf (stderr, "Cannot open klog %s\n", klog_filename);
	return NULL;
    }

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

static int write_header_into_recheck_log (int recheckfd, int sysnum, long retval, int len, u_long clock) 
{ 
    struct recheck_entry entry;
    int rc = 0;

    entry.sysnum = sysnum;
    entry.clock = clock;
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

static void write_taintmask_into_recheck_log (struct recheck_handle* handle, u_long mem_loc, u_long size)
{
    char tainted[size];

    for (u_long i = 0; i < size; i++) {
	tainted[i] = is_mem_arg_tainted (mem_loc+i, 1); // This could be more efficient
    }
    write_data_into_recheck_log (handle->recheckfd, tainted, size);
    write_data_into_recheck_log (handle->recheckfd, (void *) mem_loc, size);
}

static struct klog_result* skip_to_syscall (struct recheck_handle* handle, int syscall) 
{
    struct klog_result* res;

    do {
	res = parseklog_get_next_psr(handle->log);
	if (res->psr.sysnum != syscall) {  //debugging: print out all skipped syscall
	    switch (res->psr.sysnum) {
	    case SYS_kill:
	    case SYS_brk:
	    case SYS_munmap:  
	    case SYS_mprotect: 
            case SYS_clone:
	    case SYS_mremap:
            case SYS_sched_yield:
	    case SYS_mmap: 
	    case SYS_mmap2: 
		break; //already handled
	    default:
		fprintf (stderr, "[POTENTIAL UNHANDLED SYSCALL] skip_to_syscall: syscall %d, index %lld is skipped, start_clock %lu - looking for %d\n", res->psr.sysnum , res->index, res->start_clock, syscall); 
	    }
	}
    } while (res->psr.sysnum != syscall);

    return res;
}

static void check_reg_arguments (const char* call, int regnum)
{
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EBX, 4, 0)) fprintf (stderr, "[ERROR] register ebx (arg 1) for syscall %s is tainted\n", call);
    if (regnum == 1) return;
    if (is_reg_arg_tainted(LEVEL_BASE::REG_ECX, 4, 0)) fprintf (stderr, "[ERROR] register ecx (arg 2) for syscall %s is tainted\n", call);
    if (regnum == 2) return;
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EDX, 4, 0)) fprintf (stderr, "[ERROR] register edx (arg 3) for syscall %s is tainted\n", call);
    if (regnum == 3) return;
    if (is_reg_arg_tainted(LEVEL_BASE::REG_ESI, 4, 0)) fprintf (stderr, "[ERROR] register esi (arg 4) for syscall %s is tainted\n", call);
    if (regnum == 4) return;
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EDI, 4, 0)) fprintf (stderr, "[ERROR] register edi (arg 5) for syscall %s is tainted\n", call);
    if (regnum == 5) return;
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EBP, 4, 0)) fprintf (stderr, "[ERROR] register ebp (arg 6) for syscall %s is tainted\n", call);
    assert (regnum == 6);
}

static void check_one_reg_argument (const char* call, int arg_index) //index starts from 1
{
    switch (arg_index) {
        case 1: if (is_reg_arg_tainted(LEVEL_BASE::REG_EBX, 4, 0)) fprintf (stderr, "[ERROR] register ebx (arg 1) for syscall %s is tainted\n", call); return;
        case 2: if (is_reg_arg_tainted(LEVEL_BASE::REG_ECX, 4, 0)) fprintf (stderr, "[ERROR] register ecx (arg 2) for syscall %s is tainted\n", call); return;
        case 3: if (is_reg_arg_tainted(LEVEL_BASE::REG_EDX, 4, 0)) fprintf (stderr, "[ERROR] register edx (arg 3) for syscall %s is tainted\n", call); return;
        case 4: if (is_reg_arg_tainted(LEVEL_BASE::REG_ESI, 4, 0)) fprintf (stderr, "[ERROR] register esi (arg 4) for syscall %s is tainted\n", call); return;
        case 5: if (is_reg_arg_tainted(LEVEL_BASE::REG_EDI, 4, 0)) fprintf (stderr, "[ERROR] register edi (arg 5) for syscall %s is tainted\n", call); return;
        case 6: if (is_reg_arg_tainted(LEVEL_BASE::REG_EBP, 4, 0)) fprintf (stderr, "[ERROR] register ebp (arg 6) for syscall %s is tainted\n", call); return;
        default:
                    assert (0);
    }
}

static long calculate_partial_read_size (int is_cache_file, int partial_read, size_t start, size_t end, long total_size) { 
	if (partial_read == 0) return 0;
	if ((is_cache_file&CACHE_MASK) == 0) return 0;
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

int recheck_read_ignore (struct recheck_handle* handle) 
{
    skip_to_syscall (handle, SYS_read);
    return 0;
}

int recheck_read (struct recheck_handle* handle, int fd, void* buf, size_t count, int partial_read, size_t partial_read_start, size_t partial_read_end, u_long max_bound, u_long clock)
{
    struct read_recheck rrchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_read);
    int is_cache_file = 0;

    check_reg_arguments ("read", 2); // We check if count is tainted below
    
    if (res->psr.flags & SR_HAS_RETPARAMS) {
	rrchk.has_retvals = 1;
	rrchk.readlen = res->retparams_size;
	is_cache_file = *(unsigned int*)res->retparams;
    } else {
	rrchk.has_retvals = 0;
	rrchk.readlen = 0;
    }
    write_header_into_recheck_log (handle->recheckfd, SYS_read, res->retval, 
				   sizeof (struct read_recheck) + rrchk.readlen + calculate_partial_read_size(is_cache_file, partial_read, partial_read_start, partial_read_end, res->retval), clock);
    rrchk.fd = fd;
    rrchk.buf = buf;
    rrchk.count = count;
    rrchk.is_count_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_EDX, 4, 0);
    if (partial_read) { 
	    rrchk.partial_read = 1;
	    rrchk.partial_read_start = partial_read_start;
	    rrchk.partial_read_end = partial_read_end;
    } else {
	    rrchk.partial_read = 0;
    }
    rrchk.max_bound = max_bound;

    write_data_into_recheck_log (handle->recheckfd, &rrchk, sizeof(rrchk));
    if (rrchk.readlen) write_data_into_recheck_log (handle->recheckfd, res->retparams, rrchk.readlen);
    //put the content that we need to verify into the recheck log, so that we don't have to deal with cached files in the recheck logic (which requires sprintf causing segfault)
    if (partial_read && (is_cache_file&CACHE_MASK)) { 
	    if (partial_read_start > 0) 
		    write_data_into_recheck_log (handle->recheckfd, (char*)buf, partial_read_start);
	    if ((long)partial_read_end < res->retval) 
		    write_data_into_recheck_log (handle->recheckfd, (char*)buf+partial_read_end, res->retval-partial_read_end);
    }

    return 0;
}

int recheck_recv (struct recheck_handle* handle, int sockfd, void* buf, size_t len, int flags, int partial_read_cnt, size_t* partial_read_starts, size_t* partial_read_ends, u_long clock)
{
    struct recv_recheck rrchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);

    check_reg_arguments ("recv", 4); 
    
    if (res->retval > 0) {
	rrchk.readlen = res->retval;
    } else {
	rrchk.readlen = 0;
    }
    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, sizeof (struct recv_recheck) + rrchk.readlen, clock);
    rrchk.sockfd = sockfd;
    rrchk.buf = buf;
    rrchk.len = len;
    rrchk.flags = flags;
    rrchk.partial_read_cnt = partial_read_cnt;
    memcpy (rrchk.partial_read_starts, partial_read_starts, partial_read_cnt*sizeof(size_t));
    memcpy (rrchk.partial_read_ends, partial_read_ends, partial_read_cnt*sizeof(size_t));
    write_data_into_recheck_log (handle->recheckfd, &rrchk, sizeof(rrchk));
    struct recvfrom_retvals* pretvals = (struct recvfrom_retvals *) res->retparams;
    if (rrchk.readlen) write_data_into_recheck_log (handle->recheckfd, &pretvals->buf, rrchk.readlen);
    // Technically don't need to write data that will not be verified on partial reads - ignored

    return res->retval;
}

int recheck_recvmsg (struct recheck_handle* handle, int sockfd, struct msghdr* msg, int flags, int partial_read_cnt, size_t* partial_read_starts, size_t* partial_read_ends, u_long clock)
{
    struct recvmsg_recheck rmchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);

    check_reg_arguments ("recvmsg", 3); 
    if (is_mem_arg_tainted ((u_long) msg, sizeof(struct msghdr))) fprintf (stderr, "[ERROR] recvmsg: msg is tainted, clock %lu\n", clock);
    if (is_mem_arg_tainted ((u_long) msg->msg_iov, sizeof(struct iovec)*msg->msg_iovlen)) fprintf (stderr, "[ERROR] recvmsg: msg iov is tainted, clock %lu\n", clock);
    
    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, 
				   sizeof(struct recvmsg_recheck) + sizeof(struct msghdr) + sizeof(struct iovec)*msg->msg_iovlen+res->retparams_size, clock);
    rmchk.sockfd = sockfd;
    rmchk.msg = msg;
    rmchk.flags = flags;
    rmchk.partial_read_cnt = partial_read_cnt;
    memcpy (rmchk.partial_read_starts, partial_read_starts, partial_read_cnt*sizeof(size_t));
    memcpy (rmchk.partial_read_ends, partial_read_ends, partial_read_cnt*sizeof(size_t));
    write_data_into_recheck_log (handle->recheckfd, &rmchk, sizeof(rmchk));
    write_data_into_recheck_log (handle->recheckfd, msg, sizeof(struct msghdr));
    write_data_into_recheck_log (handle->recheckfd, msg->msg_iov, sizeof(struct iovec)*msg->msg_iovlen); 
    write_data_into_recheck_log (handle->recheckfd, res->retparams, res->retparams_size);

    return res->retval;
}

int recheck_write (struct recheck_handle* handle, int fd, void* buf, size_t count, u_long clock)
{
    struct write_recheck wrchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_write);

    check_reg_arguments ("write", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_write, res->retval, sizeof (struct write_recheck)+count*2, clock);
    wrchk.fd = fd;
    wrchk.buf = buf;
    wrchk.count = count;
    wrchk.is_count_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_EDX, 4, 0);
    
    write_data_into_recheck_log (handle->recheckfd, &wrchk, sizeof(wrchk));
    write_taintmask_into_recheck_log (handle, (u_long ) buf, count);

    return 0;
}

int recheck_writev (struct recheck_handle* handle, int fd, struct iovec* iov, int iovcnt, u_long clock)
{
    struct writev_recheck wrchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_writev);

    check_reg_arguments ("writev", 3);

    u_long count = 0;
    for (int i = 0; i < iovcnt; i++) {
	if (is_mem_arg_tainted ((u_long) &iov[i], sizeof(iov[i]))) fprintf (stderr, "[INFO] iov entry %d is tainted clock %lu\n", i, clock);
	count += iov[i].iov_len;
    }
    write_header_into_recheck_log (handle->recheckfd, SYS_writev, res->retval, sizeof(wrchk) + iovcnt*sizeof(struct iovec) + count*2, clock);
    wrchk.fd = fd;
    wrchk.iov = iov;
    wrchk.iovcnt = iovcnt;
    
    write_data_into_recheck_log (handle->recheckfd, &wrchk, sizeof(wrchk));
    write_data_into_recheck_log (handle->recheckfd, iov, iovcnt*sizeof(struct iovec));
    for (int i = 0; i < iovcnt; i++) {
	write_taintmask_into_recheck_log (handle, (u_long) iov[i].iov_base, iov[i].iov_len);
    }

    return 0;
}

int recheck_send (struct recheck_handle* handle, int sockfd, void* buf, size_t len, int flags, u_long clock)
{
    struct send_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);

    check_reg_arguments ("send", 4);

    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, sizeof(struct send_recheck) + len*2, clock);
    schk.sockfd = sockfd;
    schk.buf = buf;
    schk.len = len;
    schk.flags = flags;
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));
    write_taintmask_into_recheck_log (handle, (u_long) buf, len);

    return 0;
}

int recheck_sendmsg (struct recheck_handle* handle, int sockfd, struct msghdr* msg, int flags, u_long clock)
{
    struct sendmsg_recheck smchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);

    check_reg_arguments ("sendmsg", 3);
    if (is_mem_arg_tainted ((u_long) msg, sizeof(struct msghdr))) {
	fprintf (stderr, "[ERROR] sendmsg msghdr is tainted\n");
    }
    if (msg->msg_namelen > 0 && is_mem_arg_tainted ((u_long) msg->msg_name, msg->msg_namelen)) {
	fprintf (stderr, "[ERROR] sendmsg name is tainted\n");
    }
    if (msg->msg_iovlen > 0 && is_mem_arg_tainted ((u_long) msg->msg_iov, msg->msg_iovlen*sizeof(struct iovec))) {
	for (u_int i = 0; i < msg->msg_iovlen; i++) {
	    if (is_mem_arg_tainted ((u_long) &msg->msg_iov[i].iov_len, sizeof(msg->msg_iov[i].iov_len))) {
		fprintf (stderr, "[ERROR] sendmsg iov %d len %d is tainted, clock=%lu\n", i, msg->msg_iov[i].iov_len, clock);
	    }
	    if (is_mem_arg_tainted ((u_long) msg->msg_iov[i].iov_base, sizeof(msg->msg_iov[i].iov_base))) {
		fprintf (stderr, "[ERROR] sendmsg iov %d base %p is tainted, clock=%lu\n", i, msg->msg_iov[i].iov_base, clock);
	    }
	}
    }

    u_long count = sizeof(struct msghdr);
    count += msg->msg_namelen;
    count += msg->msg_iovlen*sizeof(struct iovec);
    for (u_int i = 0; i < msg->msg_iovlen; i++) {
	if (is_mem_arg_tainted ((u_long) &msg->msg_iov[i], sizeof(msg->msg_iov[i]))) fprintf (stderr, "[INFO] iov entry %d is tainted\n", i);
	count += msg->msg_iov[i].iov_len*2;
    }
    count += msg->msg_controllen*2;

    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, sizeof (struct sendmsg_recheck) + count, clock);
    smchk.sockfd = sockfd;
    smchk.msg = msg;
    smchk.flags = flags;
    write_data_into_recheck_log (handle->recheckfd, &smchk, sizeof(smchk));
    write_data_into_recheck_log (handle->recheckfd, msg, sizeof(struct msghdr));
    write_data_into_recheck_log (handle->recheckfd, msg->msg_name, msg->msg_namelen);
    write_data_into_recheck_log (handle->recheckfd, msg->msg_iov, msg->msg_iovlen*sizeof(struct iovec));
    for (u_int i = 0; i < msg->msg_iovlen; i++) {
	write_taintmask_into_recheck_log (handle, (u_long) msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
    }
    write_taintmask_into_recheck_log (handle, (u_long) msg->msg_control, msg->msg_controllen);

    return 0;
}

int recheck_execve (struct recheck_handle* handle, char* filename, char** argv, char** envp, u_long clock)
{
    struct execve_recheck echk;
    struct klog_result *res = skip_to_syscall (handle, SYS_execve);
    int argvcnt, envpcnt;

    check_reg_arguments ("execve", 3);
    if (is_mem_arg_tainted ((u_long) filename, strlen(filename)+1)) fprintf (stderr, "[ERROR] execve filename is tainted\n");
    //fprintf (stderr, "filename: %s\n", filename);
    for (argvcnt = 0; argv[argvcnt] != NULL; argvcnt++) {
	//fprintf (stderr, "arg at %p: %s\n", argv[argvcnt], argv[argvcnt]);
	if (is_mem_arg_tainted ((u_long) argv[argvcnt], strlen(argv[argvcnt])+1)) {
	    fprintf (stderr, "[ERROR] argument %d %s is tainted\n", argvcnt, argv[argvcnt]);	
	}
    }
    for (envpcnt = 0; envp[envpcnt] != NULL; envpcnt++) {
	//fprintf (stderr, "env at %p: %s\n", envp[envpcnt], envp[envpcnt]);
	if (is_mem_arg_tainted ((u_long) envp[envpcnt], strlen(envp[envpcnt])+1)) {
	    fprintf (stderr, "[ERROR] argument %d %s is tainted\n", envpcnt, envp[envpcnt]);	
	}
    }

    write_header_into_recheck_log (handle->recheckfd, SYS_execve, res->retval, sizeof (struct execve_recheck), clock);
    echk.filename = filename;
    echk.argv = argv;
    echk.argvcnt = argvcnt;
    echk.envp = envp;
    echk.envpcnt = envpcnt;
    write_data_into_recheck_log (handle->recheckfd, &echk, sizeof(echk));
    write_data_into_recheck_log (handle->recheckfd, filename, strlen(filename)+1);
    write_data_into_recheck_log (handle->recheckfd, argv, argvcnt*sizeof(char*));
    write_data_into_recheck_log (handle->recheckfd, envp, envpcnt*sizeof(char*));
    for (int i = 0; i < argvcnt; i++) {
	write_data_into_recheck_log (handle->recheckfd, argv[i], strlen(argv[i])+1);
    }
    for (int i = 0; i < envpcnt; i++) {
	write_data_into_recheck_log (handle->recheckfd, envp[i], strlen(envp[i])+1);
    }

    return res->retval;
}

int recheck_open (struct recheck_handle* handle, char* filename, int flags, int mode, u_long clock)
{
    struct open_recheck orchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_open);

    check_reg_arguments ("open", 1);
    if (is_mem_arg_tainted ((u_long) filename, strlen(filename)+1)) fprintf (stderr, "[ERROR] open filename is tainted: %s\n", filename);

    write_header_into_recheck_log (handle->recheckfd, SYS_open, res->retval, sizeof (struct open_recheck) + strlen(filename) + 1, clock);
    if (res->psr.flags & SR_HAS_RETPARAMS) {
	orchk.has_retvals = 1;
	memcpy (&orchk.retvals, res->retparams, sizeof(orchk.retvals));
    } else {
	orchk.has_retvals = 0;
    }
    orchk.is_flags_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_ECX, 4, 0);
    orchk.flags = flags;
    orchk.is_mode_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_EDX, 4, 0);
    orchk.mode = mode;
    write_data_into_recheck_log (handle->recheckfd, &orchk, sizeof(orchk));
    write_data_into_recheck_log (handle->recheckfd, filename, strlen(filename)+1);

    return 0;
}

int recheck_openat (struct recheck_handle* handle, int dirfd, char* filename, int flags, int mode, u_long clock)
{
    struct openat_recheck orchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_openat);

    check_reg_arguments ("openat", 4);
    if (is_mem_arg_tainted ((u_long) filename, strlen(filename)+1)) fprintf (stderr, "[ERROR] openat filename is tainted\n");

    write_header_into_recheck_log (handle->recheckfd, SYS_openat, res->retval, sizeof (struct openat_recheck) + strlen(filename) + 1, clock);
    orchk.dirfd = dirfd;
    orchk.flags = flags;
    orchk.mode = mode;
    write_data_into_recheck_log (handle->recheckfd, &orchk, sizeof(orchk));
    write_data_into_recheck_log (handle->recheckfd, filename, strlen(filename)+1);

    return 0;
}

int recheck_close (struct recheck_handle* handle, int fd, u_long clock)
{
    struct close_recheck crchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_close);

    check_reg_arguments ("close", 1);

    write_header_into_recheck_log (handle->recheckfd, SYS_close, res->retval, sizeof (struct close_recheck), clock);
    crchk.fd = fd;
    write_data_into_recheck_log (handle->recheckfd, &crchk, sizeof(crchk));

    return 0;
}

int recheck_waitpid (struct recheck_handle* handle, pid_t pid, int* status, int options, u_long clock)
{
    struct waitpid_recheck wchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_waitpid);

    check_reg_arguments ("waitpid", 3);

    write_header_into_recheck_log (handle->recheckfd, SYS_waitpid, res->retval, sizeof (struct waitpid_recheck), clock);
    wchk.pid = pid;
    wchk.status = status;
    wchk.options = options;
    wchk.statusval = *((int *) res->retparams);
    write_data_into_recheck_log (handle->recheckfd, &wchk, sizeof(wchk));

    return 0;
}

int recheck_dup2 (struct recheck_handle* handle, int oldfd, int newfd, u_long clock)
{
    struct dup2_recheck dchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_dup2);

    check_reg_arguments ("dup2", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_dup2, res->retval, sizeof (struct dup2_recheck), clock);
    dchk.oldfd = oldfd;
    dchk.newfd = newfd;
    write_data_into_recheck_log (handle->recheckfd, &dchk, sizeof(dchk));

    return 0;
}

int recheck_access (struct recheck_handle* handle, char* pathname, int mode, u_long clock)
{
    struct access_recheck archk;
    struct klog_result *res = skip_to_syscall (handle, SYS_access);

    check_reg_arguments ("access", 2);
    if (is_mem_arg_tainted ((u_long) pathname, strlen(pathname)+1)) {
	fprintf (stderr, "[ERROR] access pathname is tainted: %s clock %lu\n", pathname, clock);
	for (u_int i = 0; i < strlen(pathname)+1; i++) {
	    if (is_mem_arg_tainted ((u_long)pathname+i, 1)) fprintf (stderr, "%d (%p): %c\n", i, &pathname[i], pathname[i]);
	}
    }

    write_header_into_recheck_log (handle->recheckfd, SYS_access, res->retval, sizeof (struct access_recheck) + strlen(pathname) + 1, clock);
    archk.mode = mode;
    write_data_into_recheck_log (handle->recheckfd, &archk, sizeof(archk));
    write_data_into_recheck_log (handle->recheckfd, pathname, strlen(pathname)+1);

    return 0;
}

int recheck_stat64 (struct recheck_handle* handle, char* pathname, void* buf, u_long clock)
{
    struct stat64_recheck srchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_stat64);

    check_reg_arguments ("stat64", 2);
    if (is_mem_arg_tainted ((u_long) pathname, strlen(pathname)+1)) fprintf (stderr, "[ERROR] stat64 pathname is tainted\n");

    write_header_into_recheck_log (handle->recheckfd, SYS_stat64, res->retval, sizeof (struct stat64_recheck) + strlen(pathname) + 1, clock);
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

int recheck_lstat64 (struct recheck_handle* handle, char* pathname, void* buf, u_long clock)
{
    struct stat64_recheck srchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_lstat64);

    check_reg_arguments ("lstat64", 2);
    if (is_mem_arg_tainted ((u_long) pathname, strlen(pathname)+1)) fprintf (stderr, "[ERROR] lstat64 pathname is tainted\n");

    write_header_into_recheck_log (handle->recheckfd, SYS_lstat64, res->retval, sizeof (struct stat64_recheck) + strlen(pathname) + 1, clock);
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

int recheck_fstat64 (struct recheck_handle* handle, int fd, void* buf, u_long clock)
{
    struct fstat64_recheck srchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_fstat64);

    check_reg_arguments ("fstat64", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_fstat64, res->retval, sizeof (struct fstat64_recheck), clock);
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

int recheck_pipe (struct recheck_handle* handle, int pipefd[2], u_long clock)
{
    struct pipe_recheck pchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_pipe);

    check_reg_arguments ("pipe", 1);

    write_header_into_recheck_log (handle->recheckfd, SYS_pipe, res->retval, sizeof (struct pipe_recheck), clock);
    pchk.pipefd = pipefd;
    memcpy (pchk.piperet, res->retparams, 2*sizeof(int));
    write_data_into_recheck_log (handle->recheckfd, &pchk, sizeof(pchk));

    return 0;
}

int recheck_fcntl64_getfd (struct recheck_handle* handle, int fd, u_long clock)
{
    struct fcntl64_getfd_recheck fchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_fcntl64);

    check_reg_arguments ("fcntl64 getfd", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_fcntl64, res->retval, sizeof (struct fcntl64_getfd_recheck), clock);
    fchk.fd = fd;
    write_data_into_recheck_log (handle->recheckfd, &fchk, sizeof(fchk));

    return 0;
}

int recheck_fcntl64_setfd (struct recheck_handle* handle, int fd, int arg, u_long clock)
{
    struct fcntl64_setfd_recheck fchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_fcntl64);

    check_reg_arguments ("fcntl64 setfd", 3);

    write_header_into_recheck_log (handle->recheckfd, SYS_fcntl64, res->retval, sizeof (struct fcntl64_setfd_recheck), clock);
    fchk.fd = fd;
    fchk.arg = arg;
    write_data_into_recheck_log (handle->recheckfd, &fchk, sizeof(fchk));

    return 0;
}

int recheck_fcntl64_getfl (struct recheck_handle* handle, int fd, u_long clock)
{
    struct fcntl64_getfl_recheck fchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_fcntl64);

    check_reg_arguments ("fcntl64 getfl", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_fcntl64, res->retval, sizeof (struct fcntl64_getfl_recheck), clock);
    fchk.fd = fd;
    write_data_into_recheck_log (handle->recheckfd, &fchk, sizeof(fchk));

    return 0;
}

int recheck_fcntl64_getlk (struct recheck_handle* handle, int fd, void* arg, u_long clock)
{
    struct fcntl64_getlk_recheck fchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_fcntl64);

    check_reg_arguments ("fcntl64 getlk", 3);

    write_header_into_recheck_log (handle->recheckfd, SYS_fcntl64, res->retval, sizeof (struct fcntl64_getlk_recheck), clock);
    if (res->psr.flags & SR_HAS_RETPARAMS) {
	fchk.has_retvals = 1;
	memcpy (&fchk.flock, res->retparams, sizeof(fchk.flock));
    } else {
	fchk.has_retvals = 0;
    }
    fchk.fd = fd;
    fchk.arg = arg;
    write_data_into_recheck_log (handle->recheckfd, &fchk, sizeof(fchk));

    return 0;
}

int recheck_fcntl64_setfl (struct recheck_handle* handle, int fd, long flags, u_long clock)
{
    struct fcntl64_setfl_recheck fchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_fcntl64);

    check_reg_arguments ("fcntl64 setfl", 3);

    write_header_into_recheck_log (handle->recheckfd, SYS_fcntl64, res->retval, sizeof (struct fcntl64_setfl_recheck), clock);
    fchk.fd = fd;
    fchk.flags = flags;
    write_data_into_recheck_log (handle->recheckfd, &fchk, sizeof(fchk));

    return 0;
}

int recheck_fcntl64_getown (struct recheck_handle* handle, int fd, u_long clock)
{
    struct fcntl64_getown_recheck fchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_fcntl64);

    check_reg_arguments ("fcntl64 getown", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_fcntl64, res->retval, sizeof (struct fcntl64_getown_recheck), clock);
    fchk.fd = fd;
    write_data_into_recheck_log (handle->recheckfd, &fchk, sizeof(fchk));

    return 0;
}

int recheck_fcntl64_setown (struct recheck_handle* handle, int fd, long owner, int is_owner_tainted, u_long clock)
{
    struct fcntl64_setown_recheck fchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_fcntl64);

    check_reg_arguments ("fcntl64 setown", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_fcntl64, res->retval, sizeof (struct fcntl64_setown_recheck), clock);
    fchk.fd = fd;
    fchk.owner = owner;
    fchk.is_owner_tainted = is_owner_tainted;
    write_data_into_recheck_log (handle->recheckfd, &fchk, sizeof(fchk));

    return 0;
}

int recheck_ugetrlimit (struct recheck_handle* handle, int resource, struct rlimit* prlim, u_long clock)
{
    struct ugetrlimit_recheck ugchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_ugetrlimit);

    check_reg_arguments ("ugetrlimit", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_ugetrlimit, res->retval, sizeof (struct ugetrlimit_recheck), clock);
    ugchk.resource = resource;
    memcpy (&ugchk.rlim, res->retparams, sizeof(ugchk.rlim));
    write_data_into_recheck_log (handle->recheckfd, &ugchk, sizeof(ugchk));

    return 0;
}

int recheck_setrlimit (struct recheck_handle* handle, int resource, struct rlimit* prlim, u_long clock)
{
    struct setrlimit_recheck ugchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_setrlimit);

    check_reg_arguments ("setrlimit", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_setrlimit, res->retval, sizeof (struct setrlimit_recheck), clock);
    ugchk.resource = resource;
    memcpy (&ugchk.rlim, prlim, sizeof(ugchk.rlim));
    write_data_into_recheck_log (handle->recheckfd, &ugchk, sizeof(ugchk));

    return 0;
}

int recheck_uname (struct recheck_handle* handle, struct utsname* buf, u_long clock)
{
    struct uname_recheck uchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_uname);

    check_reg_arguments ("uname", 1);

    write_header_into_recheck_log (handle->recheckfd, SYS_uname, res->retval, sizeof (struct uname_recheck), clock);
    uchk.buf = buf;
    memcpy (&uchk.utsname, res->retparams, sizeof(uchk.utsname));
    write_data_into_recheck_log (handle->recheckfd, &uchk, sizeof(uchk));

    return 0;
}

int recheck_statfs64 (struct recheck_handle* handle, const char* path, size_t sz, struct statfs64* buf, u_long clock)
{
    struct statfs64_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_statfs64);

    check_reg_arguments ("statfs64", 3);
    if (is_mem_arg_tainted ((u_long) path, strlen(path)+1)) fprintf (stderr, "[ERROR] statfs64 path is tainted\n");

    write_header_into_recheck_log (handle->recheckfd, SYS_statfs64, res->retval, sizeof (struct statfs64_recheck) + strlen(path) + 1, clock);
    schk.sz = sz;
    schk.buf = buf;
    memcpy (&schk.statfs, res->retparams, sizeof(schk.statfs));
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));
    write_data_into_recheck_log (handle->recheckfd, path, strlen(path)+1);

    return 0;
}

int recheck_gettimeofday (struct recheck_handle* handle, struct timeval* tv, struct timezone* tz, u_long clock) {
    struct gettimeofday_recheck chk;
    struct klog_result* res = skip_to_syscall (handle, SYS_gettimeofday);

    check_reg_arguments ("gettimeofday", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_gettimeofday, res->retval, sizeof(struct gettimeofday_recheck), clock);
    chk.tv_ptr = tv;
    chk.tz_ptr = tz;
    write_data_into_recheck_log (handle->recheckfd, &chk, sizeof(chk));
    
    return 0;
}

/* Odd function: we can skip this syscall and return value from log if CLOCK_MONOTONIC */
int recheck_clock_gettime_monotonic (struct recheck_handle* handle, struct timespec* tp_out) 
{
    struct klog_result* res = skip_to_syscall (handle, SYS_clock_gettime);
    check_reg_arguments ("clock_gettime (monotonic)", 2);
    memcpy (tp_out, res->retparams, sizeof(struct timespec));
    return res->retval;
}

int recheck_clock_gettime (struct recheck_handle* handle, clockid_t clk_id, struct timespec* tp, u_long clock) {
    struct clock_getx_recheck chk;
    struct klog_result* res = skip_to_syscall (handle, SYS_clock_gettime);

    check_reg_arguments ("clock_gettime", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_clock_gettime, res->retval, sizeof(struct clock_getx_recheck), clock);
    chk.clk_id = clk_id;
    chk.tp = tp;
    write_data_into_recheck_log (handle->recheckfd, &chk, sizeof(chk));
    
    return 0;
}

int recheck_clock_getres (struct recheck_handle* handle, clockid_t clk_id, struct timespec* tp, int clock_id_tainted, u_long clock) {
    struct clock_getx_recheck chk;
    struct klog_result* res = skip_to_syscall (handle, SYS_clock_getres);

    check_one_reg_argument ("clock_getres", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_clock_getres, res->retval, sizeof(struct clock_getx_recheck), clock);
    chk.clk_id = clk_id;
    chk.tp = tp;
    chk.clock_id_tainted = clock_id_tainted;
    write_data_into_recheck_log (handle->recheckfd, &chk, sizeof(chk));
    
    return 0;
}

int recheck_time (struct recheck_handle* handle, time_t* t, u_long clock) 
{
    struct time_recheck chk;
    struct klog_result* res = skip_to_syscall (handle, SYS_time);

    check_reg_arguments ("time", 1);

    write_header_into_recheck_log (handle->recheckfd, SYS_time, res->retval, sizeof(struct time_recheck), clock);
    chk.t = t;
    write_data_into_recheck_log (handle->recheckfd, &chk, sizeof(chk));
    
    return 0;
}

int recheck_prlimit64 (struct recheck_handle* handle, pid_t pid, int resource, struct rlimit64* new_limit, struct rlimit64* old_limit, u_long clock)
{
    struct prlimit64_recheck pchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_prlimit64);

    check_reg_arguments ("prlimit64", 4);
    if (new_limit && is_mem_arg_tainted ((u_long) new_limit, sizeof(struct rlimit64))) fprintf (stderr, "[ERROR] prlimit64 new_limit is tainted\n");

    write_header_into_recheck_log (handle->recheckfd, SYS_prlimit64, res->retval, sizeof (struct prlimit64_recheck), clock);
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

int recheck_setpgid (struct recheck_handle* handle, pid_t pid, pid_t pgid, int is_pid_tainted, int is_pgid_tainted, u_long clock)
{
    struct setpgid_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_setpgid);

    write_header_into_recheck_log (handle->recheckfd, SYS_setpgid, res->retval, sizeof (struct setpgid_recheck), clock);
    schk.pid = pid;
    schk.pgid = pgid;
    schk.is_pid_tainted = is_pid_tainted;
    schk.is_pgid_tainted = is_pgid_tainted;
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));

    return 0;
}

int recheck_readlink (struct recheck_handle* handle, char* path, char* buf, size_t bufsiz, u_long clock)
{
    struct readlink_recheck rchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_readlink);

    check_reg_arguments ("readlink", 3);
    if (is_mem_arg_tainted ((u_long) path, strlen(path)+1)) fprintf (stderr, "[ERROR] readlink path is tainted\n");

    u_long size = sizeof(readlink_recheck) + strlen(path) + 1;
    if (res->retval > 0) size += res->retval;
    write_header_into_recheck_log (handle->recheckfd, SYS_readlink, res->retval, size, clock);
    rchk.buf = buf;
    rchk.bufsiz = bufsiz;
    write_data_into_recheck_log (handle->recheckfd, &rchk, sizeof(rchk));
    if (res->retval > 0) write_data_into_recheck_log (handle->recheckfd, res->retparams, res->retval);
    write_data_into_recheck_log (handle->recheckfd, path, strlen(path)+1);

    return 0;
}

int recheck_socket (struct recheck_handle* handle, int domain, int type, int protocol, u_long clock)
{
    struct socket_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);

    check_reg_arguments ("socket", 4);

    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, sizeof (struct socket_recheck), clock);
    schk.domain = domain;
    schk.type = type;
    schk.protocol = protocol;
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));

    return 0;
}

int recheck_setsockopt (struct recheck_handle* handle, int sockfd, int level, int optname, const void* optval, socklen_t optlen, u_long clock)
{
    struct setsockopt_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);

    check_reg_arguments ("setsockopt", 5);

    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, sizeof (struct setsockopt_recheck), clock);
    schk.sockfd = sockfd;
    schk.level = level;
    schk.optname = optname;
    // Some values appear to be passed by reference, but the replay system is broken for these anyway...  so need global fix to support
    schk.optval = optval;
    schk.optlen = optlen;
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));

    return 0;
}

int recheck_connect_or_bind (struct recheck_handle* handle, int sockfd, struct sockaddr* addr, socklen_t addrlen, u_long clock)
{
    struct connect_recheck cchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);

    check_reg_arguments ("connect/bind", 4);
    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, sizeof (struct connect_recheck)+2*addrlen, clock);
    cchk.sockfd = sockfd;
    cchk.addr = addr;
    cchk.addrlen = addrlen;
    write_data_into_recheck_log (handle->recheckfd, &cchk, sizeof(cchk));
    write_taintmask_into_recheck_log (handle, (u_long ) addr, addrlen);

    return 0;
}

int recheck_getsockname (struct recheck_handle* handle, int sockfd, struct sockaddr* addr, socklen_t* addrlen, u_long clock)
{
    struct getsockname_recheck pchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);

    check_reg_arguments ("getsockname", 3);
    if (is_mem_arg_tainted ((u_long) addrlen, sizeof(socklen_t))) fprintf (stderr, "[ERROR] getsockname addrlen is tainted\n");
    
    if (res->retval >= 0) {
	pchk.arglen = *(int *) ((char *)res->retparams+sizeof(int));
	printf ("getsockname: arglen is %lu\n", pchk.arglen);
    } else {
	pchk.arglen = 0;
	printf ("getsockname: arglen is 0 as rc is %ld", res->retval);
    }
    u_long size = sizeof(getsockname_recheck) + pchk.arglen;
	    
    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, size, clock);
    pchk.sockfd = sockfd;
    pchk.addr = addr;
    pchk.addrlen = addrlen;
    pchk.addrlenval = *addrlen;
    write_data_into_recheck_log (handle->recheckfd, &pchk, sizeof(pchk));
    if (pchk.arglen > 0) write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams+sizeof(int)+sizeof(int), pchk.arglen);

    return pchk.arglen;
}

int recheck_getpeername (struct recheck_handle* handle, int sockfd, struct sockaddr* addr, socklen_t* addrlen, u_long clock)
{
    struct getpeername_recheck pchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_socketcall);

    check_reg_arguments ("getpeername", 3);
    if (is_mem_arg_tainted ((u_long) addrlen, sizeof(socklen_t))) fprintf (stderr, "[ERROR] getpeername addrlen is tainted\n");
    
    if (res->retval >= 0) {
	pchk.arglen = *(int *) ((char *)res->retparams+sizeof(int));
	printf ("getpeername: arglen is %lu\n", pchk.arglen);
    } else {
	pchk.arglen = 0;
	printf ("getpeername: arglen is 0 as rc is %ld", res->retval);
    }
    u_long size = sizeof(getpeername_recheck) + pchk.arglen;
	    
    write_header_into_recheck_log (handle->recheckfd, SYS_socketcall, res->retval, size, clock);
    pchk.sockfd = sockfd;
    pchk.addr = addr;
    pchk.addrlen = addrlen;
    pchk.addrlenval = *addrlen;
    write_data_into_recheck_log (handle->recheckfd, &pchk, sizeof(pchk));
    if (pchk.arglen > 0) write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams+sizeof(int)+sizeof(int), pchk.arglen);

    return pchk.arglen;
}

int recheck_getpid (struct recheck_handle* handle, u_long clock)
{
    struct klog_result *res = skip_to_syscall (handle, SYS_getpid);
    write_header_into_recheck_log (handle->recheckfd, SYS_getpid, res->retval, 0, clock);

    return 0;
}

int recheck_gettid (struct recheck_handle* handle, u_long clock)
{
    struct klog_result *res = skip_to_syscall (handle, SYS_gettid);
    write_header_into_recheck_log (handle->recheckfd, SYS_gettid, res->retval, 0, clock);

    return 0;
}

int recheck_getpgrp (struct recheck_handle* handle, u_long clock)
{
    struct klog_result *res = skip_to_syscall (handle, SYS_getpgrp);
    write_header_into_recheck_log (handle->recheckfd, SYS_getpgrp, res->retval, 0, clock);

    return 0;
}

int recheck_getuid32 (struct recheck_handle* handle, u_long clock)
{
    struct klog_result *res = skip_to_syscall (handle, SYS_getuid32);
    write_header_into_recheck_log (handle->recheckfd, SYS_getuid32, res->retval, 0, clock);

    return 0;
}

int recheck_geteuid32 (struct recheck_handle* handle, u_long clock)
{
    struct klog_result *res = skip_to_syscall (handle, SYS_geteuid32);
    write_header_into_recheck_log (handle->recheckfd, SYS_geteuid32, res->retval, 0, clock);

    return 0;
}

int recheck_getgid32 (struct recheck_handle* handle, u_long clock)
{
    struct klog_result *res = skip_to_syscall (handle, SYS_getgid32);
    write_header_into_recheck_log (handle->recheckfd, SYS_getgid32, res->retval, 0, clock);

    return 0;
}

int recheck_getegid32 (struct recheck_handle* handle, u_long clock)
{
    struct klog_result *res = skip_to_syscall (handle, SYS_getegid32);
    write_header_into_recheck_log (handle->recheckfd, SYS_getegid32, res->retval, 0, clock);

    return 0;
}

int recheck_getresuid (struct recheck_handle* handle, uid_t* ruid, uid_t* euid, uid_t* suid, u_long clock)
{
    struct getresuid_recheck gchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_getresuid32);

    check_reg_arguments ("getresuid", 3);

    write_header_into_recheck_log (handle->recheckfd, SYS_getresuid32, res->retval, sizeof(gchk), clock);
    gchk.ruid = ruid;
    gchk.euid = euid;
    gchk.suid = suid;
    gchk.ruidval = *((uid_t *) res->retparams);
    gchk.euidval = *(((uid_t *) res->retparams)+1);
    gchk.suidval = *(((uid_t *) res->retparams)+2);
    write_data_into_recheck_log (handle->recheckfd, &gchk, sizeof(gchk));

    return 0;
}

int recheck_getresgid (struct recheck_handle* handle, gid_t* rgid, gid_t* egid, gid_t* sgid, u_long clock)
{
    struct getresgid_recheck gchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_getresgid32);

    check_reg_arguments ("getresgid", 3);

    write_header_into_recheck_log (handle->recheckfd, SYS_getresgid32, res->retval, sizeof(gchk), clock);
    gchk.rgid = rgid;
    gchk.egid = egid;
    gchk.sgid = sgid;
    gchk.rgidval = *((gid_t *) res->retparams);
    gchk.egidval = *(((gid_t *) res->retparams)+1);
    gchk.sgidval = *(((gid_t *) res->retparams)+2);
    write_data_into_recheck_log (handle->recheckfd, &gchk, sizeof(gchk));

    return 0;
}

int recheck_llseek (struct recheck_handle* handle, u_int fd, u_long offset_high, u_long offset_low, loff_t* result, u_int whence, u_long clock)
{
    struct llseek_recheck rchk;
    struct klog_result *res = skip_to_syscall (handle, SYS__llseek);

    check_reg_arguments ("llseek", 5);

    write_header_into_recheck_log (handle->recheckfd, SYS__llseek, res->retval, sizeof(rchk), clock);
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

#define TERMIOS_SIZE 36 /* Not sure how to get this reliably */

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
    case TCXONC:
	dir = _IOC_READ;
	size = 0;
	break;
    case FIONBIO:
    case FIOASYNC:
	/*case FIBMAP:*/
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
    case TIOCGLCKTRMIOS:
	dir = _IOC_WRITE;
	size = TERMIOS_SIZE;
	break;
    case TCSETA:
    case TCSETS:
    case TCSETAW:
    case TCSETAF:
    case TCSETSW:
    case TCSETSF:
    case TIOCSLCKTRMIOS:
	dir = _IOC_READ;
	size = TERMIOS_SIZE;
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
#if 0
    case TIOCGICOUNT:
	dir = _IOC_WRITE;
	size = sizeof(struct serial_icounter_struct);
	break;
#endif
    default:
	/* Generic */
	fprintf (stderr, "[WARNING] Recording generic ioctl cmd %x\n", cmd);
	dir  = _IOC_DIR(cmd);
	size = _IOC_SIZE(cmd);
	if (dir == _IOC_NONE || size == 0) {
	    fprintf (stderr, "[ERROR] Generic IOCTL cmd %x has no data! This probably needs special handling!\n", cmd);
	    dir = _IOC_NONE;
	    size = 0;
	}
	break;
    }
    *pdir = dir;
    *psize = size;
}

int recheck_ioctl (struct recheck_handle* handle, u_int fd, u_int cmd, char* arg, u_long clock)
{
    struct ioctl_recheck ichk;
    struct klog_result *res = skip_to_syscall (handle, SYS_ioctl);

    check_reg_arguments ("ioctl", 3);

    /* I would trust the kernel size here */
    decode_ioctl (cmd, &ichk.dir, &ichk.size);
    if (ichk.dir == _IOC_WRITE) {
      write_header_into_recheck_log (handle->recheckfd, SYS_ioctl, res->retval, sizeof(ichk)+res->retparams_size-sizeof(u_long), clock);
    } else if (ichk.dir == _IOC_READ) {
      write_header_into_recheck_log (handle->recheckfd, SYS_ioctl, res->retval, sizeof(ichk)+2*(ichk.size), clock);
    }
    ichk.fd = fd;
    ichk.cmd = cmd;
    ichk.arg = arg;
    if (res->retparams_size > 0) {
	ichk.arglen = *((u_long *) res->retparams);
    } else {
	ichk.arglen = 0;
    }
    write_data_into_recheck_log (handle->recheckfd, &ichk, sizeof(ichk));
    if (ichk.dir == _IOC_WRITE && ichk.arglen > 0) {
	write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams+sizeof(u_long), ichk.arglen);
    }
    if (ichk.dir == _IOC_READ && ichk.size > 0) {
	write_taintmask_into_recheck_log (handle, (u_long) arg, ichk.size);
    }
    return ichk.arglen;
}

int recheck_getdents (struct recheck_handle* handle, u_int fd, char* buf, int count, u_long clock)
{
    struct getdents64_recheck gchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_getdents);

    check_reg_arguments ("getdents", 3);

    write_header_into_recheck_log (handle->recheckfd, SYS_getdents, res->retval, sizeof(gchk)+res->retparams_size, clock);
    gchk.fd = fd;
    gchk.buf = buf;
    gchk.count = count;
    gchk.arglen = res->retparams_size;
    write_data_into_recheck_log (handle->recheckfd, &gchk, sizeof(gchk));
    if (gchk.arglen > 0) {
	write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams, gchk.arglen);
    }

    return 0;
}

int recheck_getdents64 (struct recheck_handle* handle, u_int fd, char* buf, int count, u_long clock)
{
    struct getdents64_recheck gchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_getdents64);

    check_reg_arguments ("getdents64", 3);

    write_header_into_recheck_log (handle->recheckfd, SYS_getdents64, res->retval, sizeof(gchk)+res->retparams_size, clock);
    gchk.fd = fd;
    gchk.buf = buf;
    gchk.count = count;
    gchk.arglen = res->retparams_size;
    write_data_into_recheck_log (handle->recheckfd, &gchk, sizeof(gchk));
    if (gchk.arglen > 0) {
	write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams, gchk.arglen);
    }

    return 0;
}

int recheck_eventfd2 (struct recheck_handle* handle, u_int count, int flags, u_long clock)
{
    struct eventfd2_recheck echk;
    struct klog_result *res = skip_to_syscall (handle, SYS_eventfd2);

    check_reg_arguments ("eventfd2", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_eventfd2, res->retval, sizeof(echk), clock);
    echk.count = count;
    echk.flags = flags;
    write_data_into_recheck_log (handle->recheckfd, &echk, sizeof(echk));

    return 0;
}

int recheck_poll (struct recheck_handle* handle, struct pollfd* fds, u_int nfds, int timeout, u_long clock)
{
    struct poll_recheck pchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_poll);

    check_reg_arguments ("poll", 2);

    u_long size = sizeof(pchk) + nfds*sizeof(struct pollfd);
    if (res->retval > 0) size += nfds*sizeof(short);
    write_header_into_recheck_log (handle->recheckfd, SYS_poll, res->retval, size, clock);
    pchk.nfds = nfds;
    pchk.timeout = timeout;
    pchk.is_timeout_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_EDX, 4, 0);
    pchk.buf = (char *) fds;
    write_data_into_recheck_log (handle->recheckfd, &pchk, sizeof(pchk));
    if (nfds > 0) {
	if (is_mem_arg_tainted ((u_long) fds, nfds*sizeof(struct pollfd))) fprintf (stderr, "[ERROR] poll fds are tainted\n");
	write_data_into_recheck_log (handle->recheckfd, pchk.buf, nfds*sizeof(struct pollfd));
	if (res->retval > 0) {
	    assert ((u_long) res->retparams_size == sizeof(u_long) + nfds*sizeof(short));
	    write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams+sizeof(u_long), nfds*sizeof(short));
	}
    }

    return 0;
}

int recheck__newselect (struct recheck_handle* handle, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout, u_long clock)
{
    struct newselect_recheck nschk;
    struct klog_result *res = skip_to_syscall (handle, SYS__newselect);

    u_long numsets = (readfds != NULL) + (writefds != NULL) + (exceptfds != NULL);
    nschk.setsize = res->retparams_size-sizeof(u_long);
    if (timeout) nschk.setsize -= sizeof(struct timeval);
    if (numsets) {
	nschk.setsize /= numsets;
    } else {
	assert (nschk.setsize == 0);
    }

    nschk.nfds = nfds;
    nschk.preadfds = readfds;
    nschk.pwritefds = writefds;
    nschk.pexceptfds = exceptfds;
    nschk.ptimeout = timeout;
    if (nschk.setsize) {
	if (readfds) memcpy (&nschk.readfds, readfds, nschk.setsize);
	if (writefds) memcpy (&nschk.readfds, readfds, nschk.setsize);
	if (exceptfds) memcpy (&nschk.readfds, readfds, nschk.setsize);
    }
    nschk.retlen = res->retparams_size-sizeof(u_long);

    /* Check if arguments are tainted */
    if (readfds && is_mem_arg_tainted ((u_long) readfds, nschk.setsize)) fprintf (stderr, "[ERROR] select: readfds tainted\n");
    if (writefds && is_mem_arg_tainted ((u_long) writefds, nschk.setsize)) fprintf (stderr, "[ERROR] select: writefds tainted\n");
    if (exceptfds && is_mem_arg_tainted ((u_long) exceptfds, nschk.setsize)) fprintf (stderr, "[ERROR] select: exceptfds tainted\n");
    if (timeout) {
	nschk.is_timeout_tainted = is_mem_arg_tainted ((u_long) timeout, sizeof(struct timeval));
	memcpy (&nschk.timeout, timeout, sizeof(struct timeval));
	if (nschk.is_timeout_tainted == 2) fprintf (stderr, "[ERROR] select: timeout partially tainted\n");
    }
	
    check_reg_arguments ("_newselect", 5);

    write_header_into_recheck_log (handle->recheckfd, SYS__newselect, res->retval, sizeof(nschk)+nschk.retlen, clock);
    write_data_into_recheck_log (handle->recheckfd, &nschk, sizeof(nschk));
    write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams+sizeof(u_long), nschk.retlen);

    return 0;
}

int recheck_set_robust_list (struct recheck_handle* handle, struct robust_list_head* head, size_t len, u_long clock)
{
    struct set_robust_list_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_set_robust_list);

    check_reg_arguments ("set_robut_list", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_set_robust_list, res->retval, sizeof(schk), clock);
    schk.head = head;
    schk.len = len;
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));

    return 0;
}

int recheck_set_tid_address (struct recheck_handle* handle, int* tidptr, u_long clock)
{
    struct set_tid_address_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_set_tid_address);

    check_reg_arguments ("set_tid_address", 1);

    write_header_into_recheck_log (handle->recheckfd, SYS_set_tid_address, res->retval, sizeof(schk), clock);
    schk.tidptr = tidptr;
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));

    return 0;
}

int recheck_rt_sigaction (struct recheck_handle* handle, int sig, const struct sigaction* act, struct sigaction* oact, size_t sigsetsize, u_long clock)
{
    struct rt_sigaction_recheck sachk;
    struct klog_result *res = skip_to_syscall (handle, SYS_rt_sigaction);
    u_long size = sizeof(sachk);

    check_reg_arguments ("rt_sigaction", 3);
    if (act && is_mem_arg_tainted ((u_long) act, 20)) fprintf (stderr, "[ERROR] rt_sigaction input structure is tainted\n");

    if (act) size += 20;
    write_header_into_recheck_log (handle->recheckfd, SYS_rt_sigaction, res->retval, size, clock);

    sachk.sig = sig;
    sachk.act = act;
    sachk.oact = oact;
    sachk.sigsetsize = sigsetsize;
    write_data_into_recheck_log (handle->recheckfd, &sachk, sizeof(sachk));
    if (act) write_data_into_recheck_log (handle->recheckfd, act, 20);

    return 0;
}

int recheck_rt_sigprocmask (struct recheck_handle* handle, int how, sigset_t* set, sigset_t* oset, size_t sigsetsize, u_long clock)
{
    struct rt_sigprocmask_recheck spchk;
    struct klog_result *res = skip_to_syscall (handle, SYS_rt_sigprocmask);
    u_long size = sizeof(spchk);

    check_reg_arguments ("rt_sigprocmask", 3);
    if (set && is_mem_arg_tainted ((u_long) set, sigsetsize)) fprintf (stderr, "[ERROR] rt_sigprocmask input structure is tainted\n");

    if (set) size += sigsetsize;
    if (oset) size += sigsetsize;
    write_header_into_recheck_log (handle->recheckfd, SYS_rt_sigprocmask, res->retval, size, clock);

    spchk.how = how;
    spchk.set = set;
    spchk.oset = oset;
    spchk.sigsetsize = sigsetsize;
    write_data_into_recheck_log (handle->recheckfd, &spchk, sizeof(spchk));
    if (set) write_data_into_recheck_log (handle->recheckfd, set, sigsetsize);
    if (res->retparams_size > 0) write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams+sizeof(u_long), sigsetsize);

    return 0;
}

int recheck_mkdir (struct recheck_handle* handle, char* pathname, int mode, u_long clock)
{
    struct mkdir_recheck chk;
    struct klog_result* res = skip_to_syscall (handle, SYS_mkdir);

    check_reg_arguments ("mkdir", 2);
    if (is_mem_arg_tainted ((u_long) pathname, strlen (pathname) + 1))
            fprintf (stderr, "[ERROR] mkdir pathname is tainted\n");

    write_header_into_recheck_log (handle->recheckfd, SYS_mkdir, res->retval, sizeof(struct mkdir_recheck) + strlen(pathname) + 1, clock);
    chk.mode = mode;
    write_data_into_recheck_log (handle->recheckfd, &chk, sizeof(chk));
    write_data_into_recheck_log (handle->recheckfd, pathname, strlen(pathname) + 1);

    return 0;
}

int recheck_unlink (struct recheck_handle* handle, char* pathname, u_long clock)
{
    struct unlink_recheck uchk;
    struct klog_result* res = skip_to_syscall (handle, SYS_unlink);

    check_reg_arguments ("unlink", 1);
    if (is_mem_arg_tainted ((u_long) pathname, strlen (pathname) + 1)) fprintf (stderr, "[ERROR] unlink pathname is tainted: %s\n", pathname);

    write_header_into_recheck_log (handle->recheckfd, SYS_unlink, res->retval, sizeof(struct unlink_recheck) + strlen(pathname)+1, clock);
    uchk.pathname = pathname;
    write_data_into_recheck_log (handle->recheckfd, &uchk, sizeof(uchk));
    write_data_into_recheck_log (handle->recheckfd, pathname, strlen(pathname) + 1);

    return 0;
}

int recheck_chmod (struct recheck_handle* handle, char* pathname, mode_t mode, u_long clock)
{
    struct chmod_recheck cchk;
    struct klog_result* res = skip_to_syscall (handle, SYS_chmod);

    check_reg_arguments ("chmod", 2);
    if (is_mem_arg_tainted ((u_long) pathname, strlen (pathname) + 1)) fprintf (stderr, "[ERROR] chmod pathname is tainted: %s\n", pathname);

    write_header_into_recheck_log (handle->recheckfd, SYS_chmod, res->retval, sizeof(struct chmod_recheck) + strlen(pathname)+1, clock);
    cchk.pathname = pathname;
    cchk.mode = mode;
    write_data_into_recheck_log (handle->recheckfd, &cchk, sizeof(cchk));
    write_data_into_recheck_log (handle->recheckfd, pathname, strlen(pathname) + 1);

    return 0;
}

int recheck_inotify_init1 (struct recheck_handle* handle, int flags, u_long clock)
{
    struct inotify_init1_recheck ichk;
    struct klog_result* res = skip_to_syscall (handle, SYS_inotify_init1);

    check_reg_arguments ("inotify_init1", 1);
    write_header_into_recheck_log (handle->recheckfd, SYS_inotify_init1, res->retval, sizeof(struct inotify_init1_recheck), clock);
    ichk.flags = flags;
    write_data_into_recheck_log (handle->recheckfd, &ichk, sizeof(ichk));

    return 0;
}

int recheck_inotify_add_watch (struct recheck_handle* handle, int fd, char* pathname, uint32_t mask, u_long clock)
{
    struct inotify_add_watch_recheck ichk;
    struct klog_result* res = skip_to_syscall (handle, SYS_inotify_add_watch);

    check_reg_arguments ("inotify_add_watch", 2);
    if (is_mem_arg_tainted ((u_long) pathname, strlen (pathname) + 1)) fprintf (stderr, "[ERROR] inotify_add_watch pathname is tainted\n");

    write_header_into_recheck_log (handle->recheckfd, SYS_inotify_add_watch, res->retval, 
				   sizeof(struct inotify_add_watch_recheck) + strlen(pathname)+1, clock);
    ichk.fd = fd;
    ichk.pathname = pathname;
    ichk.mask = mask;
    write_data_into_recheck_log (handle->recheckfd, &ichk, sizeof(ichk));
    write_data_into_recheck_log (handle->recheckfd, pathname, strlen(pathname) + 1);

    return 0;
}

int recheck_sched_getaffinity (struct recheck_handle* handle, pid_t pid, size_t cpusetsize, cpu_set_t* mask, int is_pid_tainted, u_long clock)
{
    struct sched_getaffinity_recheck schk;
    struct klog_result *res = skip_to_syscall (handle, SYS_sched_getaffinity);

    check_one_reg_argument ("sched_getaffinity", 2);
    check_one_reg_argument ("sched_getaffinity", 3);
    write_header_into_recheck_log (handle->recheckfd, SYS_sched_getaffinity, res->retval, sizeof (struct sched_getaffinity_recheck) + cpusetsize, clock);
    schk.pid = pid;
    schk.is_pid_tainted = is_pid_tainted;
    schk.cpusetsize = cpusetsize;
    write_data_into_recheck_log (handle->recheckfd, &schk, sizeof(schk));
    write_data_into_recheck_log (handle->recheckfd, mask, cpusetsize);

    return 0;
}

int recheck_ftruncate (struct recheck_handle* handle, u_int fd, u_long length, u_long clock)
{
    struct ftruncate_recheck chk;
    struct klog_result* res = skip_to_syscall (handle, SYS_ftruncate);
    check_reg_arguments ("ftruncate", 2);

    write_header_into_recheck_log (handle->recheckfd, SYS_ftruncate, res->retval, sizeof(struct ftruncate_recheck), clock);
    chk.fd = fd;
    chk.length = length;
    write_data_into_recheck_log (handle->recheckfd, &chk, sizeof(chk));

    return 0;
}

int recheck_prctl (struct recheck_handle* handle, int option, u_long arg2, u_long arg3, u_long arg4, u_long arg5, u_long clock)
{
    struct prctl_recheck chk;
    struct klog_result* res = skip_to_syscall (handle, SYS_prctl);
    check_reg_arguments ("prctl", 5);

    switch (option) {
    case PR_GET_NAME:
    case PR_SET_NAME:
	chk.optsize = 16;
	break;
    default:
	chk.optsize = 0;
    }

    write_header_into_recheck_log (handle->recheckfd, SYS_prctl, res->retval, sizeof(struct prctl_recheck)+chk.optsize, clock);
    chk.option = option;
    chk.arg2 = arg2;
    chk.arg3 = arg3;
    chk.arg4 = arg4;
    chk.arg5 = arg5;
    write_data_into_recheck_log (handle->recheckfd, &chk, sizeof(chk));
    switch (option) {
    case PR_GET_NAME:
	write_data_into_recheck_log (handle->recheckfd, (char *)res->retparams+sizeof(u_long), 16);
	break;
    case PR_SET_NAME:
	write_data_into_recheck_log (handle->recheckfd, (char *)arg2, 16);
	break;
    }

    return 0;
}

//this function doesn't actually put anything to the slice, but just read the klog and returns the child pid
int recheck_clone (struct recheck_handle* handle, u_long clock)
{
    struct klog_result* res = skip_to_syscall (handle, SYS_clone);
    check_reg_arguments("clone", 4); // How to handle variable length arguments
    write_header_into_recheck_log (handle->recheckfd, SYS_clone, res->retval, 0, clock);
    return res->retval;
}

int recheck_shmget (struct recheck_handle* handle, key_t key, size_t size, int shmflg, u_long clock)
{
    struct shmget_recheck sgchk;
    struct klog_result* res = skip_to_syscall (handle, SYS_ipc);
    check_reg_arguments ("shmget", 4);

    write_header_into_recheck_log (handle->recheckfd, SYS_ipc, res->retval, sizeof(struct shmget_recheck), clock);
    sgchk.key = key;
    sgchk.size = size;
    sgchk.shmflg = shmflg;
    write_data_into_recheck_log (handle->recheckfd, &sgchk, sizeof(sgchk));

    return 0;
}

int recheck_shmat (struct recheck_handle* handle, int shmid, void* shmaddr, void* raddr, int shmflg, u_long clock)
{
    struct shmat_recheck sachk;
    struct klog_result* res = skip_to_syscall (handle, SYS_ipc);
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EBX, 4, 0)) fprintf (stderr, "[ERROR] register ebx (arg 1) for shmat is tainted\n");
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EDX, 4, 0)) fprintf (stderr, "[ERROR] register edx (arg 3) for shmat is tainted\n");
    if (is_reg_arg_tainted(LEVEL_BASE::REG_ESI, 4, 0)) fprintf (stderr, "[ERROR] register esi (arg 4) for shmat is tainted\n");
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EDI, 4, 0)) fprintf (stderr, "[ERROR] register edi (arg 5) for shmat is tainted\n");

    write_header_into_recheck_log (handle->recheckfd, SYS_ipc, res->retval, sizeof(struct shmat_recheck), clock);
    sachk.is_shmid_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_ECX, 4, 0);
    sachk.shmid = shmid;
    sachk.shmaddr = shmaddr;
    sachk.raddr = raddr;
    sachk.shmflg = shmflg;
    if (res->retval != -1) {
	sachk.raddrval = ((struct shmat_retvals *) res->retparams)->raddr;
    }
    if (res->retparams) {
	struct shmat_retvals* pshmat = (struct shmat_retvals *) res->retparams;
	sachk.size = pshmat->size;
	add_shared_memory (sachk.raddrval, sachk.size);
    } else {
	sachk.size = 0;
    }

    write_data_into_recheck_log (handle->recheckfd, &sachk, sizeof(sachk));

    return 0;
}

int recheck_ipc_rmid (struct recheck_handle* handle, int shmid, int cmd, u_long clock)
{
    struct ipc_rmid_recheck irchk;
    struct klog_result* res = skip_to_syscall (handle, SYS_ipc);
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EBX, 4, 0)) fprintf (stderr, "[ERROR] register ebx (arg 1) for shmat is tainted\n");
    if (is_reg_arg_tainted(LEVEL_BASE::REG_EDX, 4, 0)) fprintf (stderr, "[ERROR] register edx (arg 3) for shmat is tainted\n");

    write_header_into_recheck_log (handle->recheckfd, SYS_ipc, res->retval, sizeof(struct ipc_rmid_recheck), clock);
    irchk.is_shmid_tainted = is_reg_arg_tainted (LEVEL_BASE::REG_ECX, 4, 0);
    irchk.shmid = shmid;
    irchk.cmd = cmd;

    write_data_into_recheck_log (handle->recheckfd, &irchk, sizeof(irchk));

    return 0;
}
