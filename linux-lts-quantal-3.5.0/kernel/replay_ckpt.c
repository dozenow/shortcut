/* Kernel support for multithreaded replay - checkpoint and resume
   Jason Flinn */
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/replay.h>
#include <linux/mount.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <asm/fcntl.h>
#include <asm/ldt.h>
#include <asm/desc.h>
#include <linux/proc_fs.h>
#include <linux/replay.h>

#ifdef TIME_TRICK
#include <linux/times.h>
#include <linux/utime.h>
#endif

// No clean way to handle this that I know of...
extern int replay_debug, replay_min_debug;
#define DPRINT if(replay_debug) printk
//#define DPRINT(x,...)
#define MPRINT if(replay_debug || replay_min_debug) printk
//#define MPRINT(x,...)

#define KMALLOC kmalloc
#define KFREE kfree

// File format:
// pid
// arguments (#, followed by len/data for each
// env. values (#, followed by len/data for each

// Allocate buffer and populate it with arguments and environment data from user level
char*
copy_args (const char __user* const __user* args, const char __user* const __user* env, int* buflen)
{
	int args_cnt, args_len, env_cnt, env_len, len, i;
	const char __user *const __user *up;
	const char __user * pc;
	char* buf, *p;

	// First determine buffer size
	args_cnt = 0;
	args_len = 0;
	up = args;
	do {
		if (get_user (pc, up)) {
			printk ("replay_checkpoint_to_disk: invalid args value\n");
			return NULL;
		}
		if (pc == 0) break; // No more args
		args_cnt++;
		args_len += strnlen_user(pc, 4096) + sizeof(int);
		up++;
	} while (1);

	env_cnt = 0;
	env_len = 0;
	up = env;
	do {
		if (get_user (pc, up)) {
			printk ("copy_args: invalid env value\n");
			return NULL;
		}
		if (pc == 0) break; // No more env
		env_cnt++;
		env_len += strnlen_user(pc, 4096) + sizeof(int);
		up++;
	} while (1);
	
	// Now allocate buffer
	*buflen = 2*sizeof(int) + args_len + env_len;
	buf = KMALLOC(*buflen, GFP_KERNEL);
	if (buf == NULL) {
		printk ("copy_args: unable to allocate buffer\n");
		return NULL;
	}

	// Now populate the buffer
	p = buf;
	*((int *) p) = args_cnt;
	p += sizeof(int);

	up = args;
	for (i = 0; i < args_cnt; i++) {
		if (get_user (pc, up) || pc == 0) {
			printk ("copy_args: invalid args value\n");
			KFREE (buf);
			return NULL;
		}		
		len = strnlen_user(pc, 4096);
		*((int *) p) = len;
		p += sizeof(int);
		if (copy_from_user (p, pc, len)) {
			printk ("copy_args: can't copy argument %d\n", i);
			KFREE (buf);
			return NULL;
		}
		p += len;
		up++;
	}

	*((int *) p) = env_cnt;
	p += sizeof(int);

	up = env;
	for (i = 0; i < env_cnt; i++) {
		if (get_user (pc, up) || pc == 0) {
			printk ("copy_args: invalid env value\n");
			KFREE (buf);
			return NULL;
		}		
		len = strnlen_user(pc, 4096);
		*((int *) p) = len;
		p += sizeof(int);
		if (copy_from_user (p, pc, len)) {
			printk ("copy_args: can't copy argument %d\n", i);
			KFREE (buf);
			return NULL;
		}
		p += len;
		up++;
	}

	return buf;
}

// This function writes the process state to a disk file
long 
#ifdef TIME_TRICK
replay_checkpoint_to_disk (char* filename, char* execname, char* buf, int buflen, __u64 parent_rg_id, struct timeval *tv, struct timespec *tp)
#else
replay_checkpoint_to_disk (char* filename, char* execname, char* buf, int buflen, __u64 parent_rg_id)
#endif
{
	mm_segment_t old_fs = get_fs();
	int fd, rc, copyed, len;
	struct file* file = NULL;
	pid_t pid;
	loff_t pos = 0;
	__u64 rg_id;
	struct timespec time;

	MPRINT ("pid %d enters replay_checkpoint_to_disk: filename %s\n", current->pid, filename);

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd < 0) {
		printk ("replay_checkpoint_to_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);

	// First - write out process identifier
	pid = current->pid;
	copyed = vfs_write (file, (char *) &pid, sizeof(pid), &pos);
	if (copyed != sizeof(pid)) {
		printk ("replay_checkpoint_to_disk: tried to write pid, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Next, write out the record group identifier
	get_record_group_id(&rg_id);
	MPRINT ("Pid %d get record group id %llu\n", current->pid, rg_id);
	copyed = vfs_write (file, (char *) &rg_id, sizeof(rg_id), &pos);
	if (copyed != sizeof(rg_id)) {
		printk ("replay_checkpoint_to_disk: tried to write rg_id, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Next, record the parent group identifier
	MPRINT ("Pid %d parent record group id %llu\n", current->pid, parent_rg_id);
	copyed = vfs_write (file, (char *) &parent_rg_id, sizeof(rg_id), &pos);
	if (copyed != sizeof(parent_rg_id)) {
		printk ("replay_checkpoint_to_disk: tried to write parent_rg_id, got %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Next, write out exec name
	len = strlen_user(execname);
	copyed = vfs_write (file, (char *) &len, sizeof(len), &pos);
	if (copyed != sizeof(len)) {
		printk ("replay_checkpoint_to_disk: tried to write exec name len, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	copyed = vfs_write (file, execname, len, &pos);
	if (copyed != len) {
		printk ("replay_checkpoint_to_disk: tried to write exec name, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Next, write out rlimit information
	copyed = vfs_write (file, (char *) &current->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, &pos);
	if (copyed != sizeof(struct rlimit)*RLIM_NLIMITS) {
		printk ("replay_checkpoint_to_disk: tried to write rlimits, got rc %d\n", buflen);
		rc = -EFAULT;
		goto exit;
	}

	// Next, copy the signal handlers
	copyed = vfs_write (file, (char *) &current->sighand->action, sizeof(struct k_sigaction) * _NSIG, &pos);
	if (copyed != sizeof(struct k_sigaction)*_NSIG) {
		printk ("replay_checkpoint_to_disk: tried to write sighands, got rc %d\n", copyed);
		rc = -EFAULT;
		goto exit;
	}

	// Next, write out arguments to exec
	copyed = vfs_write (file, buf, buflen, &pos);
	if (copyed != buflen) {
		printk ("replay_checkpoint_to_disk: tried to write arguments, got rc %d\n", buflen);
		rc = -EFAULT;
		goto exit;
	}
	KFREE (buf);

	
#ifdef TIME_TRICK
	do_gettimeofday (tv);
	rc = sys_clock_gettime (CLOCK_MONOTONIC, tp);
	if (rc < 0) printk ("Semi-det clock for clock_gettime fails to initialize.\n");
	printk ("semi-det time inits for gettimeofday %ld, %ld, for clock_gettime: %ld, %ld.\n", tv->tv_sec, tv->tv_usec, tp->tv_sec, tp->tv_nsec);
	copyed = vfs_write (file, (char*) tv, sizeof (struct timeval), &pos);
	if (copyed != sizeof (struct timeval)) {
		printk ("replay_checkpoint_to_disk: tried to write timeval, got rc %d\n", copyed);
		rc = -EFAULT;
		goto exit;
	}
	copyed = vfs_write (file, (char*) tp, sizeof (struct timespec), &pos);
	if (copyed != sizeof (struct timespec)) {
		printk ("replay_checkpoint_to_disk: tried to write timespec, got rc %d\n", copyed);
		rc = -EFAULT;
		goto exit;
	}

#endif

	// Next, the time the recording started.
	time = CURRENT_TIME;
	copyed = vfs_write (file, (char *) &time, sizeof(time), &pos);
	if (copyed != sizeof(time)) {
		printk ("replay_checkpoint_to_disk: tried to write time, got %d\n", copyed);
		rc = copyed;
		goto exit;
	}

exit:
	if (file) fput(file);
	if (fd >= 0)  {
		rc = sys_close (fd);
		if (rc < 0) printk ("replay_checkpoint_to_disk: close returns %d\n", rc);
	}
	set_fs(old_fs);
	return rc;
}
#ifdef TIME_TRICK
long replay_resume_from_disk (char* filename, char** execname, char*** argsp, char*** envp, __u64* prg_id, struct timeval* tv, struct timespec *tp) 
#else
long replay_resume_from_disk (char* filename, char** execname, char*** argsp, char*** envp, __u64* prg_id) 
#endif
{
	mm_segment_t old_fs = get_fs();
	int rc, fd, args_cnt, env_cnt, copyed, i, len;
	struct file* file = NULL;
	loff_t pos = 0;
	pid_t record_pid;
	__u64 rg_id;
	__u64 parent_rg_id;
	char** args;
	char** env;
	struct timespec time;

	MPRINT ("pid %d enters replay_resume_from_disk: filename %s\n", current->pid, filename);

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_RDONLY, 0);
	if (fd < 0) {
		printk ("replay_checkpoint_from_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);

	// Read the record pid
	copyed = vfs_read(file, (char *) &record_pid, sizeof(record_pid), &pos);
	if (copyed != sizeof(record_pid)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Next read the record group id
	copyed = vfs_read(file, (char *) &rg_id, sizeof(rg_id), &pos);
	MPRINT ("Pid %d replay_resume_from_disk: rg_id %llu\n", current->pid, rg_id);
	if (copyed != sizeof(rg_id)) {
		printk ("replay_resume_from_disk: tried to read rg_id, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	*prg_id = rg_id;

	// Next read the parent record group id
	copyed = vfs_read(file, (char *) &parent_rg_id, sizeof(parent_rg_id), &pos);
	MPRINT ("Pid %d replay_resume_from_disk: parent_rg_id %llu", current->pid, parent_rg_id);
	if (copyed != sizeof(parent_rg_id)) {
		printk ("replay_resume_from_disk: tried to read parent_rg_id got %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Next read the exec name
	copyed = vfs_read(file, (char *) &len, sizeof(len), &pos);
	if (copyed != sizeof(len)) {
		printk ("replay_resume_from_disk: tried to read execname len, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	*execname = KMALLOC (len, GFP_KERNEL);
	if (*execname == NULL) {
		printk ("replay_resume_from_disk: unable to allocate exev name of len %d\n", len);
		rc = -ENOMEM;
		goto exit;
	}
	copyed = vfs_read(file, *execname, len, &pos);
	if (copyed != len) {
		printk ("replay_resume_from_disk: tried to read execname, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	
	// Next, read the rlimit info
	copyed = vfs_read(file, (char *) &current->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, &pos);
	if (copyed != sizeof(struct rlimit)*RLIM_NLIMITS) {
		printk ("replay_resume_from_disk: tried to read rlimits, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	copyed = vfs_read(file, (char *) &current->sighand->action, sizeof(struct k_sigaction) * _NSIG, &pos);
	if (copyed != sizeof(struct k_sigaction)*_NSIG) {
		printk ("replay_resume_from_disk: tried to read sighands, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Next, read the number of arguments
	copyed = vfs_read(file, (char *) &args_cnt, sizeof(args_cnt), &pos);
	if (copyed != sizeof(args_cnt)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	MPRINT ("%d arguments in checkpoint\n", args_cnt);
	
	args = KMALLOC((args_cnt+1) * sizeof(char *), GFP_KERNEL);
	if (args == NULL) {
		printk ("replay_resume_from_disk: unable to allocate arguments\n");
		rc = -ENOMEM;
		goto exit;
	}

	// Now read in each argument
	for (i = 0; i < args_cnt; i++) {
		copyed = vfs_read(file, (char *) &len, sizeof(len), &pos);
		if (copyed != sizeof(len)) {
			printk ("replay_resume_from_disk: tried to read argument %d len, got rc %d\n", i, copyed);
			rc = copyed;
			goto exit;
		}
		args[i] = KMALLOC(len+1, GFP_KERNEL);
		if (args[i] == NULL) {
			printk ("replay_resume_froma_disk: unable to allocate argument %d\n", i);
			rc = -ENOMEM;
			goto exit;
		}
		copyed = vfs_read(file, args[i], len, &pos);
		MPRINT ("copyed %d bytes\n", copyed);
		if (copyed != len) {
			printk ("replay_resume_from_disk: tried to read argument %d, got rc %d\n", i, copyed);
			rc = copyed;
			goto exit;
		}
		args[i][len] = '\0'; // NULL terminator not in file format
		MPRINT ("Argument %d is %s\n", i, args[i]);
	}
	args[i] = NULL;

	// Next, read the number of env. objects
	copyed = vfs_read(file, (char *) &env_cnt, sizeof(env_cnt), &pos);
	if (copyed != sizeof(env_cnt)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	MPRINT ("%d env. objects in checkpoint\n", env_cnt);
	
	env = KMALLOC((env_cnt+1) * sizeof(char *), GFP_KERNEL);
	if (env == NULL) {
		printk ("replay_resume_froma_disk: unable to allocate env struct\n");
		rc = -ENOMEM;
		goto exit;
	}

	// Now read in each env. object
	for (i = 0; i < env_cnt; i++) {
		copyed = vfs_read(file, (char *) &len, sizeof(len), &pos);
		if (copyed != sizeof(len)) {
			printk ("replay_resume_from_disk: tried to read env. %d len, got rc %d\n", i, copyed);
			rc = copyed;
			goto exit;
		}
		env[i] = KMALLOC(len+1, GFP_KERNEL);
		if (env[i] == NULL) {
			printk ("replay_resume_froma_disk: unable to allocate env. %d\n", i);
			rc = -ENOMEM;
			goto exit;
		}
		copyed = vfs_read(file, env[i], len, &pos);
		if (copyed != len) {
			printk ("replay_resume_from_disk: tried to read env. %d, got rc %d\n", i, copyed);
			rc = copyed;
			goto exit;
		}
		env[i][len] = '\0'; // NULL terminator not in file format
		MPRINT ("Env. %d is %s\n", i, env[i]);
	}
	env[i] = NULL;

	*argsp = args;
	*envp = env;
	
	#ifdef TIME_TRICK
	copyed = vfs_read(file, (char*) tv, sizeof(struct timeval), &pos);
	if (copyed != sizeof(struct timeval)) {
		printk ("replay_resume_from_disk: tried to read timeval. %d len, got rc %d\n", sizeof(struct timeval), copyed);
		rc = copyed;
		goto exit;
	}
	copyed = vfs_read(file, (char*) tp, sizeof(struct timespec), &pos);
	if (copyed != sizeof(struct timespec)) {
		printk ("replay_resume_from_disk: tried to read timespec. %d len, got rc %d\n", sizeof(struct timespec), copyed);
		rc = copyed;
		goto exit;
	}
	printk ("semi-det time inits for gettimeofday: %ld, %ld, for clock_gettime: %ld, %ld.\n", tv->tv_sec, tv->tv_usec, tp->tv_sec, tp->tv_nsec);

#endif

	// Next read the time
	copyed = vfs_read(file, (char *) &time, sizeof(time), &pos);
	if (copyed != sizeof(time)) {
		printk ("replay_resume_from_disk: tried to read time, got %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	MPRINT ("replay_resume_from_disk done\n");

exit:
	if (fd >= 0) {
		rc = sys_close (fd);
		if (rc < 0) printk ("replay_resume_from_disk: close returns %d\n", rc);
	}
	if (file) fput(file);
	set_fs(old_fs);
	if (rc < 0) return rc;
	return record_pid;
}

