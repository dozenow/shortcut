/* Kernel support for multithreaded replay - checkpoint and resume
   Jason Flinn */
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/replay.h>
#include <linux/mount.h>
#include <linux/delay.h>
#include <linux/shm.h>
#include <linux/ds_list.h>
#include <linux/btree.h>
#include <asm/uaccess.h>
#include <asm/fcntl.h>
#include <asm/ldt.h>
#include <asm/desc.h>
#include <asm/ptrace.h>
#include <asm/elf.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/fpu-internal.h>
#include <linux/proc_fs.h>
#include <linux/replay.h>
#include <linux/replay_maps.h>
#include <linux/stat.h>
#include <linux/times.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/futex.h>
#include <crypto/sha.h>

#include <linux/replay_configs.h>

// No clean way to handle this that I know of...
extern int replay_debug, replay_min_debug;
#define DPRINT if(replay_debug) printk
#define MPRINT if(replay_debug || replay_min_debug) printk

#define KMALLOC kmalloc
#define KFREE kfree

#define WRITABLE_MMAPS "/run/shm/replay_mmap_%d"
#define WRITABLE_MMAPS_LEN 21
//#define WRITABLE_MMAPS_LEN 17
//#define WRITABLE_MMAPS "/tmp/replay_mmap_%d"
//print timings
#define PRINT_TIME 1
//#define JAVA_FIX_PTHREAD

/* Prototypes not in header files */
void set_tls_desc(struct task_struct *p, int idx, const struct user_desc *info, int n); /* In tls.c */
void fill_user_desc(struct user_desc *info, int idx, const struct desc_struct *desc); /* In tls.c */

struct vma_stats {
	u_long vmas_start;
	u_long vmas_end;
	int    vmas_flags;
	u_long vmas_pgoff;
	char   vmas_file[PATH_MAX];
};

struct mm_info {
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;
	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */
	void* vdso;
	//exe file
#ifdef CONFIG_PROC_FS
	char exe_file[PATH_MAX];
#endif
};
//defined in replay.c
struct ckpt_tsk; 

struct ckpt_data {
	u_long proc_count;
	__u64  rg_id;
	int    clock;	
};

struct ckpt_proc_data {
	pid_t  record_pid;
	long   retval;
	loff_t logpos;
	u_long outptr;
	u_long consumed;
	u_long expclock;
	u_long pthreadclock;
	u_long p_ignore_flag; //this is really just a memory address w/in the vma
	u_long p_user_log_addr;
	u_long user_log_pos;
	u_long p_clear_child_tid;
	u_long p_replay_hook;
//	u_long rss_stat_counts[NR_MM_COUNTERS]; //the counters from the checkpointed task
};

struct recheck_entry {
	int sysnum;
	int flag;
	long retval;
	int len;
};

extern int slice_dump_vm;
extern int pause_after_slice;

void dump_reg_struct (struct pt_regs* r) {
	MPRINT ("eax %lx, ebx %lx, ecx %lx, edx %lx, esi %lx, edi %lx, ebp %lx, esp %lx, ds %lx, es %lx, fs %lx, gs %lx, orig_eax %lx, ip %lx, cs %lx, flags %lx, ss %lx\n",
		r->ax, r->bx, r->cx, r->dx, r->si, r->di, r->bp, r->sp, r->ds, r->es, r->fs, r->gs, r->orig_ax, r->ip, r->cs, r->flags, r->ss);
}

static void
print_vmas (struct task_struct* tsk)
{
	struct vm_area_struct* mpnt;
	char buf[256];

	printk ("vmas for task %d mm %p\n", tsk->pid, tsk->mm);
	down_read (&tsk->mm->mmap_sem);
	for (mpnt = tsk->mm->mmap; mpnt; mpnt = mpnt->vm_next) {
		printk ("VMA start %lx end %lx", mpnt->vm_start, mpnt->vm_end);
		if (mpnt->vm_flags & VM_MAYSHARE) {
			printk (" s ");
		} else {
			printk (" p ");
		}
		if (mpnt->vm_file) {
			printk (" file %s ", dentry_path (mpnt->vm_file->f_dentry, buf, sizeof(buf)));
                }
                if (mpnt->vm_flags & VM_READ) {
                    printk ("r");
                } else {
                    printk ("-");
                }
                if (mpnt->vm_flags & VM_WRITE) {
                    printk ("w");
                } else {
                    printk ("-");
                }
                if (mpnt->vm_flags & VM_EXEC) {
                    printk ("x");
                } else {
                    printk ("-");
                }
                printk ("\n");
	}
	up_read (&tsk->mm->mmap_sem);
}

void print_fpu_state(struct fpu *f, pid_t record_pid) 
{
	//first byte and last byte of the thread_xstate in the struct fpu
	unsigned char *c = (unsigned char *)f->state;
	unsigned char *last = c + xstate_size; 

	printk("%d fpu state:\n", record_pid);
	printk("\tlast_cpu %u\n",f->last_cpu);
	printk("\thas_fpu %u\n",f->has_fpu);
	while (c < last) { 
		printk("%02x ",*c);
		c++;
	} 
	printk("\n");
}

inline int is_memory_zero (void* start, void* end)
{
	char empty[4096];
	int is_zero = 1;

	BUG_ON (end-start < 4096); 
	memset (empty, 0, 4096);
	while (start < end) { 
		if (memcmp (start, empty, 4096)) { 
			is_zero = 0;
			break;
		}
		start += 4096;
	}
	return is_zero;
}

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
	if (env != NULL) { 
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

	}
	
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
replay_checkpoint_to_disk (char* filename, char* execname, char* buf, int buflen, __u64 parent_rg_id)
{
	mm_segment_t old_fs = get_fs();
	int fd, rc, copied, len;
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
	copied = vfs_write (file, (char *) &pid, sizeof(pid), &pos);
	if (copied != sizeof(pid)) {
		printk ("replay_checkpoint_to_disk: tried to write pid, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, write out the record group identifier
	get_record_group_id(&rg_id);
	MPRINT ("Pid %d get record group id %llu\n", current->pid, rg_id);
	copied = vfs_write (file, (char *) &rg_id, sizeof(rg_id), &pos);
	if (copied != sizeof(rg_id)) {
		printk ("replay_checkpoint_to_disk: tried to write rg_id, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, record the parent group identifier
	MPRINT ("Pid %d parent record group id %llu\n", current->pid, parent_rg_id);
	copied = vfs_write (file, (char *) &parent_rg_id, sizeof(rg_id), &pos);
	if (copied != sizeof(parent_rg_id)) {
		printk ("replay_checkpoint_to_disk: tried to write parent_rg_id, got %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, write out exec name
	len = strlen_user(execname);
	copied = vfs_write (file, (char *) &len, sizeof(len), &pos);
	if (copied != sizeof(len)) {
		printk ("replay_checkpoint_to_disk: tried to write exec name len, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	copied = vfs_write (file, execname, len, &pos);
	if (copied != len) {
		printk ("replay_checkpoint_to_disk: tried to write exec name, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, write out rlimit information
	copied = vfs_write (file, (char *) &current->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, &pos);
	if (copied != sizeof(struct rlimit)*RLIM_NLIMITS) {
		printk ("replay_checkpoint_to_disk: tried to write rlimits, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}

	// Next, copy the signal handlers
	copied = vfs_write (file, (char *) &current->sighand->action, sizeof(struct k_sigaction) * _NSIG, &pos);
	if (copied != sizeof(struct k_sigaction)*_NSIG) {
		printk ("replay_checkpoint_to_disk: tried to write sighands, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}

	// Next, write out arguments to exec
	copied = vfs_write (file, buf, buflen, &pos);
	if (copied != buflen) {
		printk ("replay_checkpoint_to_disk: tried to write arguments, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}
	KFREE (buf);

	// Next, the time the recording started.
	time = CURRENT_TIME;
	copied = vfs_write (file, (char *) &time, sizeof(time), &pos);
	if (copied != sizeof(time)) {
		printk ("replay_checkpoint_to_disk: tried to write time, got %d\n", copied);
		rc = copied;
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

long replay_resume_from_disk (char* filename, char** execname, char*** argsp, char*** envp, __u64* prg_id) 
{
	mm_segment_t old_fs = get_fs();
	int rc, fd, args_cnt, env_cnt, copied, i, len;
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
	copied = vfs_read(file, (char *) &record_pid, sizeof(record_pid), &pos);
	if (copied != sizeof(record_pid)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next read the record group id
	copied = vfs_read(file, (char *) &rg_id, sizeof(rg_id), &pos);
	MPRINT ("Pid %d replay_resume_from_disk: rg_id %llu\n", current->pid, rg_id);
	if (copied != sizeof(rg_id)) {
		printk ("replay_resume_from_disk: tried to read rg_id, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	*prg_id = rg_id;

	// Next read the parent record group id
	copied = vfs_read(file, (char *) &parent_rg_id, sizeof(parent_rg_id), &pos);
	MPRINT ("Pid %d replay_resume_from_disk: parent_rg_id %llu", current->pid, parent_rg_id);
	if (copied != sizeof(parent_rg_id)) {
		printk ("replay_resume_from_disk: tried to read parent_rg_id got %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next read the exec name
	copied = vfs_read(file, (char *) &len, sizeof(len), &pos);
	if (copied != sizeof(len)) {
		printk ("replay_resume_from_disk: tried to read execname len, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	*execname = KMALLOC (len, GFP_KERNEL);
	if (*execname == NULL) {
		printk ("replay_resume_from_disk: unable to allocate exev name of len %d\n", len);
		rc = -ENOMEM;
		goto exit;
	}
	copied = vfs_read(file, *execname, len, &pos);
	if (copied != len) {
		printk ("replay_resume_from_disk: tried to read execname, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	
	// Next, read the rlimit info
	copied = vfs_read(file, (char *) &current->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, &pos);
	if (copied != sizeof(struct rlimit)*RLIM_NLIMITS) {
		printk ("replay_resume_from_disk: tried to read rlimits, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	copied = vfs_read(file, (char *) &current->sighand->action, sizeof(struct k_sigaction) * _NSIG, &pos);
	if (copied != sizeof(struct k_sigaction)*_NSIG) {
		printk ("replay_resume_from_disk: tried to read sighands, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, read the number of arguments
	copied = vfs_read(file, (char *) &args_cnt, sizeof(args_cnt), &pos);
	if (copied != sizeof(args_cnt)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copied);
		rc = copied;
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
		copied = vfs_read(file, (char *) &len, sizeof(len), &pos);
		if (copied != sizeof(len)) {
			printk ("replay_resume_from_disk: tried to read argument %d len, got rc %d\n", i, copied);
			rc = copied;
			goto exit;
		}
		args[i] = KMALLOC(len+1, GFP_KERNEL);
		if (args[i] == NULL) {
			printk ("replay_resume_froma_disk: unable to allocate argument %d\n", i);
			rc = -ENOMEM;
			goto exit;
		}
		copied = vfs_read(file, args[i], len, &pos);
		MPRINT ("copied %d bytes\n", copied);
		if (copied != len) {
			printk ("replay_resume_from_disk: tried to read argument %d, got rc %d\n", i, copied);
			rc = copied;
			goto exit;
		}
		args[i][len] = '\0'; // NULL terminator not in file format
		MPRINT ("Argument %d is %s\n", i, args[i]);
	}
	args[i] = NULL;

	// Next, read the number of env. objects
	copied = vfs_read(file, (char *) &env_cnt, sizeof(env_cnt), &pos);
	if (copied != sizeof(env_cnt)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copied);
		rc = copied;
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
		copied = vfs_read(file, (char *) &len, sizeof(len), &pos);
		if (copied != sizeof(len)) {
			printk ("replay_resume_from_disk: tried to read env. %d len, got rc %d\n", i, copied);
			rc = copied;
			goto exit;
		}
		env[i] = KMALLOC(len+1, GFP_KERNEL);
		if (env[i] == NULL) {
			printk ("replay_resume_froma_disk: unable to allocate env. %d\n", i);
			rc = -ENOMEM;
			goto exit;
		}
		copied = vfs_read(file, env[i], len, &pos);
		if (copied != len) {
			printk ("replay_resume_from_disk: tried to read env. %d, got rc %d\n", i, copied);
			rc = copied;
			goto exit;
		}
		env[i][len] = '\0'; // NULL terminator not in file format
		MPRINT ("Env. %d is %s\n", i, env[i]);
	}
	env[i] = NULL;

	*argsp = args;
	*envp = env;
	
	// Next read the time
	copied = vfs_read(file, (char *) &time, sizeof(time), &pos);
	if (copied != sizeof(time)) {
		printk ("replay_resume_from_disk: tried to read time, got %d\n", copied);
		rc = copied;
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

#ifdef CONFIG_PROC_FS
static char*
get_exe_path (struct mm_struct* mm, char* path)
{
	char* p;

	down_read(&mm->mmap_sem);
	p = d_path (&mm->exe_file->f_path, path, PATH_MAX);
	up_read(&mm->mmap_sem);
	return p;
}
#endif

static int 
get_replay_mmap (struct btree_head32 *replay_mmap_btree, char *filename) 
{ 
	int key, newkey, inserted = 0; 

	sscanf(filename, WRITABLE_MMAPS ,&key); // get the key	
	newkey = (int)btree_lookup32(replay_mmap_btree, key);
	if (newkey == 0) { 
		//we need to create a new key! 
		newkey = get_next_mmap_file();
		btree_insert32(replay_mmap_btree, (u32)key,(void*)newkey,GFP_KERNEL);
		inserted = 1;
	}
	sprintf(filename, WRITABLE_MMAPS,newkey);
	return inserted;
}


// This function writes the global checkpoint state to disk
long 
replay_full_checkpoint_hdr_to_disk (char* filename, __u64 rg_id, int clock, u_long proc_count, struct ckpt_tsk *ct, struct task_struct *tsk,loff_t* ppos)
{
	mm_segment_t old_fs = get_fs();
	struct file* file = NULL;
	struct ckpt_data cdata;
	int fd = -1, rc, copied;

	MPRINT ("pid %d enters replay_full_checkpoint_hdr_to_disk: filename %s\n", current->pid, filename);

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd < 0) {
		printk ("replay_full_checkpoint_hdr_to_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);
	*ppos = 0;

	// Write out checkpoint data
	cdata.rg_id = rg_id;
	cdata.clock = clock;
	cdata.proc_count = proc_count;
	copied = vfs_write (file, (char *) &cdata, sizeof(cdata), ppos);
	if (copied != sizeof(cdata)) {
		printk ("replay_full_checkpoint_hdr_to_disk: tried to write ckpt data, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	rc = checkpoint_ckpt_tsks_header(ct, -1, 0, file, ppos); 	

	//this is part of the replay_group, so do it here instead of for each proc: 
	rc = checkpoint_task_xray_monitor (tsk, file, ppos);
	
exit:
	if (file) fput(file);
	if (fd >= 0)  {
		rc = sys_close (fd);
		if (rc < 0) printk ("replay_checkpoint_proc_to_disk: close returns %d\n", rc);
	}
	set_fs(old_fs);
	return rc;
}

// This function writes the process state to a disk file
long 
replay_full_checkpoint_proc_to_disk (char* filename, struct task_struct* tsk, pid_t record_pid, 
				     int is_thread, long retval, loff_t logpos, u_long outptr, 
				     u_long consumed, u_long expclock, u_long pthread_block_clock, 
				     u_long ignore_flag, u_long user_log_addr, u_long user_log_pos,
				     u_long replay_hook, loff_t* ppos)
{
	mm_segment_t old_fs = get_fs();
	int fd = -1, rc, copied, i;
	struct file* file = NULL;
	struct vm_area_struct* vma;
	struct vma_stats* pvmas = NULL;
	char* buffer = NULL;
	struct mm_info* pmminfo = NULL;
	struct inode* inode;
	char* p;
	struct user_desc desc;
	struct ckpt_proc_data cpdata;
	long nr_pages = 0;
	struct page** ppages = NULL;  
	struct fpu *fpu = &(tsk->thread.fpu); 

	char fpu_is_allocated;

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_WRONLY|O_APPEND, 0);
	if (fd < 0) {
		printk ("replay_full_checkpoint_proc_to_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);

	// First - write out checkpoint data
	cpdata.record_pid = record_pid;
	cpdata.retval = retval;
	cpdata.logpos = logpos;
	cpdata.outptr = outptr;
	cpdata.consumed = consumed;
	cpdata.expclock = expclock;
	cpdata.pthreadclock = pthread_block_clock;
	cpdata.p_ignore_flag  = ignore_flag;
	cpdata.p_user_log_addr = user_log_addr;
	cpdata.user_log_pos = user_log_pos; 
	cpdata.p_clear_child_tid = (u_long)tsk->clear_child_tid; //ah, not having this messes up our replay on exit
	cpdata.p_replay_hook = replay_hook;

	copied = vfs_write (file, (char *) &cpdata, sizeof(cpdata), ppos);
	if (copied != sizeof(cpdata)) {
		printk ("replay_full_checkpoint_proc_to_disk: tried to write process data, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next - write out the registers
	copied = vfs_write(file, (char *) get_pt_regs(tsk), sizeof(struct pt_regs), ppos);
	if (copied != sizeof(struct pt_regs)) {
		printk ("replay_full_checkpoint_proc_to_disk: tried to write regs, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	//this is a part of the replay_thrd, so we do it regardless of thread / process
	//TODO: xdou: why this is called twice in this function?????
	checkpoint_sysv_mappings (tsk, file, ppos);

	// Write out the floating point registers: 
	if (current == tsk) { 
		//force the fpu to flush to the task_struct's data structures
		unlazy_fpu(tsk);
	}
	fpu = &(tsk->thread.fpu);

	fpu_is_allocated = fpu_allocated(fpu);
	copied = vfs_write(file, &(fpu_is_allocated), sizeof(char), ppos);
	if (copied != sizeof(char)) {
		printk ("replay_full_checkpoint_proc_to_disk: tried to write last_cpu, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}	

	if (fpu_is_allocated){
		copied = vfs_write(file, (char *) &(fpu->last_cpu), sizeof(unsigned int), ppos);
		if (copied != sizeof(unsigned int)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write last_cpu, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
		copied = vfs_write(file, (char *) &(fpu->has_fpu), sizeof(unsigned int), ppos);
		if (copied != sizeof(unsigned int)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write has_fpu, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}

		copied = 0;
		while (copied < xstate_size) {
			int ret = vfs_write(file, (char *) fpu->state + copied, xstate_size - copied, ppos);
			if (ret <= 0) { 
				printk ("[ERROR] replay_full_checkpoint_proc_to_disk cannot write xstate\n");
				break;
			}
			copied += ret;
		}
		if (copied != xstate_size) {
			printk ("[ERROR] replay_full_checkpoint_proc_to_disk: tried to write thread_xstate, got rc %d, expected %d\n", copied, xstate_size);
			rc = copied;
			goto exit;
		}

	}

	

	//this is part of the replay_thrd, so we do it regardless of thread / process
	checkpoint_sysv_mappings (tsk, file, ppos);
	if (!is_thread) { 
		// Write out the replay cache state
		checkpoint_replay_cache_files (tsk, file, ppos);		
		down_read (&tsk->mm->mmap_sem);

		// Next - number of VM area
		copied = vfs_write(file, (char *) &tsk->mm->map_count, sizeof(int), ppos);
		if (copied != sizeof(int)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write map_count, got rc %d\n", copied);
			rc = copied;
			goto unlock;
		}
		
		/* These are too big to put on the kernel stack */
		pvmas = KMALLOC (sizeof(struct vma_stats), GFP_KERNEL);
		buffer = KMALLOC (PATH_MAX, GFP_KERNEL);
		if (!pvmas || !buffer) {
			printk ("replay_full_checkpoint_proc_to_disk: cannot allocate memory\n");
			rc = -ENOMEM;
			goto unlock;
		}
		if (replay_debug) print_vmas (current);
		printk ("=========================\n");
		print_vmas (tsk);
		printk ("=========================\n");

		// Next - info and data for each vma
		for (vma = tsk->mm->mmap; vma; vma = vma->vm_next) {
			char mmap_filename[256];
			struct file* mmap_file = NULL;
			int mmap_fd = 0;
			loff_t mmap_ppos = 0;

			sprintf (mmap_filename, "%s.ckpt_mmap.%lx", filename, vma->vm_start);
			old_fs = get_fs();
			mmap_fd = sys_open (mmap_filename, O_WRONLY|O_CREAT|O_TRUNC, 0777);
			if (mmap_fd < 0) {
				printk ("replay_full_checkpoint_proc_to_disk: open of %s returns %d\n", mmap_filename, mmap_fd);
				rc = fd;
				goto exit;
			}
			mmap_file = fget (mmap_fd);
			
			if (vma->vm_start == (u_long) tsk->mm->context.vdso) {
				printk ("Pid %d replay_full_checkpoint_proc_to_disk: skip vdso %lx to %lx\n", current->pid, vma->vm_start, vma->vm_end);
				continue; // Don't save VDSO - will regenerate it on restore
			}
			
			pvmas->vmas_start = vma->vm_start;
			pvmas->vmas_end = vma->vm_end;
			pvmas->vmas_flags = vma->vm_flags;
			pvmas->vmas_pgoff = vma->vm_pgoff;
			
			if(vma->vm_file) {
				inode = vma->vm_file->f_path.dentry->d_inode;
				p = d_path (&vma->vm_file->f_path, buffer, PATH_MAX);
				strcpy (pvmas->vmas_file, p);
			}
			else {
				pvmas->vmas_file[0] = '\0';
			}

			//this is only for getting how many regions are replay_caches or read_only or zero; check the potential minimal checkpoint size we can have
			//comment it out if you're not getting numbers for jumpstart
			//read-only and cached
			if (vma->vm_file &&  !(vma->vm_flags & VM_WRITE) && !strncmp (pvmas->vmas_file, "/replay_cache/", 14)) {
				printk ("possible duplicated region %lx to %lx, size %lu file %s\n", vma->vm_start, vma->vm_end, vma->vm_end-vma->vm_start, pvmas->vmas_file);
			} else { 
				//zero-filled region
				//if (is_memory_zero ((void*)vma->vm_start, (void*)vma->vm_end)) { 
				//	printk ("possible zero-filled region %lx to %lx, size %lu file %s\n", vma->vm_start, vma->vm_end, vma->vm_end-vma->vm_start, pvmas->vmas_file);
				//} else if (vma->vm_file && vma->vm_start == 0x8048000) { 
				if (vma->vm_file && vma->vm_start == 0x8048000) { 
					printk ("possible executable region %lx to %lx, size %lu file %s\n", vma->vm_start, vma->vm_end, vma->vm_end-vma->vm_start, pvmas->vmas_file);
					printk ("possible executable region %lx to %lx, size %lu file %s\n", vma->vm_next->vm_start, vma->vm_next->vm_end, vma->vm_next->vm_end - vma->vm_next->vm_start, pvmas->vmas_file);
				}
			}

			copied = vfs_write(file, (char *) pvmas, sizeof(struct vma_stats), ppos);
			if (copied != sizeof(struct vma_stats)) {
				printk ("replay_full_checkpoint_proc_to_disk: tried to write vma info, got rc %d\n", copied);
				rc = copied;
				goto freemem;
			}
			
			if(!strncmp(pvmas->vmas_file, "/dev/zero", 9)) continue; /* Skip writing this one */

			if (/*!(pvmas->vmas_flags & VM_READ) || */
			    ((pvmas->vmas_flags&VM_MAYSHARE) && 
			     (strncmp(pvmas->vmas_file, WRITABLE_MMAPS,WRITABLE_MMAPS_LEN) && strncmp (pvmas->vmas_file, "/replay_cache/", 14)))) { //why is this in here...? 
                                printk ("[SKIPPED] file %s, range %lx to %lx, flags read %d, shared %d\n", pvmas->vmas_file, pvmas->vmas_start, pvmas->vmas_end, pvmas->vmas_flags & VM_READ, pvmas->vmas_flags & VM_MAYSHARE);
				continue;
			}
			if (!(pvmas->vmas_flags&VM_READ)){
				struct vm_area_struct *prev = NULL;
				// force it to readable temproarilly
				//sys_mprotect won't work here
				rc = mprotect_fixup (vma, &prev, vma->vm_start, vma->vm_end, vma->vm_flags | VM_READ); 
                                printk ("Pid %d change region to readable file %s, range %lx to %lx, flags read %d, shared %d\n", current->pid, pvmas->vmas_file, pvmas->vmas_start, pvmas->vmas_end, pvmas->vmas_flags & VM_READ, pvmas->vmas_flags & VM_MAYSHARE);
				if (rc) { 
					printk ("Pid %d replay_full_checkpoint_hdr_to_disk: mprotect_fixup fails %d\n", current->pid, rc);
				}
				BUG_ON(prev != vma);
			}
			
			if (current->pid != tsk->pid) {
				// Need to map these pages to kernel space
				nr_pages = (pvmas->vmas_end-pvmas->vmas_start)/PAGE_SIZE;
				DPRINT ("Region: %lx to %lx: number of pages is %ld\n", pvmas->vmas_start, pvmas->vmas_end, nr_pages);
				ppages = KMALLOC(sizeof(struct page *) * nr_pages, GFP_KERNEL);
				if (ppages == NULL) {
					printk ("replay_full_checkpoint_proc_to_disk: cannot allocate page array\n");
					rc = -ENOMEM;
					goto freemem;
				}

				rc = get_user_pages (tsk, tsk->mm, pvmas->vmas_start, nr_pages, 0, 0, ppages, NULL);
				if (rc != nr_pages) {
					printk ("replay_full_checkpoint_proc_to_disk: cannot get user pages,rc=%d\n", rc);
					KFREE (ppages);
					ppages = NULL;
					goto freemem;
				}
				for (i = 0; i < nr_pages; i++) {
					char* p = kmap (ppages[i]);
					copied = vfs_write(mmap_file, p, PAGE_SIZE, &mmap_ppos);
					kunmap (ppages[i]);
					if (copied != PAGE_SIZE) {
						printk ("replay_full_checkpoint_proc_to_disk: tried to write vma page, got rc %d\n", copied);
						rc = copied;
						goto freemem;
					}
				}
				for (i = 0; i < nr_pages; i++) {
					put_page (ppages[i]);
				}
				KFREE(ppages);
				ppages = NULL;
				printk ("replay_full_checkpoint_hdr_to_disk file %s start %lx end %lx, size %ld, flag %d, nrp_page %ld\n", pvmas->vmas_file, pvmas->vmas_start, pvmas->vmas_end, pvmas->vmas_end-pvmas->vmas_start, pvmas->vmas_flags, nr_pages);
			} else {
				set_fs(old_fs);
				copied = vfs_write(mmap_file, (char *) pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, &mmap_ppos);
				set_fs(KERNEL_DS);
				if (copied != pvmas->vmas_end - pvmas->vmas_start) {
					printk ("replay_full_checkpoint_proc_to_disk: tried to write vma data, got rc %d\n", copied);
					rc = copied;
					goto freemem;
				}
				printk ("replay_full_checkpoint_hdr_to_disk file %s start %lx end %lx, size %ld, nrp_page %ld\n", pvmas->vmas_file, pvmas->vmas_start, pvmas->vmas_end, pvmas->vmas_start-pvmas->vmas_end, nr_pages);
			}
			if (mmap_file) fput (mmap_file);	
			if (mmap_fd > 0) {
				rc = sys_close (mmap_fd);
				if (rc < 0) printk ("replay_checkpoint_proc_to_disk: close returns %d\n", rc);
			}
			if (!(pvmas->vmas_flags&VM_READ)) {
				struct vm_area_struct *prev = NULL;
				printk ("Pid %d finds a non-readable region, tsk pid %d\n", current->pid, tsk->pid);
				// restore old protections		
				rc = mprotect_fixup (vma, &prev, vma->vm_start, vma->vm_end, pvmas->vmas_flags); 
				if (rc) { 
					printk ("Pid %d replay_full_checkpoint_hdr_to_disk: mprotect_fixup fails %d\n", current->pid, rc);
				}
				BUG_ON(prev != vma);
			}
		}

		// Process-specific info in the mm struct
		pmminfo = KMALLOC (sizeof(struct mm_info), GFP_KERNEL);
		if (pmminfo == NULL) {
			printk ("replay_full_checkpoint_proc_to_disk: unable to allocate mm_info structure\n");
			rc = -ENOMEM;
			goto freemem;
		}
		pmminfo->start_code = tsk->mm->start_code;
		pmminfo->end_code = tsk->mm->end_code;
		pmminfo->start_data = tsk->mm->start_data;
		pmminfo->end_data = tsk->mm->end_data;
		pmminfo->start_brk = tsk->mm->start_brk;
		pmminfo->brk = tsk->mm->brk;
		pmminfo->start_stack = tsk->mm->start_stack;
		pmminfo->arg_start = tsk->mm->arg_start;
		pmminfo->arg_end = tsk->mm->arg_end;
		pmminfo->env_start = tsk->mm->env_start;
		pmminfo->env_end = tsk->mm->env_end;
		memcpy (pmminfo->saved_auxv, tsk->mm->saved_auxv, sizeof(pmminfo->saved_auxv));
		pmminfo->vdso = tsk->mm->context.vdso;		

#ifdef CONFIG_PROC_FS
		p = get_exe_path (tsk->mm, buffer);
		strcpy (pmminfo->exe_file, p);
#endif

		copied = vfs_write(file, (char *) pmminfo, sizeof(struct mm_info), ppos);
		if (copied != sizeof(struct mm_info)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write mm info, got rc %d\n", copied);
			rc = copied;
			goto freemem;
		}
	}
	else { 
		//we didn't do this in the if above ^^ 
		down_read (&tsk->mm->mmap_sem);
	}


	// Write out TLS info
	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
		fill_user_desc(&desc, GDT_ENTRY_TLS_MIN+i, &tsk->thread.tls_array[i]);
		copied = vfs_write(file, (char *) &desc, sizeof(desc), ppos);
		if (copied != sizeof(desc)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write TLS entry #%d, got rc %d\n", i, copied);
			rc = copied;
			goto freemem;
		}
		MPRINT ("Pid %d replay_full_checkpoint_proc_to_disk filling user_desc base_addr %x limit %x\n", tsk->pid, desc.base_addr, desc.limit);
	}

	// Next, write out rlimit information
	copied = vfs_write (file, (char *) &tsk->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, ppos);
	if (copied != sizeof(struct rlimit)*RLIM_NLIMITS) {
		printk ("replay_checkpoint_proc_to_disk: tried to write rlimits, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}

	// Next, copy the signal handlers
	copied = vfs_write (file, (char *) &tsk->sighand->action, sizeof(struct k_sigaction) * _NSIG, ppos);
	if (copied != sizeof(struct k_sigaction)*_NSIG) {
		printk ("replay_checkpoint_proc_to_disk: tried to write sighands, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}

freemem:
	if (ppages) {
		for (i = 0; i < nr_pages; i++) {
			put_page (ppages[i]);
		}
		KFREE(ppages);
	}
	KFREE(buffer);
	KFREE(pvmas);
	KFREE(pmminfo);
unlock:
	up_read (&tsk->mm->mmap_sem);
exit:
	if (file) fput(file);
	if (fd >= 0)  {
		rc = sys_close (fd);
		if (rc < 0) printk ("replay_checkpoint_proc_to_disk: close returns %d\n", rc);
	}
        printk ("Pid %d replay_checkpoint_proc_to_disk exit: current pos %lld\n", current->pid, *ppos);
	set_fs(old_fs);
	return rc;
}

long replay_full_resume_hdr_from_disk (char* filename, __u64* prg_id, int* pclock, u_long* pproc_count, loff_t* ppos) 
{
	mm_segment_t old_fs = get_fs();
	int rc = 0, fd, copied;
	struct file* file = NULL;
	struct ckpt_data cdata;

	MPRINT ("pid %d enters replay_full_resume_hdr_from_disk: filename %s\n", current->pid, filename);

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_RDONLY, 0);
	if (fd < 0) {
		printk ("replay_full_reusme_hdr_from_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);
	*ppos = 0;

	// Read the checkpoint header data
	copied = vfs_read(file, (char *) &cdata, sizeof(cdata), ppos);
	MPRINT ("Pid %d replay_full_resume_hdr_from_disk: rg_id %llu\n", current->pid, cdata.rg_id);
	if (copied != sizeof(cdata)) {
		printk ("replay_full_resume_hdr_from_disk: tried to read ckpt data, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	*prg_id = cdata.rg_id;
	*pclock = cdata.clock;
	*pproc_count = cdata.proc_count;

	rc = restore_ckpt_tsks_header(*pproc_count, file, ppos); 	
	rc = restore_task_xray_monitor (current, file, ppos);

	MPRINT ("replay_full_resume_hdr_from_disk done\n");
exit:
	if (fd >= 0) {
		if (sys_close (fd) < 0) printk ("replay_full_resume_hdr_from_disk: close returns %d\n", rc);
	}
	if (file) fput(file);
	set_fs(old_fs);
	return rc;
}

long replay_full_resume_proc_from_disk (char* filename, pid_t clock_pid, int is_thread, 
					long* pretval, loff_t* plogpos, u_long* poutptr, 
					u_long* pconsumed, u_long* pexpclock, 
					u_long* pthreadclock, u_long *ignore_flag, 
					u_long *user_log_addr, ulong *user_log_pos,
					u_long *child_tid,u_long *replay_hook, loff_t* ppos, 
					char* slicelib, u_long* slice_addr, u_long* slice_size, u_long* pthread_clock_addr)
{
	mm_segment_t old_fs = get_fs();
	int rc = 0, fd, exe_fd, copied, i, map_count, key, shmflg=0, id, premapped = 0, new_file = 0;
	struct file* file = NULL, *map_file;
	pid_t record_pid = -1;
	struct vm_area_struct* vma, *vma_next;
	struct vma_stats* pvmas = NULL;
	struct mm_info* pmminfo = NULL;
	u_long addr;
	struct ckpt_proc_data cpdata;
	struct user_desc desc;
	int flags;
	struct btree_head32 replay_mmap_btree;
	struct fpu *fpu = NULL;
	struct pt_regs* regs = NULL;
	int was_libkeep = 0;

	char fpu_is_allocated;
       
	MPRINT ("pid %d enters replay_full_resume_proc_from_disk: filename %s, pos %lld\n", current->pid, filename, *ppos);
	if (PRINT_TIME) {
		struct timeval tv;
		do_gettimeofday (&tv);
		printk ("replay_full_resume_proc_from_disk time %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
	}

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_RDONLY, 0);
	if (fd < 0) {
		printk ("replay_checkpoint_from_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);

	// Read the process checkpoint data
	copied = vfs_read(file, (char *) &cpdata, sizeof(cpdata), ppos);
	if (copied != sizeof(cpdata)) {
		printk ("replay_full_resume_proc_from_disk: tried to read checkpoint process data, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	record_pid = cpdata.record_pid;
	*pretval = cpdata.retval;
	*plogpos = cpdata.logpos;
	*poutptr = cpdata.outptr;
	*pconsumed = cpdata.consumed;
	*pexpclock = cpdata.expclock;
	*pthreadclock = cpdata.pthreadclock;
	*ignore_flag = cpdata.p_ignore_flag;
	*user_log_addr = cpdata.p_user_log_addr;
	*user_log_pos  = cpdata.user_log_pos;
	*child_tid = cpdata.p_clear_child_tid; 
	*replay_hook = cpdata.p_replay_hook;

	// Restore the user-level registers
	regs = get_pt_regs(NULL);
	copied = vfs_read(file, (char *) regs, sizeof(struct pt_regs), ppos);
	if (copied != sizeof(struct pt_regs)) {
		printk ("replay_full_resume_proc_from_disk: tried to read regs, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	MPRINT ("Registers after checkpoint restore record_pid %d\n", current->pid);
	dump_reg_struct (get_pt_regs(NULL));

	//this is a part of the replay_thrd, so we do it regardless of thread / process
	restore_sysv_mappings (file, ppos);

	// Restore the floating point registers: 
	fpu = &(current->thread.fpu);

	copied = vfs_read(file, &(fpu_is_allocated), sizeof(char), ppos);
	if (copied != sizeof(char)) {
		printk ("replay_full_checkpoint_proc_to_disk: tried to read fpu_is_allocated, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}	

	if (fpu_is_allocated) { 
		//allocate the new fpu if we need it and it isn't setup
		if (!fpu_allocated(fpu)) {
			fpu_alloc(fpu);
		}

		copied = vfs_read(file, (char *) &(fpu->last_cpu), sizeof(unsigned int), ppos);
		if (copied != sizeof(unsigned int)) {
			printk ("replay_full_resume_proc_from_disk: tried to read last cpu, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
		copied = vfs_read(file, (char *) &(fpu->has_fpu), sizeof(unsigned int), ppos);
		if (copied != sizeof(unsigned int)) {
			printk ("replay_full_resume_proc_from_disk: tried to read has_fpu, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
		copied = vfs_read(file, (char *) fpu->state, xstate_size, ppos);
		if (copied != xstate_size) {
			printk ("replay_full_resume_proc_from_disk: tried to read thread_xstate, got rc %d, expected %d\n", copied, xstate_size);
			rc = copied;
			goto exit;
		}
	}

	//this is a part of the replay_thrd, so we do it regardless of thread / process
	restore_sysv_mappings (file, ppos);

        if (!is_thread) {
                char slice_fullname[256];
                snprintf (slice_fullname, 256, "%s.%d.so", slicelib, record_pid);
		DPRINT ("Pid %d (record pid %d) slice fullname is %s\n", current->pid, record_pid, slice_fullname);
                // restore the replay cache state (this is going to be done on per process)
                restore_replay_cache_files (file, ppos, slicelib != NULL);

		// Delete all the vm areas of current process 
		// (except if there is a slice library specified - leave that)
		down_write (&current->mm->mmap_sem);
		vma = current->mm->mmap;
		*slice_addr = 0;
		while(vma) {
			vma_next = vma->vm_next;
			if (slicelib && vma->vm_file) {
				char buf[256];
				char* s = dentry_path (vma->vm_file->f_dentry, buf, sizeof(buf));
				DPRINT ("unmap path is: %s (from %lx to %lx)\n", s, vma->vm_start, vma->vm_end);
				if (strlen(s) >= 12 && !strcmp(s+strlen(s)-12,"libc-2.15.so")) {
					DPRINT ("This is libc - do not unmap it\n");
					vma = vma_next;
					was_libkeep = 1;
					continue;
				}
				if (!strcmp(s, slice_fullname)) {
					DPRINT ("This is the slice library do not unmap it\n");
					if (*slice_addr == 0) {
						char val, val2;
						get_user(val, (char __user *) vma->vm_start+4);
						get_user(val2, (char __user *) vma->vm_start+5);
						DPRINT ("val %d val2 %d\n", val, val2);
						if (val == 1 && val2 == 1) {
							*slice_addr = vma->vm_start;
							*slice_size = vma->vm_end - vma->vm_start;
						}					    
					}
                                        vma = vma_next;
                                        was_libkeep = 1;
                                        continue;
                                }
                                if (!strncmp (s, slicelib, strlen (slicelib))) { 
					DPRINT ("This is the slice library for other threads, do not unmap it\n");
                                        vma = vma_next;
                                        was_libkeep = 1;
                                        continue;
                                }
			} else if (was_libkeep) {
			    /* This I think is for globals for libc and exslice - hack, so may not work */
			    was_libkeep = 0;
			    vma = vma_next;
			    continue;
			}
			do_munmap(current->mm, vma->vm_start, vma->vm_end - vma->vm_start);
			vma = vma_next;
		} 
		up_write (&current->mm->mmap_sem);

		// Next - read the number of VM area
		copied = vfs_read(file, (char *) &map_count, sizeof(int), ppos);
		if (copied != sizeof(int)) {
			printk ("replay_full_resume_proc_from_disk: tried to read map_count, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
		
		/* This is too big to put on the kernel stack */
		pvmas = KMALLOC (sizeof(struct vma_stats), GFP_KERNEL);
		if (!pvmas) {
			printk ("replay_full_resume_proc_from_disk: cannot allocate memory\n");
			rc = -ENOMEM;
			goto exit;
		}
		if (PRINT_TIME) {
			struct timeval tv;
			do_gettimeofday (&tv);
			printk ("Pid %d replay_full_resume_proc_from_disk before mapping files %ld.%06ld\n", current->pid, tv.tv_sec, tv.tv_usec);
			printk ("\t VM_GROWSDOWN: %x, MAP_FIXED: %x, MAP_PRIVATE %x, MAP_SHARED %x, MAP_GROWSDOWN %x\n", VM_GROWSDOWN, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, MAP_GROWSDOWN);
		}

		// Map each VMA and copy data from the file - assume VDSO handled separately - so use map_count-1
		btree_init32(&replay_mmap_btree);
		for (i = 0; i < map_count-1; i++) {
			struct timeval tv_start, tv_end;
			int shared_file = 0;
			if (replay_debug) {
				do_gettimeofday(&tv_start);
			}
			premapped = 0;
			copied = vfs_read (file, (char *) pvmas, sizeof(struct vma_stats), ppos);
			if (copied != sizeof(struct vma_stats)) {
				printk ("replay_full_resume_proc_from_disk: tried to read vma info, got rc %d, pvmas %p, ppos %lld\n", copied, pvmas, *ppos);
				rc = copied;
				goto freemem;
			}				
			DPRINT ("replay_full_resume_proc_from_disk file %s\n", pvmas->vmas_file);
			//sanity check	
			//MAP_PRIVATE should use copy-on-write if we write into the memory region and changes are not carried out to the underlying files. Therefore, for writable memory regions, it's safe to mmap with MAP_PRIVATE
			//however, if the memory region is also shared, it may be tricky
			if ((pvmas->vmas_flags & VM_MAYSHARE) && (pvmas->vmas_flags & VM_WRITE)) { 
				if (pvmas->vmas_file[0] && 
				    !strncmp(pvmas->vmas_file, "/run/shm/uclock", 15)) {
                                    *pthread_clock_addr = pvmas->vmas_start;
                                    MPRINT ("Pid %d pthread_clock_addr %lx\n", current->pid, *pthread_clock_addr);
				} else {
                                    MPRINT ("[SKIPPED] file %s, range %lx to %lx, flags read %d, shared %d\n", pvmas->vmas_file, pvmas->vmas_start, pvmas->vmas_end, pvmas->vmas_flags & VM_READ, pvmas->vmas_flags & VM_MAYSHARE);
                                    MPRINT ("[CHECK] memory regions is shared and writable! %lx to %lx, file %s\n", pvmas->vmas_start, pvmas->vmas_end, pvmas->vmas_file);
                                    MPRINT ("In this case, we need the copy of that file to avoid any modification to our underlying checkpoint-mmap files, and revert the copy back after we use it.\n");

                                    shared_file = 1;
                                    //BUG();
				}
			}
			
			if (pvmas->vmas_file[0]) { 
				flags = O_RDONLY;
				if (!strncmp(pvmas->vmas_file, "/dev/zero", 9)) {
					MPRINT ("special vma for /dev/zero!\n");
					map_file = NULL;
				} else {
					if (!strncmp(pvmas->vmas_file, "/run/shm/uclock", 15)) {
						flags = O_RDWR;
						MPRINT ("special uclock vma\n");
						sprintf (pvmas->vmas_file, "/run/shm/uclock%d", clock_pid);
						map_file = filp_open (pvmas->vmas_file, O_RDWR, 0);

						if (IS_ERR(map_file)) {
							rc = PTR_ERR(map_file);
							printk ("replay_full_resume_proc_from_disk: filp_open error %d %s rc %d\n", __LINE__, pvmas->vmas_file, rc);
							goto freemem;
						}
					} 
					else if (!strncmp(pvmas->vmas_file,WRITABLE_MMAPS,WRITABLE_MMAPS_LEN)) { 
						new_file = get_replay_mmap(&replay_mmap_btree, pvmas->vmas_file);
						if (new_file) { 
							flags = O_CREAT|O_RDWR;					
							map_file = filp_open (pvmas->vmas_file, flags, 0777);
							if (IS_ERR(map_file)) {
								rc = PTR_ERR(map_file);
								printk ("replay_full_resume_proc_from_disk: filp_open error %d %s rc %d\n", __LINE__, pvmas->vmas_file, rc);
								goto freemem;
							}				
							rc = do_truncate (map_file->f_path.dentry,
									  pvmas->vmas_end - pvmas->vmas_start, 
									  ATTR_MTIME | ATTR_CTIME, map_file);

							if (rc) { 
								printk("%d problem with do_truncate, rc %d \n",
								       current->pid, rc);
								goto freemem;
							}
						}
						else { 
							char mmap_filename[256];
							if (shared_file) {
								sprintf (mmap_filename, "%s.ckpt_mmap.%lx.copy", filename, pvmas->vmas_start);
							} else {
								sprintf (mmap_filename, "%s.ckpt_mmap.%lx", filename, pvmas->vmas_start);
								pvmas->vmas_flags &= ~VM_MAYSHARE;
							}

							flags = O_RDWR;
							//map_file = filp_open (pvmas->vmas_file, flags, 0);
							map_file = filp_open (mmap_filename, flags, 0);
							if (IS_ERR(map_file)) {
								rc = PTR_ERR(map_file);
								printk ("replay_full_resume_proc_from_disk: filp_open error %d %s rc %d\n", __LINE__,  mmap_filename, rc);
								goto freemem;
							}
						}
					} else if (!strncmp(pvmas->vmas_file, "/SYSV",5)) { 
						if (slicelib) {
							// For slice execution, we could preallocate memory so PIN etc. does not grab it
							MPRINT ("slice: preallocating sysv region from %lx to %lx\n", pvmas->vmas_start, pvmas->vmas_end);
							addr = sys_mmap_pgoff (pvmas->vmas_start, pvmas->vmas_end-pvmas->vmas_start, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
							if (addr != pvmas->vmas_start) {
								printk ("slice: preallocating mmap_pgoff returns different value %lx than %lx\n", addr, pvmas->vmas_start);
							}
						} else {
							// JNF: This really looks wrong!
							sscanf(pvmas->vmas_file, "/SYSV%08x",&key);						
							id = find_sysv_mapping_by_key(key); 
							if (id < 0) { 
								printk("whoops.. what happened, key isn't in sysvmappings\n");
								goto freemem; 
							}
							
							//get the correct shmflags
							if (pvmas->vmas_flags&VM_EXEC) { 
								shmflg |= SHM_EXEC;
							}
							else if (pvmas->vmas_flags&VM_READ && 
								 !(pvmas->vmas_flags&VM_WRITE)) { 
								shmflg |= SHM_RDONLY; 
							}
							
							addr = sys_shmat(id, (char __user *)pvmas->vmas_start, shmflg); 
							
							rc = add_sysv_shm((u_long)pvmas->vmas_start, 
									  (u_long)(pvmas->vmas_end - pvmas->vmas_start));
							if (rc < 0) { 
								printk("whoops... add_sysv_shm returns negative?\n");
								goto freemem;
							}
						}

						premapped = 1;
						map_file = NULL; //just to be sure something weird doesn't happen
					} else { 
						char mmap_filename[256];
						MPRINT ("Opening file %s\n", pvmas->vmas_file);
						if (shared_file) {
							sprintf (mmap_filename, "%s.ckpt_mmap.%lx.copy", filename, pvmas->vmas_start);
						} else {
							sprintf (mmap_filename, "%s.ckpt_mmap.%lx", filename, pvmas->vmas_start);
							pvmas->vmas_flags &= ~VM_MAYSHARE;
						}
						flags = O_RDWR;
						map_file = filp_open (mmap_filename, flags, 0);
						if (IS_ERR(map_file)) {
							rc = PTR_ERR(map_file);
							printk ("replay_full_resume_proc_from_disk: filp_open error %d %s rc %d\n", __LINE__, mmap_filename, rc);
							goto freemem;
						}
					}
				}
			} else { 
				if (pvmas->vmas_flags & VM_GROWSDOWN) {
					//it seems we're not allowed to combine mmap backed file with GROWSDOWN flag; let's copy all data in
					map_file = NULL; 
				} else {
					char mmap_filename[256];
					MPRINT ("Opening file %s\n", pvmas->vmas_file);
					if (shared_file) {
						sprintf (mmap_filename, "%s.ckpt_mmap.%lx.copy", filename, pvmas->vmas_start);
					} else {
						sprintf (mmap_filename, "%s.ckpt_mmap.%lx", filename, pvmas->vmas_start);
						pvmas->vmas_flags &= ~VM_MAYSHARE;
					}
					flags = O_RDWR;
					map_file = filp_open (mmap_filename, flags, 0);
					if (IS_ERR(map_file)) {
						rc = PTR_ERR(map_file);
						printk ("replay_full_resume_proc_from_disk: filp_open error %d %s rc %d\n", __LINE__, mmap_filename, rc);
						goto freemem;
					}
				}
			}

			if (!premapped) { 
				DPRINT ("About to do mmap: map_file %p start %lx len %lx flags %x writable? %d shar %x pgoff %lx, vmas_flag %x\n", 
					map_file, pvmas->vmas_start, pvmas->vmas_end-pvmas->vmas_start, 
					(pvmas->vmas_flags&(VM_READ|VM_WRITE|VM_EXEC)), 
					(pvmas->vmas_flags & VM_WRITE),
					((pvmas->vmas_flags&VM_MAYSHARE) ? MAP_SHARED : MAP_PRIVATE) | 
					MAP_FIXED | (pvmas->vmas_flags & VM_GROWSDOWN), 
					pvmas->vmas_pgoff, pvmas->vmas_flags);


				//mmap from ckpt file instead individual replay cache files
				addr = do_mmap_pgoff(map_file, pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, 
					     (pvmas->vmas_flags&(VM_READ|VM_WRITE|VM_EXEC)), 
					     ((pvmas->vmas_flags&VM_MAYSHARE) ? MAP_SHARED : MAP_PRIVATE) | 
						     MAP_FIXED | 
						     (pvmas->vmas_flags&VM_GROWSDOWN), 
					     //pvmas->vmas_pgoff);
					     0);

			}						
			if (map_file) filp_close (map_file, NULL);
			if (IS_ERR((char *) addr)) {
				printk ("replay_full_resume_proc_from_disk: mmap error %ld\n", PTR_ERR((char *) addr));
				rc = addr;
				goto freemem;
			}
			
			if (!strncmp(pvmas->vmas_file, "/dev/zero", 9)) continue; /* Skip writing this one */
			if (/*!(pvmas->vmas_flags&VM_READ) || */
			    ((pvmas->vmas_flags&VM_MAYSHARE) && 
			     (strncmp(pvmas->vmas_file,WRITABLE_MMAPS,WRITABLE_MMAPS_LEN) && strncmp (pvmas->vmas_file, "/replay_cache/", 14)))) {
                                MPRINT ("[SKIPPED] file %s, range %lx to %lx, flags read %d, shared %d\n", pvmas->vmas_file, pvmas->vmas_start, pvmas->vmas_end, pvmas->vmas_flags & VM_READ, pvmas->vmas_flags & VM_MAYSHARE);
				continue;  // Not in checkpoint - so skip writing this one
			}				
                        if (pvmas->vmas_flags & VM_MAYSHARE && !strncmp (pvmas->vmas_file, "/replay_cache/", 14)) { 
                            MPRINT ("[CHECK] A shared file from replay cache. Maybe wrong if it's writable by another thread.\n");
                        }
		     
			if (!map_file) {
				char mmap_filename[256];
				struct file* mmap_file = NULL;
				loff_t mmap_ppos = 0;

				if (!(pvmas->vmas_flags&VM_WRITE)) {
					// force it to writable temproarilly
					rc = sys_mprotect (pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, PROT_WRITE); 
				}
				sprintf (mmap_filename, "%s.ckpt_mmap.%lx", filename, pvmas->vmas_start);

				flags = O_RDWR;
				mmap_file = filp_open (mmap_filename, flags, 0);
				if (IS_ERR(mmap_file)) {
					rc = PTR_ERR(mmap_file);
					printk ("replay_full_resume_proc_from_disk: filp_open error %d %s rc %d\n", __LINE__, mmap_filename, rc);
					goto freemem;
				}
				copied = vfs_read (mmap_file, (char *) pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, &mmap_ppos);
				if (copied != pvmas->vmas_end - pvmas->vmas_start) {
					printk ("%d reading from ckpt file into (0x%lx,0x%lx)\n", current->pid, pvmas->vmas_start, pvmas->vmas_start + (pvmas->vmas_end - pvmas->vmas_start));
					print_vmas(current);
					rc = copied;
					goto freemem;
				}
				MPRINT ("replay_full_resume_proc_from_disk copy data from ckpt (could be time-consuming), map_file %p, filename %s, len %ld, vmas_flags %x\n", map_file, mmap_filename, pvmas->vmas_end-pvmas->vmas_start, pvmas->vmas_flags);
				filp_close (mmap_file, NULL);
				if (!(pvmas->vmas_flags&VM_WRITE)) rc = sys_mprotect (pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, pvmas->vmas_flags&(VM_READ|VM_WRITE|VM_EXEC)); // restore old protections					
			}

			if (replay_debug) {
				do_gettimeofday(&tv_end);
			}
			DPRINT ("replay_full_resume_proc_from_disk mmap file %d, start %ld.%06ld, end %ld.%06ld, interval %ld\n", i, tv_start.tv_sec, tv_start.tv_usec, tv_end.tv_sec, tv_end.tv_usec, (tv_end.tv_usec-tv_start.tv_usec));
		}

		if (PRINT_TIME) {
			struct timeval tv;
			do_gettimeofday (&tv);
			printk ("replay_full_resume_proc_from_disk after mmap time %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
		}
		btree_destroy32(&replay_mmap_btree);
		// Process-specific info in the mm struct
		pmminfo = KMALLOC (sizeof(struct mm_info), GFP_KERNEL);
		if (pmminfo == NULL) {
			printk ("replay_full_resume_proc_from_disk: unable to allocate mm_info structure\n");
			rc = -ENOMEM;
			goto freemem;
		}
		copied = vfs_read (file, (char *) pmminfo, sizeof(struct mm_info), ppos);
		if (copied != sizeof(struct mm_info)) {
			printk ("replay_full_resume_proc_from_disk: tried to read mm info, got rc %d\n", copied);
			rc = copied;
			goto freemem;
		}

		current->mm->start_code =  pmminfo->start_code;
		current->mm->end_code =	pmminfo->end_code;
		current->mm->start_data = pmminfo->start_data;
		current->mm->end_data =	pmminfo->end_data;
		current->mm->start_brk = pmminfo->start_brk;
		current->mm->brk = pmminfo->brk;
		current->mm->start_stack = pmminfo->start_stack;
		current->mm->arg_start = pmminfo->arg_start;
		current->mm->arg_end =	pmminfo->arg_end;
		current->mm->env_start = pmminfo->env_start;
		current->mm->env_end =	pmminfo->env_end;
		memcpy (current->mm->saved_auxv, pmminfo->saved_auxv, sizeof(pmminfo->saved_auxv));
		current->mm->context.vdso = pmminfo->vdso;
		arch_restore_additional_pages (current->mm->context.vdso);
#ifdef CONFIG_PROC_FS
		exe_fd = sys_open (pmminfo->exe_file, O_RDONLY, 0);
		set_mm_exe_file (current->mm, fget(exe_fd));
		sys_close (exe_fd);
#endif

	}
	else { 
                char slice_fullname[256];
		arch_restore_sysenter_return(current->mm->context.vdso);
                snprintf (slice_fullname, 256, "%s.%d.so", slicelib, record_pid);
                //figure out the slice lib address 
                //deletion of the vm areas will be done by the main thread
                down_write (&current->mm->mmap_sem);
                vma = current->mm->mmap;
                *slice_addr = 0;
                while(vma) {
                    vma_next = vma->vm_next;
                    if (slicelib && vma->vm_file) {
                        char buf[256];
                        char* s = dentry_path (vma->vm_file->f_dentry, buf, sizeof(buf));
                        if (!strcmp(s, slice_fullname)) {
                            DPRINT ("This is the slice library \n");
                            if (*slice_addr == 0) {
                                char val, val2;
                                get_user(val, (char __user *) vma->vm_start+4);
                                get_user(val2, (char __user *) vma->vm_start+5);
                                DPRINT ("val %d val2 %d\n", val, val2);
                                if (val == 1 && val2 == 1) {
                                    *slice_addr = vma->vm_start;
                                    *slice_size = vma->vm_end - vma->vm_start;
                                }					    
                            }
                            vma = vma_next;
                            break;
                        }
                    }
                    vma = vma_next;
                } 
                up_write (&current->mm->mmap_sem);
	}

	// Read in TLS info
	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
		copied = vfs_read (file, (char *) &desc, sizeof(desc), ppos);
		if (copied != sizeof(desc)) {
			printk ("replay_full_resume_proc_from_disk: tried to read TLS entry #%d, got rc %d\n", i, copied);
			rc = copied;
			goto freemem;
		}
		set_tls_desc(current, GDT_ENTRY_TLS_MIN+i, &desc, 1);
		MPRINT ("Pid %d resume ckpt set GDT entry %d base_addr %x limit %x\n", current->pid, GDT_ENTRY_TLS_MIN+i, desc.base_addr, desc.limit);
	}

	if (slicelib != NULL) {
	    // rlim and signal handlers will be restored from slice execution
            //advance the file pos
            *ppos += sizeof (struct k_sigaction)*_NSIG + sizeof(struct rlimit)*RLIM_NLIMITS;
        } else {
		// Next, read the rlimit info
		copied = vfs_read(file, (char *) &current->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, ppos);
		if (copied != sizeof(struct rlimit)*RLIM_NLIMITS) {
			printk ("replay_full_resume_proc_from_disk: tried to read rlimits, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}

		copied = vfs_read(file, (char *) &current->sighand->action, sizeof(struct k_sigaction) * _NSIG, ppos);
		if (copied != sizeof(struct k_sigaction)*_NSIG) {
			printk ("replay_full_resume_proc_from_disk: tried to read sighands, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
	}
	
	MPRINT ("replay_full_resume_proc_from_disk done\n");
	if (PRINT_TIME) {
		struct timeval tv;
		do_gettimeofday (&tv);
		printk ("replay_full_resume_proc_from_disk end time %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
	}

	if (replay_debug) {
            printk ("replay_full_resume_proc_from_disk: vmas status ---------------- \n");
            print_vmas(current);
            printk ("replay_full_resume_proc_from_disk: end vmas status ---------------- \n");
        }
freemem:
	KFREE (pmminfo);
	KFREE (pvmas);
exit:
	if (fd >= 0) {
		if (sys_close (fd) < 0) printk ("replay_full_resume_proc_from_disk: close returns %d\n", rc);
	}
	if (file) fput(file);
	set_fs(old_fs);
	if (rc < 0) return rc;
	return record_pid;
}

#define SLICE_INFO_SIZE     4096
#define STACK_SIZE        1048576
#define RECHECK_FILE_NAME_LEN 124 //make sure the stack address is aligned; recheck_start takes two arguments from the stack and RECHECK_FILE_NAME_LEN + sizeof(long) = 128


struct slice_task {
	pid_t slice_pid;
	pid_t daemon_pid;
	char recheck_filename[256];
	struct list_head list;
};

DEFINE_MUTEX(slice_task_mutex);
int slice_handling_initialized = 0;
struct list_head slice_task_list;
struct list_head slice_processing_list;
wait_queue_head_t daemon_waitq;

void init_slice_handling (void)
{
	init_waitqueue_head (&daemon_waitq);
	INIT_LIST_HEAD(&slice_task_list);
	INIT_LIST_HEAD(&slice_processing_list);
	slice_handling_initialized = 1;
}

static struct fw_slice_info* get_fw_slice_info (struct pt_regs* regs) {
	// We no longer expect this to be aligned since we are using the VDSO to enter the kernel
	// Insted, adjust sp value to account for extra data on the stack
	u_long addr = regs->sp;
	MPRINT ("get_fw_slice_info: sp is %lx\n", addr);
	if (addr%4096) {
		addr &= 0xfffff000;
		addr += 4096;
	}
	MPRINT ("get_fw_slice_info: expect slice_info at %lx\n", addr);
	return (struct fw_slice_info *) addr;
}

long start_fw_slice (struct go_live_clock* go_live_clock, u_long slice_addr, u_long slice_size, long record_pid, char* recheck_filename, u_long user_clock_addr, u_long slice_mode) 
{ 
	//start to execute the slice
	long extra_space_addr = 0;
	struct pt_regs* regs = get_pt_regs(current);
	struct fw_slice_info* pinfo;
	char recheck_log_name[RECHECK_FILE_NAME_LEN] = {0};
	u_int entry;
        int index;

	if (go_live_clock != NULL) {
		index = atomic_add_return (1, &go_live_clock->num_threads)-1;
		if (index == 0) 
			go_live_clock->cache_file_structure = NULL;
		MPRINT ("Pid %d start_fw_slice pthread_clock_addr %lx\n", current->pid, user_clock_addr);
		if (index > 99) { //cannot put all information in one single page
			printk ("start_fw_slice: too many concurrent threads?\n");
			BUG ();
		} else { 
			//write the process map
			go_live_clock->process_map[index].record_pid = record_pid;
			go_live_clock->process_map[index].current_pid = current->pid;
			go_live_clock->process_map[index].taintbuf = NULL; // Will be set by each slice when started
			go_live_clock->process_map[index].taintndx = NULL; // Ditto
			go_live_clock->process_map[index].value = 0;
			go_live_clock->process_map[index].wait = 0;
		}
	}

	// Too big - so allocate on the stack
	pinfo = KMALLOC (sizeof(struct fw_slice_info), GFP_KERNEL);
	if (pinfo == NULL) {
		printk ("Cannot allocate fw_slice_info\n");
		return -ENOMEM;
	}
        pinfo->slice_clock = go_live_clock;
	pinfo->slice_mode = slice_mode;

	// Allocate space for the restore stack and also for storing some fw slice info
	extra_space_addr = sys_mmap_pgoff (0x80004000, STACK_SIZE + SLICE_INFO_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
	if (extra_space_addr != 0x80004000) {
		//a bug related to fine-grained code regions
		//okay... the correct fix is to load the extra_mmap_region file and reserve them...
		printk ("This is a hacky fix to avoid we mmap into the location that will be used by the slice later on; the assumption is that the this address is never used by the program.\n"); 
	}
	if (IS_ERR((void *) extra_space_addr)) {
		printk ("[ERROR] start_fw_slice: cannot allocate mem size %u\n", STACK_SIZE+SLICE_INFO_SIZE);
		return -ENOMEM;
	}
	//first page of this space: stack (grows downwards)
	MPRINT ("start_fw_slice stack is %lx to %lx\n", extra_space_addr, extra_space_addr + STACK_SIZE);

	//second page: extra info for the slice (grows upwards)
	pinfo->text_addr = slice_addr;
	pinfo->text_size = slice_size;
	pinfo->extra_addr = extra_space_addr;
	pinfo->extra_size = STACK_SIZE + SLICE_INFO_SIZE;

	//checkpoint the current registers
	memcpy (&pinfo->regs, regs, sizeof(struct pt_regs));
	pinfo->fpu_is_allocated = fpu_allocated (&(current->thread.fpu));
	if (pinfo->fpu_is_allocated) { 
		struct fpu* fpu = &(current->thread.fpu);
		pinfo->fpu_last_cpu = fpu->last_cpu;
		pinfo->fpu_has_fpu = fpu->has_fpu;
		memcpy (&pinfo->fpu_state, fpu->state, xstate_size);
	}
	copy_to_user ((char __user *) extra_space_addr + STACK_SIZE, pinfo, sizeof(struct fw_slice_info));
	KFREE (pinfo);

	//change instruction pointer to the start of slice
	get_user (entry, (unsigned int __user *) (slice_addr + 0x18));
	regs->ip = slice_addr + entry;
	//change stack pointer
	regs->sp = extra_space_addr + STACK_SIZE;

	printk ("pid %d start_fw_slice: slice_addr is %lx, stack is %lx, entry is %u, ip is %lx, extra_space is %lx with size %d\n", current->pid, slice_addr, regs->sp, entry, regs->ip, extra_space_addr, STACK_SIZE+SLICE_INFO_SIZE);
	DPRINT ("start_fw_slice gs is %lx\n", regs->gs);

	if (regs->gs == 0) {
		printk ("[BUG] fw slice probably won't work because checkpoint has not set the gs register\n");
	}

	//now push parameters to the stack; recheck_start function is added by process_slice.cpp
	if (recheck_filename) {
		strcpy (recheck_log_name, recheck_filename);
	} else {
		snprintf (recheck_log_name, RECHECK_FILE_NAME_LEN, "/replay_logdb/recheck");
	}

        DPRINT ("start_fw_slice: recheck filename %s\n", recheck_log_name);
                
        regs->sp -= RECHECK_FILE_NAME_LEN;
	copy_to_user ((char __user*) regs->sp, recheck_log_name, RECHECK_FILE_NAME_LEN);

        //address of the slice_clock
        regs->sp -= sizeof(long);
        put_user (user_clock_addr, (long __user*) regs->sp);
       	
	regs->bp = regs->sp;

	set_thread_flag (TIF_IRET);
	MPRINT ("Pid %d start_fw_slice stack pointer is %lx, bp is %lx\n", current->pid, regs->sp, regs->bp);

	return 0;
}

void dump_vmas_content(u_long prefix)
{
	mm_segment_t old_fs = get_fs();
	struct vm_area_struct* vma;
	char mmapinfo_filename[128];
	struct file* mmapinfo_file = NULL;
	int mmapinfo_fd = 0;
	loff_t mmapinfo_ppos = 0;

	set_fs (KERNEL_DS);
	strcpy (mmapinfo_filename, "/tmp/slice_vma_info");

	mmapinfo_fd = sys_open (mmapinfo_filename, O_WRONLY|O_CREAT|O_TRUNC, 0777);
	if (mmapinfo_fd < 0) {
		printk ("dump_vmas_content: open of %s returns %d\n", mmapinfo_filename, mmapinfo_fd);
		set_fs(old_fs);
		return;
	}

	mmapinfo_file = fget (mmapinfo_fd);
	set_fs (old_fs);

	down_read (&current->mm->mmap_sem);
	for (vma = current->mm->mmap; vma; vma = vma->vm_next) {
		char mmap_filename[256];
		char vma_filename[256];
		char buffer[256];
		struct file* mmap_file = NULL;
		int mmap_fd = 0;
		loff_t mmap_ppos = 0;
		long copied, nr_pages;
		u_long i;
		char* p;

		if (vma->vm_start == (u_long) current->mm->context.vdso) {
			printk ("dump_vmas_content: skip vdso %lx to %lx\n", vma->vm_start, vma->vm_end);
			continue; // Not in ckpt so do not save it
		}
		
		if(vma->vm_file) {
			char* p = d_path (&vma->vm_file->f_path, buffer, PATH_MAX);
			strcpy (mmap_filename, p);
		} else {
			mmap_filename[0] = '\0';
		}

		sprintf (buffer, "%08lx-%08lx: flags %lx pgoff %lx %s\n", vma->vm_start, vma->vm_end, vma->vm_flags, vma->vm_pgoff, mmap_filename);

		copied = vfs_write(mmapinfo_file, buffer, strlen(buffer), &mmapinfo_ppos);
		if (copied != strlen(buffer)) {
			printk ("dump_vmas_content: tried to write vma info, got rc %ld\n", copied);
		}

		if (!strncmp(mmap_filename, "/dev/zero", 9)) {
		    printk ("Skip /dev/zero %lx to %lx\n", vma->vm_start, vma->vm_end);
		    continue; /* Skip writing this one */
		}

		if (((vma->vm_flags&VM_MAYSHARE) && 
		     (strncmp(mmap_filename, WRITABLE_MMAPS,WRITABLE_MMAPS_LEN) && strncmp (mmap_filename, "/replay_cache/", 14)))) { //why is this in here...? 
			printk ("dump_vmas_content: skipped file %s, range %lx to %lx, flags read %ld, shared %ld\n", mmap_filename, vma->vm_start, vma->vm_end, vma->vm_flags & VM_READ, vma->vm_flags & VM_MAYSHARE);
			continue;
		}

		sprintf (vma_filename, "/tmp/slice_vma.%lu.%lx", prefix, vma->vm_start);
		set_fs (KERNEL_DS);
		mmap_fd = sys_open (vma_filename, O_WRONLY|O_CREAT|O_TRUNC, 0777);
		if (mmap_fd < 0) {
			printk ("dump_vmas_content: open of %s returns %d\n", mmap_filename, mmap_fd);
			up_read (&current->mm->mmap_sem);
			fput (mmapinfo_file);	
			sys_close (mmapinfo_fd);
			set_fs(old_fs);
			return;
		}

		mmap_file = fget (mmap_fd);
		set_fs (old_fs);

		if (!(vma->vm_flags&VM_READ)){
			struct vm_area_struct *prev = NULL;
			// force it to readable temproarilly
			//sys_mprotect won't work here
			long rc = mprotect_fixup (vma, &prev, vma->vm_start, vma->vm_end, vma->vm_flags | VM_READ); 
			printk ("Pid %d change region to readable file %s, range %lx to %lx, flags read %ld, shared %ld\n", current->pid, mmap_filename, vma->vm_start, vma->vm_end, 
				vma->vm_flags & VM_READ, vma->vm_flags & VM_MAYSHARE);
			if (rc || prev != vma) { 
				printk ("dump_vmas_content: mprotect_fixup fails %ld\n", rc);
				fput (mmap_file);
				sys_close (mmap_fd);
				up_read (&current->mm->mmap_sem);
				fput (mmapinfo_file);	
				sys_close (mmapinfo_fd);
				set_fs(old_fs);
				return;
			}
		}
			
		nr_pages = (vma->vm_end - vma->vm_start)/PAGE_SIZE;
		set_fs(old_fs);
		p = (char *) vma->vm_start;
		for (i = 0; i < nr_pages; i++) {
		    copied = vfs_write(mmap_file, p, PAGE_SIZE, &mmap_ppos);
		    if (copied != PAGE_SIZE) {
			printk ("dump_vmas_content: tried to write vma data, got rc %ld instead of %ld\n", copied, PAGE_SIZE);
		    }
		    p += PAGE_SIZE;
		}
		set_fs(KERNEL_DS);

		fput (mmap_file);
		sys_close (mmap_fd);

		if (!(vma->vm_flags&VM_READ)) {
			struct vm_area_struct *prev = NULL;
			long rc = mprotect_fixup (vma, &prev, vma->vm_start, vma->vm_end, vma->vm_flags); 
			if (rc || prev != vma) { 
				printk ("Pid %d replay_full_checkpoint_hdr_to_disk: mprotect_fixup fails rc=%ld\n", current->pid, rc);
			}
		}

	}

	up_read (&current->mm->mmap_sem);
	fput (mmapinfo_file);	
	sys_close (mmapinfo_fd);
	set_fs(old_fs);
}

asmlinkage long sys_execute_fw_slice (int finish, long arg2, long arg3)
{ 
	if (!slice_handling_initialized) {
		init_slice_handling();
	}

	if (finish == 0) { 
		// Depricated
		return -EINVAL;

	} else if (finish == 1) {
		//finish executing the slice and restore register states
		long rc = 0;
		//struct mm_info* pmminfo = &mm_info;
		struct pt_regs* regs = get_pt_regs (current);
		struct fw_slice_info __user * slice_info = NULL;
		struct pt_regs* regs_cache = NULL;
		struct timeval tv;

		long is_ckpt_thread = regs->cx; // See below
		long slice_retval = 0;
		if (is_ckpt_thread) {
		    slice_retval = regs->dx; // This is arg3, but we are going to change this later (compiler gets confused and optimizes incorrectly?)
		} 
		MPRINT ("pid %d finishes slice, ckpt_thread=%ld, retval=%ld\n", current->pid, is_ckpt_thread, slice_retval);

                if (PRINT_TIME) {
                        do_gettimeofday (&tv);
                        printk ("Pid %d sys_execute_fw_slice is called %ld.%06ld\n", current->pid, tv.tv_sec, tv.tv_usec);
                }
		slice_info = get_fw_slice_info (regs);
		regs_cache = &slice_info->regs;
		memcpy (regs, regs_cache, sizeof(struct pt_regs));
		MPRINT ("Registers after slice executes %d\n", current->pid);
		dump_reg_struct (get_pt_regs(NULL));
		if (!is_ckpt_thread) {
		    slice_retval = regs->orig_ax; // We are restarting the system call, so presumably we should reset this register to orig value
		}
		if (slice_info->fpu_is_allocated) { 
			struct fpu* fpu = &(current->thread.fpu);
			fpu->last_cpu = slice_info->fpu_last_cpu;
			fpu->has_fpu = slice_info->fpu_has_fpu;
			memcpy (fpu->state, &slice_info->fpu_state, xstate_size);
		}
		set_thread_flag (TIF_IRET);

		if (slice_dump_vm) {
			if (is_ckpt_thread) {
				dump_vmas_content (0);
				if (current->go_live_thrd) {
					wake_up_vm_dump_waiters (current->go_live_thrd);
				}
			} else {
				if (current->go_live_thrd) {
					wait_for_vm_dump (current->go_live_thrd);
				}
			}
		}

		//unmap the slice - doing this during the dump will cause process to hang
		if (slice_info->slice_mode != 0) {
			printk ("OKay... let's also ignore the step to unload the slice; do this in the user level.\n");
			//in this case, we're definitely accelerating the fine code regions and the system call we need to restart right after the slice is a sys_jumpstart_runtime call; here we return the address of the slice dl handler so we can safely unload the slice
			slice_retval = 1;
		} else {
			rc = sys_munmap (slice_info->text_addr, slice_info->text_size);
			if (rc != 0) { 
				printk ("sys_execute_fw_slice: cannot munmap");
				return -1;
			}
		}
		rc = sys_munmap (slice_info->extra_addr, slice_info->extra_size);
		if (rc != 0) { 
			printk ("sys_execute_fw_slice: cannot munmap");
			return -1;
		}

		if (current->go_live_thrd) {
			put_go_live_thread (current->go_live_thrd);
			current->go_live_thrd = NULL;
		}

		if (is_ckpt_thread) {
			struct rusage ru;
			mm_segment_t old_fs = get_fs();
			set_fs (KERNEL_DS);
			sys_getrusage (RUSAGE_SELF, &ru);
			set_fs (old_fs);
			do_gettimeofday (&tv);
			printk ("Pid %d end execute_slice %ld.%06ld, user %ld kernel %ld\n", current->pid, tv.tv_sec, tv.tv_usec, ru.ru_utime.tv_usec, ru.ru_stime.tv_usec);

			if (pause_after_slice) {
				printk ("Pausing so you can attach gdb to pid %d\n", current->pid);
				set_current_state(TASK_INTERRUPTIBLE);
				schedule();
				printk("Pid %d woken up.\n", current->pid);
			}
		}

		printk ("Pid %d returning %ld\n", current->pid, slice_retval);
		return slice_retval;

	} else if (finish == 2) {

		struct slice_task* pstask;
		long retval;

		char __user* filename = (char __user *) arg2;

		if (PRINT_TIME) {
		    struct timeval tv;
		    do_gettimeofday (&tv);
		    printk ("slice fails check at %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
		}
		{
			printk ("let's skip recovery for now.\n");
			return 0;
		}

		pstask = KMALLOC (sizeof(struct slice_task), GFP_KERNEL);
		if (pstask == NULL) {
			printk ("sys_execute_fw_slice: cannot allocate slice task\n");
			return -ENOMEM;
		}

		retval = strncpy_from_user(pstask->recheck_filename, filename, sizeof(pstask->recheck_filename));
		if (retval < 0) {
			printk ("sys_execute_fw_slice: strncpy_from_user returns %ld\n", retval);
			return -EINVAL;
		}
		DPRINT ("recheck_filename is %s\n", pstask->recheck_filename);

		pstask->slice_pid = current->pid;
		mutex_lock(&slice_task_mutex);
		list_add(&pstask->list, &slice_task_list);
		wake_up (&daemon_waitq);
		mutex_unlock(&slice_task_mutex);
		
		//if (PRINT_TIME) {
		{
			struct timespec tp;
			getnstimeofday(&tp);
			printk ("Pid %d sleeping to generate correct memory state at %ld.%09ld\n", current->pid, tp.tv_sec, tp.tv_nsec);
		}

		//xdou: for some reason, emacs can't sleep with schhedule() if we have a divergence in the middle; because of signal? 
		set_current_state(TASK_INTERRUPTIBLE);
		schedule(); 
		printk ("Pid %d returns from schedule\n", current->pid);
		if (PRINT_TIME) {
		    struct timeval tv;
		    do_gettimeofday (&tv);
		    printk ("Pid %d woken up and going live after recovery at %ld.%06ld\n", current->pid, tv.tv_sec, tv.tv_usec);
		}

		// We should have correct address space and register values now
		set_thread_flag (TIF_IRET); // Make sure we restore the new registers

		//also wakeup all threads as they could be waiting on recheck_thread_wait in the slice (which uses futex calls)

#ifdef JAVA_FIX_PTHREAD
		do {
			int num_threads = 0;
			struct go_live_clock* go_live_clock = get_go_live_clock (current);

			get_user (num_threads, (int __user*) &go_live_clock->num_threads);
			printk ("Pid %d starts to wake up all threads, go_live_clock addr %p, num_threads %d\n", current->pid, go_live_clock, num_threads);
			if (go_live_clock) { 
				int i = 0;
				for (; i < num_threads; ++i) { 
					int ret = sys_futex ((u32 __user*) &go_live_clock->process_map[i].wait, FUTEX_WAKE, 99, NULL, NULL, 0);
					printk ("Pid %d Waking up pid %d record pid %d, ret %d, addr %p\n", current->pid, go_live_clock->process_map[i].current_pid, go_live_clock->process_map[i].record_pid, ret, &go_live_clock->process_map[i].wait);
				}
			}
		} while (0);
#endif

		//TODO: free up the go_live_thrd, replay_group etc. for this thread; memory leaks

	
		return get_pt_regs(current)->orig_ax; // We stuffed actual return value in here.

	} else if (finish == 3) {

		struct slice_task* pstask;
		long retval;
		
		char __user* filename = (char __user *) arg2;

		DPRINT ("Slice daemon thread %d registered for upcall\n", current->pid);

		mutex_lock(&slice_task_mutex);
		while (list_empty (&slice_task_list)) {
			mutex_unlock(&slice_task_mutex);
			wait_event_interruptible (daemon_waitq, !list_empty (&slice_task_list));
			if (signal_pending(current)) {
				DPRINT ("Daemon wait interrupted by signal\n");
				return -EINTR;
			}
			mutex_lock(&slice_task_mutex);
		}
		pstask = list_first_entry (&slice_task_list, struct slice_task, list);
		list_del (&pstask->list);
		pstask->daemon_pid = current->pid;
		list_add(&pstask->list, &slice_processing_list);
		mutex_unlock(&slice_task_mutex);

		DPRINT ("Slice daemon thread %d gets task pid %d recheck file %s\n", current->pid, pstask->slice_pid, pstask->recheck_filename);
		retval = copy_to_user (filename, pstask->recheck_filename, sizeof(pstask->recheck_filename));
		if (retval < 0) {
			printk ("sys_execute_fw_slice: copy_to_user returns %ld\n", retval);
			return -EINVAL;
		}

	} else if (finish == 4) {

		long retval = arg3;
		if (retval < 0) {
			// Slice deamon reports success or failure here
			// If failure, responsible for cleanup here
			struct slice_task* pstask;
			struct task_struct* tsk;
			int found = 0;
			
			mutex_lock(&slice_task_mutex);
			list_for_each_entry (pstask, &slice_processing_list, list) {		
				if (pstask->daemon_pid == current->pid) {
					list_del(&pstask->list);
					found = 1;
					break;
				}
			}
			mutex_unlock(&slice_task_mutex);
			if (!found) {
				printk ("Cannot find slice task for damon pid %d\n", current->pid);
				return -1;
			}
			
			DPRINT ("Recovery failure reported by pid %d\n", current->pid);
			DPRINT ("Killing task %d\n", pstask->slice_pid);
			sys_kill (9, pstask->slice_pid); // Terminate the sleeping task
			tsk = find_task_by_vpid(pstask->slice_pid);
			if (!tsk) {
				printk ("sys_execute_fw_slice: cannot find target slice pid %d\n", pstask->slice_pid);
			}
			wake_up_process (tsk);
			KFREE (pstask);
		}
	}
	return 0;
}

void fw_slice_recover (pid_t daemon_pid, long retval)
{
	struct mm_struct* tmp_mm;
	struct task_struct* tsk;
	//struct fpu* fpu, *tsk_fpu;
	struct task_rss_stat tmp_stat;
	pid_t slice_pid = 0;
	int i;
	int __user* hack_addr = NULL;

	// Find the task in the list
	struct slice_task* pstask;
	mutex_lock(&slice_task_mutex);
	list_for_each_entry (pstask, &slice_processing_list, list) {		
		if (pstask->daemon_pid == daemon_pid) {
			slice_pid = pstask->slice_pid;
			list_del(&pstask->list);
			KFREE (pstask);
			break;
		}
	}
	mutex_unlock(&slice_task_mutex);
	{
		struct timespec tp;
		getnstimeofday(&tp);
		printk ("Pid %d, deamon pid %d  fw_slice_recover enters %ld.%09ld\n", current->pid, daemon_pid, tp.tv_sec, tp.tv_nsec);
	}

	if (slice_pid == 0) {
		printk ("fw_slice_recover: cannot find slice pid corresponding to deamon pid %d\n", daemon_pid);
		sys_exit_group (0);
	}

	tsk = find_task_by_vpid(slice_pid);
	if (!tsk) {
		printk ("fw_slice_recover: cannot find target slice pid %d\n", slice_pid);
		sys_exit_group (0);  
	}
	DPRINT ("fw_slice_recover: found slice task %d\n", slice_pid);

	if (replay_debug) {
		// Debug info - let's print out the vmas of source and dest
		printk ("VMAs for source task %d\n", current->pid);
		print_vmas (current);
		printk ("VMAs for destination task %d\n", tsk->pid);
		print_vmas (tsk);
		for (i = 0; i < NR_MM_COUNTERS; i++) {
			printk ("RSS counter %d for source %d: %d\n", i, current->pid, current->rss_stat.count[i]);
		}
		for (i = 0; i < NR_MM_COUNTERS; i++) {
			printk ("RSS counter %d for destination %d: %d\n", i, tsk->pid, tsk->rss_stat.count[i]);
		}
	}

#ifdef JAVA_FIX_PTHREAD
        #if 0
	//java hack
	printk ("Hacking: put the PTHREAD_LOG_OFF in the user space.\n");
	hack_addr = (int __user*) 0xb7e211f8;
	put_user (3, hack_addr);
	hack_addr = (int __user*) 0xb7fc3448;
	put_user (3, hack_addr);
        #endif

	//this is the shared clock region where go_live_clock struct lives
	//This is to mantain the correct futex states used by recheck_thread_wait/wakeup in recheck_support.c; these futexes are shared across processes, so just copying the content won't work (check get_futex_key in kernel/futex.c)
	MPRINT ("fw_slice_recover: copying the shared clock region\n");
	down_write (&current->mm->mmap_sem);
	do { 
		struct vm_area_struct* vma;
		int swapped = 0;
		vma = current->mm->mmap;
		while (vma) { 
			if (vma->vm_file) { 
				char buf[256];
				char* s = d_path (&vma->vm_file->f_path, buf, sizeof(buf));
				if (!strncmp (s, "/run/shm/uclock", 15)) { 
					struct vm_area_struct* swap_vma = NULL;
					int found = 0;
					MPRINT ("Pid %d fw_slice_recover found the shared clock region (go_live_clock region) %lx, name %s\n", current->pid, vma->vm_start, s);

					//make sure the recover thread has the same info at this address
					down_write (&tsk->mm->mmap_sem);
					swap_vma = tsk->mm->mmap;
					while (swap_vma) {
						if (swap_vma->vm_start == vma->vm_start) {
							s = d_path (&swap_vma->vm_file->f_path, buf, sizeof(buf));
							MPRINT ("Found the matching region, name %s\n", s);
							found = 1;
							break;
						}
						swap_vma = swap_vma->vm_next;
					}

					if (found == 0) {
						printk ("[BUG] cannot find the matching shared clock region.\n");
					} else {
						if (swap_vma->vm_end-swap_vma->vm_start != PAGE_SIZE) { 
							printk ("[BUG] the shared clock region is not a single page?\n");
						} else { 
							//try to mmap the shared clock region, forcing the live thread and recovery thread to use the same page...stupid futex...
							int fd = 0;
							long rc = 0;
							mm_segment_t old_fs = get_fs();
							do_munmap (current->mm , vma->vm_start, PAGE_SIZE);
							set_fs (KERNEL_DS);
							fd = sys_open (s, O_RDWR | O_NOFOLLOW, 0644);
							up_write (&current->mm->mmap_sem);
							rc = sys_mmap_pgoff (vma->vm_start, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, fd, 0);
							down_write (&current->mm->mmap_sem);
							sys_close (fd);
							set_fs (old_fs);
						}

					}
					up_write (&tsk->mm->mmap_sem);
					swapped = 1;
					break;
				}
			}
			vma = vma->vm_next;
		}
		if (swapped == 0) { 
			printk ("Pid %d fw_slice_recover not swapping the shared clock region? could be correct for single-threaded program\n", current->pid);
		}
	} while (0);
	up_write (&current->mm->mmap_sem);
#endif

	// Our address spaces should be identical
	// Move memory from this task to the sleeping task
	// Wouldn't it be neat if this worked?  But, it probably won't ... in which case we can copy (sigh)
	tmp_mm = current->mm;
	current->mm = current->active_mm = tsk->mm;
	tsk->mm = tsk->active_mm = tmp_mm;
	tsk->mm->owner = tsk;
	current->mm->owner = current;

	tmp_stat = current->rss_stat;
	current->rss_stat = tsk->rss_stat;
	tsk->rss_stat = tmp_stat;

	DPRINT ("fw_slice_recover: swapped address spaces\n");

	//Swap registers states for other threads
	//this function is defined in replay.c; it uses struct replay_thread etc.
	fw_slice_recover_swap_register (tsk);

	// Change register state in sleeping task to match this one
	DPRINT ("Current esi register %lx target esi register %lx\n", get_pt_regs(current)->si, get_pt_regs(tsk)->si);
	DPRINT ("Target esi register now %lx\n", get_pt_regs(tsk)->si);
	DPRINT ("Changing return value in eax %ld to %ld\n", get_pt_regs(tsk)->orig_ax, retval);
	get_pt_regs(tsk)->orig_ax = retval; // This is what we want to return from the kernel - will be returned in eax


	MPRINT ("fw_slice_recover: modified registers - about to wake up pid %d\n", tsk->pid);

	{
		struct timespec tp;
		getnstimeofday(&tp);
		printk ("Pid %d, deamon pid %d  fw_slice_recover exits %ld.%09ld\n", current->pid, daemon_pid, tp.tv_sec, tp.tv_nsec);
	}

	// Wake up the sleeping task
	wake_up_process (tsk);

	//TODO: free up the replay_group/replay_thrd or go_live_thrd here for both this task and the recovred task
	// I couldn't find an elegant way to destroy the them...

	sys_exit_group (0);  // No longer need this task
}
