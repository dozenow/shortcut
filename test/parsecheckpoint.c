#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include "util.h"
#include <assert.h>

//copyed from kernel
#define PATH_MAX 4096
#define AT_VECTOR_SIZE 44
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
	char exe_file[PATH_MAX];
};

struct ckpt_data {
	u_long proc_count;
	uint64_t  rg_id;
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

struct pt_regs {
	unsigned long bx;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long bp;
	unsigned long ax;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};
struct user_desc {
	unsigned int  entry_number;
	unsigned int  base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit:1;
	unsigned int  contents:2;
	unsigned int  read_exec_only:1;
	unsigned int  limit_in_pages:1;
	unsigned int  seg_not_present:1;
	unsigned int  useable:1;
#ifdef __x86_64__
	unsigned int  lm:1;
#endif
};

#define xstate_size 832 //should be the same as the size of union thread_xstate, not verified on other machines
#define GDT_ENTRY_TLS_ENTRIES 3
//end copyed from kernel

struct proc_info {
	int parent_pid;
	int record_pid;
	int is_thread;
	int is_main_thread;
	int ckpt_pos;
};
struct proc_info* all_proc_info;

int restore_ckpt_tsks_header (u_long num_procs, int cfile)
{
	int i, copyed, unused; 
	all_proc_info = malloc (sizeof (struct proc_info)*num_procs);
	for (i = 0; i < num_procs; ++i) { 
		struct proc_info* info = &all_proc_info[i];
		copyed = read(cfile, (char *) &unused, sizeof(unused));
		if (copyed != sizeof(unused)) {
			printf ("restore_replay_cache_files: tried to write parent_pid, got rc %d\n", copyed);
			return -1;
		}
		printf("\t%d ",unused);
		info->parent_pid = unused;
		copyed = read(cfile, (char *) &unused, sizeof(unused));
		if (copyed != sizeof(unused)) {
			printf ("restore_replay_cache_files: tried to write record_pid, got rc %d\n", copyed);
			return -1;
		}
		info->record_pid = unused;
		printf("%d ",unused);
		copyed = read(cfile, (char *) &unused, sizeof(unused));
		if (copyed != sizeof(unused)) {
			printf ("restore_replay_cache_files: tried to write is_thread, got rc %d\n", copyed);
			return -1;
		}
		info->is_thread = unused;
		printf(" is_thread %d ",unused);
		copyed = read(cfile, (char *) &unused, sizeof(unused));
		if (copyed != sizeof(unused)) {
			printf ("restore_replay_cache_files: tried to write is_main_thread got rc %d\n", copyed);
			return -1;
		}
		info->is_main_thread = unused;
		printf(" is_main_thread %d ",unused);
		copyed = read(cfile, (char *) &unused, sizeof(unused));
		if (copyed != sizeof(unused)) {
			printf ("restore_replay_cache_files: tried to write ckpt_pos, got rc %d\n", copyed);
			return -1;
		}		
		info->ckpt_pos = unused;
		printf("%d\n", unused);
	}       
}

int restore_xray_monitor(int cfile) { 

	int copyed, cnt, fd, type, data, size, i;
	char channel[256]; 

	copyed = read(cfile, (char *) &cnt, sizeof(cnt));
	if (copyed != sizeof(cnt)) {
		printf ("restore_replay_cache_files: tried to read count, got rc %d\n", copyed);
		return copyed;
	}
	for (i = 0; i < cnt; i++) {

		copyed = read(cfile, (char *) &fd, sizeof(fd));
		if (copyed != sizeof(fd)) {
			printf ("restore_xray_monitor: tried to read fd, got rc %d\n", copyed);
			return copyed;
		}
		copyed = read(cfile, (char *) &type, sizeof(fd));
		if (copyed != sizeof(type)) {
			printf ("restore_xray_monitor: can't read type, got rc %d\n", copyed);
			return copyed;
		}
		copyed = read(cfile, (char *) &data, sizeof(fd));
		if (copyed != sizeof(data)) {
			printf ("restore_xray_monitor: can't read data, got rc %d\n", copyed);
			return copyed;
		}
		copyed = read(cfile, (char *) &size, sizeof(size));
		if (copyed != sizeof(size)) {
			printf ("restore_xray_monitor: can't read chsize, got rc %d\n", copyed);
			return copyed;
		}

		if (size > 0) { 
			copyed = read(cfile, channel, size);
			if (copyed != size) {
				printf ("restore_xray_monitor: can't read channel, got rc %d\n", copyed);
				return copyed;
			}
			channel[size] = '\0';
			
		}		
	}	       
	return 0;
}

int
restore_sysv_mappings (int cfile)
{
	int copyed, cnt, recid, repid, key, shmflg, i;
	size_t size;

	copyed = read(cfile, (char *) &cnt, sizeof(cnt));
	if (copyed != sizeof(cnt)) {
		printf ("restore_replay_cache_files: tried to read count, got rc %d\n", copyed);
		return copyed;
	}
	printf ("\t restore_sysv_mappings count %d\n", cnt);
	for (i = 0; i < cnt; i++) {

		copyed = read(cfile, (char *) &recid, sizeof(recid));
		if (copyed != sizeof(recid)) {
			printf ("restore_sysv_mappings: tried to read recid, got rc %d\n", copyed);
			return copyed;
		}
		copyed = read(cfile, (char *) &key, sizeof(key));
		if (copyed != sizeof(key)) {
			printf ("restore_sysv_mappings: tried to read key, got rc %d\n", copyed);
			return copyed;
		}
		copyed = read(cfile, (char *) &size, sizeof(size));
		if (copyed != sizeof(size)) {
			printf ("restore_sysv_mappings: tried to read key, got rc %d\n", copyed);
			return copyed;
		}
		copyed = read(cfile, (char *) &shmflg, sizeof(shmflg));
		if (copyed != sizeof(shmflg)) {
			printf ("restore_sysv_mappings: tried to read key, got rc %d\n", copyed);
			return copyed;
		}
	}
	return 0;
}

int
restore_replay_cache_files (int cfile)
{
	int fd = -1, cnt, len, copyed, i, rc, val;
	char* buffer;
	loff_t pos;

	copyed = read(cfile, (char *) &cnt, sizeof(cnt));
	if (copyed != sizeof(cnt)) {
		printf ("restore_replay_cache_files: tried to read count, got rc %d\n", copyed);
		return copyed;
	}
	printf ("\t restore_replay_cache_files: %d files in checkpoint\n", cnt);

	for (i = 0; i < cnt; i++) {
		copyed = read(cfile, (char *) &val, sizeof(val));
		if (copyed != sizeof(val)) {
			printf ("restore_replay_cache_files: tried to read fd val, got rc %d\n", copyed);
			return copyed;
		}

		copyed = read(cfile, (char *) &len, sizeof(len));
		if (copyed != sizeof(len)) {
			printf ("restore_replay_cache_files: tried to read count, got rc %d\n", copyed);
			return copyed;
		}
		
		buffer = malloc (len+1);
		if (!buffer) {
			printf ("restore_replay_chache_files: cannot allocate memory\n");
			return -1;
		}
		copyed = read(cfile, (char *) buffer, len);
		if (copyed != len) {
			printf ("restore_replay_cache_files: tried to read filename, got rc %d\n", copyed);
			free (buffer);
			return copyed;
		}
		printf ("\t      file %s\n", buffer);
		free (buffer);
		copyed = read (cfile, &pos, sizeof(pos));
		assert (copyed == sizeof(pos));
		
	}
	return 0;
}



int main (int argc, char* argv[]) 
{
	int fd = 0;
	struct ckpt_proc_data cpdata;
	struct ckpt_data cdata;
	int rc;
	int count = 0;
	struct pt_regs regs;
	char fpu_allocated;
	char buffer[4096];
	int mm_region_fd = 0;
	u_long start_addr = 0, end_addr = 0;

	if (argc != 2 && argc != 3) { 
		printf ("format: parsecheckpoint checkpoint_file [-g]\n");
		exit (EXIT_FAILURE);
	}
	if (argc == 3) { 
		if (!strcmp (argv[2], "-g")) {
			char filename[256];
			snprintf (filename, 256, "%s.mm", argv[1]); 
			mm_region_fd = open (filename, O_RDWR|O_TRUNC|O_CREAT, 0644);
			if (mm_region_fd < 0) { 
				perror ("open");
				exit (mm_region_fd);
			}
		}
	}
	fd = open (argv[1], O_RDONLY);
	if (fd < 0) { 
		perror ("open");
		exit (fd);
	}
	rc = read (fd, &cdata, sizeof(cdata));
	assert (rc == sizeof(cdata));
	printf ("ckpt data:\n");
	printf ("\t proc count %lu, group %llu, clock %d\n", cdata.proc_count, cdata.rg_id, cdata.clock);
	restore_ckpt_tsks_header (cdata.proc_count, fd);
	restore_xray_monitor (fd);
	while (count < cdata.proc_count) { 
		struct proc_info* info; 
		int info_index = 0;
		int map_count;

		rc = read (fd, &cpdata, sizeof(cpdata));
		assert (rc == sizeof(cpdata));
		printf ("Ckpt proc data\n");
		printf ("\t record pid %d, retval %ld, pthreadclock %lu\n", cpdata.record_pid, cpdata.retval, cpdata.pthreadclock);
		rc = read (fd, &regs, sizeof(regs));
		assert (rc == sizeof(regs));
		printf ("\t registers info: ip %lx\n", regs.ip);
		restore_sysv_mappings (fd);
		rc = read (fd, &fpu_allocated, sizeof(char));
		assert (rc == sizeof(char));
		printf ("\t fpu allocated? %d\n", (int) fpu_allocated);
		if (fpu_allocated) { 
			rc = read (fd, buffer, sizeof (unsigned int) + sizeof (unsigned int) + xstate_size);
			assert (rc == sizeof(unsigned int) + sizeof (unsigned int) + xstate_size);
		}
		restore_sysv_mappings (fd);
		//get the cached info
		while (info_index < cdata.proc_count) {
			if (all_proc_info[info_index].record_pid == cpdata.record_pid) {
				info = &all_proc_info[info_index];
				break;
			}
			++ info_index;
		}
		if (!info->is_thread) {
			int i = 0;
			struct vma_stats pvmas;
			struct mm_info mm_info;

			restore_replay_cache_files (fd);
			rc = read (fd, &map_count, sizeof(int));
			assert (rc == sizeof(int));
			printf ("\t map count: %d\n", map_count);
			for (; i<map_count - 1; ++i) { 
				rc = read (fd, &pvmas, sizeof(pvmas));
				assert (rc == sizeof (pvmas));
				printf ("\t \t start %lx end %lx flags 0x%08x file %s\n", pvmas.vmas_start, pvmas.vmas_end, pvmas.vmas_flags, pvmas.vmas_file);
				if (mm_region_fd) {
					if (pvmas.vmas_start != end_addr) { 
						if (start_addr) { 
							rc = write (mm_region_fd, &start_addr, sizeof(start_addr));
							assert (rc == sizeof(start_addr));
							rc = write (mm_region_fd, &end_addr, sizeof(end_addr));
							assert (rc == sizeof(end_addr));
							printf ("---region: %lx %lx\n", start_addr, end_addr);
						}
						start_addr = pvmas.vmas_start;
						end_addr = pvmas.vmas_end;
					} else { 
						end_addr = pvmas.vmas_end;
					}
				}
			}
			rc = read (fd, &mm_info, sizeof(mm_info));
			assert (rc == sizeof(mm_info));
			printf ("\t\t start_brk %lx brk %lx\n", mm_info.start_brk, mm_info.brk);
			printf ("\t\t env_start %lx env_end %lx\n", mm_info.env_start, mm_info.env_end);
		}

		//ignore these structures for now; didn't bother to parse them
		rc = read (fd, buffer, sizeof(struct user_desc)*GDT_ENTRY_TLS_ENTRIES);
		assert (rc == sizeof(struct user_desc)*GDT_ENTRY_TLS_ENTRIES);
		rc = read (fd, buffer, sizeof(unsigned long)*2*16); //rlimit
		assert (rc == sizeof(unsigned long)*2*16);
		rc = read (fd, buffer, 20*64); //sig
		assert (rc == 20*64);
		//end ignore

		++count;
	}

	close (fd);
	if (mm_region_fd) close (mm_region_fd);
	return 0;
}
