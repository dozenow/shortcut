#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include "util.h"
#include <assert.h>
#include <stdint.h>
#include <sys/resource.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>

//copyed from kernel
#define PATH_MAX 4096
#define AT_VECTOR_SIZE 44
#define PCKPT_MAX_BUF 1024*1024

struct vma_stats {
	u_long vmas_start;
	u_long vmas_end;
	int    vmas_flags;
	u_long vmas_pgoff;
	char   vmas_file[PATH_MAX];
};

struct vma_stats* vms;
int vm_count;

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


struct pt_regs ckpt_regs;

#define xstate_size 832 //should be the same as the size of union thread_xstate, not verified on other machines; seems to be 832 on a VM and 512 on a physical machine
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

int parse_ckpt (char* filename, int pid)
{
	int ckpt_fd = 0;
	struct ckpt_proc_data cpdata;
	struct ckpt_data cdata;
	int rc;
	int count = 0;
	struct pt_regs regs;
	char fpu_allocated;
	char buffer[4096];
	u_long start_addr = 0, end_addr = 0;

	ckpt_fd = open (filename, O_RDONLY);
	if (ckpt_fd < 0) { 
		perror ("open");
		exit (ckpt_fd);
	}
	rc = read (ckpt_fd, &cdata, sizeof(cdata));
	assert (rc == sizeof(cdata));
	printf ("\t proc count %lu, group %llu, clock %d\n", cdata.proc_count, cdata.rg_id, cdata.clock);
	restore_ckpt_tsks_header (cdata.proc_count, ckpt_fd);
	restore_xray_monitor (ckpt_fd);
	while (count < cdata.proc_count) { 
		struct proc_info* info; 
		int info_index = 0;
		int map_count;

		rc = read (ckpt_fd, &cpdata, sizeof(cpdata));
		assert (rc == sizeof(cpdata));
		printf ("\t record pid %d, retval %ld, pthreadclock %lu\n", cpdata.record_pid, cpdata.retval, cpdata.pthreadclock);
		rc = read (ckpt_fd, &regs, sizeof(regs));
		assert (rc == sizeof(regs));
		printf ("\t registers info: ax %lx bx %lx cx %lx dx %lx ip %lx\n", regs.ax, regs.bx, regs.cx, regs.dx, regs.ip);
                if (pid == cpdata.record_pid) memcpy (&ckpt_regs, &regs, sizeof(regs));
		restore_sysv_mappings (ckpt_fd);
		rc = read (ckpt_fd, &fpu_allocated, sizeof(char));
		assert (rc == sizeof(char));
		if (fpu_allocated) { 
			rc = read (ckpt_fd, buffer, sizeof (unsigned int) + sizeof (unsigned int) + xstate_size);
			assert (rc == sizeof(unsigned int) + sizeof (unsigned int) + xstate_size);
		}
		restore_sysv_mappings (ckpt_fd);
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

			restore_replay_cache_files (ckpt_fd);
			rc = read (ckpt_fd, &map_count, sizeof(int));
			assert (rc == sizeof(int));
                        vm_count = map_count - 1;
                        if (cpdata.record_pid == pid) 
                            vms = (struct vma_stats*) malloc (sizeof(struct vma_stats)*vm_count);
			printf ("\t map count: %d\n", map_count);
			for (; i<map_count - 1; ++i) { 
				rc = read (ckpt_fd, &pvmas, sizeof(pvmas));
				assert (rc == sizeof (pvmas));
                                if (cpdata.record_pid == pid) {
                                    printf ("\t \t start %lx end %lx flags 0x%08x file %s\n", pvmas.vmas_start, pvmas.vmas_end, pvmas.vmas_flags, pvmas.vmas_file);
                                    memcpy (vms + i, &pvmas, sizeof(pvmas));
                                }
			}
			rc = read (ckpt_fd, &mm_info, sizeof(mm_info));
			assert (rc == sizeof(mm_info));
		}

		//ignore these structures for now; didn't bother to parse them
		rc = read (ckpt_fd, buffer, sizeof(struct user_desc)*GDT_ENTRY_TLS_ENTRIES);
		assert (rc == sizeof(struct user_desc)*GDT_ENTRY_TLS_ENTRIES);
		rc = read (ckpt_fd, buffer, sizeof(unsigned long)*2*16); //rlimit
		assert (rc == sizeof(unsigned long)*2*16);
		rc = read (ckpt_fd, buffer, 20*64); //sig
		assert (rc == 20*64);
		//end ignore

		++count;
	}

	close (ckpt_fd);
	return 0;
}

int open_ckpt_mmap_file (char* ckpt_base_name, struct vma_stats* pvmas) {
    char filename[256];
    sprintf (filename, "%s.ckpt_mmap.%lx", ckpt_base_name, pvmas->vmas_start);
    printf ("opening %s\n", filename);

    int ret = open (filename, O_RDONLY); 
    assert (ret > 0);
    return ret;
}

int main (int argc, char* argv[])
{
    char buf[PCKPT_MAX_BUF];
    char filename[4096];
    int fd, i;
    int reg_index = 0;
    unsigned long reg_value;
    int len = 0;
    int offset = 0;
    unsigned int regcount = 0;
    if (argc != 4) {
	printf ("format (parsing the patch based ckpt): parsepckpt <dir> <ckpt_file> <pid>\n");
	return -1;
    }

    char* ckpt_base_name = argv[2];
    parse_ckpt (argv[2], atoi(argv[3]));
    int output_fd = open ("/tmp/pckpt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    assert (output_fd > 0);

    sprintf (filename, "%s/pckpt", argv[1]);
    fd = open (filename, O_RDONLY);
    if (fd < 0) {
	perror ("open");
	return fd;
    }

    len = read (fd, &regcount, sizeof (unsigned int)); 
    assert (len == sizeof (unsigned int));
    len = write (output_fd, &regcount, sizeof (unsigned int));
    assert (len == sizeof (unsigned int));
    len = read (fd, buf, regcount * (sizeof(unsigned int) + sizeof (unsigned long)));
    assert (len == regcount* (sizeof(unsigned int) + sizeof (unsigned long)));
    len = write (output_fd, buf, regcount * (sizeof(unsigned int) + sizeof (unsigned long)));
    assert (len == regcount* (sizeof(unsigned int) + sizeof (unsigned long)));

    printf ("------checkpoint regs ------\n");
    offset = 0;
    for (i = 0; i<regcount; ++i) {
        reg_index = *((int*) (buf + offset));
        offset += sizeof (int);
        reg_value = *((unsigned long*) (buf + offset));
        offset += sizeof (unsigned long);
        if (reg_index != -1) 
            printf ("reg %d value %lu\n", reg_index, reg_value);
        else 
            printf ("skipped reg\n");
    } 

    printf ("edi %lu\n", ckpt_regs.di);
    printf ("esi %lu\n", ckpt_regs.si);
    printf ("ebp %lu\n", ckpt_regs.bp);
    printf ("esp %lu\n", ckpt_regs.sp);
    printf ("ebx %lu\n", ckpt_regs.bx);
    printf ("edx %lu\n", ckpt_regs.dx);
    printf ("ecx %lu\n", ckpt_regs.cx);
    printf ("eax %lu\n", ckpt_regs.ax);
    printf ("eip %lu\n", ckpt_regs.ip);
    printf ("eflags %lu\n", ckpt_regs.flags);

    printf ("------checkpoint mem------\n");
    int cur_size = 0;
    struct vma_stats* pvmas = vms; 
    int ckpt_fd = 0;
    while (1) {
        offset = 0;
        cur_size = 0;
        len = read (fd, (char*) &cur_size, sizeof (cur_size)); 
        if (len == 0) {
            break;
        }
        printf ("cur_size %d\n", cur_size);
        assert (len == sizeof (cur_size));
        len = write (output_fd, (char*) &cur_size, sizeof (cur_size));
        assert (len == sizeof (cur_size));
        while (offset < cur_size) {
            len = read (fd, buf + offset, cur_size - offset);
            assert (len > 0);
            offset += len;
        }
        offset = 0;
        while (offset < cur_size) {
            unsigned long start_addr = *((unsigned long*) (buf + offset));
            unsigned short int block_len  = 0;
            unsigned long mem_loc;
            unsigned char mem_value;
            int secondary_offset = 0;

            offset += sizeof (unsigned long);
            block_len = *((unsigned short int*) (buf + offset));
            //printf ("block_len %u, offset %d\n", block_len, offset);
            offset += sizeof(unsigned short);
            while (secondary_offset < block_len) {
                mem_loc = start_addr + secondary_offset;
                mem_value = *(buf + offset + secondary_offset);
                //read from ckpt file
                while (mem_loc < pvmas->vmas_start || mem_loc >= pvmas->vmas_end) {
                    ++ pvmas;
                    printf ("pvmas %lx\n", pvmas->vmas_start);
                    if (ckpt_fd) close (ckpt_fd);
                    ckpt_fd = 0;
                }
                if (ckpt_fd == 0) ckpt_fd = open_ckpt_mmap_file (ckpt_base_name, pvmas);
                lseek (ckpt_fd, mem_loc - pvmas->vmas_start, SEEK_SET);
                unsigned char compare_value;
                int cur_ret = read (ckpt_fd, &compare_value, 1);
                if (cur_ret != 1) 
                    printf ("cannot read for mem %lx\n", mem_loc);
                else if (mem_value != compare_value) {
                    printf ("mem 0x%lx value %u compare %u\n", mem_loc, (unsigned int) mem_value, (unsigned int) compare_value);
                    *(buf + offset + secondary_offset) = compare_value;
                }
                //end read
                ++ secondary_offset;
            }
            offset += secondary_offset;
        }

        //write out 
        offset = 0;
        while (offset < cur_size) {
            len = write (output_fd, buf + offset, cur_size - offset);
            assert (len > 0);
            offset += len;
        }
    }
    close (fd);
    close (output_fd);

    return 0;
}
