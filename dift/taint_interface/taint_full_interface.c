#include "../linkage_common.h"
#include "../taint_nw.h"
#include "../xray_slab_alloc.h"
#include "taint_interface.h"
#include "taint_creation.h"
#include <string.h>
#include <assert.h>
#include <glib-2.0/glib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "../mmap_regions.h"
#include <execinfo.h>

#include <map>
#include <algorithm>

using namespace std;
using namespace boost::icl;

#define USE_MERGE_HASH
#define TAINT_STATS

extern struct thread_data* current_thread;
extern pid_t first_thread;
extern int splice_output;
extern unsigned long global_syscall_cnt;
extern u_long* ppthread_log_clock;

#define LEAF_TABLE_SIZE  1024
#define ROOT_TABLE_SIZE 4194304
#define ROOT_TABLE_BITS 22
#define LEAF_TABLE_BITS 10
#define ROOT_INDEX_MASK 0xfffffc00
#define LEAF_INDEX_MASK 0x000003ff

taint_t* mem_root[ROOT_TABLE_SIZE];  // Top-level table for memory taints
struct slab_alloc leaf_table_alloc;

// #define LOGGING_ON
#ifdef LOGGING_ON
#define TAINT_START(name) \
    fprintf(stderr, "%s start\n", name);
#else
#define TAINT_START(x,...);
#endif

// Use this for extra control flow tracking debugging
//#define CFDEBUG(x,...);
#define CFDEBUG(x,...) fprintf(stderr, x, ## __VA_ARGS__)
 
// File-descriptor tainting
// A mapping of open fds to taint values.
// We do this mapping manually because some system calls, like select use a bitmap to
// track sets of fds. Our fidelty of taint-tracking, however, doesn't extend to bit
// levels.
GHashTable* taint_fds_table = NULL;
GHashTable* taint_fds_cloexec = NULL;

#define CHECK_TYPE_MMAP_REGION          0
#define CHECK_TYPE_RANGE                1
#define CHECK_TYPE_SPECIFIC_RANGE       2
#define CHECK_TYPE_RANGE_WRITE          3
#define CHECK_TYPE_SPECIFIC_RANGE_WRITE 4

struct taint_check {
    int type;
    u_long value;
    u_long size;
};

map<ADDRINT,taint_check> check_map;
map<u_long,syscall_check> syscall_checks;
vector<struct ctrl_flow_param> ctrl_flow_params;
vector<struct check_syscall> ignored_syscall;
vector<u_long> ignored_inst;
boost::icl::interval_set<unsigned long> address_taint_set;

#ifdef TAINT_STATS
struct taint_stats_profile {
    unsigned long num_second_tables;
    unsigned long num_third_tables;
    unsigned long merges;
    unsigned long merges_saved;
    unsigned long options;
};
struct taint_stats_profile tsp;
#endif

struct slab_alloc leaf_alloc;
struct slab_alloc node_alloc;

// use taint numbers instead
taint_t taint_num;
int node_num_fd = -1;

// Strategy for merge log is to put the first n bytes in named shared memory (fast)
// If this is too small, use an on-disk file for the overlow data (slow)
struct taint_number {
    taint_t p1;
    taint_t p2;
};


//ARQUINN: the control_info

struct merge_buffer_control { 
  u_long merge_buffer_count;
  u_long merge_total_count;
    bool merge_buf_overflow;
};

extern u_long num_merge_entries;
#define MERGE_FILE_ENTRIES 0x100000
#define MERGE_FILE_CHUNK (MERGE_FILE_ENTRIES*sizeof(struct taint_number))


static struct taint_number* merge_buffer;
/*
 * added for the shared merge_buffer control info accross replaying 
 * processes. 
 */

static struct merge_buffer_control * merge_control_shm;

#ifdef USE_SHMEM
// This is the most we can process in a 32-bit VM
#define MAX_MERGES (MAX_MERGE_SIZE/sizeof(struct taint_number))
#endif


#ifdef USE_NW
extern int s;
#endif
extern int outfd;

static inline const char* regName (uint32_t reg_num, uint32_t reg_size)
{
    switch (reg_num) {
    case 3:
	switch (reg_size) {
	case 4: return "edi";
	case 2: return "di";
	}
	break;
    case 4:
	switch (reg_size) {
	case 4: return "esi";
	case 2: return "si";
	}
	break;
    case 5:
	switch (reg_size) {
	case 4: return "ebp";
	case 2: return "bp";
	}
	break;
    case 6:
	switch (reg_size) {
	case 4: return "esp";
	case 2: return "sp";
	}
	break;
    case 7:
	switch (reg_size) {
	case 4: return "ebx";
	case 2: return "bx";
	case 1: return "bl";
	case -1: return "bh";
	}
	break;
    case 8:
	switch (reg_size) {
	case 4: return "edx";
	case 2: return "dx";
	case 1: return "dl";
	case -1: return "dh";
	}
	break;
    case 9:
	switch (reg_size) {
	case 4: return "ecx";
	case 2: return "cx";
	case 1: return "cl";
	case -1: return "ch";
	}
	break;
    case 10:
	switch (reg_size) {
	case 4: return "eax";
	case 2: return "ax";
	case 1: return "al";
	case -1: return "ah";
	}
	break;
    case 17:
	switch (reg_size) {
	case 4: return "eflag";
	}
	break;
    case 54:
	switch (reg_size) {
	case 16: return "xmm0";
	}
	break;
    case 55:
	switch (reg_size) {
	case 16: return "xmm1";
	}
	break;
    case 56:
	switch (reg_size) {
	case 16: return "xmm2";
	}
	break;
    case 57:
	switch (reg_size) {
	case 16: return "xmm3";
	}
	break;
    case 58:
	switch (reg_size) {
	case 16: return "xmm4";
	}
	break;
    case 59:
	switch (reg_size) {
	case 16: return "xmm5";
	}
	break;
    case 60:
	switch (reg_size) {
	case 16: return "xmm6";
	}
	break;
    case 61:
	switch (reg_size) {
	case 16: return "xmm7";
	}
	break;
    }
    fprintf (stderr, "regName: unrecognized reg %d size %d\n", reg_num, reg_size);
    assert (0);
    return NULL;
}

static void taint_reg2reg (int dst_reg, int src_reg, uint32_t size);
static UINT32 get_mem_value32 (u_long mem_loc, uint32_t size);
static inline int is_mem_tainted (u_long mem_loc, uint32_t size);
static inline int is_reg_tainted (int reg, uint32_t size, uint32_t is_upper8);
static inline void verify_memory (ADDRINT ip, u_long mem_loc, uint32_t mem_size);
int is_flag_tainted (uint32_t flag) {
    int i = 0;	
    int tainted = 0;
    for (i = 0; i<NUM_FLAGS; ++i) {
        if (flag & ( 1 << i)) {
            if (current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE + i]) {
                tainted = 1;
                break;
            }
        } 
    }
    return tainted;
}

#ifdef USE_NW
static void 
flush_merge_buffer ()
{
    struct timeval tv_start, tv_end;
    gettimeofday (&tv_start, NULL);

    struct taint_data_header hdr;

    long bytes_written = 0;
    long size = merge_control_shm->merge_buffer_count*sizeof(struct taint_number);

    if(s == -99999) { 
	fprintf(stderr, "skipping flush_merge_buffer... must not be following proc\n");
	return;
    }
    
    hdr.type = TAINT_DATA_MERGE;
    hdr.datasize = size;
    long rc = write (s, &hdr, sizeof(hdr));
    if (rc != sizeof(hdr)) {
	fprintf (stderr, "Cannot write nw header for merge data, rc=%ld\n", rc);
	assert (0);
    }
    while (bytes_written < size) {
	rc = write (s, (char *) merge_buffer+bytes_written, size-bytes_written);	
	if (rc <= 0) {
	    fprintf (stderr, "Canot write to merge log, rc=%ld, errno=%d\n", rc, errno);
	    assert (0);
	}
	bytes_written += rc;
    }

    gettimeofday (&tv_end, NULL);
    if (tv_start.tv_usec > tv_end.tv_usec) {
	printf ("merge flush %ld.%6ld seconds\n", tv_end.tv_sec - tv_start.tv_sec - 1, tv_end.tv_usec + 1000000 - tv_start.tv_usec);
    } else {
	printf ("merge flush %ld.%6ld seconds\n", tv_end.tv_sec - tv_start.tv_sec, tv_end.tv_usec - tv_start.tv_usec);
    }
}
#endif
#ifdef USE_SHMEM
static void 
flush_merge_buffer ()
{
    // Check for overflow
    if ((merge_control_shm->merge_total_count-0xe0000001) >= MAX_MERGES) {
	fprintf (stderr, "Cannot allocate any more merges than %ld\n", (u_long) (merge_control_shm->merge_total_count-0xe0000001));
	fprintf(stderr,"sycall_cnt %ld clock %ld\n", global_syscall_cnt, *ppthread_log_clock);
	assert (0);
    }

    // Unmap the current region
    if (munmap (merge_buffer, MERGE_FILE_CHUNK) < 0) {
	fprintf (stderr, "could not munmap merge buffer, errno=%d\n", errno);
	assert (0);
    }

    // Map in the next region
    merge_buffer = (struct taint_number *) mmap (0, MERGE_FILE_CHUNK, PROT_READ|PROT_WRITE, MAP_SHARED, 
						 node_num_fd, (merge_control_shm->merge_total_count-0xe0000001)*sizeof(struct taint_number));
    if (merge_buffer == MAP_FAILED) {
	fprintf (stderr, "could not map merge buffer, errno=%d\n", errno);
	assert (0);
    }
}
#endif
#ifdef USE_FILE
static void 
flush_merge_buffer ()
{
    long bytes_written = 0;
    long size = merge_control_shm->merge_buffer_count*sizeof(struct taint_number);
    
    while (bytes_written < size) {
	long rc = write (node_num_fd, (char *) merge_buffer+bytes_written, size-bytes_written);	
	if (rc <= 0) {
	    fprintf (stderr, "Canot write to merge log, rc=%ld, errno=%d\n", rc, errno);
	    assert (0);
	}
	bytes_written += rc;
    }
}
#endif
#ifdef USE_NULL
static void
flush_merge_buffer ()
{
}
#endif

static inline taint_t 
add_merge_number(taint_t p1, taint_t p2)
{
    if (merge_control_shm->merge_buffer_count == MERGE_FILE_ENTRIES) {
	flush_merge_buffer();
	merge_control_shm->merge_buffer_count = 0;
    } 

    merge_buffer[merge_control_shm->merge_buffer_count].p1 = p1;
    merge_buffer[merge_control_shm->merge_buffer_count].p2 = p2;
    merge_control_shm->merge_buffer_count++;
    return merge_control_shm->merge_total_count++;
}

struct taint_node {
    struct taint_node* parent1;
    struct taint_node* parent2;
};

struct taint_leafnode {
    struct taint_node node;
    option_t option;
};

#ifdef USE_MERGE_HASH

// simple hash for holding merged indices
#define SIMPLE_HASH_SIZE 0x1000000
struct simple_bucket {
    taint_t p1, p2, n;
};
struct simple_bucket simple_hash[SIMPLE_HASH_SIZE];

#endif

//ARQUINN: initialize the shared memory region for the mergeFile
static inline void init_merge_control_shm(char* group_dir) { 
    char merge_control_shmemname[256];
    int rc;
    u_int i;
    int merge_control_fd;

    snprintf(merge_control_shmemname, 256, "/taint_shm%s", group_dir);
    for (i = 1; i < strlen(merge_control_shmemname); i++) {
        if (merge_control_shmemname[i] == '/') merge_control_shmemname[i] = '.';
    }
    merge_control_fd = shm_open(merge_control_shmemname, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (merge_control_fd < 0) {
        fprintf(stderr, "could not open taint control shmem %s, errno %d\n",
	      merge_control_shmemname, errno);
      assert(0);
        }
    rc = ftruncate (merge_control_fd, sizeof(struct merge_buffer_control));
    if (rc < 0) {
      fprintf(stderr, "could not truncate shmem %s, errno %d\n",
		    merge_control_shmemname, errno);
      assert(0);
    }
    merge_control_shm = (struct merge_buffer_control *) mmap (0, sizeof(struct merge_buffer_control), PROT_READ|PROT_WRITE, MAP_SHARED, merge_control_fd, 0);
    if (merge_control_shm == MAP_FAILED) {
      fprintf (stderr, "could not map shared memory for control of merge buffer, errno=%d\n", errno);
	    assert (0);
    }
    
    /*
     * initialize with default values:
     *    merge_buffer_count = 0;
     *    merge_total_count = 0xe0000001;
     *    merge_buf_overflow = false;
     */

    merge_control_shm->merge_buffer_count = 0;
    merge_control_shm->merge_total_count = 0xe0000001;
    merge_control_shm->merge_buf_overflow = false;
}

static inline void init_taint_index(char* group_dir)
{
#ifdef USE_MERGE_HASH
    memset(&simple_hash,0,sizeof(simple_hash));
#endif
#ifdef TAINT_STATS
    memset(&tsp, 0, sizeof(tsp));
#endif
    init_slab_allocs();
    {
#ifdef USE_SHMEM
        char node_num_shmemname[256];
	int rc;
	u_int i;

        snprintf(node_num_shmemname, 256, "/node_nums_shm%s", group_dir);
	for (i = 1; i < strlen(node_num_shmemname); i++) {
	  if (node_num_shmemname[i] == '/') node_num_shmemname[i] = '.';
	}
        node_num_fd = shm_open(node_num_shmemname, O_CREAT | O_TRUNC | O_RDWR, 0644);
        if (node_num_fd < 0) {
            fprintf(stderr, "could not open node num shmem %s, errno %d\n",
		    node_num_shmemname, errno);
            assert(0);
        }
	rc = ftruncate64 (node_num_fd, MAX_MERGE_SIZE);
	if (rc < 0) {
            fprintf(stderr, "could not truncate shmem %s, errno %d\n",
		    node_num_shmemname, errno);
            assert(0);
        }
	merge_buffer = (struct taint_number *) mmap (0, MERGE_FILE_CHUNK, PROT_READ|PROT_WRITE, MAP_SHARED, 
						     node_num_fd, 0);
	if (merge_buffer == MAP_FAILED) {
	    fprintf (stderr, "could not map merge buffer, errno=%d\n", errno);
	    assert (0);
	}
#else
#ifdef USE_FILE
	char node_num_filename[256];
        snprintf(node_num_filename, 256, "%s/node_nums", group_dir);
	node_num_fd = open(node_num_filename, O_CREAT | O_TRUNC | O_RDWR | O_LARGEFILE, 0644);
	if (node_num_fd < 0) {
	    fprintf(stderr, "could not open node num file %s, errno %d\n",
		    node_num_filename, errno);
	    assert(0);
	}
#endif	
	merge_buffer = (struct taint_number *) malloc(MERGE_FILE_CHUNK);
	if (merge_buffer == NULL) {
	    fprintf (stderr, "Cannnot allocate file write buffer\n");
	    assert (0);
	}
#endif
    }

    new_slab_alloc((char *)"LEAF_TABLE_ALLOC", &leaf_table_alloc, LEAF_TABLE_SIZE * sizeof(taint_t), 10000);
}

static inline taint_t merge_taints(taint_t dst, taint_t src)
{
    if (dst == 0) {
        return src;
    }
    if (src == 0) {
        return dst;
    }
    if (dst == src) {
        return dst;
    }

#ifdef USE_MERGE_HASH
    if (dst < src) {
	taint_t tmp = src;
	src = dst;
	dst = tmp;
    }
    taint_t h = src + (dst << 2) + (dst << 3);
    struct simple_bucket& bucket = simple_hash[h%SIMPLE_HASH_SIZE];
    if (bucket.p1 == src && bucket.p2 == dst) {

#ifdef TAINT_STATS
	tsp.merges_saved++;
#endif       
	return bucket.n;
    } else {
	taint_t n = add_merge_number (dst, src);
	bucket.p1 = src;
	bucket.p2 = dst;
	bucket.n = n;
#ifdef TAINT_STATS
	tsp.merges++;
#endif
	return n;
    }
#else

#ifdef TAINT_STATS
    tsp.merges++;
#endif
    return add_merge_number(dst, src);
#endif
}

static inline taint_t* new_leaf_table(u_long memloc)
{
    // TODO use a slab allocator
#ifdef RETAINT
    taint_t* leaf_table = (taint_t *) malloc(LEAF_TABLE_SIZE * sizeof(taint_t));
#else
    taint_t* leaf_table = (taint_t *) get_slice(&leaf_table_alloc);
#endif
    if (!leaf_table) {
	fprintf (stderr, "Cannot allocate leaf_table, sec_marges %ld\n", 
	    tsp.num_second_tables);
	fprintf(stderr,"sycall_cnt %ld clock %ld\n", global_syscall_cnt, *ppthread_log_clock);
	assert (0);
    }

    if (splice_output) {
	memloc &= ROOT_INDEX_MASK;
	for (int i = 0; i < LEAF_TABLE_SIZE; i++) {
	    leaf_table[i] = memloc++;
	}
    } else {
	memset(leaf_table, 0, LEAF_TABLE_SIZE * sizeof(taint_t));
    }
#ifdef TAINT_STATS
    tsp.num_second_tables++;
#endif
    return leaf_table;
}

// Returns smaller of size or bytes left in third-level table
static inline int get_mem_split(u_long mem_loc, uint32_t size)
{
    uint32_t bytes_left = LEAF_TABLE_SIZE-(mem_loc&LEAF_INDEX_MASK);
    return (bytes_left < size) ? bytes_left : size;
}

taintvalue_t get_taint_value (taint_t t, option_t option)
{
    // STUB
    return 0;
}

void finish_and_print_taint_stats(FILE* fp)
{
#ifdef USE_SHMEM
    int rc = ftruncate64 (node_num_fd, (merge_control_shm->merge_total_count-0xe0000001)*sizeof(struct taint_number));
    if (rc < 0) {
	fprintf (stderr, "ftrunacte of merge file failed,rc=%d, errno=%d\n", rc, errno);
    }
    close (node_num_fd);
#else
    flush_merge_buffer ();
#endif

#ifdef TAINT_STATS
    fprintf(fp, "Taint statistics:\n");
    fprintf(fp, "Second tables allocated: %lu\n", tsp.num_second_tables);
    fprintf(fp, "Third tables allocated:  %lu\n", tsp.num_third_tables);
    fprintf(fp, "Num taint options:       %lu\n", tsp.options);
    fprintf(fp, "Num merges:              %lu\n", tsp.merges);
    fprintf(fp, "Num merges saved:        %lu\n", tsp.merges_saved);
    fflush(fp);
#endif
}

u_long get_num_merges(){ 
#ifdef TAINT_STATS
    return tsp.merges;
#endif
    return 0;
}
u_long get_num_merges_saved(){ 
#ifdef TAINT_STATS
    return tsp.merges_saved;
#endif
    return 0;
}

static inline taint_t* get_reg_taints_internal(int reg)
{
    return &(current_thread->shadow_reg_table[reg * REG_SIZE]);
}

taint_t* get_reg_taints(int reg)
{
    return get_reg_taints_internal(reg);
}

static inline void clear_reg_internal (int reg, int size)
{
    int i = 0;
    taint_t* reg_table = current_thread->shadow_reg_table;

    for (i = 0; i < size; i++) {
        reg_table[reg * REG_SIZE + i] = 0;
    }
}

void clear_reg (int reg, int size)
{
    clear_reg_internal (reg, size);
}

TAINTSIGN clear_flag_taint (uint32_t mask) { 
    int i = 0;
    for (i = 0; i<NUM_FLAGS; ++i) {
        if (mask & ( 1 << i)) {
            current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE + i] = 0;
	}
    }
}

static inline void taint_mem_internal(u_long mem_loc, taint_t t)
{
    taint_t* leaf_t;
    unsigned index = mem_loc >> LEAF_TABLE_BITS;
    if(!mem_root[index]) mem_root[index] = new_leaf_table(mem_loc);
    leaf_t = mem_root[index];
    leaf_t[mem_loc & LEAF_INDEX_MASK] = t;
}

void taint_mem(u_long mem_loc, taint_t t)
{
    taint_mem_internal(mem_loc, t);
}

static inline taint_t* get_mem_taints_internal(u_long mem_loc, uint32_t size)
{
    unsigned index = mem_loc >> LEAF_TABLE_BITS;
    taint_t* leaf_t = mem_root[index];
    if(!leaf_t) {
	if (splice_output) {
	    // Uninitialized - create table with correct values
	    leaf_t = mem_root[index] = new_leaf_table(mem_loc);
	} else {
	    return NULL;
	}
    }

    return &leaf_t[mem_loc & LEAF_INDEX_MASK];
}

taint_t* get_mem_taints(u_long mem_loc, uint32_t size)
{
    return get_mem_taints_internal(mem_loc, size);
}

#define DUMPBUFSIZE 0x100000
static taint_t* dumpbuf = NULL; 
static u_long dumpindex = 0;
#ifdef USE_SHMEM
static u_long dump_total_count = 0;
#endif

#ifdef USE_NW
static void flush_dumpbuf(int dumpfd)
{
    struct taint_data_header hdr;
    long bytes_written = 0;
    long size = dumpindex*sizeof(taint_t);
    
    hdr.type = TAINT_DATA_ADDR;
    hdr.datasize = size;
    long rc = write (s, &hdr, sizeof(hdr));
    if (rc != sizeof(hdr)) {
	fprintf (stderr, "Cannot write nw header for merge data, rc=%ld\n", rc);
	assert (0);
    }
    while (bytes_written < size) {
	rc = write (s, (char *) dumpbuf+bytes_written, size-bytes_written);	
	if (rc <= 0) {
	    fprintf (stderr, "Cannot write to addr log, rc=%ld, errno=%d\n", rc, errno);
	    assert (0);
	}
	bytes_written += rc;
    }
    dumpindex = 0;
}
#endif
#ifdef USE_SHMEM
static void flush_dumpbuf(int dumpfd)
{
    dump_total_count += dumpindex*sizeof(taint_t);

    // Check for overflow
    if (dump_total_count >= MAX_DUMP_SIZE) {
	fprintf (stderr, "Cannot allocate any more dump buffer than %lu bytes\n", (u_long) dump_total_count);
	assert (0);
    }

    // Unmap the current region
    if (munmap (dumpbuf, DUMPBUFSIZE*sizeof(taint_t)) < 0) {
	fprintf (stderr, "could not munmap dump buffer, errno=%d\n", errno);
	assert (0);
    }

    // Map in the next region
    dumpbuf = (taint_t *) mmap (0, DUMPBUFSIZE*sizeof(taint_t), PROT_READ|PROT_WRITE, MAP_SHARED, dumpfd, dump_total_count);
    if (dumpbuf == MAP_FAILED) {
	fprintf (stderr, "could not map dump buffer, errno=%d\n", errno);
	assert (0);
    }
    dumpindex = 0;
}
#endif
#ifdef USE_FILE
static void flush_dumpbuf(int dumpfd)
{
    long rc = write (dumpfd, dumpbuf, dumpindex*sizeof(taint_t));
    if (rc != (long) (dumpindex*sizeof(taint_t))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
    }
    dumpindex = 0;
}
#endif
#ifdef USE_NULL
static void flush_dumpbuf(int dumpfd)
{
}
#endif

static inline void print_value (int dumpfd, taint_t value) 
{
    if (dumpindex == DUMPBUFSIZE) flush_dumpbuf(dumpfd);
    dumpbuf[dumpindex++] = value;
}

int dump_mem_taints(int fd)
{
    u_long addr;
    int index, low_index;

    if(fd == -99999) { 
	fprintf(stderr, "skipping dump_mem_taints... must not be following proc\n");
	return -1;
    }
    for (index = 0; index < ROOT_TABLE_SIZE; index++) {
	taint_t* leaf = mem_root[index];
	if (leaf) {
	    for (low_index = 0; low_index < LEAF_TABLE_SIZE; low_index++) {
		addr = (index<<LEAF_TABLE_BITS) + low_index;
		if (leaf[low_index] != addr) {
		    print_value (fd, addr);
		    print_value (fd, leaf[low_index]);
		}
	    }
	}
    }

#ifdef USE_SHMEM
    if (ftruncate64 (fd, dump_total_count+(dumpindex*sizeof(taint_t)))) {
	fprintf (stderr, "Could not truncate dump mem to %lu\n", dump_total_count+(dumpindex*sizeof(taint_t)));
	assert (0);
    }
    close (fd);
#else
    flush_dumpbuf(fd);
#endif

    return 0;
}

int dump_mem_taints_start(int fd)
{
    u_long addr;
    int index, low_index;


    if(fd == -99999) { 
	fprintf(stderr, "skipping dump_mem_taints_start... must not be following proc\n");
	return -1;
    }
    for (index = 0; index < ROOT_TABLE_SIZE; index++) {
	taint_t* leaf = mem_root[index];
	if (leaf) {
	    for (low_index = 0; low_index < LEAF_TABLE_SIZE; low_index++) {
		addr = (index<<LEAF_TABLE_BITS) + low_index;
		if (leaf[low_index]) {
		    print_value (fd, addr);
		    print_value (fd, leaf[low_index]);
		}
	    }
	}
    }

#ifdef USE_SHMEM
    if (ftruncate (fd, dump_total_count+(dumpindex*sizeof(taint_t)))) {
	fprintf (stderr, "Cound not truncate dump mem to %ld\n", dump_total_count*sizeof(taint_t));
	assert (0);
    }
    close (fd);
#else
    flush_dumpbuf(fd);
#endif

    return 0;
}

#ifdef RETAINT
// This resets all the taints (for testing purposes only)
void reset_mem_taints()
{
    // Remove all leafs
    for (int index = 0; index < ROOT_TABLE_SIZE; index++) {
	if (mem_root[index]) {
	    free (mem_root[index]);
	    mem_root[index] = NULL;
	}
    }
    // Prevents overflow
    merge_control_shm->merge_buffer_count = 0;
    merge_control_shm->merge_total_count = 0xe0000001;

}
#endif

int dump_reg_taints (int fd, taint_t* pregs, int thread_ndx)
{
    u_long i;

    if(fd == -99999) { 
	fprintf(stderr, "skipping dump_reg_taints... must not be following proc\n");
	return -1;
    }

    u_long base = thread_ndx*(NUM_REGS*REG_SIZE);

    if (dumpbuf == NULL) {
#ifdef USE_SHMEM
	dumpbuf = (taint_t *) mmap (0, DUMPBUFSIZE*sizeof(taint_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (dumpbuf == MAP_FAILED) {
	    fprintf (stderr, "could not map dump buffer, errno=%d\n", errno);
	    assert (0);
	}
#else
	dumpbuf = (taint_t *) malloc(DUMPBUFSIZE*sizeof(taint_t));
	if (dumpbuf == NULL) {
	    fprintf (stderr, "Cannot allocate dump buffer\n");
	    assert (0);
	}
#endif
    }

    // Increment by 1 because 0 is reserved for "no taint"
    for (i = 0; i < NUM_REGS*REG_SIZE; i++) {
	if (pregs[i] != base+i+1) {
	    print_value (fd, base+i+1);
	    print_value (fd, pregs[i]);
	}
    }

    return 0;
}

int dump_reg_taints_start (int fd, taint_t* pregs, int thread_ndx)
{
    u_long i;

    if(fd == -99999) { 
	fprintf(stderr, "skipping dump_reg_taints_start... must not be following proc\n");
	return -1;
    }

    u_long base = thread_ndx*(NUM_REGS*REG_SIZE);

    if (dumpbuf == NULL) {
#ifdef USE_SHMEM
	dumpbuf = (taint_t *) mmap (0, DUMPBUFSIZE*sizeof(taint_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (dumpbuf == MAP_FAILED) {
	    fprintf (stderr, "could not map dump buffer, errno=%d\n", errno);
	    assert (0);
	}
#else
	dumpbuf = (taint_t *) malloc(DUMPBUFSIZE*sizeof(taint_t));
	if (dumpbuf == NULL) {
	    fprintf (stderr, "Cannot allocate dump buffer\n");
	    assert (0);
	}
#endif
    }

    // Increment by 1 because 0 is reserved for "no taint"
    for (i = 0; i < NUM_REGS*REG_SIZE; i++) {
	if (pregs[i]) {
	    print_value (fd, base+i+1);
	    print_value (fd, pregs[i]);
	}
    }

    return 0;
}

static inline uint32_t get_cmem_taints_internal(u_long mem_loc, uint32_t size, taint_t** mem_taints)
{
    unsigned bytes_left = get_mem_split(mem_loc, size);
    unsigned index = mem_loc >> LEAF_TABLE_BITS;
    taint_t* leaf_t = mem_root[index];
    if(!leaf_t) {
	if (splice_output) {
	    // Uninitialized - create table with correct values
	    leaf_t = mem_root[index] = new_leaf_table(mem_loc);
	} else {
	    *mem_taints = NULL;
	    return bytes_left;
	}
    }

    *mem_taints = &leaf_t[mem_loc & LEAF_INDEX_MASK];
    return bytes_left;
}

uint32_t get_cmem_taints(u_long mem_loc, uint32_t size, taint_t** mem_taints)
{
    return get_cmem_taints_internal (mem_loc, size, mem_taints);
}

static void set_mem_taints(u_long mem_loc, uint32_t size, taint_t* values)
{
    taint_t* leaf_t;
    unsigned index = mem_loc >> LEAF_TABLE_BITS;
    if(!mem_root[index]) mem_root[index] = new_leaf_table(mem_loc);
    leaf_t = mem_root[index];

    unsigned low_index = mem_loc & LEAF_INDEX_MASK;
    memcpy(leaf_t + low_index, values, size * sizeof(taint_t));
}

/* Returns the number of bytes set in a memory location.
 *  This can be less than size if it requires walking over to another
 *   page table structure.
 *   This is a performance optimization.
 * */
static inline uint32_t set_cmem_taints(u_long mem_loc, uint32_t size, taint_t* values)
{
    uint32_t set_size = get_mem_split(mem_loc, size);
    taint_t* leaf_t;
    unsigned index = mem_loc >> LEAF_TABLE_BITS;
    if(!mem_root[index]) mem_root[index] = new_leaf_table(mem_loc);
    leaf_t = mem_root[index];

    unsigned low_index = mem_loc & LEAF_INDEX_MASK;
    memcpy(leaf_t + low_index, values, set_size * sizeof(taint_t));

    return set_size;
}

/* Set a continuous range of memory to one taint value */
static inline uint32_t set_cmem_taints_one(u_long mem_loc, uint32_t size, taint_t value)
{
    uint32_t set_size = get_mem_split(mem_loc, size);
    taint_t* leaf_t;
    unsigned index = mem_loc >> LEAF_TABLE_BITS;
    if(!mem_root[index]) mem_root[index] = new_leaf_table(mem_loc);
    leaf_t = mem_root[index];

    unsigned low_index = mem_loc & LEAF_INDEX_MASK;
    memset(leaf_t + low_index, value, set_size * sizeof(taint_t));

    return set_size;
}

static inline uint32_t clear_cmem_taints(u_long mem_loc, uint32_t size)
{
    uint32_t set_size = get_mem_split(mem_loc, size);
    taint_t* leaf_t;
    unsigned index = mem_loc >> LEAF_TABLE_BITS;
    if(!mem_root[index]) {
	if (splice_output) {
	    mem_root[index] = new_leaf_table(mem_loc);
	} else {
	    return set_size;
	}
    }
    leaf_t = mem_root[index];

    unsigned low_index = mem_loc & LEAF_INDEX_MASK;
    memset(leaf_t + low_index, 0, set_size * sizeof(taint_t));
    return set_size;
}

void clear_mem_taints(u_long mem_loc, uint32_t size)
{
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    while (offset < size) {
        uint32_t count = clear_cmem_taints(mem_offset, size - offset);
        offset += count;
        mem_offset += count;
    }
}

static inline void clear_reg_value(int reg, int offset, int size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memset(&shadow_reg_table[reg * REG_SIZE + offset], 0,
            size * sizeof(taint_t));
}

static inline void set_reg_value(int reg, int offset, int size, taint_t* values)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&shadow_reg_table[reg * REG_SIZE + offset], values,
            size * sizeof(taint_t));
}

static inline void set_reg_single_value(int reg, int size, taint_t value)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    for (int i = 0; i < size; i++) shadow_reg_table[reg * REG_SIZE + i] = value;
}

void set_syscall_retval_reg_value (int offset, taint_t value) {
    current_thread->shadow_reg_table[translate_reg(LEVEL_BASE::REG_EAX)*REG_SIZE + offset] = value;
}

static inline void zero_partial_reg (int reg, int offset)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memset(&shadow_reg_table[reg * REG_SIZE + offset], 0,
            (REG_SIZE - offset) * sizeof(taint_t));
}

static inline void set_clear_flags(taint_t* flagreg, taint_t t, uint32_t set_flags, uint32_t clear_flags) 
{
    if (set_flags != (uint32_t) -1 && clear_flags != (uint32_t) -1) {
	for (int i = 0; i<NUM_FLAGS; ++i) {
	    if (set_flags & (1 << i)) {
		flagreg[i] = t;
	    } else if (clear_flags & (1 << i)) {
		flagreg[i] = 0;
	    }
       }
    }
}

//manipulate top of stack for fpu registers 
//top of stack range: 0-7
int inline increment_fp_stack_top (int sp) 
{
    sp += 1;
    return sp % 8;
}

int inline decrement_fp_stack_top (int sp)
{
    sp += 7;
    return sp % 8;
}

int inline get_fp_stack_top (const CONTEXT* ctx)
{
    PIN_REGISTER value;
    PIN_GetContextRegval (ctx, REG_FPSW, (UINT8*)&value);
    return (int) ((*value.word >> 11 ) & 0x7);
}

int inline map_fp_stack_reg (int reg, int sp) 
{
    return (sp + reg - REG_ST0)%8 + REG_ST0;
}

int inline map_fp_stack_regoff (int reg_off, int sp/*stack top*/)
{
    return map_fp_stack_reg (reg_off/REG_SIZE, sp)*REG_SIZE + reg_off%REG_SIZE;
}

void inline fw_slice_track_fp_stack_top (ADDRINT ip, char* ins_str, const CONTEXT* ctx, uint32_t fp_stack_change) 
{
    int sp = get_fp_stack_top (ctx);
    if (sp != current_thread->slice_fp_top) { 
	printf ("**********inst 0x%x %s: we need an offset in the slice for the top of fpu stack, %d while in slice %d\n", ip, ins_str, sp, current_thread->slice_fp_top);
	if (is_reg_tainted(LEVEL_BASE::REG_ST0, 10, 0) ||
	    is_reg_tainted(LEVEL_BASE::REG_ST1, 10, 0) ||
	    is_reg_tainted(LEVEL_BASE::REG_ST2, 10, 0) ||
	    is_reg_tainted(LEVEL_BASE::REG_ST3, 10, 0) ||
	    is_reg_tainted(LEVEL_BASE::REG_ST4, 10, 0) ||
	    is_reg_tainted(LEVEL_BASE::REG_ST5, 10, 0) ||
	    is_reg_tainted(LEVEL_BASE::REG_ST6, 10, 0) ||
	    is_reg_tainted(LEVEL_BASE::REG_ST7, 10, 0)) {
	    while (sp < current_thread->slice_fp_top) {
		printf ("pushing\n");
		OUTPUT_SLICE_EXTRA (ip, "fld1"); // Push nonsense value onto FPU stack where untainted data should go
		current_thread->slice_fp_top = decrement_fp_stack_top (current_thread->slice_fp_top);
	    }
	    while (sp > current_thread->slice_fp_top) {
		printf ("popping\n");
		OUTPUT_SLICE_EXTRA (ip, "fstp st(0)");
		current_thread->slice_fp_top = increment_fp_stack_top (current_thread->slice_fp_top);
	    }
	} else {
	    printf ("doesn't matter - nothing is tainted\n");
	    current_thread->slice_fp_top = sp;
	}
    }
    if (fp_stack_change == FP_PUSH) { 
        current_thread->slice_fp_top = decrement_fp_stack_top (current_thread->slice_fp_top);
    } else if (fp_stack_change == FP_POP) { 
        current_thread->slice_fp_top = increment_fp_stack_top (current_thread->slice_fp_top);
    } else if (fp_stack_change != 0) {
        assert (0);
    }
}

TAINTSIGN taint_clear_reg_offset (int offset, int size, uint32_t set_flags, uint32_t clear_flags)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memset(&shadow_reg_table[offset], 0, size * sizeof(taint_t));
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], 0, set_flags, clear_flags);
}

TAINTSIGN taint_clear_fpureg_offset (int offset, int size, uint32_t set_flags, uint32_t clear_flags, const CONTEXT* ctx, uint32_t is_load)
{
    int sp = get_fp_stack_top (ctx);
    if (is_load) 
        //first change top of stack and then clear
        sp = decrement_fp_stack_top (sp);
    offset = map_fp_stack_regoff (offset, sp);
    taint_clear_reg_offset (offset, size, set_flags, clear_flags);
}

static inline void zero_partial_reg_until (int reg, int offset, int until)
{
    assert(until > offset);
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memset(&shadow_reg_table[reg * REG_SIZE + offset], 0,
            (until - offset) * sizeof(taint_t));
}

static int init_check_map (const char* check_filename)
{
    FILE* file = fopen (check_filename, "r");
    if (!file) return -ENOENT;
    while (!feof (file)) {
	char line[256];
	char addr[64], type[64], value[64], extra1[64], extra2[64], extra3[64], extra4[64];
	struct taint_check tc;

	if (fgets (line, sizeof(line), file) != NULL) {
            if (line[0] == '#')  //for comments
                continue;
	  if (sscanf(line, "%63s %63s %63s %63s %63s %63s %63s", addr, type, value, 
		     extra1, extra2, extra3, extra4) >= 2) {
		u_long ip = strtoul(addr, NULL, 0);
		if (ip == 0 && strlen (addr) == 0) {
		    fprintf (stderr, "check %s: invalid address\n", line);
		    return -1;
		}
		if (!strcmp(type, "rangev")) {
		    if (!strcmp(value, "mm")) {
			tc.type = CHECK_TYPE_MMAP_REGION;
		    } else {
			u_long range = strtoul (value, NULL, 0);
			if (range == 0) {
			    fprintf (stderr, "check %s: invalid rnage\n", line);
			    return -1;
			}
			tc.type = CHECK_TYPE_RANGE;
			tc.value = range;
		    }
		    check_map[ip] = tc;
                } else if (!strcmp(type, "rangev_write")) {
		    u_long range = strtoul (value, NULL, 0);
		    if (range == 0) {
			fprintf (stderr, "check %s: invalid rnage\n", line);
			return -1;
		    }
                    tc.type = CHECK_TYPE_RANGE_WRITE;
                    tc.value = range;
                    check_map[ip] = tc;
		    CFDEBUG ("range write for ip %lx range %ld\n", ip, tc.value);
                } else if (!strcmp(type, "specify_range_write")) {
                    u_long start_addr, size;
                    sscanf (value, "%lx,%lu", &start_addr, &size);
                    tc.type = CHECK_TYPE_SPECIFIC_RANGE_WRITE;
                    tc.value = start_addr;
                    tc.size = size;
                    check_map[ip] = tc;
                } else if (!strcmp(type, "specify_range")) {
                    u_long start_addr, size;
                    sscanf (value, "%lx,%lu", &start_addr, &size);
                    tc.type = CHECK_TYPE_SPECIFIC_RANGE;
                    tc.value = start_addr;
                    tc.size = size;
                    check_map[ip] = tc;
                } else if (!strcmp(type, "ctrl_diverge")) {
                    struct ctrl_flow_param param;
                    param.type = CTRL_FLOW_BLOCK_TYPE_DIVERGENCE;
                    sscanf (value, "%d,%lu,%llu", &param.pid, &param.clock, &param.index);
		    param.branch_flag = extra2[0];
		    param.iter_count = atoi(extra4);
                    param.ip = ip;
                    ctrl_flow_params.push_back(param);
                } else if (!strcmp(type, "ctrl_merge")) {
                    struct ctrl_flow_param param;
                    param.type = CTRL_FLOW_BLOCK_TYPE_MERGE;
		    sscanf (value, "%d,%lu,%llu", &param.pid, &param.clock, &param.index);
		    param.ip = ip;
		    ctrl_flow_params.push_back(param);
                } else if (!strncmp (type, "ctrl_block_instrument_orig", 26)) {
                    struct ctrl_flow_param param;
                    param.type = CTRL_FLOW_BLOCK_TYPE_INSTRUMENT_ORIG;
		    param.branch_flag = extra1[0];
                    param.ip = ip;
		    ctrl_flow_params.push_back(param);
                } else if (!strncmp (type, "ctrl_block_instrument_alt", 25)) {
                    struct ctrl_flow_param param;
                    param.type = CTRL_FLOW_BLOCK_TYPE_INSTRUMENT_ALT;
		    param.branch_flag = extra1[0];
                    param.ip = ip;
                    ctrl_flow_params.push_back (param);
		} else if (!strncmp(type, "syscall_read_extra", 18)) {
		    syscall_check schk;
		    schk.type = SYSCALL_READ_EXTRA;
		    schk.clock = ip;
		    schk.value = atoi(value);
		    printf ("syscall read extra ip %ld value %ld\n", schk.clock, schk.value);
		    syscall_checks[ip] = schk;
                } else if (!strcmp (type, "ignore_syscall")) {
                    /*
                     * Currently only read syscall can be ignored; both the content and retval from syscalls
                     */
                    struct check_syscall param;
                    param.index = atol (value); 
                    param.pid = (int) ip;
                    ignored_syscall.push_back (param);
                } else if (!strcmp (type, "ignore_inst")) {
                    // Currently only taint_add_reg2esp uses this
                    // If set, the instruction uses the recorded value from previous runs and untaints the regs
                    // This is a workaround for not modifying java's random stack addresses
                    ignored_inst.push_back (ip);
		} else { 
		    fprintf (stderr, "check %s: invalid type\n", line);
		    return -1;
		}
	    } else {
		fprintf (stderr, "check %s: invalid format\n", line);
		return -1;
	    }
	}
    }
    fclose (file);
    return 0;
}

int check_is_syscall_ignored (int pid, u_long index)
{
    vector<struct check_syscall>::iterator iter = ignored_syscall.begin();
    int ret = 0;

    while (iter != ignored_syscall.end()) { 
        if (iter->pid == pid && iter->index == index) {
            ret = 1;
            break;
        }
        ++iter;
    }
    if (iter != ignored_syscall.end())
        ignored_syscall.erase (iter);
    return ret;
}

void init_taint_structures (char* group_dir, const char* check_filename)
{
    if (splice_output) {
	taint_num = 0xc0000001;
    } else {
	taint_num = 0x1;
    }
    memset(mem_root, 0, ROOT_TABLE_SIZE * sizeof(taint_t *));
    init_taint_index(group_dir);

    //ARQUINN: added code to initialize the shared mem control 
    init_merge_control_shm(group_dir);

    if (!taint_fds_table) {
        taint_fds_table = g_hash_table_new(g_direct_hash, g_direct_equal);
        taint_fds_cloexec = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    init_check_map(check_filename);
}

int translate_reg(int reg)
{
    //these coorespond to the eax, ebx, ecx and edx registers so that we 
    //can have the low / high / word varients overlap in our register map. 
    
    if (reg == 25 || reg == 26 || reg == 27) {
        return 8;
    } else if (reg == 22 || reg == 23 || reg == 24) {
        return 9;
    } else if (reg == 28 || reg == 29 || reg == 30) {
        return 7;
    } else if (reg == 19 || reg == 20 || reg == 21) {
        return 10;
    } else if (reg == 31) {
	return LEVEL_BASE::REG_EBP;
    } else if (reg == LEVEL_BASE::REG_SI)
	    return LEVEL_BASE::REG_ESI;
    else if (reg == LEVEL_BASE::REG_DI)
	    return LEVEL_BASE::REG_EDI;
    //also make sure bp,si,di,sp,flags are converted
    if (reg == LEVEL_BASE::REG_SP || reg == LEVEL_BASE::REG_FLAGS) { 
	    fprintf (stderr, "reg %d is not handled.\n", reg);
	    assert (0);
    }
    return reg;
}

void shift_reg_taint_right(int reg, int shift)
{
    assert(shift > 0);
    if (shift > 15) {
        clear_reg_internal(reg, REG_SIZE);
        return;
    } else {
        int i = 0;
        taint_t* reg_table = current_thread->shadow_reg_table;
        for (i = 0; i < (REG_SIZE - shift); i++) {
            reg_table[reg * REG_SIZE + i] = reg_table[reg * REG_SIZE + i + shift];
        }
        // zero shift amount
        for (i = (REG_SIZE - shift); i < REG_SIZE; i++) {
            reg_table[reg * REG_SIZE + i] = 0;
        }
    }
}

static inline taint_t base_index_taint (uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t bi_taint = 0;
    for (uint32_t i = 0; i < base_reg_size; i++) bi_taint = merge_taints(shadow_reg_table[base_reg_off+i], bi_taint);
    for (uint32_t i = 0; i < index_reg_size; i++) bi_taint = merge_taints(shadow_reg_table[index_reg_off+i], bi_taint);
    return bi_taint;
}

TAINTSIGN taint_mem2reg_offset(u_long mem_offset, uint32_t reg_off, uint32_t size, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    uint32_t offset = 0;

    taint_t bi_taint = base_index_taint (base_reg_off, base_reg_size, index_reg_off, index_reg_size);
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (!mem_taints) {
	    memset (&shadow_reg_table[reg_off+offset], 0, count*sizeof(taint_t));
        } else {
	    memcpy (&shadow_reg_table[reg_off+offset], mem_taints, count*sizeof(taint_t));
        }
        offset += count;
        mem_offset += count;
    }

    if (bi_taint) {
	for (uint32_t i = 0; i < size; i++) shadow_reg_table[reg_off+i] = merge_taints(shadow_reg_table[reg_off+i], bi_taint);
    }
}

TAINTSIGN taint_mem2reg_ext_offset(u_long mem_loc, uint32_t reg_off, uint32_t size, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    taint_t bi_taint = base_index_taint (base_reg_off, base_reg_size, index_reg_off, index_reg_size);
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (!mem_taints) {
	    memset (&shadow_reg_table[reg_off+offset], 0, count*sizeof(taint_t));
        } else {
	    memcpy (&shadow_reg_table[reg_off+offset], mem_taints, count*sizeof(taint_t));
        }
        offset += count;
        mem_offset += count;
    }
    memset(&shadow_reg_table[reg_off+size], 0, (REG_SIZE-size) * sizeof(taint_t));

    if (bi_taint) {
	for (uint32_t i = 0; i < size; i++) shadow_reg_table[reg_off+i] = merge_taints(shadow_reg_table[reg_off+i], bi_taint);
    }
}

TAINTSIGN taint_mem2fpureg_offset(u_long mem_loc, uint32_t reg_off, uint32_t size, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size, const CONTEXT* ctx)
{
    int sp = get_fp_stack_top (ctx);
    reg_off = map_fp_stack_regoff (reg_off, sp);
    taint_mem2reg_ext_offset (mem_loc, reg_off, size, base_reg_off, base_reg_size, index_reg_off, index_reg_size);
}

//only used for these instructions
// (opcode == XED_ICLASS_FILD || opcode == XED_ICLASS_FLD || opcode == XED_ICLASS_FBLD)
TAINTSIGN taint_load_mem2fpureg_offset(u_long mem_loc, uint32_t reg_off, uint32_t size, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size, const CONTEXT* ctx)
{
    int sp = get_fp_stack_top (ctx);
    sp = decrement_fp_stack_top (sp);
    reg_off = map_fp_stack_regoff (reg_off, sp);
    taint_mem2reg_ext_offset (mem_loc, reg_off, size, base_reg_off, base_reg_size, index_reg_off, index_reg_size);
    //This is necessary as we convert interger/float/double/bcd into double extended format here
    taint_mix_reg_offset (reg_off, REG_SIZE, -1, -1);
}

static inline void taint_mem2reg(u_long mem_loc, int reg, uint32_t size)
{
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (!mem_taints) {
	    zero_partial_reg_until(reg, offset, offset + count);
        } else {
            assert(mem_taints != NULL);
            set_reg_value(reg, offset, count, mem_taints);
        }
        offset += count;
        mem_offset += count;
    }
}

TAINTSIGN taint_add_mem2reg_offset (u_long mem_loc, int reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size)
{
    unsigned i = 0;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;
    taint_t t = 0;

    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t bi_taint = base_index_taint (base_reg_off, base_reg_size, index_reg_off, index_reg_size);
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
                t = merge_taints(shadow_reg_table[reg_off + offset + i], mem_taints[i]);
		shadow_reg_table[reg_off + offset + i] = t;
            }
        } 
	  
        offset += count;
        mem_offset += count;
    }
 
    if (bi_taint) {
	for (uint32_t i = 0; i < size; i++) shadow_reg_table[reg_off+i] = merge_taints(shadow_reg_table[reg_off+i], bi_taint);
	t = merge_taints(t, bi_taint);
    }
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

static inline int is_reg_zero(int reg, uint32_t size)
{
    unsigned i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    for (i = 0; i < size; i++) {
        if(shadow_reg_table[reg * REG_SIZE + i] != 0) {
            return 0;
        }
    }
    return 1;
}

static inline int is_reg_zero_offset(uint32_t reg_off, uint32_t size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    for (uint32_t i = 0; i < size; i++) {
        if (shadow_reg_table[reg_off + i] != 0) {
            return 0;
        }
    }
    return 1;
}

TAINTSIGN taint_xchg_memreg (u_long mem_loc, uint32_t reg_off, uint32_t size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
	for (uint32_t i = 0; i < count; i++) {
	    if (!mem_taints) {
		shadow_reg_table[reg_off+offset+i] = 0;
	    } else {
		taint_t tmp = shadow_reg_table[reg_off+offset+i];
		shadow_reg_table[reg_off+offset+i] = mem_taints[i];
		mem_taints[i] = tmp;
	    }
        }
        offset += count;
        mem_offset += count;
    }
}

inline taint_t merge_mem_taints (u_long mem_loc, uint32_t size) 
{  
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;
    taint_t result = 0;
    uint32_t i;
    
    while (offset < size) { 
	taint_t* mem_taints = NULL;
	uint32_t count = get_cmem_taints_internal (mem_offset, size - offset, &mem_taints);
	if (mem_taints) { 
	    for (i=0; i<count; ++i) { 
		result = merge_taints (result, mem_taints[i]);
	    }
	}
	offset += count;
	mem_offset += count;
    }
    return result;
}

inline taint_t merge_reg_taints (uint32_t reg, uint32_t size, uint32_t is_upper8) { 
    uint32_t i = 0;
    taint_t result = 0;
    if (is_upper8) i = 1;
    for (; i<size; ++i) {
        result = merge_taints (current_thread->shadow_reg_table[reg*REG_SIZE + i], result);
    }
    return result;
}

static inline taint_t merge_flag_taints (uint32_t mask) { 
    uint32_t i = 0;
    taint_t t = 0;
    for (i = 0; i<NUM_FLAGS; ++i) { 
        if (mask & (1 << i)) {
            t = merge_taints (t, current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE + i]);
        }
    }
    return t;
}

TAINTSIGN taint_regmem2flag (u_long mem_loc, uint32_t size_mem, uint32_t reg_off, uint32_t size_reg, uint32_t set_flags, uint32_t clear_flags) 
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    
    taint_t t = merge_mem_taints (mem_loc, size_mem);
    for (uint32_t i = 0; i<size_reg; ++i) {
	t = merge_taints (shadow_reg_table[reg_off + i], t);
    }
    
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

TAINTSIGN taint_regmem2flag_pcmpxstri (uint32_t reg, u_long mem_loc2, uint32_t reg2, uint32_t size_reg, uint32_t size2, uint32_t implicit) {
	uint32_t i = 0;
	taint_t result = 0;
	uint32_t mask = CF_FLAG | ZF_FLAG | SF_FLAG | OF_FLAG | AF_FLAG | PF_FLAG;
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	uint32_t eax = translate_reg (LEVEL_BASE::REG_EAX);
	uint32_t edx = translate_reg (LEVEL_BASE::REG_EDX);
	uint32_t ecx = translate_reg (LEVEL_BASE::REG_ECX);

	//merge taints for operand2
	if (mem_loc2 != 0) 
		result = merge_mem_taints (mem_loc2, size2);
	else {
		result = merge_reg_taints (reg2, size2, 0); //won't be upper8
	} 
	//merge input register taints for operand1
	for (i = 0; i<size_reg; ++i) {
		result = merge_taints (shadow_reg_table[reg*REG_SIZE + i], result);
	}

	if (implicit == 0) {
		//als merge EAX and EDX taints for explicit length
		for (i = 0; i<REG_SIZE; ++i) { 
			taint_t t = merge_taints (shadow_reg_table[eax*REG_SIZE + i], shadow_reg_table[edx*REG_SIZE + i]);
			result = merge_taints (result, t);
		}
	}

	//output to flags
	for (i = 0; i<NUM_FLAGS; ++i) {
		if (mask & ( 1 << i)) {
			shadow_reg_table[REG_EFLAGS*REG_SIZE + i] = result;
		} 
		//other flags are unaffected
	}
	//output to ecx
	for (i = 0; i< REG_SIZE; ++i) { 
		shadow_reg_table[ecx *REG_SIZE + i] = result;
	}
	//fprintf (stderr, "taint_regmem2flag_pcmpxstri: taint value %u\n", result);
}

TAINTSIGN taint_mem2flag (u_long mem_loc, uint32_t size, uint32_t set_flags, uint32_t clear_flags, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size) 
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    
    taint_t bi_taint = base_index_taint (base_reg_off, base_reg_size, index_reg_off, index_reg_size);
    taint_t t = merge_mem_taints (mem_loc, size);
    t = merge_taints (t, bi_taint);
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

TAINTSIGN taint_flag2mem (u_long mem_loc, uint32_t mask, uint32_t size) { 
	taint_t t = 0;
        t = merge_flag_taints (mask);
	set_cmem_taints_one (mem_loc, size, t);
}

TAINTSIGN taint_memmem2flag (u_long mem_loc1, u_long mem_loc2, uint32_t mask, uint32_t size) {
	uint32_t i = 0;
	uint32_t offset = 0;
	taint_t result = 0;
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;

	//merge taints for mem_loc1
	while (offset < size) { 
		taint_t* mem_taints = NULL;
		uint32_t count = get_cmem_taints_internal (mem_loc1+offset, size - offset, &mem_taints);
		if (mem_taints) { 
			for (i=0; i<count; ++i) { 
				result = merge_taints (result, mem_taints[i]);
			}
		} else { 
			//do nothing
			//fprintf (stderr, "taint_memmem2flag: flags %x, tainted %x, size %d, mem_taints is NULL!\n", mask, result, size);
		}
		offset += count;
	}
	//mem_loc2
	offset = 0;
	while (offset < size) { 
		taint_t* mem_taints = NULL;
		uint32_t count = get_cmem_taints_internal (mem_loc2+offset, size - offset, &mem_taints);
		if (mem_taints) { 
			for (i=0; i<count; ++i) { 
				result = merge_taints (result, mem_taints[i]);
			}
		} else { 
			//do nothing
			//fprintf (stderr, "taint_memmem2flag: flags %x, tainted %x, size %d, mem_taints is NULL!\n", mask, result, size);
		}
		offset += count;
	}
	
	for (i = 0; i<NUM_FLAGS; ++i) {
		if (mask & ( 1 << i)) {
			shadow_reg_table[REG_EFLAGS*REG_SIZE + i] = result;
		}
	}
	//fprintf (stderr, "taint_memmem2flag: flags %x, tainted %x, size %d\n", mask, result, size);
}

TAINTSIGN taint_reg2flag_offset (uint32_t reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags) 
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = shadow_reg_table[reg_off];
    for (uint32_t i = 1; i < size; i++) {
	t = merge_taints (shadow_reg_table[reg_off+i], t);
    }
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

//merge all taints from src_reg and put the merged taint value to all bytes in dst_reg
TAINTSIGN taint_merge_reg2reg (int dst_reg, int src_reg, uint32_t size) { 
    taint_t t = merge_reg_taints (src_reg, size, 0);
    uint32_t i = 0;
    assert (size != 1); //don't handle AH

    for (; i<size; ++i) { 
        current_thread->shadow_reg_table[dst_reg*REG_SIZE+i] = t;
    }
}

TAINTSIGN taint_flag2reg (uint32_t reg, uint32_t mask, uint32_t size) { 
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	uint32_t i = 0;
	taint_t t = 0;

        t = merge_flag_taints (mask);
	for (i = 0; i<size; ++i ) {
		shadow_reg_table[reg*REG_SIZE +i] = t;
	}
}

//size of dst reg and src reg should be the same
TAINTSIGN taint_regflag2reg (uint32_t mask, uint32_t dst_reg, uint32_t src_reg, uint32_t size) { 
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	taint_t t = 0;
	uint32_t i = 0;

        t = merge_flag_taints (mask);

	//merge	flag and src reg 
	for (; i<size; ++i) { 
		shadow_reg_table[dst_reg*REG_SIZE + i] = merge_taints (t, shadow_reg_table[src_reg*REG_SIZE+i]);
	}
}

//size of the mem and reg should be the same
TAINTSIGN taint_regflag2mem (uint32_t mask, u_long mem_loc, uint32_t src_reg, uint32_t size) { 
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	taint_t t = 0;
	uint32_t i = 0;

        t = merge_flag_taints (mask);
	//merge	flag and src reg
	//TODO: could make this more efficient
	for (; i<size; ++i) { 
		taint_t tmp = merge_taints (t, shadow_reg_table[src_reg*REG_SIZE+i]);
		set_cmem_taints (mem_loc + i, 1, &tmp);
	}
}

//size of the src mem and dst reg should be the same
TAINTSIGN taint_memflag2reg (uint32_t mask, uint32_t dst_reg, u_long mem_loc, uint32_t size) 
{ 
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = 0;
    uint32_t i = 0;
    uint32_t offset = 0;
    
    t = merge_flag_taints (mask);
    if (t) {
	//merge flag into src 
	while (offset < size) { 
	    taint_t* mem_taints = NULL;
	    uint32_t count = get_cmem_taints_internal (mem_loc+offset, size - offset, &mem_taints);
	    if (mem_taints) {
		for (i = 0; i < count; ++i) { 
		    shadow_reg_table[dst_reg*REG_SIZE+offset+i] = merge_taints (t, mem_taints[i]);
		} 
	    } else {
		for (i = 0; i < count; ++i) { 
		    shadow_reg_table[dst_reg*REG_SIZE+offset+i] = t;
		} 
	    }
	    offset += count;
	}
    }
}

TAINTSIGN taint_cmov_reg2reg (uint32_t mask, uint32_t dst_reg, uint32_t src_reg, uint32_t size, BOOL executed) 
{
    taint_t t = merge_flag_taints (mask);
    uint32_t dst_offset = dst_reg*REG_SIZE;
    uint32_t src_offset = src_reg*REG_SIZE;
    if (!t) {
	if (executed) { 
	    // Becomes a move
	    taint_reg2reg_offset(dst_offset, src_offset, size);
	} 
	// If not tainted and not executed, no taint changes
    } else {
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	uint32_t i;
	for (i = 0; i < size; ++i) { 
	    shadow_reg_table[dst_offset+i] = merge_taints (shadow_reg_table[dst_offset+i], merge_taints (t, shadow_reg_table[src_offset+i]));
	} 
    }
}

TAINTSIGN taint_cmov_mem2reg (uint32_t mask, uint32_t dst_reg, u_long mem_loc, uint32_t size, BOOL executed) 
{
    taint_t t = merge_flag_taints (mask);
    uint32_t reg_offset = dst_reg*REG_SIZE;
    if (!t) {
	if (executed) { 
	    // Becomes a move
	    taint_mem2reg_offset(mem_loc, reg_offset, size, 0, 0, 0, 0);
	} 
	// If not tainted and not executed, no taint changes
    } else {
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	uint32_t offset = 0, i;
	while (offset < size) { 
	    taint_t* mem_taints = NULL;
	    uint32_t count = get_cmem_taints_internal (mem_loc+offset, size - offset, &mem_taints);
	    if (mem_taints) {
		for (i = 0; i < count; ++i) { 
		    shadow_reg_table[reg_offset+offset+i] = merge_taints (shadow_reg_table[reg_offset+offset+i], merge_taints (t, mem_taints[i]));
		} 
	    } else {
		for (i = 0; i < count; ++i) { 
		    shadow_reg_table[reg_offset+offset+i] = merge_taints (shadow_reg_table[reg_offset+offset+i], t);
		} 
	    }
	    offset += count;
	}
    }
}

TAINTSIGN taint_regreg2flag_offset (uint32_t dst_reg_off, uint32_t dst_reg_size, uint32_t src_reg_off, uint32_t src_reg_size, uint32_t set_flags, uint32_t clear_flags)  
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    taint_t t = shadow_reg_table[dst_reg_off];
    for (uint32_t i = 1; i < dst_reg_size; i++) {
	t = merge_taints (shadow_reg_table[dst_reg_off+i], t);
    }
    for (uint32_t i = 0; i < src_reg_size; i++) {
	t = merge_taints (shadow_reg_table[src_reg_off+i], t);
    }

    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

TAINTSIGN taint_fpuregfpureg2flag (int reg1, int reg2, uint32_t size, const CONTEXT* ctx, uint32_t set_flags, uint32_t clear_flags) 
{
    int sp = get_fp_stack_top (ctx);
    reg1 = map_fp_stack_reg (reg1, sp);
    reg2 = map_fp_stack_reg (reg2, sp);
    taint_regreg2flag_offset (reg1*REG_SIZE, size, reg2*REG_SIZE, size, set_flags, clear_flags);
}

TAINTSIGN taint_jump (ADDRINT eflag, uint32_t flags, ADDRINT ip) {
	struct taint_creation_info tci;
        taint_t t = merge_flag_taints (flags);
	
	tci.type = TAINT_DATA_INST;
	tci.record_pid = current_thread->record_pid;
	tci.rg_id = current_thread->rg_id;
	tci.syscall_cnt = current_thread->syscall_cnt;
	tci.offset = 0;
	tci.fileno = eflag;//hacky: fileno is the flag value for this jump
	tci.data = ip;

	if (t != 0) {
		output_jump_result (ip, t, &tci, outfd);
	}
	//clear the flag register taints after jump? Probably not necessary as CMP, TEST, etc. instructions had cleaned them in taint_reg2flag
}

TAINTSIGN taint_jump_ecx (ADDRINT regvalue, uint32_t size, ADDRINT ip) {
	taint_t t = merge_reg_taints (translate_reg(LEVEL_BASE::REG_ECX), size, 0);
	struct taint_creation_info tci;

	tci.type = TAINT_DATA_INST;
	tci.record_pid = current_thread->record_pid;
	tci.rg_id = current_thread->rg_id;
	tci.syscall_cnt = current_thread->syscall_cnt;
	tci.offset = 0;
	tci.fileno = regvalue; 
	tci.data = ip;

	if (t != 0) {
		output_jump_result (ip, t, &tci, outfd);
	}
}

TAINTSIGN taint_cmpxchg_mem (ADDRINT cmp_value, u_long mem_loc, int src_reg, uint32_t size) 
{ 
    int cmp_reg = LEVEL_BASE::REG_EAX;    
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    taint_t reg_taints = merge_reg_taints (cmp_reg, size, 0);
    taint_t mem_taints = merge_mem_taints (mem_loc, size);
    taint_t t = merge_taints(reg_taints, mem_taints);
    taint_t tflags = t; 
    if (t) {
	for (uint32_t i = 0; i < size; i++) {
	    taint_t merged_taint = merge_taints(t,shadow_reg_table[src_reg*REG_SIZE+i]);
	    shadow_reg_table[cmp_reg*REG_SIZE+i] = merged_taint;
            set_mem_taints(mem_loc + i, 1, &merged_taint);
	    tflags = merge_taints(tflags, shadow_reg_table[src_reg*REG_SIZE+i]);
	} 
    } else {
	ADDRINT dst_value = get_mem_value32 (mem_loc, size);
	if (cmp_value == dst_value) {
	    for (uint32_t i = 0; i < size; i++) {
		if (shadow_reg_table[src_reg*REG_SIZE+i]) {
		    set_mem_taints(mem_loc + i, 1, &shadow_reg_table[src_reg*REG_SIZE+i]);
		}
		tflags = merge_taints(tflags, shadow_reg_table[src_reg*REG_SIZE+i]);
	    } 
	} else {
	    for (uint32_t i = 0; i < size; i++) {
		shadow_reg_table[cmp_reg*REG_SIZE+i] = 0; // Destination must be untainted to get here
	    } 
	}
    }

    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, ZF_FLAG, 0);	
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], tflags, CF_FLAG|PF_FLAG|AF_FLAG|SF_FLAG|OF_FLAG, 0);	
}

TAINTSIGN taint_cmpxchg_reg (ADDRINT cmp_value, UINT32 dst_value, int dst_reg, int src_reg, uint32_t size) 
{ 
    int cmp_reg = LEVEL_BASE::REG_EAX;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t1 = merge_reg_taints(cmp_reg, size, 0);
    taint_t t2 = merge_reg_taints(dst_reg, size, 0);
    taint_t t = merge_taints(t1, t2);
    taint_t tflags = t; 
    if (t) {
	for (uint32_t i = 0; i < size; i++) {
	    shadow_reg_table[cmp_reg*REG_SIZE+i] = shadow_reg_table[dst_reg*REG_SIZE+i] = merge_taints(t,shadow_reg_table[src_reg*REG_SIZE+i]);
	    tflags = merge_taints(tflags, shadow_reg_table[src_reg*REG_SIZE+i]);
	} 
    } else if (cmp_value == dst_value) {
	for (uint32_t i = 0; i < size; i++) {
	    shadow_reg_table[dst_reg*REG_SIZE+i] = shadow_reg_table[src_reg*REG_SIZE+i];
	    tflags = merge_taints(tflags, shadow_reg_table[src_reg*REG_SIZE+i]);
	} 
    } else {
	for (uint32_t i = 0; i < size; i++) {
	    shadow_reg_table[cmp_reg*REG_SIZE+i] = 0; // Destination must be untainted to get here
	} 
    }

    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, ZF_FLAG, 0);	
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], tflags, CF_FLAG|PF_FLAG|AF_FLAG|SF_FLAG|OF_FLAG, 0);	
}

TAINTSIGN taint_reg2mem_offset (u_long mem_loc, uint32_t reg_off, uint32_t size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    if (is_reg_zero_offset(reg_off, size)) {
	clear_mem_taints (mem_loc, size);
    } else {
        uint32_t offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < size) {
            uint32_t count = set_cmem_taints(mem_offset, size - offset,
					     &shadow_reg_table[reg_off + offset]);
            offset += count;
            mem_offset += count;
        }
    }
}

TAINTSIGN taint_reg2mem_ext_offset (u_long mem_loc, uint32_t mem_size, uint32_t reg_off, uint32_t reg_size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    if (is_reg_zero_offset(reg_off, reg_size)) {
	clear_mem_taints (mem_loc, mem_size);
    } else {
        uint32_t offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < reg_size) {
            uint32_t count = set_cmem_taints(mem_offset, reg_size - offset,
					     &shadow_reg_table[reg_off + offset]);
            offset += count;
            mem_offset += count;
        }
	clear_mem_taints (mem_loc+reg_size, mem_size-reg_size);
    }
}

TAINTSIGN taint_mix_fpureg (int reg, uint32_t reg_size, const CONTEXT* ctx)
{
    int sp = get_fp_stack_top (ctx); //get the actual st register
    reg = map_fp_stack_reg (reg, sp);

    taint_t t = merge_reg_taints (reg, reg_size, 0); 
    if (t) set_reg_single_value (reg, reg_size, t);
}

TAINTSIGN taint_mix_fpureg2mem (u_long mem_loc, uint32_t mem_size, int reg, uint32_t reg_size,  const CONTEXT* ctx)
{
    int sp = get_fp_stack_top (ctx); //get the actual st register
    reg = map_fp_stack_reg (reg, sp);

    if (is_reg_zero (reg, reg_size)) {
        clear_mem_taints (mem_loc, mem_size);
    } else {
        taint_t t = merge_reg_taints (reg, reg_size, 0); //because of the convertion from double-precision
	uint32_t bytes_set = 0;
	do {
	    uint32_t ret = set_cmem_taints_one (mem_loc+bytes_set, mem_size-bytes_set, t);
	    bytes_set += ret;
	} while (bytes_set != mem_size);
    }
}

// Returns 2 for partial taint now.  Calling functions must handle this.
static inline int is_reg_tainted_internal (int reg, uint32_t size, uint32_t is_upper8, taint_t* reg_table)
{ 
    int tainted = 0;
    uint32_t i = 0;
    uint32_t end = size;
    if (is_upper8) {
	i = 1;
	end = size + i;
    }
    for (; i<end; ++i) { 
	if (reg_table[reg*REG_SIZE + i] != 0) {
	    if (i && !is_upper8) {
		return 2; // Partially tainted: first bytes were untainted
	    } else {
		tainted = 1;
		break;
	    }
	}
    }
    if (tainted) {
	for (++i; i<end; ++i) {
	    if (reg_table[reg*REG_SIZE + i] == 0) {
		tainted = 2;
		break;
	    }
	}
    }
    return tainted;
}

static inline int is_reg_tainted (int reg, uint32_t size, uint32_t is_upper8) 
{ 
    return is_reg_tainted_internal (reg, size, is_upper8, current_thread->shadow_reg_table);
}

static inline int is_mem_tainted (u_long mem_loc, uint32_t size) { 
	uint32_t offset = 0;
	u_long mem_offset = mem_loc;
	int tainted = 0;

	while (offset < size) { 
		taint_t* mem_taints = NULL;
		uint32_t count = get_cmem_taints_internal (mem_offset, size - offset, &mem_taints);
		if (mem_taints) {
			uint32_t i = 0;
			for (; i<count; ++i) { 
				if (mem_taints[i] != 0) {
				    if (offset + i > 0 && tainted == 0) {
					return 2; // Partially tainted: first bytes were untainted
				    }
				    tainted = 1;
				} else if (tainted == 1) {
				    return 2; // First bytes were tainted - this one is not
				}
			}
		}
		offset += count;
		mem_offset += count;
	}
	return tainted;
}

/* For calling above from linkage_new.cpp (sigh) */
int is_reg_arg_tainted (int reg, uint32_t size, uint32_t is_upper8) 
{
    return is_reg_tainted (reg, size, is_upper8);
}

int is_mem_arg_tainted (u_long mem_loc, uint32_t size) 
{
    return is_mem_tainted (mem_loc, size);
}

static void print_stack_trace ()
{
    char buffer[128][128];
    int size = backtrace ((void**)buffer, 128);
    char** sym = backtrace_symbols ((void**)buffer, size);
    int i = 0;
    fprintf (stderr, "----------------stack trace---------------\n");
    for (; i<size; ++i) {
        fprintf (stderr, "%d %s\n", i, sym[i]);
    }
    fprintf (stderr, "----------------end stack trace---------------\n");
}

// This should only be used for info msgs as it does not handle >4 byte regs
static inline UINT32 get_mem_value32 (u_long mem_loc, uint32_t size) 
{ 
    UINT32 dst_value = -1;

    if (size == 1) {
	UINT8 tmp = *((UINT8*) mem_loc);
	dst_value = (UINT32) tmp;
    } else if (size == 2) {
	UINT16 tmp = *((UINT16*) mem_loc);
	dst_value = (UINT32) tmp;
    } else if (size == 4) {
	dst_value = *((UINT32*) mem_loc);
    } 

    return dst_value;
}

static inline UINT64 get_mem_value64 (u_long mem_loc, uint32_t size)
{
    if (size <= 4) {
	return get_mem_value32(mem_loc, size);
    } else {
	return *((UINT64*) mem_loc);
    }
}

static inline const char* translate_mmx (uint32_t reg)
{
    switch (reg) {
    case 54: return "xmm0";
    case 55: return "xmm1";
    case 56: return "xmm2";
    case 57: return "xmm3";
    case 58: return "xmm4";
    case 59: return "xmm5";
    case 60: return "xmm6";
    case 61: return "xmm7";
    default: return "unk";
    }
}

static inline void add_imm_load_to_slice (uint32_t reg, uint32_t size, char* val, ADDRINT ip)
{
    OUTPUT_SLICE_EXTRA (ip, "pushfd");
    OUTPUT_SLICE_EXTRA (ip, "sub esp, 12"); // For alignment
    OUTPUT_SLICE_EXTRA (ip, "push %lu", *((u_long *) (val+12)));
    OUTPUT_SLICE_EXTRA (ip, "push %lu", *((u_long *) (val+8)));
    OUTPUT_SLICE_EXTRA (ip, "push %lu", *((u_long *) (val+4)));
    OUTPUT_SLICE_EXTRA (ip, "push %lu", *((u_long *) val));
    OUTPUT_SLICE_EXTRA (ip, "movdqu %s, xmmword ptr [esp]", translate_mmx(reg));
    OUTPUT_SLICE_EXTRA (ip, "add esp, 28");
    OUTPUT_SLICE_EXTRA (ip, "popfd");
}

static inline void add_partial_load_to_slice (uint32_t reg, uint32_t size, char* val, ADDRINT ip)
{
    int i, j;
    u_long mask, vals;

    // (1) Set up a bitmask in memory 
    OUTPUT_SLICE_EXTRA (ip, "pushfd");
    OUTPUT_SLICE_EXTRA (ip, "sub esp, 12"); // For alignment
    for (i = 3; i >= 0; i--) {
	mask = 0;
	for (j = 3; j >= 0; j--) {
	    mask = mask << 8;
	    if (current_thread->shadow_reg_table[reg*REG_SIZE + i*4+j]) {
		mask |= 0xff;
	    } 
	}
	OUTPUT_SLICE_EXTRA (ip, "push 0x%lx", mask);
    }

    // (2) And register with max to include only tainted values
    // pand and por with stack address will cause a general protection error if memory is not align to 16
    OUTPUT_SLICE_EXTRA (ip, "pand %s, xmmword ptr [esp]", translate_mmx(reg));

    // (3) Set up the non-tainted values in memory
    for (i = 3; i >= 0; i--) {
	vals = 0;
	for (j = 3; j >= 0; j--) {
	    vals = vals << 8;
	    if (current_thread->shadow_reg_table[reg*REG_SIZE + i*4+j] == 0) {
		vals |= (u_char) val[i*4+j];
	    } 
	}
	OUTPUT_SLICE_EXTRA (ip, "push 0x%lx", vals);
    }

    // (4) Or with the register to load those values
    OUTPUT_SLICE_EXTRA (ip, "por %s, xmmword ptr [esp]", translate_mmx(reg));

    // (5) Fix the stack
    OUTPUT_SLICE_EXTRA (ip, "add esp, 44");
    OUTPUT_SLICE_EXTRA (ip, "popfd");
}

static inline void copy_value_to_pin_register (PIN_REGISTER* reg, uint32_t reg_value, uint32_t reg_size, uint32_t reg_u8) 
{ 
    memset (reg, 0, sizeof (PIN_REGISTER));
    if (reg_size == 0) return;
    switch (reg_size) { 
        case 4: 
            *reg->dword = reg_value;
            break;
        case 2:
            *reg->word = reg_value;
            break;
        case 1:
            if(reg_u8)
                *((UINT8*) (reg->word)) = reg_value;
            else 
                *reg->byte = reg_value;
            break;
        default:
	  printf ("reg size is %d\n", reg_size);
                assert (0);
    }
}

static inline void print_extra_move_reg_1 (ADDRINT ip, int reg, uint32_t value, uint32_t is_upper8) 
{
    if (is_upper8) {
	OUTPUT_SLICE_EXTRA (ip, "mov %s, %u", regName(reg,-1), value);
    } else {
	OUTPUT_SLICE_EXTRA (ip, "mov %s, %u", regName(reg,1), value);
    }
}
 
static inline void print_extra_move_reg_4 (ADDRINT ip, int reg, uint32_t value, int tainted) 
{
    if (!tainted) {
	OUTPUT_SLICE_EXTRA (ip, "mov %s, %u", regName(reg,4), value);
    } else {
	u_long mask = 0, valmask = 0;
	int j;
	
	for (j = 3; j >= 0; j--) {
	    mask = mask << 8;
	    valmask = valmask << 8;
	    if (current_thread->shadow_reg_table[reg*REG_SIZE + j]) {
		mask |= 0xff;
	    } else {
		valmask |= 0xff;
	    }
	}
	OUTPUT_SLICE_EXTRA (ip, "pushfd");
	OUTPUT_SLICE_EXTRA (ip, "and %s, 0x%lx", regName(reg,4), mask);
	OUTPUT_SLICE_EXTRA (ip, "or %s, 0x%lx", regName(reg,4), (value&valmask));
	OUTPUT_SLICE_EXTRA (ip, "popfd");
    }
}
 
static inline void print_extra_move_reg_10 (ADDRINT ip, int reg, const PIN_REGISTER* regvalue, int tainted) 
{
    if (!tainted) {
	OUTPUT_SLICE_EXTRA (ip, "pushfd");
	OUTPUT_SLICE_EXTRA (ip, "sub esp, 12"); // For alignment
	OUTPUT_SLICE_EXTRA (ip, "push %lu", *((u_long *) (regvalue->byte+6)));
	OUTPUT_SLICE_EXTRA (ip, "push %lu", *((u_long *) (regvalue->byte+2)));
	OUTPUT_SLICE_EXTRA (ip, "pushw %lu", *((u_long *) regvalue->byte));
	if (reg == REG::REG_ST0) {
	    OUTPUT_SLICE_EXTRA (ip, "fstp st(0)"); // Replace st0 with this value	    
	    OUTPUT_SLICE_EXTRA (ip, "fld tbyte ptr [esp]");
	} else {
	    int dest = reg - LEVEL_BASE::REG_ST0;
	    if (dest == 7) {
		fprintf (stderr, "Looks like we want to load value into ST(7)??? - yuk!\n");
	    } else {
		OUTPUT_SLICE_EXTRA (ip, "fld tbyte ptr [esp]");
		OUTPUT_SLICE_EXTRA (ip, "fxch st(%d)", dest+1);
		OUTPUT_SLICE_EXTRA (ip, "fstp st(0)");
	    }
	}
	OUTPUT_SLICE_EXTRA (ip, "add esp, 10");
	OUTPUT_SLICE_EXTRA (ip, "popfd");
    } else {
	fprintf (stderr, "don't handle partially tainted floating point registers\n");
	assert (0);
    }
}
 
static inline void print_extra_move_reg (ADDRINT ip, int reg, uint32_t reg_size, const PIN_REGISTER* regvalue, uint32_t is_upper8, int tainted) 
{ 
    switch (reg_size) {
        case 1:
            if (is_upper8)
		print_extra_move_reg_1 (ip, reg, *((UINT8*)(regvalue->word)), is_upper8);
            else
		print_extra_move_reg_1 (ip, reg, *regvalue->byte, is_upper8);
            break;
        case 2:
            OUTPUT_SLICE_EXTRA (ip, "mov %s, %u", regName(reg,reg_size), *regvalue->word);
            break;
        case 4:
	    print_extra_move_reg_4 (ip, reg, *regvalue->dword, tainted);
            break;
        case 8:
            fprintf (stderr, "print_extra_move_reg: ip %x unhandled size of reg: %d tainted %d\n", ip, reg_size, tainted);
            break;
        case 10:
	    print_extra_move_reg_10 (ip, reg, regvalue, tainted);
	    break;
        case 16:
	    if (!tainted) {
		add_imm_load_to_slice (reg, reg_size, (char*) regvalue, ip);
	    } else {
		add_partial_load_to_slice (reg, reg_size, (char*) regvalue, ip);
	    }
            break;
        default: 
            assert (0);
    }
}

static inline void print_extra_move_mem (ADDRINT ip, u_long mem_loc, uint32_t mem_size, int tainted) 
{ 
    if (is_readonly (mem_loc, mem_size)) {
        // Don't prefill read-ony memory
        // verify that we still have the same value during slice execution
        verify_memory (ip, mem_loc, mem_size);
        return;
    }
    if (tainted == 2) {
	for (uint32_t i = 0; i < mem_size; i++) {
	    if (!is_mem_tainted(mem_loc+i, 1)) {
		OUTPUT_SLICE_EXTRA (ip, "mov byte ptr [0x%lx], %u", mem_loc+i, get_mem_value32(mem_loc+i,1));
		add_modified_mem_for_final_check (mem_loc+i,1);   
	    }
	}
    } else {
	if (mem_size == 4) {
	    OUTPUT_SLICE_EXTRA (ip, "mov dword ptr [0x%lx], %u", mem_loc, get_mem_value32(mem_loc, mem_size));
	} else if (mem_size == 2) {
	    OUTPUT_SLICE_EXTRA (ip, "mov word ptr [0x%lx], %u", mem_loc, get_mem_value32(mem_loc, mem_size));
	} else if (mem_size == 1) {
	    OUTPUT_SLICE_EXTRA (ip, "mov byte ptr [0x%lx], %u", mem_loc, get_mem_value32(mem_loc, mem_size));
	}  else if (mem_size == 8) { 
            OUTPUT_SLICE_EXTRA (ip, "mov dword ptr[0x%lx], %u", mem_loc, get_mem_value32(mem_loc, 4));
            OUTPUT_SLICE_EXTRA (ip, "mov dword ptr[0x%lx], %u", mem_loc + 4, get_mem_value32(mem_loc + 4, 4));
	}  else if (mem_size == 16) { 
            OUTPUT_SLICE_EXTRA (ip, "mov dword ptr[0x%lx], %u", mem_loc, get_mem_value32(mem_loc, 4));
            OUTPUT_SLICE_EXTRA (ip, "mov dword ptr[0x%lx], %u", mem_loc + 4, get_mem_value32(mem_loc + 4, 4));
            OUTPUT_SLICE_EXTRA (ip, "mov dword ptr[0x%lx], %u", mem_loc + 8, get_mem_value32(mem_loc + 8, 4));
            OUTPUT_SLICE_EXTRA (ip, "mov dword ptr[0x%lx], %u", mem_loc + 12, get_mem_value32(mem_loc + 12, 4));
        } else { 
            fprintf (stderr, "not handled size for print_extra_move_mem %u \n", mem_size);
            print_stack_trace ();
            assert (0);
        }
	add_modified_mem_for_final_check (mem_loc,mem_size);   
    }
}

static inline void print_extra_move_flag (ADDRINT ip, char* str, uint32_t flag) { 
	fprintf (stderr, "[TODO] flag is not tainted, but we should initialize it %x, %s\n", ip, str);
}

TAINTSIGN debug_print_instr (ADDRINT ip, char* str) { 
	fprintf (stderr, "[DEBUG] ip %x, ", ip);
	fprintf (stderr, "%s\n",str);
}

u_long debug_counter = 0;
u_long jump_count = 0;

static inline void verify_memory (ADDRINT ip, u_long mem_loc, uint32_t mem_size)
{
    OUTPUT_SLICE_VERIFICATION ("pushfd"); //save flags
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x (move upwards)", ip); 
    for (uint32_t i = 0; i < mem_size; i++) {
	if (is_mem_tainted(mem_loc+i, 1)) {
	    OUTPUT_SLICE_VERIFICATION ("cmp byte ptr [0x%lx], 0x%x", mem_loc+i, *(u_char *) (mem_loc+i));
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x (move upwards)", ip);
	    OUTPUT_SLICE_VERIFICATION ("push 0x%lx", debug_counter++);
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE_VERIFICATION ("jne index_diverge");
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE_VERIFICATION ("add esp, 4");
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
	}
    }
    OUTPUT_SLICE_VERIFICATION ("popfd");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x (move upwards)", ip); 
    clear_mem_taints (mem_loc, mem_size);
}

static inline void verify_register (ADDRINT ip, int reg, uint32_t reg_size, uint32_t reg_value, uint32_t reg_u8, u_long mem_loc)
{
    OUTPUT_SLICE_VERIFICATION ("pushfd"); //save flags
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x (move upwards)", ip); 
    OUTPUT_SLICE_VERIFICATION ("cmp %s,0x%x", regName(reg, reg_size), reg_value);
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x (move upwards)", ip);
    OUTPUT_SLICE_VERIFICATION ("push 0x%lx", debug_counter++);
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x clock %ld bb %lld expected address %lx", ip, *ppthread_log_clock, current_thread->ctrl_flow_info.index, mem_loc);
    OUTPUT_SLICE_VERIFICATION ("jne index_diverge");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
    OUTPUT_SLICE_VERIFICATION ("add esp, 4");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
    OUTPUT_SLICE_VERIFICATION ("popfd");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x (move upwards)", ip); 
    memset (&current_thread->shadow_reg_table[reg*REG_SIZE+reg_u8], 0, reg_size*sizeof(taint_t)); // No longer tainted because we verified it
}

//operand_index is used when you have multiple memory operands in this instruction, to specify which one you want to verify
static inline void print_range_verification (ADDRINT ip, char* ins_str, u_long start, u_long end, u_long mem_loc, uint32_t mem_size, int operand_index = 0)
{
    char* start_index = NULL;
    do {
        start_index = strchr (ins_str, '[');
    } while (operand_index > 0);
    char* end_index = strchr (start_index, ']');
    OUTPUT_SLICE_VERIFICATION ("pushfd"); //save flags
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x (move upwards), address %lx", ip, mem_loc); 
    OUTPUT_SLICE_VERIFICATION ("push eax");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x address %lx, %s", ip, mem_loc, ins_str);
    OUTPUT_SLICE_VERIFICATION ("lea eax, %.*s", end_index-start_index+1, start_index); 
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
    OUTPUT_SLICE_VERIFICATION ("cmp eax, 0x%lx", start);
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
    OUTPUT_SLICE_VERIFICATION ("push 0x%lx", debug_counter++); 
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x clock %ld bb %lld expected range %lx to %lx", ip, *ppthread_log_clock, current_thread->ctrl_flow_info.index, start, end-1);
    OUTPUT_SLICE_VERIFICATION ("jb index_diverge");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
    OUTPUT_SLICE_VERIFICATION ("cmp eax, 0x%lx", end);
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
    OUTPUT_SLICE_VERIFICATION ("jae index_diverge");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
    OUTPUT_SLICE_VERIFICATION ("add esp, 4");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
    OUTPUT_SLICE_VERIFICATION ("pop eax");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
    OUTPUT_SLICE_VERIFICATION ("popfd");
    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x (move upwards), address %lx", ip, mem_loc); 
}

// Only called if base or index register is tainted.  Returns true if register(s) are still tainted after verification due to range check */
static inline bool verify_base_index_registers (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, 
						int base_reg, uint32_t base_reg_size, uint32_t base_reg_value, uint32_t base_reg_u8, 
						int index_reg, uint32_t index_reg_size, uint32_t index_reg_value, uint32_t index_reg_u8,
						int base_tainted, int index_tainted) 
{ 
    u_long start, end;
    PIN_REGISTER base_value;
    PIN_REGISTER index_value;

    map<ADDRINT,taint_check>::iterator iter = check_map.find(ip);
    if (iter != check_map.end()) {
	if (iter->second.type == CHECK_TYPE_MMAP_REGION) {
	    if (is_readonly_mmap_region (mem_loc, mem_size, start, end)) {
		if (base_reg_size > 0) copy_value_to_pin_register (&base_value, base_reg_value, base_reg_size, base_reg_u8);
		if (index_reg_size > 0) copy_value_to_pin_register (&index_value, index_reg_value, index_reg_size, index_reg_u8);
		if (base_tainted != 1 && base_reg_size > 0) print_extra_move_reg (ip, base_reg, base_reg_size, &base_value, base_reg_u8, base_tainted);
		if (index_tainted != 1 && index_reg_size > 0) print_extra_move_reg (ip, index_reg, index_reg_size, &index_value, index_reg_u8, index_tainted);
		print_range_verification (ip, ins_str, start, end, mem_loc, mem_size);
		return true;
	    } else {
		// This could be ok if some instructions read mmap region and some do not - handle non-mm regions as we normally do, I guess...
		//fprintf (stderr, "Check file specifies mmap region, but addres not in such a region\n");
	    }
	} else if (iter->second.type == CHECK_TYPE_RANGE || iter->second.type == CHECK_TYPE_SPECIFIC_RANGE) {
	    bool is_ro_region = false;

	    if (is_readonly_mmap_region (mem_loc, mem_size, start, end)) {
		is_ro_region = true; // Start and end set above
	    } else if (iter->second.type == CHECK_TYPE_RANGE) {
                start = mem_loc - iter->second.value;
                end = mem_loc + iter->second.value + 1;
            } else { 
                start = iter->second.value;
                end = iter->second.value + iter->second.size;
            }
	    if (base_reg_size > 0) copy_value_to_pin_register (&base_value, base_reg_value, base_reg_size, base_reg_u8);
	    if (index_reg_size > 0) copy_value_to_pin_register (&index_value, index_reg_value, index_reg_size, index_reg_u8);
	    if (base_tainted != 1 && base_reg_size > 0) print_extra_move_reg (ip, base_reg, base_reg_size, &base_value, base_reg_u8, base_tainted);
	    if (index_tainted != 1 && index_reg_size > 0) print_extra_move_reg (ip, index_reg, index_reg_size, &index_value, index_reg_u8, index_tainted);
	    if (!is_ro_region) {
		for (u_long i = start; i < end; i++) {
		    if (!is_mem_tainted(i, 1)) {
			// Untainted - load in valid value to memory address
			OUTPUT_SLICE (0, "mov byte ptr [0x%lx], %d", i, *(u_char *) i);
			OUTPUT_SLICE_INFO ("comes with %08x", ip);
			add_modified_mem_for_final_check (i,1);  
		    }
		}
	    }
	    print_range_verification (ip, ins_str, start, end, mem_loc, mem_size);
	    return true;
	}
    } 

    if (base_tainted) verify_register (ip, base_reg, base_reg_size, base_reg_value, base_reg_u8, mem_loc);
    if (index_tainted) verify_register (ip, index_reg, index_reg_size, index_reg_value, index_reg_u8, mem_loc);
    return false;
}

// Only called if base or index register is tainted.  Returns true if register(s) are still tainted after verification due to range check */
static inline bool verify_base_index_registers_write_range (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, 
							    int base_reg, uint32_t base_reg_size, uint32_t base_reg_value, uint32_t base_reg_u8, 
							    int index_reg, uint32_t index_reg_size, uint32_t index_reg_value, uint32_t index_reg_u8,
							    int base_tainted, int index_tainted) 
{ 
    u_long start, end;
    PIN_REGISTER base_value;
    PIN_REGISTER index_value;
    map<ADDRINT,taint_check>::iterator iter = check_map.find(ip);
    if (iter != check_map.end()) {
	if (iter->second.type == CHECK_TYPE_SPECIFIC_RANGE_WRITE || iter->second.type == CHECK_TYPE_RANGE_WRITE) {
	    if (iter->second.type == CHECK_TYPE_RANGE_WRITE) {
                start = mem_loc - iter->second.value;
                end = mem_loc + iter->second.value + 1;
	    } else {
		start = iter->second.value;
		end = iter->second.value + iter->second.size;
	    }
	    CFDEBUG ("Tainted base/index write from %lx to %lx\n", start, end); 
	    if (base_reg_size > 0) copy_value_to_pin_register (&base_value, base_reg_value, base_reg_size, base_reg_u8);
	    if (index_reg_size > 0) copy_value_to_pin_register (&index_value, index_reg_value, index_reg_size, index_reg_u8);
	    if (base_tainted != 1 && base_reg_size > 0) print_extra_move_reg (ip, base_reg, base_reg_size, &base_value, base_reg_u8, base_tainted);
	    if (index_tainted != 1 && index_reg_size > 0) print_extra_move_reg (ip, index_reg, index_reg_size, &index_value, index_reg_u8, index_tainted);
	    for (u_long i = start; i < end; i++) {
		if (!is_mem_tainted(i, 1)) {
		    // Untainted - load in valid value to memory address
		    OUTPUT_SLICE (0, "mov byte ptr [0x%lx], %d", i, *(u_char *) i);
		    OUTPUT_SLICE_INFO ("comes with %08x", ip);
		    add_modified_mem_for_final_check (i,1);  
		}
	    }
	    print_range_verification (ip, ins_str, start, end, mem_loc, mem_size);
	    return true;
	}
    } else {
        if (base_tainted) verify_register (ip, base_reg, base_reg_size, base_reg_value, base_reg_u8, mem_loc);
        if (index_tainted) verify_register (ip, index_reg, index_reg_size, index_reg_value, index_reg_u8, mem_loc);
	return false;
    }
    return false;
}

static inline void taint_base_index_to_range_memwrite (ADDRINT ip, u_long mem_loc, uint32_t size, int base_reg_off, uint32_t base_reg_size, int index_reg_off, uint32_t index_reg_size) 
{
    taint_t bi_taint = base_index_taint (base_reg_off, base_reg_size,index_reg_off, index_reg_size);
    if (bi_taint) {
        u_long mem_start = 0;
        uint32_t mem_size = 0;
        map<ADDRINT,taint_check>::iterator iter = check_map.find(ip);
        if (iter != check_map.end()) {
            if (iter->second.type == CHECK_TYPE_RANGE_WRITE) {
		mem_start = mem_loc - iter->second.value;
		mem_size = iter->second.value * 2 + 1;
            } else if (iter->second.type == CHECK_TYPE_SPECIFIC_RANGE_WRITE) {
                mem_start = iter->second.value;
                mem_size = iter->second.size;
            }
        } else {
            mem_start = mem_loc;
            mem_size = size;
        }
        //merge taints
        uint32_t offset = 0;
        while (offset < mem_size) { 
            taint_t* mem_taints = NULL;
            uint32_t count = get_cmem_taints_internal (mem_start + offset, mem_size-offset, &mem_taints);
            if (mem_taints) {
                for (uint32_t i = 0; i<count; ++i) { 
                    mem_taints[i] = merge_taints (mem_taints[i], bi_taint);
                }
            } else { 
                uint32_t ret = set_cmem_taints_one (mem_start+offset, count, bi_taint);
                assert (ret == count);
            }
            offset += count;
        }
    }
}

char tmpbuf[64], tmpbuf2[64], tmpbuf3[64]; // Ugly hack that works because only one thread runs at a time 
inline char* print_regval(char* valuebuf, const PIN_REGISTER* reg_value, uint32_t reg_size)
{
    switch (reg_size) {
    case 1:
	sprintf (valuebuf, "%d", *reg_value->byte);
	break;
    case 2:
	sprintf (valuebuf, "%d", *reg_value->word);
	break;
    case 4:
	sprintf (valuebuf, "%d", *reg_value->dword);
	break;
    case 8:
	sprintf (valuebuf, "%lld", *reg_value->qword);
	break;
    case 10: {
	char* ch = valuebuf+2;
	int i;
	strcpy (valuebuf, "0x");
	for (i = 0; i < 10; i++) {
	    sprintf (ch, "%02x", (reg_value->byte[i]&0xff));
	    ch += 2;
	}
	break;
    }
    default:
	sprintf (valuebuf, "reg size %d", reg_size);
    }
    return valuebuf;
}

#define VERIFY_BASE_INDEX						\
    int base_tainted = (base_reg_size>0)?is_reg_tainted (base_reg, base_reg_size, base_reg_u8):0; \
    int index_tainted = (index_reg_size>0)?is_reg_tainted (index_reg, index_reg_size, index_reg_u8):0; \
    bool still_tainted = false; \
    if (base_tainted || index_tainted) { \
	still_tainted = verify_base_index_registers (ip, ins_str, mem_loc, mem_size, \
						     base_reg, base_reg_size, base_reg_value, base_reg_u8, \
						     index_reg, index_reg_size, index_reg_value, index_reg_u8, \
						     base_tainted, index_tainted); \
    }

#define VERIFY_BASE_INDEX_WRITE						\
     int base_tainted = (base_reg_size>0)?is_reg_tainted (base_reg, base_reg_size, base_reg_u8):0; \
     int index_tainted = (index_reg_size>0)?is_reg_tainted (index_reg, index_reg_size, index_reg_u8):0; \
     if (base_tainted) verify_register (ip, base_reg, base_reg_size, base_reg_value, base_reg_u8, mem_loc); \
     if (index_tainted) verify_register (ip, index_reg, index_reg_size, index_reg_value, index_reg_u8, mem_loc);


#define VERIFY_BASE_INDEX_WRITE_RANGE						\
    int base_tainted = (base_reg_size>0)?is_reg_tainted (base_reg, base_reg_size, base_reg_u8):0; \
    int index_tainted = (index_reg_size>0)?is_reg_tainted (index_reg, index_reg_size, index_reg_u8):0; \
    bool still_tainted = false; \
    if (base_tainted || index_tainted) { \
	still_tainted = verify_base_index_registers_write_range (ip, ins_str, mem_loc, mem_size, \
						     base_reg, base_reg_size, base_reg_value, base_reg_u8, \
						     index_reg, index_reg_size, index_reg_value, index_reg_u8, \
						     base_tainted, index_tainted); \
    }

void add_modified_mem_for_final_check (u_long mem_loc, uint32_t size) 
{ 
    interval<unsigned long>::type mem_interval = interval<unsigned long>::closed(mem_loc, mem_loc+size-1);
    address_taint_set.insert (mem_interval);
}

TAINTSIGN ctrl_flow_init_reg (ADDRINT ip, REG reg, const CONTEXT* ctx, taint_t* reg_table) 
{
    int treg = translate_reg (reg);
    int size = REG_Size (reg);
    int is_upper8 = REG_is_Upper8 (reg);
    //we need to get the taint information from the checkpoint before the divergence
    int tainted = is_reg_tainted_internal (treg, size, is_upper8, reg_table);
    if (tainted != 1) { 
        PIN_REGISTER regvalue;
        PIN_GetContextRegval(ctx, reg, (UINT8*)&regvalue);
        print_extra_move_reg (0, treg, size, &regvalue, is_upper8, tainted); //a special ip for easy identification
    }
}

//for handling control flow diverges
static void ctrl_flow_taint_reg (REG reg, taint_t ctrl_flow_taint)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    uint32_t size = REG_Size (reg);
    int treg = translate_reg((int)reg);
    UINT32 reg_offset = treg * REG_SIZE;
    if (REG_is_Upper8(reg)) reg_offset += 1;

    for (uint32_t i = 0; i<size; ++i) {
	shadow_reg_table[reg_offset + i] = merge_taints (shadow_reg_table[reg_offset+i], ctrl_flow_taint);
	CFDEBUG ("[TAINT_REG]: Taint for reg %d offset %d is %d cf taint %d\n", treg, reg_offset+i, shadow_reg_table[reg_offset+i], ctrl_flow_taint);
    }
}

TAINTSIGN ctrl_flow_taint_mem (u_long mem_loc, uint32_t size, taint_t ctrl_flow_taint)
{
    
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    uint32_t i = 0;
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
		mem_taints[i] = merge_taints(ctrl_flow_taint, mem_taints[i]);
            }
        } else {
            int ret = set_cmem_taints_one (mem_offset, count, ctrl_flow_taint);
            assert (ret == (int)size);
        }
        offset += count;
        mem_offset += count;
    }
    add_modified_mem_for_final_check (mem_loc, size);
}

static void init_ctrl_flow_the_other_branch (ADDRINT ip, std::set<uint32_t> *store_set_reg, std::map<u_long, struct ctrl_flow_origin_value> *store_set_mem)
{
    for (auto i: *(store_set_reg)) {
        ctrl_flow_init_reg (ip, REG(i), &current_thread->ctrl_flow_info.ckpt.context, current_thread->ctrl_flow_info.ckpt.reg_table);
    }
    //always restore EFLAGS TODO
    print_extra_move_flag (ip, NULL, 0);
    for (auto i: *(store_set_mem)) { 
	if (!i.second.taint) { 
	    OUTPUT_SLICE_CTRL_FLOW (0, "mov byte ptr [0x%lx], %u", i.first, (UINT8) i.second.value);
	}
    }
}

static void init_ctrl_flow_this_branch (ADDRINT ip, const CONTEXT* ctx, std::set<uint32_t> *store_set_reg, std::map<u_long, struct ctrl_flow_origin_value> *store_set_mem)
{
    for (auto i: *(store_set_reg)) {
        ctrl_flow_init_reg (ip, REG(i), ctx, current_thread->shadow_reg_table);
    }
    //always restore EFLAGS TODO
    print_extra_move_flag (ip, NULL, 0);
    for (auto i: *(store_set_mem)) { 
        u_long mem_loc = i.first;
        int tainted = is_mem_tainted (mem_loc, 1);
	if (!tainted) { 
	    OUTPUT_SLICE_CTRL_FLOW (0, "mov byte ptr [0x%lx], %u", mem_loc, (UINT8) get_mem_value32(mem_loc, 1));
	}
    }
}


static void taint_ctrl_flow_branch (ADDRINT ip, taint_t ctrl_flow_taint, std::set<uint32_t> *store_set_reg, std::map<u_long, struct ctrl_flow_origin_value> *store_set_mem) 
{ 
    for (auto i: *(store_set_reg)) {
        //before we actual taint the register, we need to init if it's originally not tainted
        ctrl_flow_taint_reg (REG(i), ctrl_flow_taint);
    }
    //always restore EFLAGS TODO
    print_extra_move_flag (ip, NULL, 0);
    for (auto i: *(store_set_mem)) { 
        ctrl_flow_taint_mem (i.first, 1, ctrl_flow_taint);
    }
}

inline void ctrl_flow_checkpoint (const CONTEXT* ctx, struct ctrl_flow_checkpoint* ckpt)
{
    PIN_SaveContext (ctx, &ckpt->context);
    //save taints for regs
    //mem taints will be tracked by print_inst_dest_mem
    memcpy (ckpt->reg_table, current_thread->shadow_reg_table, sizeof (taint_t)*NUM_REGS*REG_SIZE);
    ckpt->flag_taints = new std::stack<struct flag_taints> (*current_thread->saved_flag_taints);
    ckpt->clock = *ppthread_log_clock;
 
}

static inline void ctrl_flow_rollback (struct ctrl_flow_checkpoint* ckpt, std::map<u_long, struct ctrl_flow_origin_value>* store_set_mem) 
{
    CFDEBUG ("[CTRL_FLOW] Start to rollback: index %lu,%llu\n", current_thread->ctrl_flow_info.clock, current_thread->ctrl_flow_info.index);
    assert (*ppthread_log_clock == ckpt->clock);

    //restore reg taints
    memcpy (current_thread->shadow_reg_table, ckpt->reg_table, sizeof(taint_t)*NUM_REGS*REG_SIZE);

    if (current_thread->saved_flag_taints != NULL)
        delete current_thread->saved_flag_taints;
    current_thread->saved_flag_taints = ckpt->flag_taints;

    CFDEBUG ("[CTRL_FLOW] registers are restored. \n");

    //restore mem taints and mem values
    map<u_long, struct ctrl_flow_origin_value> *mem_map = store_set_mem;
    for (auto i = mem_map->begin(); i != mem_map->end(); ++i) { 
	set_cmem_taints_one (i->first, 1, i->second.taint);
	add_modified_mem_for_final_check (i->first, 1);
        CFDEBUG ("[CTRL_FLOW] restore mem %lx, tainted? %d, current_value %d, new value %u\n", i->first, is_mem_tainted (i->first, 1), get_mem_value32 (i->first, 1), i->second.value);
        *(char*) (i->first) = i->second.value;
    }

    // Restore old index value
    CFDEBUG ("Restoring index value from %lld to %lld\n", current_thread->ctrl_flow_info.index, current_thread->ctrl_flow_info.save_index);
    current_thread->ctrl_flow_info.index = current_thread->ctrl_flow_info.save_index;

    PIN_ExecuteAt (&ckpt->context);

    fprintf (stderr, "[BUG] should never return here.\n");
}

//This function should always be called before the actual taint function
TAINTSIGN print_inst_dest_mem (ADDRINT ip, u_long mem_loc, uint32_t size, BASE_INDEX_ARGS) 
{ 
  if (current_thread->ctrl_flow_info.is_in_original_branch || current_thread->ctrl_flow_info.is_in_diverged_branch) {
        CFDEBUG ("[CONTROL_FLOW_MEM] ip %x mem(0x%lx,%u), index %lu_%llu, one bye value %u\n", ip, mem_loc, size, current_thread->ctrl_flow_info.clock, current_thread->ctrl_flow_info.index, *((uint8_t*) mem_loc));

        int base_tainted = (base_reg_size>0)?is_reg_tainted (base_reg, base_reg_size, base_reg_u8):0;
        int index_tainted = (index_reg_size>0)?is_reg_tainted (index_reg, index_reg_size, index_reg_u8):0;
        if (base_tainted || index_tainted) {
	    fprintf (stderr, "XXX - tainted base/index write should be OK as long as we verify equality to effective address?\n");
        }
        map<u_long, struct ctrl_flow_origin_value> *mem_map = (current_thread->ctrl_flow_info.is_in_diverged_branch == false? current_thread->ctrl_flow_info.store_set_mem: current_thread->ctrl_flow_info.that_branch_store_set_mem);
        uint32_t offset = 0;
        //also store the original taint value for this mem address
        while (offset < size) {
            taint_t *mem_taints = NULL;
            uint32_t count = get_cmem_taints_internal (mem_loc + offset, size-offset, &mem_taints);
            if (!mem_taints) { 
                for (uint32_t i = 0; i<count; ++i) { 
                    if (mem_map->find (mem_loc + offset + i) == mem_map->end()) {
                        (*mem_map)[mem_loc + offset + i].taint = 0;
                        (*mem_map)[mem_loc + offset + i].value = *((char*) (mem_loc+offset+i));
                    }
                }
            } else { 
                for (uint32_t i = 0; i<count; ++i) { 
                    if (mem_map->find (mem_loc + offset + i) == mem_map->end()) {
                        (*mem_map)[mem_loc + offset + i].taint = mem_taints[i];
                        (*mem_map)[mem_loc + offset + i].value = *((char*) (mem_loc+offset+i));
                    }
                }
            }
            offset += count;
        }
    }
}

TAINTSIGN print_inst_dest_reg (ADDRINT ip, int reg, PIN_REGISTER* regvalue) 
{
    //we don't need save the original value and taint for regs since we checkpoint all of them
    if (current_thread->ctrl_flow_info.is_in_original_branch) {
	CFDEBUG ("[CONTROL_FLOW_REG] ip %x reg %d @ %lu_%llu, value(%x)\n", ip, reg, current_thread->ctrl_flow_info.clock, current_thread->ctrl_flow_info.index, *regvalue->dword);
	current_thread->ctrl_flow_info.store_set_reg->insert (reg);
    }
    if (current_thread->ctrl_flow_info.is_in_diverged_branch) {
	CFDEBUG ("[CONTROL_FLOW_REG] ip %x reg %d @ %lu_%llu, value(%x)\n", ip, reg, current_thread->ctrl_flow_info.clock, current_thread->ctrl_flow_info.index, *regvalue->dword);
	current_thread->ctrl_flow_info.that_branch_store_set_reg->insert (reg);
    }
}

static void make_label_prefix (char* prefix, const struct ctrl_flow_block_index& dp) 
{
    sprintf (prefix, "b_%lu_%llu_%u", dp.clock, dp.index, dp.extra_loop_iterations);
}

static void check_diverge_point (ADDRINT ip, char* ins_str, BOOL taken, const CONTEXT* ctx, int ndx_incr) 
{
    if (!current_thread->ctrl_flow_info.is_in_diverged_branch && !current_thread->ctrl_flow_info.is_in_original_branch) {
	if (current_thread->ctrl_flow_info.diverge_point->empty() || 
	    current_thread->ctrl_flow_info.clock != current_thread->ctrl_flow_info.diverge_point->front().clock ||
	    current_thread->ctrl_flow_info.index+ndx_incr != current_thread->ctrl_flow_info.diverge_point->front().index) {
	    // If not an exact match, then look for generic match on instruction
	    std::map<u_long, struct ctrl_flow_block_index>::iterator it = current_thread->ctrl_flow_info.diverge_inst->find(ip);
	    if (it != current_thread->ctrl_flow_info.diverge_inst->end()) {
		CFDEBUG ("Found a potential divergence ip %x inst %s flag taint ", ip, ins_str);
		int tainted = 0;
		if (!strncmp(ins_str, "jns ", 4) || !strncmp(ins_str, "js ", 3)) {
		    tainted = current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE+SF_INDEX] ? 1 : 0;
		} else if (!strncmp(ins_str, "jno ", 4) || !strncmp(ins_str, "jo ", 3)) {
		    tainted = current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE+OF_INDEX] ? 1 : 0;
		} else if (!strncmp(ins_str, "je ", 3) || !strncmp(ins_str, "jz ", 3) || !strncmp(ins_str, "jne ", 4) || !strncmp(ins_str, "jnz ", 4)) {
		    tainted = current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE+ZF_INDEX] ? 1 : 0;
		} else if (!strncmp(ins_str, "jb ", 3) || !strncmp(ins_str, "jnae ", 5) || !strncmp(ins_str, "jc ", 3) || !strncmp(ins_str, "jnb ", 4) || !strncmp(ins_str, "jae ", 4) || !strncmp(ins_str, "jnc ", 4)) {
		    tainted = current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE+CF_INDEX] ? 1 : 0;
		} else if (!strncmp(ins_str, "jbe ", 4) || !strncmp(ins_str, "jna ", 4) || !strncmp(ins_str, "jnbe ", 5) || !strncmp(ins_str, "ja ", 3)) {
		    tainted = (current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE+CF_INDEX] | current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE+ZF_INDEX]) ? 1 : 0;
		} else if (!strncmp(ins_str, "jle ", 4) || !strncmp(ins_str, "jng ", 4) || !strncmp(ins_str, "jnle ", 5) || !strncmp(ins_str, "jg ", 3)) {
		    tainted = (current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE+ZF_INDEX] | current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE+OF_INDEX] | current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE+SF_INDEX]) ? 1 : 0;
		} else {
		    fprintf (stderr, "monitor_control_flow_tail: unrecognized jump type: %s\n", ins_str);
		    assert (0);
		}

		if (tainted) {
		    
		    bool need_swap = ((it->second.orig_taken && !taken) ||(!it->second.orig_taken && taken));
		    CFDEBUG ("is loop %d orig taken %d taken %d orig nonempty %d alt nonempty %d\n", it->second.ip == it->second.merge_ip, it->second.orig_taken, taken, it->second.orig_path_nonempty, it->second.alt_path_nonempty);
		    if (it->second.ip == it->second.merge_ip && 
			((!need_swap && !it->second.orig_path_nonempty) || 
			 (need_swap && !it->second.alt_path_nonempty))) {
			CFDEBUG ("This is an extra iteration for a loop\n");
			it->second.extra_loop_iterations++;
		    } else {
			it->second.extra_loop_iterations = 0;
		    }
		    
		    if (it->second.extra_loop_iterations > it->second.iter_count) {
			CFDEBUG ("Reached maximum extra loop iterations\n");
			it->second.extra_loop_iterations = 0;
		    } else {
			// Wildcard matches and flag tainted, so handle this divergence
			struct ctrl_flow_block_index dp;
			dp.clock = current_thread->ctrl_flow_info.clock;
			dp.index = current_thread->ctrl_flow_info.index+ndx_incr;
			dp.ip = it->second.ip;
			dp.orig_taken = it->second.orig_taken;
			dp.merge_ip = it->second.merge_ip;
			dp.orig_path = it->second.orig_path;
			dp.alt_path = it->second.alt_path;
			dp.extra_loop_iterations = it->second.extra_loop_iterations; // Use this to generate unique jump targets
			if (need_swap) {
			    dp.orig_path_nonempty = it->second.alt_path_nonempty;
			    dp.alt_path_nonempty = it->second.orig_path_nonempty;
			} else {
			    dp.orig_path_nonempty = it->second.orig_path_nonempty;
			    dp.alt_path_nonempty = it->second.alt_path_nonempty;
			}
			current_thread->ctrl_flow_info.diverge_point->push_front(dp);
		    }
		}
	    }
	}

        if (current_thread->ctrl_flow_info.diverge_point->empty() == false && 
	    current_thread->ctrl_flow_info.clock == current_thread->ctrl_flow_info.diverge_point->front().clock &&
	    current_thread->ctrl_flow_info.index+ndx_incr == current_thread->ctrl_flow_info.diverge_point->front().index) {

            CFDEBUG ("[CTRL_FLOW] before the divergence, index %lu_%llu, is_rolled_back %d diverge ip %lx ip %x\n", current_thread->ctrl_flow_info.clock, current_thread->ctrl_flow_info.index+ndx_incr-1, 
		     current_thread->ctrl_flow_info.is_rolled_back, current_thread->ctrl_flow_info.diverge_point->front().ip, ip);
	    assert (ip == current_thread->ctrl_flow_info.diverge_point->front().ip);
            if (current_thread->ctrl_flow_info.is_rolled_back == false) { 
                //checkpoint the current state and we may need to roll back later
                //even if we don't need to roll back, we still save the current shadow_reg_table and reg value before divergence which are used to initialize registers on different branches
                ctrl_flow_checkpoint (ctx, &current_thread->ctrl_flow_info.ckpt);
                // force to take the alternative path first here
                current_thread->ctrl_flow_info.is_in_diverged_branch = true;
                current_thread->ctrl_flow_info.is_in_diverged_branch_first_inst = true;
                current_thread->ctrl_flow_info.changed_jump = false;
                current_thread->ctrl_flow_info.change_jump = true;
		current_thread->ctrl_flow_info.save_index = current_thread->ctrl_flow_info.index+ndx_incr-1;
		CFDEBUG ("At divergence, the index is %lld\n", current_thread->ctrl_flow_info.index+ndx_incr-1);
                if (ins_str[0] != 'j') { 
		    fprintf (stderr, "unrecognized basic block exit instruction. currently assume it's always jump instruction 0x%x %s \n", ip, ins_str);
                    assert (0);
                } else if (strncmp (ins_str, "jecx", 4) == 0) {
                    fprintf (stderr, "jecx not implemented for control flow divergence. \n");
                    assert (0);
                }

		CFDEBUG ("[CTRL_FLOW] now the branch is taken %d\n", !taken);
		char changed_inst[64] = {0};
		char *t = changed_inst;
		char *p = ins_str;
		if (!taken) {
		    *t++ = *p++;
		    if (*p != 'n') {
			*t++ = 'n';
		    } else {
			p++;
		    }
		}
		for (; *p != ' '; p++, t++) *t = *p;

		char prefix[64];
		make_label_prefix (prefix, current_thread->ctrl_flow_info.diverge_point->front());

		OUTPUT_SLICE (ip, "%s %s_this_branch_init", changed_inst, prefix); 
		OUTPUT_SLICE_INFO ("#src_flag[FM?:1:4] #branch_taken %d block_index %llu", !taken, current_thread->ctrl_flow_info.index+ndx_incr-1);
		OUTPUT_SLICE (0, "jmp %s_that_branch_init", prefix);
		OUTPUT_SLICE_INFO ("")
		OUTPUT_SLICE (0, "%s_that_branch_execute_and_taint:", prefix);
		OUTPUT_SLICE_INFO ("")

                return;
            } 
        }
    }
}

TAINTSIGN monitor_control_flow_tail (ADDRINT ip, char* ins_str, BOOL taken, const CONTEXT* ctx) 
{ 
    check_diverge_point (ip, ins_str, taken, ctx, 1);

    ++ current_thread->ctrl_flow_info.index;
    if (*ppthread_log_clock != current_thread->ctrl_flow_info.clock) {
      current_thread->ctrl_flow_info.clock = *ppthread_log_clock;
      current_thread->ctrl_flow_info.index = 0;
    }
}

static void cleanup_after_merge()
{
    current_thread->ctrl_flow_info.is_in_original_branch = false;
    current_thread->ctrl_flow_info.change_jump = false;
    current_thread->ctrl_flow_info.change_original_branch = false;
    current_thread->ctrl_flow_info.diverge_point->pop_front();
    CFDEBUG ("Diverge points: %d\n", current_thread->ctrl_flow_info.diverge_point->size());
    if (current_thread->ctrl_flow_info.diverge_point->empty()) { 
	CFDEBUG ("No next divergence\n");
    } else {
	CFDEBUG ("Next divergence is at clock %ld index %lld\n", current_thread->ctrl_flow_info.diverge_point->front().clock, current_thread->ctrl_flow_info.diverge_point->front().index); 
    }
    current_thread->ctrl_flow_info.store_set_reg->clear();
    current_thread->ctrl_flow_info.store_set_mem->clear();
    current_thread->ctrl_flow_info.that_branch_store_set_reg->clear();
    current_thread->ctrl_flow_info.that_branch_store_set_mem->clear();
    current_thread->ctrl_flow_info.is_rolled_back = false;
}

TAINTSIGN monitor_merge_point (ADDRINT ip, char* ins_str, BOOL taken, const CONTEXT* ctx) 
{
    if (ip == current_thread->ctrl_flow_info.diverge_point->front().merge_ip) {
	if (current_thread->ctrl_flow_info.is_in_original_branch) {
	    //if (!current_thread->ctrl_flow_info.diverge_point->front().orig_path.empty()) {
	    if (ip == current_thread->ctrl_flow_info.diverge_point->front().ip && current_thread->ctrl_flow_info.diverge_point->front().orig_path_nonempty) {
		current_thread->ctrl_flow_info.diverge_point->front().orig_path_nonempty = false; // Only skip once
		CFDEBUG ("Original path: not yet at merge point\n");
	    } else {
		CFDEBUG ("Reached merge point on orig branch\n");

		char label_prefix[32];
		make_label_prefix (label_prefix, current_thread->ctrl_flow_info.diverge_point->front());

		CFDEBUG ("[CTRL_FLOW] taint_ctrl_flow_branch: merge before address %x\n", ip);
		CFDEBUG ("[CTRL_FLOW] found an expected control flow block, ip %x, index %llu\n", ip, current_thread->ctrl_flow_info.index);
		//We'll force to taint some registers and addresses 
		//Of course, initialization is necessary for those reg/mem that is originally untainted
		//TODO: we need to assign a meaningful value to the ctrl_flow_taint instead of 1
		init_ctrl_flow_this_branch (ip, ctx, current_thread->ctrl_flow_info.store_set_reg, current_thread->ctrl_flow_info.store_set_mem);
		/* JNF - this stmt. below seems questionable? Shouldn't we add taints only after handling original branch? */
		taint_ctrl_flow_branch (ip, 1, current_thread->ctrl_flow_info.store_set_reg, current_thread->ctrl_flow_info.store_set_mem);
		OUTPUT_SLICE (ip, "jmp %s_branch_end", label_prefix);
		OUTPUT_SLICE_INFO ("");
		OUTPUT_SLICE (ip, "%s_that_branch_init:", label_prefix);
		OUTPUT_SLICE_INFO ("");
		CFDEBUG ("[CTRL_FLOW] initialization of original reg/mem values\n");
		init_ctrl_flow_the_other_branch (ip, current_thread->ctrl_flow_info.store_set_reg, current_thread->ctrl_flow_info.store_set_mem);
		CFDEBUG ("[CTRL_FLOW] initialization of original reg/mem values done\n");
		OUTPUT_SLICE (ip, "jmp %s_that_branch_execute_and_taint", label_prefix);
		OUTPUT_SLICE_INFO ("");
		OUTPUT_SLICE (0, "%s_branch_end:", label_prefix); // Use 0x0 so that postprocessing program doesn't reorder verifications above this point (d'oh!)
		OUTPUT_SLICE_INFO ("");
		
		//then we need to also taint the other branch since we rolled back and remove all previously taint information
		//
		//TODO well, I think this might break the current taint backtracing tool
		//
		taint_ctrl_flow_branch (ip, 1, current_thread->ctrl_flow_info.that_branch_store_set_reg, current_thread->ctrl_flow_info.that_branch_store_set_mem);
		cleanup_after_merge ();
		CFDEBUG ("[CTRL_FLOW] This control flow is handled.\n");

		check_diverge_point (ip, ins_str, taken, ctx, 0); // Because we skipped this check while handling control flow
	    }
	} else if (current_thread->ctrl_flow_info.is_in_diverged_branch) {
	    
	    //if (!current_thread->ctrl_flow_info.diverge_point->front().alt_path.empty()) {
	    if (ip == current_thread->ctrl_flow_info.diverge_point->front().ip && current_thread->ctrl_flow_info.diverge_point->front().alt_path_nonempty) {
		current_thread->ctrl_flow_info.diverge_point->front().alt_path_nonempty = false; // Only skip once
		CFDEBUG ("Alternate path: not yet at merge point\n");
	    } else {
		CFDEBUG ("Merge point - alternate branch bb 0x%x merge 0x%x\n", ip, current_thread->ctrl_flow_info.diverge_point->front().merge_ip); 

		current_thread->ctrl_flow_info.is_in_diverged_branch = false;
		current_thread->ctrl_flow_info.is_in_diverged_branch_first_inst = false;
		
		char label_prefix[32];
		make_label_prefix (label_prefix, current_thread->ctrl_flow_info.diverge_point->front());

		CFDEBUG ("[CTRL_FLOW_THE_OTHER_BRANCH] taint_ctrl_flow_branch: the other branch: merge before this block, %x\n", ip);
		//TODO: we need to assign a meaningful value to the ctrl_flow_taint instead of 1
		init_ctrl_flow_this_branch (ip, ctx, current_thread->ctrl_flow_info.that_branch_store_set_reg, current_thread->ctrl_flow_info.that_branch_store_set_mem);
		taint_ctrl_flow_branch (ip, 1, current_thread->ctrl_flow_info.that_branch_store_set_reg, current_thread->ctrl_flow_info.that_branch_store_set_mem);
		OUTPUT_SLICE (ip, "jmp %s_branch_end", label_prefix);
		OUTPUT_SLICE_INFO ("");
		OUTPUT_SLICE (ip, "%s_this_branch_init:", label_prefix);
		OUTPUT_SLICE_INFO ("");
		CFDEBUG ("[CTRL_FLOW] initialization of original reg/mem values\n");
		
		init_ctrl_flow_the_other_branch (ip, current_thread->ctrl_flow_info.that_branch_store_set_reg, current_thread->ctrl_flow_info.that_branch_store_set_mem);
		CFDEBUG ("[CTRL_FLOW] initialization of original reg/mem values done\n");

		//let's roll back to the diverge point and take the original branch
		current_thread->ctrl_flow_info.is_in_original_branch = true;
		current_thread->ctrl_flow_info.change_jump = true;
		current_thread->ctrl_flow_info.is_rolled_back = true;
		CFDEBUG ("About to roll back\n");
		ctrl_flow_rollback (&current_thread->ctrl_flow_info.ckpt, current_thread->ctrl_flow_info.that_branch_store_set_mem);
	    }
	}
    }
}

static inline const char* memSizeToPrefix (int size)
{ 
    switch (size) {
    case 1: return " byte ptr";
    case 2: return " word ptr";
    case 4: return " dword ptr";
    case 8: return " qdword ptr";
    case 16: return " xmmword ptr";
    default:
	fprintf (stderr, "memSizeToPrefix: unrecognized mem size %d\n", size);
	assert (0);
    }
}

static inline void print_abs_address (ADDRINT ip, char* ins_str, u_long mem_loc)
{
    // Put absolute memory address in here
    char changed_str[64];
    char* s = strstr(ins_str, " ptr ");
    if (s) {
	char* t = changed_str;
	char* p = ins_str;
	while (p != s+5) *t++ = *p++;
	t += sprintf (t, "[0x%lx]", mem_loc);
	while (*p++ != ']');
	strcpy (t, p);
	OUTPUT_SLICE (ip, "%s", changed_str);
    } else {
	OUTPUT_SLICE (ip, "%s", ins_str); // Leave doens't use ptr notation, for example
    }
}

TAINTSIGN fw_slice_mem (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS) 
{ 
    VERIFY_BASE_INDEX;
    int mem_tainted = is_mem_tainted (mem_loc, mem_size);
    if (mem_tainted || still_tainted) {
	if (!still_tainted && mem_tainted) {
	    print_abs_address (ip, ins_str, mem_loc);
	} else {
	    OUTPUT_SLICE (ip, "%s", ins_str);
	}
	OUTPUT_SLICE_INFO ("#src_mem[%lx:%d:%u] #ndx_reg[%d:%d:%u,%d:%d:%u] #mem_value %u", mem_loc, mem_tainted, mem_size, base_reg, still_tainted ? base_tainted : 0, base_reg_size, 
			   index_reg, still_tainted ? index_tainted : 0, index_reg_size, get_mem_value32 (mem_loc, mem_size));
    }
    OUTPUT_SLICE_CHECK_ROTATE;
}

TAINTSIGN fw_slice_mem2fpureg (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, const CONTEXT* ctx, uint32_t fp_stack_change, BASE_INDEX_ARGS) 
{ 
    VERIFY_BASE_INDEX;
    int mem_tainted = is_mem_tainted (mem_loc, mem_size);
    if (mem_tainted || still_tainted) {
        char slice[256]; //convert the output instruction format
        char ch = ' ';
        int index = strchr (ins_str, ch) - ins_str;
        int len = 0;

        memset (slice, 0, 256);
        strncpy (slice, ins_str, index);
        len = index;
        index = strchr (ins_str + index + 1, ch) - ins_str;
        strcpy (slice + len, ins_str + index);

        fw_slice_track_fp_stack_top (ip, ins_str, ctx, fp_stack_change);
        if (mem_tainted != 1) print_extra_move_mem (ip, mem_loc, mem_size, mem_tainted);
        if (!still_tainted && mem_tainted) {
            print_abs_address (ip, slice, mem_loc);
        } else {
            OUTPUT_SLICE (ip, "%s", slice);
        }
	OUTPUT_SLICE_INFO ("#src_mem[%lx:%d:%u] #src_mem_value %llu", mem_loc, mem_tainted, mem_size, get_mem_value64 (mem_loc, mem_size));
    }
}

TAINTSIGN fw_slice_pop_reg (ADDRINT ip, uint32_t reg, u_long mem_loc, uint32_t mem_size) 
{ 
    int mem_tainted = is_mem_tainted (mem_loc, mem_size);
    if (mem_tainted) {
	OUTPUT_SLICE (ip, "mov %s, %s [0x%lx]", regName(reg,mem_size), memSizeToPrefix(mem_size), mem_loc);
	OUTPUT_SLICE_INFO ("#src_mem[%lx:%d:%u] #src_mem_value %u", mem_loc, mem_tainted, mem_size, get_mem_value32 (mem_loc, mem_size));
    }
}

TAINTSIGN fw_slice_2mem (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS) 
{ 
    VERIFY_BASE_INDEX_WRITE_RANGE;
    int mem_tainted = is_mem_tainted (mem_loc, mem_size);
    if (mem_tainted || still_tainted) {
	if (!still_tainted && mem_tainted) {
	    print_abs_address (ip, ins_str, mem_loc);	    
	} else {
	    OUTPUT_SLICE (ip, "%s", ins_str);
	}
	OUTPUT_SLICE_INFO ("#src_mem[%lx:%d:%u] #src_mem_value %u", mem_loc, mem_tainted, mem_size, get_mem_value32 (mem_loc, mem_size));
    }
}

TAINTSIGN fw_slice_reg (ADDRINT ip, char* ins_str, int reg, uint32_t size, const PIN_REGISTER* regvalue, uint32_t reg_u8) 
{
    int tainted = is_reg_tainted (reg, size, reg_u8);
    
    if (tainted) {
	if (tainted != 1) print_extra_move_reg (ip, reg, size, regvalue, reg_u8, tainted);
	if (!strncmp(ins_str, "lea ", 4)) {
	    // Pin puts in extra ptr that won't compile
	    char change_str[64];
	    char* p = strstr (ins_str, "ptr ");
	    assert (p);
	    u_long len = (u_long) p - (u_long) ins_str;
	    strncpy (change_str, ins_str, len);
	    strcpy (change_str+len, p+4);
	    OUTPUT_SLICE (ip, "%s", change_str);
	} else {
	    OUTPUT_SLICE (ip, "%s", ins_str);
	}
	OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%u] #src_reg_value %s", reg, tainted, size, print_regval(tmpbuf, regvalue, size));
    }
}

TAINTSIGN fw_slice_fpureg (ADDRINT ip, char* ins_str, int oreg, uint32_t size, const CONTEXT* ctx, uint32_t reg_u8, uint32_t fp_stack_change) 
{
    //get the actual st reg 
    int reg = map_fp_stack_reg (oreg, get_fp_stack_top (ctx));
    int tainted = is_reg_tainted (reg, size, reg_u8);
    
    if (tainted) {
	PIN_REGISTER regvalue;

        char slice[256]; //convert the output instruction format
	if (!strncmp(ins_str, "fchs ", 5) || !strncmp(ins_str, "frndint ", 8)) {
	    strcpy (slice, "fchs");
	} else {
	    char* p = strrchr (ins_str, ',');
	    int index;
	    if (p) {
		index = p - ins_str;
	    } else {
		index = strlen(ins_str);
	    }
	    char i = 0;
	    
	    memset (slice, 0, sizeof(slice));
	    memcpy (slice, ins_str, index);
	    //gcc representation of st register: st(0) instead of st0 (pin representation)
	    if (slice[index - 3] == 's' && slice[index - 2] == 't') {
		i = slice[index - 1];
		slice[index - 1] = '(';
		slice[index] = i;
		slice[index + 1] = ')';
	    }
	}

        fw_slice_track_fp_stack_top (ip, ins_str, ctx, fp_stack_change);

	PIN_GetContextRegval (ctx, REG (oreg), (UINT8*)&regvalue);
	OUTPUT_SLICE (ip, "%s", slice);
	OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%u] #src_reg_value %s", reg, tainted, size, print_regval(tmpbuf, &regvalue, size));
    }
}

TAINTSIGN fw_slice_fpureg2mem (ADDRINT ip, char* ins_str, int oreg, uint32_t size, const CONTEXT* ctx, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size, uint32_t fp_stack_change, BASE_INDEX_ARGS) 
{
    VERIFY_BASE_INDEX_WRITE;
    int reg = map_fp_stack_reg (oreg, get_fp_stack_top (ctx));
    int tainted = is_reg_tainted (reg, size, reg_u8);

    if (tainted) {
        char slice[256]; //convert the output instruction format
        PIN_REGISTER regvalue;

        int index = strrchr (ins_str, ',') - ins_str;
        char i = 0;

        memset (slice, 0, 256);
        memcpy (slice, ins_str, index);
        //gcc representation of st register: st(0) instead st0 (pin representation)
        if (slice[index - 3] == 's' && slice[index - 2] == 't') {
            i = slice[index - 1];
            slice[index - 1] = '(';
            slice[index] = i;
            slice[index + 1] = ')';
        }

        fw_slice_track_fp_stack_top (ip, ins_str, ctx, fp_stack_change);
        print_abs_address (ip, slice, mem_loc);
        PIN_GetContextRegval (ctx, REG (oreg), (UINT8*)&regvalue);
        OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%u], dst_mem[%lx:0:%u] #src_reg_value %s, dst_mem_value %u", reg, tainted, size, mem_loc, mem_size, print_regval(tmpbuf, &regvalue, size), get_mem_value32 (mem_loc, mem_size));
        add_modified_mem_for_final_check (mem_loc, mem_size);
    }
}

TAINTSIGN fw_slice_reg2mem (ADDRINT ip, char* ins_str, int reg, uint32_t size, const PIN_REGISTER* regvalue, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS) 
{
    VERIFY_BASE_INDEX_WRITE_RANGE;
    int tainted = is_reg_tainted (reg, size, reg_u8);
    if (tainted || still_tainted) {
	if (tainted != 1) print_extra_move_reg (ip, reg, size, regvalue, reg_u8, tainted);
	if (!still_tainted && tainted) {
	    print_abs_address (ip, ins_str, mem_loc);
	} else {
	    OUTPUT_SLICE (ip, "%s", ins_str);
	}
	OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%u], dst_mem[%lx:0:%u] #src_reg_value %s, dst_mem_value %u", reg, tainted, size, mem_loc, mem_size, print_regval(tmpbuf, regvalue, size), get_mem_value32 (mem_loc, mem_size));
	add_modified_mem_for_final_check (mem_loc, mem_size);
    }
}

TAINTSIGN fw_slice_push_reg (ADDRINT ip, int reg, const PIN_REGISTER* regvalue, uint32_t reg_u8, u_long mem_loc, uint32_t size) 
{
    int tainted = is_reg_tainted (reg, size, reg_u8);
    if (tainted) {
	if (tainted != 1) print_extra_move_reg (ip, reg, size, regvalue, reg_u8, tainted);
	OUTPUT_SLICE (ip, "mov %s [0x%lx], %s", memSizeToPrefix(size), mem_loc, regName(reg,size));
	OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%u], dst_mem[%lx:0:%u] #src_reg_value %s, dst_mem_value %u", reg, tainted, size, mem_loc, size, print_regval(tmpbuf, regvalue, size), get_mem_value32 (mem_loc, size));
	add_modified_mem_for_final_check (mem_loc, size);
    }
}

TAINTSIGN fw_slice_push_mem (ADDRINT ip, u_long mem_loc, u_long dst_mem_loc, uint32_t mem_size, BASE_INDEX_ARGS) 
{
    char* ins_str = (char *) ""; // To make macro happy
    VERIFY_BASE_INDEX;
    int tainted = is_mem_tainted (mem_loc, mem_size);
    if (tainted || still_tainted) {
	// Need to do this in two steps as no mem to mem move
	if (tainted != 1) print_extra_move_mem (ip, mem_loc, mem_size, tainted);
	OUTPUT_SLICE (ip, "push %s [0x%lx]", memSizeToPrefix(mem_size), mem_loc);
	OUTPUT_SLICE_INFO ("(former push instruction)");
	OUTPUT_SLICE (ip, "pop %s [0x%lx]", memSizeToPrefix(mem_size), dst_mem_loc);
	OUTPUT_SLICE_INFO ("#src_mem[%lx:%d:%u], dst_mem[%lx:%d:%u] #src_mem_value %d", mem_loc, tainted, mem_size, dst_mem_loc, tainted, mem_size, get_mem_value32 (mem_loc, mem_size));
	add_modified_mem_for_final_check (dst_mem_loc, mem_size);
    }
}

TAINTSIGN fw_slice_regreg (ADDRINT ip, char* ins_str, int dst_reg, uint32_t dst_regsize, const PIN_REGISTER* dst_regvalue, uint32_t dst_reg_u8, int src_reg, uint32_t src_regsize, const PIN_REGISTER* src_regvalue, uint32_t src_reg_u8) 
{
    int tainted1 = is_reg_tainted (dst_reg, dst_regsize, dst_reg_u8);
    int tainted2 = is_reg_tainted (src_reg, src_regsize, src_reg_u8);

    if (tainted1 || tainted2){
	if (tainted1 != 1) print_extra_move_reg (ip, dst_reg, dst_regsize, dst_regvalue, dst_reg_u8, tainted1);
	if (tainted2 != 1) print_extra_move_reg (ip, src_reg, src_regsize, src_regvalue, src_reg_u8, tainted2);
	if (!strncmp(ins_str, "lea ", 4)) {
	    // Pin puts in extra ptr that won't compile
	    char change_str[64];
	    char* p = strstr (ins_str, "ptr ");
	    assert (p);
	    u_long len = (u_long) p - (u_long) ins_str;
	    strncpy (change_str, ins_str, len);
	    strcpy (change_str+len, p+4);
	    OUTPUT_SLICE (ip, "%s", change_str);
	} else {
	    OUTPUT_SLICE (ip, "%s", ins_str);
	}
	OUTPUT_SLICE_INFO ("#src_regreg[%d:%d:%u,%d:%d:%u] #dst_reg_value %s, src_reg_value %s", dst_reg, tainted1, dst_regsize, src_reg, tainted2, src_regsize, print_regval(tmpbuf, dst_regvalue, dst_regsize), print_regval(tmpbuf2, src_regvalue, src_regsize));
    }
}

static void translate_fpu_inst (char* ins_str, char* slice) 
{
    char* ch = ins_str;
    char* outch = slice;
    
    // Copy instruction
    while (*ch != ' ' && *ch != '\0') *outch++ = *ch++;
    while (*ch != '\0') {
	*outch++ = *ch++; // Copies space
	if (!strncmp(ch, "st0", 3) && strncmp(ins_str, "fmul ", 5) && strncmp(ins_str, "fmulp ", 6) 
	    && strncmp(ins_str, "faddp ", 6) && strncmp(ins_str, "fcmov", 5)) {
	    ch += 3; // Skip over st0
	    if (*ch == ',') ch ++; // Skip following comma
	} else if (!strncmp(ch, "st", 2)) {
	    // Add parens
	    *outch++ = *ch++;
	    *outch++ = *ch++;
	    *outch++ = '(';
	    *outch++ = *ch++;
	    *outch++ = ')';
	    *outch++ = *ch++; // For comma
	} else {
	    // Copy operand
	    while (*ch != ' ' && *ch != '\0') *outch++ = *ch++;
	}
    }
    *outch++ = *ch++; // Terminate
}

TAINTSIGN fw_slice_fpuregfpureg (ADDRINT ip, char* ins_str, int dst_oreg, uint32_t dst_regsize,  uint32_t dst_reg_u8, int src_oreg, uint32_t src_regsize, const CONTEXT* ctx, uint32_t src_reg_u8, uint32_t fp_stack_change) 
{
    int sp = get_fp_stack_top (ctx);
    int dst_reg = map_fp_stack_reg (dst_oreg, sp);
    int src_reg = map_fp_stack_reg (src_oreg, sp);
    int tainted1 = is_reg_tainted (dst_reg, dst_regsize, dst_reg_u8);
    int tainted2 = is_reg_tainted (src_reg, src_regsize, src_reg_u8);
    if (tainted1 || tainted2){
        char slice[256]; //convert the output instruction format
        PIN_REGISTER dst_regvalue;
        PIN_REGISTER src_regvalue;

	translate_fpu_inst (ins_str, slice);

        fw_slice_track_fp_stack_top (ip, ins_str, ctx, fp_stack_change);

        PIN_GetContextRegval (ctx, REG(dst_oreg), (UINT8*)&dst_regvalue);
        PIN_GetContextRegval (ctx, REG(src_oreg), (UINT8*)&src_regvalue);
        if (tainted1 != 1) print_extra_move_reg_10 (ip, dst_oreg, &dst_regvalue, tainted1);
	if (tainted2 != 1) print_extra_move_reg_10 (ip, src_oreg, &src_regvalue, tainted2);

	OUTPUT_SLICE (ip, "%s", slice);
	OUTPUT_SLICE_INFO ("#src_regreg[%d:%d:%u,%d:%d:%u] #dst_reg_value %s, src_reg_value %s", 
		dst_reg, tainted1, dst_regsize, src_reg, tainted2, src_regsize, print_regval(tmpbuf, &dst_regvalue, dst_regsize), print_regval(tmpbuf2, &src_regvalue, src_regsize));
    }
}

TAINTSIGN fw_slice_fpu_cmov (ADDRINT ip, char* ins_str, int dst_oreg, uint32_t dst_regsize, int src_oreg, uint32_t src_regsize, const CONTEXT* ctx, uint32_t flags, BOOL executed)
{
    int sp = get_fp_stack_top (ctx);
    int dst_reg = map_fp_stack_reg (dst_oreg, sp);
    int src_reg = map_fp_stack_reg (src_oreg, sp);
    int tainted1 = is_reg_tainted (dst_reg, dst_regsize, 0);
    int tainted2 = is_reg_tainted (src_reg, src_regsize, 0);
    int tainted3 = is_flag_tainted (flags);
    PIN_REGISTER dst_regvalue;
    PIN_REGISTER src_regvalue;

    if (tainted1 || tainted2 || tainted3) {
	if (!tainted3 && !executed) {
	    // Basically a no-op
	} else if (!tainted3) {
	    char slice[256]; 
	    translate_fpu_inst (ins_str, slice);

	    if (!strncmp(ins_str, "fcmovb ", 7) || !strncmp(ins_str, "fcmovbe ", 8)) {
		OUTPUT_SLICE_EXTRA (ip, "stc");
	    } else if (!strncmp (ins_str, "fcmovnb, ", 8)) {
		OUTPUT_SLICE_EXTRA (ip, "clc");
	    } else if (!strncmp (ins_str, "fcmove, ", 7)) {
		OUTPUT_SLICE_EXTRA (ip, "pushfd");
		OUTPUT_SLICE_EXTRA (ip, "or dword ptr [esp], 0x%x", ZF_MASK);
		OUTPUT_SLICE_EXTRA (ip, "popfd");
	    } else if (!strncmp (ins_str, "fcmovne, ", 8)) {
		OUTPUT_SLICE_EXTRA (ip, "pushfd");
		OUTPUT_SLICE_EXTRA (ip, "and dword ptr [esp], 0x%x", ~ZF_MASK);
		OUTPUT_SLICE_EXTRA (ip, "popfd");
	    } else if (!strncmp (ins_str, "fcmovnbe, ", 8)) {
		OUTPUT_SLICE_EXTRA (ip, "clc");
		OUTPUT_SLICE_EXTRA (ip, "pushfd");
		OUTPUT_SLICE_EXTRA (ip, "and dword ptr [esp], 0x%x", ~ZF_MASK);
		OUTPUT_SLICE_EXTRA (ip, "popfd");
	    } else {
		fprintf (stderr, "unhandled FPU cmov: %s\n", ins_str);
	    }

	    PIN_GetContextRegval (ctx, REG(src_oreg), (UINT8*)&src_regvalue);
	    if (tainted2 != 1) print_extra_move_reg_10 (ip, src_oreg, &src_regvalue, tainted2);

	    OUTPUT_SLICE (ip, "%s", slice);
	    OUTPUT_SLICE_INFO ("#src_regregflag[%d:%d:%u,%d:%d:%u,FM:%d:%d] #dst_reg_value %s, src_reg_value %s", 
			       dst_reg, tainted1, dst_regsize, src_reg, tainted2, src_regsize, flags, tainted3, 
			       print_regval(tmpbuf, &dst_regvalue, dst_regsize), 
			       print_regval(tmpbuf2, &src_regvalue, src_regsize));
	} else {
	    char slice[256]; 
	    translate_fpu_inst (ins_str, slice);

	    PIN_GetContextRegval (ctx, REG(dst_oreg), (UINT8*)&dst_regvalue);
	    PIN_GetContextRegval (ctx, REG(src_oreg), (UINT8*)&src_regvalue);
	    if (tainted1 != 1) print_extra_move_reg_10 (ip, dst_oreg, &dst_regvalue, tainted1);
	    if (tainted2 != 1) print_extra_move_reg_10 (ip, src_oreg, &src_regvalue, tainted2);

	    OUTPUT_SLICE (ip, "%s", slice);
	    OUTPUT_SLICE_INFO ("#src_regregflag[%d:%d:%u,%d:%d:%u,FM:%d:%d] #dst_reg_value %s, src_reg_value %s", 
			       dst_reg, tainted1, dst_regsize, src_reg, tainted2, src_regsize, flags, tainted3, 
			       print_regval(tmpbuf, &dst_regvalue, dst_regsize), 
			       print_regval(tmpbuf2, &src_regvalue, src_regsize));
	}
    }
}

TAINTSIGN fw_slice_regregreg (ADDRINT ip, char* ins_str, int dst_reg, int src_reg, int count_reg, uint32_t dst_regsize, uint32_t src_regsize, uint32_t count_regsize, const PIN_REGISTER* dst_regvalue,
			      const PIN_REGISTER* src_regvalue, const PIN_REGISTER* count_regvalue, uint32_t dst_reg_u8, uint32_t src_reg_u8, uint32_t count_reg_u8)
{
    int tainted1 = is_reg_tainted (dst_reg, dst_regsize, dst_reg_u8);
    int tainted2 = is_reg_tainted (src_reg, src_regsize, src_reg_u8);
    int tainted3 = is_reg_tainted (count_reg, count_regsize, count_reg_u8);
    if (tainted1 || tainted2 || tainted3) {
	if (tainted1 != 1) print_extra_move_reg (ip, dst_reg, dst_regsize, dst_regvalue, dst_reg_u8, tainted1);
	if (tainted2 != 1) print_extra_move_reg (ip, src_reg, src_regsize, src_regvalue, src_reg_u8, tainted2);
	if (tainted3 != 1) print_extra_move_reg (ip, count_reg, count_regsize, count_regvalue, count_reg_u8, tainted3);
	OUTPUT_SLICE (ip, "%s", ins_str);
	OUTPUT_SLICE_INFO ("#src_regregreg[%d:%d:%u,%d:%d:%u,%d:%d:%u] #dst_reg_value %s, src_reg_value %s, count_reg_value %s", 
			   dst_reg, tainted1, dst_regsize, src_reg, tainted2, src_regsize, count_reg, tainted3, count_regsize, print_regval(tmpbuf, dst_regvalue, dst_regsize), print_regval(tmpbuf2, src_regvalue, src_regsize),
			   print_regval(tmpbuf3, count_regvalue, count_regsize));
    }
}

TAINTSIGN fw_slice_memreg (ADDRINT ip, char* ins_str, int reg, uint32_t reg_size, const PIN_REGISTER* reg_value, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS) 
{ 
    VERIFY_BASE_INDEX;

    int reg_tainted = is_reg_tainted (reg, reg_size, reg_u8);
    int mem_tainted = is_mem_tainted (mem_loc, mem_size);

    if (still_tainted || reg_tainted || mem_tainted) {
	if (reg_tainted != 1) print_extra_move_reg (ip, reg, reg_size, reg_value, reg_u8, reg_tainted);
	if (mem_tainted != 1) print_extra_move_mem (ip, mem_loc, mem_size, mem_tainted);
	if (!still_tainted && (reg_tainted || mem_tainted)) {
	    print_abs_address (ip, ins_str, mem_loc);
	} else {
	    OUTPUT_SLICE (ip, "%s", ins_str);
	}
	OUTPUT_SLICE_INFO ("#src_memreg[%lx:%d:%u,%d:%d:%u] #mem_value %u, reg_value %s", mem_loc, mem_tainted, mem_size, reg, reg_tainted, reg_size, get_mem_value32 (mem_loc, mem_size), print_regval(tmpbuf, reg_value, reg_size));
    }
}

TAINTSIGN fw_slice_memfpureg (ADDRINT ip, char* ins_str, int reg, uint32_t reg_size, const CONTEXT* ctx, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size, uint32_t fp_stack_change, BASE_INDEX_ARGS) 
{
    VERIFY_BASE_INDEX;

    int reg_tainted = is_reg_tainted (reg, reg_size, reg_u8);
    int mem_tainted = is_mem_tainted (mem_loc, mem_size);
    if (still_tainted || reg_tainted || mem_tainted) {
        PIN_REGISTER regvalue;
        PIN_GetContextRegval (ctx, REG (reg), (UINT8*)&regvalue);
        char slice[256]; //convert the output instruction format
        int index = strchr (ins_str, ' ') - ins_str;
        int len = 0;

        memset (slice, 0, 256);
        strncpy (slice, ins_str, index);
        len = index;
        index = strchr (ins_str + index + 1, ' ') - ins_str;
        strcpy (slice + len, ins_str + index);

        fw_slice_track_fp_stack_top (ip, ins_str, ctx, fp_stack_change);
	if (reg_tainted != 1) print_extra_move_reg (ip, reg, reg_size, &regvalue, reg_u8, reg_tainted);
	if (mem_tainted != 1) print_extra_move_mem (ip, mem_loc, mem_size, mem_tainted);

        if (!still_tainted && (reg_tainted || mem_tainted)) {
            print_abs_address (ip, slice, mem_loc);
        } else {
            OUTPUT_SLICE (ip, "%s", slice);
	}
	OUTPUT_SLICE_INFO ("#src_memreg[%lx:%d:%u,%d:%d:%u] #mem_value %u, reg_value %s", 
		mem_loc, mem_tainted, mem_size, reg, reg_tainted, reg_size, get_mem_value32 (mem_loc, mem_size), print_regval(tmpbuf, &regvalue, reg_size));
    }
}

TAINTSIGN fw_slice_memregreg (ADDRINT ip, char* ins_str, int reg1, uint32_t reg1_size, const PIN_REGISTER* reg1_value, uint32_t reg1_u8, 
			     int reg2, uint32_t reg2_size, const PIN_REGISTER* reg2_value, uint32_t reg2_u8, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS) 
{ 
    VERIFY_BASE_INDEX;
    int tainted1 = is_reg_tainted (reg1, reg1_size, reg1_u8);
    int tainted2 = is_mem_tainted (mem_loc, mem_size);
    int tainted3 = is_reg_tainted (reg2, reg2_size, reg2_u8);
    if (still_tainted || tainted1 || tainted2 || tainted3) {
	if (tainted1 != 1) print_extra_move_reg (ip, reg1, reg1_size, reg1_value, reg1_u8, tainted1);
	if (tainted2 != 1) print_extra_move_mem (ip, mem_loc, mem_size, tainted2);
	if (tainted3 != 1) print_extra_move_reg (ip, reg2, reg2_size, reg2_value, reg2_u8, tainted3);
	if (!still_tainted && (tainted1 || tainted2 || tainted3)) {
	    print_abs_address (ip, ins_str, mem_loc);
	} else {
	    OUTPUT_SLICE (ip, "%s", ins_str);
	}
	OUTPUT_SLICE_INFO ("#src_regmemreg[%d:%d:%u,%lx:%d:%u,%d:%d:%u] #reg_value %s, mem_value %u, reg_value %s", 
			   reg1, tainted1, reg1_size, mem_loc, tainted2, mem_size, reg2, tainted3, reg2_size, print_regval(tmpbuf, reg1_value, reg1_size), get_mem_value32 (mem_loc, mem_size), print_regval(tmpbuf2, reg2_value, reg2_size));
    }
}

//only used for cmov
TAINTSIGN fw_slice_regregflag_cmov (ADDRINT ip, char* ins_str, int dest_reg, uint32_t size, const PIN_REGISTER* dest_reg_value, uint32_t dest_reg_u8, int src_reg, const PIN_REGISTER* src_reg_value,
				    uint32_t src_reg_u8, uint32_t flag, BOOL executed) 
{ 
    int dest_reg_tainted = is_reg_tainted (dest_reg, size, dest_reg_u8);
    int src_reg_tainted = is_reg_tainted (src_reg, size, src_reg_u8);
    int flag_tainted = is_flag_tainted (flag);
    if (flag_tainted) {
	if (src_reg_tainted != 1) print_extra_move_reg (ip, src_reg, size, src_reg_value, src_reg_u8, src_reg_tainted);
	if (dest_reg_tainted != 1) print_extra_move_reg (ip, dest_reg, size, dest_reg_value, dest_reg_u8, dest_reg_tainted);
	OUTPUT_SLICE (ip, "%s", ins_str);
	OUTPUT_SLICE_INFO ("#src_regregflag[%d:%d:%u,%d:%d:%u,FM%x:%d:4] #dest_value %s, src_value %s, executed %d", 
			   dest_reg, dest_reg_tainted, size, src_reg, src_reg_tainted, size, flag, flag_tainted, print_regval(tmpbuf, dest_reg_value, size), print_regval(tmpbuf2, src_reg_value, size), executed);
    } else {
	if (executed && src_reg_tainted) {
	    char* e;
	    char* p = strstr (ins_str, "cmov");
	    assert (p);
	    for (e = p; !isspace(*e); e++);
	    OUTPUT_SLICE (ip, "%.*smov%s", (int)((u_long)p-(u_long)ins_str), ins_str, e);
	    OUTPUT_SLICE_INFO ("#src_regregflag[%d:%d:%u,%d:%d:%u,FM%x:%d:4] #dest_value %s, src_value %s, executed %d", 
			       dest_reg, dest_reg_tainted, size, src_reg, src_reg_tainted, size, flag, flag_tainted, print_regval(tmpbuf, dest_reg_value, size), print_regval(tmpbuf2, src_reg_value, size), executed);
	}
	// If flag not tainted and mov not executed, then this is a noop in the slice
    }
}

//deprecated function
TAINTSIGN fw_slice_mem2fpu(ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS)
{
    VERIFY_BASE_INDEX;
    int mem_tainted = is_mem_tainted (mem_loc, mem_size);
    if (still_tainted) assert (0); // FPU would be tainted - OOPS 
    if (mem_tainted) verify_memory (ip, mem_loc, mem_size);
}

TAINTSIGN fw_slice_regmemflag_cmov (ADDRINT ip, char* ins_str, int dest_reg, uint32_t dest_reg_size, PIN_REGISTER* dest_reg_value, uint32_t dest_reg_u8, u_long mem_loc, uint32_t mem_size, uint32_t flag, 
				    BOOL executed, BASE_INDEX_ARGS) 
{ 
    int dest_reg_tainted = is_reg_tainted (dest_reg, dest_reg_size, dest_reg_u8);
#ifdef PRINT_DEBUG_INFO
    int base_tainted = (base_reg_size>0)?is_reg_tainted (base_reg, base_reg_size, base_reg_u8):0;
    int index_tainted = (index_reg_size>0)?is_reg_tainted (index_reg, index_reg_size, index_reg_u8):0;
    (void)base_tainted; (void)index_tainted; //shutup compiler
#endif
    int mem_tainted2 = is_mem_tainted (mem_loc, mem_size);
    int tainted4 = is_flag_tainted (flag);

    if (tainted4) {
	VERIFY_BASE_INDEX;
	if (mem_tainted2 != 1) print_extra_move_mem (ip, mem_loc, mem_size, mem_tainted2);
	if (dest_reg_tainted != 1) print_extra_move_reg (ip, dest_reg, dest_reg_size, dest_reg_value, dest_reg_u8, dest_reg_tainted);
	if (!still_tainted) {
	    print_abs_address (ip, ins_str, mem_loc);
	} else {
	    OUTPUT_SLICE (ip, "%s", ins_str);
	}
	OUTPUT_SLICE_INFO ("#src_memregregflag[%d:%d:%u,%lx:%d:%u,%d:%d:%u,%d:%d:%u,F%x:%d:-] #dst_reg[%d:%d:%u] #dest_reg_value %u base_reg_value %u, mem_value %u, index_reg_value %u, executed %d", 
			   dest_reg, dest_reg_tainted, dest_reg_size, mem_loc, mem_tainted2, mem_size, base_reg, base_tainted, base_reg_size, index_reg, index_tainted, index_reg_size, flag, tainted4, 
			   dest_reg, dest_reg_tainted, dest_reg_size, *dest_reg_value->dword, base_reg_value, 
			   get_mem_value32 (mem_loc, mem_size), index_reg_value, executed);
    } else {
	if (executed) {
	    VERIFY_BASE_INDEX;
            //this should be equivalent to  the condition in fw_slice_memregreg_mov 
	    if (mem_tainted2 || still_tainted) {
		char changed_str[64];
		char* p = strstr (ins_str, "cmov");
		char* s = ins_str;
		char* t = changed_str;
		while (s != p) *t++ = *s++;

		*t++ = 'm'; *t++ = 'o'; *t++ = 'v';
		while (!isspace(*s)) s++;

		if (!still_tainted && mem_tainted2) {
		    char* p = strstr(s, " ptr ");
		    while (s != p+5) *t++ = *s++;
		    t += sprintf (t, "[0x%lx]", mem_loc);
		    while (*s++ != ']');
		}
		while (*s != '\0') *t++ = *s++;
		OUTPUT_SLICE (ip, "%s", changed_str);
		OUTPUT_SLICE_INFO ("#src_memregregflag[%lx:%d:%u,%d:%d:%u,%d:%d:%u,f%x:%d:-] #dst_reg[%d:%d:%u] #base_value %u, mem_value %u, index_value %u, executed %d", 
				   mem_loc, mem_tainted2, mem_size, base_reg, base_tainted, base_reg_size, index_reg, index_tainted, index_reg_size, flag, tainted4, 
				   dest_reg, dest_reg_tainted, dest_reg_size, base_reg_value, get_mem_value32 (mem_loc, mem_size), index_reg_value, executed);
	    }
	}
	// If flag not tainted and mov not executed, then this is a noop in the slice
    }
}

static void change_jump (uint32_t mask, const CONTEXT* ctx, char* ins_str)
{
    //if we enter this jump for the first time, we need to force the jump to take a different direction
    //now we modify the eflag value
    CONTEXT save_ctx;
    PIN_SaveContext (ctx, &save_ctx);
    uint32_t value = (uint32_t) PIN_GetContextReg (&save_ctx, LEVEL_BASE::REG_EFLAGS);
    CFDEBUG ("[CTRL_FLOW] %s force to jump: eflag value before %x\n", ins_str, value);
    if (!strncmp(ins_str, "jle ", 4) || !strncmp(ins_str, "jng ", 4)) {
	if ((value & ZF_MASK) || (!!(value & SF_MASK) != !!(value & OF_MASK))) {
	    value &= ~(ZF_MASK|SF_MASK|OF_MASK);
	} else {
	    value |= ZF_MASK;
	}
    } else if (!strncmp(ins_str, "jnle ", 5) || !strncmp(ins_str, "jg ", 3)) {
	if (!(value & ZF_MASK) && (!!(value & SF_MASK) == !!(value & OF_MASK))) {
	    value |= ZF_MASK;
	} else {
	    value &= ~(ZF_MASK|SF_MASK|OF_MASK);
	}
    } else {
	if (mask & CF_FLAG) value ^= CF_MASK;
	if (mask & PF_FLAG) value ^= PF_MASK;
	if (mask & AF_FLAG) value ^= AF_MASK;
	if (mask & ZF_FLAG) value ^= ZF_MASK;
	if (mask & SF_FLAG) value ^= SF_MASK;
	if (mask & OF_FLAG) value ^= OF_MASK;
	if (mask & DF_FLAG) value ^= DF_MASK;
    }
    CFDEBUG ("[CTRL_FLOW] %s force to jump: eflag value after %x\n", ins_str, value);
    PIN_SetContextReg (&save_ctx, LEVEL_BASE::REG_EFLAGS, value);
    current_thread->ctrl_flow_info.is_in_diverged_branch_first_inst = false;
    current_thread->ctrl_flow_info.changed_jump = true;
    PIN_ExecuteAt (&save_ctx);
}

TAINTSIGN fw_slice_jmp_reg (ADDRINT ip, char* ins_str, uint32_t reg, uint32_t reg_size, uint32_t is_upper8, ADDRINT target) 
{
    if (is_reg_tainted (reg, reg_size, is_upper8)) {
	verify_register (ip, reg, reg_size, target, is_upper8, target);
    }
}

TAINTSIGN fw_slice_jmp_mem (ADDRINT ip, char* ins_str, uint32_t mem_addr, uint32_t mem_size, ADDRINT target) 
{
    if (is_mem_tainted(mem_addr, mem_size)) {
	verify_memory (ip, mem_addr, mem_size);
    }
}

TAINTSIGN fw_slice_flag (ADDRINT ip, char* ins_str, uint32_t mask) 
{
    if (is_flag_tainted (mask)) {
	OUTPUT_SLICE (ip, "%s", ins_str);
	OUTPUT_SLICE_INFO ("#src_flag[FM%x:1:4]", mask);
    }
}

TAINTSIGN fw_slice_condjump (ADDRINT ip, char* ins_str, uint32_t mask, BOOL taken, ADDRINT target, const CONTEXT* ctx) 
{
#ifdef TRACK_CTRL_FLOW_DIVERGE
    if (current_thread->ctrl_flow_info.is_in_original_branch) {
	CFDEBUG ("Original branch ip 0x%x taken %d target %x next %lx\n", ip, taken, target, current_thread->ctrl_flow_info.diverge_point->front().orig_path.front().first);
	CFDEBUG ("Flag tainted %d is_diverged_branch %d change jump %d\n", is_flag_tainted(mask), current_thread->ctrl_flow_info.is_in_diverged_branch, current_thread->ctrl_flow_info.change_jump);
	if (current_thread->ctrl_flow_info.change_original_branch) { 
	    CFDEBUG ("Restart orig branch - change the jump here ip 0x%x\n", ip);
	    current_thread->ctrl_flow_info.change_original_branch = false;
	    change_jump (mask, ctx, ins_str);
	}
	if (!current_thread->ctrl_flow_info.change_jump) { 
	    // Track the original path and see if we diverge
	    pair<u_long, char> orig_branch = current_thread->ctrl_flow_info.diverge_point->front().orig_path.front();
	    current_thread->ctrl_flow_info.diverge_point->front().orig_path.pop();
	    if ((orig_branch.second == 't' && !taken) || (orig_branch.second == 'n' && taken)) {
		CFDEBUG ("Uh-oh! Original path not going expeced direction orig branch 0x%lx, ip 0x%x orig %c taken %d\n", orig_branch.first, ip, orig_branch.second, taken);
		// We are going to "abort" this control flow divergence
		char label_prefix[256];
		make_label_prefix (label_prefix, current_thread->ctrl_flow_info.diverge_point->front());

		OUTPUT_SLICE (ip, "jmp %s_branch_end", label_prefix);
		OUTPUT_SLICE_INFO ("");
		OUTPUT_SLICE (ip, "%s_that_branch_init:", label_prefix);
		OUTPUT_SLICE_INFO ("");
		// This should have been a control flow divergence at the diverge point (oops) 
		OUTPUT_SLICE (ip, "call handle_delayed_jump_diverge");
		OUTPUT_SLICE_INFO ("");
		OUTPUT_SLICE (ip, "%s_branch_end:", label_prefix);
		OUTPUT_SLICE_INFO ("");
		cleanup_after_merge();
		CFDEBUG ("Aborted handling of this divergence\n");
	    }
	}
    }

    if (current_thread->ctrl_flow_info.is_in_diverged_branch) { 
	CFDEBUG ("Should I change jump along diverged branch? ip 0x%x taken %d orig taken %d target %x\n", ip, taken, current_thread->ctrl_flow_info.diverge_point->front().orig_taken, target);
	CFDEBUG ("Flag tainted %d is_diverged_branch %d change jump %d\n", is_flag_tainted(mask), current_thread->ctrl_flow_info.is_in_diverged_branch, current_thread->ctrl_flow_info.change_jump);
	if (current_thread->ctrl_flow_info.is_in_diverged_branch_first_inst) {
	    if ((current_thread->ctrl_flow_info.diverge_point->front().orig_taken && !taken) ||
		(!current_thread->ctrl_flow_info.diverge_point->front().orig_taken && taken)) {
		CFDEBUG ("It appears that execution takes alternate path\n");
		swap (current_thread->ctrl_flow_info.diverge_point->front().orig_path, 
		      current_thread->ctrl_flow_info.diverge_point->front().alt_path);
	    } else {
		CFDEBUG ("Execution takes expected path\n");
	    }
	    change_jump(mask, ctx, ins_str);
	} else {
	    if (current_thread->ctrl_flow_info.changed_jump) {
		CFDEBUG ("Jump at 0x%x was changed\n", ip);
		current_thread->ctrl_flow_info.changed_jump = false;
	    } else {
		pair<u_long, char> alt_branch = current_thread->ctrl_flow_info.diverge_point->front().alt_path.front();
		current_thread->ctrl_flow_info.diverge_point->front().alt_path.pop();
		CFDEBUG ("Alternate branch %lx was taken %c at branch %x taken %d\n", alt_branch.first, alt_branch.second, ip, taken);
		if ((alt_branch.second == 't' && !taken) || (alt_branch.second == 'n' && taken)) {
		    CFDEBUG ("Change jump direction\n");
		    change_jump(mask, ctx, ins_str);
		}
	    }
	}
    }
#endif

    if (is_flag_tainted (mask)) {
#ifdef TRACK_CTRL_FLOW_DIVERGE
        if (!current_thread->ctrl_flow_info.is_in_diverged_branch && current_thread->ctrl_flow_info.change_jump) { 
            current_thread->ctrl_flow_info.change_jump = false; // We've already replaced this jump with divergence 
        } else if (current_thread->ctrl_flow_info.is_in_diverged_branch && current_thread->ctrl_flow_info.change_jump) { 
	    current_thread->ctrl_flow_info.change_jump = false; // We've already replaced this jump with divergence 
        } else {
#endif
	    char change_str[64];
	    char *t = change_str;
	    char *p = ins_str;
	    if (taken) {
		*t++ = *p++;
		if (*p != 'n') {
		    *t++ = 'n';
		} else {
		    p++;
		}
	    }
	    for (; *p != ' '; p++, t++) *t = *p;
	    *t++ = ' ';
	    strcpy (t, "jump_diverge");
	    OUTPUT_SLICE_VERIFICATION ("pushfd");
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE_VERIFICATION ("push %ld", jump_count++);
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
            OUTPUT_SLICE (ip, "%s", change_str);
            OUTPUT_SLICE_INFO ("#src_flag[FM%x:1:4] #branch_taken %d", mask, (int) taken);
	    OUTPUT_SLICE_VERIFICATION ("add esp, 4");
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE_VERIFICATION ("popfd");
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
#ifdef TRACK_CTRL_FLOW_DIVERGE
        }
#endif 
    } else { 
	if (current_thread->ctrl_flow_info.change_jump) fprintf (stderr, "Diverge at non-tainted jump: %x %s mask %x\n", ip, ins_str, mask);
        assert (current_thread->ctrl_flow_info.change_jump == false); //we diverge at a non-tainted jump??
    }
}

/* Mostly the same as above but the jump depends on a register value like ECX - any other registers? */
/* For now, we are not going to handle divergences - may need to change this later */
TAINTSIGN fw_slice_condregjump (ADDRINT ip, char* ins_str, int reg, uint32_t regsize, BOOL taken, ADDRINT target, const CONTEXT* ctx) 
{
#if 0
    if (current_thread->ctrl_flow_info.is_in_original_branch) {
	CFDEBUG ("Original branch ip 0x%x taken %d target %x next %lx\n", ip, taken, target, current_thread->ctrl_flow_info.diverge_point->front().orig_path.front().first);
	CFDEBUG ("Flag tainted %d is_diverged_branch %d change jump %d\n", is_flag_tainted(mask), current_thread->ctrl_flow_info.is_in_diverged_branch, current_thread->ctrl_flow_info.change_jump);
	if (current_thread->ctrl_flow_info.change_original_branch) { 
	    CFDEBUG ("Restart orig branch - change the jump here ip 0x%x\n", ip);
	    current_thread->ctrl_flow_info.change_original_branch = false;
	    change_jump (mask, ctx, ins_str);
	}
	if (!current_thread->ctrl_flow_info.change_jump) { 
	    // Track the original path and see if we diverge
	    pair<u_long, char> orig_branch = current_thread->ctrl_flow_info.diverge_point->front().orig_path.front();
	    current_thread->ctrl_flow_info.diverge_point->front().orig_path.pop();
	    if ((orig_branch.second == 't' && !taken) || (orig_branch.second == 'n' && taken)) {
		CFDEBUG ("Uh-oh! Original path not going expeced direction orig branch 0x%lx, ip 0x%x orig %c taken %d\n", orig_branch.first, ip, orig_branch.second, taken);
		// We are going to "abort" this control flow divergence
		char label_prefix[256];
		make_label_prefix (label_prefix, current_thread->ctrl_flow_info.diverge_point->front());

		OUTPUT_SLICE (ip, "jmp %s_branch_end", label_prefix);
		OUTPUT_SLICE_INFO ("");
		OUTPUT_SLICE (ip, "%s_that_branch_init:", label_prefix);
		OUTPUT_SLICE_INFO ("");
		// This should have been a control flow divergence at the diverge point (oops) 
		OUTPUT_SLICE (ip, "call handle_delayed_jump_diverge");
		OUTPUT_SLICE_INFO ("");
		OUTPUT_SLICE (ip, "%s_branch_end:", label_prefix);
		OUTPUT_SLICE_INFO ("");
		cleanup_after_merge();
		CFDEBUG ("Aborted handling of this divergence\n");
	    }
	}
    }

    if (current_thread->ctrl_flow_info.is_in_diverged_branch) { 
	CFDEBUG ("Should I change jump along diverged branch? ip 0x%x taken %d orig taken %d target %x\n", ip, taken, current_thread->ctrl_flow_info.diverge_point->front().orig_taken, target);
	CFDEBUG ("Flag tainted %d is_diverged_branch %d change jump %d\n", is_flag_tainted(mask), current_thread->ctrl_flow_info.is_in_diverged_branch, current_thread->ctrl_flow_info.change_jump);
	if (current_thread->ctrl_flow_info.is_in_diverged_branch_first_inst) {
	    if ((current_thread->ctrl_flow_info.diverge_point->front().orig_taken && !taken) ||
		(!current_thread->ctrl_flow_info.diverge_point->front().orig_taken && taken)) {
		CFDEBUG ("It appears that execution takes alternate path\n");
		swap (current_thread->ctrl_flow_info.diverge_point->front().orig_path, 
		      current_thread->ctrl_flow_info.diverge_point->front().alt_path);
	    } else {
		CFDEBUG ("Execution takes expected path\n");
	    }
	    change_jump(mask, ctx, ins_str);
	} else {
	    if (current_thread->ctrl_flow_info.changed_jump) {
		CFDEBUG ("Jump at 0x%x was changed\n", ip);
		current_thread->ctrl_flow_info.changed_jump = false;
	    } else {
		pair<u_long, char> alt_branch = current_thread->ctrl_flow_info.diverge_point->front().alt_path.front();
		current_thread->ctrl_flow_info.diverge_point->front().alt_path.pop();
		CFDEBUG ("Alternate branch %lx was taken %c at branch %x taken %d\n", alt_branch.first, alt_branch.second, ip, taken);
		if ((alt_branch.second == 't' && !taken) || (alt_branch.second == 'n' && taken)) {
		    CFDEBUG ("Change jump direction\n");
		    change_jump(mask, ctx, ins_str);
		}
	    }
	}
    }
#endif

    if (is_reg_tainted (reg, regsize, 0)) {
#if 0
        if (!current_thread->ctrl_flow_info.is_in_diverged_branch && current_thread->ctrl_flow_info.change_jump) { 
            current_thread->ctrl_flow_info.change_jump = false; // We've already replaced this jump with divergence 
        } else if (current_thread->ctrl_flow_info.is_in_diverged_branch && current_thread->ctrl_flow_info.change_jump) { 
	    current_thread->ctrl_flow_info.change_jump = false; // We've already replaced this jump with divergence 
        } else {
#endif
	    OUTPUT_SLICE_VERIFICATION ("pushfd");
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE_VERIFICATION ("push %ld", jump_count++);
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);

	    if (!strncmp(ins_str, "jcxz ", 5)) {
		if (taken) {
		    /* No opposite branch */
		    OUTPUT_SLICE (ip, "jcxz b_jcxz_%lu", jump_count);
		    OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%d] #branch_taken 1", reg, regsize, is_reg_tainted(reg, regsize, 0));
		    OUTPUT_SLICE (ip, "jmp jump_diverge");
		    OUTPUT_SLICE_VERIFICATION ("b_jcxz_%lu: add esp, 4", jump_count);
		} else {
		    OUTPUT_SLICE (ip, "jcxz b_jcxz_%lu_1", jump_count);
		    OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%d] #branch_taken 0", reg, regsize, is_reg_tainted(reg, regsize, 0));
		    OUTPUT_SLICE (ip, "jmp b_jcxz_%lu_2", jump_count);
		    OUTPUT_SLICE_INFO ("");
		    OUTPUT_SLICE (ip, "b_jcxz_%lu_1: jmp jump_diverge", jump_count);
		    OUTPUT_SLICE_INFO ("");
		    OUTPUT_SLICE_VERIFICATION ("b_jcxz_%lu_2: add esp, 4", jump_count);
		}
	    } else if (!strncmp(ins_str, "jecxz ", 6)) {
		if (taken) {
		    /* No opposite branch */
		    OUTPUT_SLICE (ip, "jecxz b_jecxz_%lu", jump_count);
		    OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%d] #branch_taken 1", reg, regsize, is_reg_tainted(reg, regsize, 0));
		    OUTPUT_SLICE (ip, "jmp jump_diverge");
		    OUTPUT_SLICE_INFO ("");
		    OUTPUT_SLICE_VERIFICATION ("b_jecxz_%lu: add esp, 4", jump_count);
		} else {
		    OUTPUT_SLICE (ip, "jecxz b_jecxz_%lu_1", jump_count);
		    OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%d] #branch_taken 0", reg, regsize, is_reg_tainted(reg, regsize, 0));
		    OUTPUT_SLICE (ip, "jmp b_jecxz_%lu_2", jump_count);
		    OUTPUT_SLICE_INFO ("");
		    OUTPUT_SLICE (ip, "b_jecxz_%lu_1: jmp jump_diverge", jump_count);
		    OUTPUT_SLICE_INFO ("");
		    OUTPUT_SLICE_VERIFICATION ("b_jecxz_%lu_2: add esp, 4", jump_count);
		}
	    } else {
		fprintf (stderr, "unhandled register-based conditional jump: %s\n", ins_str);
		assert (0);
	    }

	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE_VERIFICATION ("popfd");
	    OUTPUT_SLICE_VERIFICATION_INFO ("comes with %08x", ip);
#if 0
        }
    } else { 
	if (current_thread->ctrl_flow_info.change_jump) fprintf (stderr, "Diverge at non-tainted jump: %x %s mask %x\n", ip, ins_str, mask);
        assert (current_thread->ctrl_flow_info.change_jump == false); //we diverge at a non-tainted jump??
#endif 
    }
}

TAINTSIGN fw_slice_flag2mem (ADDRINT ip, char* ins_str, uint32_t mask, u_long mem_loc, uint32_t mem_size, BASE_INDEX_ARGS) 
{
    VERIFY_BASE_INDEX_WRITE;
    if (is_flag_tainted (mask)) {
	print_abs_address (ip, ins_str, mem_loc);
	OUTPUT_SLICE_INFO ("#src_flag[FM%x:1:4] #dst_mem[%lx:0:%u]", mask, mem_loc, mem_size);
	add_modified_mem_for_final_check (mem_loc, mem_size);
    }
}

//note: reg_size doesn't always correspond to the actual regsize (16 bytes) 
TAINTINT fw_slice_pcmpistri_reg_reg (ADDRINT ip, char* ins_str, uint32_t reg1, uint32_t reg2, uint32_t reg1_size, uint32_t reg2_size, char* reg1_val, char* reg2_val) 
{
    int reg1_taint = is_reg_tainted (reg1, reg1_size, 0);
    int reg2_taint = is_reg_tainted (reg2, reg2_size, 0);
    if (reg1_taint || reg2_taint) {
	if (reg1_taint != 1) add_imm_load_to_slice (reg1, 16, reg1_val, ip);
	if (reg2_taint != 1) add_imm_load_to_slice (reg2, 16, reg2_val, ip);
	OUTPUT_SLICE (ip, "%s", ins_str);
	OUTPUT_SLICE_INFO ("#src_regreg_pcmp[i_or_e]stri[%d:%d:%u,%d:%d:%u] #dst_reg_value %.16s, src_reg_value %.16s", reg1, reg1_taint, reg1_size, reg2, reg2_taint, reg2_size, reg1_val, reg2_val);
	return 1;
    }
    return 0;
}

TAINTINT fw_slice_pcmpistri_reg_mem (ADDRINT ip, char* ins_str, uint32_t reg1, u_long mem_loc2, uint32_t reg1_size, uint32_t mem_size, char* reg1_val) 
{
    int reg1_taint = is_reg_tainted (reg1, reg1_size, 0);
    int mem_taints = is_mem_tainted (mem_loc2, mem_size);
    if (reg1_taint || mem_taints) {
	if (reg1_taint != 1) add_imm_load_to_slice (reg1, 16, reg1_val, ip);
	OUTPUT_SLICE (ip, "%s", ins_str);
	OUTPUT_SLICE_INFO ("#src_regmem_pcmp[i_or_e]stri[%d:%d:%u,%lx:%d:%u] #dst_reg_value %.16s, src_mem_value %u", reg1, reg1_taint, reg1_size, mem_loc2, mem_taints, mem_size, reg1_val, get_mem_value32(mem_loc2, mem_size));
        if (!mem_taints) { 
            OUTPUT_SLICE (0, "[BUG][SLICE] cannot handle tainted mem for pcmpistri for now, because we didn't init the untainted mem values correctly\n");
            OUTPUT_SLICE_INFO ("");
        }
    }
    return 0;
}

static inline u_long find_string_len (ADDRINT mem_loc, ADDRINT al_val, ADDRINT ecx_val, uint32_t rep_type, int& mem_tainted)
{
    u_long i;
    for (i = 0; i < ecx_val; i++) {
	if (is_mem_tainted(mem_loc+i,1)) {
	    mem_tainted = 1;
	} else {
	    if ((rep_type == REP_TYPE_NE && *(u_char *) (mem_loc+i) == al_val) ||
		(rep_type == REP_TYPE_E && *(u_char *) (mem_loc+i) != al_val)) {
		i++;
		break;
	    }
	}
    }
    return i;
}

TAINTSIGN fw_slice_string_scan (ADDRINT ip, char* ins_str, ADDRINT mem_loc, ADDRINT eflags, ADDRINT al_val, ADDRINT ecx_val, ADDRINT edi_val, uint32_t first_iter, uint32_t rep_type) 
{ 
    //only check on the first iteration
    if (first_iter) {

	assert (is_flag_tainted(DF_FLAG) == 0); // JNF: Not sure how to handle this flag?
	assert ((eflags & DF_MASK) == 0); 

	int al_tainted = is_reg_tainted (LEVEL_BASE::REG_EAX, 1, 0);
	int ecx_tainted = is_reg_tainted (LEVEL_BASE::REG_ECX, 4, 0);
	int edi_tainted = is_reg_tainted (LEVEL_BASE::REG_EDI, 4, 0);

	// Determine max. string length, mem taint
	int mem_tainted = 0;
	u_long stringlen = find_string_len (mem_loc, al_val, ecx_val, rep_type, mem_tainted);

	if (mem_tainted) {
	    for (u_long j = 0; j < stringlen; j++) {
		if (!is_mem_tainted(mem_loc+j,1) && !is_readonly (mem_loc+j, 1)) {
		    // We need to move the string values to scan if they are not tainted (and not already there) 
		    OUTPUT_SLICE (0, "mov byte ptr [0x%lx], %d", mem_loc+j, *(u_char *) (mem_loc+j));
		    OUTPUT_SLICE_INFO ("comes with %08x", ip);
		    add_modified_mem_for_final_check (mem_loc+j,1);
		}
	    }
	}

	// If partially tainted, need to restore for validation. If untainted, restore for instruction 
	if (rep_type != REP_TYPE && al_tainted == 0 && mem_tainted) print_extra_move_reg_1 (ip, LEVEL_BASE::REG_EAX, al_val, false);
	if (ecx_tainted == 2 || (ecx_tainted == 0 && mem_tainted)) print_extra_move_reg_4 (ip, LEVEL_BASE::REG_ECX, ecx_val, ecx_tainted);
	if (edi_tainted == 2 || (edi_tainted == 0 && mem_tainted)) print_extra_move_reg_4 (ip, LEVEL_BASE::REG_EDI, edi_val, edi_tainted);

	// Always verify registers if not untainted
	if (rep_type != REP_TYPE && al_tainted) verify_register (ip, LEVEL_BASE::REG_EAX, 1, al_val, 0, mem_loc);
	if (ecx_tainted) verify_register (ip, LEVEL_BASE::REG_ECX, 4, ecx_val, 0, mem_loc);
	if (edi_tainted) verify_register (ip, LEVEL_BASE::REG_EDI, 4, edi_val, 0, mem_loc);

	// Scan string if src memory is tainted 
	if (mem_tainted) {
	    // Pin generates extra stuff that won't compile - cut it out
	    char* p = strstr (ins_str, "scas");
	    assert (p);
	    *(p+5) = '\0';
	    if (eflags & DF_MASK) { 
		OUTPUT_SLICE (0, "std");
	    } else {
		OUTPUT_SLICE (0, "cld");
	    }
	    OUTPUT_SLICE_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE (ip, "%s", ins_str);
	    OUTPUT_SLICE_INFO ("#src_mem[%x:%d:%lu] #ndx_reg[%d:%d:%d,%d:%d:%d,%d:%d:%d]", mem_loc, mem_tainted, stringlen, LEVEL_BASE::REG_ECX, ecx_tainted, 4, LEVEL_BASE::REG_EAX, al_tainted, 1, LEVEL_BASE::REG_EDI, edi_tainted, 4);
	}
    }
}

TAINTSIGN fw_slice_string_move (ADDRINT ip, char* ins_str, ADDRINT src_mem_loc, ADDRINT dst_mem_loc, ADDRINT eflags, ADDRINT ecx_val, ADDRINT edi_val, ADDRINT esi_val, UINT32 op_size, uint32_t first_iter) 
{ 
    //only check on the first iteration
    if (first_iter) {

        int size = (int) (ecx_val*op_size);
        if (!size) return; 

	assert (is_flag_tainted(DF_FLAG) == 0); // JNF: Not sure how to handle this flag?
	if (eflags & DF_MASK) { 
            src_mem_loc -= size;
            dst_mem_loc -= size;
	}

	int ecx_tainted = is_reg_tainted (LEVEL_BASE::REG_ECX, 4, 0); 
	int edi_tainted = is_reg_tainted (LEVEL_BASE::REG_EDI, 4, 0);
	int esi_tainted = is_reg_tainted (LEVEL_BASE::REG_ESI, 4, 0);
	int mem_tainted = is_mem_tainted (src_mem_loc, size);

	if (mem_tainted) {
	    for (long j = 0; j < size; j++) {
		if (!is_mem_tainted(src_mem_loc+j,1) && !is_readonly (src_mem_loc+j, 1)) {
		    // We need to move the string values to scan if they are not tainted (and not already there) 
		    OUTPUT_SLICE (0, "mov byte ptr [0x%lx], %d", src_mem_loc+j, *(u_char *) (src_mem_loc+j));
		    OUTPUT_SLICE_INFO ("comes with %08x", ip);
		    add_modified_mem_for_final_check (src_mem_loc+j,1);
		}
	    }
	}

	// If partially tainted, need to restore for validation. If untainted, restore for instruction
	if (first_iter != SPECIAL_VAL_NO_REP) {  // Instruction has no rep, so ecx is unused
	    if (ecx_tainted == 2 || (ecx_tainted == 0 && mem_tainted)) print_extra_move_reg_4 (ip, LEVEL_BASE::REG_ECX, ecx_val, ecx_tainted);
	}
	if (edi_tainted == 2 || (edi_tainted == 0 && mem_tainted)) print_extra_move_reg_4 (ip, LEVEL_BASE::REG_EDI, edi_val, edi_tainted);
	if (esi_tainted == 2 || (esi_tainted == 0 && mem_tainted)) print_extra_move_reg_4 (ip, LEVEL_BASE::REG_ESI, esi_val, esi_tainted);

	// Always verify registers if not untainted
        // TODO: xdou: I remembered there was a case where ecx could change for java???
	if (first_iter != SPECIAL_VAL_NO_REP) {  // Instruction has no rep, so exc is unused
	    if (ecx_tainted) verify_register (ip, LEVEL_BASE::REG_ECX, 4, ecx_val, 0, 0);
	}
	if (edi_tainted) verify_register (ip, LEVEL_BASE::REG_EDI, 4, edi_val, 0, 0);
	if (esi_tainted) verify_register (ip, LEVEL_BASE::REG_ESI, 4, esi_val, 0, 0);

	// Move string if src memory is tainted 
	if (mem_tainted) {
	    // Pin generates extra stuff that won't compile - cut it out
	    char* p = strstr (ins_str, "movs");
	    assert (p);
	    *(p+5) = '\0';
	    if (eflags & DF_MASK) { 
		OUTPUT_SLICE (0, "std");
	    } else {
		OUTPUT_SLICE (0, "cld");
	    }
	    OUTPUT_SLICE_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE (ip, "%s", ins_str);
	    OUTPUT_SLICE_INFO ("#src_mem[%x:%d:%u] #dst_mem[%x:%d:%d] #ndx_reg[%d:%d:%d,%d:%d:%d,%d:%d:%d]", src_mem_loc, mem_tainted, size, dst_mem_loc, is_mem_tainted(dst_mem_loc, size), size, LEVEL_BASE::REG_ECX, ecx_tainted, 4, LEVEL_BASE::REG_EDI, edi_tainted, 4, LEVEL_BASE::REG_ESI, esi_tainted, 4);

	    // We modified these bytes - add to hash
	    add_modified_mem_for_final_check (dst_mem_loc, size);
	}
    }
}

TAINTSIGN fw_slice_string_compare (ADDRINT ip, char* ins_str, ADDRINT mem_loc1, ADDRINT mem_loc2, ADDRINT eflags, ADDRINT ecx_val, ADDRINT edi_val, ADDRINT esi_val, UINT32 op_size, uint32_t first_iter) 
{ 
    //only check on the first iteration
    if (first_iter) {
        int size = (int) (ecx_val*op_size);
        if (!size) return; 

	assert (is_flag_tainted(DF_FLAG) == 0); // JNF: Not sure how to handle this flag?
	assert ((eflags & DF_MASK) == 0); 

	int ecx_tainted = is_reg_tainted (LEVEL_BASE::REG_ECX, 4, 0);
	int edi_tainted = is_reg_tainted (LEVEL_BASE::REG_EDI, 4, 0);
	int esi_tainted = is_reg_tainted (LEVEL_BASE::REG_ESI, 4, 0);
	int mem1_tainted = is_mem_tainted (mem_loc1, size);
	int mem2_tainted = is_mem_tainted (mem_loc2, size);

	if (mem1_tainted) {
	    for (long j = 0; j < size; j++) {
		if (!is_mem_tainted(mem_loc1+j,1) && !is_readonly (mem_loc1+j, 1)) {
		    // We need to move the string values to scan if they are not tainted (and not already there) 
		    OUTPUT_SLICE (0, "mov byte ptr [0x%lx], %d", mem_loc1+j, *(u_char *) (mem_loc1+j));
		    OUTPUT_SLICE_INFO ("comes with %08x", ip);
		    add_modified_mem_for_final_check (mem_loc1+j,1);
		}
	    }
	}
	if (mem2_tainted) {
	    for (long j = 0; j < size; j++) {
		if (!is_mem_tainted(mem_loc2+j,1) && !is_readonly (mem_loc2+j, 1)) {
		    // We need to move the string values to scan if they are not tainted (and not already there) 
		    OUTPUT_SLICE (0, "mov byte ptr [0x%lx], %d", mem_loc2+j, *(u_char *) (mem_loc2+j));
		    OUTPUT_SLICE_INFO ("comes with %08x", ip);
		    add_modified_mem_for_final_check (mem_loc2+j,1);
		}
	    }
	}

	// If partially tainted, need to restore for validation. If untainted, restore for instruction
	if (ecx_tainted == 2 || (ecx_tainted == 0 && (mem1_tainted||mem2_tainted))) print_extra_move_reg_4 (ip, LEVEL_BASE::REG_ECX, ecx_val, ecx_tainted);
	if (edi_tainted == 2 || (edi_tainted == 0 && (mem1_tainted||mem2_tainted))) print_extra_move_reg_4 (ip, LEVEL_BASE::REG_EDI, edi_val, edi_tainted);
	if (esi_tainted == 2 || (esi_tainted == 0 && (mem1_tainted||mem2_tainted))) print_extra_move_reg_4 (ip, LEVEL_BASE::REG_ESI, esi_val, esi_tainted);

	// Always verify registers if not untainted
	if (ecx_tainted) verify_register (ip, LEVEL_BASE::REG_ECX, 4, ecx_val, 0, 0);
	if (edi_tainted) verify_register (ip, LEVEL_BASE::REG_EDI, 4, edi_val, 0, 0);
	if (esi_tainted) verify_register (ip, LEVEL_BASE::REG_ESI, 4, esi_val, 0, 0);

	// Move string if src memory is tainted 
	if (mem1_tainted||mem2_tainted) {
	    if (eflags & DF_MASK) { 
		OUTPUT_SLICE (0, "std");
	    } else {
		OUTPUT_SLICE (0, "cld");
	    }
	    OUTPUT_SLICE_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE (ip, "%s", ins_str);
	    OUTPUT_SLICE_INFO ("#src_mem[%x:%d:%u,%x:%d:%u] #ndx_reg[%d:%d:%d,%d:%d:%d,%d:%d:%d]", mem_loc1, mem1_tainted, size, mem_loc2, mem2_tainted, size, LEVEL_BASE::REG_ECX, ecx_tainted, 4, 
			       LEVEL_BASE::REG_EDI, edi_tainted, 4, LEVEL_BASE::REG_ESI, esi_tainted, 4);
	}
    }
}

TAINTSIGN fw_slice_string_store (ADDRINT ip, char* ins_str, ADDRINT dst_mem_loc, ADDRINT eflags, const PIN_REGISTER* eax_val, ADDRINT ecx_val, ADDRINT edi_val, UINT32 op_size, uint32_t first_iter) 
{ 
    //only check on the first iteration
    if (first_iter) {

        int size = (int) (ecx_val*op_size);
        if (!size) return; 

	assert (is_flag_tainted(DF_FLAG) == 0); // JNF: Not sure how to handle this flag?
	assert ((eflags & DF_MASK) == 0); 

	int eax_tainted = is_reg_tainted (LEVEL_BASE::REG_EAX, op_size, 0);
	int ecx_tainted = is_reg_tainted (LEVEL_BASE::REG_ECX, op_size, 0);
	int edi_tainted = is_reg_tainted (LEVEL_BASE::REG_EDI, op_size, 0);

	// If partially tainted, need to restore for validation. If untainted, restore for instruction
	// JNF: xxx why was this changed?  don't we need to restore the values if untainted?
	if (eax_tainted == 2) print_extra_move_reg (ip, LEVEL_BASE::REG_EAX, op_size, eax_val, 0, eax_tainted);

	// Always verify ecx and edi if not untainted
	if (first_iter != SPECIAL_VAL_NO_REP) {  // Instruction has no rep, so ecx is unused
	    if (ecx_tainted) verify_register (ip, LEVEL_BASE::REG_ECX, 4, ecx_val, 0, 0);
	}
	if (edi_tainted) verify_register (ip, LEVEL_BASE::REG_EDI, 4, edi_val, 0, 0);

	if (eax_tainted) {
	    if (eflags & DF_MASK) { 
		OUTPUT_SLICE (0, "std");
	    } else {
		OUTPUT_SLICE (0, "cld");
	    }
	    OUTPUT_SLICE_INFO ("comes with %08x", ip);
	    OUTPUT_SLICE (ip, "%s", ins_str);
	    OUTPUT_SLICE_INFO ("#src_reg[%d:%d:%u] #ndx_reg[%d:%d:%d,%d:%d:%d]", LEVEL_BASE::REG_EAX, eax_tainted, op_size, LEVEL_BASE::REG_ECX, ecx_tainted, 4, LEVEL_BASE::REG_EDI, edi_tainted, 4);

	    // We modified these bytes - add to hash
	    add_modified_mem_for_final_check (dst_mem_loc, size);
	}
    }
}

TAINTSIGN taint_add_reg2mem_offset (u_long mem_loc, int reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags)
{
    unsigned i = 0;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;
    taint_t t = 0;

    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
		t = merge_taints(shadow_reg_table[reg_off + offset + i], mem_taints[i]);
		mem_taints[i]  = t;
            }
        } else {
            // mem not tainted, just a set
	    if (shadow_reg_table[reg_off]) { // JNF: I think this is wrong
                set_mem_taints(mem_offset, count, &shadow_reg_table[reg_off + offset]);
            }
	    t = shadow_reg_table[reg_off]; // Also wrong
        }
        offset += count;
        mem_offset += count;
    }

    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

// reg2mem rep
TAINTSIGN taint_rep_lbreg2mem (u_long mem_loc, int reg, int count)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = shadow_reg_table[reg * REG_SIZE];
    uint32_t size = count;
    if (t) {
        unsigned i = 0; 
        while (i < size) {
            // FIXME: size is wrong on each iter
            i += set_cmem_taints_one(mem_loc + i, size, t);
        }
    } else {
        clear_mem_taints(mem_loc, size);
    }
}

TAINTSIGN taint_rep_ubreg2mem (u_long mem_loc, int reg, int count)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = shadow_reg_table[reg * REG_SIZE + 1];
    uint32_t size = count;
    if (t) {
        unsigned i = 0; 
        while (i < size) {
            // FIXME: size is wrong on each iter
            i += set_cmem_taints_one(mem_loc + i, size, t);
        }
    } else {
        clear_mem_taints(mem_loc, size);
    }
}

TAINTSIGN taint_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&shadow_reg_table[dst_reg_off], &shadow_reg_table[src_reg_off], size * sizeof(taint_t));
}

// reg2reg
static inline void taint_reg2reg (int dst_reg, int src_reg, uint32_t size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE], &shadow_reg_table[src_reg * REG_SIZE], size * sizeof(taint_t));
}

// JNF: What mike did - but only really right for zero extension, not sign extension, etc.
TAINTSIGN taint_reg2reg_ext_offset (int dst_reg_off, int src_reg_off, uint32_t size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&shadow_reg_table[dst_reg_off], &shadow_reg_table[src_reg_off], size * sizeof(taint_t));
    memset(&shadow_reg_table[dst_reg_off+size], 0, (REG_SIZE-size) * sizeof(taint_t));
}

TAINTSIGN taint_fpureg2fpureg (int dst_reg, int src_reg, uint32_t size, const CONTEXT* ctx, uint32_t opcode)
{
    int sp = get_fp_stack_top (ctx);
    src_reg = map_fp_stack_reg (src_reg, sp);
    if (opcode == XED_ICLASS_FLD) {
        //per FLD specification
        sp = decrement_fp_stack_top (sp);
    }
    dst_reg = map_fp_stack_reg (dst_reg, sp);
    taint_reg2reg (dst_reg, src_reg, size);
}

TAINTSIGN taint_fpu_cmov (int dst_oreg, int src_oreg, uint32_t size, const CONTEXT* ctx, uint32_t mask, BOOL executed)
{
    int sp = get_fp_stack_top (ctx);
    int src_reg = map_fp_stack_reg (src_oreg, sp);
    int dst_reg = map_fp_stack_reg (dst_oreg, sp);
    taint_t t = merge_flag_taints (mask);
    if (!t) {
	if (executed) { 
	    // Becomes a move
	    taint_fpureg2fpureg (dst_oreg, src_oreg, size, ctx, XED_ICLASS_CMOVNBE);
	} 
    } else {
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	uint32_t dst_offset = dst_reg*REG_SIZE;
	uint32_t src_offset = src_reg*REG_SIZE;
	uint32_t i;
	for (i = 0; i < size; ++i) { 
	    shadow_reg_table[dst_offset+i] = merge_taints (shadow_reg_table[dst_offset+i], 
							   merge_taints (t, shadow_reg_table[src_offset+i]));
	} 
    }
    // If not tainted and not executed, no taint changes
}


TAINTSIGN taint_wregwreg2wreg (int dst_reg, int base_reg, int index_reg) { 
    uint32_t size = 4;
    taint_t base_taint = merge_reg_taints(base_reg, size, 0);
    taint_t index_taint = merge_reg_taints (index_reg, size, 0);
    taint_t result = merge_taints (base_taint, index_taint);
    uint32_t i = 0;
    for (; i<size; ++i) { 
        current_thread->shadow_reg_table[dst_reg*REG_SIZE+i] = result;
    }
}

TAINTSIGN taint_add_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags)
{
    unsigned i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = 0;

    for (i = 0; i < size; i++) {
	t = merge_taints(shadow_reg_table[dst_reg_off + i], shadow_reg_table[src_reg_off + i]);
	shadow_reg_table[dst_reg_off + i]  = t;
    } 

    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

TAINTSIGN taint_add_reg2esp (ADDRINT ip, int src_reg, uint32_t src_size, uint32_t src_value, uint32_t src_u8, uint32_t set_flags, uint32_t clear_flags)
{
    uint32_t i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    int src_tainted = is_reg_tainted (src_reg, src_size, src_u8);
    assert (src_tainted != 2); // Verification would fail for partial taint
    if (src_tainted) {
        if (find (ignored_inst.begin(), ignored_inst.end(), ip) != ignored_inst.end()) {
            //randomization of JVM stack
            fprintf (stderr, "Force to untaint esp (for JVM at first)\n");
            print_extra_move_reg_4 (ip, src_reg, src_value, 0);
        }
	verify_register (ip, src_reg, src_size, src_value, src_u8, 0);

	// Since we verified, src and flags are not tainted
	for (i = 0; i < src_size; i++) {
	    shadow_reg_table[src_reg*REG_SIZE+i] = 0;
	} 
	set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], 0, set_flags, clear_flags); 
    }
}

TAINTSIGN taint_mix_reg_offset (int reg_off, uint32_t size, uint32_t set_flags, uint32_t clear_flags)
{
    unsigned i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = shadow_reg_table[reg_off];

    for (i = 1; i < size; i++) {
	t = merge_taints(shadow_reg_table[reg_off + i], t);
    } 
    for (i = 0; i < size; i++) {
	shadow_reg_table[reg_off + i] = t;
    }

    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

TAINTSIGN taint_mix_cwde ()
{
    // This is simply a sign extend of EAX from 2 to 4 bytes
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    int eax_offset = LEVEL_BASE::REG_EAX*REG_SIZE;
    shadow_reg_table[eax_offset+2] = shadow_reg_table[eax_offset+1];
    shadow_reg_table[eax_offset+3] = shadow_reg_table[eax_offset+1];
}

TAINTSIGN taint_bswap_offset (int reg_offset)
{
    // Swap bytes 0 and 3, 1 and 2
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = shadow_reg_table[reg_offset];
    shadow_reg_table[reg_offset] = shadow_reg_table[reg_offset+3];
    shadow_reg_table[reg_offset+3] = t;
    t = shadow_reg_table[reg_offset+1];
    shadow_reg_table[reg_offset+1] = shadow_reg_table[reg_offset+2];
    shadow_reg_table[reg_offset+2] = t;
}

TAINTSIGN taint_mix_regreg2reg_offset (int dst_off, uint32_t dst_size, int src1_off, uint32_t src1_size, int src2_off, uint32_t src2_size, 
				       uint32_t set_flags, uint32_t clear_flags)
{
    unsigned i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    taint_t t = shadow_reg_table[dst_off];
    for (i = 1; i < dst_size; i++) {
	t = merge_taints(shadow_reg_table[dst_off + i], t);
    } 
    for (i = 0; i < src1_size; i++) {
	t = merge_taints(shadow_reg_table[src1_off + i], t);
    } 
    for (i = 0; i < src2_size; i++) {
	t = merge_taints(shadow_reg_table[src2_off + i], t);
    } 
    for (i = 0; i < dst_size; i++) {
	shadow_reg_table[dst_off + i] = t;
    }
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

TAINTSIGN taint_mix_reg2reg_offset (int dst_off, uint32_t dst_size, int src_off, uint32_t src_size, uint32_t set_flags, uint32_t clear_flags)
{
    unsigned i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    taint_t t = shadow_reg_table[dst_off];
    for (i = 1; i < dst_size; i++) {
	t = merge_taints(shadow_reg_table[dst_off + i], t);
    } 
    for (i = 0; i < src_size; i++) {
	t = merge_taints(shadow_reg_table[src_off + i], t);
    } 
    for (i = 0; i < dst_size; i++) {
	shadow_reg_table[dst_off + i] = t;
    }
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

TAINTSIGN taint_mixmov_reg2reg_offset (int dst_off, uint32_t dst_size, int src_off, uint32_t src_size, uint32_t set_flags, uint32_t clear_flags)
{
    unsigned i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    taint_t t = shadow_reg_table[src_off];
    for (i = 1; i < src_size; i++) {
	t = merge_taints(shadow_reg_table[src_off + i], t);
    } 
    for (i = 0; i < dst_size; i++) {
	shadow_reg_table[dst_off + i] = t;
    }
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

TAINTSIGN taint_mix_fpureg2fpureg (int dst_reg, uint32_t dst_size, int src_reg, uint32_t src_size, const CONTEXT* ctx)
{
    int sp = get_fp_stack_top (ctx);
    dst_reg = map_fp_stack_reg (dst_reg, sp);
    src_reg = map_fp_stack_reg (src_reg, sp);
    taint_mix_reg2reg_offset (dst_reg*REG_SIZE, dst_size, src_reg*REG_SIZE, src_size, -1, -1);
}

TAINTSIGN taint_mix_mem (u_long mem_loc, uint32_t size, uint32_t set_flags, uint32_t clear_flags, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size) 
{ 
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t bi_taint = base_index_taint (base_reg_off, base_reg_size, index_reg_off, index_reg_size);
    taint_t t = merge_mem_taints (mem_loc, size);
    t = merge_taints (t, bi_taint);
    set_cmem_taints_one (mem_loc, size, t);
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags); 
}

TAINTSIGN taint_mix_mem2reg (u_long mem_loc, uint32_t size, int dst_off, uint32_t dst_size, uint32_t set_flags, uint32_t clear_flags, uint32_t base_reg_off, uint32_t base_reg_size, uint32_t index_reg_off, uint32_t index_reg_size) 
{ 
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t bi_taint = base_index_taint (base_reg_off, base_reg_size, index_reg_off, index_reg_size);
    taint_t t = merge_mem_taints (mem_loc, size);
    t = merge_taints (t, bi_taint);
    for (uint32_t i = 0; i < dst_size; i++) {
	shadow_reg_table[dst_off + i] = t;
    }
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags);
}

TAINTSIGN taint_mix_reg2mem_offset (u_long mem_loc, uint32_t memsize, int reg_off, uint32_t reg_size, uint32_t set_flags, uint32_t clear_flags) 
{ 
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = merge_mem_taints (mem_loc, memsize);
    uint32_t i;

    for (i = 0; i < reg_size; i++) {
	t = merge_taints(shadow_reg_table[reg_off + i], t);
    } 
    set_cmem_taints_one (mem_loc, memsize, t);
    set_clear_flags (&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, set_flags, clear_flags); 
}

TAINTSIGN taint_mix_fpuregmem2fpureg (u_long mem_loc, uint32_t memsize, int src_reg, uint32_t src_regsize, int dst_reg, uint32_t dst_regsize, const CONTEXT* ctx, TAINT_BASE_INDEX_ARGS)
{
    int sp = get_fp_stack_top (ctx);
    src_reg = map_fp_stack_reg (src_reg, sp);
    dst_reg = map_fp_stack_reg (dst_reg, sp);
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t bi_taint = base_index_taint (base_reg_off, base_reg_size, index_reg_off, index_reg_size);
    taint_t t = merge_mem_taints (mem_loc, memsize);
    taint_t src_t = merge_reg_taints (src_reg, src_regsize, 0);
    t = merge_taints (t, bi_taint);
    t = merge_taints (t, src_t);
    for (uint32_t i = 0; i < dst_regsize; i++) {
	shadow_reg_table[dst_reg*REG_SIZE + i] = t;
    }
}

TAINTSIGN taint_xchg_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size) 
{ 
    taint_t tmp[REG_SIZE];
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy((char*)&tmp, &shadow_reg_table[dst_reg_off], size * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg_off], &shadow_reg_table[src_reg_off], size * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg_off], (char*)&tmp, size * sizeof(taint_t));
}

TAINTSIGN taint_xchg_fpureg2fpureg (int dst_reg, int src_reg, uint32_t size, const CONTEXT* ctx) 
{ 
    taint_t tmp[REG_SIZE];
    int sp = get_fp_stack_top (ctx);
    dst_reg = map_fp_stack_reg (dst_reg, sp);
    src_reg = map_fp_stack_reg (src_reg, sp);
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy((char*)&tmp, &shadow_reg_table[dst_reg*REG_SIZE], size * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg*REG_SIZE], &shadow_reg_table[src_reg*REG_SIZE], size * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg*REG_SIZE], (char*)&tmp, size * sizeof(taint_t));
}

// Assumes 16->4 for now
TAINTSIGN taint_mask_reg2reg (int dst_reg, int src_reg)
{
    taint_t t;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    int i;

    t = shadow_reg_table[src_reg * REG_SIZE];
    for (i = 1; i < 8; i++) {
	t = merge_taints(t, shadow_reg_table[src_reg * REG_SIZE + i]);
    }
    shadow_reg_table[dst_reg * REG_SIZE] = t;
    t = shadow_reg_table[src_reg * REG_SIZE+8];
    for (i = 9; i < 16; i++) {
	t = merge_taints(t, shadow_reg_table[src_reg * REG_SIZE + i]);
    }
    shadow_reg_table[dst_reg * REG_SIZE+1] = t;
    shadow_reg_table[dst_reg * REG_SIZE+2] = 0;
    shadow_reg_table[dst_reg * REG_SIZE+3] = 0;
}

TAINTSIGN taint_mem2mem (u_long src_loc, u_long dst_loc, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++) {
        taint_t* dst_mem_taint = get_mem_taints_internal(dst_loc + i, 1);
        taint_t* src_mem_taint = get_mem_taints_internal(src_loc + i, 1);

        if (!src_mem_taint && !dst_mem_taint) {
            continue;
        } else if (!src_mem_taint) {
            clear_mem_taints(dst_loc + i, 1);
        } else {
            set_mem_taints(dst_loc + i, 1, src_mem_taint);
        }
    }
}

TAINTSIGN taint_call_near (u_long esp)
{
    //printf ("taint_call_near: clear mem %lx\n", esp-4);
    clear_cmem_taints (esp-4, 4); /* IP written to stack */
}

TAINTSIGN taint_call_far (u_long esp)
{
    //printf ("taint_call_near: clear mem %lx\n", esp-8);
    clear_cmem_taints (esp-8, 8); /* IP and CS written to stack */
}

// 3-way operations (for supporting instructions like mul and div)
TAINTSIGN taint_add2_bmemlbreg_hwreg (u_long mem_loc, int src_reg, int dst_reg)
{
    taint_t merged_taint;
    taint_t* mem_taints;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    mem_taints = get_mem_taints_internal(mem_loc, 1);
    if (mem_taints) {
        merged_taint = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE]);
        shadow_reg_table[dst_reg * REG_SIZE] = merged_taint;
        shadow_reg_table[dst_reg * REG_SIZE + 1] = merged_taint;
    } else {
        shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
        shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE];
    }
}

TAINTSIGN taint_add2_hwmemhwreg_2hwreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[2];
    taint_t final_merged_taint;

    mem_taints = get_mem_taints_internal(mem_loc, 1);
    if (mem_taints) {
        merged_taints[0] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE]);
    } else {
        merged_taints[0] = shadow_reg_table[src_reg * REG_SIZE];
    }
    mem_taints = get_mem_taints_internal(mem_loc + 1, 1);
    if (mem_taints) {
        merged_taints[1] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE + 1]);
    } else {
        merged_taints[1] = shadow_reg_table[src_reg * REG_SIZE + 1];
    }
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add2_wmemwreg_2wreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2)
{
    int i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[4];
    taint_t final_merged_taint;

    for (i = 0; i < 4; i++) {
        mem_taints = get_mem_taints_internal(mem_loc + i, 1);
        if (mem_taints) {
            merged_taints[i] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE + i]);
        } else {
            merged_taints[i] = shadow_reg_table[src_reg * REG_SIZE + i];
        }
    }
    final_merged_taint = merged_taints[0];
    for (i = 1; i < 4; i++) {
        final_merged_taint = merge_taints(final_merged_taint, merged_taints[i]);
    }
    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 3] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 3] = final_merged_taint;
}

TAINTSIGN taint_add2_lbreglbreg_hwreg (int src_reg1, int src_reg2, int dst_reg)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t final_merged_taint;

    final_merged_taint = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                        shadow_reg_table[src_reg2 * REG_SIZE]);

    shadow_reg_table[dst_reg * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add2_hwreghwreg_2hwreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[2];
    taint_t final_merged_taint;

    merged_taints[0] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                    shadow_reg_table[src_reg2 * REG_SIZE]);
    merged_taints[1] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 1]);
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add2_wregwreg_2wreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[4];
    taint_t final_merged_taint;

    merged_taints[0] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                    shadow_reg_table[src_reg2 * REG_SIZE]);
    merged_taints[1] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 1]);
    merged_taints[2] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 2],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 2]);
    merged_taints[3] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 3],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 3]);
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);
    final_merged_taint = merge_taints(final_merged_taint, merged_taints[2]);
    final_merged_taint = merge_taints(final_merged_taint, merged_taints[3]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 3] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 3] = final_merged_taint;
}

TAINTSIGN taint_add2_hwmemhwreg_2breg (u_long mem_loc,
                                    int src_reg, int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[2];
    taint_t final_merged_taint;

    mem_taints = get_mem_taints_internal(mem_loc, 1);
    if (mem_taints) {
        merged_taints[0] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE]);
    } else {
        merged_taints[0] = shadow_reg_table[src_reg * REG_SIZE];
    }
    mem_taints = get_mem_taints_internal(mem_loc + 1, 1);
    if (mem_taints) {
        merged_taints[1] = merge_taints(mem_taints[0], shadow_reg_table[src_reg * REG_SIZE + 1]);
    } else {
        merged_taints[1] = shadow_reg_table[src_reg * REG_SIZE + 1];
    }
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
}

TAINTSIGN taint_add3_mem2reg_2reg (u_long mem_loc, int src_reg1, int src_reg2, int dst_reg1, int dst_reg2, int size)
{
    int i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[4]; // JNF: Correct for div - should rewrite this to just merge into common taint
    taint_t final_merged_taint;

    for (i = 0; i < size; i++) {
        mem_taints = get_mem_taints_internal(mem_loc + i, 1);
        if (mem_taints) {
            merged_taints[i] = merge_taints(mem_taints[0], shadow_reg_table[src_reg1 * REG_SIZE + i]);
	    merged_taints[i] = merge_taints(merged_taints[i], shadow_reg_table[src_reg2 * REG_SIZE + i]);
        } else {
	    merged_taints[i] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + i], shadow_reg_table[src_reg2 * REG_SIZE + i]);
        }
    }
    final_merged_taint = merged_taints[0];
    for (i = 1; i < size; i++) {
        final_merged_taint = merge_taints(final_merged_taint, merged_taints[i]);
    }
    for (i = 0; i < size; i++) {
	shadow_reg_table[dst_reg1 * REG_SIZE + i] = final_merged_taint;
	shadow_reg_table[dst_reg2 * REG_SIZE + i] = final_merged_taint;
    }
}

TAINTSIGN taint_add2_hwregbreg_2breg (int src_reg1, int src_reg2,
				      int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints, final_merged_taint;

    merged_taints = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
				 shadow_reg_table[src_reg1 * REG_SIZE + 1]);
    final_merged_taint = merge_taints(merged_taints,
				      shadow_reg_table[src_reg2 * REG_SIZE]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
}

TAINTSIGN taint_add2_2hwreg_2breg (int src_reg1, int src_reg2,
                                int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[2];
    taint_t final_merged_taint;

    merged_taints[0] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                    shadow_reg_table[src_reg2 * REG_SIZE]);
    merged_taints[1] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg2 * REG_SIZE + 1]);
    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
}

TAINTSIGN taint_add3_2hwreg_2hwreg (int src_reg1, int src_reg2, int src_reg3,
                                    int dst_reg1, int dst_reg2)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[4];
    taint_t final_merged_taint;

    merged_taints[0] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE],
                                    shadow_reg_table[src_reg3 * REG_SIZE]);
    merged_taints[1] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg3 * REG_SIZE + 1]);
    merged_taints[2] = merge_taints(shadow_reg_table[src_reg2 * REG_SIZE],
                                    shadow_reg_table[src_reg3 * REG_SIZE + 2]);
    merged_taints[3] = merge_taints(shadow_reg_table[src_reg2 * REG_SIZE + 1],
                                    shadow_reg_table[src_reg3 * REG_SIZE + 3]);

    final_merged_taint = merge_taints(merged_taints[0], merged_taints[1]);
    final_merged_taint = merge_taints(final_merged_taint, merged_taints[2]);
    final_merged_taint = merge_taints(final_merged_taint, merged_taints[3]);

    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add3_2wreg_2wreg (int src_reg1, int src_reg2, int src_reg3,
                                    int dst_reg1, int dst_reg2)
{
    int i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t merged_taints[8];
    taint_t final_merged_taint;

    for (i = 0; i < 4; i++) {
        merged_taints[i] = merge_taints(shadow_reg_table[src_reg1 * REG_SIZE + i],
                                        shadow_reg_table[src_reg3 * REG_SIZE + i]);
    }
    for (i = 0; i < 4; i++) {
        merged_taints[i + 4] = merge_taints(shadow_reg_table[src_reg2 * REG_SIZE + i],
                                        shadow_reg_table[src_reg3 * REG_SIZE + 4 + i]);
    }

    final_merged_taint = merged_taints[0];
    for (i = 1; i < 8; i++) {
        final_merged_taint = merge_taints(final_merged_taint, merged_taints[i]);
    }
    shadow_reg_table[dst_reg1 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg1 * REG_SIZE + 3] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 2] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 3] = final_merged_taint;
}

TAINTSIGN taint_immval2mem (ADDRINT ip, u_long mem_loc, uint32_t size, int base_reg_off, uint32_t base_reg_size, int index_reg_off, uint32_t index_reg_size)
{
    clear_mem_taints(mem_loc, size);
    taint_base_index_to_range_memwrite (ip, mem_loc, size, base_reg_off, base_reg_size, index_reg_off, index_reg_size);
}

TAINTSIGN taint_string_scan (u_long mem_loc, ADDRINT al_val, ADDRINT ecx_val, uint32_t first_iter, uint32_t rep_type)
{
    if (first_iter) {
	// Accumulate taints from memory until we are sure that we will stop the scan
	// AL, ECX, EDI assumed to be verified/untainted here.
	taint_t t = 0;
	for (u_long i = 0; i < ecx_val; i++) {
	    taint_t* mem_taints = get_mem_taints_internal(mem_loc+i, 1);
	    if (mem_taints) t = merge_taints (t, mem_taints[0]);
	    if ((rep_type == REP_TYPE_NE && *(u_char *) (mem_loc+i) == al_val && !is_mem_tainted(mem_loc+i,1)) ||
		(rep_type == REP_TYPE_E && *(u_char *) (mem_loc+i) != al_val && !is_mem_tainted(mem_loc+i,1))) {
		break;
	    }
	}

	// ECX and EDI could have different values if bytes were tainted (early stop)
	set_reg_single_value(LEVEL_BASE::REG_ECX, 4, t);	
	set_reg_single_value(LEVEL_BASE::REG_EDI, 4, t);	
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	set_clear_flags(&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, SF_FLAG|ZF_FLAG|PF_FLAG|CF_FLAG|OF_FLAG|AF_FLAG, 0); 
    }
}

TAINTSIGN taint_string_move (u_long src_mem_loc, u_long dst_mem_loc, uint32_t op_size, ADDRINT ecx_val, uint32_t first_iter)
{
    if (first_iter) {

        int size = (int) (ecx_val*op_size);
        if (!size) return; 

	// ECX, EDI, ESI assumed to be verified/untainted here.
	taint_t t = 0;
	for (long i = 0; i < size; i++) {
	    taint_t* src_mem_taint = get_mem_taints_internal(src_mem_loc+i, 1);
	    taint_t* dst_mem_taint = get_mem_taints_internal(dst_mem_loc+i, 1);
	    if (dst_mem_taint && !src_mem_taint) {
		clear_mem_taints(dst_mem_loc+i, 1);
	    } else if (src_mem_taint) {
		set_mem_taints(dst_mem_loc+i, 1, src_mem_taint);
		t = merge_taints (t, src_mem_taint[0]);
	    }
	}

	// ECX, EDI, ESI could have different values if bytes were tainted (early stop)
	if (first_iter != SPECIAL_VAL_NO_REP) set_reg_single_value(LEVEL_BASE::REG_ECX, 4, t);	
	set_reg_single_value(LEVEL_BASE::REG_EDI, 4, t);	
	set_reg_single_value(LEVEL_BASE::REG_ESI, 4, t);	
    }
}

TAINTSIGN taint_string_compare (u_long mem_loc1, u_long mem_loc2, ADDRINT ecx_val, uint32_t first_iter)
{
    if (first_iter) {
	// Accumulate taints from memory until we are sure that we will stop the scan
	// AL, ECX, EDI assumed to be verified/untainted here.
	taint_t t = 0;
	for (u_long i = 0; i < ecx_val; i++) {
	    taint_t* mem_taints = get_mem_taints_internal(mem_loc1+i, 1);
	    if (mem_taints) t = merge_taints (t, mem_taints[0]);
	    mem_taints = get_mem_taints_internal(mem_loc2+i, 1);
	    if (mem_taints) t = merge_taints (t, mem_taints[0]);
	}

	// Registers could have different values if bytes were tainted (early stop)
	set_reg_single_value(LEVEL_BASE::REG_ECX, 4, t);	
	set_reg_single_value(LEVEL_BASE::REG_EDI, 4, t);	
	set_reg_single_value(LEVEL_BASE::REG_ESI, 4, t);	
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	set_clear_flags(&shadow_reg_table[REG_EFLAGS*REG_SIZE], t, SF_FLAG|ZF_FLAG|PF_FLAG|CF_FLAG|OF_FLAG|AF_FLAG, 0); 
    }
}

TAINTSIGN taint_string_store (u_long dst_mem_loc, uint32_t op_size, ADDRINT ecx_val, uint32_t first_iter)
{
    if (first_iter) {

        uint32_t size = ecx_val*op_size;
        if (!size) return; 

	// ECX, EDI assumed to be verified/untainted here.
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	taint_t t = 0;
	for (uint32_t i = 0; i < op_size; i++) {
	    t = merge_taints (t, shadow_reg_table[LEVEL_BASE::REG_EAX*REG_SIZE+i]);
	}
	if (t == 0) {
	    clear_mem_taints (dst_mem_loc, size);
	} else {
	    uint32_t offset = 0;
	    while (offset < size) {
		uint32_t count = set_cmem_taints_one(dst_mem_loc+offset, size-offset, t);
		offset += count;
	    }
	}
    }
}

TAINTSIGN taint_pushfd (u_long mem_loc, uint32_t size) 
{
    taint_t* t = &current_thread->shadow_reg_table[LEVEL_BASE::REG_EFLAGS*REG_SIZE];
    taint_t first_byte = merge_flag_taints (CF_FLAG|PF_FLAG|AF_FLAG|ZF_FLAG|SF_FLAG);
    taint_t second_byte = merge_flag_taints (OF_FLAG|DF_FLAG);
    current_thread->saved_flag_taints->push(*(struct flag_taints *) t);  // Use auxillary structure as we want to preserve individual flag taints
    set_cmem_taints_one (mem_loc, 1, first_byte);
    set_cmem_taints_one (mem_loc + 1, 1, second_byte);
    clear_cmem_taints (mem_loc + 2, size - 2);
}

TAINTSIGN taint_popfd (u_long mem_loc, uint32_t size) 
{ 
    taint_t* t = &current_thread->shadow_reg_table[LEVEL_BASE::REG_EFLAGS*REG_SIZE];
    *(flag_taints *) t = current_thread->saved_flag_taints->top();
    current_thread->saved_flag_taints->pop();
}

TAINTSIGN taint_palignr_mem2dwreg(int reg, u_long mem_loc, int imm)
{
    int i = 0;
    taint_t tmp[16];
    taint_t* reg1;

    reg1 = get_reg_taints_internal(reg);
    // concat dst:src
    for (i = 0; i < 8; i++) {
        taint_t* mem_taints;
        mem_taints = get_mem_taints_internal(mem_loc + i, 1);
        if (mem_taints) {
            tmp[i] = mem_taints[0];
        } else {
            tmp[i] = 0;
        }
    }
    memcpy(&tmp[8], reg1, sizeof(taint_t) * 8);

    assert(imm >= 0 && imm < 8);
    set_reg_value(reg, 0, 8, &tmp[imm]);
}

TAINTSIGN taint_palignr_mem2qwreg(int reg, u_long mem_loc, int imm)
{
    int i = 0;
    taint_t tmp[32];
    taint_t* reg1;

    reg1 = get_reg_taints_internal(reg);
    // concat dst:src
    for (i = 0; i < 16; i++) {
        taint_t* mem_taints;
        mem_taints = get_mem_taints_internal(mem_loc + i, 1);
        if (mem_taints) {
            tmp[i] = mem_taints[0];
        } else {
            tmp[i] = 0;
        }
    }
    memcpy(&tmp[16], reg1, sizeof(taint_t) * 16);

    assert(imm >= 0 && imm < 16);
    set_reg_value(reg, 0, 16, &tmp[imm]);
}

TAINTSIGN taint_palignr_dwreg2dwreg(int dst_reg, int src_reg, int imm)
{
    taint_t tmp[16];
    taint_t* reg1;
    taint_t* reg2;

    reg1 = get_reg_taints_internal(dst_reg);
    reg2 = get_reg_taints_internal(src_reg);

    // concat dst:src
    memcpy(&tmp, reg2, sizeof(taint_t) * 8);
    memcpy(&tmp[8], reg1, sizeof(taint_t) * 8);

    assert(imm >= 0 && imm <= 8);
    set_reg_value(dst_reg, 0, 8, &tmp[imm]);
}

TAINTSIGN taint_palignr_qwreg2qwreg(int dst_reg, int src_reg, int imm)
{
    taint_t tmp[32];
    taint_t* reg1;
    taint_t* reg2;

    reg1 = get_reg_taints_internal(dst_reg);
    reg2 = get_reg_taints_internal(src_reg);

    // concat
    memcpy(&tmp, reg2, sizeof(taint_t) * 16);
    memcpy(&tmp[16], reg1, sizeof(taint_t) * 16);

    assert(imm >= 0 && imm < 16);
    set_reg_value(dst_reg, 0, 16, &tmp[imm]);
}

taint_t create_and_taint_option (u_long mem_addr)
{
    taint_t t = taint_num++;
    taint_mem_internal(mem_addr, t);
    return t;
}

int fw_slice_print_file_header (struct thread_data* tdata)
{
    char slicename[256];
    sprintf (slicename, "/replay_logdb/rec_%llu/exslice%ld.%d.c", 
	     tdata->rg_id, tdata->slice_filecnt, tdata->record_pid);
    tdata->slice_output_file = fopen(slicename, "w");
    if (tdata->slice_output_file == NULL) {
	fprintf (stderr, "Cannot open %s\n", slicename);
	return -1;
    }
    fprintf (tdata->slice_output_file, "asm (\n");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, ".section	.text");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, ".globl _section%ld", tdata->slice_filecnt);
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "_section%ld:", tdata->slice_filecnt);

    OUTPUT_MAIN_THREAD (tdata, "call _section%ld", tdata->slice_filecnt); 

    return 0;
}

int fw_slice_print_file_footer (struct thread_data* tdata)
{
    //control flow divergence - deosn't return
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "ret");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "jump_diverge:");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "push eax");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "push ecx");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "push edx");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "call handle_jump_diverge");
    
    //index divergence  - doesn't return
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "index_diverge:");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "push eax");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "push ecx");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "push edx");
    OUTPUT_SLICE_EXTRA_THREAD (tdata, 0, "call handle_index_diverge");
    
    fprintf (tdata->slice_output_file, ");\n");
    fclose (tdata->slice_output_file);
    tdata->slice_output_file = NULL;
    return 0;
}

int fw_slice_print_header (u_long recheck_group, struct thread_data* tdata, bool is_first_thread)
{
    char filename[256];
    sprintf (filename, "/replay_logdb/rec_%ld/exslice.%d.c", recheck_group, tdata->record_pid);
    tdata->main_output_file= fopen(filename, "w");
    if (tdata->main_output_file == NULL) {
	fprintf (stderr, "Cannot open %s\n", filename);
	return -1;
    }

    fprintf (tdata->main_output_file, "asm (\n");
    OUTPUT_MAIN_THREAD (tdata, ".section	.text");
    OUTPUT_MAIN_THREAD (tdata, ".globl _start");
    OUTPUT_MAIN_THREAD (tdata, "_start:");
    OUTPUT_MAIN_THREAD (tdata, "pushfd");
    OUTPUT_MAIN_THREAD (tdata, "push %d", tdata->record_pid); // 3rd arg is record pid
    OUTPUT_MAIN_THREAD (tdata, "push dword ptr [ebp]");
    OUTPUT_MAIN_THREAD (tdata, "add ebp, 4"); 
    OUTPUT_MAIN_THREAD (tdata, "push ebp");
    OUTPUT_MAIN_THREAD (tdata, "call recheck_start");
    OUTPUT_MAIN_THREAD (tdata, "pop ebp");
    OUTPUT_MAIN_THREAD (tdata, "sub ebp, 4"); 
    OUTPUT_MAIN_THREAD (tdata, "add esp, 8"); // Dunno

    OUTPUT_MAIN_THREAD (tdata, "popfd");
    if (is_first_thread) {
	OUTPUT_MAIN_THREAD (tdata, "call downprotect_mem");
	OUTPUT_MAIN_THREAD (tdata, "jmp ckpt_mem");
    } else {
	OUTPUT_MAIN_THREAD (tdata, "sub esp, 12"); // 16-byte alignment adjusting for 4-byte offset
    }
    OUTPUT_MAIN_THREAD (tdata, "slice_begins:");

    tdata->slice_filecnt = 1;

    // TODO: make sure we follow the calling conventions (preseve eax, edx, ecx when we call recheck-support func)

    fw_slice_print_file_header (tdata);

    return 0;
}

int fw_slice_rotate_file (struct thread_data* tdata)
{
    fprintf (stderr, "rotate!\n");
    fw_slice_print_file_footer (tdata);
    tdata->slice_filecnt++;
    tdata->slice_linecnt = 0;
    fw_slice_print_file_header (tdata);

    return 0;
}

class AddrToRestore {
  private: 
    u_long loc;
    int size;
    struct thread_data* tdata;
  public:

    AddrToRestore(struct thread_data* tdata, u_long loc, int size) { 
	this->loc = loc;
	this->size = size;
        this->tdata = tdata;
        assert (tdata != NULL);
    }

    int printPush() {
	if (size == 2 || size == 4) {//qword and xmmword are not suported for push on 32-bit
	    OUTPUT_MAIN_THREAD (tdata, "push %s [0x%lx]", memSizeToPrefix(size), loc);
        } else {
	    //use movsb
	    cout <<"/*TODO: make sure we don't mess up with original ecs, edi and esi*/" << endl;
	    OUTPUT_MAIN_THREAD (tdata, "sub esp, %d", size);
	    OUTPUT_MAIN_THREAD (tdata, "mov ecx, %d", size);
	    OUTPUT_MAIN_THREAD (tdata, "lea edi, [esp]");
	    OUTPUT_MAIN_THREAD (tdata, "lea esi, [0x%lx]", loc);
	    OUTPUT_MAIN_THREAD (tdata, "rep movsb");
	}
        return size;
    }

    void printPop () { 
	if (size == 2 || size == 4) {
	    OUTPUT_MAIN_THREAD (tdata, "pop %s [0x%lx]", memSizeToPrefix(size), loc);
        } else {
	    //use movsb
	    cout << "/*TODO: make sure we don't mess up with original ecs, edi and esi*/" << endl;
	    OUTPUT_MAIN_THREAD (tdata, "mov ecx, %d", size);
	    OUTPUT_MAIN_THREAD (tdata, "lea edi, [0x%lx]", loc);
	    OUTPUT_MAIN_THREAD (tdata, "lea esi, [esp]");
	    OUTPUT_MAIN_THREAD (tdata, "rep movsb");
	    OUTPUT_MAIN_THREAD (tdata, "add esp, %d", size);
	}
    }
};

void remove_modified_mem_for_final_check (u_long mem_loc, u_long size)
{
    interval<unsigned long>::type mem_interval = interval<unsigned long>::closed(mem_loc, mem_loc+size-1);
    address_taint_set.erase (mem_interval);
}

static void fw_slice_check_final_mem_taint (struct thread_data* tdata) 
{ 
    u_long pushed = 0;
    /* First build up a list of ranges to restore */
    list<AddrToRestore> restoreAddress;
    for(interval_set<unsigned long>::iterator iter = address_taint_set.begin(); iter != address_taint_set.end(); ++iter) {
	// We need to deal with partial taint
	u_long bytes_to_restore = 0;
	u_long addr;
	for (addr = iter->lower(); addr <= iter->upper(); addr++) {
	    if (is_mem_tainted (addr, 1)) {
		if (bytes_to_restore) {
		    AddrToRestore tmp(tdata, addr-bytes_to_restore, bytes_to_restore);
		    restoreAddress.push_back(tmp);
		    bytes_to_restore = 0;
		}
	    } else {
		bytes_to_restore++;
	    }
	}
	if (bytes_to_restore) {
	    AddrToRestore tmp(tdata, addr-bytes_to_restore, bytes_to_restore);
	    restoreAddress.push_back(tmp);
	}
    }

    // Now write out the ckpt code
    OUTPUT_MAIN_THREAD (tdata, "ckpt_mem:");
    for (AddrToRestore addrRestore: restoreAddress) {
	pushed += addrRestore.printPush();
    }
    fprintf (stderr, "pid %d: pushed %ld bytes onto the stack\n", tdata->record_pid, pushed);

    // Stack must be aligned for use during slice
    // Adjust for 4 byte return address pushed for call of sections (needed for large slices)
    OUTPUT_MAIN_THREAD (tdata, "sub esp, %ld", (28-(pushed%16))%16);
    OUTPUT_MAIN_THREAD (tdata, "jmp slice_begins");

    // And write out the restore code
    OUTPUT_MAIN_THREAD (tdata, "restore_mem:");
    OUTPUT_MAIN_THREAD (tdata, "add esp, %ld", (28-(pushed%16))%16);

    for (auto addrRestore = restoreAddress.rbegin(); addrRestore != restoreAddress.rend(); ++addrRestore) {
	addrRestore->printPop();
    }

    OUTPUT_MAIN_THREAD (tdata, "jmp restore_mem_done");

    for (int i = 0; i < NUM_REGS*REG_SIZE; i++) {
	if (tdata->shadow_reg_table[i]) {
	    DEBUG_INFO ("[CHECK_REG] $reg(%d) is tainted, index %d, thread id %d record pid %d\n", i/REG_SIZE, i, tdata->threadid, tdata->record_pid);
	}
    }
}

void fw_slice_print_footer (struct thread_data* tdata, int is_ckpt_thread, long rc)
{
    if (tdata->record_pid != first_thread) {
	OUTPUT_MAIN_THREAD (tdata, "add esp, 12");
    }

    OUTPUT_MAIN_THREAD (tdata, "slice_ends:");

    OUTPUT_MAIN_THREAD (tdata, "mov edx, %ld", rc);
    OUTPUT_MAIN_THREAD (tdata, "mov ecx, %d", is_ckpt_thread);
    OUTPUT_MAIN_THREAD (tdata, "mov ebx, 1");
    OUTPUT_MAIN_THREAD (tdata, "mov eax, 350");
    OUTPUT_MAIN_THREAD (tdata, "int 0x80");
    
    if (tdata->record_pid == first_thread) {
	fw_slice_check_final_mem_taint (tdata);
	handle_downprotected_pages (tdata);
	handle_upprotected_pages (tdata);
    }

    fprintf (tdata->main_output_file, ");\n");
    fclose (tdata->main_output_file);
    tdata->main_output_file = NULL;

    fw_slice_print_file_footer (tdata);
}

