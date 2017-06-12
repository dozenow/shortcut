#include "../linkage_common.h"
#include "../taint_nw.h"
#include "../xray_slab_alloc.h"
#include "taint_interface.h"
#include "taint_creation.h"
#include <string.h>
#include <assert.h>
#include <glib-2.0/glib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#define USE_MERGE_HASH
#define TAINT_STATS
//#define TRACE_TAINT

#ifdef TRACE_TAINT
#define TPRINT printf
#else
#define TPRINT(x,...)
#endif

extern struct thread_data* current_thread;
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


// File-descriptor tainting
// A mapping of open fds to taint values.
// We do this mapping manually because some system calls, like select use a bitmap to
// track sets of fds. Our fidelty of taint-tracking, however, doesn't extend to bit
// levels.
GHashTable* taint_fds_table = NULL;
GHashTable* taint_fds_cloexec = NULL;

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

#ifdef TAINT_DEBUG
extern u_long taint_debug_inst;
extern FILE* debug_f;
#endif
extern FILE* slice_f;

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

static void taint_reg2reg (int dst_reg, int src_reg, uint32_t size);
static void taint_reg2mem(u_long mem_loc, int reg, uint32_t size);
static UINT32 get_mem_value (u_long mem_loc, uint32_t size);
static inline int is_mem_tainted (u_long mem_loc, uint32_t size);
static inline int is_reg_tainted (int reg, uint32_t size, uint32_t is_upper8);
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

#ifdef DEBUGTRACE

GHashTable* trace_set = NULL;

static void init_trace_set ()
{
    if (trace_set == NULL) {
	trace_set = g_hash_table_new (NULL, NULL);
	g_hash_table_add (trace_set, GUINT_TO_POINTER(DEBUGTRACE));
    }
}

void add_to_trace_set(u_long val)
{
    init_trace_set();
    g_hash_table_add (trace_set, GUINT_TO_POINTER(val));
}

int is_in_trace_set(u_long val) 
{
    init_trace_set();
    return g_hash_table_contains (trace_set, GUINT_TO_POINTER(val));
}
#endif

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
#ifdef TAINT_DEBUG
    if (TAINT_DEBUG(p1) || TAINT_DEBUG(p2)|| TAINT_DEBUG(merge_control_shm->merge_total_count)) {
	fprintf (debug_f, "merge %x,%x -> %lx inst %lx clock %ld\n", p1, p2, merge_control_shm->merge_total_count, taint_debug_inst, *ppthread_log_clock);
    }
#endif

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
    if (dst != 0 || src != 0) TPRINT ("merge_taints %x %x\n", dst, src);
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
	TPRINT  ("merge_taints ret %x\n", bucket.n);
	return bucket.n;
    } else {
	taint_t n = add_merge_number (dst, src);
	bucket.p1 = src;
	bucket.p2 = dst;
	bucket.n = n;
#ifdef TAINT_STATS
	tsp.merges++;
#endif

	TPRINT  ("merge_taints ret %x\n", n);
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

#ifdef TAINT_DEBUG
#define TAINT_DEBUG_REG_GET(reg,size) \
  {									\
      int i;								\
      for (i = (reg) * REG_SIZE; i < (reg) * REG_SIZE + (int) (size); i++) { \
	  if (TAINT_DEBUG(current_thread->shadow_reg_table[i])) {	\
	      fprintf (debug_f, "Register offset %d get taint %x at inst %lx clock %ld\n", \
		       i, current_thread->shadow_reg_table[i], taint_debug_inst, *ppthread_log_clock); \
	  }								\
      }									\
  }
#else
#define TAINT_DEBUG_REG_GET(reg,size)
#endif

static inline taint_t* get_reg_taints_internal(int reg)
{
    TAINT_DEBUG_REG_GET(reg,16)
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
	TPRINT ("clear reg %x\n", reg * REG_SIZE + i);
    }
}

void clear_reg (int reg, int size)
{
    clear_reg_internal (reg, size);
}

static inline void taint_mem_internal(u_long mem_loc, taint_t t)
{
    taint_t* leaf_t;
    unsigned index = mem_loc >> LEAF_TABLE_BITS;
    if(!mem_root[index]) mem_root[index] = new_leaf_table(mem_loc);
    leaf_t = mem_root[index];
    leaf_t[mem_loc & LEAF_INDEX_MASK] = t;
#ifdef TAINT_DEBUG
    if (TAINT_DEBUG(t)) {
	fprintf (debug_f, "taint_mem: address %lx set taint %x at inst %lx clock %ld\n", mem_loc, t, taint_debug_inst, *ppthread_log_clock);
	fprintf (debug_f, "index %u table %p offset %lu\n", index, leaf_t, mem_loc&LEAF_INDEX_MASK);
    }
#endif
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

#ifdef TAINT_DEBUG
    u_long i;
    for (i = 0; i < size; i++) {
	if (TAINT_DEBUG(leaf_t[mem_loc&LEAF_INDEX_MASK])) {
	    fprintf (debug_f, "get_mem_taints: address %lx get taint %x at instr %lx clock %ld\n", mem_loc+i, leaf_t[(mem_loc&LEAF_INDEX_MASK)+i], taint_debug_inst, *ppthread_log_clock);
	}
    }
#endif
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
#ifdef DEBUGTRACE
		    if (is_in_trace_set(leaf[low_index])) {
			printf ("addr %lx has taint value %lx\n", addr, leaf[low_index]);
		    }
#endif
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
#ifdef DEBUGTRACE
		    if (is_in_trace_set(leaf[low_index])) {
			printf ("addr %lx has taint value %lx\n", addr, leaf[low_index]);
		    }
#endif
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
#ifdef DEBUGTRACE
	    if (is_in_trace_set(pregs[i])) {
		printf ("reg %lx has taint value %lx\n", i, pregs[i]);
	    }
#endif
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

#ifdef TAINT_DEBUG
// Prints out locations with the specified taint
void print_taint_debug_reg (int tid, taint_t* pregs)
{
    for (int i = 0; i < NUM_REGS*REG_SIZE; i++) {
	if (TAINT_DEBUG(pregs[i])) {
	    fprintf (debug_f, "Register %d of thread %d has taint %x\n", i, tid, pregs[i]);
	}
    }
}

void print_taint_debug_mem ()
{
    for (u_long index = 0; index < ROOT_TABLE_SIZE; index++) {
	taint_t* leaf = mem_root[index];
	if (leaf) {
	    for (u_long low_index = 0; low_index < LEAF_TABLE_SIZE; low_index++) {
		if (TAINT_DEBUG(leaf[low_index])) {
		    u_long addr = (index<<LEAF_TABLE_BITS) + low_index;
		    fprintf (debug_f, "Address %lx has taint %x\n", addr, leaf[low_index]);
		}
	    }
	}
    }
}
#endif

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

#ifdef TAINT_DEBUG
    u_long i;
    for (i = 0; i < size; i++) {
	if (TAINT_DEBUG(leaf_t[mem_loc&LEAF_INDEX_MASK])) {
	    fprintf (debug_f, "get_cmem_taints: address %lx get taint %x at instr %lx clock %ld\n", mem_loc+i, leaf_t[(mem_loc&LEAF_INDEX_MASK)+i], taint_debug_inst, *ppthread_log_clock);
	}
    }
#endif
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

#ifdef TAINT_DEBUG
    {
        u_long i;
        taint_t* mem_taints = leaf_t + low_index;
	u_long addr = mem_loc;
        for (i = 0; i < size; i++) {
	    if (TAINT_DEBUG(mem_taints[i])) {
		fprintf (debug_f, "set_mem_taints: address %lx set taint %x at inst %lx clock %ld\n", addr+i, mem_taints[i], taint_debug_inst, *ppthread_log_clock);
	    }
        }
    }
#endif
}

#if 0
static void set_mem_taint(u_long mem_loc, uint32_t size, taint_t value)
{
    taint_t* leaf_t;
    unsigned i;
    unsigned index = mem_loc >> LEAF_TABLE_BITS;
    if(!mem_root[index]) mem_root[index] = new_leaf_table(mem_loc);
    leaf_t = mem_root[index];

    unsigned low_index = mem_loc & LEAF_INDEX_MASK;
    for (i = 0; i < size; i++) {
	leaf_t[low_index+i] = value;
    }
}
#endif

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
#ifdef TAINT_DEBUG
    {
	u_long i;
        taint_t* mem_taints = leaf_t + low_index;
	u_long addr = mem_loc;
        for (i = 0; i < set_size; i++) {
	    if (TAINT_DEBUG(mem_taints[i])) {
		fprintf (debug_f, "set_cmem_taints: address %lx set taint %x at instr %lx clock %ld\n", addr+i, mem_taints[i], taint_debug_inst, *ppthread_log_clock);
	    }
        }
    }
#endif

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
#ifdef TAINT_DEBUG
    {
	u_long i;
        taint_t* mem_taints = leaf_t + low_index;
	u_long addr = mem_loc;
        for (i = 0; i < set_size; i++) {
	    if (TAINT_DEBUG(mem_taints[i])) {
		fprintf (debug_f, "set_cmem_taints_one: address %lx set taint %x at inst %lx clock %ld\n", 
			 addr+i, mem_taints[i], taint_debug_inst, *ppthread_log_clock);
	    }
        }
    }
#endif

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
#ifdef TRACE_TAINT
    {
	int i;
	for (i = reg * REG_SIZE + offset; i < reg * REG_SIZE + offset + size; i++) {
	    TPRINT ("clear reg %x\n", i);
	}
    }
#endif
}

static inline void set_reg_value(int reg, int offset, int size, taint_t* values)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&shadow_reg_table[reg * REG_SIZE + offset], values,
            size * sizeof(taint_t));
#ifdef TAINT_DEBUG
    {
	int i;
	for (i = reg * REG_SIZE + offset; i < reg * REG_SIZE + offset + size; i++) {
	    if (TAINT_DEBUG(shadow_reg_table[i])) {
		fprintf (debug_f, "Register offset %d set taint %x at inst %lx clock %ld\n", 
			 i, shadow_reg_table[i], taint_debug_inst, *ppthread_log_clock);
	    }
	}
    }
#endif
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

static inline void zero_partial_reg_until (int reg, int offset, int until)
{
    assert(until > offset);
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memset(&shadow_reg_table[reg * REG_SIZE + offset], 0,
            (until - offset) * sizeof(taint_t));
}

void init_taint_structures (char* group_dir)
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

void* get_non_zero_taints(taint_t t) {
    GHashTable* seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    GList* list = NULL;
    GQueue* queue = g_queue_new();
    struct taint_node* n = (struct taint_node *) t;

    g_queue_push_tail(queue, n);
    while(!g_queue_is_empty(queue)) {
        n = (struct taint_node *) g_queue_pop_head(queue);
        if (g_hash_table_lookup(seen_indices, n)) {
            continue;
        }
        g_hash_table_insert(seen_indices, n, GINT_TO_POINTER(1));

        if (!n->parent1 && !n->parent2) { // leaf node
            struct taint_leafnode* ln = (struct taint_leafnode *) n;
            list = g_list_prepend(list, GUINT_TO_POINTER(ln->option));
        } else {
            if (!g_hash_table_lookup(seen_indices, n->parent1)) {
                g_queue_push_tail(queue, n->parent1);
            }
            if (!g_hash_table_lookup(seen_indices, n->parent2)) {
                g_queue_push_tail(queue, n->parent2);
            }
        }
    }

    g_queue_free(queue);
    g_hash_table_destroy(seen_indices);
    return (void *) list;
}

void print_options(FILE* fp, taint_t t)
{
    GHashTable* seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    GList* list = NULL;
    GQueue* queue = g_queue_new();
    struct taint_node* n = (struct taint_node *) t;
    assert(n);

    g_queue_push_tail(queue, n);
    while(!g_queue_is_empty(queue)) {
        n = (struct taint_node *) g_queue_pop_head(queue);
        assert(n);
        if (g_hash_table_lookup(seen_indices, n)) {
            continue;
        }
        g_hash_table_insert(seen_indices, n, GINT_TO_POINTER(1));

        if (!n->parent1 && !n->parent2) { // leaf node
            struct taint_leafnode* ln = (struct taint_leafnode *) n;
            fprintf(fp, "%u, ", ln->option);
            list = g_list_prepend(list, GUINT_TO_POINTER(ln->option));
        } else {
            if (!g_hash_table_lookup(seen_indices, n->parent1)) {
                g_queue_push_tail(queue, n->parent1);
            }
            if (!g_hash_table_lookup(seen_indices, n->parent2)) {
                g_queue_push_tail(queue, n->parent2);
            }
        }
    }

    g_queue_free(queue);
    g_hash_table_destroy(seen_indices);
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

void reverse_reg_taint(int reg, int size)
{
    // Only support word-sized registers for now
    assert(size == 4);
    taint_t* reg_table = current_thread->shadow_reg_table;
    taint_t tmp;
    tmp = reg_table[reg * REG_SIZE];
    reg_table[reg * REG_SIZE] = reg_table[reg * REG_SIZE + 3];
    reg_table[reg * REG_SIZE + 3] = tmp;
    
    tmp = reg_table[reg * REG_SIZE + 1];
    reg_table[reg * REG_SIZE + 1] = reg_table[reg * REG_SIZE + 2];
    reg_table[reg * REG_SIZE + 2] = tmp;
}

// mem2reg
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

TAINTSIGN taint_mem2lbreg(u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2lbreg");
    taint_mem2reg(mem_loc, reg, 1);
}

TAINTSIGN taint_mem2ubreg(u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2ubreg");
    taint_t* mem_taints = get_mem_taints_internal(mem_loc, 1);
    if (!mem_taints) {
        clear_reg_value(reg, 1, 1);
        return;
    }
    set_reg_value(reg, 1, 1, mem_taints);
}

TAINTSIGN taint_mem2hwreg(u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2hwreg");
    taint_mem2reg(mem_loc, reg, 2);
}

TAINTSIGN taint_mem2wreg(u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2wreg"); 
    taint_mem2reg(mem_loc, reg, 4);
}

TAINTSIGN taint_mem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2dwreg");
    taint_mem2reg(mem_loc, reg, 8);
}

TAINTSIGN taint_mem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2qwreg");
    taint_mem2reg(mem_loc, reg, 16);
}

TAINTSIGN taint_bmem2hwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_bmem2hwreg");
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_bmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_bmem2wreg");
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_bmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_bmem2dwreg");
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_bmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_bmem2qwreg");
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_hwmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwmem2wreg");
    taint_mem2hwreg(mem_loc, reg);
}

TAINTSIGN taint_hwmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwmem2dwreg");
    taint_mem2hwreg(mem_loc, reg);
}

TAINTSIGN taint_hwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwmem2qwreg");
    taint_mem2hwreg(mem_loc, reg);
}

TAINTSIGN taint_wmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_wmem2dwreg");
    taint_mem2wreg(mem_loc, reg);
}

TAINTSIGN taint_wmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_wmem2qwreg");
    taint_mem2wreg(mem_loc, reg);
}

TAINTSIGN taint_dwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_dwmem2qwreg");
    taint_mem2dwreg(mem_loc, reg);
}

// mem2reg extend
TAINTSIGN taintx_bmem2hwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_bmem2hwreg");
    taint_mem2reg(mem_loc, reg, 1);
    zero_partial_reg(reg, 1);
}

TAINTSIGN taintx_bmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_bmem2wreg");
    taint_mem2reg(mem_loc, reg, 1);
    zero_partial_reg(reg, 1);
}

TAINTSIGN taintx_bmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_bmem2dwreg");
    taint_mem2reg(mem_loc, reg, 1);
    zero_partial_reg(reg, 1);
}

TAINTSIGN taintx_bmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_bmem2qwreg");
    taint_mem2reg(mem_loc, reg, 1);
    zero_partial_reg(reg, 1);
}


TAINTSIGN taintx_hwmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwmem2wreg");
    taint_mem2reg(mem_loc, reg, 2);
    zero_partial_reg(reg, 2);
}

TAINTSIGN taintx_hwmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwmem2dwreg");
    taint_mem2reg(mem_loc, reg, 2);
    zero_partial_reg(reg, 2);
}

TAINTSIGN taintx_hwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwmem2qwreg");
    taint_mem2reg(mem_loc, reg, 2);
    zero_partial_reg(reg, 2);
}

TAINTSIGN taintx_wmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_wmem2dwreg");
    taint_mem2reg(mem_loc, reg, 4);
    zero_partial_reg(reg, 4);
}

TAINTSIGN taintx_wmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_wmem2qwreg");
    taint_mem2reg(mem_loc, reg, 4);
    zero_partial_reg(reg, 4);
}

TAINTSIGN taintx_dwmem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taintx_dwmem2qwreg");
    taint_mem2reg(mem_loc, reg, 8);
    zero_partial_reg(reg, 8);
}

TAINTSIGN taint_add_mem2reg_offset (u_long mem_loc, int reg_off, uint32_t size)
{
    unsigned i = 0;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
                taint_t t = merge_taints(shadow_reg_table[reg_off + offset + i], mem_taints[i]);
		shadow_reg_table[reg_off + offset + i] = t;
            }
        } 
        offset += count;
        mem_offset += count;
    }
}

// mem2reg xchg
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

TAINTSIGN taint_xchg_bmem2lbreg (u_long mem_loc, int reg)
{
    taint_t tmp;
    taint_t* mem_taints;
    TAINT_START("taint_xchg_bmem2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[reg * REG_SIZE];
    mem_taints = get_mem_taints_internal(mem_loc, 1);
    if (mem_taints) {
        shadow_reg_table[reg * REG_SIZE] = mem_taints[0];
    } else {
        shadow_reg_table[reg * REG_SIZE] = 0;
    }
    set_cmem_taints(mem_loc, 1, &tmp);
}

TAINTSIGN taint_xchg_bmem2ubreg (u_long mem_loc, int reg)
{
    taint_t tmp;
    taint_t* mem_taints;
    TAINT_START("taint_xchg_bmem2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[reg * REG_SIZE + 1];
    mem_taints = get_mem_taints_internal(mem_loc, 1);
    if (mem_taints) {
        shadow_reg_table[reg * REG_SIZE + 1] = mem_taints[0];
    } else {
        shadow_reg_table[reg * REG_SIZE + 1] = 0;
    }
    set_cmem_taints(mem_loc, 1, &tmp);
}

static inline void taint_xchg_mem2reg (u_long mem_loc, int reg, int size)
{
    int i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t tmp[size];

    // This can be optimized, we can optimize it need be
    for (i = 0; i < size; i++) {
        taint_t* mem_taints;
        mem_taints = get_mem_taints_internal(mem_loc + i, 1);
        if (mem_taints) {
            tmp[i] = mem_taints[0];
        } else {
            tmp[i] = 0;
        }
    }

    // TODO remove this conditional
    if (is_reg_zero(reg, size)) {
        int offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < size) {
            uint32_t count = clear_cmem_taints(mem_offset, size - offset);
            offset += count;
            mem_offset += count;
        }
    } else {
        int offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < size) {
            uint32_t count = set_cmem_taints(mem_offset, size - offset,
					     &shadow_reg_table[reg * REG_SIZE + offset]);
            offset += count;
            mem_offset += count;
        }
    }

    // now set the register taints
    memcpy(&shadow_reg_table[reg * REG_SIZE], &tmp, size * sizeof(taint_t));
}

TAINTSIGN taint_xchg_hwmem2hwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_xchg_hwmem2hwreg");
    taint_xchg_mem2reg(mem_loc, reg, 2);
}

TAINTSIGN taint_xchg_wmem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_xchg_hwmem2hwreg");
    taint_xchg_mem2reg(mem_loc, reg, 4);
}

TAINTSIGN taint_xchg_dwmem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_xchg_hwmem2hwreg");
    taint_xchg_mem2reg(mem_loc, reg, 8);
}

TAINTSIGN taint_xchg_qwmem2qwreg( u_long mem_loc, int reg)
{
    TAINT_START("taint_xchg_hwmem2hwreg");
    taint_xchg_mem2reg(mem_loc, reg, 16);
}

//control flow stuff

//DEPRECATED
void inline clear_flag_reg () {
	taint_t* reg_table = current_thread->shadow_reg_table;
	memset (&reg_table[REG_EFLAGS], 0, REG_SIZE*sizeof(taint_t));
}

TAINTSIGN taint_regmem2flag (u_long mem_loc, uint32_t reg, uint32_t mask, uint32_t size) {
	return taint_regmem2flag_with_different_size (mem_loc, reg, mask, size, size);
}

inline taint_t merge_mem_taints (u_long mem_loc, uint32_t size) {  
	uint32_t offset = 0;
	u_long mem_offset = mem_loc;
	taint_t result = 0;
	uint32_t i;
	/*int printout = 0;
	if (strncmp ((char*) mem_loc, "ine __LEAF_ATTR ", 16) == 0 || strncmp ((char*) mem_loc, "#  define __LEAF", 16) == 0) { 	
		printout = 1;
	}*/

	while (offset < size) { 
		taint_t* mem_taints = NULL;
		uint32_t count = get_cmem_taints_internal (mem_offset, size - offset, &mem_taints);
		if (mem_taints) { 
			for (i=0; i<count; ++i) { 
				//if (printout) fprintf (stderr, "mem_loc %lx size %u count %u mem_taints %u.\n", mem_loc, size, i, mem_taints[i]);
				result = merge_taints (result, mem_taints[i]);
			}
		} else { 
		}
		offset += count;
		mem_offset += count;
	}
	return result;
}

inline taint_t merge_reg_taints (uint32_t reg, uint32_t size) { 
	uint32_t i = 0;
	taint_t result = 0;
	for (; i<size; ++i) {
		result = merge_taints (current_thread->shadow_reg_table[reg*REG_SIZE + i], result);
	}
	return result;
}

TAINTSIGN taint_regmem2flag_with_different_size (u_long mem_loc, uint32_t reg, uint32_t mask, uint32_t size_mem, uint32_t size_reg) {
	uint32_t i = 0;
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	taint_t result = 0;

	//merge taints for mem
	result = merge_mem_taints (mem_loc, size_mem);

	//merge register taints
	for (i = 0; i<size_reg; ++i) {
		result = merge_taints (shadow_reg_table[reg*REG_SIZE + i], result);
	}

	for (i = 0; i<NUM_FLAGS; ++i) {
		if (mask & ( 1 << i)) {
			shadow_reg_table[REG_EFLAGS*REG_SIZE + i] = result;
		} 
		//other flags are unaffected
	}

	//fprintf (stderr, "taint_regmem2flag: flags %x, tainted %x, size_mem %d\n", mask, result, size_mem);
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
		result = merge_reg_taints (reg2, size2);
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

TAINTSIGN taint_mem2flag (u_long mem_loc, uint32_t mask, uint32_t size) {
	uint32_t i = 0;
	taint_t result = 0;
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;

	//merge taints
	result = merge_mem_taints (mem_loc, size);

	for (i = 0; i<NUM_FLAGS; ++i) {
		if (mask & ( 1 << i)) {
			shadow_reg_table[REG_EFLAGS*REG_SIZE + i] = result;
		}
	}
}

TAINTSIGN taint_flag2mem (u_long mem_loc, uint32_t mask, uint32_t size) { 
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	uint32_t i = 0;
	taint_t t = 0;

	for (i = 0; i<NUM_FLAGS; ++i) { 
		if (mask & (1 << i)) {
			t = merge_taints (t, shadow_reg_table[REG_EFLAGS*REG_SIZE + i]);
		}
	}

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

TAINTSIGN taint_reg2flag (uint32_t reg, uint32_t mask, uint32_t size) {
	uint32_t i = 0;
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	taint_t result = 0;

	//merge taints
	for (i = 0; i<size; ++i) {
		result = merge_taints (result, shadow_reg_table[reg*REG_SIZE +i]);
	}

	for (i = 0; i<NUM_FLAGS; ++i) {
		if (mask & ( 1 << i)) {
			shadow_reg_table[REG_EFLAGS*REG_SIZE + i] = result;
		} 
	}
}

TAINTSIGN taint_flag2reg (uint32_t reg, uint32_t mask, uint32_t size) { 
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	uint32_t i = 0;
	taint_t t = 0;

	for (i = 0; i<NUM_FLAGS; ++i) { 
		if (mask & (1 << i)) {
			t = merge_taints (t, shadow_reg_table[REG_EFLAGS*REG_SIZE + i]);
		}
	}
	for (i = 0; i<size; ++i ) {
		shadow_reg_table[reg*REG_SIZE +i] = t;
	}
}

//size of dst reg and src reg should be the same
TAINTSIGN taint_regflag2reg (uint32_t mask, uint32_t dst_reg, uint32_t src_reg, uint32_t size) { 
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	taint_t t = 0;
	uint32_t i = 0;

	for (i = 0; i<NUM_FLAGS; ++i) { 
		if (mask & (1 << i)) {
			t = merge_taints (t, shadow_reg_table[REG_EFLAGS*REG_SIZE + i]);
		}
	}

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

	for (i = 0; i<NUM_FLAGS; ++i) { 
		if (mask & (1 << i)) {
			t = merge_taints (t, shadow_reg_table[REG_EFLAGS*REG_SIZE + i]);
		}
	}

	//merge	flag and src reg
	//TODO: could make this more efficient
	for (; i<size; ++i) { 
		taint_t tmp = merge_taints (t, shadow_reg_table[src_reg*REG_SIZE+i]);
		set_cmem_taints (mem_loc + i, 1, &tmp);
	}
}

//size of the src mem and dst reg should be the same
TAINTSIGN taint_memflag2reg (uint32_t mask, uint32_t dst_reg, u_long mem_loc, uint32_t size) { 
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	taint_t t = 0;
	uint32_t i = 0;
	uint32_t offset = 0;

	for (i = 0; i<NUM_FLAGS; ++i) { 
		if (mask & (1 << i)) {
			t = merge_taints (t, shadow_reg_table[REG_EFLAGS*REG_SIZE + i]);
		}
	}

	//merge	flag and src 
	while (offset < size) { 
		taint_t* mem_taints = NULL;
		uint32_t count = get_cmem_taints_internal (mem_loc+offset, size - offset, &mem_taints);
		if (mem_taints) {
			for (i = 0; i<count; ++i) { 
				shadow_reg_table[dst_reg*REG_SIZE+offset+i] = merge_taints (t, mem_taints[i]);
			}
		} 
		offset += count;
	}
}

TAINTSIGN taint_regreg2flag (uint32_t dst_reg, uint32_t src_reg, uint32_t mask, uint32_t size)  {
	int i = 0;
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	uint32_t index =0;
	//TPRINT ("start to taint_regreg2flag(address %x), dst_reg %u, src_reg %u\n", ip, dst_reg, src_reg);
	taint_t result = 0;

	//merge taints from two registers
	for (; index < size; ++index) {
		taint_t t = merge_taints (shadow_reg_table[dst_reg*REG_SIZE + index], shadow_reg_table[src_reg*REG_SIZE + index]);
		result = merge_taints (t, result);
	}

	for (; i<NUM_FLAGS; ++i) {
		if (mask & ( 1 << i)) {
			//merge taints into flag register
			//TODO: should we only calculate this once for all flags??? Will the merge log preserve the merges?
			shadow_reg_table[REG_EFLAGS*REG_SIZE + i] = result;
			TPRINT ("taint_regreg2flag tainted flag index %d, value %x\n", i, shadow_reg_table[REG_EFLAGS*REG_SIZE + i]);
		} 
	}
}

TAINTSIGN taint_jump (ADDRINT eflag, uint32_t flags, ADDRINT ip) {
	int i = 0;
	taint_t t = 0;
	struct taint_creation_info tci;
	//int flag_value = 0;

	for (; i < NUM_FLAGS; ++i) {
		if (flags & (1 << i)) {
			//preserve the taint value and merge together
			t = merge_taints (current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE + i], t);
		} 
	}
	//if (ip == 0x87d0cec)
		//fprintf (stderr, "taint_jump: ip %#x flags %x, tainted value %u\n", ip, flags, t);
	//TPRINT( "taint_jump: ip %#x flags %x, tainted value %u\n", ip, flags, t);
	/*for (i = 0; i<NUM_FLAGS; ++i) {
		if (flags & (1 << i)) {
			TPRINT ("taint_jump flag index %d, taint value %x, flag value %d\n", i, current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE + i], GET_FLAG_VALUE (eflag, i));
			if (flag_value == 0) 
				flag_value = GET_FLAG_VALUE(eflag, i);
			else {
			}
		}
	}*/

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
	taint_t t = merge_reg_taints (translate_reg(LEVEL_BASE::REG_ECX), size);
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

//these instructinos depends on DF_FLAG to eihter incrment or decrement esi and edi
//we regard these to be output
TAINTSIGN taint_string_operation (ADDRINT ip) {
	taint_t t = 0;
	struct taint_creation_info tci;

	//DF_FLAG
	t = current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE + DF_INDEX];

	TPRINT ("taint_string_operation: ip %#x tainted  %x\n", ip, t);

	tci.type = TAINT_DATA_INST;
	tci.record_pid = current_thread->record_pid;
	tci.rg_id = current_thread->rg_id;
	tci.syscall_cnt = current_thread->syscall_cnt;
	tci.offset = 0;
	tci.fileno = 0;
	tci.data = ip;

	if (t != 0) {
		output_jump_result (ip, t, &tci, outfd);
	}
}

TAINTSIGN taint_rep (uint32_t flags, ADDRINT ip) {
	int i = 0;
	taint_t t = 0;
	struct taint_creation_info tci;

	//merge taints from all flags we care
	//REPZ only cares about ZF, but REPZ CMPS cares about ZF and DF, so it's specific to instructions
	for (; i < NUM_FLAGS; ++i) {
		if (flags & (1 << i)) {
			//preserve the taint value and merge together
			t = merge_taints (current_thread->shadow_reg_table[REG_EFLAGS*REG_SIZE + i], t);
		} 
	}
	//fprintf (stderr, "taint_rep: ip %#x flags %x, tainted  %x\n", ip, flags, t);
	//merge counter register; also taint the counter register
	for (i = 0; i< REG_SIZE; ++i) { 
		t = merge_taints (current_thread->shadow_reg_table[translate_reg(LEVEL_BASE::REG_ECX)*REG_SIZE + i], t);
	}
	for (i = 0; i<REG_SIZE; ++i) { //this is because old ecx value can affect the final state of ecx
		current_thread->shadow_reg_table[translate_reg(LEVEL_BASE::REG_ECX)*REG_SIZE+i] = t;
	}

	TPRINT( "taint_rep: ip %#x flags %x, tainted  %x\n", ip, flags, t);

	tci.type = TAINT_DATA_INST;
	tci.record_pid = current_thread->record_pid;
	tci.rg_id = current_thread->rg_id;
	tci.syscall_cnt = current_thread->syscall_cnt;
	tci.offset = 0;
	tci.fileno = 0;
	tci.data = ip;

	if (t != 0) {
		output_jump_result (ip, t, &tci, outfd);
	}
}


TAINTSIGN taint_rotate_reg (int dstreg, uint32_t size, int is_count_reg) { 
	taint_t result = 0;
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	if (is_count_reg) { 
		//CL is the count register
		int count_reg = translate_reg(LEVEL_BASE::REG_ECX);
		//merge all taints from dstreg
		taint_t dst_taint = merge_reg_taints (dstreg, size);
		result = merge_taints (dst_taint, shadow_reg_table[count_reg*REG_SIZE]);
	} else { 
		result = merge_reg_taints (dstreg, size);
	}
	uint32_t i = 0;
	//set taints
	for (; i<size; ++i) { 
		shadow_reg_table[dstreg*REG_SIZE+i] = result;
	}
}

TAINTSIGN taint_rotate_mem (u_long mem_loc, uint32_t size, int is_count_reg) { 
	taint_t result = 0;
	if (is_count_reg) { 
		int count_reg = translate_reg(LEVEL_BASE::REG_ECX);
		taint_t* shadow_reg_table = current_thread->shadow_reg_table;
		//merge all taints from dst mem loc
		taint_t dst_taint = merge_mem_taints (mem_loc, size);
		result = merge_taints (dst_taint, shadow_reg_table[count_reg*REG_SIZE]);
	} else { 
		result = merge_mem_taints (mem_loc, size);
	}
	set_cmem_taints_one (mem_loc, size, result);
}

//the first param should be the value in AL/AX/EAX
//dst_value is only used when dst_reg is valid and mem_loc is 0
TAINTSIGN taint_cmpxchg_mem (ADDRINT eax_value, u_long mem_loc, int src_reg, uint32_t size) { 
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	int eax_reg = translate_reg (LEVEL_BASE::REG_EAX);
	uint32_t mask = ZF_FLAG|CF_FLAG|PF_FLAG|AF_FLAG|SF_FLAG|OF_FLAG;
	//read from mem
	//first get the dst_value
	uint32_t dst_value = get_mem_value (mem_loc, size);	
	if (eax_value == dst_value) { 
		//load src_reg to mem
		taint_reg2mem (mem_loc, src_reg, size);
	} else { 
		//load mem to EAX/AX/AL
		//set_reg_value (translate_reg(LEVEL_BASE::REG_EAX), 0, size, );
		taint_mem2reg (mem_loc, eax_reg, size);
	}
	uint32_t i = 0;
	//set ZF_FLAG
	//compare AL.. with mem_loc
	taint_t flag_taint = 0;
	taint_t mem_taints = merge_mem_taints (mem_loc, size);
	taint_t reg_taints = merge_reg_taints (eax_reg, size);
	flag_taint = merge_taints (mem_taints, reg_taints);
	for (; i<NUM_FLAGS; ++i)  {
		if (mask && (1<<i)) {
			shadow_reg_table[REG_EFLAGS*REG_SIZE + i] = flag_taint;
			break;
		}
	}
}

TAINTSIGN taint_cmpxchg_reg (ADDRINT eax_value, UINT32 dst_value, int dst_reg, int src_reg, uint32_t size) { 
	taint_t* shadow_reg_table = current_thread->shadow_reg_table;
	int eax_reg = translate_reg (LEVEL_BASE::REG_EAX);
	uint32_t mask = ZF_FLAG|CF_FLAG|PF_FLAG|AF_FLAG|SF_FLAG|OF_FLAG;
	if (eax_value == dst_value) {
		//load str_reg to dst_reg
		taint_reg2reg (dst_reg, src_reg, size);
	} else { 
		//load dst_reg to AX..
		taint_reg2reg (dst_reg, translate_reg(LEVEL_BASE::REG_EAX), size);
	}
	uint32_t i = 0;
	//set ZF_FLAG
	//compare AL.. with dst_reg
	taint_t flag_taint = 0;
	taint_t dst_taints = merge_reg_taints (dst_reg, size);
	taint_t eax_taints = merge_reg_taints (eax_reg, size);
	flag_taint = merge_taints (dst_taints, eax_taints);
	for (; i<NUM_FLAGS; ++i)  {
		if (mask && (1<<i)) {
			shadow_reg_table[REG_EFLAGS*REG_SIZE + i] = flag_taint;
			break;
		}
	}
}

// reg2mem
static inline void taint_reg2mem(u_long mem_loc, int reg, uint32_t size)
{
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    // TODO remove this conditional
    TAINT_DEBUG_REG_GET(reg,size);
    if (is_reg_zero(reg, size)) {
        uint32_t offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < size) {
            uint32_t count = clear_cmem_taints(mem_offset, size - offset);
            offset += count;
            mem_offset += count;
        }
    } else {
        uint32_t offset = 0;
        u_long mem_offset = mem_loc;

        while (offset < size) {
            uint32_t count = set_cmem_taints(mem_offset, size - offset,
					     &shadow_reg_table[reg * REG_SIZE + offset]);
            offset += count;
            mem_offset += count;
        }
    }
}

//TODO: this is not correct: if al is tainted and ah is not, when reading from ax, we should init ah with SLICE_EXTRA
static inline int is_reg_tainted (int reg, uint32_t size, uint32_t is_upper8) { 
	int tainted = 0;
	uint32_t i = 0;
	uint32_t end = size;
	if (is_upper8) {
		i = 1;
		end = size + i;
	}
	for (; i<end; ++i) { 
		if (current_thread->shadow_reg_table[reg*REG_SIZE + i] != 0) {
			tainted = 1;
			break;
		}
	}
	return tainted;
}

/* For calling above from linkage_new.cpp (sigh) */
int is_reg_arg_tainted (int reg, uint32_t size, uint32_t is_upper8) 
{
    return is_reg_tainted (reg, size, is_upper8);
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
					tainted = 1;
					break;
				}
			}
		}
		if (tainted) break;
		offset += count;
		mem_offset += count;
	}
	return tainted;
}

static inline UINT32 get_mem_value (u_long mem_loc, uint32_t size) { 
	UINT32 dst_value = 0;
	assert (mem_loc != 0);
	assert (mem_loc > 0x100);
	switch (size) { 
		case 1: {
			UINT8 tmp = *((UINT8*) mem_loc);
			dst_value = (UINT32) tmp;
			break;
			}
		case 2: {
			UINT16 tmp = *((UINT16*) mem_loc);
			dst_value = (UINT32) tmp;
			break;
			}
		case 4: {
			dst_value = *((UINT32*) mem_loc);
			break;
			}
		default:
			{
				fprintf (stderr, "get_mem_value: size is %u. \n", size);
				return 0;
			}
	}
	return dst_value;
}

static inline void print_extra_move_reg (ADDRINT ip, int reg, uint32_t reg_size, uint32_t regvalue, uint32_t is_upper8) { 
	if (is_upper8)
		printf ("[SLICE_EXTRA] mov $reg(%d,%u), %u //comes with %x\n", reg, -1, regvalue, ip);
	else 
		printf ("[SLICE_EXTRA] mov $reg(%d,%u), %u //comes with %x\n", reg, reg_size, regvalue, ip);
}

static inline void print_extra_move_mem (ADDRINT ip, u_long mem_loc, uint32_t mem_size) { 
	printf ("[SLICE_EXTRA] mov $addr(%lx,%u), %u  //comes with %x\n", mem_loc, mem_size, get_mem_value(mem_loc, mem_size), ip);
}

static inline void print_extra_move_flag (ADDRINT ip, char* str, uint32_t flag) { 
	fprintf (stderr, "[BUG] flag is not tainted, but we should initialize it %x, %s\n", ip, str);
}

TAINTSIGN debug_print_instr (ADDRINT ip, char* str) { 
	fprintf (stderr, "[DEBUG] ip %x, ", ip);
	fprintf (stderr, "%s\n",str);
}

TAINTSIGN fw_slice_addressing (ADDRINT ip, int base_reg, uint32_t base_reg_size, uint32_t base_reg_value, uint32_t base_reg_u8,
		int index_reg, uint32_t index_reg_size, uint32_t index_reg_value, uint32_t index_reg_u8,
		u_long mem_loc, uint32_t mem_size, uint32_t is_read) { 
	//first check if both registers are not tainted
	int all_clean = 1;
	if (base_reg_size > 0 && is_reg_tainted(base_reg, base_reg_size, base_reg_u8)) 
		all_clean = 0;
	if (index_reg_size > 0 && is_reg_tainted(index_reg, index_reg_size, index_reg_u8))
		all_clean = 0;
	if (all_clean) { 
		//the address doesn't depend on base or index register, we can safely replace it with a constant
		printf ("[SLICE_ADDRESSING] immediate_address $addr(0x%lx)  //come with %x (move upwards)\n", mem_loc, ip);
	} else {
		if (base_reg_size > 0) { 
			if (is_reg_tainted (base_reg, base_reg_size, base_reg_u8) == 0){
				assert (base_reg != 6);//TODO: move value to esp is dangerous! this can probably mess up the whole stack, especially for call/ret
				if (base_reg_u8)
					printf ("[SLICE_ADDRESSING] mov $reg(%d,%u), 0x%x //comes with %x (move upwards)\n", base_reg, -1, base_reg_value, ip);
				else 
					printf ("[SLICE_ADDRESSING] mov $reg(%d,%u), 0x%x //comes with %x (move upwards)\n", base_reg, base_reg_size, base_reg_value, ip);
			} else 
				printf ("[SLICE_VERIFICATION] $reg(%d,%u) is tainted //comes with %x (move upwards), address %lx\n", base_reg, base_reg_size, ip, mem_loc);
		} 
		if (index_reg_size > 0) { 
			if (is_reg_tainted (index_reg, index_reg_size, index_reg_u8) == 0) {
				assert (index_reg != 6); //esp 
				if (index_reg_u8)
					printf ("[SLICE_ADDRESSING] mov $reg(%d,%u), 0x%x //comes with %x (move upwards)\n", index_reg, -1, index_reg_value, ip);
				else
					printf ("[SLICE_ADDRESSING] mov $reg(%d,%u), 0x%x //comes with %x (move upwards)\n", index_reg, index_reg_size, index_reg_value, ip);
				fprintf (stderr, "[TODO] double check if the index tool handles all cases\n");
			} else { 
				printf ("[SLICE_VERIFICATION] $reg(%d,%u) is tainted //comes with %x (move upwards), address %lx\n", index_reg, index_reg_size, ip, mem_loc);
			}
		}
	}
	// let's check the memory address at the checkpoint clock
	if (is_read == 0) {//only check dst memory operand
		struct address_taint_set* addr_struct = NULL;
		HASH_FIND_ULONG (current_thread->address_taint_set, &mem_loc, addr_struct);
		if (addr_struct == NULL) {
			addr_struct = (struct address_taint_set*)malloc (sizeof(struct address_taint_set));
			addr_struct->loc = mem_loc;
			addr_struct->is_imm = all_clean;
			addr_struct->size = mem_size;
			HASH_ADD_ULONG (current_thread->address_taint_set, loc, addr_struct);
		} else { 
			//if already exits, do sanity check
			//it's tricky if one tainted address is both directly addressable and indirectly addressable
			if (addr_struct->is_imm != all_clean) { 
				printf ("[BUG][SLICE] tricky: the memory address is not immediate (for checking taints on the final checkpoint, %x\n", ip);
				printf ("[SLICE_ADDRESSING_NOT_HANDLED] $addr(0x%lx)  //come with %x (move upwards)\n", mem_loc, ip);
			}
			if (addr_struct->size != mem_size) { 
				fprintf (stderr, "[INFO] the memory address is overlapping (for checking taints on the final checkpoint, %x\n", ip);
				fprintf (stderr, "[INFO] $addr(0x%lx)  //come with %x (move upwards)\n", mem_loc, ip);
			}
		}
	}
}

int fw_slice_check_final_mem_taint (taint_t* pregs) { 
	struct address_taint_set* addr_struct = NULL;
	int has_mem = 0;
	int mem_count = 0;
	int i;
	for (addr_struct = current_thread->address_taint_set; addr_struct != NULL; addr_struct = (struct address_taint_set*)addr_struct->hh.next) { 
		//printf ("checking mem_loc,is_imm,size: %lx, %d, %u\n", addr_struct->loc, addr_struct->is_imm, addr_struct->size);
		if (is_mem_tainted (addr_struct->loc, addr_struct->size) == 0) {
			printf ("[SLICE_RESTORE_ADDRESS] mem_loc,is_imm,size: %lx, %d, %u\n", addr_struct->loc, addr_struct->is_imm, addr_struct->size);
			has_mem = 1;
		}
		++ mem_count;
	}
	printf ("fw_slice_check_final_mem_taint: %d mem addrs are checked.\n", mem_count);

	/* Assume 1 thread for now */
	for (i = 0; i < NUM_REGS*REG_SIZE; i++) {
	    if (pregs[i]) {
		printf ("[CHECK_REG] $reg(%d) is tainted, index %d\n", i/REG_SIZE, i);
	    }
	}

	return has_mem;
}

TAINTSIGN fw_slice_addressing_check_two (ADDRINT ip, 
		int base_reg1, uint32_t base_reg_size1, uint32_t base_reg_value1, uint32_t base_reg1_u8,
		int index_reg1, uint32_t index_reg_size1, uint32_t index_reg_value1, uint32_t index_reg1_u8,
		u_long mem_loc1, uint32_t mem_size1, uint32_t is_read1,
		int base_reg2, uint32_t base_reg_size2, uint32_t base_reg_value2, uint32_t base_reg2_u8,
		int index_reg2, uint32_t index_reg_size2, uint32_t index_reg_value2, uint32_t index_reg2_u8,
		u_long mem_loc2, uint32_t mem_size2, uint32_t is_read2) { 
	fw_slice_addressing (ip, base_reg1, base_reg_size1, base_reg_value1, base_reg1_u8,
			index_reg1, index_reg_size1, index_reg_value1, index_reg1_u8,
			mem_loc1, mem_size1, is_read1);
	fw_slice_addressing (ip, base_reg2, base_reg_size2, base_reg_value2, base_reg2_u8,
			index_reg2, index_reg_size2, index_reg_value2, index_reg2_u8,
			mem_loc2, mem_size2, is_read2);
}

//#define PRINT(x) fprintf(stderr, x)
#define PRINT(x)

//source operand is mem
TAINTINT fw_slice_mem (ADDRINT ip, char* ins_str, u_long mem_loc, uint32_t size, u_long dst_mem_loc) { 
	int tainted = is_mem_tainted (mem_loc, size);

	if (tainted) {
		PRINT("mem\n");
		if (ip < 10000){
			fprintf (stderr, "ip %x, inst %p\n", ip, ins_str);
			return 1;
			//assert (0);
		}
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		if (dst_mem_loc != 0)
			printf ("    [SLICE_INFO] #src_mem[%lx:%d:%u],dst_mem[%lx:%d:%u] #src_mem_value %u, dst_mem_value %u\n", mem_loc, tainted, size, dst_mem_loc, 0, size, get_mem_value (mem_loc, size), get_mem_value (dst_mem_loc, size));
		else { 
			printf ("    [SLICE_INFO] #src_mem[%lx:%d:%u] #src_mem_value %u\n", mem_loc, tainted, size, get_mem_value (mem_loc, size));
		}
		return 1;
	}
	return 0;
}


//source operand is reg, dst_mem_loc is the dst memory location (could be null if two operands are both regs);
TAINTINT fw_slice_reg (ADDRINT ip, char* ins_str, int reg, uint32_t size, u_long dst_mem_loc, ADDRINT regvalue, uint32_t reg_u8) {
	int tainted = is_reg_tainted (reg, size, reg_u8);
	//Warning: The reg value for xmm register is the register index, instead of the actual content
	if (tainted) {
		PRINT("reg\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		if (dst_mem_loc != 0)
			printf ("    [SLICE_INFO] #src_reg[%d:1:%u], dst_mem[%lx:0:%u] #src_reg_value %u, dst_mem_value %u\n", reg, size, dst_mem_loc, size, regvalue, get_mem_value (dst_mem_loc, size));
		else 
			printf ("    [SLICE_INFO] #src_reg[%d:1:%u] #src_reg_value %u\n", reg, size,  regvalue);
		return 1;
	}
	return 0;
}

//print out two reg values if both operands are registers
TAINTINT fw_slice_regreg (ADDRINT ip, char* ins_str, int dst_reg, int src_reg, uint32_t dst_regsize, uint32_t src_regsize, ADDRINT dst_regvalue, ADDRINT src_regvalue,
		uint32_t dst_reg_u8, uint32_t src_reg_u8) {
	//Warning: The reg value for xmm register is the register index, instead of the actual content
	int tainted1 = is_reg_tainted (dst_reg, dst_regsize, dst_reg_u8);
	int tainted2 = is_reg_tainted (src_reg, src_regsize, src_reg_u8);
	//printf ("    [DEBUG] #src_regreg[%d:%d:%u,%d:%d:%u] #dst_reg_value %u, src_reg_value %u\n", dst_reg, tainted1, dst_regsize, src_reg, tainted2, src_regsize, dst_regvalue, src_regvalue);

	if (tainted1 || tainted2){
		PRINT ("regreg\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_regreg[%d:%d:%u,%d:%d:%u] #dst_reg_value %u, src_reg_value %u\n", 
				dst_reg, tainted1, dst_regsize, src_reg, tainted2, src_regsize, dst_regvalue, src_regvalue);
		if (!tainted1) print_extra_move_reg (ip, dst_reg, dst_regsize, dst_regvalue, dst_reg_u8);
		if (!tainted2) print_extra_move_reg (ip, src_reg, src_regsize, src_regvalue, src_reg_u8);
		return 1;
	}
	return 0;
}


TAINTINT fw_slice_regregreg (ADDRINT ip, char* ins_str, int dst_reg, int src_reg, int count_reg, 
		uint32_t dst_regsize, uint32_t src_regsize, uint32_t count_regsize, 
		ADDRINT dst_regvalue, ADDRINT src_regvalue, ADDRINT count_regvalue,
		uint32_t dst_reg_u8, uint32_t src_reg_u8, uint32_t count_reg_u8) { 
	//Warning: The reg value for xmm register is the register index, instead of the actual content
	int tainted1 = is_reg_tainted (dst_reg, dst_regsize, dst_reg_u8);
	int tainted2 = is_reg_tainted (src_reg, src_regsize, src_reg_u8);
	int tainted3 = is_reg_tainted (count_reg, count_regsize, count_reg_u8);

	if (tainted1 || tainted2 || tainted3) {
		PRINT ("regregreg\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_regregreg[%d:%d:%u,%d:%d:%u,%d:%d:%u] #dst_reg_value %u, src_reg_value %u, count_reg_value %u\n", 
				dst_reg, tainted1, dst_regsize, src_reg, tainted2, src_regsize, count_reg, tainted3, count_regsize, dst_regvalue, src_regvalue, count_regvalue);
		if (!tainted1) print_extra_move_reg (ip, dst_reg, dst_regsize, dst_regvalue, dst_reg_u8);
		if (!tainted2) print_extra_move_reg (ip, src_reg, src_regsize, src_regvalue, src_reg_u8);
		if (!tainted3) print_extra_move_reg (ip, count_reg, count_regsize, count_regvalue, count_reg_u8);
		return 1;
	}
	return 0;
}

TAINTINT fw_slice_memmem (ADDRINT ip, char* ins_str, u_long mem_read, u_long mem_write, uint32_t mem_readsize, uint32_t mem_writesize) { 
	int tainted1 = is_mem_tainted (mem_read, mem_readsize);
	int tainted2 = is_mem_tainted (mem_write, mem_writesize);

	if (tainted1 || tainted2) {
		PRINT ("memmem\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_memmem[%lx:%d:%u,%lx:%d:%u] #mem_write_value %u, mem_read_addr %u\n", 
				mem_write, tainted2, mem_writesize, mem_read, tainted1, mem_readsize, get_mem_value (mem_write, mem_writesize), get_mem_value (mem_read, mem_readsize));
		if (!tainted1) print_extra_move_mem (ip, mem_read, mem_readsize);
		if (!tainted2) print_extra_move_mem (ip, mem_write, mem_writesize);
		return 1;
	}
	return 0;
}

TAINTINT fw_slice_memmemreg (ADDRINT ip, char* ins_str, u_long mem_read, u_long mem_write, uint32_t mem_readsize, uint32_t mem_writesize, 
		int reg, uint32_t reg_size, uint32_t regvalue, uint32_t reg_u8) { 
	int tainted1 = is_mem_tainted (mem_read, mem_readsize);
	int tainted2 = is_mem_tainted (mem_write, mem_writesize);
	int tainted3 = is_reg_tainted (reg, reg_size, reg_u8);

	if (tainted1 || tainted2 || tainted3) {
		PRINT ("memmemreg\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_memmemreg[%lx:%d:%u,%lx:%d:%u,%d:%d:%u] #mem_write_value %u, mem_read_addr %u, reg_value %u\n", 
				mem_write, tainted2, mem_writesize, mem_read, tainted1, mem_readsize, reg, tainted3, reg_size, 
				get_mem_value (mem_write, mem_writesize), get_mem_value (mem_read, mem_readsize), regvalue);
		if (!tainted1) print_extra_move_mem (ip, mem_read, mem_readsize);
		if (!tainted2) print_extra_move_mem (ip, mem_write, mem_writesize);
		if (!tainted3) print_extra_move_reg (ip, reg, reg_size, regvalue, reg_u8);
		return 1;
	}
	return 0;
}

TAINTINT fw_slice_memreg (ADDRINT ip, char* ins_str, int reg, uint32_t reg_size, uint32_t regvalue, uint32_t reg_u8, u_long mem_loc, uint32_t mem_size) { 
	//Warning: The reg value for xmm register is the register index, instead of the actual content
	int reg_tainted = is_reg_tainted (reg, reg_size, reg_u8);
	int mem_tainted = is_mem_tainted (mem_loc, mem_size);
	if (reg_tainted || mem_tainted) {
		PRINT ("memreg.\n");		
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_memreg[%lx:%d:%u,%d:%d:%u] #mem_value %u, reg_value %u\n", 
				mem_loc, mem_tainted, mem_size, reg, reg_tainted, reg_size, get_mem_value (mem_loc, mem_size), regvalue);
		if (reg_tainted == 0) 
			print_extra_move_reg (ip, reg, reg_size, regvalue, reg_u8);
		else if (mem_tainted == 0) 
			print_extra_move_mem (ip, mem_loc, mem_size);
		return 1;
	}
	return 0;
}

TAINTINT fw_slice_memregreg (ADDRINT ip, char* ins_str, int reg1, uint32_t reg1_size, uint32_t reg1_value, uint32_t reg1_u8, 
		int reg2, uint32_t reg2_size, uint32_t reg2_value, uint32_t reg2_u8, u_long mem_loc, uint32_t mem_size) { 
	int tainted1 = is_reg_tainted (reg1, reg1_size, reg1_u8);
	int tainted2 = is_mem_tainted (mem_loc, mem_size);
	int tainted3 = is_reg_tainted (reg2, reg2_size, reg2_u8);
	if (tainted1 || tainted2 || tainted3) {
		PRINT ("memregreg\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_regmemreg[%d:%d:%u,%lx:%d:%u,%d:%d:%u] #reg_value %u, mem_value %u, reg_value %u\n", 
				reg1, tainted1, reg1_size, mem_loc, tainted2, mem_size, reg2, tainted3, reg2_size, reg1_value, get_mem_value (mem_loc, mem_size), reg2_value);
		if (!tainted1) print_extra_move_reg (ip, reg1, reg1_size, reg1_value, reg1_u8);
		if (!tainted2) print_extra_move_mem (ip, mem_loc, mem_size);
		if (!tainted3) print_extra_move_reg (ip, reg2, reg2_size, reg2_value, reg2_u8);
		return 1;
	}
	return 0;
}

TAINTINT fw_slice_memregregreg (ADDRINT ip, char* ins_str, int reg1, uint32_t reg1_size, uint32_t reg1_value, uint32_t reg1_u8, 
		int reg2, uint32_t reg2_size, uint32_t reg2_value, uint32_t reg2_u8,
		int reg3, uint32_t reg3_size, uint32_t reg3_value, uint32_t reg3_u8, u_long mem_loc, uint32_t mem_size) { 
	int tainted1 = is_reg_tainted (reg1, reg1_size, reg1_u8);
	int tainted2 = is_mem_tainted (mem_loc, mem_size);
	int tainted3 = is_reg_tainted (reg2, reg2_size, reg2_u8);
	int tainted4 = is_reg_tainted (reg3, reg3_size, reg3_u8);
	if (tainted1 || tainted2 || tainted3 || tainted4) {
		PRINT ("memregregreg\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_regmemregreg[%d:%d:%u,%lx:%d:%u,%d:%d:%u,%d:%d:%u] #reg_value %u, mem_value %u, reg_value %u, reg_value %u\n", 
				reg1, tainted1, reg1_size, mem_loc, tainted2, mem_size, reg2, tainted3, reg2_size, reg3, tainted4, reg3_size, reg1_value, get_mem_value (mem_loc, mem_size), reg2_value, reg3_value);
		if (!tainted1) print_extra_move_reg (ip, reg1, reg1_size, reg1_value, reg1_u8);
		if (!tainted2) print_extra_move_reg (ip, reg2, reg2_size, reg2_value, reg2_u8);
		if (!tainted3) print_extra_move_mem (ip, mem_loc, mem_size);
		if (!tainted4) print_extra_move_reg (ip, reg3, reg3_size, reg3_value, reg3_u8);
		return 1;
	}
	return 0;
}

//only used for cmov
TAINTINT fw_slice_memregregflag (ADDRINT ip, char* ins_str, int reg1, uint32_t reg1_size, uint32_t reg1_value, uint32_t reg1_u8, 
		int reg2, uint32_t reg2_size, uint32_t reg2_value, uint32_t reg2_u8, u_long mem_loc, uint32_t mem_size, uint32_t flag) { 
	int tainted1 = (reg1_size>0)?is_reg_tainted (reg1, reg1_size, reg1_u8):0;
	int tainted2 = is_mem_tainted (mem_loc, mem_size);
	int tainted3 = (reg2_size>0)?is_reg_tainted (reg2, reg2_size, reg2_u8):0;
	int tainted4 = is_flag_tainted (flag);

	if (tainted1 || tainted2 || tainted3 || tainted4) {
		PRINT ("memregregflag\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_memregregflag[%d:%d:%u,%lx:%d:%u,%d:%d:%u] #reg_value %u, mem_value %u, reg_value %u, flag %x, flag tainted %d\n", 
				reg1, tainted1, reg1_size, mem_loc, tainted2, mem_size, reg2, tainted3, reg2_size, reg1_value, get_mem_value (mem_loc, mem_size), reg2_value, flag, tainted4);
		if (!tainted1 && reg1_size > 0) print_extra_move_reg (ip, reg1, reg1_size, reg1_value, reg1_u8);
		if (!tainted2 && mem_size > 0) print_extra_move_reg (ip, reg2, reg2_size, reg2_value, reg2_u8);
		if (!tainted3 && reg2_size > 0) print_extra_move_mem (ip, mem_loc, mem_size);
		if (!tainted4) print_extra_move_flag (ip, ins_str, flag);
		return 1;
	}
	return 0;
}

TAINTINT fw_slice_flag (ADDRINT ip, char* ins_str, uint32_t mask, BOOL taken) {
	int tainted = is_flag_tainted (mask);
	if (tainted) {
		PRINT ("flag\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_flag[%x:1:4] #branch_taken %d\n", mask, (int) taken);
		return 1;
	}
	return 0;
}

TAINTINT fw_slice_regflag (ADDRINT ip, char* ins_str, uint32_t mask, uint32_t src_reg, uint32_t size, ADDRINT regvalue, uint32_t reg_u8) { 
	int flag_tainted = is_flag_tainted (mask);
	int reg_tainted = is_reg_tainted (src_reg, size, reg_u8);

	if (flag_tainted || reg_tainted) {
		//assert (flag_tainted);
		PRINT ("regflag\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_regflag[%d:%d:%u,%x:%d:4] #reg_value %u, flag_value TODO\n", src_reg, reg_tainted, size, mask, flag_tainted, regvalue);
		if (!reg_tainted) print_extra_move_reg (ip, src_reg, size, regvalue, reg_u8);
		if (!flag_tainted) print_extra_move_flag (ip, ins_str, mask);
		return 1;
	}
	return 0;
}

TAINTINT fw_slice_memflag (ADDRINT ip, char* ins_str, uint32_t mask, u_long mem_loc, uint32_t size) { 
	int flag_tainted = is_flag_tainted (mask);
	int mem_tainted = is_mem_tainted (mem_loc, size);
	if (flag_tainted || mem_tainted) {
		PRINT ("memflag.\n");
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_memflag[%lx:%d:%u,%x:%d:4] #mem_value %u, flag_value TODO\n", mem_loc, mem_tainted, size, mask, flag_tainted, get_mem_value (mem_loc, size));
		if (!mem_tainted) print_extra_move_mem (ip, mem_loc, size);
		if (!flag_tainted) print_extra_move_flag (ip, ins_str, mask);
		return 1;
	}
	return 0;
}

static const char* translate_mmx (uint32_t reg)
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

TAINTINT fw_slice_pcmpistri_reg_reg (ADDRINT ip, char* ins_str, uint32_t reg1, uint32_t reg2, uint32_t reg1_size, uint32_t reg2_size, char* reg1_val, char* reg2_val) 
{
	int reg1_taint = is_reg_tainted (reg1, reg1_size, 0);
	int reg2_taint = is_reg_tainted (reg2, reg2_size, 0);
	if (reg1_taint || reg2_taint) {
		if (!reg1_taint) {
		    printf ("[SLICE] #00000000 #push %lu [SLICE_INFO] comes with %x\n", *((u_long *) reg1_val), ip);
		    printf ("[SLICE] #00000000 #push %lu [SLICE_INFO] comes with %x\n", *((u_long *) (reg1_val+4)), ip);
		    printf ("[SLICE] #00000000 #push %lu [SLICE_INFO] comes with %x\n", *((u_long *) (reg1_val+8)), ip);
		    printf ("[SLICE] #00000000 #push %lu [SLICE_INFO] comes with %x\n", *((u_long *) (reg1_val+12)), ip);
		    printf ("[SLICE] #00000000 #movdqu %s, xmmword ptr [esp] [SLICE_INFO] comes with %x\n", translate_mmx(reg1), ip);
		    printf ("[SLICE] #00000000 #add esp, 16 [SLICE_INFO] comes with %x\n", ip);
		}
		if (!reg2_taint) {
		    printf ("[SLICE] #00000000 #push %lu [SLICE_INFO] comes with %x\n", *((u_long *) reg2_val), ip);
		    printf ("[SLICE] #00000000 #push %lu [SLICE_INFO] comes with %x\n", *((u_long *) (reg2_val+4)), ip);
		    printf ("[SLICE] #00000000 #push %lu [SLICE_INFO] comes with %x\n", *((u_long *) (reg2_val+8)), ip);
		    printf ("[SLICE] #00000000 #push %lu [SLICE_INFO] comes with %x\n", *((u_long *) (reg2_val+12)), ip);
		    printf ("[SLICE] #00000000 #movdqu %s, xmmword ptr [esp] [SLICE_INFO] comes with %x\n", translate_mmx(reg2), ip);
		    printf ("[SLICE] #00000000 #add esp, 16 [SLICE_INFO] comes with %x\n", ip);
		}
		printf ("[SLICE] #%x #%s\t", ip, ins_str);
		printf ("    [SLICE_INFO] #src_regreg[%d:%d:%u,%d:%d:%u] #dst_reg_value %.16s, src_reg_value %.16s\n", 
			reg1, reg1_taint, reg1_size, reg2, reg2_taint, reg2_size, reg1_val, reg2_val);
		return 1;
	}
	return 0;
}

TAINTSIGN taint_lbreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2mem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE]);
    }
}

TAINTSIGN taint_ubreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2mem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_hwreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwreg2mem");
    taint_reg2mem(mem_loc, reg, 2);
}

TAINTSIGN taint_wreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_wreg2mem");
    taint_reg2mem(mem_loc, reg, 4);
}

TAINTSIGN taint_dwreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_dwreg2mem");
    taint_reg2mem(mem_loc, reg, 8);
}

TAINTSIGN taint_qwreg2mem (u_long mem_loc, int reg)
{
    TAINT_START("taint_qwreg2mem");
    taint_reg2mem(mem_loc, reg, 16);
}

TAINTSIGN taint_lbreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2hwmem");
    taint_reg2mem(mem_loc, reg, 1);
}

TAINTSIGN taint_lbreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2wmem");
    taint_reg2mem(mem_loc, reg, 1);
}

TAINTSIGN taint_lbreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2dwmem");
    taint_reg2mem(mem_loc, reg, 1);
}

TAINTSIGN taint_lbreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_lbreg2qwmem");
    taint_reg2mem(mem_loc, reg, 1);
}

TAINTSIGN taint_ubreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2hwmem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_cmem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_ubreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2wmem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_ubreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2dwmem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_ubreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_ubreg2qwmem");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    if(shadow_reg_table[reg * REG_SIZE + 1] == 0) {
        clear_mem_taints(mem_loc, 1);
    } else {
        set_mem_taints(mem_loc, 1, &shadow_reg_table[reg * REG_SIZE + 1]);
    }
}

TAINTSIGN taint_hwreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwreg2wmem");
    taint_reg2mem(mem_loc, reg, 2);
}

TAINTSIGN taint_hwreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwreg2dwmem");
    taint_reg2mem(mem_loc, reg, 2);
}

TAINTSIGN taint_hwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_hwreg2qwmem");
    taint_reg2mem(mem_loc, reg, 2);
}

TAINTSIGN taint_wreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_wreg2dwmem");
    taint_reg2mem(mem_loc, reg, 4);
}

TAINTSIGN taint_wreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_wreg2qwmem");
    taint_reg2mem(mem_loc, reg, 4);
}

TAINTSIGN taint_dwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taint_dwreg2qwmem");
    taint_reg2mem(mem_loc, reg, 8);
}

// reg2mem extend
TAINTSIGN taintx_lbreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_lbreg2hwmem");
    taint_lbreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 1);
}

TAINTSIGN taintx_lbreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_lbreg2wmem");
    taint_lbreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 3);
}

TAINTSIGN taintx_lbreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_lbreg2dwmem");
    taint_lbreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 7);
}

TAINTSIGN taintx_lbreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_lbreg2qwmem");
    taint_lbreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 15);
}

TAINTSIGN taintx_ubreg2hwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_ubreg2hwmem");
    taint_ubreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 1);
}

TAINTSIGN taintx_ubreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_ubreg2wmem");
    taint_ubreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 3);
}

TAINTSIGN taintx_ubreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_ubreg2hwmem");
    taint_ubreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 7);
}

TAINTSIGN taintx_ubreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_ubreg2qwmem");
    taint_ubreg2hwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 1, 15);
}


TAINTSIGN taintx_hwreg2wmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwreg2wmem");
    taint_hwreg2wmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 2, 2);
}

TAINTSIGN taintx_hwreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwreg2dwmem");
    taint_hwreg2wmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 2, 6);
}

TAINTSIGN taintx_hwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_hwreg2qwmem");
    taint_hwreg2wmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 2, 14);
}

TAINTSIGN taintx_wreg2dwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_wreg2dwmem");
    taint_wreg2dwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 4, 4);
}

TAINTSIGN taintx_wreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_wreg2qwmem");
    taint_wreg2dwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 4, 12);
}

TAINTSIGN taintx_dwreg2qwmem (u_long mem_loc, int reg)
{
    TAINT_START("taintx_dwreg2qwmem");
    taint_dwreg2qwmem(mem_loc, reg);
    clear_mem_taints(mem_loc + 8, 8);
}

TAINTSIGN taint_add_reg2flag_offset (int reg_off, uint32_t size, uint32_t flag) { 
    unsigned i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t t = 0;

    for (i = 0; i < size; i++) {
       	t = merge_taints(shadow_reg_table[reg_off + i], t);
    } 

    for (i = 0; i<NUM_FLAGS; ++i) { 
        if (flag & (1<<i))
	    shadow_reg_table[REG_EFLAGS*REG_SIZE+i] = merge_taints(shadow_reg_table[REG_EFLAGS*REG_SIZE+i], t);
    }
}

#if 1
// This is a faithful translation of Mike's function (yuck) 
TAINTSIGN taint_add_reg2mem_offset (u_long mem_loc, int reg_off, uint32_t size, int set_flags, int clear_flags)
{
    unsigned i = 0;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
                mem_taints[i] = merge_taints(shadow_reg_table[reg_off + offset + i], mem_taints[i]);
            }
        } else {
            // mem not tainted, just a set
	    if (shadow_reg_table[reg_off]) { // JNF: I think this is wrong
                set_mem_taints(mem_offset, count, &shadow_reg_table[reg_off + offset]);
            }
        }
        offset += count;
        mem_offset += count;
    }
}
#else
// This is probably wrong, tho
TAINTSIGN taint_add_reg2mem_offset (u_long mem_loc, int reg_off, uint32_t size, int set_flags, int clear_flags)
{
    unsigned i = 0;

    // First accumulate memory taint 
    taint_t result = 0;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;
    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
                result = merge_taints(result, mem_taints[i]);
            }
        }
        offset += count;
        mem_offset += count;
    }

    // Next, mix in register taint
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    for (i = 0; i < size; i++) {
	result = merge_taints (result, shadow_reg_table[reg_off + i]);
    }
    if (result) {
	// Now set memory taint
	offset = 0;
	mem_offset = mem_loc;
	while (offset < size) {
	    taint_t* mem_taints = NULL;
	    uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
	    if (mem_taints) {
		for (i = 0; i < count; i++) {
		    mem_taints[i] = result;
		}
	    } else {
		set_mem_taint (mem_offset, count, result);
	    }
	    offset += count;
	    mem_offset += count;
	}
    }
}
#endif

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

TAINTSIGN taint_rep_hwreg2mem (u_long mem_loc, int reg, int count) {
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_hwreg2mem(mem_loc + (i * 2), reg);
    }
}

TAINTSIGN taint_rep_wreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_wreg2mem(mem_loc + (i * 4), reg);
    }
}

TAINTSIGN taint_rep_dwreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_dwreg2mem(mem_loc + (i * 8), reg);
    }
}

TAINTSIGN taint_rep_qwreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_qwreg2mem(mem_loc + (i * 16), reg);
    }
}

// reg2reg
static inline void taint_reg2reg (int dst_reg, int src_reg, uint32_t size)
{
    //TPRINT ("taint_reg2reg dest %d src %d\n", dst_reg, src_reg);
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], size * sizeof(taint_t));

#ifdef TRACE_TAINT
    {
	u_int i;
	for (i = 0; i < size; i++) {
	    TPRINT ("set reg %x to %x\n", dst_reg*REG_SIZE+i, shadow_reg_table[dst_reg*REG_SIZE+i]);
	}
    }
#endif
}

static inline void taint_regreg2reg (int dst_reg, int base_reg, int index_reg, uint32_t size) {
	taint_t base_taint = merge_reg_taints(base_reg, size);
	taint_t index_taint = merge_reg_taints (index_reg, size);
	taint_t result = merge_taints (base_taint, index_taint);
	uint32_t i = 0;
	for (; i<size; ++i) { 
		current_thread->shadow_reg_table[dst_reg*REG_SIZE+i] = result;
	}
}

TAINTSIGN taint_wregwreg2wreg (int dst_reg, int base_reg, int index_reg) { 
	TAINT_START ("taint_wregwreg2wreg");
	taint_regreg2reg (dst_reg, base_reg, index_reg, 4);
}

TAINTSIGN taint_lbreg2lbreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2lbreg");
    taint_reg2reg(dst_reg, src_reg, 1);
}

TAINTSIGN taint_ubreg2lbreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_lbreg2ubreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    // shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
    shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_ubreg2ubreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_wreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_wreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 4);
}

TAINTSIGN taint_hwreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_hwreg2hwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
}

TAINTSIGN taint_dwreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_dwreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 8);
}

TAINTSIGN taint_qwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_qwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 16);
}

TAINTSIGN taint_lbreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2wreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_lbreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2hwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_lbreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2dwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_lbreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_lbreg2qwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
}

TAINTSIGN taint_ubreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2hwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_ubreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2wreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_ubreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2dwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_ubreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_ubreg2qwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
}

TAINTSIGN taint_hwreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_hwreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 2);
}

TAINTSIGN taint_hwreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_hwreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
}

TAINTSIGN taint_hwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_hwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
}

TAINTSIGN taint_wreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_wreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 4);
}

TAINTSIGN taint_wreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_wreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 4);
}

TAINTSIGN taint_dwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taint_qwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 8);
}

// reg2reg extend
TAINTSIGN taintx_lbreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_lbreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_lbreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_lbreg2hwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_lbreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_lbreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_lbreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_lbreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_ubreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_ubreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_ubreg2hwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_ubreg2hwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_ubreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_ubreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_ubreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_ubreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 1);
    zero_partial_reg(dst_reg, 1);
}

TAINTSIGN taintx_hwreg2wreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_hwreg2wreg");
    taint_reg2reg(dst_reg, src_reg, 2);
    zero_partial_reg(dst_reg, 2);
}

TAINTSIGN taintx_hwreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_hwreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
    zero_partial_reg(dst_reg, 2);
}

TAINTSIGN taintx_hwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_hwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 2);
    zero_partial_reg(dst_reg, 2);
}

TAINTSIGN taintx_wreg2dwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_wreg2dwreg");
    taint_reg2reg(dst_reg, src_reg, 4);
    zero_partial_reg(dst_reg, 4);
}

TAINTSIGN taintx_wreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_wreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 4);
    zero_partial_reg(dst_reg, 4);
}

TAINTSIGN taintx_dwreg2qwreg (int dst_reg, int src_reg)
{
    TAINT_START("taintx_dwreg2qwreg");
    taint_reg2reg(dst_reg, src_reg, 8);
    zero_partial_reg(dst_reg, 8);
}

TAINTSIGN taint_add_reg2reg_offset (int dst_reg_off, int src_reg_off, uint32_t size)
{
    unsigned i;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;

    for (i = 0; i < size; i++) {
        shadow_reg_table[dst_reg_off + i] = merge_taints(shadow_reg_table[dst_reg_off + i], shadow_reg_table[src_reg_off + i]);
    } 
}

// reg2reg xchg
TAINTSIGN taint_xchg_lbreg2lbreg (int dst_reg, int src_reg)
{
    taint_t tmp;
    TAINT_START("taint_xchg_lbreg2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[dst_reg * REG_SIZE];
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE];
    shadow_reg_table[src_reg * REG_SIZE] = tmp;
}

TAINTSIGN taint_xchg_ubreg2ubreg (int dst_reg, int src_reg)
{
    taint_t tmp;
    TAINT_START("taint_xchg_ubreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[dst_reg * REG_SIZE + 1];
    shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE + 1];
    shadow_reg_table[src_reg * REG_SIZE + 1] = tmp;
}

TAINTSIGN taint_xchg_ubreg2lbreg (int dst_reg, int src_reg)
{
    taint_t tmp;
    TAINT_START("taint_xchg_ubreg2lbreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[dst_reg * REG_SIZE + 1];
    shadow_reg_table[dst_reg * REG_SIZE + 1] = shadow_reg_table[src_reg * REG_SIZE];
    shadow_reg_table[src_reg * REG_SIZE] = tmp;
}

TAINTSIGN taint_xchg_lbreg2ubreg (int dst_reg, int src_reg)
{
    taint_t tmp;
    TAINT_START("taint_xchg_lbreg2ubreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    tmp = shadow_reg_table[dst_reg * REG_SIZE];
    shadow_reg_table[dst_reg * REG_SIZE] = shadow_reg_table[src_reg * REG_SIZE + 1];
    shadow_reg_table[src_reg * REG_SIZE + 1] = tmp;
}

TAINTSIGN taint_xchg_hwreg2hwreg (int dst_reg, int src_reg)
{
    taint_t tmp[2];
    TAINT_START("taint_xchg_hwreg2hwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&tmp, &shadow_reg_table[dst_reg * REG_SIZE], 2 * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], 2 * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg * REG_SIZE], &tmp, 2 * sizeof(taint_t));
}

TAINTSIGN taint_xchg_wreg2wreg (int dst_reg, int src_reg)
{
    taint_t tmp[4];
    TAINT_START("taint_xchg_wreg2wreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&tmp, &shadow_reg_table[dst_reg * REG_SIZE], 4 * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], 4 * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg * REG_SIZE], &tmp, 4 * sizeof(taint_t));
}

TAINTSIGN taint_xchg_dwreg2dwreg (int dst_reg, int src_reg)
{
    taint_t tmp[8];
    TAINT_START("taint_xchg_dwreg2dwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&tmp, &shadow_reg_table[dst_reg * REG_SIZE], 8 * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], 8 * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg * REG_SIZE], &tmp, 8 * sizeof(taint_t));
}

TAINTSIGN taint_xchg_qwreg2qwreg (int dst_reg, int src_reg)
{
    taint_t tmp[16];
    TAINT_START("taint_xchg_qwreg2qwreg");
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    memcpy(&tmp, &shadow_reg_table[dst_reg * REG_SIZE], 16 * sizeof(taint_t));
    memcpy(&shadow_reg_table[dst_reg * REG_SIZE],
            &shadow_reg_table[src_reg * REG_SIZE], 16 * sizeof(taint_t));
    memcpy(&shadow_reg_table[src_reg * REG_SIZE], &tmp, 16 * sizeof(taint_t));
}

TAINTSIGN taint_mask_reg2reg (int dst_reg, int src_reg)
{
    taint_t merge_taint;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    merge_taint = merge_taints(shadow_reg_table[src_reg * REG_SIZE + 3],
                                    shadow_reg_table[src_reg * REG_SIZE + 7]);
    merge_taint = merge_taints(merge_taint, shadow_reg_table[src_reg * REG_SIZE + 11]);
    merge_taint = merge_taints(merge_taint, shadow_reg_table[src_reg * REG_SIZE + 15]);
    // this is overtainting, but we don't track taint at the bit-level
    shadow_reg_table[dst_reg * REG_SIZE] = merge_taint;
}

// mem2mem
TAINTSIGN taint_mem2mem (u_long src_loc, u_long dst_loc, uint32_t size)
{
    // TODO: This can be optimized, by minimizng the number of walks through the
    // page table structure
    unsigned i = 0;
    taint_t* dst_mem_taint;
    taint_t* src_mem_taint;
    for (i = 0; i < size; i++) {
        dst_mem_taint = get_mem_taints_internal(dst_loc + i, 1);
        src_mem_taint = get_mem_taints_internal(src_loc + i, 1);

        if (!src_mem_taint && !dst_mem_taint) {
            continue;
        } else if (!src_mem_taint) {
            clear_mem_taints(dst_loc + i, 1);
        } else {
            set_mem_taints(dst_loc + i, 1, src_mem_taint);
        }
    }
}

TAINTSIGN taint_mem2mem_b (u_long src_loc, u_long dst_loc)
{
    taint_t* dst_mem_taints = get_mem_taints_internal(dst_loc, 1);
    taint_t* src_mem_taints = get_mem_taints_internal(dst_loc, 1);
    if (!src_mem_taints && !dst_mem_taints) {
        return;
    } else if (!src_mem_taints) {
        clear_mem_taints(dst_loc, 1);
    } else {
        set_mem_taints(dst_loc, 1, src_mem_taints);
    }
}

TAINTSIGN taint_mem2mem_hw (u_long src_loc, u_long dst_loc)
{
    taint_mem2mem(src_loc, dst_loc, 2);
}

TAINTSIGN taint_mem2mem_w (u_long src_loc, u_long dst_loc)
{
    taint_mem2mem(src_loc, dst_loc, 4);
}

TAINTSIGN taint_mem2mem_dw (u_long src_loc, u_long dst_loc)
{
    taint_mem2mem(src_loc, dst_loc, 8);
}

TAINTSIGN taint_mem2mem_qw (u_long src_loc, u_long dst_loc)
{
    taint_mem2mem(src_loc, dst_loc, 16);
}

TAINTSIGN taint_call_near (u_long esp)
{
    clear_cmem_taints (esp-4, 4); /* IP written to stack */
}

TAINTSIGN taint_call_far (u_long esp)
{
    clear_cmem_taints (esp-8, 8); /* IP and CS written to stack */
}

static inline void taint_add_mem2mem (u_long src_loc, u_long dst_loc, uint32_t size)
{
    // TODO: This can be optimized, by minimizng the number of walks through the
    // page table structure
    unsigned i = 0;
    taint_t* dst_mem_taint;
    taint_t* src_mem_taint;
    for (i = 0; i < size; i++) {
        dst_mem_taint = get_mem_taints_internal(dst_loc + i, 1);
        src_mem_taint = get_mem_taints_internal(src_loc + i, 1);

        if (!src_mem_taint) {
            continue;
        } else if (!dst_mem_taint) {
            set_mem_taints(dst_loc + i, 1, src_mem_taint);
        } else {
            taint_t merged_taint;
            merged_taint = merge_taints(dst_mem_taint[0], src_mem_taint[0]);
            set_mem_taints(dst_loc + i, 1, &merged_taint);
        }
    }
}

TAINTSIGN taint_add_mem2mem_b (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 1);
}

TAINTSIGN taint_add_mem2mem_hw (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 2);
}

TAINTSIGN taint_add_mem2mem_w (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 4);
}

TAINTSIGN taint_add_mem2mem_dw (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 8);
}

TAINTSIGN taint_add_mem2mem_qw (u_long src_loc, u_long dst_loc)
{
    taint_add_mem2mem(src_loc, dst_loc, 16);
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

TAINTSIGN taint_add2_wmemwreg_2hwreg (u_long mem_loc, int src_reg,
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
    shadow_reg_table[dst_reg2 * REG_SIZE] = final_merged_taint;
    shadow_reg_table[dst_reg2 * REG_SIZE + 1] = final_merged_taint;
}

TAINTSIGN taint_add3_dwmem2wreg_2wreg (u_long mem_loc,
                                    int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2)
{
    int i = 0;
    taint_t* shadow_reg_table = current_thread->shadow_reg_table;
    taint_t* mem_taints;
    taint_t merged_taints[8];
    taint_t final_merged_taint;

    for (i = 0; i < 4; i++) {
        mem_taints = get_mem_taints_internal(mem_loc + i, 1);
        if (mem_taints) {
            merged_taints[i] = merge_taints(mem_taints[0], shadow_reg_table[src_reg1 * REG_SIZE + i]);
        } else {
            merged_taints[i] = shadow_reg_table[src_reg1 * REG_SIZE + i];
        }
    }
    for (i = 0; i < 4; i++) {
        mem_taints = get_mem_taints_internal(mem_loc + 4 + i, 1);
        if (mem_taints) {
            merged_taints[i + 4] = merge_taints(mem_taints[0], shadow_reg_table[src_reg2 * REG_SIZE + i]);
        } else {
            merged_taints[i + 4] = shadow_reg_table[src_reg2 * REG_SIZE + i];
        }
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

// immval2mem
TAINTSIGN taint_immvalb2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 1);
}

TAINTSIGN taint_immvalhw2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 2);
}

TAINTSIGN taint_immvalw2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 4);
}

TAINTSIGN taint_immvaldw2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 8);
}

TAINTSIGN taint_immvalqw2mem (u_long mem_loc)
{
    clear_mem_taints(mem_loc, 16);
}

// immval2mem add
TAINTSIGN taint_add_immvalb2mem (u_long mem_loc)
{
    return;
}

TAINTSIGN taint_add_immvalhw2mem (u_long mem_loc)
{
    return;
}

TAINTSIGN taint_add_immvalw2mem (u_long mem_loc)
{
    return;
}

TAINTSIGN taint_add_immvaldw2mem (u_long mem_loc)
{
    return;
}

TAINTSIGN taint_add_immvalqw2mem (u_long mem_loc)
{
    return;
}

// immval2reg
TAINTSIGN taint_immval2lbreg(int reg)
{
}

TAINTSIGN taint_immval2ubreg(int reg)
{
    zero_partial_reg_until(reg, 0, 1);
}

TAINTSIGN taint_immval2hwreg(int reg)
{
    zero_partial_reg_until(reg, 0, 2);
}

TAINTSIGN taint_immval2wreg(int reg)
{
    zero_partial_reg_until(reg, 0, 4);
}

TAINTSIGN taint_immval2dwreg(int reg)
{
    zero_partial_reg_until(reg, 0, 8);
}

TAINTSIGN taint_immval2qwreg(int reg)
{
    zero_partial_reg_until(reg, 0, 16);
}

// immval2reg add
TAINTSIGN taint_add_immval2lbreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2ubreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2hwreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2wreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2dwreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2qwreg(int reg)
{
    return;
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

int add_taint_fd(int fd, int cloexec)
{
    g_hash_table_insert(taint_fds_table, GINT_TO_POINTER(fd), GINT_TO_POINTER(0));
    if (cloexec) {
        g_hash_table_insert(taint_fds_cloexec, GINT_TO_POINTER(fd), GINT_TO_POINTER(1));
    }
    return 0;
}

static void set_fd_taint(int fd, taint_t taint)
{
    g_hash_table_insert(taint_fds_table, GINT_TO_POINTER(fd), GINT_TO_POINTER(taint));
}

taint_t create_and_taint_fdset(int nfds, fd_set* fds)
{
    taint_t t = taint_num++;
    for (int i = 0; i < nfds; i++) {
        if (FD_ISSET(i, fds)) {
            set_fd_taint(i, t);
        }
    }
    return t;
}

int remove_taint_fd(int fd)
{
    if (g_hash_table_contains(taint_fds_cloexec, GINT_TO_POINTER(fd))) {
        g_hash_table_remove(taint_fds_cloexec, GINT_TO_POINTER(fd));
    } 
    return g_hash_table_remove(taint_fds_table, GINT_TO_POINTER(fd));
}

int remove_cloexec_taint_fds(void)
{
    assert(0);
    return 0;
}

int is_fd_tainted(int fd)
{
    return GPOINTER_TO_INT(g_hash_table_lookup(taint_fds_table,
                                            GINT_TO_POINTER(fd)));
}

void taint_fd(int fd, taint_t taint)
{
    set_fd_taint(fd, taint);
}

static void merge_fd_taint(int fd, taint_t taint)
{
    taint_t old_taint;
    taint_t new_taint;
    old_taint = GPOINTER_TO_INT(g_hash_table_lookup(taint_fds_table, GINT_TO_POINTER(fd)));
    new_taint = merge_taints(old_taint, taint);

    g_hash_table_insert(taint_fds_table, GINT_TO_POINTER(fd), GINT_TO_POINTER(new_taint));
}

void taint_mem2fd(u_long mem_loc, int fd)
{
    taint_t* mem_taints = NULL;
    uint32_t count = get_cmem_taints_internal(mem_loc, 1, &mem_taints);
    assert(count == 1);
    if (!mem_taints) {
        set_fd_taint(fd, mem_taints[0]);
    } else {
        set_fd_taint(fd, 0);
    }
}

void taint_mem2fd_size(u_long mem_loc, uint32_t size, int fd)
{
    assert(0);
}

void taint_reg2fd(int reg, int fd)
{
    assert(0);
}

void taint_add_mem2fd(u_long mem_loc, int fd)
{
    taint_t* mem_taints = NULL;
    taint_t* mt = NULL;
    uint32_t count = get_cmem_taints_internal(mem_loc, 1, &mem_taints);
    mt = get_mem_taints_internal(mem_loc, 1);
    assert(mt == mem_taints);
    assert(count == 1);
    if (!mem_taints) {
        fprintf(stderr, "add from mem loc %lx to fd %d\n", mem_loc, fd);
        merge_fd_taint(fd, mem_taints[0]);
    } else {
        fprintf(stderr, "add from mem loc %lx is zero to fd %d\n", mem_loc, fd);
    }
    // else it's zero, so do nothing

}

void taint_add_reg2fd(int reg, int fd)
{
    assert(0);
}

void taint_fd2mem(u_long mem_loc, uint32_t size, int fd)
{
    taint_t t;
    unsigned i = 0;
    t = GPOINTER_TO_INT(g_hash_table_lookup(taint_fds_table,
                                            GINT_TO_POINTER(fd)));

    uint32_t nsize = size;
    while (i < size) {
        uint32_t inc = 0;
        inc += set_cmem_taints_one(mem_loc + i, nsize, t);
        i += inc;
        nsize -= inc;
    }
}

void taint_add_fd2mem(u_long mem_loc, uint32_t size, int fd)
{
    taint_t t;
    t = GPOINTER_TO_INT(g_hash_table_lookup(taint_fds_table,
                                            GINT_TO_POINTER(fd)));
    unsigned i = 0;
    uint32_t offset = 0;
    u_long mem_offset = mem_loc;

    while (offset < size) {
        taint_t* mem_taints = NULL;
        uint32_t count = get_cmem_taints_internal(mem_offset, size - offset, &mem_taints);
        if (mem_taints) {
            for (i = 0; i < count; i++) {
                mem_taints[i] = merge_taints(t, mem_taints[i]);
            }
        } else {
            // mem not tainted, just a set
            if (t) {
                set_mem_taints(mem_offset, count, &t);
            }
        }
        offset += count;
        mem_offset += count;
    }
}

taint_t create_and_taint_option (u_long mem_addr)
{
    taint_t t = taint_num++;
    taint_mem_internal(mem_addr, t);
    TPRINT ("taint %x created at mem address %lx clock %ld\n", t, mem_addr, *ppthread_log_clock);
#ifdef TAINT_DEBUG
    if (TAINT_DEBUG(t)) {
	fprintf (debug_f, "taint %x created at mem address %lx clock %ld\n", t, mem_addr, *ppthread_log_clock);
    }
#endif
    return t;
}
