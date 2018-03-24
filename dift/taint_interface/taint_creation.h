#ifndef TAINT_CREATION_H
#define TAINT_CREATION_H

#include <stdint.h>
#include <string.h>
#include <sys/select.h>
#include "taint.h"

#ifdef __cplusplus
extern "C" {
#endif

// filter types
#define FILTER_FILENAME     1
#define FILTER_PARTFILENAME 2
#define FILTER_SYSCALL      3
#define FILTER_REGEX        4
#define FILTER_BYTERANGE    5

struct taint_creation_info {
    int32_t type;
    int32_t record_pid;
    uint64_t rg_id;
    uint32_t syscall_cnt;
    int32_t offset;
    int32_t fileno;
    // extra data
    int32_t data;
};

void init_filters();
void set_filter_inputs(int f);
int filter_input(void);
void set_filter_outputs(int f, u_long syscall);
int filter_output(void);

// input filters
void add_input_filter(int type, void* filter);

// output filters
void add_output_filter(int type, void* filter);

#define MAX_REGIONS 20
int get_partial_taint_byte_range (pid_t pid, int syscall, size_t* start, size_t* end);

int serialize_filters(int outfd);
int deserialize_filters(int infd);

// build input filters from reading a filter file
void build_filters_from_file(const char* filter_filename);

/* Creates taints from a buffer that match any of the
 * input filters, if input filters are on.
 *
 * */
void create_taints_from_buffer(void* buf, int size, 
			       struct taint_creation_info*,
			       int outfd,
			       char* channel_name);
void create_taints_from_buffer_unfiltered(void* buf, int size, 
					  struct taint_creation_info*,
					  int outfd);
void create_syscall_retval_taint (struct taint_creation_info *tci, int outfd, char* channel_name);
void create_syscall_retval_taint_unfiltered (struct taint_creation_info *tci, int outfd);
  
/* Outputs the taints in a buffer that match the output
 * filters, if output filters are on. */
void output_buffer_result (void* buf, int size,
			   struct taint_creation_info* tci,
			   int outfd);
void output_jump_result (u_long inst_addr, taint_t value, struct taint_creation_info* tci, int outfd);
void write_output_header(int outfd, struct taint_creation_info* tci,
                            void* buf, int buf_size);
void write_output_taints (int outfd, void* buf, int size);

void output_xcoords (int outfd, int syscall_cnt,
		     int dest_x, int dest_y, u_long mem_loc);

#ifdef __cplusplus
}
#endif

#endif
