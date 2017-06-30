#include "linkage_common.h"
#include <sys/mman.h>

void init_mmap_region (struct thread_data* tdata);
void add_mmap_region (struct thread_data* tdata, struct mmap_info* info);
void delete_mmap_region (struct thread_data* tdata, u_long addr, int len);
void change_mmap_region (struct thread_data* tdata, u_long addr, int len, int prot);
struct mmap_info* is_readonly_mmap_region (struct thread_data* tdata, u_long addr, int len);


