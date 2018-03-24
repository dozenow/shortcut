#ifndef __MMAP_REGIONS_H__
#define __MMAP_REGIONS_H__

#include <stdlib.h>
#include <sys/mman.h>

void init_mmap_region ();
void add_mmap_region (u_long addr, int len, int prot, int flags);
void delete_mmap_region (u_long addr, int len);
void change_mmap_region (u_long addr, int len, int prot);
bool is_readonly (u_long addr, int len);
bool is_readonly_mmap_region (u_long addr, int len, u_long& start, u_long& end);
void handle_downprotected_pages (struct thread_data*);
void handle_upprotected_pages (struct thread_data*);


#endif
