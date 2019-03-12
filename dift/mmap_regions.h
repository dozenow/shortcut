#ifndef __MMAP_REGIONS_H__
#define __MMAP_REGIONS_H__

#include <stdlib.h>
#include <sys/mman.h>
#include <bitset>

void init_mmap_region ();
void clear_mmap_region ();
void add_mmap_region (u_long addr, int len, int prot, int flags);
void move_mmap_region (u_long new_address, u_long new_size, u_long old_address, u_long old_size);
void delete_mmap_region (u_long addr, int len);
void change_mmap_region (u_long addr, int len, int prot);
bool is_readonly (u_long addr, int len);
bool is_readonly_mmap_region (u_long addr, int len, u_long& start, u_long& end);
void handle_downprotected_pages (struct thread_data*);
void handle_upprotected_pages (struct thread_data*);
bool is_existed (u_long addr);
void jumpstart_create_extra_memory_region_list (int fd, bitset<0xc0000>* pages);


#endif
