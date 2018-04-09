#include <string.h>
#include <assert.h>
#include <syscall.h>

#include <iostream>
#include <fstream>
#include <string>
#include <bitset>
using namespace std;

#include "linkage_common.h"
#include "taint_interface/taint_interface.h"

//#define DPRINT fprintf
#define DPRINT(x,...)

#include "mmap_regions.h"

// Let's optimize for fast checking and easy code!
#define PAGE_SIZE 4096
bitset<0xc0000> ro_pages;
bitset<0xc0000> rw_pages;
bitset<0xc0000> ex_pages;
bitset<0xc0000> max_ro_pages;
bitset<0xc0000> max_rw_pages;

void init_mmap_region ()
{
    char filename[256];
    sprintf (filename, "/proc/%d/maps", getpid());
    ifstream in(filename, ios::in);
    if (!in.is_open()) {
        cerr << "cannot open " << filename <<endl;
        return;
    }
    string line;
    while (!in.eof()) { 
        if (in.fail() || in.bad()) assert (0);
        getline (in, line);
	DPRINT (stderr, "%s", line.c_str());
        if (line.empty()) continue;
        //cerr <<line<<endl;
        u_long start = std::stoul(line.substr(0, 8), 0, 16);
        u_long end = stoul(line.substr(9, 8), 0, 16);
        string flag_str = line.substr (18, 4);

        int flag = PROT_NONE;
        if (flag_str[0] == 'r') flag |= PROT_READ;
        if (flag_str[1] == 'w') flag |= PROT_WRITE;
        if (flag_str[2] == 'x') flag |= PROT_EXEC;
        if (flag == PROT_NONE) continue;
        add_mmap_region (start, end-start, flag, (flag_str[3] == 'p'?MAP_PRIVATE:MAP_SHARED));
        DPRINT (stderr, "init_mmap_region: start %lx end %lx, length %ld, prot %x, flag %x\n", start, end, end-start, flag, (flag_str[3] == 'p'?MAP_PRIVATE:MAP_SHARED));
    }
}

void add_mmap_region (u_long addr, int len, int prot, int flags) 
{ 
    bool ro_val = (prot & PROT_READ) && !(prot & PROT_WRITE); /* this only included private pages - why? */
    bool rw_val = (prot & PROT_READ) && (prot & PROT_WRITE);
    bool ex_val = (prot & PROT_EXEC);
    DPRINT (stderr, "add mmap region from %lx to %lx read only? %d read-write? %d executable? %d\n", addr, addr+len, ro_val, rw_val, ex_val);
    for (auto i = addr; i < addr+len; i += PAGE_SIZE) {
	if (max_rw_pages.test(i/PAGE_SIZE) && !ro_pages.test(i/PAGE_SIZE) && !rw_pages.test(i/PAGE_SIZE) && ro_val) DPRINT (stderr, "remap of prev read/write page 0x%lx\n", i);
	ro_pages.set(i/PAGE_SIZE, ro_val);
	rw_pages.set(i/PAGE_SIZE, rw_val);
	ex_pages.set(i/PAGE_SIZE, ex_val);
	max_ro_pages.set(i/PAGE_SIZE, ro_val || max_ro_pages.test(i/PAGE_SIZE));
	max_rw_pages.set(i/PAGE_SIZE, rw_val || max_rw_pages.test(i/PAGE_SIZE));
    }
}

void delete_mmap_region (u_long addr, int len) 
{
    DPRINT (stderr, "delete mmap region from %lx to %lx\n", addr, addr+len);
    for (auto i = addr; i < addr+len; i += PAGE_SIZE) {
	ro_pages.reset(i/PAGE_SIZE);
	rw_pages.reset(i/PAGE_SIZE);
    }
}

void change_mmap_region (u_long addr, int len, int prot)
{
    DPRINT (stderr, "change mmap region 0x%lx len 0x%x prot 0x%x\n", addr, len, prot);
    // Are we changing from read-write to read-only?
    if (prot & PROT_WRITE) {
	for (auto i = addr; i < addr+len; i += PAGE_SIZE) {
	    if (rw_pages.test(i/PAGE_SIZE)) {
		// Check if the memory is tainted
		fprintf (stderr, "changing from read-write to read-only: tainted? %d addr 0x%lx len 0x%x\n", is_mem_arg_tainted(addr, len), addr, len);
	    }
	}
    }

    add_mmap_region (addr, len, prot, MAP_PRIVATE);
}

#define is_readonly_now(i)  (ro_pages.test(i) && !max_rw_pages.test(i))

bool is_readonly (u_long addr, int len) 
{
    for (u_int i = addr/PAGE_SIZE; i <= (addr+len-1)/PAGE_SIZE; i++) {
	if (!is_readonly_now(i)) return false;  // Not perfect
    }
    return true;
}

//given a memory range, see if it's in a read-only region
bool is_readonly_mmap_region (u_long addr, int len, u_long& start, u_long& end) 
{
    u_int i;
    for (i = addr/PAGE_SIZE; i <= (addr+len-1)/PAGE_SIZE; i++) {
	if (!is_readonly_now(i)) {
	    DPRINT (stderr, "addr %lx len %d is not in a read-only region i %x ro %d max_rw %d\n", addr, len, i, ro_pages.test(i), max_rw_pages.test(i));
	    return false;
	}
    }
    for (i++; i < 0xc00000 && is_readonly_now(i); i++);
    end = i*PAGE_SIZE;
    
    for (i = addr/PAGE_SIZE - 1; i >= 0 && is_readonly_now(i); i--);
    start = (i+1)*PAGE_SIZE;

    DPRINT (stderr, "addr %lx len %d is in a read-only region from %lx to %lx\n", addr, len, start, end);
    return true;
}

static void handle_unprotection (struct thread_data* tdata, u_long start, u_long size, int type)
{
    DPRINT (stderr, "handle protection for range from 0x%lx size %lx: type %d\n", start, size, type);
    if (type == 1) {
	// mprotect read-write
	OUTPUT_MAIN_THREAD (tdata, "mov eax, %d", SYS_mprotect);
	OUTPUT_MAIN_THREAD (tdata, "mov ebx, 0x%lx", start);
	OUTPUT_MAIN_THREAD (tdata, "mov ecx, 0x%lx", size);
	int flags = PROT_READ|PROT_WRITE;
	if (ex_pages.test(start/PAGE_SIZE)) flags |= PROT_EXEC;
	OUTPUT_MAIN_THREAD (tdata, "mov edx, %d", flags);
	OUTPUT_MAIN_THREAD (tdata, "int 0x80");
#if 0
	// unmap than map anonymous read-write - when do we need to do this?
	OUTPUT_MAIN_THREAD (tdata, "mov eax, %d", SYS_munmap);
	OUTPUT_MAIN_THREAD (tdata, "mov ebx, 0x%lx", start);
	OUTPUT_MAIN_THREAD (tdata, "mov ecx, 0x%lx", size);
	OUTPUT_MAIN_THREAD (tdata, "int 0x80");

	OUTPUT_MAIN_THREAD (tdata, "mov eax, %d", SYS_mmap2);
	OUTPUT_MAIN_THREAD (tdata, "mov ebx, 0x%lx", start);
	OUTPUT_MAIN_THREAD (tdata, "mov ecx, 0x%lx", size);
	OUTPUT_MAIN_THREAD (tdata, "mov edx, %d", PROT_READ|PROT_WRITE);
	OUTPUT_MAIN_THREAD (tdata, "mov esi, %d", MAP_ANONYMOUS | MAP_PRIVATE);
	OUTPUT_MAIN_THREAD (tdata, "mov edi, -1");
	OUTPUT_MAIN_THREAD (tdata, "mov ebp, 0");
	OUTPUT_MAIN_THREAD (tdata, "int 0x80");
#endif
    } else if (type == 2) {
	// mmap anonymous read-write
	OUTPUT_MAIN_THREAD (tdata, "mov eax, %d", SYS_mmap2);
	OUTPUT_MAIN_THREAD (tdata, "mov ebx, 0x%lx", start);
	OUTPUT_MAIN_THREAD (tdata, "mov ecx, 0x%lx", size);
	OUTPUT_MAIN_THREAD (tdata, "mov edx, %d", PROT_READ|PROT_WRITE);
	OUTPUT_MAIN_THREAD (tdata, "mov esi, %d", MAP_ANONYMOUS | MAP_PRIVATE);
	OUTPUT_MAIN_THREAD (tdata, "mov edi, -1");
	OUTPUT_MAIN_THREAD (tdata, "mov ebp, 0");
	OUTPUT_MAIN_THREAD (tdata, "int 0x80");
    } else if (type == 3) {
	// mmap anonymous read-only
	OUTPUT_MAIN_THREAD (tdata, "mov eax, %d", SYS_mmap2);
	OUTPUT_MAIN_THREAD (tdata, "mov ebx, 0x%lx", start);
	OUTPUT_MAIN_THREAD (tdata, "mov ecx, 0x%lx", size);
	OUTPUT_MAIN_THREAD (tdata, "mov edx, %d", PROT_READ);
	OUTPUT_MAIN_THREAD (tdata, "mov esi, %d", MAP_ANONYMOUS | MAP_PRIVATE);
	OUTPUT_MAIN_THREAD (tdata, "mov edi, -1");
	OUTPUT_MAIN_THREAD (tdata, "mov ebp, 0");
	OUTPUT_MAIN_THREAD (tdata, "int 0x80");
	// unmap
    }
}

static void handle_protection (struct thread_data* tdata, u_long start, u_long size, int type)
{
    DPRINT (stderr, "handle protection for range from 0x%lx size %lx: type %d\n", start, size, type);
    if (type == 1) {
	// mprotect read-only
	OUTPUT_MAIN_THREAD (tdata, "mov eax, %d", SYS_mprotect);
	OUTPUT_MAIN_THREAD (tdata, "mov ebx, 0x%lx", start);
	OUTPUT_MAIN_THREAD (tdata, "mov ecx, 0x%lx", size);
	int flags = PROT_READ;
	if (ex_pages.test(start/PAGE_SIZE)) flags |= PROT_EXEC;
	OUTPUT_MAIN_THREAD (tdata, "mov edx, %d", flags);
	OUTPUT_MAIN_THREAD (tdata, "int 0x80");
    } else if (type == 2 || type == 3) {
	// unmap
	OUTPUT_MAIN_THREAD (tdata, "mov eax, %d", SYS_munmap);
	OUTPUT_MAIN_THREAD (tdata, "mov ebx, 0x%lx", start);
	OUTPUT_MAIN_THREAD (tdata, "mov ecx, 0x%lx", size);
	OUTPUT_MAIN_THREAD (tdata, "int 0x80");
    }
}

// If performance is an issue, we could do this is one loop and print to separate files?
void handle_downprotected_pages (struct thread_data* tdata)
{
    DPRINT (stderr, "handle down protected pages\n");
    OUTPUT_MAIN_THREAD (tdata, "downprotect_mem:");
    int i, start_at = 0, type = 0, prev_type = 0;
    int is_prev_executable = 0, is_executable = 0;
    for (i = 0; i < 0xc0000; i++) {
	if (max_rw_pages.test(i) && !rw_pages.test(i)) {
	    if (ro_pages.test(i)) {
		type = 1;
	    } else {
		type = 2;
	    }
	} else if (max_ro_pages.test(i) && !ro_pages.test(i) && !rw_pages.test(i)) {
	    type = 3;
	} else {
	    type = 0;
	}
        if (ex_pages.test(i)) {
            is_executable = 1;
        } else { 
            is_executable = 0;
        }
	
	if (type != prev_type || is_prev_executable != is_executable) {
	    if (prev_type != 0) {
		handle_unprotection (tdata, start_at*PAGE_SIZE, (i-start_at)*PAGE_SIZE, prev_type);
	    } 
	    start_at = i;
	}
	prev_type = type;
        is_prev_executable = is_executable;
    }	
    if (prev_type) {
	handle_unprotection (tdata, start_at*PAGE_SIZE, (i-start_at)*PAGE_SIZE, prev_type);
    } 
    OUTPUT_MAIN_THREAD (tdata, "ret");
}

void handle_upprotected_pages (struct thread_data* tdata)
{
    DPRINT (stderr, "handle up protected pages\n");
    OUTPUT_MAIN_THREAD (tdata, "upprotect_mem:"); 
    int i, start_at = 0, type = 0, prev_type = 0;
    int is_prev_executable = 0, is_executable = 0;
    for (i = 0; i < 0xc0000; i++) {
	if (max_rw_pages.test(i) && !rw_pages.test(i)) {
	    if (ro_pages.test(i)) {
		type = 1;
	    } else {
		type = 2;
	    }
	} else if (max_ro_pages.test(i) && !ro_pages.test(i) && !rw_pages.test(i)) {
	    type = 3;
	} else {
	    type = 0;
	}

        if (ex_pages.test(i) || is_prev_executable != is_executable) {
            is_executable = 1;
        } else { 
            is_executable = 0;
        }
	
	if (type != prev_type || is_prev_executable != is_executable) {
            if (prev_type != 0) {
		handle_protection (tdata, start_at*PAGE_SIZE, (i-start_at)*PAGE_SIZE, prev_type);
	    } 
            start_at = i;
	}
	prev_type = type;
        is_prev_executable = is_executable;
    }	
    if (prev_type) {
	handle_protection (tdata, start_at*PAGE_SIZE, (i-start_at)*PAGE_SIZE, prev_type);
    } 
    OUTPUT_MAIN_THREAD (tdata, "ret");
}

