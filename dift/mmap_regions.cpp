#include "mmap_regions.h"
#include <string.h>
#include <iostream>
#include <fstream>
#include <string>
using namespace std;
#define IS_READ_ONLY(info) (info->prot & PROT_READ) && !(info->prot & PROT_WRITE) && (info->flags & MAP_PRIVATE) 
#define DPRINT if(0) fprintf

void init_mmap_region (struct thread_data* tdata) 
{
#ifdef TRACK_READONLY_REGION
    char filename[256];
    sprintf (filename, "/proc/%d/maps", getpid());
    tdata->all_mmap_regions->clear();
    tdata->ro_mmap_regions->clear();
    ifstream in(filename, ios::in);
    if (!in.is_open()) {
        cerr << "cannot open " << filename <<endl;
        return;
    }
    string line;
    while (!in.eof()) { 
        if (in.fail() || in.bad()) assert (0);
        getline (in, line);
        if (line.empty()) continue;
        //cerr <<line<<endl;
        u_long start = std::stoul(line.substr(0, 8), 0, 16);
        u_long end = stoul(line.substr(9, 8), 0, 16);
        string flag_str = line.substr (18, 4);
        struct mmap_info info;
        info.addr = start;
        info.length = end - start;
        int flag = PROT_NONE;
        if (flag_str[0] == 'r') flag |= PROT_READ;
        if (flag_str[1] == 'w') flag |= PROT_WRITE;
        if (flag_str[2] == 'x') flag |= PROT_EXEC;
        if (flag == PROT_NONE) continue;
        info.prot = flag;
        info.flags = (flag_str[3] == 'p'?MAP_PRIVATE:MAP_SHARED);
        info.fd = -1;
        add_mmap_region (tdata, &info);
        DPRINT (stderr, "init_mmap_region: start %lx end %lx, length %d, prot %x, flag %x\n", start, end, info.length, flag, info.flags);
    }
#endif
}

void add_mmap_region (struct thread_data* tdata, struct mmap_info* info) 
{ 
#ifdef TRACK_READONLY_REGION
    //info->length = (info->length/4096+1)*4096;
    pair<map<u_long, struct mmap_info>::iterator,bool> ret = tdata->all_mmap_regions->insert (make_pair(info->addr, *info));
    DPRINT (stderr, "add_mmap_region: add region %lx, %d\n", info->addr, info->length);
    if (!ret.second) { 
        fprintf (stderr, "add_mmap_region: already added memory region? %lx, size %d\n", info->addr, info->length);
        assert (false);
    }
    if (IS_READ_ONLY(info)) {
        //mark read-only regions
        tdata->ro_mmap_regions->push_back (*info);
        DPRINT (stderr, "add_mmap_region: read-only region %lx, %d\n", info->addr, info->length);
    }
#endif
}

void delete_mmap_region (struct thread_data* tdata, u_long addr, int len) 
{
#ifdef TRACK_READONLY_REGION
   map<u_long, struct mmap_info>::iterator it = tdata->all_mmap_regions->find (addr); 
   DPRINT (stderr, "delete_mmap_region %lx %d\n", addr, len);
   assert (it != tdata->all_mmap_regions->end());
   if (it->second.length > len) {
       if (IS_READ_ONLY((&it->second))) {
           fprintf (stderr, "[BUG] unmap a read-only region.\n");
           //TODO: then remove it from the readonly list
       }
       it->second.addr += len;
       it->second.length -= len;
       DPRINT (stderr, "delete_mmap_region shrink to %lx size %d\n", it->second.addr, it->second.length);
   } else if (it->second.length <= len) { 
       while (len > 0) {
           //don't handle the case where we unmap a read-only region
           if (IS_READ_ONLY((&it->second))) {
               fprintf (stderr, "[BUG] unmap a read-only region.\n");
               //TODO: then remove it from the readonly list
           }
           addr += it->second.length;
           len -= it->second.length;
           DPRINT (stderr, "delete_mmap_region delete %lx size %d\n", it->second.addr, it->second.length);
           tdata->all_mmap_regions->erase (it);
           if (len > 0) {
               DPRINT (stderr, "delete_mmap_region: next addr to delete %lx, len %d\n", addr, len);
               it = tdata->all_mmap_regions->find (addr);
               assert (it!=tdata->all_mmap_regions->end());
           }
       }
   }
#endif
}

void change_mmap_region (struct thread_data* tdata, u_long addr, int len, int prot)
{
#ifdef TRACK_READONLY_REGION
    map<u_long, struct mmap_info>::iterator it = tdata->all_mmap_regions->find (addr); 
    DPRINT (stderr, "change_mmap_region: %lx %d %x\n", addr, len, prot);
    if (it == tdata->all_mmap_regions->end()) {
        fprintf (stderr, "[ERROR]change_mmap_region cannot find the region: %lx %d %x, is this the text region or stack or a subset of some region?\n", addr, len, prot);
        return;
    }
    if (it->second.length > len) { 
        //well, we have to break this region into two 
        struct mmap_info second;
        memcpy (&second, &(it->second), sizeof(struct mmap_info));
        second.length = it->second.length - len;
        second.addr = second.addr + len;
        tdata->all_mmap_regions->insert (make_pair (second.addr, second));
        it->second.length = len;
        DPRINT (stderr, "change_mmap_region: split: %lx %d, %lx %d\n", it->second.addr, it->second.length, second.addr, second.length);
    } else if (it->second.length < len) { 
        fprintf (stderr, "[ERROR] change_mmap_region: mismatched region size %d %d \n", it->second.length, len);
    }
    if (IS_READ_ONLY((&it->second))) { 
        if (prot & PROT_WRITE) { 
            fprintf (stderr, "[BUG] change the protection of a read-only region to writable.\n");
            //TODO: then remove it from the readonly list
            //And also, need to be carefull about the second part of this region if we split it in the previous step
        }
    }
    if ((prot & PROT_READ) && !(prot & PROT_WRITE)) { 
        //we find a new read-only region
        tdata->ro_mmap_regions->push_back (it->second);
    }
    it->second.prot = prot;
#endif
}

//given a memory range, see if it's in a read-only region
struct mmap_info* is_readonly_mmap_region (struct thread_data* tdata, u_long addr, int len) 
{
#ifdef TRACK_READONLY_REGION
    DPRINT (stderr, "is_readonly_mmap_region: %lx ,%d\n", addr, len);
    for (list<struct mmap_info>::iterator it = tdata->ro_mmap_regions->begin(); it != tdata->ro_mmap_regions->end(); ++it) {
        if (it->addr < addr && (it->addr + it->length >= addr + len)) {
            return &(*it);
        }
    }
#endif
    return NULL;
}

