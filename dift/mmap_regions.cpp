#include "mmap_regions.h"
#include <string.h>
using namespace std;
#define IS_READ_ONLY(info) (info->prot & PROT_READ) && !(info->prot & PROT_WRITE) && (info->flags & MAP_PRIVATE) 
#define DPRINT if(0) fprintf

void add_mmap_region (struct thread_data* tdata, struct mmap_info* info) 
{ 
    pair<map<u_long, struct mmap_info>::iterator,bool> ret = tdata->all_mmap_regions->insert (make_pair(info->addr, *info));
    DPRINT (stderr, "add_mmap_region: add region %lx, %d\n", info->addr, info->length);
    if (!ret.second) { 
        fprintf (stderr, "add_mmap_region: already added memory region?\n");
        assert (false);
    }
    if (IS_READ_ONLY(info)) {
        //mark read-only regions
        tdata->ro_mmap_regions->push_back (*info);
        DPRINT (stderr, "add_mmap_region: read-only region %lx, %d\n", info->addr, info->length);
    }
}

void delete_mmap_region (struct thread_data* tdata, u_long addr, int len) 
{
   map<u_long, struct mmap_info>::iterator it = tdata->all_mmap_regions->find (addr); 
   DPRINT (stderr, "delete_mmap_region %lx %d\n", addr, len);
   assert (it != tdata->all_mmap_regions->end());
   assert (it->second.length == len);
   //don't handle the case where we unmap a read-only region
   if (IS_READ_ONLY((&it->second))) {
       fprintf (stderr, "[BUG] unmap a read-only region.\n");
       //TODO: then remove it from the readonly list
   }
   tdata->all_mmap_regions->erase (it);
}

void change_mmap_region (struct thread_data* tdata, u_long addr, int len, int prot)
{
    map<u_long, struct mmap_info>::iterator it = tdata->all_mmap_regions->find (addr); 
    DPRINT (stderr, "change_mmap_region: %lx %d %x\n", addr, len, prot);
    if (it == tdata->all_mmap_regions->end()) {
        fprintf (stderr, "[ERROR]change_mmap_region cannot find the region: %lx %d %x, is this the text region or stack?\n", addr, len, prot);
    }
    if (it->second.length != len) { 
        assert (it->second.length > len);
        //well, we have to break this region into two 
        struct mmap_info second;
        memcpy (&second, &(it->second), sizeof(struct mmap_info));
        second.length = it->second.length - len;
        second.addr = second.addr + len;
        tdata->all_mmap_regions->insert (make_pair (second.addr, second));
        it->second.length = len;
        DPRINT (stderr, "change_mmap_region: split: %lx %d, %lx %d\n", it->second.addr, it->second.length, second.addr, second.length);
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
}

//given a memory range, see if it's in a read-only region
struct mmap_info* is_readonly_mmap_region (struct thread_data* tdata, u_long addr, int len) 
{
    DPRINT (stderr, "is_readonly_mmap_region: %lx ,%d\n", addr, len);
    for (list<struct mmap_info>::iterator it = tdata->ro_mmap_regions->begin(); it != tdata->ro_mmap_regions->end(); ++it) {
        if (it->addr < addr && (it->addr + it->length >= addr + len)) {
            return &(*it);
        }
    }
    return NULL;
}

