#ifndef __PARSEULIB_H
#define __PARSEULIB_H

#include <queue>

struct ulog { 
    int fd;
    long size;
    long bytes_read;
    u_long total_clock;
    std::queue<u_long> *clocks;
};

struct ulog* parseulib_open (char* filename);
u_long parseulib_get_next_clock (struct ulog* log);
void parseulib_close (struct ulog* log);
#endif
