#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/resource.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#define PCKPT_MAX_BUF 1024*1024
int main (int argc, char* argv[])
{
    char buf[PCKPT_MAX_BUF];
    char filename[4096];
    int fd, i;
    int reg_index = 0;
    unsigned long reg_value;
    unsigned long mem_loc;
    unsigned char mem_value;
    int len = 0;
    int offset = 0;
    unsigned int regcount = 0;


    if (argc != 2) {
	printf ("format (parsing the patch based ckpt): parsepckpt <dir>\n");
	return -1;
    }
    
    sprintf (filename, "%s/pckpt", argv[1]);
    fd = open (filename, O_RDONLY);
    if (fd < 0) {
	perror ("open");
	return fd;
    }

    len = read (fd, &regcount, sizeof (unsigned int)); 
    assert (len == sizeof (unsigned int));
    len = read (fd, buf, regcount * (sizeof(unsigned int) + sizeof (unsigned long)));
    assert (len == regcount* (sizeof(unsigned int) + sizeof (unsigned long)));

    printf ("------checkpoint regs ------\n");
    offset = 0;
    for (i = 0; i<regcount; ++i) {
        reg_index = *((int*) (buf + offset));
        offset += sizeof (int);
        reg_value = *((unsigned long*) (buf + offset));
        offset += sizeof (unsigned long);
        if (reg_index != -1) 
            printf ("reg %d value %lu\n", reg_index, reg_value);
        else 
            printf ("skipped reg\n");
    } 

    printf ("------checkpoint mem------\n");
    len = read (fd, buf, PCKPT_MAX_BUF/5*5);
    while (len != 0) {
        offset = 0;
        while (offset < len) { 
            mem_loc = *((unsigned long*) (buf + offset));
            offset += sizeof (unsigned long);
            mem_value = *((unsigned char*)(buf + offset));
            offset += sizeof (unsigned char);
            printf ("mem 0x%lx value %u\n", mem_loc, (unsigned int) mem_value);
        }
        len = read (fd, buf, PCKPT_MAX_BUF/5*5);
    }
    return 0;
}
