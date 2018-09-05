#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/resource.h>
#include <time.h>
#include <string.h>
#include <assert.h>

int main (int argc, char* argv[])
{
    char buf[1024*1024];
    char filename[4096];
    int fd, i;
    int reg_index = 0;
    unsigned int reg_value;
    unsigned long mem_loc;
    unsigned char mem_value;
    int len = 0;
    int offset = 0;

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

    len = read (fd, buf, sizeof(buf));
    assert (len < sizeof(buf));

    printf ("------checkpoint regs ------\n");
    reg_index = *((unsigned int*) buf);
    offset += sizeof (unsigned int);
    while (reg_index != -1) {
        reg_value = *((unsigned int*) (buf + offset));
        offset += sizeof (unsigned int);
        printf ("reg %d value %u\n", reg_index, reg_value);
        reg_index = *((int*) (buf + offset));
        offset += sizeof (int);
    } 
    offset += sizeof (int);
    printf ("------checkpoint mem------\n");
    while (offset < len) { 
        mem_loc = *((unsigned long*) (buf + offset));
        offset += sizeof (unsigned long);
        mem_value = *((unsigned char*)(buf + offset));
        offset += sizeof (unsigned char);
        printf ("mem 0x%lx value %u\n", mem_loc, (unsigned int) mem_value);
    }
    return 0;
}
