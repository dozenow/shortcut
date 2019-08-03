#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/resource.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#define MAX_BUF 1024*1024
#define NUM_REGS 120
#define REG_SIZE 16
typedef char bool;

int main (int argc, char* argv[])
{
    char buf[MAX_BUF];
    char filename[4096];
    int fd;
    unsigned long mem_loc;
    unsigned char mem_value;
    int len = 0;
    int offset = 0;
    bool read_reg[NUM_REGS*REG_SIZE];
    char read_reg_value[NUM_REGS*REG_SIZE];
    int failed_output = 0;

    if (argc < 2) {
	printf ("format (parsing the verification set): parseverif -o <dir>\n");
	return -1;
    }
    
    if (argc == 2)  {
        sprintf (filename, "%s/verification_output", argv[1]);
        failed_output = 1;
    } else 
        sprintf (filename, "%s/verification", argv[2]);
    fd = open (filename, O_RDONLY);
    if (fd < 0) {
	perror ("open");
	return fd;
    }

    if (argc == 3) {
        len = read (fd, (char*) read_reg, sizeof(read_reg));
        assert (len == sizeof(read_reg));
        len = read (fd, read_reg_value, sizeof(read_reg_value));
        assert (len == sizeof(read_reg_value));
    }

    printf ("------verification regs ------\n");

    printf ("------verification mem------\n");
    len = read (fd, buf, MAX_BUF/5*5);
    while (len != 0) {
        offset = 0;
        while (offset < len) { 
            mem_loc = *((unsigned long*) (buf + offset));
            offset += sizeof (unsigned long);
            mem_value = *((unsigned char*)(buf + offset));
            offset += sizeof (unsigned char);
            if (failed_output) {
                unsigned char cur_value = *((unsigned char*)(buf + offset));
                printf ("0x0 mem_predicate 0x%lx %u,%u\n", mem_loc, (unsigned int) mem_value, (unsigned int) cur_value);
                offset += sizeof (unsigned char);
            } else 
                printf ("0x0 mem_predicate 0x%lx %u\n", mem_loc, (unsigned int) mem_value);
        }
        len = read (fd, buf, MAX_BUF/5*5);
    }
    return 0;
}
