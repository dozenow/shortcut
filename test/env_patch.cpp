#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

char target_str[] = "DBUS_SESSION_BUS_ADDRESS=";

int main (int argc, char* argv[]) 
{
    char env_str[256];
    strcpy (env_str, target_str);
    env_str[strlen(env_str)-1] = '\0';
    char* substitution_str = getenv(env_str);
    fprintf (stderr, "sub string is %s\n", substitution_str);
    if (substitution_str == NULL) {
	fprintf (stderr, "Cannot get %s from the environment\n", env_str);
	return -1;
    }

    char* c = strstr (argv[1], "ckpt_mmap.");
    if (c == NULL) {
	fprintf (stderr, "%s is a badly formatted checkpoint file name\n", argv[1]);
	return -1;
    }
    u_long region_address = strtoul (c+10, NULL, 16);

    // Map writable in ckpt file with target memory region
    int fd = open (argv[1], O_RDWR);
    if (fd < 0) {
	fprintf (stderr, "Cannot open %s\n", argv[1]);
	return fd;
    }

    struct stat st;
    long rc = fstat (fd, &st);
    if (rc < 0) {
	fprintf (stderr, "Unable to stat %s\n", argv[1]);
	return fd;
    }
    u_long size = st.st_size;
    if (st.st_size%4096) size += 4096-st.st_size;

    char* p = (char *) mmap (0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
	fprintf (stderr, "Unable to map %s, errno=%d\n", argv[1], errno);
	return fd;
    }

    // Calculate target address
    u_long abs_address = strtoul (argv[2], NULL, 16);
    u_long rel_address = abs_address - region_address;
    if (rel_address+strlen(target_str)+strlen(substitution_str) > (u_long) st.st_size) {
	fprintf (stderr, "Region not large enough to contain string\n");
	return -1;
    }
    if (strncmp (p+rel_address, target_str, strlen(target_str))) {
	fprintf (stderr, "Target string mismatch: found %s\n", p+rel_address);
	return -1;
    }
    fprintf (stderr, "previous string was: %s\n", p+rel_address+strlen(target_str));
    if (strlen(p+rel_address+strlen(target_str)) != strlen(substitution_str)) {
	fprintf (stderr, "Mismatch in length : substitution string is %s - target string is %s\n",
		 substitution_str, p+rel_address+strlen(target_str));
	return -1;
    }

    // This makes the change
    memcpy (p+rel_address+strlen(target_str), substitution_str, strlen(substitution_str));
    fprintf (stderr, "new string was: %s\n", p+rel_address+strlen(target_str));

    msync(p, size, 0);

    close (fd);
    return 0;
}
