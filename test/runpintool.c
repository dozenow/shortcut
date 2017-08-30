// Shell program for running a sequential multi-stage DIFT
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include "util.h"

//TODO: Currently, we only use data flow tool, probably should also enable the index tool in the future
int main (int argc, char* argv[]) 
{
    char cpids[256];
    char* dirname, *pintool;
    pid_t cpid, mpid;
    int fd, rc, status, i;
    int attach_gdb = 0;
    int args_index = 1;
    char* attach_offset = NULL; //the position(clock_value) where we start to attach pin

    if (argc < 2) {
	fprintf (stderr, "format: runpintool [--attach_offset==<pid,syscall_start_clock>] <replay dir> <tool> [args passed to pin tool]\n");
	return -1;
    }

    if (argc >=4 && !strncmp (argv[args_index], "--attach_offset=", 15)) { 
        printf ("Pin will run after %s\n", argv[args_index]);
        attach_offset = argv[args_index];
        ++ args_index;
    }

    dirname = argv[args_index++];
    pintool = argv[args_index++];

    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror("open /dev/spec0");
	return fd;
    }

    cpid = fork ();
    if (cpid == 0) {
	rc = execl("./resume", "resume", "-p", dirname, "--pthread", "../eglibc-2.15/prefix/lib", attach_offset, NULL);
	fprintf (stderr, "execl of resume failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    } 
    
    do {
	// Wait until we can attach pin
	rc = get_attach_status (fd, cpid);
    } while (rc <= 0);

    mpid = fork();
    if (mpid == 0) {
	const char* args[256];
	u_int argcnt = 0;

	args[argcnt++] = "pin";
	args[argcnt++] = "-pid";
	sprintf (cpids, "%d", cpid);
	args[argcnt++] = cpids;
        if (attach_gdb) {
            args[argcnt++] = "-pause_tool";
            args[argcnt++] = "15";
        }
	args[argcnt++] = "-t";
	args[argcnt++] = pintool;
	for (i = args_index; i < argc; i++) {
	    args[argcnt++] = argv[i];
	}
	args[argcnt++] = NULL;
	rc = execv ("../../pin/pin", (char **) args);
	fprintf (stderr, "execv of pin tool failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    rc = wait_for_replay_group(fd, cpid);
    rc = waitpid (cpid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
    }

    return 0;
}
