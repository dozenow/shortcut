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

#define MAX_PROCESSES  2
#define BUFFER_SIZE 1024

//TODO: Currently, we only use data flow tool, probably should also enable the index tool in the future
int main (int argc, char* argv[]) 
{
    struct timeval tv_start, tv_attach, tv_tool_done, tv_done;
    char cpids[80], tmpdir[80], lscmd[80];
    char* lscmd_output;
    char* dirname;
    char cache_dir[BUFFER_SIZE] = "";

    pid_t cpid, mpid, ppid;
    int fd, rc, status, filter_inet = 0;
    u_long filter_output_after = 0;
    char* stop_at = NULL;
    char* ckpt_clock = NULL;
    char* filter_output_after_str = NULL;
    char* filter_partfile = NULL;
    char* filter_byterange = NULL;
    char* filter_syscall = NULL;
    char* filter_file_input = NULL;
    int next_child = 0, i;
    size_t n = BUFFER_SIZE;
    FILE* fp; 
    int instruction_only = 0;
    char* group_dir = NULL;
    int attach_gdb = 0;
    int run_data_tool = 0;
    
    int post_process_pids[MAX_PROCESSES];

    if (argc < 2) {
	fprintf (stderr, "format: seqtt <replay dir> [filter syscall] [--cache_dir cache_dir] [-filter_inet] [-filter_partfile xxx] [-filter_byterange xxx] [-filter_syscall xxx] [-filter_output_after clock] [-print_instruction] [-ckpt_clock clock] [-group_dir dir] [-attach_gdb] [-run_data_tool] [-filter_file_input filename]\n");
	//byterange: buffer starts with 0, start: inclusive, end: exclusive
	return -1;
    }

    dirname = argv[1];
    if (argc > 2) {
	int index = 2;
	while (index < argc) { 
	    //if the current argument is cache_dir, then save the cache_dir
	    if(!strncmp(argv[index],"--cache_dir",BUFFER_SIZE)) {
		strncpy(cache_dir,argv[index + 1],BUFFER_SIZE); 
		index++;
	    } else if (!strncmp(argv[index],"-print_instruction",BUFFER_SIZE)) {
		    instruction_only = 1;
		    ++index;
	    } else if (!strncmp(argv[index],"-stop_at",BUFFER_SIZE)) {
		stop_at = argv[index+1];
		index += 2;
	    } else if (!strncmp(argv[index],"-ckpt_clock",BUFFER_SIZE)) {
		ckpt_clock = argv[index+1];
		index += 2;
	    } else if (!strncmp(argv[index],"-filter_inet",BUFFER_SIZE)) {
		filter_inet = 1;
		index++;
	    } else if (!strncmp(argv[index],"-filter_partfile",BUFFER_SIZE)) {
		filter_partfile = argv[index+1];
		index += 2;
	    } else if (!strncmp(argv[index],"-filter_byterange",BUFFER_SIZE)) {
		filter_byterange = argv[index+1];
		index += 2;
	    } else if (!strncmp(argv[index],"-filter_syscall",BUFFER_SIZE)) {
		filter_syscall = argv[index+1];
		index += 2;
	    } else if (!strncmp(argv[index],"-filter_output_after",BUFFER_SIZE)) {
		filter_output_after_str = argv[index+1];
		filter_output_after = atoi(argv[index+1]);
		index += 2;
	    } else if (!strncmp(argv[index], "-group_dir", BUFFER_SIZE)) { 
		group_dir = argv[index + 1];
		index += 2;
	    } else if (!strncmp(argv[index], "-attach_gdb", BUFFER_SIZE)) { 
		    attach_gdb = 1;
		    index ++;
	    } else if (!strncmp(argv[index], "-run_data_tool", BUFFER_SIZE)) {
		    run_data_tool = 1;
		    ++index;
	    } else if (!strncmp (argv[index], "-filter_file_input", BUFFER_SIZE)) {
		    filter_file_input = argv[index + 1];
		    index += 2;
	    } else {
		fprintf (stderr, "format: seqtt <replay dir> [filter syscall] [--cache_dir cache_dir] [-filter_inet] [-filter_partfile xxx] [-filter_byterange xxx] [-filter_syscall xxx] [-filter_output_after clock] [-print_instruction][-stop_at][-ckpt_clock] [-attach_gdb] [-run_data_tool] [-filter_file_input filename]\n");
		return -1;
	    }
	}
    }


    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror("open /dev/spec0");
	return fd;
    }

    gettimeofday (&tv_start, NULL);
    cpid = fork ();
    if (cpid == 0) {
	if(strncmp(cache_dir,"",BUFFER_SIZE)) { 
	    rc = execl("./resume", "resume", "-p", dirname, "--pthread", "../eglibc-2.15/prefix/lib", "--cache_dir",cache_dir,NULL);
	}
	else {
	    rc = execl("./resume", "resume", "-p", dirname, "--pthread", "../eglibc-2.15/prefix/lib", NULL);
	}
	fprintf (stderr, "execl of resume failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    } 
    printf ("resume called.\n");
    
    do {
	// Wait until we can attach pin
	rc = get_attach_status (fd, cpid);
    } while (rc <= 0);

    printf ("start to attach pin.\n");
    
    gettimeofday (&tv_attach, NULL);

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
	if (instruction_only) 
		args[argcnt++] = "../pin_tools/obj-ia32/print_instructions.so";
	else {
		if (run_data_tool)//default is to run the index tool
			args[argcnt++] = "../dift/obj-ia32/linkage_data.so";
		else 
			args[argcnt++] = "../dift/obj-ia32/linkage_offset.so";
	}
	if (filter_output_after) {
	    args[argcnt++] = "-ofb";
	    args[argcnt++] = filter_output_after_str;
	} 
	if (filter_inet) {
	    args[argcnt++] = "-i";
	    args[argcnt++] = "-f";
	    args[argcnt++] = "inetsocket";
	} else if (filter_partfile) {
	    args[argcnt++] = "-i";
	    args[argcnt++] = "-e";
	    args[argcnt++] = filter_partfile;
	} else if (filter_byterange) {
	    args[argcnt++] = "-i";
	    args[argcnt++] = "-b";
	    args[argcnt++] = filter_byterange;
        } else if (filter_syscall) { 
            args[argcnt++] = "-i";
            args[argcnt++] = "-s";
            args[argcnt++] = filter_syscall;
	} else if (filter_file_input) { 
            args[argcnt++] = "-i";
            args[argcnt++] = "-rf";
            args[argcnt++] = filter_file_input;
	    fprintf (stderr, "filter_file_input: %s\n", filter_file_input);
	}
	if (stop_at) {
	    args[argcnt++] = "-l";
	    args[argcnt++] = stop_at;
	}
	if (ckpt_clock) {
	    args[argcnt++] = "-ckpt_clock";
	    args[argcnt++] = ckpt_clock;
	}
	if (group_dir) { 
		args[argcnt++] = "-group_dir";
		args[argcnt++] = group_dir;
	}
	args[argcnt++] = NULL;
	rc = execv ("../../pin/pin", (char **) args);
	fprintf (stderr, "execv of pin tool failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    // Wait for cpid to complete
    printf ("waiting for finishing, fd %d, cpid %d\n", fd, cpid);

    rc = wait_for_replay_group(fd, cpid);
    printf ("waitpid starts.\n");
    rc = waitpid (cpid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
    }

    gettimeofday (&tv_tool_done, NULL);

    // Now post-process the results
    //do some magic to get all of the underling's pids. 
    
    printf("DIFT finished\n");
    sprintf(tmpdir, "/tmp/%d",cpid);
    if (group_dir)
    	sprintf(lscmd, "/bin/ls %s/dataflow.result*", group_dir);
    else
    	sprintf(lscmd, "/bin/ls %s/dataflow.result*", tmpdir);
    fp = popen(lscmd, "r");
    if(fp == NULL) { 
	fprintf(stderr, "popen failed: errno %d", errno);
	return -1;
    }

    lscmd_output = malloc(n); 
    while((rc = getline(&lscmd_output, &n, fp)) > 0) 
    { 
	char* pid;
	//the output will be like /tmp/%d/dataflow.results.%d all we want is the last %d
//	fprintf(stderr,"line lscmd_output %s", lscmd_output);
	strtok(lscmd_output, "."); 
	strtok(NULL, "."); 
	pid = strtok(NULL, "."); 
	if(pid == NULL) { 
	    continue;
	}

	pid = strtok(pid, "\n");

	post_process_pids[next_child] = fork(); 
	if (post_process_pids[next_child] == 0) {
	    if (group_dir)
		strcpy (tmpdir, group_dir);
	    else 
	    	sprintf(tmpdir, "/tmp/%d",cpid);
	    printf ("tmpdir is %s, pid %s\n", tmpdir, pid);
	    rc = execl ("../dift/obj-ia32/postprocess_linkage", "postprocess_linkage", "-m", tmpdir, "-p", pid, NULL);
	    fprintf (stderr, "execl of postprocess_linkage failed, rc=%d, errno=%d\n", rc, errno);
	    return -1;
	}
	next_child+=1;
    }
    free(lscmd_output); 

    ppid = fork();
    if (ppid == 0) {
	    if (group_dir)
		strcpy (tmpdir, group_dir);
	    else 
		sprintf(tmpdir, "/tmp/%d",cpid);

	    rc = execl ("../dift/obj-ia32/postprocess_linkage", "postprocess_linkage", "-m", tmpdir, NULL);
	    fprintf (stderr, "execl of postprocess_linkage failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }


    // Wait for analysis to complete

    for(i = 0; i < next_child; i++) 
    { 
	rc = waitpid (post_process_pids[i], &status, 0);
	if (rc < 0) {
	    fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
	}
    }
    printf ("wait for %d\n", ppid);
    rc = waitpid (ppid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
    }


    gettimeofday (&tv_done, NULL);
    
    close (fd);

    printf ("Start time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("Attach time: %ld.%06ld\n", tv_attach.tv_sec, tv_attach.tv_usec);
    printf ("Tool done time: %ld.%06ld\n", tv_tool_done.tv_sec, tv_tool_done.tv_usec);
    printf ("End time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);

    long diff_usec = tv_done.tv_usec - tv_tool_done.tv_usec;  
    long carryover = 0;
    if(diff_usec < 0) { 
	carryover = -1;
	diff_usec = 1 - diff_usec;
    }    
    long diff_sec = tv_done.tv_sec - tv_tool_done.tv_sec - carryover; 

    printf ("Tool -> End: %ld.%06ld\n", diff_sec,diff_usec);

    diff_usec = tv_done.tv_usec - tv_start.tv_usec;  
    carryover = 0;
    if(diff_usec < 0) { 
	carryover = -1;
	diff_usec = 1 - diff_usec;
    }
    diff_sec = tv_done.tv_sec - tv_start.tv_sec - carryover; 

    printf ("Start -> End: %ld.%06ld\n", diff_sec,diff_usec);
    

    //need to unlink the shared memroy region... need to 'recreate' tmpdir b/c it was not done in the parent
//    sprintf (tmpdir, "/tmp/%d", cpid);
//    snprintf(shmemname, 256, "/node_nums_shm%s/node_nums", tmpdir);
//    for (i = 1; i < strlen(shmemname); i++) {
//	if (shmemname[i] == '/') shmemname[i] = '.';
//    }
//    shmemname[strlen(shmemname)-10] = '\0';
//    rc = shm_unlink (shmemname); 
//    if (rc < 0) perror ("shmem_unlink");

    return 0;
}
