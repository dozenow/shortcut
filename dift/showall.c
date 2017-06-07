#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "taint_interface/taint.h"
#include "taint_interface/taint_creation.h"
#include "xray_token.h"
#include "maputil.h"
#include "uthash.h"
#include "taint_nw.h"
#include "bitmap.h"

#define MAX_INPUT_SYSCALLS 128

//TODO: a mix use of int and long for buffer size/bitmap size/file size

struct read_syscall { 
	int pid;           
	long index;    //syscall index
	bitmap* map;    //location of buffer that affects the control flow
	UT_hash_handle hh;
};
struct read_syscall* sys_reads = NULL;  //this is a hash list: it contains all read syscalls we care about
//for each read syscall we checked, we maintain the start location of the read buffer that affects the control flow as well as the end location
struct read_syscall_key { 
	int pid;
	long index;
};

struct range { 
	long start;
	long end;
};

static inline void change_read_syscall_boundary (int pid, long index, long pos) {
	struct read_syscall_key lookup_key;
	struct read_syscall* entry = NULL;

	memset (&lookup_key, 0, sizeof(struct read_syscall_key));
	lookup_key.pid = pid;
	lookup_key.index = index;
	HASH_FIND (hh, sys_reads, &lookup_key.pid, sizeof(struct read_syscall_key), entry);
	if (entry == NULL) {
		//add it 
		entry = (struct read_syscall*) malloc (sizeof(struct read_syscall));
		if (entry == NULL) {
			fprintf (stderr, "cannot allocate memory.\n");
			exit (EXIT_FAILURE);
		}
		memset (entry, 0, sizeof(struct read_syscall));
		entry->pid = pid;
		entry->index = index;
		entry->map = bitmap_allocate(pos*2);
		HASH_ADD (hh, sys_reads, pid, sizeof(struct read_syscall_key), entry);
	}
	bitmap_set (entry->map, pos);
}

int sys_read_sort (void *first, void *second) { 
	struct read_syscall_key* a = (struct read_syscall_key*) first;
	struct read_syscall_key* b = (struct read_syscall_key*) second;
	if (a->pid != b->pid) return a->pid - b->pid;
	else return a->index - b->index;
}

int blur = 0;  //sometimes, the interval between the previous range and the next range is pretty small, so we may ignore some small spaces between ranges

//#define BLUR

//first range starts at 1
void scan_bitmap_find_range (bitmap* map, int fd) { 
	long i = 0;
	long start = 0;
	long end = 0;
#ifdef BLUR
	int blur_step = 0;
#endif
	for (; i<map->bits; ++i) { 
		if (bitmap_read (map, i)) { 
			if (!start) start = i;
		} else { 
			if (start) {
				end = i-1;
#ifdef BLUR
				if (blur > 0){
					//wait before we output
					++ blur_step;
					if (blur_step == blur) { 
						end -= blur - 1;
						printf ("      range: %ld %ld\n", start, end);
						start = 0;
						end = 0;
						blur_step = 0;
					} 
				} else { 
					printf ("      range: %ld %ld\n", start, end);
					start = 0;
					end = 0;
					blur_step = 0;
				}
#else
				printf ("      range: %ld %ld\n", start, end);
				start = 0;
				end = 0;
#endif
			}
		}
	}
}

int main (int argc, char* argv[])
{
    char tokfile[80], outfile[80], mergefile[80];
    int tfd, ofd, mfd;
    int sys_reads_analysis = 0;
    u_long tdatasize, odatasize, mdatasize, tmapsize, omapsize, mmapsize;
    char* tbuf, *obuf, *mbuf, *dir, *pid = NULL, opt;
    u_long* mptr;
    u_long buf_size, i;
    long rc;
    u_long ocnt = 0;
    char* output_dir = NULL;

    while (1) 
    {
	opt = getopt(argc, argv, "p:r:");
	if (opt == -1) 
	{
	    if(optind < argc) 
	    {
		dir = argv[optind];
		break;
	    }
	    else 
	    { 
		fprintf (stderr, "format: showall <dirno> [-p pid] [-r output_dir]\n");
		return -1;
	    }
	}
	switch(opt) 
	{
	case 'p': 
	    pid = optarg;
	    break;
	case 'r':
	    sys_reads_analysis = 1;
	    output_dir = optarg;
	    break;
	default:
	    fprintf(stderr, "Unrecognized option\n");
	    break;
	}
    }
    if(pid == NULL)
    { 
	sprintf (tokfile, "%s/tokens", dir);
	sprintf (outfile, "%s/dataflow.result", dir);
	sprintf (mergefile, "%s/mergeout", dir);
    }
    else 
    {
	sprintf (tokfile, "%s/tokens.%s", dir, pid);
	sprintf (outfile, "%s/dataflow.result.%s", dir, pid);
	sprintf (mergefile, "%s/mergeout.%s", dir, pid);
    }
    rc = map_file (tokfile, &tfd, &tdatasize, &tmapsize, &tbuf);
    if (rc < 0) return rc;
    rc = map_file (outfile, &ofd, &odatasize, &omapsize, &obuf);
    if (rc < 0) return rc;
    rc = map_file (mergefile, &mfd, &mdatasize, &mmapsize, &mbuf);
    if (rc < 0) return rc;

    mptr = (u_long *) mbuf;
    while ((u_long) mptr < (u_long) mbuf + mdatasize) {
	struct taint_creation_info* tci = (struct taint_creation_info *) obuf;
	u_long syscall = tci->syscall_cnt;
	int record_pid = tci->record_pid;

	obuf += sizeof(struct taint_creation_info);
	obuf += sizeof(u_long); 
	buf_size = *((u_long *) obuf);
	obuf += sizeof(u_long);
	for (i = 0; i < buf_size; i++) {
	    do {
		if (*mptr) {
		    u_long tokval = *mptr;

		    struct token* ptok = (struct token *) tbuf;
		    while (tokval > ptok->size) {
			tokval -= ptok->size;
			ptok++;
		    } 

		    if (sys_reads_analysis == 0 || (sys_reads_analysis == 1 && (ptok->type == TOK_READ || ptok->type == TOK_RECV || ptok->type == TOK_RECVMSG || ptok->type == TOK_PREAD))) { 
			    //if (sys_reads_analysis == 0) { 
				    printf ("output pid/syscall %u/%lu offset %lu (%lx) type %d addr %x fileno %d <- (%lx)", record_pid, syscall, i, ocnt, tci->type, tci->data, tci->fileno, *mptr);
				    printf ("input pid/syscall %d/%d offset %lu type %d\n", ptok->record_pid, ptok->syscall_cnt, tokval, ptok->type);
			    //}
			    if (sys_reads_analysis == 1) change_read_syscall_boundary (ptok->record_pid, ptok->syscall_cnt, tokval);
		    }
		    mptr++;
		} else {
		    mptr++;
		    break;
		}
	    } while (1);
	    obuf += sizeof(u_long) + sizeof(taint_t);
	    ocnt++;
	}
    }
    if (sys_reads_analysis) { 
	    char outputfilename[256];
	    int fd = -1;
	    printf ("##### sys_read/pread analysis#### (index starts with 1)\n");
	    //sort
	    HASH_SORT (sys_reads, sys_read_sort); 
	    struct read_syscall * s;
	    int cur_pid = -1;
	    for (s = sys_reads; s!= NULL; s=s->hh.next) { 
		    printf ("pid %d, index %ld\n", s->pid, s->index); 
		    if (cur_pid != s->pid) {
			    cur_pid = s->pid;
			    if (fd > 0) close (fd);
			    memset (outputfilename, 0, 256);
			    sprintf (outputfilename, "%s/%d\n", output_dir, cur_pid);
			    fd = open (outputfilename, O_RDWR | O_TRUNC | O_CREAT, 0644);
			    if (fd < 0) {
				    fprintf (stderr, "cannot open output file %s\n", outputfilename);
				    exit(EXIT_FAILURE);
			    }
		    }
		    scan_bitmap_find_range (s->map, fd);
	    }
    }

    return 0;
    
}

