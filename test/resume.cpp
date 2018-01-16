// A simple program to resume a recorded execution
#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <pthread.h> 
#include <dirent.h>
#include <dlfcn.h>

#include "recheck.h"
#include "util.h"

#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <vector>
#include <map>
#include <list>

using namespace std;

#define MAX_THREADS 128 //arbitrary... but works

//#define LPRINT
//#define LTIMING


void print_help(const char *program) {
    fprintf (stderr, "format: %s <logdir> [-p] [-f] [-m] [-g] [-r] [--pthread libdir] [--attach_offset=pid,sysnum] [--ckpt_at=replay_clock_val]\n"
                     "                    [--recover_at=replay_clock_val] [--recover_pid=daemon_pid] [--from_ckpt=replay_clock-val]\n"
	             "                    [--fake_calls=c1,c2...] \n", program);
}
struct ckpt_data { 
    int fd;
    int attach_pin;
    int attach_gdb; 
    int follow_splits;
    int save_mmap;   
    char logdir[4096];
    char libdir[4096];
    char filename[4096];
    char uniqueid[4096];       
    loff_t attach_index; 
    int attach_pid; 
    u_long nfake_calls; 
    u_long *fake_calls;
    int ckpt_pos; 
    int go_live;
    char* slice_filename;
    char* recheck_filename;
};

//used to read in the header from the ckpt file
struct ckpt_hdr{ 
    u_long proc_count;
    unsigned long long rg_id;
    int clock;
};

//used to read in the processes from the header of the ckpt file
struct process_data { 
    int ppid;
    int rpid;
    int is_thread;
    int main_thread;
    int ckpt_pos; 
};

class Ckpt_Proc {            
public: 
    int pid;
    int main_thread;
    int ckpt_pos;
    std::vector<Ckpt_Proc *> threads;
    std::vector<Ckpt_Proc *> children;
    Ckpt_Proc(int p) { pid = p;};
};

std::map<int, Ckpt_Proc*> ckpt_procs; 
int generated_mm_region_fd = 0;

Ckpt_Proc * get_ckpt_proc(int pid) {
    std::map<int, Ckpt_Proc*>::iterator i =  ckpt_procs.find(pid);
    if (i == ckpt_procs.end()) { 
	ckpt_procs[pid] = new Ckpt_Proc(pid);
    }
    return ckpt_procs[pid];   
}


void *start_thread(void *td) {
    int rc;
    struct ckpt_data *cd = (struct ckpt_data *) td;
    
    rc = resume_proc_after_ckpt (cd->fd, cd->logdir, cd->filename, cd->uniqueid, cd->ckpt_pos, cd->go_live, cd->slice_filename, cd->recheck_filename);
    if (rc < 0) {
	perror ("resume proc after ckpt");
	exit (-1);
    }
    return NULL;
}

void *start_main_thread(void *td) {
    int rc;
    struct ckpt_data *cd = (struct ckpt_data *) td;
    
    rc = resume_after_ckpt (cd->fd, cd->attach_pin, cd->attach_gdb, cd->follow_splits, 
			    cd->save_mmap, cd->logdir, cd->libdir, cd->filename, cd->uniqueid,
			    cd->attach_index, cd->attach_pid, cd->nfake_calls, cd->fake_calls, 
			    cd->go_live, cd->slice_filename, cd->recheck_filename);

    if (rc < 0) {
	perror ("resume after ckpt");
	exit (-1);
    }
    return NULL;
}


int parse_process_map(int pcount, int fd) { 
    int i, copyed, first_proc = -1;
    struct process_data curr_pdata; 
    Ckpt_Proc *parent, *current; 

    for (i = 0; i < pcount; ++i) { 
	copyed = read(fd,&curr_pdata, sizeof(curr_pdata));
	if (copyed != sizeof(curr_pdata)) { 
	    perror("couldn't read curr_pdata");
	    return copyed; 
	}
	
	current = get_ckpt_proc(curr_pdata.rpid); 
	current->main_thread = curr_pdata.main_thread;
	current->ckpt_pos = curr_pdata.ckpt_pos;

	if (curr_pdata.ppid == -1) { 
	    first_proc = curr_pdata.rpid;	    
	}
	else { 
	    parent = get_ckpt_proc(curr_pdata.ppid);
	    if (curr_pdata.is_thread) { 
		parent->threads.push_back(current);
	    }
	    else { 
		parent->children.push_back(current);
	    }	    
	}       
    }
    return first_proc;
}

int recheck_all_procs(Ckpt_Proc *current, struct ckpt_data *cd, pthread_t *thread, u_long &i) {

    struct ckpt_data *thread_cd; 
    int rc = 0;

    for (auto t : current->threads) { 
	if (t->main_thread) { 
	    rc = pthread_create(&thread[i++], NULL, start_main_thread,(void *)cd);
	    
	    if (rc) { 
		printf("hmm... what rc is %d\n",rc);
		exit(-1);		
	    }

	}
	else { 
	    thread_cd = (struct ckpt_data *) malloc(sizeof(struct ckpt_data)); 
	    memcpy(thread_cd, cd, sizeof(struct ckpt_data));
	    thread_cd->ckpt_pos = t->ckpt_pos;
	    rc = pthread_create(&thread[i++], NULL, start_thread,(void *)thread_cd);
	    if (rc) { 
		printf("hmm... what rc is %d\n",rc);
		exit(-1);		
	    }

	}
    }
    for (auto c : current->children) {
	if (!fork()) { 
	    return recheck_all_procs(c, cd, thread, i);
	}
    }
    if (current->main_thread){ 
	rc = resume_after_ckpt (cd->fd, cd->attach_pin, cd->attach_gdb, cd->follow_splits, 
				cd->save_mmap, cd->logdir, cd->libdir, cd->filename, cd->uniqueid,
				cd->attach_index, cd->attach_pid, cd->nfake_calls, cd->fake_calls, cd->go_live, cd->slice_filename, //this is the prefix of the slice and recheck filename
				cd->recheck_filename);
	if (rc) { 
	    printf("hmm... what rc is %d\n",rc);
	    exit(-1);		
	}

    }
    else { 
	rc = resume_proc_after_ckpt (cd->fd, cd->logdir, cd->filename, cd->uniqueid, current->ckpt_pos, cd->go_live, cd->slice_filename, cd->recheck_filename); //again this is the prefix for the filenames
	if (rc) { 
	    printf("hmm... what rc is %d\n",rc);
	    exit(-1);		
	}	
    }
    return 0;
}


int load_slice_lib (char* dirname, u_long from_ckpt, char* slicelib, char* pthread_dir)
{
    char filename[256], mapname[256], procname[256], buf[256];

    list<pair<u_long,u_long>> maps;
    sprintf (procname, "/proc/%d/maps", getpid());
    FILE* file = fopen(procname, "r");
    while (!feof(file)) {
	if (fgets (buf+2, sizeof(buf)-2, file)) {
	    buf[0] = '0'; buf[1] = 'x'; buf[10] = '\0';
	    u_long start = strtold(buf, NULL);
	    buf[9] = '0'; buf[10] = 'x'; buf[19] = '\0';
	    u_long end = strtold(buf+9, NULL);
	    if (!maps.empty() && maps.back().second == start) {
		maps.back().second = end;
	    } else {
		maps.push_back(make_pair(start,end));
	    }
	}
    }
    fclose(file);

#ifdef LPRINT
    for (auto t : maps) {
	printf ("%lx %lx\n", t.first, t.second);
    }
    printf ("\n\n\n");
#endif

    sprintf (filename, "ckpt.%ld.ckpt_mmap.", from_ckpt);
    u_long len = strlen(filename);
    struct stat st;
    DIR* dir = NULL;
    struct dirent* pent = NULL;

    if (!generated_mm_region_fd) { 
        dir = opendir(dirname);

        if (dir == NULL) {
            fprintf (stderr, "Cannot open directory %s\n", dirname);
            return -1;
        }

        pent = readdir(dir);
    }
    while (1) {
	if (generated_mm_region_fd > 0 || !strncmp(pent->d_name, filename, strlen(filename))) {
            u_long start = 0;
            u_long end = 0;
            int rc = 0;
            if (generated_mm_region_fd) { 
                //get the memory regions from memory region files
                rc = read (generated_mm_region_fd, &start, sizeof(start));
                if (rc != sizeof(start)) {
                    printf ("Already mmap all memory regions.\n");
                    break;
                }
                rc = read (generated_mm_region_fd, &end, sizeof(end));
                assert (rc == sizeof(end));
            } else { 
                //get the memory regions from checkpoint filenames
                sprintf (mapname, "%s/%s", dirname, pent->d_name);
                rc = stat(mapname, &st);
                if (rc < 0) {
                    fprintf (stderr, "Cannot stat %s\n", mapname);
                    return -1;
                }
                *(pent->d_name+len-2) = '0';
                *(pent->d_name+len-1) = 'x';
                start = strtold(pent->d_name+len-2, NULL);
                if (st.st_size == 0) st.st_size = 4096;
                end = start + st.st_size;
            }
#ifdef LPRINT
	    printf ("%lx %lx\n", start, end);
#endif
	    for (auto m : maps) {
again:
#ifdef LPRINT
		printf ("\tTrying map from %lx to %lx\n", m.first, m.second);
#endif
		if (m.second <= start) {
		    /* Skip this region */
		} else if (m.first >= end) {
#ifdef LPRINT		    
		    printf ("entirely in unallocated region\n");
#endif
		    void* p = mmap ((void *) start, end-start, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		    if ((u_long) p != start) {
			fprintf (stderr, "Tried to map at %lx size %lx, got %p\n", end-start, st.st_size, p);
			return -1;
		    }
		    break;
		} else if (m.first <= start) {
		    if (m.second >= end) {
#ifdef LPRINT
			printf ("entirely in allocated region - no work to do\n");
#endif
			break;
		    } else {
#ifdef LPRINT
			printf ("starts with allocated region, start at %lx\n", m.second);

#endif
			start = m.second;
			goto again;
		    }
		} else {
#ifdef LPRINT
		    printf ("starts with unallocated region of size %lx\n", m.first-start);
#endif
		    if (end == 0xc0000000) {
#ifdef LPRINT			
			printf ("Stack region should grow from %lx to %lx\n", start, m.first);
#endif
			for (u_long stack_val = m.first-0x1000; stack_val >= start; stack_val -= 0x1000) {
			    *((int *) stack_val) = 0; // This implicitly grows the stack (store to region below current page)
			} 
		    } else {
			void* p = mmap ((void *) start, m.first-start, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if ((u_long) p != start) {
			    fprintf (stderr, "Tried to map at %lx, got %p\n", start, p);
			    return -1;
			}
			start = m.first;
			goto again;
		    }
		}
	    }
	}
        if (generated_mm_region_fd) { 
        } else { 
            pent = readdir(dir);
            if (!pent) break;
        }
    }
	
    if (!generated_mm_region_fd) closedir(dir);

#ifdef LPRINT
    printf ("Before libc\n");
    file = fopen(procname, "r");
    while (!feof(file)) {
	if (fgets (buf, sizeof(buf), file)) {
	    printf ("%s", buf);
	}
    }
    fclose(file);
    printf ("\n\n\n");
#endif

    // Let's load libc first
    void* hndl = NULL;

    if (pthread_dir) {
	    char libc_filename[256];
	    sprintf (libc_filename, "%s/libc-2.15.so", pthread_dir);
	    hndl = dlopen (libc_filename, RTLD_NOW);
    } else  {
    	hndl = dlopen ("../eglibc-2.15/prefix/lib/libc-2.15.so", RTLD_NOW);
    }
    if (hndl == NULL) {
	fprintf (stderr, "dlopen libc %s", dlerror ());
	exit (0);
    }

#ifdef LPRINT
    printf ("After libc\n");
    file = fopen(procname, "r");
    while (!feof(file)) {
	if (fgets (buf, sizeof(buf), file)) {
	    printf ("%s", buf);
	}
    }
    fclose(file);
    printf ("\n\n\n");
#endif

    // Now try and load the library and get the start fn address
    for (map<int, Ckpt_Proc*>::iterator iter = ckpt_procs.begin(); iter != ckpt_procs.end(); ++iter) {
        char slicename[256];
        snprintf (slicename, 256, "%s.%d.so", slicelib, iter->first);
        hndl = dlopen (slicename, RTLD_NOW);
        if (hndl == NULL) {
            fprintf (stderr, "slice %s dlopen failed: %s\n", slicename, dlerror());
            exit (0);
        }
#ifdef LPRINT
        printf ("hndl: %p\n", hndl);
#endif

        void* pfn = dlsym (hndl, "_start");
        if (pfn == NULL) {
            perror ("dlsym");
        }

#ifdef LPRINT
        printf ("pfn: %p\n", pfn);
        file = fopen(procname, "r");
        while (!feof(file)) {
            if (fgets (buf, sizeof(buf), file)) {
                printf ("%s", buf);
            }
        }
        fclose(file);
#endif
    }

    return 0;
}


int main (int argc, char* argv[])
{
	int fd, cfd, rc, attach_pin = 0, attach_gdb = 0;
	loff_t attach_index = -1;
	int attach_pid = -1;
	char* libdir = NULL;
	char* pthread_dir = NULL;
	pid_t pid;
	char ldpath[4096];
	int base;
	int follow_splits = 0;
	int save_mmap = 0;
	int ckpt_at = 0;
	int ckpt_memory_only = 0;
	int recover_at = 0;
	int recover_pid = 0;
	int from_ckpt = 0;
	int record_timing = 0;
	int first_proc = -1;
	char filename[4096], pathname[4096], uniqueid[4096];
	int go_live = 0;
	char* slice_filename = NULL;
	char* recheck_filename = NULL;
	struct timeval tv;

	u_long i = 0;
	u_long nfake_calls = 0;
	u_long* fake_calls = NULL;

	struct ckpt_hdr hdr;
	struct ckpt_data cd; 
	pthread_t thread[MAX_THREADS];
        pid = getpid();

	//fprintf (stderr, "resume starts: %ld.%ld\n", tv.tv_sec, tv.tv_usec);

	sprintf(uniqueid,"%d",pid); //use the parent's pid as the uniqueid
#ifdef LTIMING
	gettimeofday (&tv, NULL);
	fprintf (stderr, "Resume start %d, %ld.%06ld\n", pid, tv.tv_sec, tv.tv_usec);
#endif


	struct option long_options[] = {
		{"pthread", required_argument, 0, 0},
		{"attach_pin_later", optional_argument, 0, 0},
		{"attach_offset", optional_argument, 0, 0},
		{"ckpt_at", required_argument, 0, 0},
		{"recover_at", required_argument, 0, 0},
		{"recover_pid", required_argument, 0, 0},
		{"from_ckpt", required_argument, 0, 0},
		{"fake_calls", required_argument, 0, 0},
		{"slice", required_argument, 0, 0},
		{"recheck", required_argument, 0, 0},
		{0, 0, 0, 0}
	};

	while (1) {
		char opt;
		int option_index = 0;

		opt = getopt_long(argc, argv, "fpmhgtlr", long_options, &option_index);
		//printf("getopt_long returns %c (%d)\n", opt, opt);

		if (opt == -1) {
			break;
		}

		switch(opt) {
		case 0:
			switch(option_index) {
				/* --pthread */
			case 0: 
				libdir = optarg;
				pthread_dir = optarg;
				break;
				/* --attach_offset or --attach_pin_later */
			case 1: case 2:
				if (sscanf(optarg, "%d,%lld", &attach_pid, &attach_index)
				    != 2) {
					fprintf(stderr, "ERROR: expected format: --attach_offset <pid>,<sysnum>\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 3:
				ckpt_at = atoi(optarg);
				break;
			case 4:
				recover_at = atoi(optarg);
				break;
			case 5:
				recover_pid = atoi(optarg);
				break;
			case 6:
				from_ckpt = atoi(optarg);
				break;	
			case 7:
			{
				char* p, *last;
				u_long i = 0;

				nfake_calls = 1;
				for (p = optarg; *p != '\0'; p++) {
					if (*p == ',') nfake_calls++;
				}
				fake_calls = (u_long *)malloc(nfake_calls*sizeof(u_long));
				if (fake_calls == NULL) {
					fprintf (stderr, "Cannot allocate fake calls\n");
					return -1;
				}
				last = optarg;
				for (p = optarg; *p != '\0'; p++) {
					if (*p == ',') {
						*p++ = '\0';
						fake_calls[i++] = atoi(last);
						last = p;
					}
				}
				fake_calls[i++] = atoi(last);
				break;
			}
			case 8:
			{
				slice_filename = optarg;
                                perror ("Deprecated arguments! Now always using the default slice filenames in replay_logdb\n");
				break;
			}
			case 9:
			{
				recheck_filename = optarg;
                                perror ("Deprecated arguments! Now always using the default recheck filenames in replay_logdb\n");
				break;
			}
			default:
				assert(0);
			}
			break;
		case 'm':
			//printf("save_mmap is on");
			save_mmap = 1;
			break;
		case 'f':
			//printf("follow_splits is on");
			follow_splits = 1;
			break;
		case 'p':
			//printf("attach_pin is on\n");
			attach_pin = 1;
			
			break;
		case 'h':
			print_help(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'g':
			//printf("attach_gdb is on\n");
			attach_gdb = 1;
			break;
		case 't':
			//printf("record timing is on\n");
			record_timing = 1;
			break;
		case 'l':
			go_live = 1;
			break;
		case 'r':
			//use generated memory region information
			generated_mm_region_fd = 1;
			break;
		default:
			fprintf(stderr, "Unrecognized option\n");
			print_help(argv[0]);
			exit(EXIT_FAILURE);
			break;
		}
	}

	base = optind;

	if (argc-base != 1) {
		fprintf(stderr, "Invalid non-arg arguments!\n");
		print_help(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (attach_pin && save_mmap) {
		fprintf(stderr, "Attaching pin (-p) and saving mmaps (-m) shouldn't both be enabled!\n");
		exit(EXIT_FAILURE);
	}

	if (attach_pin && attach_gdb) {
		fprintf(stderr, "Cannot attach both pin (-p) and gdb (-g).\n");
		exit(EXIT_FAILURE);
	}

	if (ckpt_at && recover_at) {
	    fprintf (stderr, "Cannot set both ckpt_at and revoer_at\n");
	    exit (EXIT_FAILURE);
	}

	if (recover_at) {
	    ckpt_at = recover_at; 
	    ckpt_memory_only = 1;
	}

	if (libdir) {
		strcpy(ldpath, libdir);
		strcat(ldpath, "/ld-linux.so.2");
		libdir = ldpath;
	}
	
	fd = open ("/dev/spec0", O_RDWR);
	if (fd < 0) {
		perror("open /dev/spec0");
		exit(EXIT_FAILURE);
	}
        rc = dup2 (fd, 1019);
        assert (rc > 0);
        close (fd);
        fd = 1019; //TODO: we need a better open syscall to avoid unclosed fd

	if (from_ckpt > 0) {
            char generated_mm_filename[4096];
	    
	    sprintf (filename, "ckpt.%d", from_ckpt);
	    sprintf (pathname, "%s/ckpt.%d", argv[base], from_ckpt);
	    if (generated_mm_region_fd) {
                sprintf (generated_mm_filename, "%s/ckpt.%d.mm", argv[base], from_ckpt);
                generated_mm_region_fd = open (generated_mm_filename, O_RDONLY);
                if (generated_mm_region_fd < 0) { 
                    perror ("open generated memory region file");
                    return generated_mm_region_fd;
                }
                //TODO: fix this
                rc = dup2 (generated_mm_region_fd, 1011);
                assert (rc > 0);
                close (generated_mm_region_fd);
                generated_mm_region_fd = 1011;
            }
	    cfd = open (pathname, O_RDONLY);
	    if (cfd < 0) {
		perror ("open checkpoint file");
		return cfd;
	    }
	    rc = read (cfd, &hdr, sizeof(hdr)); 
	    if (rc != sizeof(hdr)) {
		perror ("read proc count");
		return rc;
	    }
	    if (hdr.proc_count > MAX_THREADS) { 
		perror("we need more threads!");
		return -1;
	    }
            if (hdr.proc_count > 1) {
                printf ("Resuming a multi-threaded program, loading slices with default filenames\n");
            }
	    
	    first_proc = parse_process_map(hdr.proc_count, cfd);
	    
	    close(cfd);
	    
	    if (go_live) {
		// Supply default slice filename and recheck filename if not specified
		if (slice_filename == NULL) {
		    slice_filename = new char[256];
                    sprintf (slice_filename, "%s/exslice", argv[base]); //this is only the prefix for the filename
		}
		if (recheck_filename == NULL) {
		    recheck_filename = new char[256];
		    sprintf (recheck_filename, "%s/recheck", argv[base]);
		}
	    }

	    if (slice_filename) {
		load_slice_lib (argv[base], from_ckpt, slice_filename, pthread_dir);
	    }
#ifdef LTIMING
	gettimeofday (&tv, NULL);
	fprintf (stderr, "slice loaded %d, %ld.%06ld\n", pid, tv.tv_sec, tv.tv_usec);
#endif
	    
	    cd.fd = fd;
	    cd.attach_pin = attach_pin;
	    cd.attach_gdb = attach_gdb;
	    cd.follow_splits = follow_splits;
	    cd.save_mmap = save_mmap;		    
	    strcpy(cd.logdir, argv[base]);
	    strcpy(cd.libdir, libdir);
	    strcpy(cd.filename, filename);
	    strcpy(cd.uniqueid,uniqueid);
	    cd.attach_index = attach_index;
	    cd.attach_pid = attach_pid;
	    cd.nfake_calls = nfake_calls;
	    cd.fake_calls = fake_calls;
	    cd.go_live = go_live;
	    cd.slice_filename = slice_filename;
	    cd.recheck_filename = recheck_filename;
	    recheck_all_procs(get_ckpt_proc(first_proc), &cd, thread, i);
	} else {
	    rc = resume_with_ckpt (fd, attach_pin, attach_gdb, follow_splits, save_mmap, argv[base], libdir,
				   attach_index, attach_pid, ckpt_at, ckpt_memory_only, recover_pid, 
				   record_timing, nfake_calls, fake_calls);
	}
	if (rc < 0) {
		perror("resume");
		return -1;
	}
	fprintf(stderr, "resume should not return\n");
	return -1;
}

