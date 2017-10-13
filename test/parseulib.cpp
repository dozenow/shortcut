#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#define __user
#include "../linux-lts-quantal-3.5.0/include/linux/pthread_log.h"
#include "parseulib.h"

using namespace std;
struct ulog* parseulib_open (char* filename)
{
    int fd, rc;
    struct stat st;
    struct ulog* log = (struct ulog*) malloc (sizeof (struct ulog));
    rc = stat(filename, &st);
    if (rc < 0) {
        fprintf(stderr, "stat of %s failed with %d\n", filename, rc);
        return NULL;
    }

    fd = open (filename, O_RDONLY);
    if (fd < 0) {
        perror ("open log file\n");
        return NULL;
    }
    log->fd = fd;
    log->total_clock = 0;
    log->size = st.st_size;
    log->bytes_read = 0;
    log->clocks = new queue<u_long>();
    return log;
}

u_long parseulib_get_next_clock (struct ulog* log) 
{
    if (log == NULL) {
        fprintf(stderr, "cannot parse a NULL ulog\n");
        return 0;
    }
    if (log->clocks->empty()) { 
        if (log->bytes_read < log->size) {
            int fd = log->fd;
            int count = 0;
            int num_bytes;
            int new_errno;
            int rc = read (fd, &num_bytes, sizeof(int));
            if (rc != sizeof(int)) {
                perror("Could not read the count\n");
                return -1;
            }
            printf ("** reading %d bytes ***\n", num_bytes);
            log->bytes_read += rc;

            while (count < num_bytes) {
#ifdef USE_DEBUG_LOG
                struct pthread_log_data rec;
                rc = read (fd, &rec, sizeof(struct pthread_log_data));
                if (rc < 0) {
                    perror ("read log record\n");
                    return rc;
                }
                printf ("clock %lu type %lu check %lx retval %d (%x)\n", rec.clock, rec.type, rec.check, rec.retval, rec.retval);
                count += rc;
                log->bytes_read += rc;
                log->clocks->push (rec.clock);
#else
                u_long entry;
                long i;
                int skip, retval, fake_calls;

                rc = read (fd, &entry, sizeof(u_long));
                if (rc != sizeof(u_long)) {
                    perror ("read log record\n");
                    return rc;
                }
                count += rc;
                log->bytes_read += rc;
                printf ("   entry %lx usual recs %ld non-zero retval? %d errno change? %d fake calls? %d skip? %d\n", entry, (entry&CLOCK_MASK), !!(entry&NONZERO_RETVAL_FLAG), !!(entry&ERRNO_CHANGE_FLAG), !!(entry&FAKE_CALLS_FLAG), !!(entry&SKIPPED_CLOCK_FLAG));
                for (i = 0; i < (entry&CLOCK_MASK); i++) {
                    log->total_clock++;
                    printf ("clock %lu fake calls 0 retval 0\n", log->total_clock-1);
                    log->clocks->push (log->total_clock - 1);
                }
                if (entry&SKIPPED_CLOCK_FLAG) {
                    rc = read (fd, &skip, sizeof(int));
                    if (rc != sizeof(int)) {
                        perror ("read skip value\n");
                        return rc;
                    }
                    printf ("     skip %d records\n", skip);
                    count += rc;
                    log->bytes_read += rc;
                    log->total_clock += skip + 1;
                } else {
                    log->total_clock++;
                }
                if (entry&NONZERO_RETVAL_FLAG) {
                    rc = read (fd, &retval, sizeof(int));
                    if (rc != sizeof(int)) {
                        perror ("read retval value\n");
                        return rc;
                    }
                    count += rc;
                    log->bytes_read += rc;
                } else {
                    retval = 0;
                }
                if (entry&ERRNO_CHANGE_FLAG) {
                    rc = read (fd, &new_errno, sizeof(int));
                    if (rc != sizeof(int)) {
                        perror ("read retval value\n");
                        return rc;
                    }
                    count += rc;
                    log->bytes_read += rc;
                } else {
                    retval = 0;
                }
                if (entry&FAKE_CALLS_FLAG) {
                    rc = read (fd, &fake_calls, sizeof(int));
                    if (rc != sizeof(int)) {
                        perror ("read fake calls value\n");
                        return rc;
                    }
                    count += rc;
                    log->bytes_read += rc;
                } else {
                    fake_calls = 0;
                }
                if (entry&(SKIPPED_CLOCK_FLAG|NONZERO_RETVAL_FLAG|FAKE_CALLS_FLAG|ERRNO_CHANGE_FLAG)) {
                    printf ("clock %lu fake calls %d retval %d \n", log->total_clock-1, fake_calls, retval);
                    log->clocks->push (log->total_clock - 1);
                }
#endif
            }

        } else { 
            fprintf (stderr,"bytes_read > log size ??? %ld, %ld, %lu\n", log->bytes_read, log->size, log->total_clock);
            return 0;
        }
    }
    u_long ret = log->clocks->front();
    log->clocks->pop();
    return ret;
}

void parseulib_close (struct ulog* log) 
{
    if (log != NULL) {
        close (log->fd);
        delete (log->clocks);
        free (log);
    }
}


