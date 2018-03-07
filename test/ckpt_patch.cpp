#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

char target_str[] = "DBUS_SESSION_BUS_ADDRESS=";

int main (int argc, char* argv[]) 
{
    char env_str[256];
    strcpy (env_str, target_str);
    env_str[strlen(env_str)-1] = '\0';
    char* substitution_str = getenv(env_str);
    printf ("sub string is %s\n", substitution_str);
    if (substitution_str == NULL) {
	fprintf (stderr, "Cannot get %s from the environment\n", env_str);
	return -1;
    }

    char ckpt_name[256]; 
    strcpy (ckpt_name, argv[1]);
    strcat (ckpt_name, "/last_altex/ckpt");
  
    char old_ckpt_name[256];
    strcpy (old_ckpt_name, argv[1]);
    strcat (old_ckpt_name, "/ckpt");

    // unlink old ckpt/symlink
    long rc = unlink (ckpt_name);
    if (rc < 0) {
	fprintf (stderr, "Unable to unlink %s\n", ckpt_name);
	return rc;
    }

    // creat new ckpt file
    int fd = open(ckpt_name, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
	fprintf (stderr, "Unable to create %s\n", ckpt_name);
	return rc;
    }

    int oldfd = open(old_ckpt_name, O_RDONLY);
    if (oldfd < 0) {
	fprintf (stderr, "Unable to open %s\n", old_ckpt_name);
	return rc;
    }

    // Copy record_pid and rg_ids to new checkpoint
    char buf[65536];
    long tocopy = sizeof(pid_t) + sizeof(uint64_t) + sizeof(uint64_t);
    rc = read (oldfd, buf, tocopy);
    if (rc != tocopy) {
	fprintf (stderr, "Unable to read header\n");
	return rc;
    }
    rc = write(fd, buf, tocopy);
    if (rc != tocopy) {
	fprintf (stderr, "Unable to write header\n");
	return rc;
    }

    // Copy filename
    long len;
    rc = read (oldfd, &len, sizeof(len));
    if (rc != sizeof(len)) {
	fprintf (stderr, "Unable to read filename len\n");
	return rc;
    }
    rc = write(fd, &len, sizeof(len));
    if (rc != sizeof(len)) {
	fprintf (stderr, "Unable to write filename len\n");
	return rc;
    }

    rc = read (oldfd, buf, len);
    if (rc != len) {
	fprintf (stderr, "Unable to read filename\n");
	return rc;
    }
    rc = write(fd, buf, len);
    if (rc != len) {
	fprintf (stderr, "Unable to write filename\n");
	return rc;
    }

    // Copy other stuff
    tocopy = sizeof (struct rlimit)*RLIM_NLIMITS + 64*20;
    rc = read (oldfd, buf, tocopy);
    if (rc != tocopy) {
	fprintf (stderr, "Unable to read header data\n");
	return rc;
    }
    rc = write(fd, buf, tocopy);
    if (rc != tocopy) {
	fprintf (stderr, "Unable to write header data\n");
	return rc;
    }

    // Number of arguments
    long args_cnt;
    rc = read (oldfd, &args_cnt, sizeof(args_cnt));
    if (rc != sizeof(args_cnt)) {
	fprintf (stderr, "Unable to read args cnt\n");
	return rc;
    }
    rc = write(fd, &args_cnt, sizeof(args_cnt));
    if (rc != sizeof(args_cnt)) {
	fprintf (stderr, "Unable to write args cnt\n");
	return rc;
    }

    for (long i = 0; i < args_cnt; i++) {

	// Copy argument
	rc = read (oldfd, &len, sizeof(len));
	if (rc != sizeof(len)) {
	    fprintf (stderr, "Unable to read arg %ld len\n", i);
	    return rc;
	}
	rc = write(fd, &len, sizeof(len));
	if (rc != sizeof(len)) {
	    fprintf (stderr, "Unable to write arg %ld len\n", i);
	    return rc;
	}

	rc = read (oldfd, buf, len);
	if (rc != len) {
	    fprintf (stderr, "Unable to read arg %ld\n", i);
	    return rc;
	}
	rc = write(fd, buf, len);
	if (rc != len) {
	    fprintf (stderr, "Unable to write arg %ld\n", i);
	    return rc;
	}

    }

    // Number of env vars
    long env_cnt;
    rc = read (oldfd, &env_cnt, sizeof(env_cnt));
    if (rc != sizeof(env_cnt)) {
	fprintf (stderr, "Unable to read args cnt\n");
	return rc;
    }
    rc = write(fd, &env_cnt, sizeof(env_cnt));
    if (rc != sizeof(env_cnt)) {
	fprintf (stderr, "Unable to write args cnt\n");
	return rc;
    }
    printf ("env_cnt is %ld\n", env_cnt);
    for (long i = 0; i < env_cnt; i++) {

	// Copy env variable or replace it
	rc = read (oldfd, &len, sizeof(len));
	if (rc != sizeof(len)) {
	    fprintf (stderr, "Unable to read arg %ld len\n", i);
	    return rc;
	}
	rc = write(fd, &len, sizeof(len));
	if (rc != sizeof(len)) {
	    fprintf (stderr, "Unable to write arg %ld len\n", i);
	    return rc;
	}

	rc = read (oldfd, buf, len);
	if (rc != len) {
	    fprintf (stderr, "Unable to read arg %ld\n", i);
	    return rc;
	}
	printf ("Environment variable %ld: %s\n", i, buf);
	if (!strncmp (buf, target_str, strlen(target_str))) {
	    printf ("previous string was: %s\n", buf+strlen(target_str));
	    if (strlen(buf+strlen(target_str)) != strlen(substitution_str)) {
		fprintf (stderr, "Mismatch in length : substitution string is %s - target string is %s\n",
			 substitution_str, buf+strlen(target_str));
		return -1;
	    }

	    // This makes the change
	    memcpy (buf+strlen(target_str), substitution_str, strlen(substitution_str));
	    printf ("new string was: %s\n", buf+strlen(target_str));
	}

	rc = write(fd, buf, len);
	if (rc != len) {
	    fprintf (stderr, "Unable to write arg %ld\n", i);
	    return rc;
	}
    }

    // Finally copy timespec
    tocopy = sizeof(struct timespec);
    rc = read (oldfd, buf, tocopy);
    if (rc != tocopy) {
	fprintf (stderr, "Unable to read header\n");
	return rc;
    }
    rc = write(fd, buf, tocopy);
    if (rc != tocopy) {
	fprintf (stderr, "Unable to write header\n");
	return rc;
    }

    return 0;
}
