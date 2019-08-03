#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/replay.h>
#include <linux/mount.h>
#include <linux/delay.h>
#include <linux/shm.h>
#include <asm/uaccess.h>
#include <asm/fcntl.h>
#include <asm/ldt.h>
#include <asm/desc.h>
#include <asm/ptrace.h>
#include <asm/elf.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/fpu-internal.h>
#include <linux/proc_fs.h>
#include <linux/replay.h>
#include <linux/replay_maps.h>
#include <linux/stat.h>
#include <linux/times.h>
#include <linux/rwlock.h>
#include "./uthash.h"
#include <linux/export.h>


//TODO  add rw lock
//TODO  add environment variables also as key
extern unsigned int replay_debug;
#define DPRINT if(replay_debug) printk
struct startup_entry {
	char* argbuf; //key
	int arglen;
	__u64 group_id;
	unsigned long ckpt_clock;
	UT_hash_handle hh;
};

struct startup_entry* startup_db = NULL;

void init_startup_db (void) { 
	//read from disk
}
EXPORT_SYMBOL(init_startup_db);

void sync_startup_db (void) {
	//write to disk
}

static inline void fuzzy_string (char* argbuf, int arglen) { 
	//hacky for cc1 only
	//TODO: fix this after we can generate slice
	char* exe = "/usr/lib/gcc/i686-linux-gnu/4.6/cc1";
	if (strncmp (argbuf + 8, exe, strlen(exe)) == 0) {
		char* index = memchr (argbuf + arglen - 17, '/', 17);
		if (index != NULL) { 
			char* end = NULL;
			DPRINT ("fuzzy string before: %s\n", index);
			if ((end = strstr (index, ".s")) != NULL) {
				char* i = index + 1;
				while (i < end) { 
					*i = 'x';
					++i;
				}
				DPRINT ("fuzzy string: %s\n", index);
			}
		}
	}
}

void free_startup_db (void) { 
	struct startup_entry* s = NULL;
	struct startup_entry* tmp = NULL;
	HASH_ITER (hh, startup_db, s, tmp) { 
		HASH_DEL (startup_db, s);
		vfree (s->argbuf);
		vfree (s);
	}
}

void dump_startup_db (void) { 
	struct startup_entry* s = NULL;
	struct startup_entry* tmp = NULL;
	printk ("----dump startup db----\n");
	HASH_ITER (hh, startup_db, s, tmp) { 
		printk ("   gid: %llu, ckpt_clock: %lu\n", s->group_id, s->ckpt_clock);
	}
	printk ("----dump startup db----\n");
}

//return 0 if not found, return 1 if found
int find_startup_cache (char* argbuf, int arglen, struct startup_db_result* result) {  
	struct startup_entry* e = NULL;
	fuzzy_string (argbuf, arglen);
	HASH_FIND (hh, startup_db, argbuf, arglen, e);
	if (e == NULL) { 
		return 0;
	} else { 
		result->group_id = e->group_id;
		result->ckpt_clock = e->ckpt_clock;
		return 1;
	}
}

int find_startup_cache_user_argv (const char __user *const __user *__argv, struct startup_db_result* result) { 
	int arglen;
	char* argbuf = copy_args (__argv, NULL, &arglen);
	int ret = 0;
	if (argbuf == NULL) { 
		DPRINT ("find_startup_cache_user_argv: cannot copy args.\n");
		return 0;
	}
	if (replay_debug) {
		int i = 0;
		printk ("Find in startup cache, len %d:", arglen);
		while (i<arglen) { 
			printk ("%c,", argbuf[i]);
			++i;
		}
		printk ("\n");
	}

	//free argbuf
	ret = find_startup_cache (argbuf, arglen, result);
	kfree (argbuf);
	return ret;
}

//the key is the content in argbuf
//IMPORTANT: check existence of the key before adding it!
void add_to_startup_cache (char* old_argbuf, int arglen, __u64 group_id, unsigned long ckpt_clock) { 
	struct startup_entry* e = NULL;
	char* argbuf = vmalloc (arglen);
	memcpy (argbuf, old_argbuf, arglen);
	
	fuzzy_string (argbuf, arglen);
	HASH_FIND (hh, startup_db, argbuf, arglen, e);
	if (e == NULL) { 
		e = vmalloc (sizeof (struct startup_entry));
		e->argbuf = vmalloc (arglen);
		memcpy (e->argbuf, argbuf, arglen);
		e->arglen = arglen;
		e->group_id = group_id;
		e->ckpt_clock = ckpt_clock;
		HASH_ADD_KEYPTR (hh, startup_db, e->argbuf, arglen, e);
	} else {
		e->group_id = group_id;
		e->ckpt_clock = ckpt_clock;
	}
	if (replay_debug) {
		int i = 0;
		printk ("Add to startup cache, len %d, id %llu, clock %lu: ", arglen, group_id, ckpt_clock);
		while (i<arglen) { 
			printk ("%c,", argbuf[i]);
			++i;
		}
		printk ("\n");
	}
	vfree (argbuf);

}
EXPORT_SYMBOL(add_to_startup_cache);



