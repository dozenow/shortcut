

# Important components #

| Directory | Description  |
|--|--|
| linux-lts-quantal-3.5.0 | Customized kernel based on Arnold (Eidetic systems OSDI'14) that supports deterministic record and replay. You can find many things we added to Arnold here, including kernel supports for transparent recovery, applying state diff, generating state diff for application startup, etc.  |
| dift  | Intel PIN tools, including slice and predicate generation, control/data flow divergences handling, and generic state diff generation. A good entry point for understanding this component is [linkage_new2.cpp](https://github.com/dozenow/shortcut/blob/master/dift/linkage_new2.cpp "linkage_new2.cpp")). In this file, we instrument every x86 instruction (e.g., instrument_fpu_store) and every system call (e.g., sys_open_start).   |
| test | All utility tools, including recording the process, profiler, a daemon that supports transparent record and recovery, convenient tools for running PIN instruments.  |
| pin_tools | Also Intel PIN tools, but most of them are debugging tools we use when developing the system.  |

# Setup #
### 1. Kernel setup ###

##### *Setup your OMNIPLAY_ENVIRONMENT* #####
Run the following code one time to setup your $OMNIPLAY_DIR environment

Assuming that <omniplay> is the root directory where you checked out the source:

    cd <omniplay>/scripts
    ./setup.sh
    source $HOME/.omniplay_setup

NOTE: You may also check out ./setup.sh -h and see if you want any of the additional options.  setup.sh may be run again at any time, the changes will be seen upon logging out and logging back in.

##### *Building the kernel* #####

If you're building the kernel on a fresh system, you'll need build dependencies:

    sudo apt-get build-dep linux-image-3.5.0-54-generic g++

To build (and run) the kernel, run the following

    cd $OMNIPLAY_DIR/linux-lts-quantal-3.5.0
    sudo ./compile
    # You'll only need to do a modules_install if your modules were rebuilt, usually this is not the case (with the exception of your first build), and you wont have to
    sudo make INSTALL_MOD_STRIP=1 modules_install
    # You'll also only need to do the 2nd compile if you had to do a make modules_install
    sudo ./compile
    sudo reboot

NOTE: The compile script will also build your "test" tools.

You could alternatively (and equivalently) run:

    cd $OMNIPLAY_DIR/linux-lts-quantal-3.5.0
    make
    sudo make modules_install
    sudo make install
    sudo make headers_install INSTALL_HDR_PATH=$OMNIPLAY_DIR/test/replay_headers
    sudo reboot

##### *Building Glibc* #####
To build glibc, run the following:

Dependencies:

    sudo apt-get install gawk texinfo autoconf gettext

One-time configure:

    cd $OMNIPLAY_DIR/eglibc-2.15/
    mkdir build
    mkdir prefix
    cd build
    LD_LIBRARY_PATH="" ../configure -prefix=$OMNIPLAY_DIR/eglibc-2.15/prefix --disable-profile --enable-add-on --without-gd --without-selinux --without-cvs --enable-kernel=3.2.0
    sudo mkdir /var/db
    sudo chown $USER /var/db
    mkdir ../prefix/etc/
    touch ../prefix/etc/ld.so.conf

To build/install:

    cd $OMNIPLAY_DIR/eglibc-2.15/build
    # Feel free to use -j<# cores+1> for a parallel make...
    LD_LIBRARY_PATH="" make
    LD_LIBRARY_PATH="" make install

Also, run some misc fixups (once):

    LD_LIBRARY_PATH="" cd $OMNIPLAY_DIR/eglibc-2.15/prefix/lib
    LD_LIBRARY_PATH="" ln -s /usr/lib/locale



### 2. Utility tools compilation ###
To build the tools (no installation):

Note: Depends on the headers_install step from building the kernel

    cd $OMNIPLAY_DIR/test/dev
    make
    cd ..
    make


### 3. Pin tool compilation ###
We use Intel Pin version 2.13 

To build:

    cd omniplay/dift
    make PIN_ROOT=<pin_root> (i.e. make PIN_ROOT=/home/dozenow/pin -j4) 

where pin_root is the location where you untar'ed the Pin folder from the download above.


Ubuntu versions after 10.10 no longer allow processes to ptrace a random process unless you run as root. 
This breaks all of our Pin tools. To fix this, go into /etc/sysctl.d/10-ptrace.conf and change the line:

    kernel.yama.ptrace_scope = 1

to be:

    kernel.yama.ptrace_scope = 0


# Basics #

	$ cd $OMNIPLAY_DIR/test
	$ ./setup.sh

Now you can record programs.  You will need to know your dynamic link path.  You can look in /etc/ld.so.conf.d/ to figure this out.  A typical path might be: /lib/i386-linux-gnu:/usr/lib/i386-linux-gnu:/usr/local/lib:/usr/lib:/lib

One you determine this, you can record a program by knowing its fully-qualified pathname

	$ ./launcher --pthread <omniplay>/eglibc-2.15/prefix/lib:<libpath> <fq program> <args>

This will record the execution of that program, as well as any children spawned by that program. So, an easy way to record programs is just to launch a shell that is replayed.  Anything started from that shell will also  be replayed:

	$ ./launcher --pthread <omniplay>/eglibc-2.15/prefix/lib:<libpath> /bin/bash

You should now see that the following directories are being populated:

#### /replay_logdb: 

This contains the logs of non-determinism plus the initial checkpoints.  Each directory is a separate replay group named with an id that increments over time.  Within each directory you should see klog* files (which are kernel-level nondeterminism), ulog* files (which are user-level nondeterminism) and ckpt files (the initial checkpoints).

A new replay group is created on each successful exec.  The replay group contains all threads and processes spawned by the execed process (up to the point where they do execs and start new replay groups)

#### /replay_cache: 

This is a copy-on-read cache of file data.  Cache files are named by device and inode number.  If a file changes over time, past versions are additionally named by their respective modification times.

You can replay a given group with id <id> as follows:

	$ ./resume /replay_logdir/rec_<id> -pthread <omniplay>/src/omniplay/eglibc-2.15/prefix/lib

Keep in mind that a recording process can not initiate a replay.  So, do this from some shell other than the recording bash shell that you started above.  Also, a recording must finish in order for you to replay it successfully.

A successful replay will print the message "Goodbye, cruel lamp! This replay is over" in the kernel log (use dmesg to check).  An unsuccessful replay may or may not print this message.  It will also print out error messages in any event.

# Quick tutorial 


Here we use the xword benchmark mentioned in the paper, as this benchmark takes less to reproduce and also demonstrates our ideas of predicated slices, transparent recovery, control flow divergence handling. 


	unarchive shorcut/tutorial/xword.tar.gz
    cd xword; make  (build it)
    cd omniplay/test
    ~/omniplay/scripts/easy_launch.sh ~/xword/placer -b ~/xword/board.tofro -w ~/xword/wordlist/newmega.txt -v 25 -m 1 -s  (record this using omniplay)

Use the recording to generate a slice. 

	./gen_ckpt.py <replay_dir #> <ckpt #> -taint_byterange <pid>,90,5,250  (the last arguments specifies that an input could change and in this case the changed input comes from the board file)
	
Here the ckpt # specifies the end of the code region. In this case, it is a record/replay clock used internally in Arnold. Here we could use the last gettimeofday system call in the replay log (this is 3043 on my recording - your milage may vary). 
	
Now change the file ~/xword/board.tofro and save it:

	 remove the black squares in the first row at the 6th and 11th columns.

Now replay the execution:

First, make sure sdaemon is running. The sdaemon is required for transparent recovery:

	 ./sdaemon &

Then, do the replay with go-live. This is the our first trial to accelerate the program:

	 ./resume <replay dir> --pthread ../eglibc-2.15/prefix/lib --from_ckpt=<ckpt #> -l

Unfortunately, for this benchmark, we need more profiling runs to get a stable slice. The above should yield a divergence and the program should produce output (thanks to sdaemon-enabled recovery). Of course, for simple programs, you may not observe any divergence for your first profiling run. 

Now, the alternate execution should be in <replay dir>/last_altex

So now generate the checks file. First, generate the base log (you only need do this once):

	 ./runpintool [-no_pthread_lib] <replay dir> ../dift/obj-ia32/print_bb.so -f <replay dir>/trace -s 3043
 (this logs data and control flow information in the file <replay dir>/trace for later comparisons

Now, compare the most recent execution to the original one we just logged:

	 ./runpintool [-no_pthread_lib] <replay dir>/last_altex ../dift/obj-ia32/cmp_bb.so -f <replay dir>/trace -s 3043 > /tmp/cmp

This generates a bunch of divergences - we want to generalize them:

	 ./canonicalize /tmp/cmp > /tmp/canon

Look at the file - if OK, copy to the checks file spot:

	 cp /tmp/canon <replay_dir>/checks

This program only requires one pass. So, you should be able to just generate a new slice and run it successfully:

	 ./gen_ckpt.py <replay_dir #> <ckpt #> -taint_byterange <pid>,90,5,250
	 ./resume <replay dir> --pthread ../eglibc-2.15/prefix/lib --from_ckpt=<ckpt #> -l



