#!/usr/bin/python

import subprocess
import os

# For emacs
recid = 61464
ckpt = 5361
taintarg = "-taint_syscall"
taintvalue = "999999999"
recpid = 7906

# For placer
#recid = 61487
#ckpt = 3043
#taintarg = "-taint_byterange" 
#taintvalue =  "30369,90,5,260"
#recpid = 30369

if os.path.exists("/replay_logdb/rec_%d/taintbuf"%recid):
    os.remove ("/replay_logdb/rec_%d/taintbuf"%recid)

#fh = open("/tmp/gen_ckpt.out", "w")
#subprocess.call (["./gen_ckpt.py", "%d"%recid, "%d"%ckpt, taintarg, taintvalue], stdout=fh, stderr=subprocess.STDOUT)
#fh.close()

# Ideally, this should be as close to running from the command line as possible...
cpid = os.fork()
if cpid == 0:
    pid = os.getpid()
    print "pid", pid, "pgid", os.getpgid(0), "sid", os.getsid(0)
    os.setpgid(0,0)
    pid = os.getpid()
    print "pid", pid, "pgid", os.getpgid(0), "sid", os.getsid(0)
    #os.execl ("./resume", "./resume", "/replay_logdb/rec_%d"%recid, "--pthread", "../eglibc-2.15/prefix/lib", "--from_ckpt=%d"%ckpt, "-l")
    os.execl ("/bin/ls", "ls", "-l")
else:
    try:
        print "wait for", cpid
        os.waitpid(cpid, 0)
    except (OSError) as e:
        print ("waitpid fails, errno=", e.errno)

if os.path.exists("/replay_logdb/rec_%d/taintbuf"%recid):
    subprocess.call (["./patchklog", "/replay_logdb/rec_%d/klog.id.%d"%(recid,recpid)])
else:
    print "Application completed successfully!"
