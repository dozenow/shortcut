#!/usr/bin/python

import os
from subprocess import Popen, PIPE
import sys
import argparse

instr_jumps = True

# Modify these config paraemters for new checkpoint
parser = argparse.ArgumentParser()
parser.add_argument("rec_group_id", help = "record group id")
parser.add_argument("checkpoint_clock", help = "clock of the checkpoint")
parser.add_argument("-taint_syscall", help = "only taint this syscall at index XXX")
parser.add_argument("-taint_byterange", help = "taint a specific byte range: RECORD_PID,SYSCALL_INDEX,START,END")
parser.add_argument("-taint_byterange_file", help = "give a file specifying all ranges and all syscalls to be tainted.");
parser.add_argument("-outputdir", help = "the output dir of all output files.");
args = parser.parse_args()

rec_dir = args.rec_group_id
ckpt_at = args.checkpoint_clock
taint_filter = False
if args.taint_syscall:
    taint_syscall = args.taint_syscall
    taint_filter = True
else:
    taint_syscall = ""

if args.taint_byterange:
    taint_byterange = args.taint_byterange
    taint_filter = True
else:
    taint_byterange = ""
if args.taint_byterange_file:
    taint_byterange_file = args.taint_byterange_file
    taint_filter = True
else:
    taint_byrterange_file = ""
outputdir = "/replay_logdb/rec_" + str(rec_dir)
if args.outputdir:
    outputdir = args.outputdir

usage = "Usage: ./gen_ckpt.py rec_group_id checkpoint_clock [-o outputdir] [-taint_syscall SYSCALL_INDEX] [-taint_byterange RECORD_PID,SYSCALL_INDEX,START,END] [-taint_byterange_file filename]" 
	
# Run the pin tool to generate slice info and the recheck log
outfd = open(outputdir+"/pinout", "w")
checkfilename = outputdir+"/checks"
if (taint_filter > 0):
	if (taint_syscall):
		p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", "-i", "-s", 
			str(taint_syscall), "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at), "-chk", checkfilename], 
			stdout=outfd)
	elif (taint_byterange):
		p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", "-i", "-b", 
			taint_byterange, "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at), "-chk", checkfilename], 
			stdout=outfd)
	elif (taint_byterange_file):
		p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", "-i", "-rf", 
			taint_byterange_file, "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at), "-chk", checkfilename], 
			stdout=outfd)
else:
    p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", 
               "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at), "-chk", checkfilename], 
              stdout=outfd)
p.wait()
outfd.close()

# Refine the slice with grep
outfd = open(outputdir+"/slice", "w")
p = Popen (["grep", "SLICE", outputdir+"/pinout"], stdout=outfd)
p.wait()
outfd.close()

# Run scala tool
outfd = open(outputdir+"/exslice.asm", "w")
p = Popen (["./process_slice", outputdir+"/slice"],stdout=outfd)
#Note: Try to avoid recompilation, but this requires you to run make if you change preprocess_asm.scala file
#If this hangs for a long time, it's probably because your environment configuration is wrong
#Add  127.0.0.1 YOUR_HOST_NAME to /etc/hosts, where YOUR_HOST_NAME comes from running command: hostname
p.wait()
outfd.close()

# Convert asm to c file
fcnt = 1;
infd = open(outputdir+"/exslice.asm", "r")
mainfd = open(outputdir+"/exslice.c", "w")
mainfd.write ("asm (\n")
for line in infd:
    if line.strip() == "/*slice begins*/":
        break
    mainfd.write ("\"" + line.strip() + "\\n\"\n")
mainfd.write("\"call _section1\\n\"\n")
     
outfd = open(outputdir+"/exslice1.c", "w")
outfd.write ("asm (\n")
outfd.write ("\".section	.text\\n\"\n")
outfd.write ("\".globl _section1\\n\"\n")
outfd.write ("\"_section1:\\n\"\n")

def write_jump_index ():
    outfd.write ("\"ret\\n\"\n");
    outfd.write ("\"jump_diverge:\\n\"\n");
    outfd.write ("\"push eax\\n\"\n");
    outfd.write ("\"push ecx\\n\"\n");
    outfd.write ("\"push edx\\n\"\n");
    outfd.write ("\"call handle_jump_diverge\\n\"\n");
    outfd.write ("\"push edx\\n\"\n");
    outfd.write ("\"push ecx\\n\"\n");
    outfd.write ("\"push eax\\n\"\n");
    outfd.write ("\"index_diverge:\\n\"\n");
    outfd.write ("\"push eax\\n\"\n");
    outfd.write ("\"push ecx\\n\"\n");
    outfd.write ("\"push edx\\n\"\n");
    outfd.write ("\"call handle_index_diverge\\n\"\n");
    outfd.write ("\"push edx\\n\"\n");
    outfd.write ("\"push ecx\\n\"\n");
    outfd.write ("\"push eax\\n\"\n");
    outfd.write (");\n")
    outfd.close()

jcnt = 0
linecnt = 0
for line in infd:
    if line.strip() == "/* restoring address and registers */":
        write_jump_index ()
        break
    if linecnt > 2500000 and "[ORIGINAL_SLICE]" in line:
        write_jump_index ()
        fcnt += 1
        linecnt = 0
        mainfd.write("\"call _section" + str(fcnt) + "\\n\"\n")
        outfd = open(outputdir+"/exslice" + str(fcnt) + ".c", "w")
        outfd.write ("asm (\n")
        outfd.write ("\".section	.text\\n\"\n")
        outfd.write ("\".globl _section" + str(fcnt) + "\\n\"\n")
        outfd.write ("\"_section" + str(fcnt) +":\\n\"\n")
    if instr_jumps and " jump_diverge" in line:
        outfd.write ("\"" + "pushfd" + "\\n\"\n")
        outfd.write ("\"" + "push " + str(jcnt) + "\\n\"\n")
	outfd.write ("\"" + line.strip() + "\\n\"\n")
        outfd.write ("\"" + "add esp, 4" + "\\n\"\n")
        outfd.write ("\"" + "popfd" + "\\n\"\n")
        jcnt = jcnt + 1
        linecnt += 5
    else:
	outfd.write ("\"" + line.strip() + "\\n\"\n")
        linecnt += 1
        
for line in infd:
    mainfd.write ("\"" + line.strip() + "\\n\"\n")

mainfd.write (");\n")
mainfd.close()
infd.close()

# And compile it
os.system("gcc -masm=intel -c -fpic -Wall -Werror "+outputdir+"/exslice.c -o "+outputdir+"/exslice.o")
linkstr = "gcc -shared "+outputdir+"/exslice.o -o "+outputdir+"/exslice.so recheck_support.o"
for i in range(fcnt):
    strno = str(i + 1)
    os.system("gcc -masm=intel -c -fpic -Wall -Werror "+outputdir+"/exslice" + strno + ".c -o "+outputdir+"/exslice" + strno + ".o")
    linkstr += " " + outputdir + "/exslice" + strno + ".o"
os.system(linkstr)

# Generate a checkpoint
p = Popen(["./resume", "/replay_logdb/rec_" + str(rec_dir), "--pthread", "../eglibc-2.15/prefix/lib/", "--ckpt_at=" + str(ckpt_at)])
p.wait()

