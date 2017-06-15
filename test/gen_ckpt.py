#!/usr/bin/python

import os
from subprocess import Popen, PIPE
import sys
import argparse

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
outputdir = "/tmp"
if args.outputdir:
    outputdir = args.outputdir

usage = "Usage: ./gen_ckpt.py rec_group_id checkpoint_clock [-o outputdir] [-taint_syscall SYSCALL_INDEX] [-taint_byterange RECORD_PID,SYSCALL_INDEX,START,END] [-taint_byterange_file filename]" 
	
# Run the pin tool to generate slice info and the recheck log
outfd = open(outputdir+"/pinout", "w")
if (taint_filter > 0):
	if (taint_syscall):
		p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", "-i", "-s", 
			str(taint_syscall), "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at)],
			stdout=outfd)
	elif (taint_byterange):
		p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", "-i", "-b", 
			taint_byterange, "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at)],
			stdout=outfd)
	elif (taint_byterange_file):
		p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", "-i", "-rf", 
			taint_byterange_file, "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at)],
			stdout=outfd)
else:
    p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", 
               "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at)],
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
infd = open(outputdir+"/exslice.asm", "r")
outfd = open(outputdir+"/exslice.c", "w")
outfd.write ("asm (\n")
for line in infd:
	outfd.write ("\"" + line.strip() + "\\n\"\n")
outfd.write (");\n")

infd.close();
outfd.close();
# And compile it
#os.system("as /tmp/exslice.asm -o /tmp/exslice.o")
#os.system("ld -m elf_i386 -s -shared -o /tmp/exslice.so /tmp/exslice.o")
os.system("gcc -masm=intel -c -fpic -Wall -Werror "+outputdir+"/exslice.c -o "+outputdir+"/exslice.o")
os.system("gcc -shared "+outputdir+"exslice.o -o "+outputdir+"/exslice.so recheck_support.o")

# Generate a checkpoint
p = Popen(["./resume", "/replay_logdb/rec_" + str(rec_dir), "--pthread", "../eglibc-2.15/prefix/lib/", "--ckpt_at=" + str(ckpt_at)])
p.wait()

