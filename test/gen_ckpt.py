#!/usr/bin/python

import os
from subprocess import Popen, PIPE

# Modify these config paraemters for new checkpoint
#rec_dir = 12334
#ckpt_at = 69
#taint_syscall = 9999

rec_dir = 8216
ckpt_at = 1475
taint_syscall = 999999

# Run the pin tool to generate slice info and the recheck log
outfd = open("/tmp/pinout", "w")
if (taint_syscall > 0):
    p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", "-i", "-s", 
               str(taint_syscall), "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at)],
              stdout=outfd)
else:
    p = Popen(["./runpintool", "/replay_logdb/rec_" + str(rec_dir), "../dift/obj-ia32/linkage_offset.so", 
               "-recheck_group", str(rec_dir), "-ckpt_clock", str(ckpt_at)],
              stdout=outfd)
p.wait()
outfd.close()

# Refine the slice with grep
outfd = open("/tmp/slice", "w")
p = Popen (["grep", "SLICE", "/tmp/pinout"], stdout=outfd)
p.wait()
outfd.close()

# Run scala tool
outfd = open("/tmp/exslice.asm", "w")
p = Popen (["scala", "-nc", "preprocess_asm.scala", "/tmp/slice"],stdout=outfd)
p.wait()
outfd.close()

# Convert asm to c file
infd = open("/tmp/exslice.asm", "r")
outfd = open("/tmp/exslice.c", "w")
outfd.write ("asm (\n")
for line in infd:
    if line[:13] == ".intel_syntax":
        continue # Handled by -masm flag
    else:
        outfd.write ("\"" + line.strip() + "\\n\"\n")
outfd.write (");\n")

infd.close();
outfd.close();
# And compile it
#os.system("as /tmp/exslice.asm -o /tmp/exslice.o")
#os.system("ld -m elf_i386 -s -shared -o /tmp/exslice.so /tmp/exslice.o")
os.system("gcc -masm=intel -c -fpic -Wall -Werror /tmp/exslice.c -o /tmp/exslice.o")
os.system("gcc -shared /tmp/exslice.o -o /tmp/exslice.so recheck_support.o")

# Generate a checkpoint
p = Popen(["./resume", "/replay_logdb/rec_" + str(rec_dir), "--pthread", "../eglibc-2.15/prefix/lib/", "--ckpt_at=" + str(ckpt_at)])
p.wait()

