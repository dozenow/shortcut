#!/usr/bin/python

import os
from subprocess import Popen, PIPE
import sys
import shutil

outputdir = "/tmp"
instr_jumps = True

# Insert a breakpoint
lineno = 1596213
os.system ("head -n " + str(lineno) + " /tmp/pinout > /tmp/pinout.brk")
os.system ("echo \"[SLICE] #ffffffff #int 0x3 [SLICE_INFO] debug breakpoint\" >> /tmp/pinout.brk")
os.system ("tail -n +" + str(lineno+1) + " /tmp/pinout >> /tmp/pinout.brk")

# Refine the slice with grep
outfd = open(outputdir+"/slice", "w")
p = Popen (["grep", "SLICE", outputdir+"/pinout.brk"], stdout=outfd)
p.wait()
outfd.close()

# Generate asm file
outfd = open(outputdir+"/exslice.asm", "w")
p = Popen (["./process_slice", outputdir+"/slice"],stdout=outfd)
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
    if linecnt > 2500000:
        write_jump_index ()
        fcnt += 1
        linecnt = 0
        mainfd.write("\"call _section" + str(fcnt) + "\\n\"\n")
        outfd = open(outputdir+"/exslice" + str(fcnt) + ".c", "w")
        outfd.write ("asm (\n")
        outfd.write ("\".section	.text\\n\"\n")
        outfd.write ("\".globl _section" + str(fcnt) + "\\n\"\n")
        outfd.write ("\"_section" + str(fcnt) +":\\n\"\n")
        
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


