#!/usr/bin/python

import os
from subprocess import Popen, PIPE
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("first_group_id", help = "first group id")
parser.add_argument("first_asm_file", help = "first asm filename")
parser.add_argument("second_group_id", help = "second group id")
parser.add_argument("second_asm_file", help = "second asm filename")
parser.add_argument("checkpoint_clock", help = "clock to checkpoint")
args = parser.parse_args()

master_group = args.first_group_id

p = Popen (["./merge_slice_ctrl_flow", args.first_asm_file, args.second_asm_file])
p.wait()
if (p.returncode == 2):
    master_group = args.second_group_id
print "master group is " + master_group

print '######run slice generation and generate taint set'
p = Popen (["./gen_ckpt.py", master_group, args.checkpoint_clock, "-taint_syscall", "9999999", "-ctrl_flow_g_taint_set"])
p.wait()

outfd = open ("/tmp/ctrl", "w")
p = Popen (["grep", "CONTROL", "/tmp/pinout"], stdout=outfd)
p.wait()
outfd.close()

print '######run slice generation again with taint set and generate new slice'
p = Popen (["./gen_ckpt.py", master_group, args.checkpoint_clock, "-taint_syscall", "9999999", "-ctrl_flow_g_slice"])
p.wait()

print '######post process new slice'
p = Popen (["./finalize_slice_ctrl_flow", "/tmp/exslice.asm", "/tmp/test.asm"])
p.wait()

print '#####finally compile new slice'
p = Popen (["./gen_ckpt.py", master_group, args.checkpoint_clock, "-taint_syscall", "9999999", "-compile_only", "/tmp/test.asm"])

