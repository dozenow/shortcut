#!/usr/bin/python

import os
from subprocess import Popen, PIPE
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("first_group_id", help = "first group id")
parser.add_argument("first_record_pid", help = "the record pid in the first replay to which you want to attach pin")
parser.add_argument("second_group_id", help = "second group id")
parser.add_argument("second_record_pid", help = "the record pid in the second replay to which you want to attach pin")
parser.add_argument("instrument_start_clock", help = "the clock value to attach pin")
parser.add_argument("instrument_stop_clock", help = "clock to detach pin")
args = parser.parse_args()

#runpintool --attach_offset=10233,60 /replay_logdb/rec_307204/ ../dift/obj-ia32/ctrl_flow_bb_trace.so -s 62 > m1
print '#####generate basic block traces for first execution'
outfd = open ("/tmp/bb_trace1", "w")
p = Popen (['./runpintool', '--attach_offset='+args.first_record_pid+','+args.instrument_start_clock, '/replay_logdb/rec_'+args.first_group_id, '../dift/obj-ia32/ctrl_flow_bb_trace.so', '-s', args.instrument_stop_clock], stdout=outfd)
p.wait()
outfd.close()

print '#####generate basic block traces for second execution'
outfd = open ("/tmp/bb_trace2", "w")
p = Popen (['./runpintool', '--attach_offset='+args.second_record_pid+','+args.instrument_start_clock, '/replay_logdb/rec_'+args.second_group_id, '../dift/obj-ia32/ctrl_flow_bb_trace.so', '-s', args.instrument_stop_clock], stdout=outfd)
p.wait()

print '#####figure out the merge point'
p = Popen (["./diverge_and_merge_point", '/tmp/bb_trace1', '/tmp/bb_trace2'])
p.wait()

'''
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
'''
