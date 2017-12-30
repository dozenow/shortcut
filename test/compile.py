#!/usr/bin/python

import os
from multiprocessing import Pool

outputdir="/replay_logdb/rec_65582"
fcnt = 12

def compMain (outputdir):
    return os.system("gcc -masm=intel -c -fpic -Wall -Werror "+outputdir+"/exslice.c -o "+outputdir+"/exslice.o")

def compSlice (outputdir, strno):
    return os.system("gcc -masm=intel -c -fpic -Wall -Werror "+outputdir+"/exslice" + strno + ".c -o "+outputdir+"/exslice" + strno + ".o")

# And compile it
pool = Pool(processes=8)
linkstr = "gcc -shared "+outputdir+"/exslice.o -o "+outputdir+"/exslice.so recheck_support.o"
pool.apply_async (compMain, (outputdir, ))
for i in range(fcnt):
    strno = str(i + 1)
    pool.apply_async (compSlice, (outputdir, strno))
    linkstr += " " + outputdir + "/exslice" + strno + ".o"

pool.close()
pool.join()
os.system(linkstr)
