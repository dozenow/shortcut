#!/usr/bin/python

import os

outputdir="/replay_logdb/rec_61464"
fcnt = 4

# And compile it
os.system("gcc -masm=intel -c -fpic -Wall -Werror "+outputdir+"/exslice.c -o "+outputdir+"/exslice.o")
linkstr = "gcc -shared "+outputdir+"/exslice.o -o "+outputdir+"/exslice.so recheck_support.o"
for i in range(fcnt):
    strno = str(i + 1)
    os.system("gcc -masm=intel -c -fpic -Wall -Werror "+outputdir+"/exslice" + strno + ".c -o "+outputdir+"/exslice" + strno + ".o")
    linkstr += " " + outputdir + "/exslice" + strno + ".o"
os.system(linkstr)

