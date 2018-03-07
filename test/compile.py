#!/usr/bin/python

import os

outputdir="/replay_logdb/rec_28721"

#Recompile the slice source
os.system("gcc -masm=intel -c -fpic -Wall -Werror "+outputdir+"/exslice1.19777.c -o "+outputdir+"/exslice1.19777.o")

# Link
os.system("gcc -shared " + outputdir + "/exslice1.19777.o " + outputdir + "/exslice.19777.o -o " + outputdir + "/exslice.19777.so recheck_support.o")
