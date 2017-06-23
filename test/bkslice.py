#!/usr/bin/python
# Take in line number, generate backward slice from pinout file

import sys

lineno = int(sys.argv[1])

sources = {}

regname = {}
regname["3"] = "edi"
regname["4"] = "esi"
regname["5"] = "ebp"
regname["7"] = "ebx"
regname["8"] = "edx"
regname["9"] = "ecx"
regname["10"] = "eax"

transreg = {}
transreg["dl"] = "edx"

def is_reg (loc):
    return loc in regname.values()

def is_cmp (inst):
    return (inst == "#cmp")

def is_cmov (inst):
    return (inst[:5] == "#cmov")

def findSources(target):
    # Determine what sources this line
    if target.find("flag tainted 1") > 0:
        #print "Flags are tainted"
        sources["flags"] = 1
    b = target.find("[", target.find("src_")) + 1
    e = target.find("]", b)
    for src in target[b:e].split(","):
        (reg,taint,sz) = src.split(":")
        #print reg, taint, sz
        if (reg[:2] == "FM"):
            sources["flags"] = 1
        elif int(taint): 
            if (int(reg,16) < 4096):
                #print "look for reg", reg
                sources[regname[reg]] = 1
            else:
                sources[reg] = 1

def findNextBSlice(cnt):
    use_next_slice = 0
    while cnt > 0:
        cnt = cnt - 1
        if lines[cnt][:7] == "[SLICE]":
            if is_cmp(lines[cnt].split()[2]):
                if use_next_slice:
                    use_next_slice = False
                if "flags" in sources:
                    print cnt+1, lines[cnt],
                    del sources["flags"]
                    return cnt
            else:
                if use_next_slice:
                    del sources[addr]
                    print addrline,
                dest = lines[cnt].split()[3].split(",")[0]
                if dest in transreg:
                    dest = transreg[dest];
                if dest in sources or use_next_slice:
                    print cnt+1, lines[cnt],
                    if (not use_next_slice):
                        del sources[dest]
                    return cnt
        elif lines[cnt][:13] == "[SLICE_TAINT]":
            begin = int(lines[cnt].split()[-2],16)
            end = int(lines[cnt].split()[-1],16)
            for s in sources.keys():
                v = int(s,16)
                if (v >= begin and v <= end):
                    print cnt+1, lines[cnt],
                    del sources[s]
                    print "source for", s
        elif lines[cnt][:18] == "[SLICE_ADDRESSING]":
            b = lines[cnt].find("$addr(")+8
            e = lines[cnt][b:].find(")")+b
            addr = lines[cnt][b:e]
            if (addr in sources):
                addrline = lines[cnt]
                #print "addrfind", addrline,
                while cnt > 0:
                    cnt = cnt - 1
                    #print "addrwalk", lines[cnt],
                    if lines[cnt][:7] == "[SLICE]":
                        # Address may be used as a source - check for this
                        dest = lines[cnt].split()[3].split(",")[0]
                        if not is_reg(dest):
                            cnt = cnt + 1
                            use_next_slice = True
                        break

        

# Read in and cache lines up to slicing point
fh = open ("/tmp/pinout", "r")
cnt = 0
lines = {}
for line in fh:
    lines[cnt] = line;
    cnt = cnt + 1
    if cnt == lineno:
        break
fh.close()

cnt = cnt-1
target = lines[cnt]
print target,

while (cnt > 0):
    findSources(lines[cnt])
    #print sources
    cnt = findNextBSlice(cnt)
