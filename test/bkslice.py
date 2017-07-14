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
regname["54"] = "xmm0"
regname["55"] = "xmm1"
regname["56"] = "xmm2"
regname["57"] = "xmm3"

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
                for n in range(int(sz)):
                    addr = ("%X" % (int(reg,16)+int(n))).lower()
                    sources[addr] = 1

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
                    #del sources[addr]
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
            if (len(lines[cnt].split()) == 3):
                reg = lines[cnt].split()[-1][1:]
                if reg in sources.keys():
                    print cnt+1, lines[cnt],
                    del sources[reg]
                    print "source for", reg
            else:
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
            addrline = lines[cnt]
            #print "addrfind", addrline,
            while cnt > 0:
                cnt = cnt - 1
                #print "addrwalk", lines[cnt],
                if lines[cnt][:7] == "[SLICE]":
                    # determine size of instruction
                    if "xmmword ptr" in lines[cnt]:
                        opsize = 16
                    elif "dword ptr" in lines[cnt]:
                        opsize = 4
                    elif "word ptr" in lines[cnt]:
                        opsize = 2
                    elif "byte ptr" in lines[cnt]:
                        opsize = 1
                    elif "#pop" in lines[cnt]:
                        opsize = 4
                    elif "#push" in lines[cnt]:
                        opsize = 4
                    else:
                        print ">>> ", lines[cnt]
                        die 
                    for n in range(opsize):
                        maddr = ("%X" % (int(addr,16)+int(n))).lower()
                        #print "maddr: ", maddr, sources
                        if (maddr in sources):
                            # Address may be used as a source - check for this
                            dest = lines[cnt].split()[3].split(",")[0]
                            #print "dest: ", dest
                            if not is_reg(dest):
                                #print "use next slice"
                                if not(is_cmp(lines[cnt].split()[2])):
                                    del sources[maddr]
                                use_next_slice = True
                    cnt = cnt + 1
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
    print "Source: ", sorted(sources.keys());
    cnt = findNextBSlice(cnt)
