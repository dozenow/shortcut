import re, sys
import argparse
from string import punctuation, whitespace
parser = argparse.ArgumentParser()
parser.add_argument("inFile", help="the exslice.asm filename that you want clean")
args = parser.parse_args()
#bad_words = [ 'jnb','jnbe','jnle','jp', 'jns', 'js', 'jnz', 'jz', 'jno', 'jo', 'jbe', 'jb', 'jle', 'jl', 'jae', 'ja', 'jne loc', 'je', 'jmp', 'jge', 'jg', 'SLICE_EXTRA', '[BUG]', '[ERROR]','SLICE_VERIFICATION', 'syscall', '#PARAMS_LOG']

registers = [
" eax ",
" ecx ",
" edi ",
" edx ",
" ebx ",
" esp ",
" ebp ",
" esi ",
" ax ",
" cx ",
" di ",
" dx ",
" bx ",
" sp ",
" bp ",
" si ",
" di ",
" ah ",
" ch ",
" dh ",
" bh ",
" al ",
" cl ",
" dl ",
" bl ",
" eflags ",
" xmm0 ",
" xmm1 ",
" xmm2 ",
" xmm3 ",
]

registersNoSpace = [
"eax ",
"ecx ",
"edi ",
"edx ",
"ebx ",
"esp ",
"ebp ",
"esi ",
"ax ",
"cx ",
"di ",
"dx ",
"bx ",
"sp ",
"bp ",
"si ",
"di ",
"ah ",
"ch ",
"dh ",
"bh ",
"al ",
"cl ",
"dl ",
"bl ",
"eflags ",
"xmm0 ",
"xmm1 ",
"xmm2 ",
"xmm3 ",
]

#removes jumps (Control flow instructions) for right now
#bad_words = ['.section', '.globl', '_start:',]
bad_words = []
sliceEnd = False
sliceStarted = False

extraMem = False

inFileName = args.inFile
outFile = 'cleaned' + inFileName
print(inFileName)
print('converted to: ' + outFile)

def first_word(s):
    to_strip = punctuation + whitespace
    return s.lstrip(to_strip).split(' ', 1)[0].rstrip(to_strip)

def find_word(searchterm, text):
    if('(' in searchterm):
        searchterm = searchterm.replace("(", "\(")
    if(')' in searchterm):
        searchterm = searchterm.replace(")", "\)")
    result = re.findall(searchterm, text, flags=re.IGNORECASE)
    if len(result)>0:
      return True
    else:
      return False

def find_word_list(searchtermList, text):
    yesFound = False
    for searchterm in searchtermList:
        if('(' in searchterm):
            searchterm = searchterm.replace("(", "\(")
        if(')' in searchterm):
            searchterm = searchterm.replace(")", "\)")
        result = re.findall(searchterm, text, flags=re.IGNORECASE)
        if len(result)>0:
            yesFound = True
    return yesFound

def getPiece(listA, index):
    piece = "[ERROR] getPiece() out of bounds of input List."
    if len(listA) > index:
        piece = str(listA[index])
    return piece

def showMem(text):
    tempPieces = text.split('#')
    #print(tempPieces[3])
    tmpStr = getPiece(tempPieces, 3)
    #tmpStr = str(tempPieces[3])
    dest = tmpStr[tmpStr.find("[")+1 : tmpStr.find("]")]
    dest = "dst" + dest
    tmpStr = getPiece(tempPieces, 2)
    #tmpStr = str(tempPieces[2])
    src = tmpStr[tmpStr.find("[")+1 : tmpStr.find("]")]
    src = "src" + src
    #print(dest)
    text = re.sub("/\*(.|\n)*?\*/", '', line)
    text = text + dest
    text = text + ' ' + src
    #print(text)
    #tempPieces2 = tempPieces[1].split('dst_mem')
    #print(tempPieces2)
    return text

def printSomething(fooName, foo):
    if (foo is not None):
        fooStr = str(foo)
        print(fooName + ' is: ' + fooStr)

def prefixToMemSize(prefix):
    if (prefix is " byte ptr"):
        return 1
    elif (prefix is " word ptr"):
        return 2
    elif (prefix is " dword ptr"):
        return 4
    elif (prefix is " qdword ptr"):
        return 8
    elif (prefix is " xmmword ptr"):
        return 16
    else:
        printSomething("[ERROR]", "prefixToMemSize: unrecognized prefix")
        return 0

#takes input string "Foo" and returns "#Foo"
#removes the first character from the input string, because was spaces
def markStr(string):
    marked = "#" + str(string[1:])
    return marked 


def markRegisters(instructionStr):
    #print("[markR] checking instruction: " + instructionStr)
    count = 0
    markedInstruction = instructionStr
    for register in registers:
        count = count + 1 
        #print (register + str(count))
        #print (markStr(register))
        markedInstruction = markedInstruction.replace(register, markStr(register))
    #print(markedInstruction)
    return markedInstruction

with open(inFileName) as oldfile, open(outFile, 'w') as newfile:

    instrListList = []
    instrCount = 0
    #dictionary of instructions with the key being instruction number and the value being a list: instruction name, first argument, second argument
    #{instrCount, [instructionName, firstArg, secondArg]}
#    instrDict = {}
    for line in oldfile:

        if ((not any(bad_word in line for bad_word in bad_words)) and ( not line.startswith('get_mem_value'))):
            
            if(sliceStarted == True):
                #mark every first word in the instruction as an instruction name.
                #this includes and marks 'call' for function calls and 'index_diverge' as instructions, but they are not actually x86 asm instructions 
                #the string before the next comma (so before the 2nd comma)is the first argument to the instruction
                #the string after the 2nd comma is the second argument to the instruction.
                #the second instruction is the string before the "/*[SLICE]" 
                #if(not (line.startswith('"call'))):
                if(1):
                    splitline = line.split()
                    #mark the first word in every instruction as the instruction name
                    #do not add a comma , to the very last line of the .c file, the closing ); for the inline assembly in the .c file
                    if(");" not in splitline[0]):
                        line = line.replace(splitline[0], (splitline[0]+','))

                if(line.find(" xmmword ptr ")):
                    line = line.replace("xmmword ptr ", "#sze16")
                if(line.find(" qdword ptr ")):
                    line = line.replace("qdword ptr ", "#sze8")
                if(line.find(" dword ptr ")):
                    line = line.replace("dword ptr ", "#sze4")
                if(line.find(" word ptr ")):
                    line = line.replace("word ptr ", "#sze2")
                if(line.find(" byte ptr ")):
                    line = line.replace("byte ptr ", "#sze1")
                else:
                    printSomething("[ERROR]", "prefixToMemSize: unrecognized prefix")

                # if the instruction is a special case 'rep' instruction then we need to mark the second argument (which is the instruction that will be repeatedly executed)
                if(('rep') in line):
                    line = line.replace(splitline[1], (splitline[1]+','))

                instpieces = re.split('; |, |\/|\n',line)
                #instructionPiecesA = line.split(",")
                #instructionPiecesB = ''.join(instructionPiecesA)
                #instructionPiecesC = instructionPiecesA.split("/*")
                #printSomething("instpieces", instpieces)
                if ((len(instpieces) >= 3) and not( ("*" in instpieces[2]))):
                    instrListList.append(instpieces[0:3])
                else:
                    instrListList.append(instpieces[0:2])
                
#                line = ''.join(instrListList[instrCount])

                instrCount = instrCount + 1
#                instrDict[instrCount] = instrListList[instrCount]

                

            

            #only check every instruction that is below the "_section1:" line, does not check the section1 line itself
            if (line.startswith('"_section1:')):
                sliceStarted = True

        newfile.write(line)

printSomething("instrListList", instrListList)
print('Done! Parsed slice in: ' + outFile)

#make a reversed copy of the original instrListList 
revInstrListList = instrListList.copy()
revInstrListList = revInstrListList.reverse()

#TODO process this reversed instruction list list (list of asm instructions represented as a list of strings [[(instruction), (dest), (src)],[(instruction2), (dest2), (src2)]])
#for instrList in revInstrListList:


