/*#!/bin/sh
exec scala "$0" "$@"
!#*/

import scala.io.Source
import scala.collection.mutable.Queue

//replace registers with meaning full name
//replace memory address if necessary 
object preprocess_asm {
	class AddrToRestore (val loc:String, val isImm:Int, val size:Int)
	def cleanupSliceLine (s:String):String = {
		val strs = s.substring(0, s.indexOf("[SLICE_INFO]")).split("#")
		strs(2) + "   /* [ORIGINAL_SLICE] " +  strs(1)  + " " + s.substring(s.indexOf("[SLICE_INFO]")) + "*/"
	}
	def cleanupExtraline (s:String):String = s.substring(s.indexOf("]") + 2, s.indexOf("//")) + " /* [SLICE_EXTRA]" + s.substring(s.indexOf("//")) + "*/"
	def cleanupAddressingLine (s:String):String = s.substring(s.indexOf("]") + 2, s.indexOf("//")) + " /* [SLICE_ADDRESSING]" + s.substring(s.indexOf("//")) + "*/"
	def memSizeToPrefix(size:Int) = size match {
		case 1 => " byte ptr "
		case 2 => " word ptr "
		case 4 => " dword ptr "
		case 16 => " xmmword ptr "
		case _ => {
			println ("unrecognized mem size " + size)
			throw new Exception ()
		}
	}
	def rewriteInst (s:String):String = {
		if (s == null) return null
		if (s.contains ("#push") || s.contains ("#pop")) { 
			val index = s.indexOf("_mem[")
			val memParams = s.substring (index+5, s.indexOf("]", index)).split(":")
			if (memParams.size != 3) println (s)
			val addr = memParams(0)
			val size = memParams(2)
			var newInst:String = null
			if (s.contains("#push")) { 
				val tmp = s.replace ("#push ", "#mov " + memSizeToPrefix(size.toInt) + "[" + addr + "], ") 
				return tmp.replace ("[SLICE_INFO]", "[SLICE_INFO] push instruction (rewrite)")
			} 
			if (s.contains ("#pop")) { 
				val tmp = s.replace ("#pop ", "#mov ")
				return tmp.replace ("    [SLICE_INFO]", ", " + memSizeToPrefix(size.toInt) + "[" + addr + "]    [SLICE_INFO] pop instruction(rewrite)")
			}
		} else if (s.contains ("#j")) { //change jump instruction
			val index = s.indexOf ("#j")		
			val spaceIndex = s.indexOf (" ", index)
			val inst = s.substring (index +1, spaceIndex)
			val address = s.substring (spaceIndex + 1, s.indexOf (" ", spaceIndex + 1))
			//assert (jumpMap.contains(inst))
			if (s.contains ("branch_taken 1")) //if the original branch is taken, then we jump to error if not taken as before
				return s.replace (inst, jumpMap(inst)).replace(address, "0x0000004")
			else if (s.contains ("branch_taken 0")) 
				return s.replace(address, "0x0000000")
			else 
				assert (false)
		}
		s
	}
	def replaceReg (s:String):String = {
		val index = s.indexOf ("$reg(")
		if (index > 0) { 
			//replace reg
			val lastIndex = s.indexOf (")", index +1)
			val regIndex = s.substring (index + 4, lastIndex + 1)
			if (regMap.contains (regIndex)) {
				val out = s.replace (s.substring (index, lastIndex + 1), regMap(regIndex))
				//println (out)
				return out
			} else  {
				System.err.println ("cannot find corresponding reg!!!!!!.")
				println (s)
				assert (false)
			}
		} 
		return null
	}

	def replaceMem (s:String, instStr:String):String = {
		if (s.contains("$addr(")) {
			val addrIndex = s.indexOf("$addr(")
			//replace the mem operand in this line
			//copy the original slice code's addressing mode
			assert (instStr.indexOf (" ptr " ) > 0)
			//I haven't handled the case where more than one operand is mem
			assert (instStr.indexOf (" ptr " ) == instStr.lastIndexOf(" ptr "))
			assert (instStr.startsWith ("[SLICE]"))
			val inst = instStr.substring(0, instStr.indexOf("[SLICE_INFO]")).split("#")(2)
			val operands = inst.substring (inst.indexOf(" ") + 1).split(",")
			var out = ""
			//println ("replaceMem: " + instStr + ", " + s + ", " + operands)
			//replace address with base+index registers
			operands.foreach (op => { 
				//println ("replaceMem: " + op)
				if(op.contains ("ptr")) {
					out = s.replace (s.substring(addrIndex, s.indexOf(")", addrIndex + 1) + 1), op)
				}
			})
			return out
		}
		return s
	}
	def parseRestoreAddress (s:String):AddrToRestore = {
		val index = s.indexOf(":")
		val strs = s.substring(index + 2).split(", ")
		new AddrToRestore (strs(0), strs(1).toInt, strs(2).toInt)
	}

	def main (args:Array[String]):Unit = {
		var lastLine:String = null
		val lines = Source.fromFile(args(0)).getLines().toList 
		val buffer = new Queue[String]()
		val restoreAddress = new Queue[AddrToRestore]()
		val restoreReg = new Queue[String]()
		var totalRestoreSize = 0
		//first round: 1. process all SLICE_EXTRA : TODO merge two round maybe
		//2. convert instructions if necessary
		//3. get all mem addresses we need to restore
		for (i <- 0 to lines.length - 1) {
			val s = lines.apply (i)
			if (s.startsWith ("[SLICE_RESTORE_ADDRESS]")) {
				val tmp =  parseRestoreAddress(s)
				restoreAddress += tmp
				totalRestoreSize += tmp.size
			} else if (s.startsWith("[SLICE_RESTORE_REG]")) {
				val index = s.indexOf("$reg(")
				assert (index > 0)
				restoreReg += regMap(s.substring(index+4, s.indexOf (")", index+1)+1))
				totalRestoreSize += 4
			} else {
				val regStr = replaceReg (s)
				//special case: to avoid affecting esp, we change pos/push to mov instructions
				lastLine = rewriteInst(lastLine)

				if (regStr != null)  {
					//replace reg
					buffer += regStr
				} else {
					//replace mem
					val addrIndex = s.indexOf ("$addr(")
					if (addrIndex > 0) { 
						//println (lastLine)
						if (s.contains ("immediate_address ")) {
							//replace the mem operand in the SLICE instead of this line
							val immAddressIndex = s.indexOf("$addr(")
							if (immAddressIndex == -1 || s.indexOf (")") == -1) {
								println (s)
							}
							val immAddress = s.substring(immAddressIndex + 6, s.indexOf(")"))
							var memPtrIndex = lastLine.indexOf (" ptr ", lastLine.indexOf (" ptr [0x"))
							var memPtrEnd = lastLine.indexOf ("]", memPtrIndex)
							if (memPtrIndex == -1 || memPtrEnd == -1) {
								println ("line " + i + ":" + lastLine)
								assert (false)
							}
							lastLine = lastLine.substring(0, memPtrIndex) + " ptr [" + immAddress + lastLine.substring(memPtrEnd)

							buffer += s
						} else {
							//replace the mem operand in this line later
							buffer += s
						}
					} else 
						if(lastLine != null) {
							//println (lastLine)
							buffer += lastLine
						}

				}
				if(s.startsWith ("[SLICE]"))
					lastLine = s
			}
		}
		//println (lastLine)
		buffer += lastLine
		assert (totalRestoreSize < 65536) //currently we only allocated 65536 bytes for this restore stack
		//second round
		//write out headers
		println	(".intel_syntax noprefix")
		println (".section	.text")
   		println (".globl _start")
		println ("_start:")
		//write out all restore address
		println ("/*first checkpoint necessary addresses and registers*/")
		restoreReg.foreach (reg => println ("push " + reg))
		restoreAddress.foreach (addr => println ("push " + memSizeToPrefix(addr.size) + "[0x" + addr.loc + "]"))
		println ("call recheck_start")

		println ("/*slice begins*/")
		//switch posistion and generate compilable assembly
		//println ("**************************")
		val extraLines = new Queue[String]()
		val immAddress = new Queue[String]() //here I can handle multiple address convertion
		buffer.foreach (s => { 
			//SLICE_ADDRESSING comes first, then SLICE_EXTRA then SLICE
			if (s.startsWith ("[SLICE_EXTRA]")) {
				extraLines += s
			} else if (s.startsWith("[SLICE]")) {
				while (extraLines.size > 0) {
					//special case: if inst is mov, the src reg/mem operand must have been tainted; and there is no need to initialize the dst operand 
					//therefore, SLICE_EXTRA is not necessary
					if (s.contains("#mov ") || s.contains("#movzx ")) {
						println ("/*Eliminated SLICE_EXTRA" + extraLines.dequeue() + "*/")
					} else 
						println (cleanupExtraline(replaceMem(extraLines.dequeue(), s)))
				}
				println (cleanupSliceLine(s))
			} else if (s.startsWith("[SLICE_ADDRESSING]")) {
				if (s.contains("immediate_address")) {
					println ("/*Eliminated " + s + "*/")
				} else {

					println (cleanupAddressingLine(s))
				}
			} else if (s.startsWith("[SLICE_VERIFICATION]")) {
				println ("/*" + s + "*/")
			} else { 
				println (s)
				assert (false)
			}
		})
		println ("/* restoring address and registers */")
		restoreAddress.reverse.foreach (addr => println ("pop " + memSizeToPrefix(addr.size) + "[0x" + addr.loc + "]"))
		restoreReg.reverse.foreach (reg => println ("pop " + reg))
		println ("/* slice finishes and return to kernel */")
		println ("mov ebx, 1")
		println ("mov eax, 350")
		println ("int 0x80")
	}

	//register list from PIN
	//Make it more complete as we need
	val regMap = Map(
		"(3,4)" -> "edi",
		"(4,4)" -> "esi",
		"(5,4)"-> "ebp",
		"(6,4)" -> "esp",
		"(7,4)" -> "ebx",
		"(7,1)" -> "bl",
		"(7,-1)" -> "bh",
		"(8,4)" -> "edx",
		"(8,1)" -> "dl",
		"(8,-1)" -> "dh",
		"(9,4)" -> "ecx",
		"(9,1)" -> "cl",
		"(9,-1)" -> "ch",
		"(10,4)" -> "eax",
		"(10,1)" -> "al",
		"(10,-1)" -> "ah"
	)
	/*val jumpMap = Map (
		"jns" -> "js",
		"js"  -> "jns",
		"jnz" -> "jz",
		"jz" -> "jnz",
		"ja" -> "jna",
		"jae" -> "jnae",
		"jb" -> "jnb",
		"jbe" -> "jnbe",
		)*/
       def jumpMap(ins:String):String = {
	       if (ins.charAt(1) == 'n')
		       "j" + ins.substring (2)
	       else 
			"jn" + ins.substring (1)
       }
	
}
