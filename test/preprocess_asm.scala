import scala.io.Source
import scala.collection.mutable.Queue

//replace registers with meaning full name
//replace memory address if necessary (TODO: currently, replace aggressively, which means even if base/index registers are neither tainted, we still use base+index addressing mode, even though immediate addressing mode is better)
object PreProcess {
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
		case _ => throw new Exception ()
	}
	def rewriteInst (s:String):String = {
		if (s == null) return null
		if (s.contains ("#push") || s.contains ("#pop")) { 
			val index = s.indexOf("_mem[")
			val memParams = s.substring (index+5, s.indexOf("]", index)).split(":")
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
			assert (jumpMap.contains(inst))
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


	def main (args:Array[String]):Unit = {
		var lastLine:String = null
		val lines = Source.fromFile("m2").getLines().toList 
		val buffer = new Queue[String]()
		//first round: process all SLICE_EXTRA : TODO merge two rounds
		for (i <- 0 to lines.length - 1) {
			val s = lines.apply (i)
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
						val immAddress = s.substring(s.indexOf("$addr(") + 6, s.indexOf(")"))
						var memPtrIndex = lastLine.indexOf (" ptr ", lastLine.indexOf (" ptr [0x"))
						var memPtrEnd = lastLine.indexOf ("]", memPtrIndex)
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
		//println (lastLine)
		buffer += lastLine
		//second round
		//write out headers
		println	(".intel_syntax noprefix")
		println (".section	.text")
   		println (".globl _start")
		println ("_start:")

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
			} else {
				println ("/*" + s + "*/")
			}
		})
		println ("ret")
	}

	//register list from PIN
	//Make it more complete as we need
	val regMap = Map(
		"(3,4)" -> "edi",
		"(4,4)" -> "esi",
		"(5,4)"-> "ebp",
		"(6,4)" -> "esp",
		"(7,4)" -> "ebx",
		"(8,4)" -> "edx",
		"(9,4)" -> "ecx",
		"(10,4)" -> "eax"
	)
	val jumpMap = Map (
		"jns" -> "js",
		"jnz" -> "jz",
		"jz" -> "jnz"
		)
	
}
