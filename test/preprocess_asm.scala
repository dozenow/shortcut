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

	def main (args:Array[String]):Unit = {
		var lastLine:String = null
		val lines = Source.fromFile("m2").getLines().toList 
		val buffer = new Queue[String]()
		//first round: process all SLICE_EXTRA : TODO merge two rounds
		for (val i <- 0 to lines.length - 1) {
			val s = lines.apply (i)
			val index = s.indexOf ("$reg(")
			if (index > 0) { 
				//replace reg
				val lastIndex = s.indexOf (")", index +1)
				val regIndex = s.substring (index + 4, lastIndex + 1)
				if (regMap.contains (regIndex)) {
					val out = s.replace (s.substring (index, lastIndex + 1), regMap(regIndex))
					//println (out)
					buffer += out
				} else 
					System.err.println ("cannot find corresponding reg!!!!!!.")
			} else {
				//replace mem
				val addrIndex = s.indexOf ("$addr(")
				if (addrIndex > 0) { 
					//println (lastLine)
					//copy the original slice code's addressing mode
					assert (lastLine.indexOf (" ptr " ) > 0)
					//I haven't handled the case where more than one operand is mem
					assert (lastLine.indexOf (" ptr " ) == lastLine.lastIndexOf(" ptr "))
					assert (lastLine.startsWith ("[SLICE]"))
					val inst = lastLine.substring(0, lastLine.indexOf("[SLICE_INFO]")).split("#")(2)
					val operands = inst.substring (inst.indexOf(" ") + 1).split(",")
					//special case: to avoid affecting esp, we change pos/push to mov
					//special case: if inst is mov and mem operand is dst operand, there is no need to initialize this address
					if (ins.startsWith ("mov ") && operands(0).containts("ptr")) {
						buffer += "/*Eliminated SLICE_EXTRA" + s + "*/\n"
					} else {
						operands.foreach (op => { 
							if(op.contains ("ptr")) {
								val out = s.replace (s.substring(addrIndex, s.indexOf(")", addrIndex + 1) + 1), op)
								//println (out)
								buffer += out
							}
						})
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
		//switch posistion and generate compilable assembly
		//println ("**************************")
		val extraLines = new Queue[String]()
		buffer.foreach (s => { 
			//SLICE_ADDRESSING comes first, then SLICE_EXTRA then SLICE
			if (s.startsWith ("[SLICE_EXTRA]")) {
				extraLines += s
			} else if (s.startsWith("[SLICE]")) {
				while (extraLines.size > 0) 
					println (cleanupExtraline(extraLines.dequeue()))
				println (cleanupSliceLine(s))
			} else if (s.startsWith("[SLICE_ADDRESSING]")) {
				println (cleanupAddressingLine(s))
			} else {
				println ("/*" + s + "*/")
			}
		})
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
	
}
