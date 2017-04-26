import scala.io.Source

//replace registers with meaning full name
//replace memory address if necessary (TODO: currently, replace aggressively, which means even if base/index registers are neither tainted, we still use base+index addressing mode, even though immediate addressing mode is better)
object PreProcess {
	def main (args:Array[String]):Unit = {
		var lastLine:String = null
		Source.fromFile("m2").getLines().foreach (s => {
			val index = s.indexOf ("$reg(")
			if (index > 0) { 
				val lastIndex = s.indexOf (")", index +1)
				val regIndex = s.substring (index + 4, lastIndex + 1)
				if (regMap.contains (regIndex)) 
					println (s.replace (s.substring (index, lastIndex + 1), regMap(regIndex)))
				else 
					System.err.println ("cannot find corresponding reg!!!!!!.")
			} else {
				val addrIndex = s.indexOf ("$addr(")
				if (addrIndex > 0) { 
					//copy the original slice code's addressing mode
					assert (lastLine.indexOf (" ptr " ) > 0)
					//I haven't handled the case where more than one operand is mem
					assert (lastLine.indexOf (" ptr " ) == lastLine.lastIndexOf(" ptr "))
					assert (lastLine.startsWith ("[SLICE]"))
					val inst = lastLine.substring(0, lastLine.indexOf("[SLICE_INFO]")).split("#")(2)
					val operands = inst.substring (inst.indexOf(" ") + 1).split(",")
					operands.foreach (op => { 
						if(op.contains ("ptr")) 
							println (s.replace (s.substring(addrIndex, s.indexOf(")", addrIndex + 1) + 1), op))
					})
				} else 
					println (s)
			}
			lastLine = s
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
