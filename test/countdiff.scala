import sys.process._
println ("starting..")
for(i <- (args(0).toInt + 1) to args(1).toInt) {
	val command = "/home/dozenow/omniplay/test/diff.sh " + args(0) + " " + i 
	println ("executing " + command) 
	val result = command!!
	val lines = result.split("\n").toList
	var count = 0
	lines.foreach (s => {
		if (s.startsWith ("Binary")) {
			
		} else { 
			count += s.toInt
		}
	})
	println (count)
}

