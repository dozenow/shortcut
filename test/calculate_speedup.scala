import scala.io.Source

def getTime(line:String):Double = {
	val timeString = line.substring(line.lastIndexOf (" ")+1)
	val index = timeString.indexOf(".")
	val first = timeString.substring(0, index)
	val second = timeString.substring (index+1)
	var tmp = second 
	if (second.size < 6) {
		for(i <- second.size+1 to 6)
			tmp = "0" + tmp
	}
	(first+"."+tmp).toDouble

}

val lines = Source.fromFile(args(0)).getLines
var pid = 0
var start = 0.0
var end = 0.0
var start_ckpt = 0.0
var end_ckpt = 0.0
var start_live = 0.0
var end_live = 0.0

val convert = lines.map(line => line.substring(line.indexOf("]")+2))
convert.foreach ( line => { 
	if (line.startsWith("replay_full_resume_proc_from_disk time")){ 
		start = getTime(line)
	} else if (line.contains("in replay_full_ckpt_wakeup, debug")){
		//val index = line.indexOf("]") + 2
		pid = line.substring(0, line.indexOf("in")-1).toInt
	} else if (line.startsWith ("replay_full_ckpt_wakeup from_disk starts")) {
		//start_ckpt = getTime(line)
		start_ckpt =start
	} else if (line.startsWith("replay_full_resume_proc_from_disk end time")) {
		end_ckpt = getTime(line)
	} else if (line.startsWith("go_live_recheck start time with gid")) {
		start_live = getTime(line)
	} else if (line.startsWith("go_live_recheck end time")) {
		end_live = getTime (line)
		end = end_live
		//println (pid+","+start + "," + end + "," + start_ckpt + "," + end_ckpt + "," + start_live + "," + end_live + ",")
		println (pid+","+(end-start) + "," + (end_ckpt - start_ckpt) + "," + (end_live - start_live))
	}
})
