import scala.io.Source
import sys.process._

val lines = Source.fromFile ("ckpt_clocks").getLines
lines.foreach (s => {
	val split = s.split(",")
	val group_id = split(0).toLong
	val clock = split(1).toLong
	println (group_id + ":" + clock)
	val add_command = "./parseckpt /replay_logdb/rec_" + group_id + " -a " + clock
	println ("####Excuting " + add_command)
	add_command!!;

})
