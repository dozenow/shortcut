import scala.io.Source
import sys.process._

for (i <- args(0).toInt to args(1).toInt) {
	val add_command = "./parseckpt /replay_logdb/rec_" + i
	val add_results = add_command!!;
	if (add_results.contains ("record filename: /usr/lib/gcc/i686-linux-gnu/4.6/cc1")) {
		var command = ""
		add_results.split ("\n").toList.filter(_.startsWith("Argument ")).foreach ( s => {
			command += s.split(" ")(3) + " "
		})
		println ("~/omniplay/scripts/easy_launch.sh " + command)
	}
}

