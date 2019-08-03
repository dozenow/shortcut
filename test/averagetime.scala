import scala.io.Source

val lines = Source.fromFile("/home/dozenow/omniplay/test/m").getLines
var count = 0D
var sum = 0D
lines.foreach (s=> {
	if (s.startsWith("real"	)) {
		count += 1
		val start = s.indexOf("m")
		val end = s.indexOf ("s", start)
		sum += s.substring (start + 1, end).toDouble
	}
})
println (sum/count)

