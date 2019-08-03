#!/bin/sh
exec scala -nc "$0" "$@"
!#

import scala.io.Source
import sys.process._
//ARGS: (optional) start and end group id
var start = 0L
var end = 9999999L
if (args.size == 2) { 
	start = args(0).toLong
	end = args(1).toLong
}

val lines = Source.fromFile ("ckpt_clocks").getLines
lines.foreach (s => {
	val split = s.split(",")
	val group_id = split(0).toLong
	if (group_id >= start && group_id <=end) { 
		val clock = split(1).toLong
		println (group_id + ":" + clock)
		val add_command = "./parseckpt /replay_logdb/rec_" + group_id + " -a " + clock
		println ("####Excuting " + add_command)
		add_command!!;
	}

})
