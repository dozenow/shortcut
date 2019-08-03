#!/bin/bash
FILES=/replay_logdb/rec_$1/ckpt.*.ckpt_mmap.*
for file in $FILES
do
	diff /replay_logdb/rec_$1/${file##*/} /replay_logdb/rec_$2/${file##*/}
	if [ $? != 0 ]; then
		#xdelta delta /replay_logdb/rec_$1/${file##*/} /replay_logdb/rec_$2/${file##*/} /tmp/${file##*/}
		diff -y  --suppress-common-lines <(od -An -tx1 -w1 -v /replay_logdb/rec_$1/${file##*/})    <(od -An -tx1 -w1 -v /replay_logdb/rec_$2/${file##*/}) | grep -v ^@ | wc -l
	fi
done



