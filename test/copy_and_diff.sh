#!/bin/bash
#$1 is the first record group id and $2 is the first record pid; $3 is the second group id and $4 is the secnod record pid

for i in /replay_logdb/rec_$1/ckpt.*.$2.ckpt_mmap.*; do cp $i /tmp/base1/$(echo ${i##*/} | sed 's/'"$2"'//g'); done

for i in /replay_logdb/rec_$3/ckpt.*.$4.ckpt_mmap.*; do cp $i /tmp/base2/$(echo ${i##*/} | sed 's/'"$4"'//g'); done

for i in /tmp/base1/ckpt.226351.*; do mv $i /tmp/base1/$(echo ${i##*/} | sed 's/226351//g'); done
for i in /tmp/base2/ckpt.226273.*; do mv $i /tmp/base2/$(echo ${i##*/} | sed 's/226273//g'); done

FILES=/tmp/base1/*
for file in $FILES
do
	diff /tmp/base1/${file##*/} /tmp/base2/${file##*/}
	if [ $? != 0 ]; then
		diff -y  --suppress-common-lines <(od -An -tx1 -w1 -v /tmp/base1/${file##*/})    <(od -An -tx1 -w1 -v /tmp/base2/${file##*/}) | grep -v ^@ | wc -l 
	fi
done



