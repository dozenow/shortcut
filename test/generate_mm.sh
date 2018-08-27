for i in $(seq $1 $2)
do 
	echo $i
	./parsecheckpoint /replay_logdb/rec_$i/ckpt.* 
done


