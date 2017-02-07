for i in $(seq $1 $2)
do 
	echo $i
	./resume /replay_logdb/rec_$i --pthread /home/dozenow/omniplay/eglibc-2.15/prefix/lib --ckpt_at=940
done


