for i in $(seq $1 $2)
do
    echo $i
#    cp /replay_logdb/rec_$i/*.c /mnt/hd/backup_exslice
#    rename /replay_logdb/rec_$i/*.c.swp /replay_logdb/rec_$i/*.c.swp.c
    rm /replay_logdb/rec_$i/*.c.d.c
done

