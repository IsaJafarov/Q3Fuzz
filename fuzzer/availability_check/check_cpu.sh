#!/bin/bash

# this script runs on the target server

while true;
do
	cpu=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else print ($2+$4-u1) * 100 / (t-t1); }' <(grep 'cpu ' /proc/stat) <(sleep 1;grep 'cpu ' /proc/stat));

	#echo $cpu

	if (( $(echo "$cpu > 20" | bc -l) )); then
  		echo "CPU reached $cpu% at $(date)"
		top -b -n 1 | grep -E "CPU|caddy|nginx|h2o|litespeed"
		echo
    fi
done