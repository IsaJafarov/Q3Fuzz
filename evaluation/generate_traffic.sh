#!/bin/bash

# Check if a parameter is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <parameter>"
    echo "Parameter can be one of: ng_n, ng_o, ols_n, ols_o, h2o_n, h2o_o, cdy_n, cdy_o"
    exit 1
fi

# Assign the parameter to a variable
server="$1"

traffics=(
    "ch_n_${server}"
    "op_n_${server}"
    "ff_n_${server}"
    "ch_o_${server}"
    "op_o_${server}"
    "ff_o_${server}"
)

# Iterate through the list
for traffic in "${traffics[@]}"; do
    echo "\n\n\n\n\n----------------------------------------------------------------------\n\n\n\n\n"
    echo "Traffic: $traffic"
    python3 prett3_syn.py https://prett3.com ./sample_traffics/"$traffic".pcapng -ok $server.keylog
    sleep 5
done
