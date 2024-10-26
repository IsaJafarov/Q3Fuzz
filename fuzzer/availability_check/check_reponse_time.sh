#!/bin/bash

# this script runs on an honest client's machine

server_addresses=("fuzzserver1" "fuzzserver2")

while true;
do

    for server_address in "${server_addresses[@]}"; do
        
        response=$(curl -k --http3-only -s -w '%{http_code} %{time_total}' -o /dev/null https://"$server_address")

        http_code=$(echo "$response" | awk '{print $1}')
        response_time=$(echo "$response" | awk '{print $2}')
        response_time_ms=$(printf "%.0f" "$(echo "$response_time * 1000" | bc -l)")

        #echo $http_code
        #echo $


        if [[ "$http_code" -ne 200 || "$response_time_ms" -gt 10000 ]]; then
            echo "$server_address server unavailable at $(date). HTTP code=$http_code. Response time=$response_time_ms ms"
        #else
            #echo all good
        fi
    done

    sleep 1
done