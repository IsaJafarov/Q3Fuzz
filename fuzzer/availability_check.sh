while true;
do
    response=$(curl -k --http3-only -s -w '%{http_code} %{time_total}' -o /dev/null https://prett3.com)

    http_code=$(echo "$response" | awk '{print $1}')
    response_time=$(echo "$response" | awk '{print $2}')
    response_time_ms=$(printf "%.0f" "$(echo "$response_time * 1000" | bc -l)")

    #echo $http_code
    #echo $response_time_ms


    if [[ "$http_code" -ne 200 || "$response_time_ms" -gt 10000 ]]; then
        echo "Server unavailable at $(date)"
    #else
        #echo all good
    fi
    sleep 1
done