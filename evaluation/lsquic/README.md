

# Q3Fuzz

Build the server
```sh
# install some dependencies
sudo apt update && sudo apt install -y golang-go zlib1g-dev libevent-dev lcov

cd ~/evaluation
git clone https://github.com/QUICTester/QUIC-Fuzz.git
git clone git@github.com:IsaJafarov/PRETT3.git

# install Boringssl
mkdir lsquic_for_q3fuzz; cd lsquic_for_q3fuzz
git clone https://boringssl.googlesource.com/boringssl
cd ./boringssl
git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd
CC=gcc CXX=g++ cmake -DCMAKE_C_FLAGS="-Wno-unused-result" -DCMAKE_CXX_FLAGS="-Wno-unused-result" -DCMAKE_BUILD_TYPE=Release .
make -j2


# install the server
cd ..
git clone https://github.com/litespeedtech/lsquic.git
cd lsquic
git checkout c4f359f
git submodule update --init
CC=gcc CXX=g++ CFLAGS="--coverage" LDFLAGS="--coverage" cmake -DCMAKE_BUILD_TYPE=Release -DBORINGSSL_DIR=$(realpath ../boringssl) .
make clean all -j2
```

Run the server to generate SM
```sh
sudo ./bin/http_server -s 0.0.0.0:443 -c prett3.com,$(realpath ../../PRETT3/servers_setup/certs/prett3.com.pem),$(realpath ../../PRETT3/servers_setup/certs/prett3.com.key) -r /usr/local/nginx/html/
```

Put a sample *favicon.ico* file in the document root. Otherwise, when you request it, the server will crash. Stupid server.

Generate traffic: *ff_n_lsquic_eval.pcapng* and *ff_n_lsquic_eval.keylog*

Reset the coverage and run the server. Preferably, run in a `tmux` session

```bash
cd ~/evaluation/; \
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/lsquic_for_q3fuzz/lsquic/ --rc lcov_branch_coverage=1; \
sudo rm coverage_log.txt; \
while true; do \
    sudo timeout --signal=USR1 300 /home/ubuntu/evaluation/lsquic_for_q3fuzz/lsquic/bin/http_server -s 0.0.0.0:443 -c prett3.com,/home/ubuntu/evaluation/PRETT3/servers_setup/certs/prett3.com.pem,/home/ubuntu/evaluation/PRETT3/servers_setup/certs/prett3.com.key -r /usr/local/nginx/html/; \
    if [ $? -eq 124 ]; then sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/lsquic_for_q3fuzz/lsquic/; fi; \
done
```

Start fuzzing
```sh
while true; do \
    python3 generation_fuzzer.py https://prett3.com ../sample_traffics/evaluation/ff_lsquic_eval.pcapng ../result/evaluation/ff_lsquic_eval/level_4.json -dk  ../sample_traffics/secrets.keylog -p1 -i1 -d1 -g50 -m50 -nr; \
done
```


# QUICFuzz

## Setup

Build server

```sh
# install go
sudo apt update && sudo apt install -y golang-go zlib1g-dev

cd ~/evaluation
git clone https://github.com/QUICTester/QUIC-Fuzz.git

# install Boringssl
mkdir lsquic_for_quicfuzz; cd lsquic_for_quicfuzz/
git clone https://boringssl.googlesource.com/boringssl
cd ./boringssl
git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd
git apply ../../QUIC-Fuzz/dockerFiles/lsquic/boringssl.patch
CC=gcc CXX=g++ cmake -DCMAKE_C_FLAGS="-Wno-unused-result" -DCMAKE_CXX_FLAGS="-Wno-unused-result" -DCMAKE_BUILD_TYPE=Release .
make -j2

# install the server
cd ..
git clone https://github.com/litespeedtech/lsquic.git
cd lsquic
git checkout c4f359f
git submodule update --init
git apply ../../QUIC-Fuzz/dockerFiles/lsquic/lsquic.patch
CC=gcc CXX=g++ CFLAGS="--coverage" LDFLAGS="--coverage" cmake -DCMAKE_BUILD_TYPE=Release -DBORINGSSL_DIR=$(realpath ../boringssl) .
make clean all -j2
```

Set up docker container
```sh
git clone https://github.com/QUICTester/QUIC-Fuzz.git

cd QUIC-Fuzz/dockerFiles/lsquic/

# build image
sudo docker build -t quicfuzz_lsquic . # if you face connection issues, try adding --network=host

# create container
sudo docker run --network host -it --name quicfuzz_lsquic_1 quicfuzz_lsquic bash # network=host so that it can send messages to remote machines too

# start container
sudo docker start quicfuzz_lsquic_1

# spawn a shell inside docker
sudo docker exec -it quicfuzz_lsquic_1 bash
```

Update **replayX.sh** scripts
```sh
#!/bin/bash

CONTAINER_ID="quicfuzz_lsquic_10"
CONTAINER_QUEUE="/tmp/lsquic/lsquic_out_enc_sync_snap_24h/replayable-queue"
SERVER_BINARY="/home/ubuntu/evaluation/lsquic_for_quicfuzz/lsquic/bin/http_server"
CERT_FILE="/home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/lsquic/server-cert.pem"
KEY_FILE="/home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/lsquic/server-key.pem"
SO_FILE="/home/ubuntu/evaluation/covdump_1sec.so"
PROCESSED_FILE="./$CONTAINER_ID"_processed_testcases.txt
TARGET_IP="10.20.20.93"
TARGET_PORT="443"
LOCAL_PORT=$((49152 + RANDOM % 16384))
TMUX_PANEL="server"

rm "$PROCESSED_FILE"
touch "$PROCESSED_FILE"

echo "Processing test cases from container..."

# when you replay messages to port 443 inside docker, docker should forward it to host 443
docker exec "$CONTAINER_ID" bash -c "apt install -y socat"
docker exec "$CONTAINER_ID" bash -c "socat -d -d UDP4-RECVFROM:$LOCAL_PORT,reuseaddr,fork UDP4-SENDTO:$TARGET_IP:$TARGET_PORT &"

while true; do

# Get list of +cov files from container
files=$(docker exec "$CONTAINER_ID" bash -c "ls $CONTAINER_QUEUE/*+cov 2>/dev/null" | sort)

total=$(echo "$files" | wc -l)
count=0

	for file in $files; do
	    count=$((count + 1))
	    filename=$(basename "$file")
	    
	    # Skip if already processed
	    if grep -Fxq "$filename" "$PROCESSED_FILE"; then
	        continue
	    fi
	    
	    echo "[$count/$total] Processing: $filename"
	    
	    # Restart server on host
	    echo "  Restarting server..."
	    ssh -i /home/isa/.ssh/id_rsa ubuntu@"$TARGET_IP" "tmux send-keys -t $TMUX_PANEL C-c 2>/dev/null"
	    sleep 0.5
	    ssh -i /home/isa/.ssh/id_rsa ubuntu@"$TARGET_IP" "tmux send-keys -t $TMUX_PANEL 'sudo env LD_PRELOAD=$SO_FILE ./bin/http_server -Q hq-29 -s 0.0.0.0:443 -c www.example.com,$CERT_FILE,$KEY_FILE' C-m 2>/dev/null"
	    sleep 1.6
	    
	    # Replay from inside container using aflnet-replay
	    echo "  Replaying..."
	    docker exec "$CONTAINER_ID" /tmp/quic-fuzz/aflnet/aflnet-replay "$file" QUIC $LOCAL_PORT
	    sleep 1.6
	    
	    # Mark as processed
	    echo "$filename" >> "$PROCESSED_FILE"
	    
	    echo "  Done"
	done;
	sleep 0.5
done

echo "All test cases processed: $count"
```

## Run

Start the server
```sh
$ tmux attach -t server

$ cd ~/evaluation/lsquic_for_quicfuzz/lsquic

$ sudo lcov --zerocounters --directory . --rc lcov_branch_coverage=1

$ sudo env LD_PRELOAD=../../covdump_1sec.so ./bin/http_server -Q hq-29 -s 0.0.0.0:443 -c www.example.com,/home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/lsquic/server-cert.pem,/home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/lsquic/server-key.pem
```

Start logging the coverage
```sh
cd ~/evaluation

sudo bash covrecord.sh lsquic_for_prett3/lsquic/
```

Start the replayX.sh script
```sh
sudo bash replayX.sh
```



Start the fuzzer inside the container
```sh
tmux new -s quicfuzz_lsquic_3

sudo docker exec -it quicfuzz_lsquic_3 bash

./run quic-fuzz/aflnet lsquic_out_enc_sync_snap_24h '-a /tmp/quic-fuzz/aflnet/sabre -A /tmp/quic-fuzz/aflnet/libsnapfuzz.so -p -1 -m none -y -b 1 -P QUIC -q 3 -s 3 -E -K' 86400 5
```