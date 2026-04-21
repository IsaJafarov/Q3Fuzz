

# Q3Fuzz

Build the server
```sh
# install some dependencies
sudo apt update && sudo apt install -y golang-go zlib1g-dev libevent-dev lcov

cd ~/evaluation
git clone https://github.com/QUICTester/QUIC-Fuzz.git
git clone git@github.com:IsaJafarov/Q3Fuzz.git

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

Now run the server

```bash
cd ~/evaluation/;
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/lsquic_for_q3fuzz/lsquic/ --rc lcov_branch_coverage=1;
sudo rm coverage_log.txt;
INTERVAL=300
NEXT=$(( $(date +%s) + INTERVAL ))

while true; do \

    sudo timeout --signal=USR1 $(( NEXT - $(date +%s) )) /home/ubuntu/evaluation/lsquic_for_q3fuzz/lsquic/bin/http_server -s 0.0.0.0:443 -c prett3.com,/home/ubuntu/Q3Fuzz/servers_setup/certs/prett3.com.pem,/home/ubuntu/Q3Fuzz/servers_setup/certs/prett3.com.key -r /usr/local/nginx/html/; \

	NOW=$(date +%s)
	if [ $NOW -ge $NEXT ]; then
        sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/lsquic_for_q3fuzz/lsquic/
        NEXT=$(( NOW + INTERVAL ))
    fi
    # if server crashed before deadline, loop restarts with remaining time
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

Build the server just like QUICFuzz on host machine and apply the patches.

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

Setup the docker container on the attacking machine.

```sh
git clone https://github.com/QUICTester/QUIC-Fuzz.git

cd QUIC-Fuzz/dockerFiles/lsquic/

# build image
sudo docker build -t quicfuzz_lsquic . # if you face connection issues, try adding --network=host

# create container
sudo docker run --network host -it --name quicfuzz_lsquic quicfuzz_lsquic bash # network=host so that it can send messages to remote machines too

# start container
sudo docker start quicfuzz_lsquic

# spawn a shell inside docker
sudo docker exec -it quicfuzz_lsquic bash
```

Set up the *replayer* script. It will run on the attacking machine, extract test inputs from the docker container and replay them to the web server running on the host machine.

```sh
#!/bin/bash

CONTAINER_ID="quicfuzz_lsquic"
CONTAINER_QUEUE="/tmp/lsquic/lsquic_out_enc_sync_snap_24h/replayable-queue"
PROCESSED_FILE="./$CONTAINER_ID"_processed_testcases.txt
TARGET_IP="10.20.20.130"
TARGET_PORT="443"
LOCAL_PORT=$((49152 + RANDOM % 16384))
SERVER_RUN_CMD="tmux send-keys -t server 'sudo timeout --signal=USR1 2 /home/ubuntu/evaluation/lsquic_for_quicfuzz/lsquic/bin/http_server -s 0.0.0.0:$TARGET_PORT -c ,/home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/lsquic/server-cert.pem,/home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/lsquic/server-key.pem -r /usr/local/nginx/html/ -Q hq-29' C-m 2>/dev/null"

rm "$PROCESSED_FILE"
touch "$PROCESSED_FILE"

echo "Processing test cases from container..."

# when you replay messages to port 443 inside docker, docker should forward it to host 443
docker exec "$CONTAINER_ID" bash -c "which socat || apt install -y socat"
docker exec "$CONTAINER_ID" bash -c "socat -d -d UDP4-RECVFROM:$LOCAL_PORT,reuseaddr,fork UDP4-SENDTO:$TARGET_IP:$TARGET_PORT &"

while true; do

    # Get list of +cov files from container
    files=$(docker exec "$CONTAINER_ID" bash -c "ls $CONTAINER_QUEUE/*+cov 2>/dev/null" | sort)

	for file in $files; do

	    filename=$(basename "$file")

	    # Skip if already processed
	    if grep -Fxq "$filename" "$PROCESSED_FILE"; then
	        continue
	    fi

	    echo "  Processing: $filename"

		# Restart server on host
	    echo "  Running server..."
		ssh -i /home/isa/.ssh/id_rsa ubuntu@"$TARGET_IP" $SERVER_RUN_CMD
		sleep 1;

	    # Replay from inside container using aflnet-replay
	    echo "  Replaying..."
	    docker exec "$CONTAINER_ID" /tmp/quic-fuzz/aflnet/aflnet-replay "$file" QUIC $LOCAL_PORT
	    sleep 2;

	    # Mark as processed
	    echo "$filename" >> "$PROCESSED_FILE"

	    echo "  Done"
	done;

done

echo "All test cases processed"
```

## Run

Start measering coverage every 5 minutes on the host machine

```sh
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/lsquic_for_quicfuzz/lsquic/ --rc lcov_branch_coverage=1; \
sudo rm coverage_log.txt; \
while true; do sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/lsquic_for_quicfuzz/lsquic/; sleep 300; done
```

Start fuzzer inside the QUICFuzz docker container.

```sh
./run quic-fuzz/aflnet lsquic_out_enc_sync_snap_24h '-a /tmp/quic-fuzz/aflnet/sabre -A /tmp/quic-fuzz/aflnet/libsnapfuzz.so -p -1 -m none -y -b 1 -P QUIC -q 3 -s 3 -E -K' 86400 5
```

Run the *replayer* script on the attacking machine.
```sh
sudo bash replay.sh
```
