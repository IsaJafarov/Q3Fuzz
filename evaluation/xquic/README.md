
# Q3Fuzz 

```sh
sudo apt install -y libevent-dev lcov

cd ~/evaluation

git clone https://github.com/IsaJafarov/Q3Fuzz.git

mkdir xquic_for_q3fuzz; cd xquic_for_q3fuzz

git clone https://github.com/alibaba/xquic.git; cd xquic
git checkout ae6f7f7
git clone https://github.com/google/boringssl.git ./third_party/boringssl; cd third_party/boringssl
git checkout afd52e91
mkdir -p build; cd build
CC=gcc CXX=g++ cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make -j2 ssl crypto
cd ../../..
git submodule update --init --recursive
cp ../../Q3Fuzz/servers_setup/certs/prett3.com.crt server.crt
cp ../../Q3Fuzz/servers_setup/certs/prett3.com.key server.key
cp /usr/local/nginx/html/index.html ./
mkdir -p build; cd build

CC=gcc CXX=g++ CFLAGS="--coverage" LDFLAGS="--coverage" cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=boringssl -DSSL_PATH=$(realpath ../third_party/boringssl) -DCMAKE_C_FLAGS_RELEASE="-w" -DCMAKE_CXX_FLAGS_RELEASE="-w" ..

make -j2
```


Now run the server

```sh
cd ~/evaluation/xquic_for_q3fuzz/xquic;
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/xquic_for_q3fuzz/xquic/ --rc lcov_branch_coverage=1;
sudo rm /home/ubuntu/evaluation/coverage_log.txt;
INTERVAL=300
NEXT=$(( $(date +%s) + INTERVAL ))

while true; do \
    sudo timeout --signal=TERM $(( NEXT - $(date +%s) )) /home/ubuntu/evaluation/xquic_for_q3fuzz/xquic/build/demo/demo_server -p 443 -l e -L /dev/null;
	NOW=$(date +%s)
	if [ $NOW -ge $NEXT ]; then
        sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/xquic_for_q3fuzz/xquic/
        NEXT=$(( NOW + INTERVAL ))
    fi
    # if server crashed before deadline, loop restarts with remaining time
done
```



Start fuzzing
```sh
while true; do \
    python3 generation_fuzzer.py https://prett3.com ../sample_traffics/evaluation/ff_xquic_eval.pcapng ../result/evaluation/ff_xquic_eval/level_4.json -dk  ../sample_traffics/secrets.keylog -p1 -i1 -d1 -g50 -m50 -nr; \
done
```



# QUICFuzz

Build the server just like QUICFuzz on host machine and apply the patches.

```sh
sudo apt install -y libevent-dev
cd evaluation

git clone https://github.com/QUICTester/QUIC-Fuzz.git

mkdir xquic_for_quicfuzz; cd xquic_for_quicfuzz

git clone https://github.com/alibaba/xquic.git; cd xquic
git checkout ae6f7f7
git clone https://github.com/google/boringssl.git ./third_party/boringssl; cd third_party/boringssl
git checkout afd52e91
git apply ../../../../QUIC-Fuzz/dockerFiles/xquic/boringssl.patch
mkdir -p build; cd build
CC=gcc CXX=g++ cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make -j2 ssl crypto

cd ../../..
git submodule update --init --recursive
git apply ../../QUIC-Fuzz/dockerFiles/xquic/xquic.patch
mkdir -p build; cd build

CC=gcc CXX=g++ CFLAGS="--coverage" LDFLAGS="--coverage" cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=boringssl -DSSL_PATH=$(realpath ../third_party/boringssl) -DCMAKE_C_FLAGS_RELEASE="-w" -DCMAKE_CXX_FLAGS_RELEASE="-w" ..

make -j2

# the path instructs the test_server to use /tmp/secrets/serverCert/xquic.crt and /tmp/secrets/serverCert/xquic.key
mkdir -p /tmp/secrets/serverCert
cp ../../../QUIC-Fuzz/dockerFiles/xquic/xquic.crt /tmp/secrets/serverCert/
cp ../../../QUIC-Fuzz/dockerFiles/xquic/xquic.key /tmp/secrets/serverCert/

# if you are running demo_server, put the cert file in the xquic folder
cd ..
cp ../../QUIC-Fuzz/dockerFiles/xquic/xquic.crt ./server.crt
cp ../../QUIC-Fuzz/dockerFiles/xquic/xquic.key ./server.key
```


Setup the docker container on the attacking machine

```sh
git clone https://github.com/QUICTester/QUIC-Fuzz.git

cd QUIC-Fuzz/dockerFiles/xquic/

# build image
sudo docker build -t quicfuzz_xquic . # on sidekick
# docker build --network=host -t quicfuzz_xquic . # on fuzzservers

# create container
sudo docker run --network host -it --name quicfuzz_xquic quicfuzz_xquic bash # network=host so that it can send messages to remote machines too

# start container
sudo docker start quicfuzz_xquic

# spawn a shell inside docker
sudo docker exec -it quicfuzz_xquic bash
```

Set up the *replayer* script. It will run on the attacking machine, extract test inputs from the docker container and replay them to the web server running on the host machine.

```sh
#!/bin/bash

CONTAINER_ID="quicfuzz_xquic"
CONTAINER_QUEUE="/tmp/xquic/xquic_out_enc_sync_snap_24h/replayable-queue"
PROCESSED_FILE="./$CONTAINER_ID"_processed_testcases.txt
TARGET_IP="10.20.20.217"
TARGET_PORT="443"
LOCAL_PORT=$((49152 + RANDOM % 16384))
# The binary has be executed from the xquic directory. Otherwise, it crashes.
SERVER_RUN_CMD="tmux send-keys -t server 'cd /home/ubuntu/evaluation/xquic_for_quicfuzz/xquic; sudo timeout --signal=TERM 2 ./build/demo/demo_server -p $TARGET_PORT -l e -L /dev/null' C-m 2>/dev/null"

rm "$PROCESSED_FILE"; touch "$PROCESSED_FILE"

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


Start measering coverage every 5 minutes on the host machine
```sh
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/xquic_for_quicfuzz/xquic/ --rc lcov_branch_coverage=1; \
sudo rm /home/ubuntu/evaluation/coverage_log.txt; \
while true; do sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/xquic_for_quicfuzz/xquic/; sleep 300; done
```


Start fuzzer inside the QUICFuzz docker container.

```sh
# with encryption module + Synchronisation + Snapshot
./run quic-fuzz/aflnet xquic_out_enc_sync_snap_24h '-a /tmp/quic-fuzz/aflnet/sabre -A /tmp/quic-fuzz/aflnet/libsnapfuzz.so -p -1 -y -m none -b 1 -P QUIC -q 3 -s 3 -E -K' 86400 5
```

Run the *replayer* script on the attacking machine.
```sh
sudo bash replay.sh
```