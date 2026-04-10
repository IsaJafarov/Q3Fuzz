
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

Run
```sh
sudo ./build/tests/test_server -p 443 -l e
```

Generate simple traffic

Put `ff_xquic_eval.keylog`, `ff_xquic_eval.pcapng` and `level_4.json` in `xquic_for_prett3`

Now run the server with the shared object, so that the coverage will be recorded

```sh
cd ~/evaluation/xquic_for_q3fuzz/xquic;
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/xquic_for_q3fuzz/xquic/ --rc lcov_branch_coverage=1;
sudo rm /home/ubuntu/evaluation/coverage_log.txt;
while true; do \
    sudo timeout --signal=TERM 300 /home/ubuntu/evaluation/xquic_for_q3fuzz/xquic/build/demo/demo_server -p 443 -l e -L /dev/null; \
    if [ $? -eq 124 ]; then sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/xquic_for_q3fuzz/xquic/; fi; \
done
```

Start fuzzing
```sh
while true; do \
    python3 generation_fuzzer.py https://prett3.com ../sample_traffics/evaluation/ff_xquic_eval.pcapng ../result/evaluation/ff_xquic_eval/level_4.json -dk  ../sample_traffics/secrets.keylog -p1 -i1 -d1 -g50 -m50 -nr; \
done
```



# QUICFuzz

Build the server just like QUICFuzz on host machine and apply the patches

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

Run the patched server on host
```sh
cd ~/evaluation/xquic_for_quicfuzz/xquic;
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/xquic_for_quicfuzz/xquic/ --rc lcov_branch_coverage=1;
sudo rm /home/ubuntu/evaluation/coverage_log.txt;
while true; do \
    sudo timeout --signal=TERM 300 /home/ubuntu/evaluation/xquic_for_quicfuzz/xquic/build/demo/demo_server -p 443 -l e -L /dev/null; \
    if [ $? -eq 124 ]; then sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/xquic_for_quicfuzz/xquic/; fi; \
done
```


Setup docker container
```sh
git clone https://github.com/QUICTester/QUIC-Fuzz.git

cd QUIC-Fuzz/dockerFiles/xquic/

# build image
sudo docker build -t quicfuzz_xquic . # on sidekick
# docker build --network=host -t quicfuzz_xquic . # on fuzzservers

# create container
sudo docker run --network host -it --name quicfuzz_xquic_1 quicfuzz_xquic bash # network=host so that it can send messages to remote machines too

# start container
sudo docker start quicfuzz_xquic_1

# spawn a shell inside docker
sudo docker exec -it quicfuzz_xquic_1 bash
```

Set up the script that is going to forward traffic
```sh
#!/bin/bash

CONTAINER_ID="quicfuzz_xquic_6"
CONTAINER_QUEUE="/tmp/xquic/xquic_out_enc_sync_snap_24h/replayable-queue"
PROCESSED_FILE="./$CONTAINER_ID"_processed_testcases.txt
TARGET_IP="10.20.20.130"
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


	for file in $files; do
	    
	    filename=$(basename "$file")
	    
	    # Skip if already processed
	    if grep -Fxq "$filename" "$PROCESSED_FILE"; then
	        continue
	    fi
	    
	    echo "  Processing: $filename"
	    
	    # Replay from inside container using aflnet-replay
	    echo "  Replaying..."
	    docker exec "$CONTAINER_ID" /tmp/quic-fuzz/aflnet/aflnet-replay "$file" QUIC $LOCAL_PORT
	    sleep 0.5
	    
	    # Mark as processed
	    echo "$filename" >> "$PROCESSED_FILE"
	    
	    echo "  Done"
	    sleep 0.5
	done;
	
done

echo "All test cases processed"
```


Start fuzzing

```sh
# with encryption module + Synchronisation + Snapshot
./run quic-fuzz/aflnet xquic_out_enc_sync_snap_24h '-a /tmp/quic-fuzz/aflnet/sabre -A /tmp/quic-fuzz/aflnet/libsnapfuzz.so -p -1 -y -m none -b 1 -P QUIC -q 3 -s 3 -E -K' 86400 5
```
Make sure port 4433 is not occupied. Otherwise, you will get the following. In that case, replace 4433 with a different port number `sed -i 's/4433/4434/g' run`

Run the *replayer* to send the test inputs.
```sh
sudo bash replay_1.sh
```