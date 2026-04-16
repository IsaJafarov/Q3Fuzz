
# Q3Fuzz 

## Server setup

Build the server without applying the patches

```sh
sudo apt-get install -y build-essential make libtool libev-dev libbrotli-dev libtool libtool-bin autoconf automake pkg-config gcc lcov

mkdir ngtcp_for_q3fuzz; cd ngtcp_for_q3fuzz

git clone --recursive https://github.com/ngtcp2/ngtcp2; cd ngtcp2
git clone --depth 1 -b v5.7.0-stable https://github.com/wolfSSL/wolfssl; cd wolfssl

autoreconf -i
./configure --prefix=$PWD/build --enable-all --enable-aesni --enable-harden --disable-ech
make -j2
make install
cd ..

git clone --recursive https://github.com/ngtcp2/nghttp3; cd nghttp3
git checkout 6bcfffb
git submodule update --init --recursive
autoreconf -i
./configure --prefix=$PWD/build --enable-lib-only
make -j2 check
make install
cd ..
# v1.5.0
git checkout e2372a8
autoreconf -i

./configure CC="gcc" CXX="g++" CFLAGS="--coverage" LDFLAGS="--coverage" PKG_CONFIG_PATH=$PWD/wolfssl/build/lib/pkgconfig:$PWD/nghttp3/build/lib/pkgconfig --with-wolfssl --disable-shared --enable-static
make -j2 check
```

Now run the server

```bash
cd ~/evaluation/; \
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/ --rc lcov_branch_coverage=1; \
sudo rm coverage_log.txt; \
while true; do \
    sudo timeout --signal=INT 300 /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/examples/wsslserver 0.0.0.0 443 /home/ubuntu/PRETT3/servers_setup/certs/prett3.com.key /home/ubuntu/PRETT3/servers_setup/certs/prett3.com.crt --initial-pkt-num=0 -d /usr/local/nginx/html/; \
	if [ $? -eq 124 ]; then sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/; fi; \
done
```


Start fuzzing
```sh
while true; do \
	python3 generation_fuzzer.py https://prett3.com ../sample_traffics/evaluation/ff_ngtcp2_eval.pcapng ../result/evaluation/ff_ngtcp2_eval/level_4.json -dk  ../sample_traffics/secrets.keylog -p1 -i1 -d1 -g50 -m50 -nr; \
done
```


# QUICFuzz

## Setup

Build the server just like QUICFuzz on host machine and apply the patches.

```sh
sudo apt-get install -y libev-dev libbrotli-dev libtool autoconf automake

cd ~/evaluation
git clone https://github.com/QUICTester/QUIC-Fuzz.git
mkdir ngtcp_for_quicfuzz; cd ngtcp_for_quicfuzz

git clone --recursive https://github.com/ngtcp2/ngtcp2; cd ngtcp2
git clone --depth 1 -b v5.7.0-stable https://github.com/wolfSSL/wolfssl; cd wolfssl

git apply ../../../QUIC-Fuzz/dockerFiles/ngtcp2/wolfssl.patch
autoreconf -i
./configure --prefix=$PWD/build --enable-all --enable-aesni --enable-harden --disable-ech
make -j2
make install
cd ..

git clone --recursive https://github.com/ngtcp2/nghttp3; cd nghttp3
git checkout 6bcfffb
git submodule update --init --recursive
autoreconf -i
./configure --prefix=$PWD/build --enable-lib-only
make -j2 check
make install
cd ..
# v1.5.0
git checkout e2372a8
git apply ../../QUIC-Fuzz/dockerFiles/ngtcp2/ngtcp2.patch
autoreconf -i

./configure CC="gcc" CXX="g++" CFLAGS="--coverage" LDFLAGS="--coverage" PKG_CONFIG_PATH=$PWD/wolfssl/build/lib/pkgconfig:$PWD/nghttp3/build/lib/pkgconfig --with-wolfssl --disable-shared --enable-static
make -j2 check
```

Setup the docker container on the attacking machine.

P.S. The 2nd line in Dockerfile from the end (`COPY ngtcp2_RetryClientAuth_seed ngtcp2_RetryClientAuth_seed`) causes a problem. It tries to copy `ngtcp2_RetryClientAuth_seed`, but there is no file or folder named that. We check the `run.sh` script and see that, it is not used anywhere. The `run.sh` script uses `ngtcp2_seed`, but not `ngtcp2_RetryClientAuth_seed`. Therefore, we assume that we can safely comment out that line from the Dockerfile.

P.S. We also added `RUN git submodule update --init --recursive` line to Dockerfile. Otherwise, nghttp3 would not build due to some version mismatch.

```sh
git clone https://github.com/QUICTester/QUIC-Fuzz.git

cd QUIC-Fuzz/dockerFiles/ngtcp2/

# build image
sudo docker build -t quicfuzz_ngtcp2 . # if you face connection issues, try adding --network=host

# create containers. Add "network=host" so that it can send messages to remote machines too
sudo docker run --network host -it --name quicfuzz_ngtcp2 quicfuzz_ngtcp2 bash

# start container
sudo docker start quicfuzz_ngtcp2

# spawn a shell inside docker
sudo docker exec -it quicfuzz_ngtcp2 bash
```


Set up the replayer script. It will run on the attacking machine, extract test inputs from the docker container and replay them to the web server running on the host machine.

```sh
#!/bin/bash

CONTAINER_ID="quicfuzz_ngtcp2" # update
CONTAINER_QUEUE="/tmp/ngtcp2/ngtcp2_out_enc_sync_snap_24h/replayable-queue"
PROCESSED_FILE="./$CONTAINER_ID"_processed_testcases.txt
TARGET_IP="10.20.20.130" # update
TARGET_PORT="443"
LOCAL_PORT=$((49152 + RANDOM % 16384))

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

Run the patched server on host

```sh
cd ~/evaluation/; \
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/ --rc lcov_branch_coverage=1; \
sudo rm coverage_log.txt; \
while true; do \
    sudo timeout --signal=INT 300 /home/ubuntu/evaluation/ngtcp_for_quicfuzz/ngtcp2/examples/wsslserver 0.0.0.0 443 /home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/ngtcp2/server-key.pem /home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/ngtcp2/server-cert.pem --initial-pkt-num=0 -d /usr/local/nginx/html/; \
    if [ $? -eq 124 ]; then sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/ngtcp_for_quicfuzz/ngtcp2/; fi; \
done
```

Start fuzzer inside the QUICFuzz docker container.
```sh
./run quic-fuzz/aflnet ngtcp2_out_enc_sync_snap_24h '-a /tmp/quic-fuzz/aflnet/sabre -A /tmp/quic-fuzz/aflnet/libsnapfuzz.so -p 0 -y -b 1 -m none -P QUIC -q 3 -s 3 -E -K' 86400 5
```

Run the *replayer* script on the attacking machine.
```sh
sudo bash replay.sh
```




