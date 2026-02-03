
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

Run the server to generate SM
```sh
sudo ./examples/wsslserver 0.0.0.0 443 ../../../PRETT3/servers_setup/certs/prett3.com.key ../../../PRETT3/servers_setup/certs/prett3.com.crt --initial-pkt-num=0 -d /usr/local/nginx/html/
```

Generate traffic with firefox: `ff_n_ngtcp2_eval.pcapng` and `ff_n_ngtcp2_eval.keylog`

Generate SM
```sh
python3 prett3_syn.py https://prett3.com ../ff_n_ngtcp2_eval.pcapng -dk ../ff_n_ngtcp2_eval.keylog
```

Run the server for fuzzing. Preferably, run in a `tmux` session

```bash
cd ~/evaluation/; \
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/ --rc lcov_branch_coverage=1; \
sudo rm coverage_log.txt; \
while true; do \
    sudo timeout --signal=INT 300 /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/examples/wsslserver 0.0.0.0 443 /home/ubuntu/PRETT3/servers_setup/certs/prett3.com.key /home/ubuntu/PRETT3/servers_setup/certs/prett3.com.crt --initial-pkt-num=0 -d /usr/local/nginx/html/; \
    sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/; \
done
```


Start fuzzer
```sh
while true; do \
	python3 generation_fuzzer.py https://prett3.com ../sample_traffics/evaluation/ff_ngtcp2_eval.pcapng ../result/evaluation/ff_ngtcp2_eval/level_4.json -dk  ../sample_traffics/secrets.keylog -p1 -i1 -d1 -g50 -m50 -nr; \
done
```


# QUICFuzz

## Setup

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

Set up docker container. 

The 2nd line in Dockerfile from the end (`COPY ngtcp2_RetryClientAuth_seed ngtcp2_RetryClientAuth_seed`) causes a problem. It tries to copy `ngtcp2_RetryClientAuth_seed`, but there is no file or folder named that. We check the `run.sh` script and see that, it is not used anywhere. The `run.sh` script uses `ngtcp2_seed`, but not `ngtcp2_RetryClientAuth_seed`. Therefore, we assume that we can safely comment out that line from the Dockerfile.

I also added `RUN git submodule update --init --recursive` line to Dockerfile. Otherwise, nghttp3 would not build due to some version mismatch.

```sh
git clone https://github.com/QUICTester/QUIC-Fuzz.git

cd QUIC-Fuzz/dockerFiles/ngtcp2/

# build image
sudo docker build -t quicfuzz_ngtcp2 . # if you face connection issues, try adding --network=host

# create containers. Add "network=host" so that it can send messages to remote machines too
sudo docker run --network host -it --name quicfuzz_ngtcp2_1 quicfuzz_ngtcp2 bash

# start container
sudo docker start quicfuzz_ngtcp2_1

# spawn a shell inside docker
tmux new -s quicfuzz_ngtcp2_1 # optional
sudo docker exec -it quicfuzz_ngtcp2_1 bash
```


Update **replayX.sh** scripts.
For the first 5 instances, we did `replayable-queue` and `$CONTAINER_QUEUE/*+cov`.
For the last 5 instances, we did `replayable-new-ipsm-paths` and `$CONTAINER_QUEUE/*new`
```sh
#!/bin/bash

CONTAINER_ID="quicfuzz_ngtcp2_5"
CONTAINER_QUEUE="/tmp/ngtcp2/ngtcp2_out_enc_sync_snap_24h/replayable-queue"
SERVER_BINARY="/home/ubuntu/evaluation/ngtcp_for_quicfuzz/ngtcp2/examples/wsslserver"
CERT_FILE="/home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/ngtcp2/server-cert.pem"
KEY_FILE="/home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/ngtcp2/server-key.pem"
SO_FILE="/home/ubuntu/evaluation/covdump_5sec.so"
PROCESSED_FILE="./$CONTAINER_ID"_processed_testcases.txt
TARGET_IP="10.20.20.204"
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
files=$(docker exec "$CONTAINER_ID" bash -c "ls $CONTAINER_QUEUE/*+new 2>/dev/null" | sort)

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
	    ssh -i /home/isa/.ssh/id_rsa ubuntu@"$TARGET_IP" "tmux send-keys -t $TMUX_PANEL 'sudo env LD_PRELOAD=$SO_FILE $SERVER_BINARY 0.0.0.0 443 $KEY_FILE $CERT_FILE --initial-pkt-num=0' C-m 2>/dev/null"
	    sleep 1
	    
	    # Replay from inside container using aflnet-replay
	    echo "  Replaying..."
	    docker exec "$CONTAINER_ID" /tmp/quic-fuzz/aflnet/aflnet-replay "$file" QUIC $LOCAL_PORT
	    sleep 5
	    
	    # Mark as processed
	    echo "$filename" >> "$PROCESSED_FILE"
	    
	    echo "  Done"
	done;
	sleep 0.5
done

echo "All test cases processed: $count"
```

## Run

Start the server. Preferably, run the server in a `tmux` session
```sh
cd ~/evaluation/; \
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/ --rc lcov_branch_coverage=1; \
sudo rm coverage_log.txt; \
while true; do \
    sudo timeout --signal=INT 300 /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/examples/wsslserver 0.0.0.0 443 /home/ubuntu/PRETT3/servers_setup/certs/prett3.com.key /home/ubuntu/PRETT3/servers_setup/certs/prett3.com.crt --initial-pkt-num=0 -d /usr/local/nginx/html/; \
    sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/ngtcp_for_q3fuzz/ngtcp2/; \
done
```

Start the **replayX.sh** script
```sh
sudo bash replayX.sh
```

Start the fuzzer inside the container
```sh
tmux new -s quicfuzz_ngtcp2_1

sudo docker exec -it quicfuzz_ngtcp2_1 bash

./run quic-fuzz/aflnet ngtcp2_out_enc_sync_snap_24h '-a /tmp/quic-fuzz/aflnet/sabre -A /tmp/quic-fuzz/aflnet/libsnapfuzz.so -p 0 -y -b 1 -m none -P QUIC -q 3 -s 3 -E -K' 86400 5
```


