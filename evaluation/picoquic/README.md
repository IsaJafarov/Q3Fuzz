# Q3Fuzz

## Setup

Build the server

```sh
# install some dependencies
sudo apt install -y pkg-config lcov

cd ~/evaluation
mkdir pico_for_q3fuzz; cd pico_for_q3fuzz

git clone https://github.com/h2o/picotls.git
cd picotls
git checkout 096fc5c
git submodule init
git submodule update
cmake -DCMAKE_C_FLAGS="-fPIC" .
make -j

cd ..
git clone https://github.com/private-octopus/picoquic.git
cd picoquic
git checkout 8f4f77f
CFLAGS="--coverage" LDFLAGS="--coverage" cmake -DCMAKE_BUILD_TYPE=Release .
make -j
```

Unlike the other servers (xquic, lsquic, ngtcp2), picoquic does not flush gcov when it receives any kind of signal. Therefore, we need to use an additional shared object, which dumps gcov, when it intercepts USR1 signal.

```c
// gcov_flush.c
#define _GNU_SOURCE
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static void coverage_handler(int sig) {
    pid_t pid = fork();
    if (pid == 0) {
        exit(0);  // child inherits gcov state, exit() writes .gcda
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
    }
    // parent continues — but since you want it to stop, re-raise default
    signal(sig, SIG_DFL);
    raise(sig);
}

__attribute__((constructor))
static void init(void) {
    struct sigaction sa = {
        .sa_handler = coverage_handler,
        .sa_flags   = 0,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
}
```

```sh
gcc -shared -fPIC -O2 -o /home/ubuntu/evaluation/gcov_flush.so /home/ubuntu/evaluation/gcov_flush.c
```

## Run

Run the server

```sh
cd ~/evaluation/;
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/pico_for_q3fuzz/picoquic/ --rc lcov_branch_coverage=1;
sudo rm coverage_log.txt;

INTERVAL=300
NEXT=$(( $(date +%s) + INTERVAL ))

while true; do
    sudo timeout --signal=USR1 $(( NEXT - $(date +%s) )) env \
        LD_PRELOAD=/home/ubuntu/evaluation/gcov_flush.so \
        /home/ubuntu/evaluation/pico_for_q3fuzz/picoquic/picoquicdemo \
        -p 443 -w /usr/local/nginx/html/ \
        -c /home/ubuntu/Q3Fuzz/servers_setup/certs/prett3.com.pem \
        -k /home/ubuntu/Q3Fuzz/servers_setup/certs/prett3.com.key

    NOW=$(date +%s)
    if [ $NOW -ge $NEXT ]; then
        sudo bash /home/ubuntu/evaluation/covrecord.sh \
            /home/ubuntu/evaluation/pico_for_q3fuzz/picoquic/
        NEXT=$(( NOW + INTERVAL ))
    fi
    # if server crashed before deadline, loop restarts with remaining time
done
```

Start fuzzing

```sh
while true; do \
    python3 generation_fuzzer.py https://prett3.com ../sample_traffics/evaluation/ff_pico_eval.pcapng ../result/evaluation/ff_pico_eval/level_3.json -dk  ../sample_traffics/secrets.keylog -p1 -i1 -d1 -g50 -m50 -nr; \
done
```

---

# QUICFuzz

## Setup

Build the server just like QUICFuzz on host machine and apply the patches.

```sh
cd ~/evaluation
git clone https://github.com/QUICTester/QUIC-Fuzz.git

mkdir pico_for_quicfuzz; cd pico_for_quicfuzz

git clone https://github.com/h2o/picotls.git
cd picotls
git checkout 096fc5c
git submodule init
git submodule update
git apply ../../QUIC-Fuzz/dockerFiles/picoquic/picotls.patch
cmake -DCMAKE_C_FLAGS="-fPIC" .
make -j

cd ..
git clone https://github.com/private-octopus/picoquic.git
cd picoquic
git checkout 8f4f77f
git apply ~/evaluation/QUIC-Fuzz/dockerFiles/picoquic/picoquic.patch
CFLAGS="--coverage" LDFLAGS="--coverage" cmake -DCMAKE_BUILD_TYPE=Release .
make -j
```

Setup the docker container on the attacking machine.


```sh
git clone https://github.com/QUICTester/QUIC-Fuzz.git

cd QUIC-Fuzz/dockerFiles/picoquic/

# build image
sudo docker build -t quicfuzz_picoquic . # if you face connection issues, try adding --network=host

# create container
sudo docker run --network host -it --name quicfuzz_pico quicfuzz_picoquic bash # network=host so that it can send messages to remote machines too

# start container
sudo docker start quicfuzz_pico

# spawn a shell inside docker
sudo docker exec -it quicfuzz_pico bash
```

Set up the *replayer* script. It will run on the attacking machine, extract test inputs from the docker container and replay them to the web server running on the host machine.


```sh
#!/bin/bash

CONTAINER_ID="quicfuzz_pico"
CONTAINER_QUEUE="/tmp/picoquic/pico_out_enc_sync_24h/replayable-queue"
PROCESSED_FILE="./$CONTAINER_ID"_processed_testcases.txt
TARGET_IP="10.20.20.130"
TARGET_PORT="443"
LOCAL_PORT=$((49152 + RANDOM % 16384))
SERVER_RUN_CMD="tmux send-keys -t server 'sudo timeout --signal=USR1 2 env LD_PRELOAD=/home/ubuntu/evaluation/gcov_flush.so /home/ubuntu/evaluation/pico_for_quicfuzz/picoquic/picoquicdemo -R 0 -p 443 -w /usr/local/nginx/html/ -c /home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/picoquic/server-cert.pem -k /home/ubuntu/evaluation/QUIC-Fuzz/dockerFiles/picoquic/server-key.pem' C-m 2>/dev/null"

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
sudo lcov --zerocounters --directory /home/ubuntu/evaluation/pico_for_quicfuzz/picoquic/ --rc lcov_branch_coverage=1; \
sudo rm /home/ubuntu/evaluation/coverage_log.txt; \
while true; do sudo bash /home/ubuntu/evaluation/covrecord.sh /home/ubuntu/evaluation/pico_for_quicfuzz/picoquic/; sleep 300; done
```

Start fuzzer inside the QUICFuzz docker container.

```sh
./run quic-fuzz/aflnet pico_out_enc_sync_24h '-a /tmp/quic-fuzz/aflnet/sabre -A /tmp/quic-fuzz/aflnet/libsnapfuzz_no_snap.so -p 0 -m none -y -b 1 -P QUIC -q 3 -s 3 -E -K' 86400 5
```

Run the *replayer* script on the attacking machine.
```sh
sudo bash replay.sh
```
