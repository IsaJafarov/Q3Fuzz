# PRETT3

## Requirements
- python 3.x

Install the dependencies
```bash
$ sudo add-apt-repository ppa:wireshark-dev/stable
$ sudo apt update
$ sudo apt install -y tshark=4.6.3-1~ubuntu22.04.0~ppa1 graphviz graphviz-dev
$ pip3 install pyshark==0.6
$ pip3 install aioquic==1.2.0
$ pip3 install networkx==3.1
$ pip3 install hypothesis==6.113.0
$ pip3 install rich
$ pip3 install transitions[diagrams]
$ pip3 install paramiko # to restart web server periodically during fuzzing
```

- To communicate with the web servers, import root-ca.crt in your browser.

The methodology consists of three main stages:
1. Geerating Traffic
2. Generating State Machine based on the generated traffic
3. Fuzzing using the State Machine

# Step 1: Geerating Traffic

Sample traffic is provided in the [sample_traffics](./sample_traffics/) folder. You can also generate a new one following the steps below.

[autoinstall.py](./servers_setup/autoinstall.py) and [autorun.py](./servers_setup/autorun.py) allows to easily build and run a wide range of QUIC-HTTP/3 servers.

```bash
$ python3 autoinstall.py -h
usage: autoinstall.py [-h] server version

HTTP/3 web servers installation

positional arguments:
  server      supported servers
              	- nginx
              - caddy
              - h2o
              - ols (lsquic + openlitespeed)
              - cloudflare-quiche
              - quic-go
              - msquic-kestrel
              - neqo
              - aioquic
              - quinn-h3
              - ngtcp2-nghttp3
              - xquic
              - mvfst-proxygen
              - picoquic
              - google-quiche
  version     corresponding version(s)
              	- 1.23.4, 1.25.5, 1.27.0 or 1.28.0 	(for nginx)
              - 2.4.6, 2.7.6, 2.8.4, 2.10.0	(for caddy)
              - a429117, 222b36d, 16b13ee or f1918a5	(for h2o)
              - 1.7.15, 1.8.1, 1.8.3.1	(for ols)
              - 0.23.5 	(for cloudflare-quiche)
              - 0.50.1 	 (for quic-go)
              - 2.4.8 	 (for msquic-kestrel)
              - 0.13.1, 0.14.1 	 (for neqo)
              - 1.2.0 	 (for aioquic)
              - 0.0.9 	 (for quinn-h3)
              - 1.12.0 	 (for ngtcp2-nghttp3)
              - 1.8.3 	 (for xquic)
              - 2025.04.14.00 	 (for mvfst-proxygen)
              - b19dcf1 	 (for picoquic)
              - 7b2b126 	 (for google-quiche)

options:
  -h, --help  show this help message and exit
```

Once the installation process completes, the server automatically runs. You can run the server later without reinstalling using the `servers_setup/autorun.py` script with the same command-line flags.

By default, the servers use `/usr/local/nginx/html/` folder as their web root. Make sure the folder exists with a small `index.html` file.

After running the server, generate a sample QUIC-HTTP/3 traffic by communicating with the server using a client. We generated traffic using Firefox 132.0. First, [instruct Firefox to use QUIC connection](https://github.com/mozilla/neqo?tab=readme-ov-file#connect-with-firefox-to-local-neqo-server). On Firefox, set about:config preferences:
- network.http.http3.alt-svc-mapping-for-testing to localhost;h3=":12345"
- network.http.http3.disable_when_third_party_roots_found to false

With [wireshark](https://www.wireshark.org/) listen for QUIC communication.

Set `SSLKEYLOGFILE` environment variable.
```bash
$ export SSLKEYLOGFILE=./secrets.keylog
```

```
./firefox --private-window https://<server-address>/
```

Once the page is loaded, stop capturing packets on wireshark. Using the secrets from the `./secrets.keylog` file, decrypt the captured traffic. 

Export PDU, since we are interested only in QUIC and HTTP/3 layers. 

![alt text](image.png)

![alt text](image.png)


## Step 2: Running state machine generation

Sample state machine are provided in [result](./result/) folder. 

You can also generate a new state machine given a target server is running and a .pcapng file.

```bash
python3 generate_sm.py http3://q3fuzz.com ../sample_traffics/ch_m_mg_m.pcapng -dk ../sample_traffics/secrets.keylog -ok secrets.keylog
```

## Step 3: Fuzzing

Once the given traffic modelled, you start fuzzing the target server. The fuzzer needs the generated state machine for guidance, as well as the traffic extract/mutate/replay messages.

Two types of fuzzers are provided:

1. Mutation-based fuzzer
```
$ python3 mutation_fuzzer.py -h
usage: mutation_fuzzer.py [-h] [-dk DECRYPT_KEYLOG] [-ok OUTPUT_KEYLOG] [-m MUTATIONS] [-p PARALLEL_REQUESTS]
                          [-i INTERVAL] [-d DURATION] [-rs] [-su SSH_USER] [-skp SSH_KEY_PATH] [-sn SERVER_NAME]
                          [-sv SERVER_VERSION] [-r REPLAY] [-nr] [-v]
                          url pcap state_machine

HTTP/3 client

positional arguments:
  url                   the URL to query (must be HTTPS)
  pcap                  PATH to the QUIC/HTTP3 traffic (must be Wireshark-readable pcap)
  state_machine         Path to the state machine json file

options:
  -h, --help            show this help message and exit
  -dk DECRYPT_KEYLOG, --decrypt_keylog DECRYPT_KEYLOG
                        SSLKEYLOG file to decrypt the traffic files (default ./sample_traffics/secrets.keylog)
  -ok OUTPUT_KEYLOG, --output_keylog OUTPUT_KEYLOG
                        File path to log new traffic secrets
  -m MUTATIONS, --mutations MUTATIONS
                        The number of mutations to apply on each QUIC, HTTP/3 frame and Transport Params (default 100)
  -p PARALLEL_REQUESTS, --parallel_requests PARALLEL_REQUESTS
                        The number of requests to send in parallel (default 20)
  -i INTERVAL, --interval INTERVAL
                        Time to wait before sending the next parallel requests (in sec.) (default 1)
  -d DURATION, --duration DURATION
                        The length of attack (in sec.) (default 60)
  -rs, --restart_server
                        After fuzzing for each mutation, connect to the target server and restart the QUIC server
  -su SSH_USER, --ssh_user SSH_USER
                        The SSH user on the server side to connect to (default: ubuntu)
  -skp SSH_KEY_PATH, --ssh_key_path SSH_KEY_PATH
                        The SSH private key path to use to connect to the target server (default:
                        /home/ubuntu/.ssh/id_ed25519)
  -sn SERVER_NAME, --server_name SERVER_NAME
                        Server name to use as input parameter while running autorun.py to restart QUIC server
  -sv SERVER_VERSION, --server_version SERVER_VERSION
                        Server name to use as input parameter while running autorun.py to restart QUIC server
  -r REPLAY, --replay REPLAY
                        Number of additional replays to confirm a finding (default 2)
  -nr, --no_response    Do not wait for the server to send back resonse for 1-RTT messages. Transmitting messages without
                        waiting can lead to abnormal server behaviour.
  -v, --verbose         Verbose output
```

Sample command:
```
python3 mutation_fuzzer.py https://q3fuzz.com ./sample_traffics/ff_n_nginx_n.pcapng ./result/ff_n_nginx_n/level_5.json -dk ./sample_traffics/secrets.keylog -p2 -i1 -d1 -m1000 -v
```

2. Generation-based fuzzer

```
$ python3 generation_fuzzer.py -h
usage: generation_fuzzer.py [-h] [-dk DECRYPT_KEYLOG] [-ok OUTPUT_KEYLOG] [-g GENERATION] [-m MUTATIONS]
                            [-p PARALLEL_REQUESTS] [-i INTERVAL] [-d DURATION] [-rs] [-su SSH_USER] [-skp SSH_KEY_PATH]
                            [-sn SERVER_NAME] [-sv SERVER_VERSION] [-r REPLAY] [-nr] [-v]
                            url pcap state_machine

HTTP/3 client

positional arguments:
  url                   the URL to query (must be HTTPS)
  pcap                  PATH to the QUIC/HTTP3 traffic (must be Wireshark-readable pcap)
  state_machine         Path to the state machine json file

options:
  -h, --help            show this help message and exit
  -dk DECRYPT_KEYLOG, --decrypt_keylog DECRYPT_KEYLOG
                        SSLKEYLOG file to decrypt the traffic files (default ./sample_traffics/secrets.keylog)
  -ok OUTPUT_KEYLOG, --output_keylog OUTPUT_KEYLOG
                        File path to log new traffic secrets
  -g GENERATION, --generation GENERATION
                        The number of generations for each transition (default 10)
  -m MUTATIONS, --mutations MUTATIONS
                        The number of mutations to apply on generated packets (default 100)
  -p PARALLEL_REQUESTS, --parallel_requests PARALLEL_REQUESTS
                        The number of requests to send in parallel (default 20)
  -i INTERVAL, --interval INTERVAL
                        Time to wait before sending the next parallel requests (in sec.) (default 1)
  -d DURATION, --duration DURATION
                        The length of attack (in sec.) (default 60)
  -rs, --restart_server
                        After fuzzing for each mutation, connect to the target server and restart the QUIC server
  -su SSH_USER, --ssh_user SSH_USER
                        The SSH user on the server side to connect to (default: ubuntu)
  -skp SSH_KEY_PATH, --ssh_key_path SSH_KEY_PATH
                        The SSH private key path to use to connect to the target server (default:
                        /home/ubuntu/.ssh/id_ed25519)
  -sn SERVER_NAME, --server_name SERVER_NAME
                        Server name to use as input parameter while running autorun.py to restart QUIC server
  -sv SERVER_VERSION, --server_version SERVER_VERSION
                        Server name to use as input parameter while running autorun.py to restart QUIC server
  -r REPLAY, --replay REPLAY
                        Number of additional replays to confirm a finding (default 2)
  -nr, --no_response    Do not wait for the server to send back resonse for 1-RTT messages. Transmitting messages without
                        waiting can lead to abnormal server behaviour.
  -v, --verbose         Verbose output
```

Sample command:

```
python3 generation_fuzzer.py -dk ./sample_traffics/secrets.keylog https://prett3.com ./sample_traffics/ff_n_nginx_n.pcapng ./result/ff_n_nginx_n/level_5.json -p20 -i1 -d60 -g30 -m30
```