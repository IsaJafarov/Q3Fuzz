# PRETT3

## Requirements
- python 3.x
- pyshark and aioquic packages
```
$ sudo add-apt-repository ppa:wireshark-dev/stable
$ sudo apt update
$ sudo apt install -y tshark=4.4.9-1~ubuntu22.04.0~ppa1
$ pip3 install pyshark==0.6
$ pip3 install aioquic==1.2.0
$ pip3 install networkx==3.1
$ pip3 install hypothesis==6.113.0
$ pip3 install rich
$ pip3 install transitions[diagrams]
```

- To communicate with the web servers, import root-ca.crt in your browser.

## Running state machine generation

Given a target server is running and a .pcapng file or multiple .pcapng files generated, you can run either single-run or multiple-runs

- Single run: Generate a SM by the specific .pcapng file using `prett3_syn.py`

```bash
// Example for the simple run
// Note that the pcapng file is in sample_traffic and its corresponding SSLKEYLOG is in the same directory
sudo python3 prett3_syn.py -dk sample_traffics/secrets.keylog -ok secrets.keylog http3://prett3.com sample_traffics/ch_m_mg_m.pcapng
```

- Multiple run: Generate SMs by the multiple .pcapng files of the target server

```bash
// Example for the multiple runs
TODO
```