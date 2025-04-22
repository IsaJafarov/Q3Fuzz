# PRETT3

## Requirements
- python 3.x
- pyshark and aioquic packages
```
$ sudo add-apt-repository ppa:wireshark-dev/stable
$ sudo apt update
$ sudo apt install tshark=4.4.3-1~ubuntu20.04.0~ppa1
$ pip3 install pyshark==0.6
$ pip3 install aioquic==1.2.0
$ pip3 install networkx==3.1
$ pip3 install hypothesis==6.113.0
$ pip3 install rich
$ pip3 install transitions[diagrams]
```

- To communicate with the web servers, import root-ca.crt in your browser.