#! /usr/bin/env python
import util
import os
import sys
import logging
import subprocess
import time
from datetime import datetime

from aioquic.quic.configuration import SMALLEST_MAX_DATAGRAM_SIZE, QuicConfiguration
from aioquic.quic.logger import QuicLogger
from aioquic.quic.connection import (
    STREAM_COUNT_MAX,
    NetworkAddress,
    QuicConnection,
    QuicConnectionError,
    QuicNetworkPath,
    QuicReceiveContext,
)

def setup_logger(pcapfile, switch=0):
	outdir = "./"
	if switch:
		dt = datetime.now().strftime("%Y%m%d-%H%M%S")
		pcap_name = pcapfile.split("/")[-1].replace(".pcapng", "")
		outdir = "output_%s_%s" % (pcap_name, dt)
		os.system("sudo mkdir %s" % outdir)
		os.system("sudo mkdir %s/diagram" % outdir)
		f = open('%s/http3_PRE_logging.txt' % outdir, 'w')
		sys.stdout = util.Tee(sys.stdout, f)
		os.system("sudo cp %s %s/" % (pcapfile, outdir))
	return outdir

def _enable_capture(switch=0):
	# UNDER TESTING
	if switch:
		print("[INFO] If you want to capture packet via wireshark, type interface (ex. ens38).")
		print("[INFO] You can skip capturing by typing \'n\' or \'N\'")
		ens = input("[Q] Interface? : ")
		if ens == 'n' or ens == 'N':
			pass
		else:
			output = subprocess.Popen("sudo wireshark -k -i %s > /dev/null" % ens, shell=True)
	else:
		pass

def init():
	print("\n[STEP 1] Initializing...")
	os.system("sudo rm -r __pycache__")

	SERVER_ADDR = sys.argv[1]
	pcapfile = sys.argv[2]
	outdir = setup_logger(pcapfile, 0)
	_enable_capture()

	print("  [+] Initializing done!\n    => pcap : %s, SERVER_ADDR : %s" % (pcapfile, SERVER_ADDR))
	return SERVER_ADDR, pcapfile, outdir

def info():
	print("Run this script with target IP address (python3).")
	print("sudo python3 %s [target IP] [pcap_path]" % sys.argv[0])
	print("Target IP is IP address or URL without https://")
	sys.exit()

def create_standalone_client(SERVER_ADDR):
    client = QuicConnection(
        configuration=QuicConfiguration(
            is_client=True, quic_logger=QuicLogger(), alpn_protocols=["h3-25", "hq-25"]
        )
    )
    client._ack_delay = 0

    # kick-off handshake
    client.connect(SERVER_ADDR, now=time.time())
    print('connect done.')

    return client

def modeller_h3(http2_basic_messages, SERVER_ADDR, outdir):
	client = create_standalone_client(SERVER_ADDR)

if __name__ == "__main__":
	if len(sys.argv) != 3:
		info()

	#### general setting ###
	SERVER_ADDR, pcapfile, outdir = init()
	
	### Extract initial state machine ###
	http2_basic_messages = util.h3msg_from_pcap(pcapfile)

	### Construct reverse engineering for HTTP/2
	# modeller_h3(http2_basic_messages, SERVER_ADDR, outdir)

else :
	print ("[-] Invalid Input... exit...\n")
	sys.exit()