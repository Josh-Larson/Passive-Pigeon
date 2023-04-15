#!/usr/bin/env python3
from scapy.all import raw
from scapy.utils import PcapReader

from packet_engine import PacketEngine
import argparse
import constants
import logging


def read_pcap(filepath):
	with PcapReader(filepath) as fdesc:
		frame = 0
		try:
			p = fdesc.read_packet()
			while p is not None:
				yield p, frame
				p = fdesc.read_packet()
				frame += 1
		except EOFError:
			pass


logging.basicConfig(format='%(levelname).1s | %(message)s', datefmt='%Y-%d-%m %H:%M:%S', level=logging.INFO)
constants.INVISIBLE = 2

parser = argparse.ArgumentParser()
parser.add_argument("capture", nargs="?", default="./cap.pcap")
options = parser.parse_args()

engine = PacketEngine()
# Let's iterate through every packet
for packet in read_pcap(options.capture):
	engine.handle_packet(raw(packet[0]))

engine.display_information()

# table = [[host.get_ip_str(), host.mac, "\n".join(["%s: %s" % (key, value) for key, value in host.attributes.items()])] for host in sorted(engine.hosts.values(), key=lambda h: h.ip if h.ip is not None else b"\0\0\0\0")]
# print(tabulate.tabulate(table, headers=["IP", "MAC", "Attributes"], tablefmt="grid"))
