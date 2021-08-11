from scapy.all import raw
from scapy.utils import PcapReader

from engine import PacketEngine
import tabulate
import constants
import logging


def read_pcap(filepath):
	with PcapReader(filepath) as fdesc:
		try:
			p = fdesc.read_packet()
			while p is not None:
				yield p
				p = fdesc.read_packet()
		except EOFError:
			pass


logging.basicConfig(format='%(levelname).1s | %(message)s', datefmt='%Y-%d-%m %H:%M:%S', level=logging.INFO)
constants.INVISIBLE = 2

engine = PacketEngine()
# Let's iterate through every packet
for packet in read_pcap("./caps/capture.pcapng"):
	engine.handle_packet(raw(packet))

for host in sorted(engine.hosts.values(), key=lambda h: h.ip if h.ip is not None else b"\0\0\0\0"):
	print("")
	print("%-15s%s" % (host.get_ip_str(), host.mac))
	for key, value in host.attributes.items():
		if type(value) == list or type(value) == set:
			print("    %s:" % key)
			for v in value:
				print("        %s" % v)
		else:
			print("    %s: %s" % (key, value))
# table = [[host.get_ip_str(), host.mac, "\n".join(["%s: %s" % (key, value) for key, value in host.attributes.items()])] for host in sorted(engine.hosts.values(), key=lambda h: h.ip if h.ip is not None else b"\0\0\0\0")]
# print(tabulate.tabulate(table, headers=["IP", "MAC", "Attributes"], tablefmt="grid"))
