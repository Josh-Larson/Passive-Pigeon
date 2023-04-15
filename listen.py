#!/usr/bin/env python3
import socket
from packet_engine import PacketEngine
import argparse
import logging
import constants


parser = argparse.ArgumentParser()
parser.add_argument("-log", "--log", nargs='?', default="info", help="The logging level (e.x. debug, info, warning, error, critical, fatal)'")
options = parser.parse_args()

levels = {
	'fatal': logging.FATAL,
	'critical': logging.CRITICAL,
	'error': logging.ERROR,
	'warn': logging.WARNING,
	'warning': logging.WARNING,
	'info': logging.INFO,
	'debug': logging.DEBUG
}
if options.log.lower() not in levels:
	print("Unknown log level: %s" % options.log)
	log_level = logging.INFO
else:
	log_level = levels[options.log.lower()]
logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname).1s | %(message)s', datefmt='%Y-%d-%m %H:%M:%S', level=log_level)
logger = logging.getLogger(constants.NAME)

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
engine = PacketEngine()

try:
	while True:
		packet, remote = s.recvfrom(65535)
		engine.handle_packet(packet)
except (KeyboardInterrupt, EOFError):
	engine.display_information()
