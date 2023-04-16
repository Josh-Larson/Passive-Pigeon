from struct import unpack, iter_unpack
import pathlib
import logging
import socket
import constants
import re

from engine.mac import MACAddress, MACAddressType


def get_ip(binary):
	return ".".join("%d" % b for b in binary)


def get_proto(proto):
	if proto == 6:
		return "TCP"
	if proto == 17:
		return "UDP"
	print("UNKNOWN PROTOCOL: %d" % proto)
	return ""


class Host:
	def __init__(self, ip, mac):
		self.ip = ip
		self.mac = MACAddress(mac)
		self.friendly_names = ""
		self.is_mac_randomized = (mac[0] & 0b00000010) != 0
		self.attributes = {}
	
	def __repr__(self):
		return "Host[%s %s]" % (self.get_ip_str(), str(self.mac))
	
	def get_ip_str(self):
		return get_ip(self.ip) if self.ip is not None else "0.0.0.0"
	
	def get_mac_organization(self):
		return self.mac.organization if self.mac.type == MACAddressType.REGISTERED else self.mac.type.name
	
	def get_friendly_names(self):
		return self.friendly_names


class PacketEngine:
	def __init__(self):
		self.hosts = {}
		self.oui_lookup = {}
		self.mac_version_parser = re.compile("^model=([a-zA-Z]+)([0-9]+)(?:,([0-9]+))?$")
		self.dhcp_option_lookup = {}
		self.mdns_service_lookup = {}
		engine_directory = pathlib.Path(__file__).parent.absolute()
		with open("%s/resources/dhcp_options.tsv" % engine_directory, "r") as file:
			for line in file.readlines():
				line_split = line.strip().split("\t")
				if "-" in line_split[0]:
					for i in range(int(line_split[0][:line_split[0].index("-")]), int(line_split[0][line_split[0].index("-")+1:])):
						self.dhcp_option_lookup[i] = line_split[1:]
				else:
					self.dhcp_option_lookup[int(line_split[0])] = line_split[1:]
		with open("%s/resources/mdns_services.tsv" % engine_directory, "r") as file:
			for line in file.readlines():
				if "#" in line:
					line = line[line.index("#")]
				if ":" not in line:
					continue
				service_id, service_name = line.strip().split(":", 2)
				self.mdns_service_lookup[service_id] = service_name
	
	def display_information(self):
		for host in sorted(self.hosts.values(), key=lambda h: h.ip if h.ip is not None else b"\0\0\0\0"):
			print("")
			print("%-15s%s" % (host.get_ip_str(), host.mac))
			for key, value in host.attributes.items():
				if type(value) == list or type(value) == set:
					print("    %s:" % key)
					for v in value:
						print("        %s" % v)
				else:
					print("    %s: %s" % (key, value))
	
	def handle_packet(self, packet):
		ethernet_header = unpack("!6s6sH", packet[:14])
		if ethernet_header[2] < 0x05DC:  # 802.3 Ethernet
			return
		
		type = ethernet_header[2]
		if type == 0x0806:  # ARP
			self.handle_arp(packet[14:], ethernet_header)
			return
		
		if type != 0x0800 or len(packet) < 34:
			return
		ip_header = unpack('!BBHHHBBH4s4s', packet[14:34])
		ip_payload_type = ip_header[6]
		payload = packet[14+4*(ip_header[0] & 0xF):]
		
		if ip_payload_type == 1:  # ICMP
			self.handle_icmp(payload, ethernet_header, ip_header)
		elif ip_payload_type == 2:  # IGMP
			self.handle_igmp(payload, ethernet_header, ip_header)
		elif ip_payload_type == 6:  # TCP
			pass
		elif ip_payload_type == 17:  # UDP
		#	pass
		 	self.handle_udp(payload, ethernet_header, ip_header)
		else:
			print("Unknown payload: %d" % ip_payload_type)
	
	def get_host(self, ethernet_header, ip_header=None):
		src_mac = ethernet_header[1]
		src_ip = ip_header[8] if ip_header is not None else None
		if src_mac not in self.hosts:
			cur_host = Host(src_ip, src_mac)
			self.hosts[src_mac] = cur_host
			
			if constants.INVISIBLE <= 1:
				try:
					cur_host.attributes["names_rdns"] = socket.gethostbyaddr(cur_host.get_ip_str())[0]
					logging.log(logging.INFO, "%s Reverse DNS Name: %s" % (str(cur_host), cur_host.attributes["names_rdns"]))
				except socket.herror:
					pass
		else:
			cur_host = self.hosts[src_mac]
		
		if src_ip is not None and src_ip != b"\0\0\0\0":
			cur_host.ip = src_ip
		return cur_host
	
	def handle_arp(self, packet, ethernet_header):
		hardware_type, protocol_type, hardware_size, protocol_size, opcode = unpack("!HHBBH", packet[:8])
		src_hardware_address, src_protocol_address, target_hardware_address, target_protocol_address = unpack("!%ds%ds%ds%ds" % (hardware_size, protocol_size, hardware_size, protocol_size), packet[8:8+hardware_size*2+protocol_size*2])
		if opcode == 0x001:  # Request
			cur_host = self.get_host(ethernet_header, ip_header=None)
			target_hardware_addresses = {b"\x00\x00\x00\x00\x00\x00", b"\xFF\xFF\xFF\xFF\xFF\xFF"}
			if target_hardware_address in target_hardware_addresses and src_protocol_address == target_protocol_address:  # Gratuitous ARP
				if target_protocol_address != b"\0\0\0\0":
					cur_host.ip = target_protocol_address
			elif src_protocol_address == cur_host.ip and target_protocol_address != cur_host.ip and src_hardware_address == cur_host.mac.mac:
				if "arp_lookups" not in cur_host.attributes:
					cur_host.attributes["arp_lookups"] = set()
				target_protocol_address_friendly = get_ip(target_protocol_address)
				if target_protocol_address_friendly not in cur_host.attributes["arp_lookups"]:
					logging.info("%s ARP Lookup: %s", str(cur_host), target_protocol_address_friendly)
					cur_host.attributes["arp_lookups"].add(target_protocol_address_friendly)
	
	def handle_icmp(self, packet, ethernet_header, ip_header):
		pass
	
	def handle_igmp(self, packet, ethernet_header, ip_header):
		if len(packet) < 8:
			return
		type = packet[0]
		cur_host = self.get_host(ethernet_header, ip_header)
		if type == 0x11:  #
			type, max_response_time, checksum, group_address = unpack("!BBH4s", packet[:8])
			if len(packet) == 8:
				logging.info("%s IGMPv2 Membership Query %02X %d %4X group=%s", str(cur_host), type, max_response_time, checksum, get_ip(group_address))
			elif len(packet) >= 16:
				value_set1, qqic, number_of_sources = unpack("!BBH", packet[8:12])
				sources = [src[0] for src in iter_unpack("!4s", packet[12:12+number_of_sources*4])]
				logging.info("%s IGMPv3 Membership Query %02X %d %4X group=%s sources=%s", str(cur_host), type, max_response_time, checksum, get_ip(group_address), str(sources))
		elif type == 0x12:  # IGMPv1 Membership Report
			logging.info("%s IGMPv1 Membership Report", str(cur_host), type)
		elif type == 0x16:  # IGMPv2 Membership Report
			type, max_response_time, checksum, group_address = unpack("!BBH4s", packet[:8])
			logging.info("%s IGMPv2 Membership Report %02X %d %4X group=%s", str(cur_host), type, max_response_time, checksum, get_ip(group_address))
		elif type == 0x22:  # IGMPv3 Membership Report
			type, _, checksum, _, num_group_records = unpack("!BBHHH", packet[:8])
			parse_idx = 8
			group_records = []
			while parse_idx + 4 < len(packet):
				group_record_header = unpack("!BBH", packet[parse_idx:parse_idx+4])
				group_record_ips = [ip[0] for ip in iter_unpack("!4s", packet[parse_idx+4:parse_idx+4+4*(1 + group_record_header[2])])]
				group_records.append((*group_record_header, *group_record_ips))
				parse_idx += 4 + 4 * (1 + group_record_header[2])
			
			logging.info("%s IGMPv3 Membership Report %02X %4X group=%s", str(cur_host), type, checksum, [get_ip(group_record[-1]) for group_record in group_records])
		elif type == 0x17:  # Leave Group
			logging.info("%s IGMP Leave Group Request", str(cur_host), type)
	
	def handle_tcp(self, packet, ethernet_header, ip_header):
		pass
	
	def handle_udp(self, packet, ethernet_header, ip_header):
		if len(packet) < 8:
			return
		src_mac, dst_mac = ethernet_header[1], ethernet_header[0]
		ttl, src_ip, dst_ip = ip_header[5], ip_header[8], ip_header[9]
		udp_header = unpack("!HHHH", packet[:8])
		payload = packet[8:]
		src_port, dst_port = udp_header[0], udp_header[1]
		
		dst_mac = MACAddress(dst_mac)
		broadcast_ips = [b'\xE0\x00\x00\xFB', b'\xEF\xFF\xFF\xFA', b'\xFF\xFF\xFF\xFF']
		if (dst_mac.type == MACAddressType.LOCAL or dst_mac.type == MACAddressType.REGISTERED) and dst_ip not in broadcast_ips:
			return
		
		cur_host = self.get_host(ethernet_header, ip_header)
		
		if dst_port != 5353 and ("ttl" not in cur_host.attributes or ttl > cur_host.attributes["ttl"]):
			cur_host.attributes["ttl"] = ttl
			
			if ttl == 128:
				cur_host.attributes["os_ttl"] = "WINDOWS"
			elif "os_ttl" in cur_host.attributes:
				del cur_host.attributes["os_ttl"]
			
			if "os_ttl" in cur_host.attributes:
				logging.log(logging.INFO, "%s Likely OS (TTL): %s" % (str(cur_host), cur_host.attributes["os_ttl"]))
			logging.log(logging.INFO, "%s TTL: %d" % (str(cur_host), cur_host.attributes["ttl"]))
		
		if dst_port == 5353:
			logging.log(logging.DEBUG, "%s [%s] -> %s [%s]  PROTO %s  %d -> %d" % (cur_host.mac, get_ip(src_ip), dst_mac, get_ip(dst_ip), get_proto(ip_header[6]), src_port, dst_port))
			queries, answers, authority, additional, flags = self.parse_mdns(payload)
			
			if flags["response"] and flags["authoritative"]:
				device_names = set([rr[1]["domain_name"] for rr in answers if "domain_name" in rr[1]] +
				                   [rr[1]["domain_name"] for rr in authority if "domain_name" in rr[1]] +
				                   [rr[1]["domain_name"] for rr in additional if "domain_name" in rr[1]] +
				                   [rr[0] for rr in (answers + authority + additional)])
				device_names = set(name if "." not in name else name[:name.index(".")] for name in device_names if name.endswith(".local"))
				device_names = [name for name in device_names if len(name) > 0 and not (":" in name and "@" in name) and not name.startswith("_")]
				
				if len(device_names) > 0:
					if "names_mdns" not in cur_host.attributes:
						cur_host.attributes["names_mdns"] = set()
					for name in device_names:
						if name not in cur_host.attributes["names_mdns"]:
							logging.log(logging.INFO, "%s MDNS Name: %s" % (str(cur_host), name))
							cur_host.attributes["names_mdns"].add(name)
				
				for rr in queries:
					if rr[1] == 12:
						if "capabilities_mdns" not in cur_host.attributes:
							cur_host.attributes["capabilities_mdns"] = []
							cur_host.attributes["capabilities_human_mdns"] = []
						attribute = rr[0]
						if attribute.endswith(".local"):
							attribute = attribute[:-6]
						
						if attribute in self.mdns_service_lookup:
							attribute_human = self.mdns_service_lookup[attribute]
							if attribute_human not in cur_host.attributes["capabilities_human_mdns"]:
								logging.info("%s MDNS Capability: %s", str(cur_host), attribute_human)
								cur_host.attributes["capabilities_human_mdns"].append(attribute_human)
							elif attribute not in cur_host.attributes["capabilities_mdns"]:
								logging.info("%s MDNS Capability: %s", str(cur_host), attribute)
						
						if attribute not in cur_host.attributes["capabilities_mdns"]:
							cur_host.attributes["capabilities_mdns"].append(attribute)
				
				for rr in (answers + additional):
					if rr[3] == 16:
						if "attributes_mdns" not in cur_host.attributes:
							cur_host.attributes["attributes_mdns"] = []
						for attribute in rr[2]:
							if "=" in attribute and attribute not in cur_host.attributes["attributes_mdns"]:
								logging.info("%s MDNS Attribute: %s", str(cur_host), attribute)
								cur_host.attributes["attributes_mdns"].append(attribute)
								if attribute.startswith("model="):
									model_parse = self.mac_version_parser.match(attribute)
									if model_parse:
										cur_host.attributes["os_mdns"] = model_parse.group(1)
										cur_host.attributes["os_version_mdns"] = model_parse.group(2) + (".%s" % model_parse.group(3) if len(model_parse.groups()) >= 3 else "")
								if attribute.startswith("fn="):
									if "names_mdns_fn" not in cur_host.attributes:
										logging.info("%s Name: %s", str(cur_host), attribute[3:])
									cur_host.attributes["names_mdns_fn"] = attribute[3:]
		elif dst_port == 137:
			logging.log(logging.DEBUG, "%s [%s] -> %s [%s]  PROTO %s  %d -> %d" % (cur_host.mac, get_ip(src_ip), dst_mac, get_ip(dst_ip), get_proto(ip_header[6]), src_port, dst_port))
			queries, answers, authority, additional, flags = self.parse_mdns(payload)
			if flags["opcode"] == 6 and flags["broadcast"]:
				for rr in additional:
					name_encoded = rr[0]
					if rr[3] == 32 and len(name_encoded) == 32 and (rr[1]["flags"] & 0b10000000) == 0:
						# Such an inefficient encoding...
						name = "".join(chr(((ord(name_encoded[i]) - 0x41) << 4) | ((ord(name_encoded[i + 1]) - 0x41) & 0xf)) for i in range(0, 32, 2))
						name = name.strip()
						if "name_nbns" not in cur_host.attributes:
							logging.info("%s NetBIOS Name Service Name: %s", str(cur_host), name)
						cur_host.attributes["name_nbns"] = name
		elif dst_port == 57621:
			self.parse_spotify(cur_host, payload)
		elif dst_port == 32412 or dst_port == 32414:
			self.parse_plex(cur_host, payload)
		elif dst_port == 1900:
			self.parse_ssdp(cur_host, payload)
		elif dst_port == 67:
			self.parse_dhcp_request(cur_host, payload)
		elif dst_port == 68:
			self.parse_dhcp_response(cur_host, payload)
		elif dst_port == 10001:
			self.parse_ubdisc(cur_host, payload)
		elif dst_port == 15600:
			if payload.decode("UTF-8").startswith("SEARCH BSDP/"):
				if "os_bsdp" not in cur_host.attributes:
					logging.info("%s Samsung TV (BSDP)", str(cur_host))
				cur_host.attributes["os_bsdp"] = "Samsung TV"
		elif dst_port == 5002:
			if payload[:8].decode("UTF-8").startswith("DRINETTM"):
				if "applications" not in cur_host.attributes:
					cur_host.attributes["applications"] = []
				if "drobo_dashboard" not in cur_host.attributes["applications"]:
					logging.info("%s Application: Drobo Dashboard", str(cur_host))
					cur_host.attributes["applications"].append("drobo_dashboard")
		elif dst_port == 17500:
			if payload[0] == "{":
				if "applications" not in cur_host.attributes:
					cur_host.attributes["applications"] = []
				if "drobo_lan_sync" not in cur_host.attributes["applications"]:
					logging.info("%s Application: Drobo LAN Sync", str(cur_host))
					cur_host.attributes["applications"].append("drobo_lan_sync")
		elif dst_port == 7788 or dst_port == 9999:
			# ASUS Router
			pass
		elif dst_port == 54915:
			# TODO: Logitech ARX
			endstr = 1
			for i in range(1, len(payload)):
				if payload[i] == 0:
					endstr = i
					break
			if endstr > 1:
				hostname = payload[1:endstr].decode("UTF-8")
				if "applications" not in cur_host.attributes:
					cur_host.attributes["applications"] = []
				if "logitech_arx" not in cur_host.attributes["applications"]:
					logging.info("%s Application: Logitech ARX", str(cur_host))
					cur_host.attributes["applications"].append("logitech_arx")
				if "name_logitech" not in cur_host.attributes:
					cur_host.attributes["name_logitech"] = hostname
		else:
			print("Unhandled port: %d" % dst_port)
	
	def parse_mdns(self, data):
		mdnsh = unpack("!HBBHHHH", data[:12])
		response = (mdnsh[1] & 0b10000000) != 0
		authoritative = (mdnsh[1] & 0b00000100) != 0
		opcode = (mdnsh[1] & 0b01111000) >> 3
		broadcast = (mdnsh[2] & 0b00010000) != 0
		flags = {
			"response": response,
			"authoritative": authoritative,
			"broadcast": broadcast,
			"opcode": opcode
		}
		
		# print("    %s %s %s %s %s" % (reply, opcode, auth, trnc, recursive))
		# print("    %d %d %d %d" % (mdnsh[3], mdnsh[4], mdnsh[5], mdnsh[6]))
		
		def parse_text(cur_ptr, max_count=None, delimiter="."):
			total_length = 0
			text_length = 1
			text = ""
			cur_count = 0
			using_fqdn = False
			while (max_count is None or cur_count < max_count) and text_length > 0 and cur_ptr < len(data):
				text_length = data[cur_ptr]
				if (text_length & 0b11000000) == 0xC0:  # We all love special cases
					cur_ptr = ((data[cur_ptr] & 0b00111111) << 8) | data[cur_ptr+1]
					if not using_fqdn:
						total_length += 2
					using_fqdn = True
					continue
				if not using_fqdn:
					total_length += 1 + text_length
				cur_count += 1
				if text_length > 0:
					if len(text) > 0:
						text += delimiter
					try:
						text += data[cur_ptr+1:cur_ptr+1+text_length].decode("utf-8")
					except UnicodeDecodeError:
						text += str(bytes(data[cur_ptr+1:cur_ptr+1+text_length]))
				cur_ptr += 1 + text_length
			return text, total_length
		
		def parse_queries(cur_ptr, count):
			queries = []
			start_ptr = cur_ptr
			for _ in range(count):
				name, n = parse_text(cur_ptr)
				cur_ptr += n
				type, cls = unpack("!HH", data[cur_ptr:cur_ptr + 4])
				cur_ptr += 4
				queries.append([name, type, cls])
			return queries, cur_ptr - start_ptr
		
		def parse_rr(cur_ptr, count):
			rrs = []
			start_ptr = cur_ptr
			for _ in range(count):
				name, n = parse_text(cur_ptr)
				cur_ptr += n
				type, cls, ttl, data_len = unpack("!HHIH", data[cur_ptr:cur_ptr + 10])
				cur_ptr += 10
				rr_data = {}
				strings = []
				if type == 16:
					tmp_ptr = cur_ptr
					while tmp_ptr < cur_ptr + data_len:
						txt, n = parse_text(tmp_ptr, delimiter="\0")
						txt = txt.split("\0")
						tmp_ptr += n
						strings += txt
				elif type == 12:  # Domain Name PTR
					name, _ = parse_text(cur_ptr, max_count=1)
					rr_data["domain_name"] = name
				elif type == 32:  # NetBIOS Name
					tmp_ptr = cur_ptr
					if data_len == 6:
						flags, addr = unpack("!H4s", data[tmp_ptr:tmp_ptr+6])
						rr_data["flags"] = flags
						rr_data["addr"] = addr
				cur_ptr += data_len
				rrs.append([name, rr_data, strings, type, cls, ttl])
			return rrs, cur_ptr - start_ptr
		
		ptr = 12
		queries, n = parse_queries(ptr, mdnsh[3])
		ptr += n
		answers, n = parse_rr(ptr, mdnsh[4])
		ptr += n
		authority, n = parse_rr(ptr, mdnsh[5])
		ptr += n
		additional, n = parse_rr(ptr, mdnsh[6])
		ptr += n
		return queries, answers, authority, additional, flags
	
	def parse_spotify(self, host, data):
		if data[:8].decode("utf-8") != "SpotUdp0":
			return
		
		unique_id = sum((data[i] << ((8 - (i - 8)) * 8)) for i in range(8, 16))
		unknown_short1 = (data[16] << 8) | data[17]
		unknown_short2 = (data[18] << 8) | data[19]
		if unknown_short1 != 1:
			print("ADMIN_NOTIF: Spotify Parser Anomaly. Short #1 is: %04X" % unknown_short1)
		if unknown_short2 != 0 and unknown_short2 != 4:
			print("ADMIN_NOTIF: Spotify Parser Anomaly. Short #2 is: %04X" % unknown_short2)
		
		unique_id_str = "%16X" % unique_id
		if "uid_spotify" not in host.attributes or host.attributes["uid_spotify"] != unique_id_str:
			logging.log(logging.INFO, "%s Spotify UID: %s  (mobile=%s)" % (str(host), unique_id_str, (unknown_short2 == 0)))
		host.attributes["uid_spotify"] = unique_id_str
		host.attributes["mobile_spotify"] = (unknown_short2 == 0)

	def parse_plex(self, host, data):
		# Plex Discovery uses a HTTP based protocol
		data_str = data.decode("UTF-8")
		data_lines = data_str.split("\r\n")
		if len(data_lines) == 0:
			return
		if data_str.startswith("M-SEARCH * HTTP/"):
			search_line = data_lines[0].split(" ")
			if "plex_discovery" not in host.attributes:
				host.attributes["plex_discovery"] = True
				host.attributes["plex_discovery_protocol"] = search_line[2]
				logging.info("%s Plex Discovery using %s", str(host), search_line[2])
	
	def parse_ssdp(self, host, data):
		data_str = data.decode("UTF-8")
		data_lines = data_str.split("\r\n")
		for line in data_lines:
			if len(line) == 0:
				break
			if ": " in line:
				key, value = line.split(": ", 2)
				if key.upper() == "USER-AGENT" and "user_agent_ssdp" not in host.attributes:
					logging.info("%s User Agent (SSDP): %s", str(host), value)
					host.attributes["user_agent_ssdp"] = value
	
	def parse_dhcp_request(self, host, data):
		dhcp_packet = unpack("!BBBBIHH4s4s4s4s6s10s64s128s4s", data[:240])
		if dhcp_packet[-1] != b"\x63\x82\x53\x63":  # Magic Cookie
			return
		options = []
		options_parsed = {}
		option_index = 240
		while option_index < len(data):
			option_type = data[option_index]
			if option_type == 255:
				break
			option_info = self.dhcp_option_lookup[option_type]
			if option_info[1] == "0" or option_index + 1 >= len(data):
				option_index += 1
				continue
			length = data[option_index+1]
			if option_index + 2 + length >= len(data):
				break
			option_data = data[option_index+2:option_index+2+length]
			option_index += length + 2
			options.append([option_type, option_info, option_data])
			
			if option_type == 12:  # Hostname
				options_parsed["hostname_dhcp"] = option_data.decode("UTF-8"), "Hostname"
			elif option_type == 60:  # Vendor Class Identifier
				options_parsed["vendor_dhcp"] = option_data.decode("UTF-8"), "Vendor Class Identifier"
			elif option_type == 81:  # Client FQDN
				options_parsed["fqdn_dhcp"] = option_data.decode("UTF-8"), "Client FQDN"
		# op, htype, hlen, hops, xid, secs, flags
		# ciaddr, yiaddr, siaddr, giaddr, chaddr
		# sname, file, options
		logging.info("DHCP Request %02X from %s  %s", dhcp_packet[0], MACAddress(dhcp_packet[11]), dhcp_packet[13].decode("UTF-8"))
		for option_parsed in options_parsed:
			if option_parsed not in host.attributes:
				option_data, option_description = options_parsed[option_parsed]
				logging.info("%s %s: %s", str(host), option_description, option_data)
				host.attributes[option_parsed] = option_data
	
	def parse_dhcp_response(self, host, data):
		dhcp_packet = unpack("!BBBBIHH4s4s4s4s6s10s64s128s", data[:236])
		logging.info("DHCP Response %02X from %s", dhcp_packet[0], MACAddress(dhcp_packet[11]))
	
	def parse_ubdisc(self, host, data):
		disc_version, disc_type, disc_length = unpack("!BBH", data[:4])
		idx = 4
		attributes = {}
		while idx < 4 + disc_length:
			field_type, field_length = unpack("!BH", data[idx:idx + 3])
			field_data = data[idx + 3:idx + 3 + field_length]
			idx += 3 + field_length
			if field_type == 0x0A:  # Uptime
				host.attributes["uptime_ubdisc"] = unpack("!I", field_data)[0]
				attributes["uptime"] = unpack("!I", field_data)[0]
			elif field_type == 0x0B:  # Hostname
				host.attributes["hostname_ubdisc"] = field_data.decode("UTF-8")
			elif field_type == 0x0C:  # Platform
				host.attributes["platform_ubdisc"] = field_data.decode("UTF-8")
			elif field_type == 0x03:  # Firmware
				host.attributes["firmware_ubdisc"] = field_data.decode("UTF-8")
				attributes["firmware"] = field_data.decode("UTF-8")
			elif field_type == 0x16:  # Version
				host.attributes["version_ubdisc"] = field_data.decode("UTF-8")
			elif field_type == 0x19:  # Version
				host.attributes["has_dhcp_client_ubdisc"] = field_data[0] == 1
		logging.info("Ubiquiti Discovery  uptime=%d  firmware=%s" % (attributes.get("uptime", 0), attributes.get("firmware", "")))
