from .parser import NetworkParser


class MDNS:
	
	def parse_mdns(self, data):
		data = NetworkParser(data)
		mdnsh = data.unpack("!HBBHHHH")
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
		
		def parse_queries(count):
			queries = []
			for _ in range(count):
				name = data.dns_string()
				type, cls = data.unpack("!HH")
				queries.append([name, type, cls])
			return queries
		
		def parse_rr(count):
			rrs = []
			for _ in range(count):
				name = data.dns_string()
				type, cls, ttl, data_len = data.unpack("!HHIH")
				type_data = NetworkParser(data.raw(data_len))
				rr_data = {}
				strings = []
				if type == 16:
					while type_data.remaining() > 0:
						txt = type_data.dns_string(delimiter="\0").split("\0")
						strings += txt
				elif type == 12:  # Domain Name PTR
					name = type_data.dns_string(max_count=1)
					rr_data["domain_name"] = name
				elif type == 32:  # NetBIOS Name
					name = NetworkParser.decode_netbios(name)
					if data_len == 6:
						flags, addr = type_data.unpack("!H4s")
						rr_data["flags"] = flags
						rr_data["addr"] = addr
				rrs.append([name, rr_data, strings, type, cls, ttl])
			return rrs
		
		queries = parse_queries(mdnsh[3])
		answers = parse_rr(mdnsh[4])
		authority = parse_rr(mdnsh[5])
		additional = parse_rr(mdnsh[6])
		return queries, answers, authority, additional, flags
