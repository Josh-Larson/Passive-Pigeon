import struct


class NetworkParser:
	def __init__(self, buffer, index=0):
		self.buffer = buffer
		self.index = index
	
	def index(self, new_index=None):
		if new_index is not None:
			self.index = new_index
		else:
			return self.index
	
	def remaining(self):
		return len(self.buffer) - self.index
	
	def raw(self, length):
		r = self.buffer[self.index:self.index + length]
		self.index += length
		return r
	
	def dns_string(self, max_count=None, delimiter="."):
		text_length = 1
		text = ""
		cur_count = 0
		using_fqdn = False
		dns_index = self.index
		
		while (max_count is None or cur_count < max_count) and text_length > 0 and dns_index < len(self.buffer):
			text_length = self.buffer[dns_index]
			if (text_length & 0b11000000) == 0xC0:  # We all love special cases
				dns_index = ((self.buffer[dns_index] & 0b00111111) << 8) | self.buffer[dns_index + 1]
				if not using_fqdn:
					self.index += 2
				using_fqdn = True  # Disables the index increment--since we're now at a completely different index
				continue
			cur_count += 1
			if text_length > 0:
				if len(text) > 0:
					text += delimiter
				next_text = self.buffer[dns_index + 1:dns_index + 1 + text_length]
				try:
					text += next_text.decode("utf-8")
				except UnicodeDecodeError:
					text += str(bytes(next_text))
			dns_index += 1 + text_length
			if not using_fqdn:
				self.index += 1 + text_length
		return text
	
	def c_string(self, char_size=1):
		start_index = self.index
		while self.index < len(self.buffer) and self.buffer[self.index] != 0:
			self.index += char_size
		self.index += char_size
		return self.buffer[start_index:self.index-1]

	def unpack(self, fmt):
		size = struct.calcsize(fmt)
		r = struct.unpack(fmt, self.buffer[self.index:self.index+size])
		self.index += size
		return r

	@staticmethod
	def decode_netbios(netbios_string):
		return ("".join(chr(((ord(netbios_string[i]) - 0x41) << 4) | ((ord(netbios_string[i + 1]) - 0x41) & 0xf)) for i in range(0, 32, 2))).strip(" \0")
