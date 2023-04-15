import pathlib
from enum import Enum
from typing import Tuple


class MACAddressType(Enum):
	UNKNOWN = 0
	BROADCAST = 1
	IPV4_MULTICAST = 2
	MPLS_MULTICAST = 3
	VRRP_IPV4 = 4
	VRRP_IPV6 = 5
	IPV6_MULTICAST = 6
	POINT_TO_POINT = 7
	LOCAL = 8
	REGISTERED = 9


class MACAddress:
	oui_lookup = None
	
	def __init__(self, mac: bytes):
		self.mac = mac
		self.type, self.organization = self.get_organization(mac)
	
	def __repr__(self):
		return "%s[%s/%s]" % (":".join("%02X" % b for b in self.mac), self.type.name, self.organization)
	
	@staticmethod
	def get_organization(mac: bytes) -> Tuple[MACAddressType, str]:
		if MACAddress.oui_lookup is None:
			MACAddress.oui_lookup = {}
			engine_directory = pathlib.Path(__file__).parent.parent.absolute()
			with open("%s/resources/oui.txt" % engine_directory, "r") as file:
				for line in file.readlines():
					if "(base 16)" not in line:
						continue
					idx = line.index("(base 16)")
					oui = line[:idx].rstrip()
					organization = line[idx + 9:].strip()
					oui = "%s:%s:%s" % (oui[:2], oui[2:4], oui[4:6])
					MACAddress.oui_lookup[oui] = organization
		mac_oui = (mac[0] << 16) | (mac[1] << 8) | mac[2]
		mac_adr = (mac[3] << 16) | (mac[4] << 8) | mac[5]
		if mac_oui == 0xFFFFFF and mac_adr == 0xFFFFFF:
			return MACAddressType.BROADCAST, ""
		if mac_oui == 0x01005E:
			if mac_adr < 0x800000:
				return MACAddressType.IPV4_MULTICAST, ""
			return MACAddressType.MPLS_MULTICAST, ""
		if (mac_oui & 0xFFFF00) == 0x333300:
			return MACAddressType.IPV6_MULTICAST, ""
		if mac_oui == 0x00005E:
			if (mac_adr & 0xFFFF00) == 0x0001:
				return MACAddressType.VRRP_IPV4, ""
			if (mac_adr & 0xFFFF00) == 0x0002:
				return MACAddressType.VRRP_IPV6, ""
			return MACAddressType.UNKNOWN, ""
		if (mac_oui & 0xFF0000) == 0xCF0000:
			return MACAddressType.POINT_TO_POINT, ""
		if (mac_oui & 0b00000010_00000000_00000000) != 0:
			return MACAddressType.LOCAL, ""
		
		src_mac_lookup = "%02X:%02X:%02X" % (mac[0], mac[1], mac[2])
		if src_mac_lookup in MACAddress.oui_lookup:
			return MACAddressType.REGISTERED, MACAddress.oui_lookup[src_mac_lookup]
		return MACAddressType.UNKNOWN, ""
