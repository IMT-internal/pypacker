"""
Multiprotocol Label Switching
"""
from pypacker import pypacker
from pypacker.layer3 import ip, ip6
from pypacker.structcbs import *


# Bit/Byte encoding MPLS fields
BYTE_AND_BIT_ORDERING = {
	"label": (0xFFFFF000, 12),
	"cos": (0x00000E00, 9),
	"bos": (0x00000100, 8),
	"ttl": (0x000000FF, 0),
}


def get_property_of_mpls_field(varname):
	"""Create a get/set-property for byte/bit encoding of MPLS fields."""
	mask = BYTE_AND_BIT_ORDERING.get(varname)[0]
	bit_order = BYTE_AND_BIT_ORDERING.get(varname)[1]
	return property(
		lambda obj: (obj.mpls_fields & mask) >> bit_order,
		lambda obj, val: obj.__setattr__("mpls_fields",
			(obj.mpls_fields & ~mask) | (val << bit_order)),
	)

def define_ip_version(buf):
	hlen = 4
	dlen = len(buf) - hlen
	ip_version = (int.from_bytes(buf[hlen: hlen + 1], byteorder='little') >> 4) & 0xF
	if ip_version == 4:
		dlen_ip = unpack_H(buf[hlen + 2: hlen + 4])[0]  # real data length

		if dlen_ip < dlen:
			# padding found
			# self._padding = buf[hlen + dlen_ip:]
			# logger.debug("got padding for IPv4: %r" % self._padding)
			dlen = dlen_ip
	# handle padding using IPv6
	# IPv6 is a piece of sh$§! payloadlength (in header) = exclusive standard header
	# but INCLUSIVE options!
	elif ip_version == 6:
		dlen_ip = unpack_H(buf[hlen + 4: hlen + 6])[0]  # real data length
		# logger.debug("eth.hlen=%d, data length based on header: %d" % (hlen, dlen_ip))

		if 40 + dlen_ip < dlen:
			# padding found
			# self._padding = buf[hlen + 40 + dlen_ip:]
			# logger.debug("got padding for IPv6: %r" % self._padding)
			dlen = 40 + dlen_ip
	return ip_version, hlen, dlen

class MPLS2(pypacker.Packet):
	__hdr__ = (
		("mpls_fields", "L", 12799),
	)

	label = get_property_of_mpls_field("label")
	cos = get_property_of_mpls_field("cos")
	bos = get_property_of_mpls_field("bos")
	ttl = get_property_of_mpls_field("ttl")

	__handler__ = {
		4: ip.IP,
		6: ip6.IP6,
	}

	def _dissect(self, buf):
		ip_version, hlen, dlen = define_ip_version(buf)
		self._init_handler(ip_version, buf[hlen: hlen + dlen])
		return hlen

class MPLS(pypacker.Packet):
	__hdr__ = (
		("mpls_fields", "L", 12799),
	)

	label = get_property_of_mpls_field("label")
	cos = get_property_of_mpls_field("cos")
	bos = get_property_of_mpls_field("bos")
	ttl = get_property_of_mpls_field("ttl")

	__handler__ = {
		4: ip.IP,
		6: ip6.IP6,
		0: MPLS2,
	}

	def _dissect(self, buf):
		ip_version, hlen, dlen = define_ip_version(buf)
		if int(int.from_bytes(buf[: hlen], byteorder='little') >> 8) & 0x00000100:
			self._init_handler(ip_version, buf[hlen: hlen + dlen])
		else:
			self._init_handler(0, buf[hlen: hlen + dlen])
		return hlen
