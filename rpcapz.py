#!/usr/bin/python3
import zstandard as zstd
import dpkt
import sys


def extract_zst(zstfile):
	with open(zstfile, "rb") as f:
		data = f.read()
	dctx = zstd.ZstdDecompressor()
	decompressed = dctx.stream_reader(data)
	packets = dpkt.pcap.Reader(decompressed)
	print("-----Extracted .zst successfull-----")
	return packets

def main(packets):
	count_tcp = 0
	count_udp = 0
	count_icmp = 0
	for ts, buf in packets:
		try: 
			eth = dpkt.ethernet.Ethernet(buf)
		except:
			print("Faile parse Frame")

		if type(eth.data) == dpkt.ip.IP:
			ip = eth.data
			if ip.p == dpkt.ip.IP_PROTO_TCP: count_tcp += 1
			if ip.p == dpkt.ip.IP_PROTO_UDP: count_udp += 1
			if ip.p == dpkt.ip.IP_PROTO_ICMP: count_icmp += 1
	print("##########PCAP FILE INFORMATION##########")
	print("TCP Packets: {}".format(count_tcp))
	print("UDP Packets: {}".format(count_udp))
	print("ICMP Packets: {}".format(count_icmp))

if __name__ == "__main__":
	main(extract_zst(sys.argv[1]))
