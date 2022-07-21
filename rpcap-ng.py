#!/usr/bin/python3
import zstandard as zstd
import dpkt
import sys

def read_pcap(pfile):
	fp = open(pfile, "rb")
	packets = dpkt.pcapng.Reader(fp)
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
	main(read_pcap(sys.argv[1]))
