from backend.sample_data.generate_sample_pcap import _generate_natt
from backend.analyzers.pcap_parser import parse_pcap
from scapy.all import wrpcap, rdpcap, IP
packets = _generate_natt()
wrpcap("test_natt.pcap", packets)
parsed = parse_pcap("test_natt.pcap")
for p in parsed.get("packets", [])[:5]:
    print(p.get("protocol_type"), p.get("nat_t"))
