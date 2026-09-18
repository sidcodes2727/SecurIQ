from backend.sample_data.generate_sample_pcap import _generate_natt
from backend.analyzers.pcap_parser import parse_pcap
from scapy.all import wrpcap
packets = _generate_natt()
wrpcap("test_natt.pcap", packets)
parsed = parse_pcap("test_natt.pcap")
pkts = parsed.get("packets", [])
nat_t_esp = [p for p in pkts if p.get("protocol_type") == "esp" and p.get("nat_t")]
print("Found nat_t_esp:", len(nat_t_esp))
