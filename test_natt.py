from backend.sample_data.generate_sample_pcap import _generate_natt
from backend.analyzers.pcap_parser import parse_pcap
from backend.analyzers.ipsec_analyzer import analyze_ipsec
from scapy.all import wrpcap
packets = _generate_natt()
wrpcap("test_natt.pcap", packets)
parsed = parse_pcap("test_natt.pcap")
analysis = analyze_ipsec(parsed)
print("NAT-T Detected:", analysis["nat_t_analysis"]["detected"])
print("ESP Packets:", analysis["esp_analysis"]["packet_count"])
