"""
VPN testbed: reproducible IPsec captures across a configuration matrix, with ground truth.

- esp_model.py       cipher-suite framing (IV / block / ICV) shared with the ML dataset
- traffic_models.py  application packet-sequence generators
- ike_builder.py     IKEv1 / IKEv2 message construction (RFC-accurate wire format)
- pcap_writer.py     fast PCAP writer (Ethernet + IPv4/IPv6 + UDP/ESP/AH)
- scenarios.py       configuration matrix, curated demo scenarios, capture builder
- build_dataset.py   CLI: labelled PCAP dataset + manifest + feature table
- strongswan/        real strongSwan docker testbed producing the same matrix on the wire
"""
