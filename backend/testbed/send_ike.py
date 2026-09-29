"""Send real IKE messages from a stored capture onto a network interface, to exercise live capture.

Live capture needs traffic to see. This replays the UDP-500 payloads of a testbed sample (or any pcap) as ordinary UDP
datagrams to a host you choose, by default this machine's loopback address, so `securiq live capture <loopback>` has
genuine IKE to identify. ESP is a raw IP protocol and cannot be sent from a normal socket, so only IKE is replayed.

    python -m backend.testbed.send_ike moderate_ikev2_cbc_sha1_nopfs
    python -m backend.testbed.send_ike path\\to\\capture.pcap --host 127.0.0.1 --delay 0.2
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

IKE_PORT = 500


def ike_payloads(pcap: Path, limit: int) -> list[bytes]:
    from scapy.all import UDP, rdpcap
    packets = rdpcap(str(pcap))
    return [bytes(p[UDP].payload) for p in packets if UDP in p and IKE_PORT in (p[UDP].sport, p[UDP].dport)][:limit]


def resolve(target: str) -> Path:
    if Path(target).is_file():
        return Path(target)
    from backend.storage import resolve_capture
    resolved = resolve_capture(target)
    if resolved is None:
        raise SystemExit(f"'{target}' is not a file or a known sample (try `securiq captures`)")
    return resolved[0]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="pcap path or testbed sample name")
    ap.add_argument("--host", default="127.0.0.1", help="destination address (default: loopback)")
    ap.add_argument("--delay", type=float, default=0.2, help="seconds between messages")
    ap.add_argument("--limit", type=int, default=30, help="maximum messages to send")
    ap.add_argument("--repeat", type=int, default=1, help="send the whole exchange this many times")
    args = ap.parse_args()

    messages = ike_payloads(resolve(args.capture), args.limit)
    if not messages:
        raise SystemExit("No IKE (UDP 500) messages found in that capture")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((args.host if args.host.startswith("127.") else "", IKE_PORT))  # look like an IKE peer if we can
    except OSError:
        pass  # port 500 may belong to the OS IKE service; the destination port is what matters
    sent = 0
    for _ in range(args.repeat):
        for message in messages:
            sock.sendto(message, (args.host, IKE_PORT))
            sent += 1
            time.sleep(args.delay)
    print(f"sent {sent} IKE messages ({len(messages)} distinct) to {args.host}:{IKE_PORT}")


if __name__ == "__main__":
    sys.exit(main())
