#!/bin/bash
# Run inside the initiator: capture, bring the tunnel up, generate traffic, save pcap + ground truth.
set -euo pipefail
NAME=${PROFILE_NAME:?profile name missing}
OUT=/captures
mkdir -p "$OUT"

tcpdump -i eth0 -s 0 -U -w "$OUT/$NAME.pcap" 'udp port 500 or udp port 4500 or esp or ah' >/dev/null 2>&1 &
TCPDUMP=$!
sleep 1

swanctl --initiate --child net --timeout 30
for spec in $TRAFFIC; do            # e.g. "web:40 video:40"
  class=${spec%%:*}; seconds=${spec##*:}
  echo "traffic: $class for ${seconds}s"
  /lab/traffic.sh "$class" "$seconds"
  sleep 2
done
sleep 2
kill "$TCPDUMP"; wait "$TCPDUMP" 2>/dev/null || true

# Ground truth = the profile that configured both gateways.
python3 - "$OUT/$NAME.json" <<'PY'
import json, os, sys
keys = ["PROFILE_NAME", "DESCRIPTION", "IKE_VERSION", "AGGRESSIVE", "IKE_PROPOSALS", "ESP_PROPOSALS", "MODE",
        "IP_FAMILY", "FORCE_ENCAP", "CHILD_REKEY_TIME", "IKE_REKEY_TIME", "TRAFFIC"]
json.dump({k.lower(): os.environ.get(k) for k in keys}, open(sys.argv[1], "w"), indent=2)
PY
echo "saved $OUT/$NAME.pcap"
