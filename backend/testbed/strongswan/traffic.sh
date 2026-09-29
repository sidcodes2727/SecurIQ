#!/bin/bash
# Application-like traffic through the tunnel (run on the initiator).
# usage: traffic.sh <class> <seconds>
# Classes mirror backend/testbed/traffic_models.py. E-mail and chat are approximations built
# from HTTP exchanges with the same size/timing structure (no SMTP server in the lab).
set -uo pipefail
CLASS=$1; SECONDS_TOTAL=$2
PEER=$(cat /tmp/peer)
URL_HOST=$PEER; [[ $PEER == *:* ]] && URL_HOST="[$PEER]"
BASE="http://$URL_HOST:8080"
END=$((SECONDS + SECONDS_TOTAL))

case "$CLASS" in
  icmp)
    ping -c "$SECONDS_TOTAL" -i 1 "$PEER" >/dev/null ;;
  voip)   # RTP-like: 172-byte datagrams at 50 packets/s, both directions
    iperf3 -c "$PEER" -u -b 69k -l 172 --bidir -t "$SECONDS_TOTAL" >/dev/null ;;
  video)  # DASH-like: a 1–3 MB segment every 4 s
    while [ $SECONDS -lt $END ]; do curl -s -o /dev/null -r 0-$((RANDOM % 2000000 + 1000000)) "$BASE/large.bin"; sleep 4; done ;;
  file_transfer)
    curl -s -o /dev/null --limit-rate 3M --max-time "$SECONDS_TOTAL" "$BASE/large.bin" ;;
  web)    # page = small document + several objects, then think time
    while [ $SECONDS -lt $END ]; do
      for obj in 20k 2k 80k 2k 250k 20k; do curl -s -o /dev/null "$BASE/obj-$obj.bin" & done; wait
      sleep $((RANDOM % 6 + 2))
    done ;;
  email)  # command/response turns, then one message transfer
    while [ $SECONDS -lt $END ]; do
      for _ in 1 2 3 4 5 6; do curl -s -o /dev/null -r 0-120 "$BASE/obj-2k.bin"; sleep 0.1; done
      curl -s -o /dev/null "$BASE/obj-80k.bin"; sleep $((RANDOM % 8 + 3))
    done ;;
  chat)   # sporadic small messages + receipts
    while [ $SECONDS -lt $END ]; do
      curl -s -o /dev/null -r 0-$((RANDOM % 350 + 80)) "$BASE/obj-2k.bin"; sleep $((RANDOM % 5 + 1))
    done ;;
  *) echo "unknown class $CLASS" >&2; exit 2 ;;
esac
