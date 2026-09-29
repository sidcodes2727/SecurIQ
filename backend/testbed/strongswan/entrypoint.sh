#!/bin/bash
# Configure one lab gateway from the profile, start charon and load the connection.
# ROLE=initiator|responder is set by docker-compose; the profile arrives via env_file.
set -euo pipefail

if [ "${IP_FAMILY:-4}" = "6" ]; then
  A_ADDR=fd30::a; B_ADDR=fd30::b; A_INNER=fd31::1; B_INNER=fd32::1; PREFIX=128
else
  A_ADDR=172.30.0.10; B_ADDR=172.30.0.20; A_INNER=10.1.0.1; B_INNER=10.2.0.1; PREFIX=32
fi

if [ "$ROLE" = "initiator" ]; then
  export LOCAL_ADDR=$A_ADDR REMOTE_ADDR=$B_ADDR LOCAL_ID=gw-a.lab.example REMOTE_ID=gw-b.lab.example
  LOCAL_INNER=$A_INNER; REMOTE_INNER=$B_INNER
else
  export LOCAL_ADDR=$B_ADDR REMOTE_ADDR=$A_ADDR LOCAL_ID=gw-b.lab.example REMOTE_ID=gw-a.lab.example
  LOCAL_INNER=$B_INNER; REMOTE_INNER=$A_INNER
fi

if [ "${MODE:-tunnel}" = "tunnel" ]; then
  # Site-to-site: a private "LAN" address behind each gateway; charon installs routes (table 220).
  ip addr add "$LOCAL_INNER/$PREFIX" dev lo 2>/dev/null || true
  export LOCAL_TS="$LOCAL_INNER/$PREFIX" REMOTE_TS="$REMOTE_INNER/$PREFIX"
  echo "$REMOTE_INNER" > /tmp/peer
else
  export LOCAL_TS=dynamic REMOTE_TS=dynamic
  echo "$REMOTE_ADDR" > /tmp/peer
fi

export AGGRESSIVE=${AGGRESSIVE:-no} FORCE_ENCAP=${FORCE_ENCAP:-no}
export IKE_REKEY_TIME=${IKE_REKEY_TIME:-4h} CHILD_REKEY_TIME=${CHILD_REKEY_TIME:-1h}
export CHILD_LIFE_TIME=${CHILD_LIFE_TIME:-2h}
envsubst < /lab/swanctl.conf.tmpl > /etc/swanctl/swanctl.conf

/usr/libexec/ipsec/charon &
for _ in $(seq 1 30); do [ -S /var/run/charon.vici ] && break; sleep 0.5; done
swanctl --load-all

if [ "$ROLE" = "responder" ]; then
  # Application endpoints for traffic.sh
  mkdir -p /srv/www
  for size in 2k 20k 80k 250k 2M; do head -c "$size" /dev/urandom > "/srv/www/obj-$size.bin"; done
  head -c 30M /dev/urandom > /srv/www/large.bin
  (cd /srv/www && python3 -m http.server 8080 --bind "::" >/dev/null 2>&1 &)
  iperf3 -s -D
fi

echo "gateway ready: role=$ROLE profile=${PROFILE_NAME:-?} mode=$MODE family=IPv${IP_FAMILY:-4}"
sleep infinity
