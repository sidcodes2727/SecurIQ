#!/bin/bash
# Run every profile (or the ones given as arguments) and collect captures/<profile>.{pcap,json}.
#   ./run_matrix.sh                      # all profiles
#   ./run_matrix.sh 03-ikev1-main-3des-md5
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p captures
profiles=("$@")
[ ${#profiles[@]} -eq 0 ] && profiles=($(ls profiles | sed 's/\.env$//'))

for profile in "${profiles[@]}"; do
  echo "=== $profile"
  export PROFILE=$profile
  docker compose up -d --build
  for _ in $(seq 1 30); do
    docker compose logs gw-b 2>/dev/null | grep -q "gateway ready" && docker compose logs gw-a 2>/dev/null | grep -q "gateway ready" && break
    sleep 1
  done
  docker compose exec -T gw-a /lab/run-scenario.sh || echo "!! $profile failed"
  docker compose down -v
done
echo "Captures in $(pwd)/captures — upload them in the SecurIQ dashboard (Captures & samples)."
