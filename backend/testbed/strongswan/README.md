# strongSwan lab testbed

Two strongSwan gateways in Docker that negotiate real IPsec tunnels for each profile of the
configuration matrix, push application-like traffic through them, and save a capture plus its
ground truth. Use it to validate SecurIQ's side-channel inferences on real wire traffic, and to
extend the training data beyond the synthetic generator.

> **Status:** written for this MVP but **not yet executed**. The build machine's Docker engine was
> stopped. Run it once on Linux or WSL2 with Docker and compare the results with the synthetic
> scenarios before quoting real-world accuracy.

## Requirements

- Docker with Compose v2, on a Linux host or WSL2 (kernel XFRM support; the containers need `NET_ADMIN`)
- About 1 minute per profile

## Run

```bash
cd backend/testbed/strongswan
./run_matrix.sh                        # every profile in profiles/
./run_matrix.sh 04-ikev1-aggressive-psk  # a single profile
```

Each profile writes `captures/<profile>.pcap` and `captures/<profile>.json` (the profile values,
i.e. the ground truth). Upload the PCAPs in the dashboard (**Captures & samples**) and compare
the *Protocol identification* tab with the JSON.

## Profiles

| Profile | What it exercises |
|---|---|
| `01-ikev2-strong-pfs` | AES-256-GCM, ECP-384, PFS on 40 s Child SA rekeys, web + video |
| `02-ikev2-cbc-sha1-nopfs` | AES-128-CBC/SHA1, MODP-2048, no PFS, weak fallback proposal offered |
| `03-ikev1-main-3des-md5` | IKEv1 Main Mode, 3DES/MD5, MODP-1024, 7-day IKE lifetime |
| `04-ikev1-aggressive-psk` | Aggressive Mode + PSK: identity and crackable hash in cleartext |
| `05-ikev2-transport-ipv6` | Transport mode over IPv6, Curve25519, PFS |
| `06-ikev2-natt-chacha` | Forced UDP-4500 encapsulation (NAT-T), ChaCha20-Poly1305 |
| `07-esp-null` | ESP-NULL (integrity only) |

Add a profile by copying an `.env` file. The keys map one-to-one onto `swanctl.conf`
(`IKE_PROPOSALS` → `proposals`, `ESP_PROPOSALS` → `esp_proposals`, and a DH group in
`ESP_PROPOSALS` enables PFS). `TRAFFIC` is a list of `class:seconds`, using classes from
`traffic.sh`: `icmp web voip video email chat file_transfer`.

## How it works

- `docker-compose.yml`: `gw-a` (initiator) and `gw-b` (responder) on 172.30.0.0/24 and fd30::/64.
- `entrypoint.sh`: renders `swanctl.conf` from the profile, starts `charon`, and loads the connection.
  In tunnel mode each gateway gets a private LAN address (10.1.0.1 / 10.2.0.1) so traffic is
  genuinely tunnelled.
- `run-scenario.sh` (on gw-a): starts `tcpdump` (IKE, NAT-T, ESP, AH only), initiates the Child SA,
  runs `traffic.sh` for each class, then writes the pcap and the ground-truth JSON.
- `strongswan.conf` enables Aggressive-Mode PSK for the lab. **Never** copy that setting to production.

The PSKs in `profiles/` exist for this isolated lab only.
