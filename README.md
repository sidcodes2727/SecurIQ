# SecurIQ — AI-Powered IPsec VPN Protocol Analyzer

SIH 26160 (NTRO) · *AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework*

SecurIQ analyses a capture of an IPsec VPN **passively, without keys**. It tells an analyst what
the VPN is (protocols, IKE version, mode, algorithms, key exchange, SA behaviour, and the traffic
inside the tunnel), **how sure it is about each claim**, and how secure the deployment is. It
produces executive and technical reports, and it ships the lab that generates labelled captures
to train and evaluate the AI.

The design, the verified gaps in the previous version, and the decision log are in
[docs/MVP_PLAN.md](docs/MVP_PLAN.md).

## Quick start (terminal)

SecurIQ is a terminal package: one `securiq` command holds every feature, and `securiq` on its own opens a
full-screen, Palantir-style operations console.

```powershell
.\setup.ps1          # Windows PowerShell
./setup.sh           # Linux / macOS / WSL
```

Or by hand, from the repository root: `pip install -e . && securiq init && securiq`.

```bash
securiq                                        # the console: dashboard, explorer, link graph, triage, workspace, live, lab
securiq analyze weak_ikev1_main_3des_md5       # analyse a sample (or a .pcap/.pcapng path) from the shell
securiq whatif latest --recommended --verify   # what-if, then verified in the digital twin
securiq --help                                 # every command
```

The full guide (console views and keys, every command, architecture) is in [docs/TERMINAL.md](docs/TERMINAL.md).

## Quick start (web UI, optional)

The React front end and its API are still available and share the terminal's data directory and analyses:

```bash
backend/venv/Scripts/python -m uvicorn backend.main:app --port 8000   # Windows (Linux: backend/venv/bin/python)
cd frontend && npm run dev                                             # second terminal
```

Open http://localhost:5173. On first start the backend generates 10 testbed captures and trains
the classifier in the background (about 30 s; the header shows *Model training…*). Then go to
**Captures & samples → Analyse**.

## Decision support: attack → observe → explain → fix → verify

SecurIQ is built around one loop. Every step has its own page:

| Step | Page | What it does |
|---|---|---|
| Attack | **VPN lab** | A digital twin: choose IKE version, ciphers, DH group, PFS, mode, lifetimes and the applications inside the tunnel; SecurIQ generates the negotiation and encrypted traffic, captures it, and analyses the PCAP. Also emits the matching strongSwan profile for the Docker lab. |
| Observe | **Protocol identification** | Every property with its evidence checklist (✓ supporting observations, ✕ contrary ones, ! limits), an IKE message ladder (cleartext vs encrypted), ESP packet anatomy reconstructed from lengths, and sequence-number plots that pinpoint replayed frames. |
| Explain | **Security assessment** | Each finding is an evidence chain: *packet frames → extracted parameter → security rule (with RFC/NIST reference) → risk and impact → fix*. The overall verdict is phrased as Risk → Evidence → Impact → Recommendation. Deterministic rules and templates, no language model. |
| Fix | **What-if simulator** | Change any setting; the unchanged rule engine re-scores the capture. Each change is attributed on its own, uncapped, and "if removed", so the analyst sees what actually moves the posture. Golden-policy compliance and the configuration fingerprint update too. |
| Verify | **What-if simulator → Verify** | The proposed configuration is rendered by the twin with the same traffic and measured by the full pipeline. On the weak IKEv1/3DES/MD5 sample: modelled 39.5 → 96.5, measured 39.5 → 95.0. |

Also:

- **Attack surface map:** gateways → IKE SA → Child SA tunnels → traffic classes, with each finding pinned to the layer it concerns.
- **Metadata leakage:** confidentiality and metadata privacy scored separately over 10 exposure dimensions, with plain statements such as "an observer cannot read tunnel 0x35…, but can infer that it resembles VoIP (97%)".
- **Configuration fingerprint and drift:** a hash of the identified configuration (e.g. `A1A4-7D9D-C9E5`); two captures of the same gateways are compared component by component, and each change is judged strengthened, weakened or visibility-only by NIST SP 800-57 strength.
- **Golden policy:** the administrator's required configuration (editable, shown as YAML); every capture is checked, and anything the capture cannot show is *unknown*, never a pass.
- **Novelty:** unregistered or rare parameters are flagged, and a k-nearest-neighbour detector marks traffic windows unlike anything in the training data.

## Investigation workspace

Fleet-wide tools that work across every stored capture:

| Tool | How to use it |
|---|---|
| **Command palette** | `Ctrl K` (or `/`) anywhere. Fuzzy search over pages, captures, findings, gateways and fingerprints; `>` for actions (analyse a sample, run the benchmark, open pre-built queries), `#` for findings, `@` for objects. Recent commands come first. |
| **Object explorer** | Every capture as a row you can filter with facets or a query: `dh:2 dh:5 pfs:off risk:high score<70 -src:lab finding:KE-001 traffic:voip`. Same field = OR, different fields = AND, `-` negates. Facet counts update as you filter, columns sort, queries can be saved as views and exported to CSV. |
| **Link graph** | Captures, gateways, configuration fingerprints, findings, traffic classes and configuration values as one force-directed graph. Wheel to zoom, drag to pan, drag a node to pin it, click to inspect, isolate a neighbourhood (1 or 2 hops). It lists recurring findings, shared configurations and gateways whose configuration drifted. |
| **Triage inbox** | Every finding occurrence with a persisted status (new, investigating, risk accepted, resolved, false positive), analyst notes and history. `j`/`k` to move, `i` `a` `r` `f` `n` to set status, `x` to select, bulk actions, and the evidence chain beside each finding. |
| **Investigation timeline** | Per capture (Protocol identification → Timeline): IKE messages, each tunnel's lifetime with the application in every window, rekeys and replay anomalies on one axis. Brush the overview or use the wheel to zoom, drag to pan, and select an event to jump to it. |

Keyboard: `g` then a letter jumps to a page (`g i` inbox, `g e` explorer, `g g` graph, `g s` security…), `Ctrl B`
collapses the navigation, `?` lists every shortcut.

These five tools are covered by a browser test that drives them the way an analyst would: 35 checks, including
typing in the palette, clicking facets, CSV download, node selection, zoom, keyboard triage with persistence
across reload, and brushing the timeline.

## What it does (mapped to the problem statement)

| PS item | SecurIQ |
|---|---|
| **a. Testbed generation** | `backend/testbed`: a configuration matrix (IKEv1 Main/Aggressive, IKEv2 · 9 IKE suites · 11 ESP suites incl. AES-128/256, GCM, CBC+HMAC, 3DES, ChaCha20, NULL · DH groups 2–31 · PFS on/off · tunnel/transport · IPv4/IPv6 · NAT-T · PSK/RSA/ECDSA/EAP · 7 traffic types · replay anomalies) rendered as PCAPs with ground truth. `backend/testbed/strongswan` runs the same matrix on real strongSwan gateways in Docker. |
| **b. Traffic capture** | PCAP/PCAPNG upload (Ethernet, VLAN, Linux SLL/SLL2, raw IP, loopback; IPv6 extension headers; snaplen-truncated frames), **real-time streaming analysis** of live interfaces (tcpdump/dumpcap/Scapy) or paced replays, and tcpdump capture inside the strongSwan lab. |
| **c. AI protocol identification** | Every property is an evidence record: *observed* from cleartext IKE, *inferred* from side channels with a confidence, or *not observable*. It covers ESP/AH, IKE version and exchange, tunnel/transport, IKE SA and **ESP** encryption and integrity, DH group, authentication method, PFS, lifetimes, replay behaviour, NAT-T, implementation, and the **traffic type inside ESP** (impairment-robust ensemble, 7 classes, calibrated, HMM-smoothed). |
| **d. Security assessment** | 8 categories (crypto strength, key exchange, forward secrecy, auth & integrity, SA lifetime, replay, configuration compliance, metadata exposure), coverage-weighted with critical caps; compliance against RFC 8247/8221/9395, NIST SP 800-77r1 and CNSA 1.0; NIST SP 800-57 weakest-link strength. |
| **e. Outputs** | Security score, risk score, 5×5 threat matrix with ATT&CK references, AI confidence score, executive and technical reports (printable HTML → PDF, plus JSON export), interactive dashboard. |

### How ESP properties are inferred without keys

In IKEv2 the Child SA (ESP) proposal, the mode and any PFS key exchange travel inside
**encrypted** messages. SecurIQ infers them from sizes and says so:

- **Cipher and ICV:** an ESP payload is `IV ‖ padded ciphertext ‖ ICV`. CBC ciphers make every
  length share one residue mod 16 (AES) or mod 8 (3DES), and that residue gives the ICV length.
  AEAD suites are only 4-byte aligned.
- **Tunnel vs transport:** the smallest recurring packet bounds the inner packet. Under 40 B cannot
  hold a tunnelled TCP segment. A TCP ACK clock whose packets exceed a transport-mode ACK carries
  inner IP headers. Otherwise the capture cannot decide, and SecurIQ reports *not observable*.
- **PFS:** the size of encrypted `CREATE_CHILD_SA` (IKEv2) or Quick Mode (IKEv1) messages against
  the size expected without a Key Exchange payload for the negotiated DH group.
- **Authentication (IKEv2):** `CERTREQ` presence, `IKE_AUTH` size and the number of round trips
  (EAP needs three or more).
- **ESP-NULL:** structurally valid inner IP/UDP headers whose length fields match the packet.

## Results

### Protocol identification — 30 **unseen** configuration-matrix captures per condition

| Field | Accuracy (decided) | Coverage |
|---|---|---|
| IKE version, exchange mode, IKE encryption, DH group, NAT-T, IP version, protocol, authentication | 100% | 100% |
| ESP cipher family / ICV length | 100% | 97–100% |
| Perfect Forward Secrecy (captures containing a rekey) | 100% | 100% |
| Tunnel / transport mode | 100% | 53–60% (abstains when the capture cannot decide) |

### Traffic inside ESP — robustness to real network conditions

Captures from a lab link are unrealistically clean, so the classifier is also measured under
**network impairments** (`backend/testbed/impairments.py`): jitter, packet loss with TCP
retransmissions, and other small flows multiplexed into the same SA.

| Classifier (same held-out flows) | Clean | Moderate impairment | Heavy impairment |
|---|---|---|---|
| Previous: RandomForest trained on clean flows | 98.7% | 77.1% | 64.9% |
| **Now: ExtraTrees + gradient-boosting ensemble, impairment-augmented, noise-robust features** | 97.5% | **95.7%** | **90.1%** |

End-to-end on unseen captures (parse → windows → classifier → HMM smoothing):

| Condition | Single-application windows | All windows (incl. application switches) | Gain from smoothing |
|---|---|---|---|
| No impairment | 98.5% | 92.6% | ±0 |
| Moderate | 96.0% | 92.3% | +1.9 pts |
| Heavy | 90.8% | 88.7% | +4.7 pts |

Confidence is calibrated on held-out flows: expected calibration error fell from 4.5% to 2.1% on the
unseen heavy-impairment set, so the AI confidence score means what it says. Macro one-vs-rest ROC-AUC on
held-out flows is 0.996.

**Novel traffic.** Left out of training one application at a time, the k-NN novelty detector flags 53% of
that unseen application's windows (ICMP 100%, VoIP 98%, e-mail 62%, chat 62%, video 36%, file transfer 7%,
web 4%) while flagging 2.2% of normal held-out windows. In a side-by-side experiment on the same data the
k-NN detector flagged 49% of unseen-application windows against 25% for an IsolationForest, both under 1%
false alarms. Web browsing and bulk transfers overlap other classes too much to look novel, so treat this as a
warning signal, not a detector of every new application.

### Misconfiguration benchmark (`python -m backend.ml.benchmark`)

Random configurations with 0–3 injected weaknesses: weak DH, 3DES, ESP-NULL, MD5, PFS off, IKE lifetime
over 24 h, Aggressive-mode PSK, IKEv1, replayed packets, counter reset, weak fallback proposals, Vendor ID.
Ground truth is the configuration; detection is what the pipeline finds in the rendered PCAP.

| Run | Injected weaknesses | Detected (recall) | False detections | False alarms on clean captures |
|---|---|---|---|---|
| 40 captures, seed 99 | 69 | 69 (100%) | 0 | 0 of 9 |
| 60 captures, seed 7 | 107 | 107 (100%) | 1 (3DES reported on an AEAD tunnel) | 0 of 13 |

Building the benchmark exposed one real bug, now fixed: a counter reset in a short-lived SA (restart before
256 packets) was reported as replayed packets. A reset re-uses a consecutive run of old numbers; a replay
injects isolated ones, and the analyzer now tells them apart.

### Real-time

| Metric | Value |
|---|---|
| Live vs batch agreement | identical windows, classes and security score on every tested capture |
| Ingest rate (decode + state, one core) | 35,000–53,000 packets/s |
| Full security re-assessment | 20–300 ms (every 3 s while streaming) |
| Traffic verdict after a window closes | ≤ 2 s (1 s grace for late packets + 1 s tick) |
| Alert latency | first re-assessment after the evidence appears (≤ 3 s) |

**Read these numbers with their caveats.** Training and evaluation captures come from the same
synthetic generator (different seeds), so they are optimistic even with impairments. Validate on
strongSwan captures from `backend/testbed/strongswan` (written, not yet executed; see its README)
before quoting real-world accuracy. Mode coverage is limited by physics: with AES-CBC padding a
transport ACK with TCP timestamps and a tunnelled ACK encrypt to the same length, and
constant-size traffic (VoIP, ping) has no ACK clock to measure.

## Real-time monitoring

**Live monitor** in the dashboard (or `POST /api/live/start`) analyses traffic as it arrives:

- **Sources:** replay of any stored capture at 1–200× (or unthrottled, for benchmarking); a live
  interface through `tcpdump` / `dumpcap` writing pcap to a pipe (no shell, validated arguments);
  or Scapy as a fallback.
- **Streaming events** over Server-Sent Events (`GET /api/live/{id}/events`, resumable with
  `Last-Event-ID`): IKE exchanges, new SAs, per-window traffic class with causal HMM smoothing,
  throughput every second, evidence profile and security score every 3 s, and an alert the
  moment a new Critical/High/Medium finding appears.
- **Same code as the batch analysis:** windows sit on an absolute 10-second grid and tunnel IDs
  are canonical, so a live session and the later full report agree exactly. When a stream ends
  (or is stopped) the capture is analysed by the full pipeline and saved as a normal report.

## Architecture

```
frontend/ (React + TypeScript, Vite)
  pages/        Operations · Triage inbox · Object explorer · Link graph · Captures & samples · Live monitor · VPN lab · Protocol identification · Traffic & metadata
                Security assessment · Attack surface · What-if simulator · Golden policy · Drift detection · Reports · Testbed & model
  components/   ipsec.tsx: evidence chain, posture, IKE ladder, ESP anatomy, replay chart, encapsulation hero, fingerprint
  components/   evidence badges, meters, bar/part-to-whole charts, per-tunnel timeline, threat matrix, heatmap
backend/ (FastAPI)
  analyzers/    pcap_parser (struct reader) · ike_parser (IKEv1/IKEv2) · ike_constants (IANA registries)
                esp_fingerprint · ipsec_analyzer (evidence profile) · flow_extractor (SA pairing, windows)
  ml/           dataset (train/infer parity, impairment augmentation) · model (ensemble, calibration, HMM smoothing,
                k-NN novelty, per-window reasoning) · evaluation (end-to-end vs ground truth) · benchmark (misconfigurations)
  realtime/     sources (replay / tcpdump|dumpcap pipe / Scapy) · engine (live session) · manager
  intel/        chains · rules · checks · metadata · fingerprint (+ drift) · policy · simulator · surface · lab · fleet
  security/     scoring_engine · compliance · strength · threat_matrix · confidence
  reports/      generator (JSON) · html + templates (printable)
  testbed/      esp_model · traffic_models · impairments · ike_builder · pcap_writer · scenarios · build_dataset · strongswan/
  pipeline.py   parse → analyse → classify → assess → threats → confidence → reports
  storage.py    on-disk persistence (backend/data, git-ignored)
```

## API (selection)

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/upload` | Upload a pcap/pcapng (extension + magic-number checked, streamed 100 MB limit) |
| GET | `/api/upload/list` | Uploads and testbed samples |
| POST | `/api/analyze/{file_id}` | Run the full pipeline |
| GET | `/api/analysis/{id}` · `/packets` | Evidence profile, classification, security, threats, confidence, ground truth |
| GET | `/api/security/{id}` · `/findings` · `/compliance` · `/threat-matrix` | Assessment parts |
| GET | `/api/reports/{id}/executive.html` · `/technical.html` · `/export.json` | Reports |
| GET/POST | `/api/ml/model-info` · `/api/ml/train` | Classifier |
| GET/POST | `/api/testbed/scenarios` · `/api/testbed/matrix` · `/api/dataset/generate` · `/api/dataset/download/{name}` | Testbed and dataset |
| GET/POST | `/api/evaluation/latest` · `/api/evaluation/run` | End-to-end evaluation |
| GET/POST | `/api/live/capabilities` · `/api/live/start` · `/api/live/{id}` · `/api/live/{id}/stop` | Real-time sessions |
| GET | `/api/live/{id}/events` | Server-Sent Events stream |
| GET/POST | `/api/capture/interfaces` · `/api/capture/start` | Bounded one-shot capture |
| GET | `/api/intel/{id}` | Evidence chains, posture, checklists, novelty, metadata leakage, fingerprint, attack surface, policy |
| GET/POST | `/api/simulator/{id}/baseline` · `/api/simulator/{id}` · `/api/simulator/{id}/verify` | What-if simulation and measured verification |
| GET/POST | `/api/policy` · `/api/policy/reset` · `/api/policy/evaluate/{id}` · `/api/policy/fleet` | Golden policy |
| GET | `/api/fingerprints` · `/api/drift/{id}?baseline=` | Fingerprints and drift |
| GET/POST | `/api/lab/build` · `/api/lab/builds` | Digital-twin lab builds (with strongSwan profile) |
| GET/POST | `/api/benchmark/latest` · `/api/benchmark/run` | Misconfiguration benchmark |
| GET | `/api/fleet/objects` · `/api/fleet/graph` | Explorer rows and link graph across all captures |
| GET/POST | `/api/triage` | Triage inbox: list, and set status or notes for finding occurrences |

Interactive docs: http://localhost:8000/docs

## Dataset

- `backend/data/datasets/training_windows.csv`: the classifier's training windows (32 features + label).
- `python -m backend.testbed.build_dataset --count 50` (or **Testbed & model → Dataset**) writes
  labelled PCAPs, `manifest.jsonl` (ground truth) and `windows.csv` (features extracted *from the PCAPs*).

## Tests

```bash
cd backend && ./venv/Scripts/python -m pytest -q     # 135 tests, about 2–4 min
```

They cover IKE parsing (RFC notify codes, IKEv1 attributes, malformed input), capture formats,
ESP fingerprinting and mode inference, per-scenario ground truth, train/inference feature parity,
scoring and compliance, the real-time engine (live ≡ batch, SSE stream, source validation), the API
(including upload hardening and path traversal), and the decision-support layer: evidence chains, simulator
reproduction and verification, policy, fingerprint stability and drift direction, lab builds, replay evidence.

## Limitations

- AES key length on ESP is not observable; it is reported as such, never assumed as the weakest link.
- Several applications multiplexed in one SA are classified by the dominant pattern per 10 s window.
- The size heuristics (PFS, authentication) assume standard IKE implementations; they carry
  moderate confidence and should be validated on the strongSwan captures.
- Live interface capture requires tcpdump/dumpcap (or Npcap for Scapy) and capture privileges; on the
  build machine none was installed, so only replay sessions and the error paths were exercised.
