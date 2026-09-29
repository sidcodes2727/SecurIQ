# SecurIQ — Project Overview and Feature List

AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
Smart India Hackathon 2026 · Problem Statement 26160 · NTRO

---

## 1. What the project is

SecurIQ looks at a **capture of network traffic** from an IPsec VPN and, **without any keys**, tells an analyst:

1. **What the VPN is:** protocols, IKE version and exchange type, tunnel or transport mode, encryption and integrity algorithms, key-exchange group, authentication method, forward secrecy, lifetimes, replay behaviour, NAT traversal, the VPN product, and the kind of traffic inside the tunnel (web, video, VoIP, file transfer, e-mail, chat, ping).
2. **How sure it is** about each claim. Every property is marked *observed* (read from cleartext), *inferred* (deduced from sizes and timing, with a confidence) or *not observable* (the capture cannot show it). The tool abstains rather than guesses.
3. **How secure the deployment is:** a security score, a risk level, findings with evidence chains, compliance against standards, and a threat matrix.
4. **What to do about it:** a what-if simulator that re-scores the capture under a proposed configuration, and a digital twin that renders the proposed configuration as a new capture and measures it for real.

It also includes the lab that generates labelled captures used to train and evaluate the AI.

It is delivered three ways, all using the same analysis engine:

| Interface | How to use it |
|---|---|
| **Terminal package** | The `securiq` command (about 25 sub-commands) and a full-screen operations console (`securiq` with no arguments) |
| **Web application** | React front end (16 pages) with a FastAPI backend |
| **REST API** | About 45 endpoints under `/api` (used by the web app; scriptable) |

---

## 2. Problem-statement mapping (PS 26160)

| Requirement | Where it is delivered |
|---|---|
| **a. Testbed generation** | `backend/testbed`: a configuration matrix rendered as PCAPs with ground truth, plus strongSwan/Docker lab scripts |
| **b. Traffic capture** | PCAP/PCAPNG upload, bounded live capture (Scapy), real-time streaming analysis of interfaces or paced replays |
| **c. AI protocol identification** | Evidence-based identification of every property, plus an ML traffic classifier for the traffic inside ESP |
| **d. Security assessment** | 8 scored categories, standards compliance, weakest-link strength, threat matrix |
| **e. Outputs** | Security score, risk score, 5×5 threat matrix, AI confidence score, executive and technical reports (HTML/PDF/JSON), interactive dashboard |

---

## 3. Core ideas

- **Passive and keyless.** Only packet headers, sizes, timing and cleartext IKE messages are used. Nothing is decrypted.
- **Evidence, not assertion.** Each identified property is an evidence record: value, source (observed / inferred / not observable), confidence, evidence sentence and method.
- **Deterministic explanations.** Findings, verdicts and recommendations come from rules and templates. No language model is used, so the same capture always gives the same explanation.
- **Weakest-link scoring.** A single critical or high finding caps the overall score (critical caps at 40, high at 70), and categories that the capture cannot show lower the coverage figure rather than being assumed good.
- **Attack → observe → explain → fix → verify.** One loop from a lab build, through analysis and explanation, to a simulated fix and a measured re-test.

---

## 4. Feature list

### 4.1 Capture input
- PCAP and PCAPNG files (Ethernet, VLAN, Linux SLL/SLL2, raw IP, loopback), IPv4 and IPv6 including extension headers, snaplen-truncated frames.
- Upload validation: extension allow-list, magic-number check, streamed size limit (100 MB by default, configurable), server-generated file names.
- Bounded live capture with Scapy and a BPF filter.
- Real-time streaming from `tcpdump`, `dumpcap` or Scapy, or a paced replay of any stored capture (1 to 200 times speed, or unthrottled).
- A curated set of ten testbed samples, each with ground truth.

### 4.2 Protocol identification
- **IKE parsing:** IKEv1 (Main and Aggressive Mode, Quick Mode) and IKEv2; proposals, transforms, key-exchange groups, notifications, vendor IDs, identities, certificate requests, signature hash algorithms, cookie challenge.
- **Identified properties (19):** IPsec protocol, IKE version, exchange mode, tunnel/transport mode, IKE encryption, IKE integrity, IKE PRF, key exchange (DH group), ESP encryption, ESP integrity, authentication method, PFS, IKE and Child SA lifetimes, replay behaviour, NAT traversal, IP version, implementation (from vendor IDs), traffic types.
- **ESP inference without keys:** cipher family, block size, IV and ICV length from ciphertext length residues; tunnel vs transport from the smallest recurring packet and ACK clocking; PFS from the size of encrypted rekey messages; authentication class from CERTREQ, `IKE_AUTH` size and round trips; ESP-NULL from structurally valid inner headers.
- **Downgrade surface:** weak proposals offered but not chosen.
- **Evidence checklist per property:** supporting observations, contradicting ones and limits.
- **Replay analysis:** duplicates, counter resets, reordering, near-exhaustion, with sequence traces.
- **Ground-truth comparison** on testbed captures: field-by-field correct / wrong / abstained.

### 4.3 Traffic classification (inside ESP)
- Seven classes: web, video, VoIP, file transfer, e-mail, chat, ICMP.
- Ensemble of ExtraTrees and HistGradientBoosting, trained on impairment-augmented flows, 38 noise-robust features.
- 10-second windows on an absolute grid, calibrated probabilities, causal HMM smoothing, an uncertain flag below 50% confidence.
- Per-window explanation: which features drove the label, class medians, supporting evidence and caveats.
- k-NN novelty detector for traffic unlike anything in training.
- Model card: per-class precision/recall, calibration error, stress accuracy, feature importance, novelty performance.

### 4.4 Security assessment
- **8 weighted categories:** cryptographic strength, key exchange, forward secrecy, authentication and integrity, SA lifetime, replay protection, configuration compliance, metadata exposure.
- **Finding catalogue** with IDs (for example KE-001, CRYPTO-003, AUTH-004, PFS-001, CFG-001, META-003), severity, description, evidence, recommendation and evidence source.
- **Compliance frameworks:** IETF (RFC 8247, 8221, 9395), NIST SP 800-77r1, CNSA 1.0. Each check is pass, warn, fail or unknown.
- **Effective strength:** NIST SP 800-57 weakest-link security bits across cipher, key exchange and PRF.
- **Threat matrix:** 5×5 likelihood by impact, with ATT&CK references and the findings that drive each threat.
- **AI confidence score:** identification, classification and assessment coverage combined, with the formula shown.

### 4.5 Explanation and decision support
- **Evidence chains:** packet frames → extracted parameter → rule (with RFC/NIST reference) → risk and impact → fix.
- **Posture statement:** Risk → Evidence → Impact → Recommendation.
- **What-if simulator:** 14 settings; per-change attribution (alone, uncapped, if removed); resolved and introduced findings; policy and fingerprint effect; recommended minimal change set.
- **Verify in digital twin:** the proposed configuration is rendered with the same traffic and measured by the full pipeline (on the weak sample: modelled 39.5 to 96.5, measured 39.5 to 95.0).
- **Attack surface map:** gateways → IKE SA → Child SAs → traffic, with weaknesses pinned to layers.
- **Metadata leakage:** confidentiality and metadata privacy scored separately over ten exposure dimensions, with plain statements about what an observer can and cannot learn.
- **Configuration fingerprint:** a hash of the identified configuration, and **drift detection** between two captures of the same gateways (each change judged strengthened, weakened or visibility-only).
- **Golden policy:** an editable required configuration; every capture is checked and unknown is never counted as a pass.
- **Novelty flags** for unregistered or rare parameters.

### 4.6 Fleet investigation
- **Operations dashboard:** counts, score distribution, risk posture, recurring findings, configuration distributions.
- **Object explorer:** filter every capture with a query language (`dh:2 pfs:off risk:high score<70 -src:testbed finding:KE-001 traffic:voip`), facets with live counts, CSV export.
- **Link graph:** captures, gateways, fingerprints, findings, traffic classes and configuration values as a graph with recurring-finding, shared-configuration and drifted-gateway insights.
- **Triage inbox:** per-finding status (new, investigating, accepted, resolved, false positive), analyst notes and history, bulk actions.
- **Investigation timeline:** IKE messages, tunnel lifetimes, applications per window, rekeys and replay anomalies on one axis.
- **Command palette** with fuzzy search over pages, captures, findings, gateways and fingerprints.

### 4.7 Lab, testbed and evaluation
- **Configuration matrix:** IKEv1 Main and Aggressive, IKEv2; 9 IKE suites and 11 ESP suites (AES-128/256, GCM, CBC+HMAC, 3DES, ChaCha20, NULL); DH groups 2 to 31; PFS on/off; tunnel/transport; IPv4/IPv6; NAT-T; PSK, RSA, ECDSA and EAP authentication; seven traffic types; replay anomalies.
- **Network impairments:** jitter, packet loss with retransmissions, multiplexed background flows.
- **Digital twin (VPN lab):** choose a configuration and traffic, generate the negotiation and encrypted traffic, analyse the result, and emit a matching strongSwan profile for the Docker lab.
- **Dataset generation:** labelled PCAPs with a ground-truth manifest and window CSVs.
- **End-to-end evaluation** on unseen scenarios (every field, abstentions counted separately).
- **Misconfiguration benchmark:** known weaknesses injected, then measured for detection.
- **Retraining** of the classifier from freshly generated flows.

### 4.8 Real-time monitoring
- Live sessions grow the profile, score, category scores, traffic mix, threats and alerts as packets arrive; alerts fire when a new critical, high or medium finding appears.
- Streaming over Server-Sent Events (resumable), up to three concurrent sessions.
- Uses the same code and grid as the batch analysis, so a live session agrees with the later full report. When the stream ends, the full pipeline runs and the analysis is stored.

### 4.9 Reports and export
- Executive report (bottom line, what the VPN is, do-this-first list, top threats) and technical report (statistics, remediation plan, methodology, protocol details, findings, compliance).
- Printable HTML (save as PDF from a browser), JSON export, CSV export of the fleet table.

---

## 5. The terminal package

Installed with `pip install .` (or `pip install -e .` for development). The command is `securiq`.

### 5.1 Commands
| Group | Commands |
|---|---|
| Setup | `init`, `doctor` |
| Analyse | `analyze`, `show`, `explain`, `packets`, `analyses`, `captures` |
| Fleet | `dashboard`, `fleet`, `graph`, `triage`, `fingerprints` |
| Decide | `whatif` (`--set`, `--recommended`, `--verify`, `--options`), `policy` (`show`, `set`, `reset`, `check`), `drift` |
| Build | `lab` (`options`, `build`, `list`) |
| Live | `live` (`replay`, `capture`, `interfaces`), `capture` |
| Research | `testbed` (`matrix`, `samples`, `regen`, `dataset`, `evaluate`, `benchmark`, `model`, `train`) |
| Output | `report`, `export` |

Captures can be referred to as a file path, a sample name, a lab build id, an upload id, or (for stored analyses) `latest`, `@N`, an id or a file-name fragment. Errors are one readable line with exit code 1, never a traceback. Output is plain text when piped.

### 5.2 Full-screen console
A Gotham/Blueprint-style dark interface with nine views: Operations (with animated tunnel topology and a scrolling finding ticker), Object explorer, Link graph, Triage inbox, Analysis workspace (14 tabs), Live ops, Digital twin, Testbed and model, and Policy and compliance. It also has a boot sequence, a command palette (`Ctrl+P`), and a keyboard help screen (`?`).

Full guide: [TERMINAL.md](TERMINAL.md).

---

## 6. The web application

React 19, TypeScript and Vite. Sixteen pages behind a left rail:

| Section | Pages |
|---|---|
| Overview | Operations |
| Investigate | Triage inbox, Object explorer, Link graph |
| Capture | Captures and samples, Live monitor, VPN lab |
| Analyse | Protocol identification, Traffic and metadata, Security assessment, Attack surface |
| Decide | What-if simulator, Golden policy, Drift detection |
| Output | Reports |
| Research | Testbed and model |

Keyboard shortcuts: `Ctrl+K` command palette, `g` then a letter to jump to a page, `?` for help, `Ctrl+B` to collapse the rail.

---

## 7. REST API (FastAPI)

| Area | Endpoints |
|---|---|
| Health | `GET /api/health` |
| Upload | `POST /api/upload`, `GET /api/upload/list` |
| Analysis | `POST /api/analyze/{id}`, `GET /api/analysis/{id}`, `/packets`, `GET /api/analyses` |
| Security | `GET /api/security/{id}` (`/findings`, `/threat-matrix`, `/compliance`) |
| ML | `GET /api/ml/classify/{id}`, `GET /api/ml/model-info`, `POST /api/ml/train` |
| Reports | `GET /api/reports/{id}/executive` and `/technical` (JSON and HTML), `/export.json` |
| Explanations | `GET /api/intel/{id}` |
| Simulator | `GET /api/simulator/options`, `/{id}/baseline`, `POST /api/simulator/{id}`, `/{id}/verify` |
| Policy | `GET/POST /api/policy`, `POST /api/policy/reset`, `GET /api/policy/evaluate/{id}`, `/fleet` |
| Fingerprints | `GET /api/fingerprints`, `GET /api/drift/{id}` |
| Lab | `POST /api/lab/build`, `GET /api/lab/builds` |
| Fleet | `GET /api/fleet/objects`, `/graph`, `GET/POST /api/triage` |
| Live | `GET /api/live/capabilities`, `POST /api/live/start`, `GET /api/live/sessions`, `/{id}`, `POST /{id}/stop`, `GET /{id}/events` (SSE) |
| Capture | `GET /api/capture/interfaces`, `POST /api/capture/start` |
| Testbed | `GET /api/testbed/scenarios`, `/matrix`, `POST /api/samples/generate`, `/api/dataset/generate`, `POST /api/evaluation/run`, `POST /api/benchmark/run` |

---

## 8. Architecture

```
                 ┌──────────────────────────────────────────────┐
  React web app ─┤ FastAPI routes  (backend/routes)             │
                 └──────────────────────┬───────────────────────┘
                                        │
  securiq CLI ─┐                        ▼
  securiq TUI ─┴─►  securiq/core.py ──► backend engine
                                        │
        pcap_parser → ike_parser → ipsec_analyzer → flow_extractor
              → ML classifier → security scoring → threat matrix
              → AI confidence → intel (chains, simulator, policy,
                fingerprint, fleet) → reports
```

### Repository layout
```
securiq/            terminal package: cli.py, core.py, render.py, render_fleet.py, viz.py, theme.py, tui/
backend/
  analyzers/        pcap and IKE parsing, ESP fingerprinting, flow features
  security/         scoring engine, compliance, strength, confidence, threat matrix
  intel/            evidence chains, simulator, policy, fingerprint and drift, fleet, lab, surface, metadata
  ml/               traffic classifier, dataset, evaluation, benchmark
  realtime/         streaming engine, sources, session manager
  testbed/          scenario generator, IKE builder, ESP model, impairments, strongSwan lab
  reports/          report generator and HTML templates
  routes/           FastAPI routers
  seed/             pre-built model and small samples for hosts with an ephemeral disk
  tests/            automated tests
frontend/           React web application
docs/               MVP_PLAN.md, TERMINAL.md, this file
pyproject.toml      package definition (command: securiq)
render.yaml         Render deployment blueprint (API, free plan)
```

---

## 9. Technology

| Layer | Technology |
|---|---|
| Language | Python 3.9 to 3.13 (deployed on 3.12) |
| Analysis | Built-in struct-based PCAP reader, NumPy, SciPy, scikit-learn, joblib, Scapy (live capture only) |
| Terminal | Click, Rich, Textual |
| API | FastAPI, Uvicorn, Pydantic |
| Web | React 19, TypeScript, React Router, Vite |
| Reports | Jinja2 templates |
| Lab | Docker and strongSwan scripts (written, not yet executed against real gateways) |

---

## 10. Quality and measured results

The project measures itself. Figures below come from its own evaluation and benchmark on **synthetic testbed data**, generated with different seeds from the training data.

| Measure | Result |
|---|---|
| Protocol identification on 30 unseen captures | 100% accuracy on decided fields (IKE version, mode, encryption, DH group, NAT-T, IP version, authentication, ESP family, PFS); tunnel/transport abstains on 40 to 47% because captures cannot decide |
| Traffic classifier (held out) | About 94% accuracy, macro F1 about 94%, ROC-AUC 0.996 |
| Under heavy network impairment | About 87 to 90% accuracy |
| Calibration | Expected calibration error 4.5% reduced to 2.1% |
| Misconfiguration benchmark | 100% recall on injected weaknesses (69 of 69, then 107 of 107), 0 to 1 false detections |
| Real-time | 35,000 to 53,000 packets per second ingest, full re-assessment in 20 to 300 ms, live and batch results identical |
| Automated tests | About 165 tests: parser, analyzer, inference, security, ML, API, real-time, intel, terminal, seeding |

---

## 11. Deployment

| Piece | Where | Notes |
|---|---|---|
| API | Render (free plan) using `render.yaml` | 512 MB RAM, data in `/tmp` (resets on restart), uses the seeded model and six small samples, one worker |
| Web front end | Vercel (Hobby), root directory `frontend` | `VITE_API_BASE` must point at the API, `SECURIQ_CORS_ORIGINS` on the API must list the front-end address |
| Package | `pip install .` from the repository | Not published to PyPI. The wheel currently installs a generic top-level `backend` package, which should be renamed before a public release. |

Environment variables: `SECURIQ_DATA_DIR`, `SECURIQ_SEED_DIR`, `SECURIQ_MAX_UPLOAD_MB`, `SECURIQ_CORS_ORIGINS`, `VITE_API_BASE`.

---

## 12. Limitations

- **Synthetic data.** Training and evaluation captures come from the project's own generator, so accuracy figures are optimistic. Real-world accuracy should be measured on captures from real gateways (the strongSwan lab is written but has not been run).
- **Some properties cannot be seen.** Tunnel versus transport mode and PFS are sometimes impossible to determine from ciphertext lengths. The tool reports *not observable* in those cases.
- **Novelty detection is a warning signal**, not a detector of every unseen application (web and bulk transfer overlap other classes).
- **No authentication** on the API. Anyone who can reach a deployment can upload captures. Put it behind a login or keep it internal.
- **Hosted free tier:** the API sleeps after 15 minutes idle, data does not persist across restarts, uploads are limited to 15 MB, and live capture from a network interface is unavailable. Live replay works.
- **Live interface capture** needs Npcap, tcpdump or dumpcap and administrator rights, and has not been tested on a real interface in this environment.
- **Only IPsec** (IKEv1, IKEv2, ESP, AH) is analysed.

---

## 13. Quick start

```bash
pip install -e .          # from the repository root
securiq init              # generate samples and train the classifier (about 30 s, once)
securiq                   # open the console
securiq analyze weak_ikev1_main_3des_md5
securiq whatif latest --recommended --verify
```

Web application:
```bash
python -m uvicorn backend.main:app --port 8000
cd frontend && npm install && npm run dev      # http://localhost:5173
```

Tests:
```bash
cd backend && python -m pytest -q
```

More detail: [README.md](../README.md), [TERMINAL.md](TERMINAL.md), [MVP_PLAN.md](MVP_PLAN.md).
