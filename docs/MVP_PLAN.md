# SecurIQ — Refined MVP Plan

Problem statement: **SIH 26160 — AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework (NTRO)**

This document is the output of a structured brainstorm (the `@brainstorming` skill from
*antigravity-awesome-skills*: context review → understanding lock → non-functional requirements →
approaches → design → decision log), plus the `@api-security-best-practices` and
`@lint-and-validate` skills applied to the existing SecurIQ code.

---

## 1. Context review — what SecurIQ had before this MVP

A FastAPI + Scapy + scikit-learn backend with a React dashboard. It parsed PCAPs, pulled IKE
proposals out of `IKE_SA_INIT`, grouped ESP by SPI, classified flows with a RandomForest, scored
7 rule-based categories and produced JSON reports. The structure was sound; the problems were in
**protocol correctness** and **ML validity**, which a judge with IPsec experience would catch fast.

### Verified gaps (each reproduced against the code, not assumed)

| # | Gap | Evidence | Impact |
|---|-----|----------|--------|
| G1 | IKEv2 Notify codes were shifted (e.g. `NAT_DETECTION_SOURCE_IP` coded as 16394; RFC 7296 says 16388; `USE_TRANSPORT_MODE` 16397 vs 16391) | Cross-checked against Scapy's IKEv2 registry | NAT-T / mode detection wrong on any real capture; samples used the same wrong codes so tests passed |
| G2 | IKE SA algorithms reported as the tunnel's (ESP) algorithms | In IKEv2 the Child SA (ESP) proposal is inside the **encrypted** `IKE_AUTH` | Report claims certainty it does not have |
| G3 | Tunnel/Transport mode = "Tunnel unless USE_TRANSPORT_MODE seen" — but that notify is encrypted in real traffic | RFC 7296 §1.3.1 | Mode was effectively hard-coded |
| G4 | PFS detection looked for a cleartext KE payload in `CREATE_CHILD_SA` — that exchange is encrypted | RFC 7296 §1.3 | PFS never detected on real traffic |
| G5 | IKEv1 SA payload parsed with the IKEv2 transform layout | IKEv1 uses DOI/Situation + attribute-encoded transforms | IKEv1 algorithms, auth method (PSK!), lifetime all lost |
| G6 | ML trained on feature vectors *sampled from distributions*, never extracted from packets | `synthetic_data.py` vs `flow_extractor.py` | 99% "accuracy" does not transfer |
| G7 | Flows grouped by SPI — an ESP SA is **unidirectional** | Probe: every real SA has `fwd_ratio = 1.0`; training data had 0.1–0.6 | Direction features out-of-distribution at inference |
| G8 | AH parsed via `Raw`, but Scapy decodes AH itself → AH fields empty | `scapy.layers.ipsec.AH` | AH analysis silently broken |
| G9 | Upload path used the client filename directly | `UPLOAD_DIR / f"{id}_{file.filename}"` | Path traversal on Windows; no magic-byte check; whole file read before size check |
| G10 | Results in memory only; `/api/capture/start` documented but missing; dashboard "Total Findings" always 0 | routes / App.tsx | Demo fragility |
| G11 | Unknown values scored as 50/100 | `scoring_engine.py` | Score moves with missing data, not with evidence |

## 2. Understanding lock

**What we are building:** a passive analyzer that, given a capture of an IPsec VPN, tells an analyst
*what* the VPN is (protocols, IKE version, mode, algorithms, key exchange, SA behaviour, traffic
inside the tunnel), *how sure* it is about each claim, and *how secure* it is — with reports an
executive and an engineer can each act on. Plus the lab (testbed) that produces labelled captures
to train and evaluate the AI.

**Assumptions (marked, since no stakeholder was available to confirm):**

- A1. Analysis is **passive** — no keys, no decryption. Anything inside encrypted payloads is
  *inferred* from side channels (lengths, timing, message sizes) and labelled as such.
- A2. The demo must run fully offline on a laptop (Windows/Linux) in < 1 min from cold start.
- A3. Real strongSwan captures are the gold standard; synthetic captures are for coverage and
  labelled training data, and must go through the *same* parser and feature pipeline.
- A4. Reference standards: RFC 8221 (ESP algorithms), RFC 8247 (IKEv2 algorithms), RFC 9395
  (IKEv1 deprecation), NIST SP 800-77r1, NIST SP 800-57 (security strength), CNSA 1.0.
- A5. Single-user local tool. No auth or multi-tenancy in the MVP.

**Non-functional requirements (defaults chosen):**

| NFR | Target |
|-----|--------|
| Performance | 10 MB capture analysed in < 5 s; model trains in < 60 s at first start |
| Honesty | Every identified property carries `source ∈ {observed, inferred, not_observable}` + confidence + evidence |
| Security | Sanitised uploads, magic-byte validation, bounded sizes, no shell-outs with user input |
| Reliability | Results persist across restarts; malformed packets never crash analysis |
| Maintainability | Pure-function analyzers, unit tests per module, no new heavy dependencies |

## 3. Approaches considered

| | A. Polish | **B. Evidence-first inference engine (chosen)** | C. Full platform |
|---|---|---|---|
| Idea | Fix bugs + UI, keep logic | Re-centre the core on an evidence model; add side-channel inference, labelled testbed, retrained ML, compliance | B + live streaming, deep learning, DB, auth, orchestrated real testbed |
| Covers PS | Partially (G2–G7 stay) | All of (a)–(e) | All, plus extras |
| Risk | Low effort, low credibility | Medium, well-contained | High; unlikely to be solid by demo day |
| Why / why not | Judges with IPsec background spot G2–G4 | Honest, demonstrable, testable end-to-end | Scope > team capacity; DL needs real data we do not have yet |

## 4. Design (approach B)

### 4.1 Evidence model
Every property in the VPN profile is an **Evidence** record:

```json
{"value": "AES-CBC + HMAC-SHA1-96", "source": "inferred", "confidence": 0.94,
 "method": "ESP length fingerprint", "evidence": "412 pkts, 37 distinct lengths, all ≡ 12 (mod 16)"}
```

### 4.2 What is observed vs inferred

| Property (PS §c) | IKEv2 | IKEv1 | Method |
|---|---|---|---|
| IPsec protocol (ESP/AH) | observed | observed | IP proto 50/51, UDP-4500 encapsulation |
| IKE version / exchange | observed | observed | IKE header |
| IKE SA encryption/PRF/integrity | observed | observed | `IKE_SA_INIT` SA / Main-Mode SA attributes |
| Key exchange (DH group) | observed | observed | KE payload / Group attribute |
| ESP encryption & integrity | **inferred** | **inferred** | ESP length fingerprint: block size + ICV length from `len mod 16/8` |
| Tunnel vs Transport | **inferred** (observed for AH) | same | Smallest-inner-packet bound; AH Next Header is cleartext |
| Authentication method | **inferred** | observed | IKEv2: `CERTREQ` + `IKE_AUTH` size/round-trips; IKEv1: Auth attribute |
| PFS | **inferred** | **inferred** | Size of encrypted `CREATE_CHILD_SA` / Quick Mode vs expected KE payload size |
| Key lifetime | inferred (rekey interval) | observed | Life Duration attribute; SPI succession timing |
| Replay protection | inferred | inferred | Per-SA sequence analysis: duplicates, counter resets, reorder depth vs 64-window |
| Traffic type inside ESP | **inferred (ML)** | same | RandomForest over bidirectional, windowed size/timing features |
| Implementation | observed | observed | Vendor ID payloads |
| ESP-NULL | inferred | inferred | Byte-position constancy at payload start |

### 4.3 Components

```
backend/
  analyzers/ike_constants.py   IANA registries (IKEv1 + IKEv2), vendor IDs, KE sizes
  analyzers/ike_parser.py      IKEv1/IKEv2 payload chains (SA, KE, N, VID, ID, CERTREQ, SK/SKF)
  analyzers/pcap_parser.py     streaming parser; ESP/AH/IKE/NAT-T/keepalive
  analyzers/esp_fingerprint.py ESP cipher-family, ICV, mode, ESP-NULL inference
  analyzers/ipsec_analyzer.py  sessions, evidence profile, PFS/auth/lifetime/replay inference
  analyzers/flow_extractor.py  SA pairing → bidirectional tunnels → 10 s windows → 32 features
  testbed/esp_model.py         cipher-suite framing (IV / block / ICV) used by the generator
  testbed/traffic_models.py    packet-sequence generators: ICMP, Web, VoIP, Video, Email, Chat(WhatsApp-like), File
  testbed/scenarios.py         config matrix → realistic IKE + ESP captures + ground truth
  testbed/build_dataset.py     CLI: N labelled PCAPs + manifest + features.csv
  testbed/strongswan/          real docker testbed (swanctl profiles, capture + traffic scripts)
  ml/dataset.py                training windows via the *same* feature extractor (train/infer parity)
  ml/model.py                  RandomForest, group-aware split, uncertainty threshold
  ml/evaluation.py             end-to-end identification accuracy vs ground truth
  security/strength.py         NIST SP 800-57 bits of security, weakest link
  security/compliance.py       RFC 8221/8247/9395, NIST SP 800-77r1, CNSA 1.0 checks
  security/scoring_engine.py   8 categories, coverage-weighted, critical caps
  security/threat_matrix.py    5×5 likelihood × impact matrix, ATT&CK references
  security/confidence.py       composite AI confidence score
  reports/                     executive + technical (JSON + printable HTML)
  storage.py                   on-disk persistence of uploads and analyses
  routes/                      upload (hardened), analysis, capture (live), testbed/evaluation
```

### 4.4 Scoring
Eight categories (PS §d): cryptographic strength 20 %, key exchange 15 %, forward secrecy 10 %,
authentication & integrity 10 %, SA lifetime 10 %, replay protection 10 %, configuration
compliance 15 %, metadata exposure 10 %.

- Each category returns `score | None` and `confidence`. Overall = Σ wᵢ·cᵢ·sᵢ / Σ wᵢ·cᵢ over assessable
  categories; **coverage** = Σ wᵢ·cᵢ is reported next to the score.
- A Critical finding caps the score at 40; a High finding caps it at 70. One broken control sinks
  the posture, however good the others are.
- **Metadata exposure uses the AI's own result**: if the classifier identifies tunnel traffic with high
  confidence, the tunnel leaks traffic-type metadata, and that becomes a finding (TFC padding recommended).

### 4.5 AI confidence score
`0.4 × identification confidence + 0.4 × classification confidence + 0.2 × assessment coverage`,
each part shown separately in the reports.

## 5. MVP scope (MoSCoW)

**Must:** G1–G11 fixed · evidence model · ESP fingerprinting · IKEv1 attributes/aggressive-mode
identity exposure · PFS/auth/lifetime/replay inference · scenario-matrix testbed with ground truth ·
retrained ML with train/infer parity · compliance profiles · 5×5 threat matrix · AI confidence ·
HTML reports · persistence · hardened upload · dashboard updates · tests.

**Should:** strongSwan docker testbed · bounded live capture endpoint.

**Won't (this MVP):** decryption with keys, deep-learning classifier, streaming dashboard,
database, authentication, concurrent-flow demultiplexing inside one SA.

## 6. Demo storyline (≈ 6 min)

1. Dashboard → *Testbed*: generate the scenario matrix and show ground truth.
2. Analyse `weak_ikev1_aggressive_psk` → identity leaked in cleartext, 3DES/MD5/MODP-1024,
   PSK crackable offline → score capped, Critical threats on the 5×5 matrix.
3. Analyse `strong_ikev2_gcm_ecp384_pfs` → evidence badges: *observed* IKE suite,
   *inferred* ESP AEAD, *inferred* PFS, traffic mix timeline (web → video).
4. Analyse `transport_ipv6_voip` → transport mode inferred from ESP sizes, VoIP identified →
   metadata-exposure finding generated from the AI's own confidence.
5. Dataset & Model page → end-to-end identification accuracy on held-out captures.
6. Download the executive + technical HTML reports (print to PDF).

## 7. Risks

| Risk | Mitigation |
|------|------------|
| Side-channel heuristics calibrated on our own generator (circular) | Sizes derived from RFC payload layouts; validate on strongSwan captures (§ testbed) before claiming accuracy |
| Real tunnels multiplex many apps in one SA | Windowed classification + "uncertain" label; stated limitation |
| Live capture needs Npcap/root | Endpoint degrades with a clear error; PCAP upload is the primary path |

## 8. Decision log

| # | Decision | Alternatives | Rationale |
|---|----------|--------------|-----------|
| D1 | Approach B | A, C | Covers the whole PS, and every claim can be demonstrated and tested |
| D2 | Evidence records instead of plain strings | Plain strings + "Not Observable" | PS asks for AI confidence; honesty is the differentiator |
| D3 | ESP length fingerprinting for Child SA crypto | Report IKE SA suite as ESP suite | IKEv2 Child SA proposal is encrypted; the length maths is deterministic and explainable |
| D4 | Generate training data as packet sequences run through the real feature extractor | Keep distribution sampling | Removes train/inference skew (G6) |
| D5 | Pair SAs into bidirectional tunnels + 10 s windows | Per-SPI flows | ESP SAs are unidirectional (G7); windows give a traffic-mix timeline |
| D6 | Canonical direction = heavier-byte direction | Initiator direction | Initiator is not always observable; makes features direction-agnostic |
| D7 | RandomForest kept, scaler dropped, group-aware split | Deep learning | Explainable, fast, enough for tabular features; avoids window leakage between train/test |
| D8 | Coverage-weighted score + critical caps | Unknown = 50 | Score reflects evidence, and a single broken control dominates |
| D9 | HTML reports (print → PDF) via Jinja2 | WeasyPrint/ReportLab | Zero new dependencies, works offline on Windows |
| D10 | JSON-on-disk persistence | SQLite/Postgres | Enough for a single-user tool; trivially inspectable |
| D11 | strongSwan testbed shipped as docker profiles | Hand-built VMs | Reproducible; the matrix maps 1:1 onto swanctl proposals |

## 9. Status after implementation

| Item | Status |
|------|--------|
| G1–G11 | Fixed and covered by tests (109 passing) |
| Evidence model, ESP fingerprint, mode / PFS / auth / lifetime / replay inference | Done |
| Scenario-matrix testbed + labelled dataset CLI | Done |
| Classifier retrained with train/infer parity (feature diff 0.0 between generator records and parsed PCAP) | Done |
| Compliance, threat matrix, AI confidence, HTML reports, persistence, hardened upload | Done |
| Dashboard rebuilt (7 pages, evidence badges, charts validated for colour-vision deficiency) | Done |
| strongSwan docker testbed | Written, **not executed** (Docker engine unavailable on the build machine) |
| Live capture | Implemented; error path tested, success path untested (needs Npcap/root) |

**End-to-end evaluation (30 unseen matrix captures):** 100% of decided fields correct; traffic
windows 96.4%; tunnel/transport mode decided in 56.7% of captures.

**D12 (added during implementation):** tunnel/transport inference abstains when the capture
cannot decide, instead of defaulting to "Tunnel". The first run guessed and scored 76.7%; after
the change, decided accuracy is 100% at 56.7% coverage. The remaining abstentions are physical
limits (AES-CBC padding hides the 8-byte difference; constant-size traffic has no ACK clock).

**Next steps:** run `backend/testbed/strongswan/run_matrix.sh` on Linux or WSL2, analyse the
captures, and recalibrate the PFS/auth size baselines if real strongSwan messages differ.
Add those captures to the training data.

## 10. Iteration 2: accuracy under realistic conditions and real-time analysis

**Finding that triggered it.** A stress test showed that the first-iteration classifier (RandomForest
trained on clean synthetic flows) held 98.7% on clean traffic but fell to 77.1% under moderate
and 64.9% under heavy network impairment (jitter, loss with retransmissions, multiplexed
background flows). Good scores on the clean set had hidden this.

| # | Decision | Alternatives | Rationale / evidence |
|---|----------|--------------|----------------------|
| D13 | Impairment augmentation during training; an unseen *heavy* stress set as a separate metric | Clean-only training | Heavy-impairment accuracy 64.9% → 90.1% on the same held-out flows |
| D14 | Soft-voting ensemble: ExtraTrees 0.6 + HistGradientBoosting 0.4 | RF, ET or HGB alone | Best balance measured: 97.5 / 95.7 / 90.1% (clean / moderate / heavy) |
| D15 | 6 noise-robust features (modal-size share and cadence, large-packet byte share and IAT, mid-size share) | Keep 32 generic features | +1–3 pts under heavy impairment, where multiplexed flows distort quantile features |
| D16 | Power calibration of probabilities, fitted on held-out flows | Uncalibrated scores | ECE 4.5% → 2.1% on the unseen stress set; the AI confidence score is meaningful |
| D17 | Sticky-HMM smoothing across consecutive windows (forward-backward offline, forward-only live) | Independent windows | +1.9 / +4.7 pts end-to-end under moderate / heavy impairment; no change when clean |
| D18 | Report single-application windows separately from windows that straddle an application switch | One blended number | A window holding two applications has no single true label; blending hid a 98.5% vs 79% split |
| D19 | ESP cipher only named at ≥ 85% chance-corrected confidence | Name at any residue match | With 3 distinct lengths a matching residue happens by chance 25% of the time (one real miss) |
| D20 | Windows on an absolute 10 s grid; canonical tunnel IDs | Per-tunnel first-packet alignment | Lets the live engine, which holds only recent packets, cut exactly the batch windows |
| D21 | Streaming engine reuses the batch decoder, analyzer, scorer and classifier; SSE to the browser | Separate streaming logic; WebSocket | Live and batch give identical windows, classes and scores; SSE is one-way, auto-resumes, no library |
| D22 | Live sources: paced replay, tcpdump/dumpcap pipe, Scapy fallback | Scapy only | tcpdump/dumpcap need no Npcap-in-Python; replay makes real time demonstrable and testable anywhere |

**Measured (30 unseen captures per condition):** single-application windows 98.5% clean, 96.0%
moderate, 90.8% heavy; protocol fields 100% of decided. **Real time:** 35–53K packets/s ingest,
verdicts within 2 s of a window closing, live ≡ batch on every tested capture.

**Still open:** live interface capture untested on this machine (no capture backend installed);
all numbers are on the synthetic testbed until the strongSwan lab is run.

## 11. Iteration 3: decision support and the IPsec-themed UI

| # | Decision | Evidence |
|---|---|---|
| D23 | Every finding carries an evidence chain (frames → parameter → rule + reference → impact → fix), built by deterministic templates, not an LLM | Every statement traces to a packet field or statistic; chains exist for all findings (tests/test_intel.py) |
| D24 | What-if simulation re-scores the *same* analysis with chosen profile fields replaced | "Current" reproduces the stored score exactly; per-change attribution reported alone, uncapped and if-removed because the weakest-link cap hides single changes |
| D25 | Verify renders the proposal through the testbed twin and measures it with the full pipeline | Weak IKEv1/3DES/MD5 sample: modelled 96.5, measured 95.0, identification 100% on the new capture |
| D26 | Golden policy reports unobservable requirements as *unknown* | ESP key length and IKEv2 lifetimes are never visible; a pass there would be a false assurance |
| D27 | Configuration fingerprint = hash of identified configuration; drift direction judged by NIST SP 800-57 strength | Same capture twice → same fingerprint; strong → moderate sample → 8 components weakened |
| D28 | k-NN novelty detector (log-scaled features, 97.5th percentile) over IsolationForest | Leave-one-class-out: 49% vs 25% unseen-application windows flagged at < 1% false alarms (same data); production model 53% at 2.2% |
| D29 | Misconfiguration benchmark with ground truth from the configuration | 69/69 and 107/107 injected weaknesses detected, 1 false detection, 0 false alarms on 22 clean captures; exposed and fixed a short-SA counter-reset bug |
| D30 | Frame numbers are 1-based, matching Wireshark | Analysts can jump from an evidence chain straight to the frame in Wireshark |

## 12. Iteration 4: investigation workspace

| # | Decision | Evidence |
|---|---|---|
| D31 | Fleet views are built from memoised per-capture rows (records are immutable once saved) | 10 captures: rows, 78-node graph and 73-item inbox served in ~0.5 s cold |
| D32 | Explorer queries are text (`dh:2 pfs:off score<70`), facet clicks edit that text | One source of truth, shareable URLs, saved views, and the palette can deep-link a query |
| D33 | Link graph uses a small in-house force layout plus greedy screen-space label placement | No dependency; labels never overlap each other at any zoom |
| D34 | Triage state lives on the server, keyed by capture + finding, with history | Decisions survive reloads and are shared; keys are validated against path tricks |
| D35 | Features are verified by driving a real browser (Playwright + installed Chrome) | 35/35 interaction checks; found and fixed palette focus, ranking, timeline brush and inbox scroll bugs |
