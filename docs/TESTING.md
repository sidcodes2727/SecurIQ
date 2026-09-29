# SecurIQ — Testing Guide

How to test every feature, which capture file to use for each test, and what result to expect.
The expected values in this guide were measured by running the tool on these exact files; small differences
(for example a score that differs by a few tenths) usually mean the samples were regenerated.

Sections:
1. [Test files: what exists and where](#1-test-files)
2. [Terminal testing, step by step](#2-terminal-testing-step-by-step)
3. [Full-screen console testing](#3-full-screen-console-testing)
4. [Automated tests](#4-automated-tests)
5. [Web app testing](#5-web-app-testing)
6. [Negative and edge-case tests](#6-negative-and-edge-case-tests)
7. [Known issue found while writing this guide](#7-known-issue)
8. [Testing the live feature](#8-testing-the-live-feature)

All commands are for **Windows PowerShell 5.1** (no `&&`; run one command per line).

---

## 1. Test files

You do not need to download anything. SecurIQ generates its own captures. Three groups exist.

### 1.1 Testbed samples (generated, with ground truth)
`securiq init` creates ten samples. Refer to them **by name, without a path**: `securiq analyze weak_ikev1_main_3des_md5`.

Location: `backend\data\samples\` (source checkout), or `~\.securiq\samples\` (installed package).
Six of them are also committed to git in `backend\seed\samples\` (these are the ones the hosted site has).

| Sample name | Size | What it is | Use it to test | Expected result |
|---|---|---|---|---|
| `weak_ikev1_main_3des_md5` | 37,988 pkts | IKEv1 Main Mode, 3DES + MD5, MODP-1024, 7-day lifetime, PSK, no PFS | Weak-crypto findings, what-if, verify, drift baseline | **39.5, High Risk.** Critical/High: `KE-001`, `CRYPTO-003`, `AUTH-004`. Traffic: ICMP 50%, file transfer 50%. Ground truth 13/13 |
| `ikev1_aggressive_psk_identity` *(seed)* | 3,013 | IKEv1 Aggressive Mode with PSK, MODP-1536 | Cleartext-identity and crackable-PSK findings | **57.9, Elevated Risk.** `KE-002`, `AUTH-001`, `META-001`. VoIP 100%. GT 12/12 |
| `moderate_ikev2_cbc_sha1_nopfs` *(seed)* | 344 | IKEv2, AES-128-CBC + HMAC-SHA1, MODP-2048, no PFS, legacy fallback proposal | Mid-range score, no critical findings | **73.2, Moderate Risk.** No critical/high. Medium: `KE-006`, `PFS-001`. E-mail 57%, chat 43%. GT 12/12 |
| `strong_ikev2_gcm_ecp384_pfs` | 53,394 | IKEv2, AES-256-GCM, ECP-384, PFS, certificates | The "good" reference; policy compliance | **94.2, Low Risk.** Only `META-003`. Policy: *Compliant on observable requirements*. Video 71%, web 29%. GT 13/13 |
| `transport_ipv6_voip` *(seed)* | 4,974 | IKEv2 **transport mode over IPv6**, AES-128-GCM, Curve25519 | IPv6 parsing, transport-mode inference | **87.9, Low Risk.** Mode *Transport*, IP *IPv6*. VoIP 67%, web 33% |
| `natt_ikev2_chacha_eap` *(seed)* | 4,085 | IKEv2 behind NAT (UDP 4500), ChaCha20-Poly1305, EAP | NAT-T detection, EAP identification | **90.0, Low Risk.** NAT traversal *on*; auth *EAP*. Web 67%, chat 33% |
| `mixed_all_traffic_ikev2` | 59,046 | One tunnel carrying all seven traffic classes in sequence, with PFS rekeys | Traffic classifier, timeline, novelty | **87.7, Low Risk.** 6+ classes listed; novelty *novel* |
| `misconfig_esp_null` *(seed)* | 590 | ESP with NULL encryption (integrity only) | ESP-NULL detection | **40, High Risk**, "capped at 40: Critical finding present". Finding `CRYPTO-001`. ESP shown as *NULL (no encryption)* |
| `replay_anomaly` | 27,511 | Duplicate ESP sequence numbers and a counter reset without rekey | Replay analysis | **70, Moderate Risk**, "capped at 70: High finding present". `REPLAY-001`, `REPLAY-002`. **12 duplicates, 1 counter reset** |
| `ah_transport_integrity_only` *(seed)* | 85 | AH transport mode: authenticated but not encrypted | AH parsing | **40, High Risk.** `CRYPTO-001`. ESP shown as *None (AH provides no encryption)*. No traffic classified |

*(seed)* = also available on the hosted website.

### 1.2 Real-world captures (if you have them)
If you uploaded captures earlier, they are in `backend\data\uploads\` (local only, not in git). These were analysed while writing this guide:

| File | Packets | Expected |
|---|---|---|
| `east-capture.pcap` | 45 | IKEv1 Main Mode, 3DES, MODP-1024 → **40, High Risk**, `KE-001`, `CRYPTO-003`, `AUTH-004`. Novelty *novel* |
| `isakmp-ipsec.pcapng` (two copies) | 15 | IKEv1 Main Mode, AES-128-CBC, MODP-1024 → **40, High Risk**, `KE-001`. Novelty *unusual* |
| `fragmented-icmp-traffic.pcapng` | 20 | **Not IPsec** (no IKE/ESP/AH). Use it as the "wrong kind of capture" test. See [section 7](#7-known-issue) |
| `live-capture-*.pcap` | 500 | A live capture with no IPsec packets in it; same behaviour as above |

To test your own file, pass its path: `securiq analyze C:\path\to\file.pcap`. Any Wireshark capture of IKE/ESP works.

### 1.3 Files that are generated during testing
| Created by | Where |
|---|---|
| `securiq lab build` | `backend\data\lab\` (id like `lab_20260929-185824_228799`) |
| `securiq testbed dataset` | `backend\data\datasets\testbed\` (PCAPs, `manifest.jsonl`, `windows.csv`) |
| `securiq report … -o file` / `export -o file` | The file name you give, in the current folder |
| Analyses | `backend\data\analyses\` |
| Policy, triage | `backend\data\policy.json`, `backend\data\triage.json` |

---

## 2. Terminal testing, step by step

### Step 0. Set up an isolated test environment
This installs the package as a user would, in a throwaway environment with its own data folder, so it cannot
touch your real analyses.

```powershell
cd C:\Users\vedan\OneDrive\Desktop\IP_sec_sih\SecurIQ
python -m venv $env:TEMP\siq-test
$py = "$env:TEMP\siq-test\Scripts\python.exe"
$sq = "$env:TEMP\siq-test\Scripts\securiq.exe"
& $py -m pip install --quiet .
$env:SECURIQ_DATA_DIR = "$env:TEMP\siq-data"
```
Keep this same PowerShell window open (the variables `$sq` and `SECURIQ_DATA_DIR` only exist in it).
Use Windows Terminal or the VS Code terminal so the box characters draw correctly.

To test your working copy instead (fast, uses your real data), use the source install:
```powershell
$sq = "C:\Users\vedan\OneDrive\Desktop\IP_sec_sih\SecurIQ\backend\venv\Scripts\securiq.exe"
Remove-Item Env:\SECURIQ_DATA_DIR -ErrorAction SilentlyContinue
```

### Step 1. Install check
```powershell
& $sq --version
& $sq --help
```
**Pass:** `securiq, version 4.0.0`; help lists the commands (`analyze`, `whatif`, `fleet`, `graph`, `triage`, `policy`, `drift`, `lab`, `live`, `testbed`, `report`, …).

### Step 2. Environment check before setup
```powershell
& $sq doctor
```
**Pass:** Python and data directory are ✓. On a fresh data folder the classifier and samples show ✕ or "run `securiq init`". "Capture tools" shows `!` on Windows (no tcpdump); that is normal.

### Step 3. First-run setup
```powershell
& $sq init
& $sq doctor
```
**Pass:** about 30 to 60 seconds, then "model trained: True · testbed samples: 10"; `doctor` now shows ✓ for the classifier and samples.

### Step 4. List what can be analysed
```powershell
& $sq captures
```
**Pass:** a table of the ten samples with IKE version, ESP suite, mode, IP version, traffic and packet counts.

### Step 5. Analysis — the weak sample
```powershell
& $sq analyze weak_ikev1_main_3des_md5
```
**Pass:**
- A green line: "analysis `<id>` saved — score **39.5** · High Risk".
- **Assessment panel:** big score, risk posture HIGH, finding bars showing 1 Critical, 2 High, 5 Medium, 3 Low.
- **Bottom line** mentions IKEv1, 3DES, MODP-1024; effective strength "64-bit, Broken (<80-bit), limited by PRF-HMAC-MD5".
- **Category scores:** cryptographic strength 30, key exchange 25, forward secrecy 35, authentication 25.
- **Top findings:** `KE-001`, `CRYPTO-003`, `AUTH-004`.
- **Ground truth** panel at the end: 13 of 13 correct.

### Step 6. Analysis — the strong sample (contrast)
```powershell
& $sq analyze strong_ikev2_gcm_ecp384_pfs
```
**Pass:** score **94.2**, Low Risk; one Medium finding (`META-003`). Compare with step 5: the difference shows the scoring works in both directions.

### Step 7. Every view of a capture
Run each and check the "Pass" column. `latest` means the most recent analysis; `@2` means the second newest (the weak one).

| Command | Pass |
|---|---|
| `& $sq show @2 protocol` | Table of properties with a badge (● observed, ◐ inferred, ○ not observable), confidence bars and evidence; the IKE message ladder; the evidence checklist with ✓, ✕, !; negotiated proposals; "Chosen: 3DES-CBC / HMAC-MD5 / PRF-HMAC-MD5 / MODP-1024" |
| `& $sq show @2 findings` | Findings table; evidence chains for Critical and High findings |
| `& $sq show @2 threats` | 5×5 heat matrix with numbered threats and a table with ATT&CK ids (for example T1040) |
| `& $sq show @2 compliance` | Three frameworks (IETF, NIST, CNSA) with pass/warn/fail/unknown; IKEv1 shows a **fail** ("RFC 9395 moves IKEv1 to Historic") |
| `& $sq show @2 traffic` | Application mix (ICMP 50%, file transfer 50%), per-window table, explainability panel |
| `& $sq show @2 timeline` | Gantt-style strips for IKE and ESP tunnels plus a key-events table |
| `& $sq show @2 surface` | Layered boxes: gateways → IKE SA → child SAs → traffic, with weaknesses inside |
| `& $sq show @2 privacy` | Confidentiality and metadata-privacy scores; "an observer CAN see / CANNOT see" lists |
| `& $sq show @2 policy` | Golden policy table with ✓ / ✕ / ? rows; status *Non-compliant* |
| `& $sq show @2 fingerprint` | A hash such as `3071-7A51-B1CE` and a components table |
| `& $sq show @2 esp` | ESP fingerprint (block, IV, ICV), security associations table |
| `& $sq show @2 packets` | Packet table plus per-SPI sequence traces |
| `& $sq show @2 executive` and `technical` | Terminal versions of the two reports |
| `& $sq show @2 all` | Everything in one run |

### Step 8. Evidence chain
```powershell
& $sq explain @2 KE-001
```
**Pass:** five numbered steps: (1) packets, frames `#…`; (2) parameter "Key exchange: MODP-1024 (group 2) — observed 100%"; (3) rule "must provide ≥ 112-bit security", reference "NIST SP 800-57 Pt1 r5 Table 2 · RFC 8247 §2.4"; (4) risk Critical with impact; (5) fix "Use group 19/20/31 or MODP ≥ 3072".
Then `& $sq explain @2 NOT-A-FINDING`. **Pass:** one-line error listing the findings that do exist.

### Step 9. What-if simulator
```powershell
& $sq whatif @2 --options
& $sq whatif @2
& $sq whatif @2 --set dh_group=20 --set pfs=on
& $sq whatif @2 --recommended
```
**Pass:**
- `--options` lists all 14 settings with their allowed values and what the capture currently has.
- With no changes, it prints the recommended change set and how to apply it.
- `--set dh_group=20 --set pfs=on`: the score rises, `KE-001` and `PFS-001` are listed as resolved; the attribution table shows each change on its own and "if removed".
- `--recommended`: the modelled score goes to about **96**, nothing new is introduced, and the policy line improves.

Now the real measurement (renders the proposed configuration as a new capture and re-analyses it; about a minute):
```powershell
& $sq whatif @2 --recommended --verify
```
**Pass:** "measured 39.5 → **95.0** (+55.5) Low Risk, identification accuracy 100%", a resolved/remaining list, and a strongSwan profile at the bottom.

Invalid input should give one line, not a traceback:
```powershell
& $sq whatif @2 --set dh_group=7
& $sq whatif @2 --set ike_version=IKEv1 --set ike_encryption=AES-256-GCM-16
```
**Pass:** the first says "'7' is not valid for dh_group. Choose one of: …"; the second reports that IKEv1 has no AEAD ciphers. Exit code is 1 (`$LASTEXITCODE`).

### Step 10. Golden policy
```powershell
& $sq policy
& $sq policy check @2
& $sq policy set require_pfs=false allowed_dh_groups=14,20
& $sq policy
& $sq policy check all
& $sq policy reset
```
**Pass:** the default policy lists rules such as `allowed_ike_versions: ['IKEv2']`; the weak capture is *Non-compliant*; after `set`, changed values appear highlighted; `check all` prints one line per capture; `reset` restores the defaults. `policy set bogus=1` gives "Unknown policy key".

### Step 11. Drift
```powershell
& $sq drift @1 -b @2
```
**Pass:** baseline and target with their fingerprint ids and scores, a table of changed components with verdicts (▲ strengthened, ▼ weakened, ◌ visibility only), and new/resolved findings. Using the strong sample as target and the weak one as baseline should show mostly **strengthened**.

### Step 12. Fleet tools
Analyse at least four captures first (steps 5 and 6, plus these):
```powershell
& $sq analyze ikev1_aggressive_psk_identity moderate_ikev2_cbc_sha1_nopfs replay_anomaly misconfig_esp_null
& $sq dashboard
& $sq fleet
& $sq fleet ike:ikev1 --facets
& $sq fleet pfs:off risk:high
& $sq fleet "score<70" -src:lab
& $sq fleet finding:KE-001
& $sq fleet --csv fleet.csv
& $sq fleet --help-query
& $sq fingerprints
& $sq analyses
```
**Pass:**
- `dashboard`: KPI numbers, score histogram, risk bar, recurring findings, distribution panels.
- `ike:ikev1`: only IKEv1 rows (the weak and the aggressive ones). `--facets` adds counts.
- `pfs:off risk:high` combines with AND; `dh:2 dh:5` would combine with OR.
- `fleet.csv` is written and starts with `analysis_id,filename,…`.
- `analyses` shows `@1`, `@2`, … references you can use anywhere.

### Step 13. Link graph
```powershell
& $sq graph
& $sq graph --focus finding:KE-001
& $sq graph --type gateway --type finding
```
**Pass:** a node graph with a legend; `--focus` isolates a node and prints its properties; insights list recurring findings, shared configurations and gateways with drift. A wrong `--focus` prints valid node ids.

### Step 14. Triage
```powershell
& $sq triage
& $sq triage set KE-001 --status investigating --note "checking with network team"
& $sq triage --status investigating
& $sq triage set KE-001 --status new
```
**Pass:** the inbox lists every finding occurrence; a bare finding id updates all occurrences ("updated N finding(s)"); the status filter shows only those; an invalid status gives an error.

### Step 15. Lab (digital twin)
```powershell
& $sq lab options
& $sq lab build --set ike_version=IKEv1 --set ike_encryption=3DES-CBC --set ike_integrity=HMAC-MD5-96 --set dh_group=2 --set pfs=off --traffic voip:20 --traffic web:20 --strongswan
& $sq lab list
```
**Pass:** the build reports a new `lab_…` id and packet count; the analysis scores **low** (weak configuration); a **ground-truth** panel shows the tool recovering the settings you chose; a strongSwan profile prints. Now build the opposite:
```powershell
& $sq lab build --label hardened
```
(The defaults are the hardened settings: AES-256-GCM, ECP-384, PFS on, certificates.) **Pass:** a high score, Low Risk.

### Step 16. Real-time analysis
```powershell
& $sq live replay natt_ikev2_chacha_eap --speed 10
& $sq live replay strong_ikev2_gcm_ecp384_pfs --speed 0
& $sq live interfaces
```
**Pass:** a dashboard that refreshes: session status, throughput sparkline, score, IKE/ESP/AH counts, what the VPN is so far (● observed, ◐ inferred), category scores, traffic mix, top threats and an alert feed (for example `META-003`). At the end: "full analysis saved: `<id>` → securiq show `<id>`". Press **Ctrl+C** once to stop early; it should still store an analysis. `--speed 0` runs as fast as possible. `live interfaces` lists capture tools and interfaces (live capture itself needs Npcap or tcpdump and administrator rights).

### Step 17. Testbed, model and evaluation
```powershell
& $sq testbed matrix
& $sq testbed samples
& $sq testbed model
& $sq testbed dataset --count 10 --seed 5
& $sq testbed evaluate --scenarios 8
& $sq testbed benchmark --count 12
& $sq testbed evaluate --latest
& $sq testbed benchmark --latest
```
**Pass:**
- `matrix`: IKE suites, ESP suites and all dimensions.
- `model`: accuracy about **94%**, macro F1 about 94%, ROC-AUC 0.996, per-class table, feature importance.
- `dataset`: a summary of files written under `backend\data\datasets\testbed`.
- `evaluate`: per-field accuracy (about 100% on decided fields; "abstained" is not an error); allow about a minute.
- `benchmark`: detection rate near **100%**, few or no false positives; allow one to two minutes.

### Step 18. Reports and export
```powershell
& $sq report @2 --kind executive
& $sq report @2 --kind technical
& $sq report @2 --kind executive --format html -o exec.html
& $sq report @2 --kind technical --format html -o tech.html
& $sq report @2 --format json -o report.json
& $sq export @2 -o analysis.json
start exec.html
```
**Pass:** the terminal versions render; the HTML files open in the browser and print cleanly (Ctrl+P → Save as PDF); `analysis.json` is valid JSON (`Get-Content analysis.json | ConvertFrom-Json | Select-Object analysis_id`).

### Step 19. Packets and machine-readable output
```powershell
& $sq packets @2 --kind esp --limit 20
& $sq analyze moderate_ikev2_cbc_sha1_nopfs --json | Out-File a.json -Encoding utf8
```
**Pass:** the packet table shows ESP rows with SPI and sequence numbers; the JSON file contains the full analysis.

### Step 20. Real capture file from disk
```powershell
& $sq analyze C:\Users\vedan\OneDrive\Desktop\IP_sec_sih\SecurIQ\backend\seed\samples\misconfig_esp_null.pcap
```
**Pass:** it imports the file and analyses it: **40**, `CRYPTO-001`, ESP "NULL (no encryption)". This proves the path route works, not just sample names. Also try a file of your own.

### Step 21. Clean up
```powershell
Remove-Item -Recurse -Force $env:TEMP\siq-test, $env:TEMP\siq-data
Remove-Item exec.html, tech.html, report.json, analysis.json, a.json, fleet.csv -ErrorAction SilentlyContinue
```

---

## 3. Full-screen console testing

Start it with `& $sq` (or `securiq`). Use a window at least 160 × 45 for the full layout.

| # | Do | Pass |
|---|---|---|
| 1 | Start it | A logo and start-up log scroll (engine, samples, classifier, analyses, capture backends) with a progress bar, then the Operations view. Any key skips the log. |
| 2 | Press `1` (Operations) | A scrolling "LIVE" ticker on top; **animated tunnels** (packets moving both ways ▸ ◂, gold ◆ rekey pulses), tunnels coloured by score; KPI tiles, histograms |
| 3 | Press `2` (Explorer), type `pfs:off` | Rows narrow immediately; the count line updates; select a row and the right panel shows its details; Enter opens it; `e` writes `securiq-fleet.csv` |
| 4 | Press `3` (Link graph) | Nodes burst from the centre and settle; arrow keys or `n`/`p` select nodes; Enter isolates; Esc releases; `i c y g h` toggle node types; click selects the nearest node |
| 5 | Press `4` (Triage) | `j`/`k` move; `i` marks investigating (a toast appears); `x` selects several; `n` opens a note box; `s`/`v` cycle filters; the evidence chain is shown beside the finding |
| 6 | Press `o`, choose `weak_ikev1_main_3des_md5` | Analysis runs (status bar shows a spinner) and the Workspace opens with 14 tabs. `[` and `]` change tabs |
| 7 | Workspace → **Findings** | Highlight a finding: its five-step evidence chain appears on the right |
| 8 | Workspace → **What-if** | Change a select box: results update. **Apply recommended** → about 96. **Verify in digital twin** → about 95.0 measured |
| 9 | Workspace → **Fingerprint** | Press `d`, type `@2`: drift against that baseline |
| 10 | Workspace → **Report** | Buttons switch Executive/Technical; `x` writes an HTML file, `j` a JSON file into the folder you started in |
| 11 | Press `6` (Live), pick a sample, press Replay | Live cards fill in; alerts appear; press `k` (or Stop) to end; Enter opens the stored analysis |
| 12 | Press `7` (Digital twin) | Change settings, press **Build & analyse**; result panel and strongSwan profile appear |
| 13 | Press `8` (Testbed) | Choose "Classifier & metrics", then "Configuration matrix", then "Misconfig benchmark — run" |
| 14 | Press `9` (Policy) | Enter on a row edits its value; the right side re-evaluates every capture; `r` resets |
| 15 | `Ctrl+P`, type `KE-001` or `pfs` | Fuzzy results for pages, captures, findings, saved queries; Enter runs one |
| 16 | `?` then Esc; `Ctrl+B`; `q` | Help lists keys; navigation collapses; the app exits cleanly |

**Pass overall:** no red error toast at any point, and no traceback in the terminal after quitting.

---

## 4. Automated tests

Run from the `backend` folder:
```powershell
cd C:\Users\vedan\OneDrive\Desktop\IP_sec_sih\SecurIQ\backend
.\venv\Scripts\python -m pytest tests\test_terminal.py tests\test_seed.py -q     # the terminal package: about 2 to 6 min
.\venv\Scripts\python -m pytest -q                                              # everything: about 15 min
```
The tests use a temporary data folder and never change your data.

| Test file | What it checks | Uses |
|---|---|---|
| `test_parser.py` | PCAP/PCAPNG reading, link types, IPv6, fragments, truncated frames, IKE payload parsing | Small generated captures |
| `test_analyzer.py` | IKEv1/IKEv2 analysis, ESP/AH, NAT-T, timelines | Generated scenarios |
| `test_inference.py` | Keyless inference: cipher family, ICV, tunnel/transport, PFS, authentication, ESP-NULL, replay vs counter reset | Scenarios with known truth |
| `test_security.py` | Scoring, caps, findings, compliance, threat matrix | Synthetic analysis objects |
| `test_ml.py` | Classifier training and prediction, calibration | A small training run |
| `test_intel.py` | Evidence chains, simulator, policy, fingerprint and drift, fleet, lab | Scenarios |
| `test_realtime.py` | Live engine matches the batch analysis, alerts, sessions | Replay of a scenario |
| `test_api.py` | Every API route: upload validation, analyse, reports, simulator, lab, policy | FastAPI test client |
| `test_terminal.py` | Service layer, query language, every renderer (all 15 views), CLI commands and error messages, a scripted walk through every console view, topology and ticker animation | Scenarios `weak_ikev1_main_3des_md5`, `strong_ikev2_gcm_ecp384_pfs`, `replay_anomaly` |
| `test_seed.py` | Seeding a fresh data folder from the bundled model and samples | Temporary folders |

Last measured: about 165 tests passing.

To run a single test: `.\venv\Scripts\python -m pytest tests\test_terminal.py -q -k query_language`.

---

## 5. Web app testing

The website has its own step-by-step plan with the exact page and button names: **[WEB_TESTING.md](WEB_TESTING.md)**.
Use these samples in it:

| Web page | Best capture |
|---|---|
| Security assessment, What-if, Reports | `weak_ikev1_main_3des_md5` (local) or `ikev1_aggressive_psk_identity` (hosted) |
| Protocol identification → Ground truth | Any sample |
| Traffic & metadata | `mixed_all_traffic_ikev2` (local) or `natt_ikev2_chacha_eap` (hosted) |
| Drift detection | `moderate_ikev2_cbc_sha1_nopfs` versus `ikev1_aggressive_psk_identity` |
| Live monitor | Any sample; try speed 10× |
| VPN lab | Presets *Legacy weak VPN*, *Hardened (golden)*, *Aggressive-mode PSK*, *ESP-NULL misconfiguration* |
| Upload | A real `.pcap` under the size limit; a `.txt` file for the rejection test |

Backend check for the deployed API: open `https://securiq.onrender.com/api/health`.

---

## 6. Negative and edge-case tests

| Test | Command | Expected |
|---|---|---|
| Missing file | `& $sq analyze C:\nope.pcap` | One line: "…is not a file, a testbed sample, a lab build or an upload id"; exit code 1 |
| Not a capture | `Set-Content bad.pcap "hello"`, then `& $sq analyze bad.pcap` | "…is not a pcap / pcapng capture (unrecognised magic number)" |
| Unknown analysis | `& $sq show zzzz` | "No analysis matches 'zzzz'" |
| `@N` out of range | `& $sq show @99` | "Only N analyses exist" |
| Invalid setting | `& $sq whatif @2 --set nonsense=1` | "Unknown setting 'nonsense'. Known: …" |
| Impossible lab config | `& $sq lab build --set ike_version=IKEv1 --set ike_encryption=AES-256-GCM-16` | "IKEv1 Phase 1 has no AEAD ciphers…" |
| Bad triage status | `& $sq triage set KE-001 --status maybe` | Rejected by the option list |
| Wrong policy type | `& $sq policy set max_ike_lifetime_s=abc` | "max_ike_lifetime_s must be an integer" |
| No data yet | Fresh data folder, `& $sq show latest` | "No analyses yet — run `securiq analyze <capture>` first" |
| Empty graph or fleet | Fresh data folder, `& $sq dashboard` | A friendly "No analyses yet" message, no crash |
| Live capture, bad interface | `& $sq capture -i x -d 3` | "Live capture unavailable: Interface 'x' not found !…" with install advice, exit code 1 (this used to crash with a traceback; fixed) |
| Negated query term | `& $sq fleet ike:ikev1 -src:lab` | Works: a leading `-` negates a term and is not treated as a command option (this used to fail with "No such option"; fixed) |
| Ctrl+C during `live replay` | Press Ctrl+C | Stops cleanly and still saves the analysis |
| Piped output | `& $sq fleet --csv out.csv`, `& $sq analyze <s> --json` | Plain, parseable output with no colour codes |

Every failure above should be **one readable line with exit code 1** (`$LASTEXITCODE`), never a Python traceback.

---

## 7. Known issue

Writing this guide involved running every command, which found two defects. Both are **fixed** and covered by new
tests: `securiq capture -i <bad interface>` crashed with a traceback, and `securiq fleet … -src:lab` was rejected as an
unknown option. One defect remains open:

While preparing the expected results I analysed a capture that contains **no IPsec traffic at all**
(`fragmented-icmp-traffic.pcapng`: 20 packets, 0 IKE, 0 ESP, 0 AH). The tool reported:

- **Score 100.0, "Low Risk"**, and a bottom line beginning "The capture shows an IPsec VPN using a data-channel
  cipher that could not be inferred…".

It also marks the result **provisional with 8.5% coverage**, and every category except metadata exposure is
"not assessable", so the tool does signal that it knows little. But a headline of "100, Low Risk" for a capture with
no VPN in it is misleading. **What a tester should expect today:** any non-IPsec capture scores 100 with very low
coverage. **Recommended fix (not yet made):** when no IKE, ESP or AH is found, show "No IPsec traffic found in this
capture", withhold the score and risk level, and skip the "shows an IPsec VPN" wording.

Other limits that affect testing:
- Tunnel-versus-transport mode and PFS are sometimes reported as *not observable* (for example, mode for the aggressive-mode,
  moderate and mixed samples). That is by design: the tool abstains rather than guesses.
- Live capture from a real network interface has not been tested here (needs Npcap or tcpdump and admin rights).
- The hosted free-tier site loses its data on restart, has six samples, and caps uploads at 15 MB.

---

## 8. Testing the live feature

"Live" means the analysis runs **while packets arrive**: the profile, score, traffic mix and alerts grow over time and
alerts fire the moment a weakness becomes evident. Test it at three levels, from easiest to most realistic.

### Level 1: Replay (works everywhere, including the hosted site)
A stored capture is fed through the same real-time engine at a chosen speed.

Terminal:
```powershell
& $sq live replay natt_ikev2_chacha_eap --speed 10
```
Console (`& $sq`, key `6`), or web (**Live monitor**): choose the capture, choose a speed, press Replay / Start.

**Pass:**
- The status goes `running` → `finalizing` → `finished`, and packets and capture time advance.
- The throughput line moves; **"what the VPN is (so far)"** starts nearly empty and fills in: IKE version first
  (● observed), then the ESP suite (◐ inferred).
- The score changes as evidence arrives; the alert feed adds entries such as `META-003`.
- At the end: "full analysis saved: `<id>`". That analysis matches the batch result: run `& $sq analyze natt_ikev2_chacha_eap`
  and compare the score (90.0) and identified properties. They should be identical.
- `--speed 0` runs as fast as possible. On the web, the speed selector goes 1× to 200×.
- **Stop early:** press `Ctrl+C` in the terminal (or Stop in the app). It should still store an analysis of what arrived.
- **Limit:** start four sessions at once; the fourth is refused (maximum three).

Good replay samples: `weak_ikev1_main_3des_md5` (alerts for `KE-001`, `CRYPTO-003`, `AUTH-004` appear early),
`replay_anomaly` (raises `REPLAY-001` / `REPLAY-002` only once the duplicates arrive), `mixed_all_traffic_ikev2`
(the traffic mix changes as the applications change).

### Level 2: A real interface, with real IKE messages (loopback)
This proves live capture from a network adapter works without needing a VPN. You need **two terminal windows**, and
capture tools: **Npcap** on Windows (you may need to run the terminal as Administrator), or `tcpdump`/root on Linux.

1. Find the loopback interface name:
   ```powershell
   & $sq live interfaces
   ```
   Windows: `\Device\NPF_Loopback`. Linux: `lo`.
2. **Window 1**, start capturing (quote the name):
   ```powershell
   & $sq live capture "\Device\NPF_Loopback"
   ```
   **Pass:** a live dashboard appears with 0 packets, status `running`.
3. **Window 2**, send genuine IKE messages taken from a sample (from the repo folder, using your venv's python):
   ```powershell
   cd C:\Users\vedan\OneDrive\Desktop\IP_sec_sih\SecurIQ
   .\backend\venv\Scripts\python -m backend.testbed.send_ike moderate_ikev2_cbc_sha1_nopfs
   ```
   **Pass:** it prints `sent 12 IKE messages (12 distinct) to 127.0.0.1:500`.
4. Watch window 1. **Pass (measured on this machine):**
   - Within a second or two: **12 packets, 12 IKE**, and the profile fills in: **IKEv2, AES-128-CBC, MODP-2048 (group 14),
     Pre-Shared Key, PFS off, IPv4**.
   - A score of about **71, Moderate Risk**, and alerts `KE-006`, `PFS-001`, `CFG-005`.
   - The score differs slightly from the batch sample (73.2) because only IKE is sent here, so there is no ESP evidence.
5. Press `Ctrl+C` in window 1. **Pass:** it stops and prints "full analysis saved: `<id>`". Then `& $sq show <id> protocol`
   shows the same properties, with 12 IKE packets.

Options for the sender: `--host <address>` to send to another machine that you are capturing on, `--repeat 5` to send
the exchange several times, `--delay 0.5` to slow it down, and a path instead of a sample name to use your own pcap.

Only IKE can be sent this way. ESP is a raw IP protocol and needs a real tunnel, which is Level 3.

**Not IPsec traffic:** capturing your ordinary traffic with the default filter shows nothing, because the default filter
is `esp or ah or udp port 500 or udp port 4500`. That is correct behaviour.

### Level 3: Real IPsec traffic
Capture a real VPN on a machine or gateway you own:
- **strongSwan lab** in `backend/testbed/strongswan` (Docker on Linux or WSL2): `./run_matrix.sh 01-ikev2-strong-pfs`. It
  creates real tunnels and saves captures. Capture on the docker bridge with `securiq live capture <bridge>` while it runs.
  This lab is written but has **not been run yet**.
- **Any real IPsec VPN** you are authorised to monitor: `securiq live capture <interface>` on the machine or its gateway.
  Confirm the result against the gateway's configuration.

**Pass:** the identified properties match the configuration, and the score agrees with `securiq analyze` on a capture
of the same traffic.

### Troubleshooting live capture
| Symptom | Cause | Fix |
|---|---|---|
| `Live capture unavailable: … not found` | Wrong interface name | Copy the exact name from `securiq live interfaces` |
| `No capture backend` | No Npcap / tcpdump | Install Npcap (Windows) or tcpdump (Linux) |
| Permission error | Needs elevated rights | Run the terminal as Administrator (Windows) or with `sudo` (Linux) |
| 0 packets while sending | Filter or interface mismatch | Use the loopback name and the default filter; send to `127.0.0.1` |
| Packets counted but nothing identified | Frames from a link type the parser could not read | Fixed in this version for the loopback adapter; report other interface types |
| Hosted website: interface option missing | Servers have no capture backend | Use Replay on the hosted site; use the terminal locally for interfaces |

### Bugs this test found (both fixed, with regression tests)
1. **Loopback captures identified nothing.** The live capture source labelled loopback frames as "raw IP", and the parser
   also mis-decoded the 4-byte loopback header used on Windows, macOS and BSD (`02 00 00 00`), so every such frame was
   counted as non-IP. Both are fixed (`backend/realtime/sources.py`, `backend/analyzers/pcap_parser.py`), and
   the parser now also accepts the IPv6 family codes used by Windows and Linux (23 and 10).
2. `securiq capture -i <bad name>` crashed with a traceback; it now reports one line.
