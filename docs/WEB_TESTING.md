# Testing every feature in the web app

A step-by-step manual test plan. Page names and button labels match the app. Open the deployed address, or
`http://localhost:5173` for a local run (backend on port 8000).

**Hosted note.** On the free Render plan the API sleeps after 15 minutes idle (first request takes about a minute),
data resets on restart, only six small samples exist, uploads are capped at 15 MB, and live capture from a network
interface is unavailable. Those steps are marked *(local only)*.

Keyboard: `Ctrl+K` (or `/`) opens the search palette, `?` lists shortcuts, `Ctrl+B` collapses the left rail,
and `g` then a letter jumps to a page (`g c` Captures, `g s` Security, `g w` What-if, and so on).

---

## 0. Before you start

| Check | How | Pass |
|---|---|---|
| API is up | Open `<api>/api/health` in a browser | `"status":"healthy"`, `"model_trained":true`, `"sample_files"` is 6 (hosted) or 10 (local) |
| Site loads | Open the front-end address | The left rail and the top bar appear; no red error banner |
| Model ready | Look at the header | It does not say "Model training…" |

If the page loads but every request fails, see the troubleshooting table at the end.

---

## 1. Create test data (do this first)

1. Go to **Captures & samples** (`g c`).
2. In **Testbed scenarios**, click **Analyse** on `weak_ikev1_main_3des_md5` (local only) or on
   `ikev1_aggressive_psk_identity` (hosted).
3. Click **Analyse** on `moderate_ikev2_cbc_sha1_nopfs`, then on `natt_ikev2_chacha_eap`.

**Pass:** each click shows a progress state, then the app opens the analysis. Analysing a sample takes a few
seconds. Three analyses now exist, and the newest is the "current capture" used by every *Analyse*, *Decide* and
*Output* page.

Sample checks (local samples):
| Sample | Expected |
|---|---|
| `weak_ikev1_main_3des_md5` | Score about **39.5**, High Risk; critical finding for MODP-1024 (weak DH) |
| `strong_ikev2_gcm_ecp384_pfs` | Score about **94**, Low Risk |
| `mixed_all_traffic_ikev2` | Score about 88, several traffic classes |

---

## 2. Feature-by-feature tests

### 2.1 Captures & samples (`g c`)
| Test | Steps | Expected |
|---|---|---|
| Analyse a sample | Click **Analyse** on any scenario | Analysis opens; no error toast |
| Upload a valid capture | Use the upload area with a `.pcap` or `.pcapng` under the size limit | Listed under **Your uploads**; **Analyse** works |
| Reject a bad file | Upload a `.txt`, or a renamed non-pcap | A clear error message (invalid type or "not a pcap"); nothing is stored |
| Reject an oversize file | Upload a file over the limit (15 MB hosted, 100 MB local) | "File too large" message |
| VPN lab builds | After section 2.12, return here | Your lab builds are listed under **VPN lab builds** with an **Analyse** button |
| Live capture *(local only)* | **Start capture** with an interface and duration | Requires Npcap and admin rights; otherwise a message explains what is missing |

### 2.2 Operations dashboard (`g d`)
Needs at least two analyses.
- **Expected:** a **Latest assessment** card for the newest capture, fleet numbers, score distribution, risk
  posture and recurring findings. With nothing analysed you see "Nothing analysed yet".
- Click a capture or finding; it navigates to the matching page.

### 2.3 Protocol identification (`g a`)
Tabs: **Identification**, **IKE negotiation**, **ESP / AH**, **Ground truth** (samples only), **Timeline**, **Packets**.

| Tab | Test | Expected |
|---|---|---|
| Identification | Read the property list | Each property shows a value, a badge (observed / inferred / not observable), a confidence, and the evidence sentence. Click a property to expand its evidence checklist (✓ supports, ✕ contradicts, ! limits). |
| IKE negotiation | Open it | Offered proposals, the chosen suite, weak proposals offered, and the IKE message ladder |
| ESP / AH | Open it | SPIs, security associations, cipher fingerprint reasoning from ciphertext lengths, tunnel-vs-transport inference |
| Ground truth | Open it (samples and lab builds) | A field-by-field table: correct / wrong / abstained, with an accuracy figure. Abstained is not an error. |
| Timeline | Zoom with the wheel, drag to pan, select an event | IKE messages, tunnel lifetimes, application per window, rekeys and replay anomalies |
| Packets | Scroll the table | Packet list with IKE and ESP details and sequence numbers |

### 2.4 Traffic & metadata (`g m`)
- **Expected:** the application mix (VoIP, web, video, file transfer, e-mail, chat, ICMP), per-window
  classification with confidence, flags for uncertain or novel windows, the features behind each label, and
  a metadata-privacy section stating what a passive observer can learn.
- **Pass:** for `mixed_all_traffic_ikev2` several classes appear; the model card shows accuracy about 94% and
  ROC-AUC about 0.996.

### 2.5 Security assessment (`g s`)
Tabs: **Overview**, **Findings**, **Compliance**, **Threat matrix**, **Recommendations**.

| Tab | Test | Expected |
|---|---|---|
| Overview | Read the score card and category bars | Overall score, risk level, coverage, the cap message ("capped at 40: Critical finding present") for weak captures, eight category scores |
| Findings | Click a finding | Its evidence chain: packet frames → parameter → rule with RFC/NIST reference → risk and impact → fix |
| Compliance | Open it | IETF, NIST and CNSA checks with pass / warn / fail / unknown |
| Threat matrix | Open it | A 5×5 likelihood-by-impact grid with threats placed in it and ATT&CK references |
| Recommendations | Open it | Prioritised actions (Immediate, High, Medium…) |

**Pass:** weak sample = Critical/High findings and a low score; strong sample = few findings and a score near 94.

### 2.6 Attack surface (`g x`)
- **Expected:** layers from gateways to IKE SA, child SAs and traffic, each box coloured by its worst finding,
  with weaknesses listed inside it. Clicking a box should reveal its facts.

### 2.7 What-if simulator (`g w`) — the key feature
1. Open it on the weak capture.
2. Click **Apply recommended fixes**.
3. **Expected:** the proposed column fills in; a modelled score appears (about 96 for the weak sample); resolved
   findings are listed; the golden policy status and fingerprint update.
4. Click **Reset**, then change one setting yourself (for example DH group). **Expected:** the score changes and
   the attribution table shows what each change contributes alone and "if removed".
5. Click **Verify proposed configuration**. **Expected:** the steps tick through ("render", "capture", "analyse"),
   then a **measured** score (about **95.0** for the weak sample) next to the modelled one, and a strongSwan
   profile you can copy with **Copy profile**.
6. Try an invalid combination (for example IKEv1 with a GCM cipher). **Expected:** a clear validation message,
   and Verify is disabled.

### 2.8 Golden policy (`g p`)
1. Open it and note the checks and their status (a weak capture fails many).
2. Change a rule (for example untick IKEv1, or set a minimum encryption size), then click **Save policy**.
   **Expected:** status changes to "Saved", and the checks re-evaluate.
3. Refresh the page. **Expected:** the change persists (until the server restarts on the free plan).
4. Click **Restore default**. **Expected:** the original rules return.
5. **Pass criterion:** anything the capture cannot show is *unknown*, never *pass*.

### 2.9 Drift detection (`g f`)
1. Analyse two different captures (for example the weak and moderate samples).
2. Open it, choose a **Baseline (earlier)** and a target capture.
3. **Expected:** the two configuration fingerprints, a component-by-component change table with each change marked
   strengthened, weakened or visibility only, the score change, and new and resolved findings.
4. With no earlier capture of the same gateways it shows "no baseline".

### 2.10 Reports (`g r`)
- Click **Executive report** and **Technical report**: each opens in a new tab as a formatted page. Use the browser
  print dialog and "Save as PDF" to confirm it prints cleanly.
- Click **Full results (JSON)**: a JSON file downloads with the complete analysis.

### 2.11 Live monitor (`g v`)
1. Choose **Replay a capture**, pick a sample, choose a speed (for example 10×), and click the start button.
2. **Expected:** the session card shows packets and time advancing; the **Live identification** card fills in as
   evidence accumulates; **Throughput** draws; **Traffic inside the tunnel** classifies each 10-second window;
   **Protocol events** lists IKE exchanges and new SAs; **Alerts** fire when a weakness becomes evident.
3. Let it finish, or click **Stop**. **Expected:** it stores a full analysis and offers to open it, and its
   score matches the batch analysis of the same capture.
4. Try starting a second and third session at the same time, then a fourth. **Expected:** the fourth is refused
   (limit of three).
5. **Network interface** mode *(local only)* needs Npcap or tcpdump and administrator rights.

### 2.12 VPN lab / digital twin (`g l`)
1. Click a preset: **Legacy weak VPN**, **Hardened (golden)**, **Aggressive-mode PSK**, or
   **ESP-NULL misconfiguration**.
2. Adjust any setting, the traffic mix (add or remove classes), and the impairment level.
3. Click **Generate & analyse**.
4. **Expected:** progress steps run, then a result with the score and the identification accuracy against the
   configuration you chose, plus a strongSwan profile.
5. **Pass:** *Legacy weak VPN* scores low with critical or high findings; *Hardened (golden)* scores high
   (Low Risk); *ESP-NULL* raises an ESP-NULL finding; *Aggressive-mode PSK* raises the cleartext-identity and
   crackable-PSK findings. The identification accuracy should be near 100% on the fields the capture can show.
6. The built capture appears under **Captures & samples → VPN lab builds**.

### 2.13 Triage inbox (`g i`)
1. Open it. **Expected:** every finding from every capture, sorted by severity.
2. Select a row and press `i` (investigating), `a` (risk accepted), `r` (resolved), `f` (false positive),
   `n` (add a note), or `j` and `k` to move. Press `x` to select several and apply a status in bulk.
3. **Expected:** the status changes immediately, the evidence chain shows beside the finding, and the change
   **survives a page reload**.

### 2.14 Object explorer (`g e`)
1. Type `pfs:off` in the query box. **Expected:** only captures with PFS off.
2. Add `risk:high`. **Expected:** the list narrows (different fields combine with AND).
3. Add `dh:2 dh:5`. **Expected:** matches either group (the same field combines with OR).
4. Type `-src:testbed`. **Expected:** testbed samples are excluded (`-` negates).
5. Try `score<70` and `finding:KE-001`. **Expected:** filtered results.
6. Click a facet; **Expected:** the query updates and facet counts change. Click a column header to sort.
7. Export CSV. **Expected:** a CSV with the visible rows downloads.

### 2.15 Link graph (`g g`)
1. **Expected:** captures, gateways, fingerprints, findings, traffic classes and configuration values as a graph.
2. Wheel to zoom, drag the background to pan, drag a node to pin it, click a node to inspect it.
3. Isolate a neighbourhood (1 or 2 hops). **Expected:** everything unrelated dims or hides.
4. **Pass:** the side panel lists recurring findings, shared configurations, and gateways with configuration drift.

### 2.16 Testbed & model (`g t`)
| Section | Test | Expected |
|---|---|---|
| Curated scenarios | Click **Analyse** on a row | Opens an analysis |
| Dimensions | Read the matrix | IKE and ESP suites and their wire framing |
| Labelled PCAP dataset | Click **Generate dataset** | A result summary and files available to download |
| Classifier | View the model card; click **Retrain** (about a minute; skip on the free hosted plan) | Confusion matrix, per-class quality, features, accuracy about 94% |
| End-to-end identification accuracy | **Run evaluation** (about 1 minute) | Per-field accuracy; abstentions counted separately |
| Misconfiguration benchmark | **Run benchmark** (1 to 2 minutes) | Detection rate near 100%, false-positive counts, per-defect table |

Hosted note: evaluation and benchmark generate captures in memory; on 512 MB they may be slow or fail. If they
do, run them locally or from the terminal (`securiq testbed evaluate`, `securiq testbed benchmark`).

### 2.17 Command palette and shortcuts
- `Ctrl+K`: type a page name, a finding ID such as `KE-001`, a gateway address, or a fingerprint. **Expected:**
  fuzzy results; Enter navigates. Use `>` for actions, `#` for findings, `@` for objects.
- `?`: shows the shortcuts list. `Ctrl+B`: collapses the rail. `g` then a letter: jumps to a page.

---

## 3. Cross-cutting checks

| Check | How | Pass |
|---|---|---|
| Deep links | Reload the browser on `/security` or `/graph` | The page loads (no 404) |
| Persistence | Triage a finding, reload | Status is still set |
| Error handling | Stop the API (or turn off wifi) and click Analyse | A readable error toast, no blank screen |
| Empty state | Open **Security assessment** with no analyses | "Nothing analysed yet" style prompt |
| Responsive | Narrow the window | The rail collapses; pages remain usable |
| Cold start (hosted) | Wait 20 minutes, reload | First load takes about a minute, then works |

---

## 4. Quick pass/fail summary

- [ ] Health endpoint shows `model_trained: true`
- [ ] Analysing the weak sample gives about 39.5 with Critical and High findings
- [ ] Every finding opens an evidence chain
- [ ] What-if recommended fixes give about 96 modelled and **Verify** gives about 95 measured
- [ ] Policy edits save and persist across a reload
- [ ] Drift shows changed components between two captures
- [ ] Live replay completes and stores an analysis
- [ ] Lab presets build and score as described
- [ ] Triage status persists across reload
- [ ] Explorer queries filter, and CSV exports
- [ ] Link graph selects, zooms and isolates nodes
- [ ] Reports open and print

---

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Every page shows "Failed to fetch" | `VITE_API_BASE` is wrong, or CORS mismatch | Check `VITE_API_BASE` ends in `/api`; in Render set `SECURIQ_CORS_ORIGINS` to the exact front-end address (no trailing slash); redeploy Vercel after changing the variable |
| Works after a minute | API was asleep (free plan) | Open `/api/health` first and wait |
| Analyses vanished | Free plan resets data on restart | Re-run the analysis |
| Header says "Model training…" for long | Model failed to load | Check the Render log for `Seeded model and samples`; check `SECURIQ_SEED_DIR=backend/seed` |
| Upload rejected | Over the size limit or not a pcap | Use a smaller pcap; the hosted limit is 15 MB |
| Lab or evaluation times out | Not enough memory on the free plan | Run them locally or from the terminal |
| Simulator, Policy, Drift or Reports empty | No current capture | Analyse a capture first |
| Live interface list empty | No capture backend | Use replay, or run locally with Npcap or tcpdump and admin rights |
