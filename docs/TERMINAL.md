# SecurIQ in the terminal

SecurIQ ships as an installable Python package with one command, `securiq`. Every feature of the web
application is available from the shell, and `securiq` with no arguments opens a full-screen operations
console styled after Palantir Gotham / Blueprint: near-black canvas, thin panel chrome, small-caps labels,
saturated intent colours, dense data, everything linked. There is no server: the console and the commands
call the analysis engine directly.

## Install and first run

```bash
pip install -e .            # from the repository root; adds the `securiq` command
securiq init                # generates 10 testbed captures and trains the classifier (~30 s, once)
securiq                     # opens the console
```

`setup.ps1` / `setup.sh` do the same inside `backend/venv`. Data lives in `backend/data` when run from a
source checkout (shared with the web app) and in `~/.securiq` for a normal install; set `SECURIQ_DATA_DIR`
to move it. `securiq doctor` checks the model, samples, data directory and capture backends.

Requires Python 3.9+, a terminal with truecolor and Unicode (Windows Terminal, iTerm2, GNOME Terminal, VS Code),
about 190×50 cells for the full layout (it adapts down to about 120×36).

## The console (`securiq`, or `securiq tui`)

On start a boot sequence narrates the real initialisation steps (engine, samples, classifier with its accuracy,
stored analyses, capture backends) with a progress bar; any key skips it. The link graph bursts from the centre and
settles into its layout whenever it is opened, filtered or isolated.

Layout: a classification banner, a status bar (fleet size, model state, current capture, clock, background
job), a navigation rail on the left, the active view, and a key-hint footer.

| Key | View | What it is for |
|---|---|---|
| `1` | **Operations** | A scrolling ticker of findings across the fleet, and the **live tunnel topology**: every gateway pair drawn as an animated tunnel with ciphertext packets flowing both ways (▸ outbound, ◂ inbound), packet density and speed taken from the capture's real packet rate, the pipe coloured by the tunnel's security score, periodic IKE rekey pulses (◆), and the worst finding under each tunnel. Below it: fleet KPIs (captures, mean score, criticals, policy breaches, novel configurations, fingerprints), score histogram, risk posture bar, recurring findings across captures, distributions of IKE version, DH group, authentication and PFS, recent captures. |
| `2` | **Object explorer** | Every capture as a row. Type a query (`dh:2 dh:5 pfs:off risk:high score<70 -src:testbed finding:KE-001 traffic:voip`); facet counts update as you filter and `enter` on a facet adds it to the query; the right panel shows the selected capture. `enter` opens it, `e` exports CSV. |
| `3` | **Link graph** | Captures, gateways, configuration fingerprints, findings, traffic classes and configuration values as a force-directed graph drawn on the terminal. Arrow keys / `n` `p` / click select nodes; `enter` isolates a neighbourhood; `i c y g h` toggle node types. The side panel lists the node's properties and links, recurring findings, shared configurations and gateways whose configuration drifted. |
| `4` | **Triage inbox** | Every finding occurrence with a persisted status (new, investigating, accepted, resolved, false positive), notes and history. `j`/`k` move, `i a r f w` set status, `n` notes, `x` selects for bulk changes, `s`/`v` filter by status/severity. The evidence chain of the highlighted finding is shown beside it. |
| `5` | **Analysis workspace** | One capture in 14 tabs (below). `[` `]` switch tabs, `x`/`j` export the report. |
| `6` | **Live ops** | Real-time analysis: replay a stored capture at 1×–50× (or as fast as possible) or capture an interface. The profile, score, categories, traffic mix, threats and an alert feed update as packets arrive; when the stream ends the full pipeline runs and the analysis is stored. |
| `7` | **Digital twin** | Choose IKE version, ciphers, DH group, PFS, mode, lifetimes, hardening options, IP version, NAT-T and the applications inside the tunnel; SecurIQ generates the negotiation and encrypted traffic, captures it as a PCAP and analyses it. Shows accuracy against the ground truth and emits the matching strongSwan profile. |
| `8` | **Testbed & model** | The configuration matrix, curated samples, classifier metrics (per-class report, calibration, feature importance, novelty detector), end-to-end evaluation, the misconfiguration benchmark, dataset generation, sample regeneration and retraining. |
| `9` | **Policy & compliance** | The golden policy as an editable table (`enter` edits a value, `r` resets) beside every capture checked against it. Anything the capture cannot show is *unknown*, never a pass. |

Global keys: `ctrl+p` command palette (fuzzy search over pages, workspace tabs, captures, findings,
fingerprints, gateways, saved queries, samples and actions), `o` open or analyse a capture (a path, sample name,
lab build or stored analysis), `ctrl+r` refresh, `ctrl+b` collapse navigation, `?` help, `q` quit.

### The workspace tabs

| Tab | Contents |
|---|---|
| Overview | Security score, risk posture, finding counts, AI confidence, bottom line, category scores, top findings, and the explanation *Risk → Evidence → Impact → Recommendation*. |
| Protocol | Every identified property with how it is known (● observed · ◐ inferred · ○ not observable), a confidence bar and the evidence sentence; the IKE message ladder; the evidence checklist (✓ supports, ✕ contradicts, ! limit); the negotiated proposals and downgrade surface. |
| Findings | Table of findings; the highlighted one expands into its evidence chain: packet frames → extracted parameter → security rule with RFC/NIST reference → risk and impact → fix. |
| Threats | 5×5 likelihood × impact matrix with numbered threats and ATT&CK references. |
| Compliance | RFC 8247/8221/9395, NIST SP 800-77r1 and CNSA 1.0 checks, each pass / warn / fail / unknown with its reference. |
| Traffic | Application mix inside the tunnel, per-window classification with confidence, HMM smoothing, novelty flags and the features that drove the label. |
| Timeline | Gantt view of IKE messages, each tunnel's lifetime and the application in every window; replay anomalies and SA lifetimes. |
| Surface | Gateways → IKE SA → child SAs → traffic, with each finding pinned to the layer it concerns. |
| Privacy | Confidentiality and metadata privacy scored separately over ten exposure dimensions, and what a passive observer can and cannot learn. |
| Policy | The capture against the golden policy. |
| Fingerprint | The configuration hash and its components, the novelty verdict, and drift against an earlier capture of the same gateways (`d` picks the baseline). |
| What-if | Change any setting (left); the unchanged rule engine re-scores the capture (right) with per-change attribution, resolved and introduced findings and the policy and fingerprint effect. *Apply recommended* sets the smallest fixing change set; *Verify in digital twin* renders the proposed configuration with the same traffic and measures it with the full pipeline. |
| Packets | Packet table and per-SPI ESP sequence-number traces that pinpoint replay. |
| Report | Executive and technical reports; export as printable HTML (PDF from a browser) or JSON. |

## Commands

Every command accepts a capture as a `.pcap`/`.pcapng` path, a testbed sample name, a lab build id or an upload
id. Stored analyses are referenced as `latest`, `@N` (Nth newest), an id, or a file-name fragment.

```text
securiq init [--force]                       first-run setup
securiq doctor                               environment check
securiq captures | analyses                  what can be analysed / what has been analysed

securiq analyze TARGET… [-v VIEW…|-v all] [--json] [--open]
securiq show REF [VIEW]                      overview protocol findings threats compliance traffic timeline
                                             surface privacy policy fingerprint esp packets executive technical all
securiq explain REF [FINDING]                evidence chain(s)
securiq packets REF [--kind esp|ike|ah]

securiq dashboard                            fleet operations
securiq fleet [QUERY…] [--facets] [--csv F]  object explorer
securiq graph [--focus NODE] [--type T…]     link graph
securiq triage [--status S] [--severity V]   inbox;   securiq triage set KEY… --status S --note N
securiq fingerprints                         configurations grouped

securiq whatif REF --set dh_group=20 --set pfs=on | --recommended  [--verify] | --options
securiq policy [show|set K=V…|reset|check REF|all]
securiq drift TARGET [-b BASELINE]

securiq lab options | build --set K=V --traffic web:25 --traffic voip:20 [--strongswan] | list
securiq live replay TARGET --speed 10        real-time engine on a stored capture
securiq live capture IFACE [--filter BPF]    live interface (needs Npcap/tcpdump and privileges)
securiq live interfaces
securiq capture -i IFACE -d 30               bounded Scapy capture, then analyse

securiq testbed matrix | samples | regen | dataset --count 30 | evaluate | benchmark | model | train
securiq report REF --kind executive|technical --format terminal|html|json [-o FILE]
securiq export REF -o FILE                   complete analysis as JSON
```

Exit codes are 0 on success and 1 on a reported problem (bad reference, invalid setting, unreadable capture);
errors are one readable line, never a traceback. Output is plain when piped, so `securiq fleet --csv` and
`securiq analyze --json` are scriptable.

## A five-minute tour

```bash
securiq init
securiq analyze weak_ikev1_main_3des_md5 -v overview -v findings     # 39.5/100, MODP-1024 + 3DES + MD5
securiq explain latest KE-001                                        # the evidence chain
securiq whatif latest --recommended --verify                         # modelled 39.5 → 96.5, measured 39.5 → 95.0
securiq analyze strong_ikev2_gcm_ecp384_pfs mixed_all_traffic_ikev2
securiq fleet "pfs:off risk:high"                                    # query the fleet
securiq graph                                                        # link graph
securiq live replay mixed_all_traffic_ikev2 --speed 25               # real-time dashboard
securiq                                                              # everything above, interactive
```

## Architecture

```
securiq/
  cli.py          click commands (thin: parse arguments, call core, print renderables)
  core.py         service layer: analyse, resolve references, simulate, verify, lab, policy, fleet, triage,
                  query language, testbed, live sessions, reports. No I/O beyond the data directory.
  render.py       Rich renderables for one capture (used by the CLI and the workspace tabs)
  render_fleet.py Rich renderables for fleet views, graph, triage, model, evaluation, benchmark, live
  viz.py          bars, sparklines, block digits, histograms, heat matrix, Gantt strips, character canvas,
                  force-directed layout
  theme.py        palette and style helpers
  tui/            Textual application: app shell, nine views, dialogs, stylesheet
backend/          the analysis engine (unchanged API surface; the web app still runs from it)
```

The CLI and the console never duplicate logic: both call `core` and both draw with `render` / `render_fleet`,
so a number on the command line is the number in the console. Tests are in `backend/tests/test_terminal.py`
(service layer, every renderer, every command, and a scripted run through every console view).
