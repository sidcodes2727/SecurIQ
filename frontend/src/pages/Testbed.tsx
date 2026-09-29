import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { BarList, ConfusionHeatmap } from '../components/charts';
import { Page } from '../components/Layout';
import { Card, ErrorBanner, KeyValue, Loading, StatTile, StatusPill, TableWrap, Tabs } from '../components/ui';
import { rememberAnalysis, usePolling } from '../hooks/useAnalysis';
import { TRAFFIC_CLASSES, TRAFFIC_LABELS, pct, titleCase } from '../lib/format';
import { api } from '../services/api';
import type { Loose } from '../types';

type Tab = 'scenarios' | 'matrix' | 'dataset' | 'model' | 'evaluation' | 'benchmark';

export default function Testbed() {
  const [params] = useSearchParams();
  const [tab, setTab] = useState<Tab>((params.get('tab') as Tab) || 'scenarios');
  return (
    <Page title="Testbed & model" subtitle="Configuration matrix, labelled dataset, classifier, and the evaluations behind every accuracy figure">
      <Tabs active={tab} onChange={setTab} tabs={[
        { key: 'scenarios', label: 'Scenarios' },
        { key: 'matrix', label: 'Configuration matrix' },
        { key: 'dataset', label: 'Dataset' },
        { key: 'model', label: 'Classifier' },
        { key: 'evaluation', label: 'Identification accuracy' },
        { key: 'benchmark', label: 'Misconfiguration benchmark' },
      ]} />
      {tab === 'scenarios' && <Scenarios />}
      {tab === 'matrix' && <Matrix />}
      {tab === 'dataset' && <Dataset />}
      {tab === 'model' && <Model />}
      {tab === 'evaluation' && <Evaluation />}
      {tab === 'benchmark' && <Benchmark />}
    </Page>
  );
}

function Scenarios() {
  const navigate = useNavigate();
  const [scenarios, setScenarios] = useState<Loose[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.getScenarios().then((d) => setScenarios(d.scenarios)).catch((e) => setError(e.message)); }, []);

  const analyze = async (name: string) => {
    setBusy(name);
    try {
      const res = await api.analyze(name);
      rememberAnalysis(res.analysis_id);
      navigate(`/analysis?id=${res.analysis_id}&tab=truth`);
    } catch (e) { setError((e as Error).message); setBusy(null); }
  };

  if (error) return <ErrorBanner message={error} />;
  if (!scenarios) return <Loading />;
  return (
    <Card title="Curated scenarios" subtitle="Each capture is generated from a known configuration — the ground truth the AI is checked against">
      <TableWrap>
        <table className="data-table">
          <thead><tr><th>Scenario</th><th>IKE</th><th>IKE SA suite</th><th>ESP suite</th><th>Mode</th><th>IP</th>
            <th>PFS</th><th>Auth</th><th>Traffic</th><th /></tr></thead>
          <tbody>{scenarios.map((s) => (
            <tr key={s.name}>
              <td className="text-primary">{s.name.replace(/_/g, ' ')}<div className="muted text-xs wrap">{s.description}</div></td>
              <td>{s.ike_version}{s.ike_version === 'IKEv1' ? ` ${s.exchange_mode}` : ''}</td>
              <td>{s.ike_encryption}<div className="muted text-xs">{s.dh_group_name}</div></td>
              <td>{s.esp_suite ?? 'AH only'}</td><td>{s.mode}</td><td>{s.ip_version}</td>
              <td>{s.pfs ? 'on' : 'off'}{!s.pfs_observable && <span className="muted"> (no rekey)</span>}</td>
              <td>{s.auth_method}</td>
              <td>{s.traffic_segments.map((t: Loose) => TRAFFIC_LABELS[t.class]).join(' → ')}</td>
              <td><button className="btn btn-sm btn-primary" disabled={busy !== null} onClick={() => analyze(s.name)}>
                {busy === s.name ? '…' : 'Analyse'}</button></td>
            </tr>))}</tbody>
        </table>
      </TableWrap>
    </Card>
  );
}

function Matrix() {
  const [m, setM] = useState<Loose>(null);
  useEffect(() => { api.getMatrix().then(setM).catch(() => {}); }, []);
  if (!m) return <Loading />;
  return (
    <div className="stack">
      <Card title="Dimensions" subtitle="Every combination can be rendered as a capture (backend/testbed) or run live on strongSwan (testbed/strongswan)">
        <KeyValue items={[
          { label: 'IKE', value: m.ike_versions.join(' · ') },
          { label: 'Mode', value: m.modes.join(' · ') },
          { label: 'IP version', value: m.ip_versions.join(' · ') },
          { label: 'PFS', value: m.pfs.join(' · ') },
          { label: 'NAT traversal', value: m.nat_traversal.join(' · ') },
          { label: 'Authentication', value: m.authentication.join(' · ') },
          { label: 'Traffic', value: Object.values(m.traffic).join(' · ') },
          { label: 'Anomalies', value: m.anomalies.join(' · ') },
        ]} />
      </Card>
      <div className="grid-2">
        <Card title="IKE SA suites">
          <TableWrap><table className="data-table">
            <thead><tr><th>Encryption</th><th>Integrity</th><th>PRF</th><th>DH group</th></tr></thead>
            <tbody>{m.ike_suites.map((s: Loose) => (
              <tr key={s.key}><td>{s.encryption}</td><td>{s.integrity}</td><td>{s.prf}</td><td>{s.dh_group}</td></tr>))}</tbody>
          </table></TableWrap>
        </Card>
        <Card title="ESP suites and their wire framing" subtitle="What the length fingerprint keys on">
          <TableWrap><table className="data-table">
            <thead><tr><th>Suite</th><th className="num">IV</th><th className="num">Block</th><th className="num">ICV</th><th>Family</th></tr></thead>
            <tbody>{m.esp_suites.map((s: Loose) => (
              <tr key={s.key}><td>{s.label}</td><td className="num">{s.iv}</td><td className="num">{s.block}</td>
                <td className="num">{s.icv}</td><td>{s.family}</td></tr>))}</tbody>
          </table></TableWrap>
        </Card>
      </div>
    </div>
  );
}

function Dataset() {
  const [info, setInfo] = useState<Loose>(null);
  const [count, setCount] = useState(30);
  const [seed, setSeed] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => api.getDatasetInfo().then(setInfo).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);

  const generate = async () => {
    setBusy(true); setError(null);
    try { await api.generateDataset(count, seed); await load(); } catch (e) { setError((e as Error).message); }
    setBusy(false);
  };

  if (!info) return <Loading />;
  const perClass = info.windows_per_class ?? {};
  return (
    <div className="stack">
      {error && <ErrorBanner message={error} />}
      <div className="grid-2">
        <Card title="Classifier training set" subtitle="Traffic models framed by every ESP suite, extracted with the production feature code">
          <KeyValue items={[
            { label: 'Windows', value: info.windows?.toLocaleString() ?? '—' },
            { label: 'Flows', value: info.flows ?? '—' },
            { label: 'Window length', value: info.window_seconds ? `${info.window_seconds} s` : '—' },
            { label: 'ESP suites covered', value: info.suites?.length ?? '—' },
          ]} />
          <h4 className="subhead">Windows per class</h4>
          <BarList items={TRAFFIC_CLASSES.map((c) => ({ key: c, label: TRAFFIC_LABELS[c], value: perClass[c] ?? 0 }))}
            max={Math.max(1, ...Object.values(perClass).map(Number))} format={(v) => String(v)} />
          {info.exists && <a className="btn btn-sm btn-secondary mt-md" href={api.downloadUrl('training_windows.csv')}>Download training_windows.csv</a>}
        </Card>
        <Card title="Labelled PCAP dataset" subtitle="Random points of the configuration matrix, written as PCAPs with ground truth">
          <div className="form-grid">
            <label>Captures<input type="number" min={1} max={200} value={count} onChange={(e) => setCount(Number(e.target.value))} /></label>
            <label>Seed<input type="number" min={0} value={seed} onChange={(e) => setSeed(Number(e.target.value))} /></label>
            <button className="btn btn-primary" disabled={busy} onClick={generate}>{busy ? 'Generating…' : 'Generate dataset'}</button>
          </div>
          {info.testbed ? (
            <>
              <KeyValue items={[
                { label: 'Captures', value: info.testbed.captures },
                { label: 'Labelled windows', value: info.testbed.windows },
                { label: 'Seed', value: info.testbed.seed },
                { label: 'Location', value: <span className="mono text-xs">{info.testbed.directory}</span> },
              ]} />
              <div className="button-row mt-md">
                <a className="btn btn-sm btn-secondary" href={api.downloadUrl('testbed_manifest.jsonl')}>manifest.jsonl</a>
                <a className="btn btn-sm btn-secondary" href={api.downloadUrl('testbed_windows.csv')}>windows.csv</a>
              </div>
            </>
          ) : <p className="muted mt-md">Not generated yet. CLI: <span className="mono">python -m backend.testbed.build_dataset --count 50</span></p>}
        </Card>
      </div>
    </div>
  );
}

function Model() {
  const [model, setModel] = useState<Loose>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => { api.getModelInfo().then(setModel).catch((e) => setError(e.message)); }, []);
  useEffect(load, [load]);
  usePolling(load, 3000, Boolean(model?.training_in_progress));

  const retrain = async () => {
    setError(null);
    setModel({ ...model, training_in_progress: true });
    try { await api.trainModel(); } catch (e) { setError((e as Error).message); }
    load();
  };

  if (!model) return <Loading />;
  const m = model.metrics ?? {};
  const report = m.classification_report ?? {};
  return (
    <div className="stack">
      {error && <ErrorBanner message={error} />}
      <div className="kpi-row">
        <StatTile label="Accuracy" value={pct(m.accuracy, 1)} sub="Held-out flows (never seen in training)" />
        <StatTile label="Macro F1" value={pct(m.f1_macro, 1)} sub="Equal weight per class" />
        <StatTile label="Group CV" value={pct(m.cv_mean_accuracy, 1)} sub={`± ${pct(m.cv_std_accuracy, 1)}`} />
        <StatTile label="Stress set (heavy impairment)" value={pct(m.stress_accuracy, 1)}
          sub={`${m.stress_windows ?? '—'} unseen windows · macro-F1 ${pct(m.stress_f1_macro, 1)}`} />
        <StatTile label="ROC-AUC (macro OvR)" value={m.roc_auc_ovr?.toFixed(3) ?? '—'}
          sub={`stress set ${m.stress_roc_auc_ovr?.toFixed(3) ?? '—'}`} />
        <StatTile label="Novelty: unseen application" value={pct(m.novelty?.mean_unseen_detection, 0)}
          sub={`flagged, leave-one-class-out · ${pct(m.novelty?.false_alarm_rate, 1)} false alarms`} />
        <StatTile label="Calibration error (ECE)" value={pct(m.calibration?.ece_after, 1)}
          sub={`was ${pct(m.calibration?.ece_before, 1)} before calibration`} />
        <StatTile label="Training time" value={m.training_seconds ? `${m.training_seconds} s` : '—'} sub={model.trained_at ?? ''} />
      </div>
      <div className="grid-2">
        <Card title="Confusion matrix" subtitle="Held-out windows; darker = larger share of the true class"
          actions={<button className="btn btn-sm btn-secondary" disabled={model.training_in_progress} onClick={retrain}>
            {model.training_in_progress ? 'Training…' : 'Retrain'}</button>}>
          {m.confusion_matrix ? <ConfusionHeatmap labels={m.classes} matrix={m.confusion_matrix} /> : <p className="muted">Not trained yet.</p>}
        </Card>
        <Card title="Per-class quality">
          <TableWrap><table className="data-table">
            <thead><tr><th>Class</th><th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th><th className="num">Windows</th></tr></thead>
            <tbody>{TRAFFIC_CLASSES.filter((c) => report[c]).map((c) => (
              <tr key={c}><td className="text-primary">{TRAFFIC_LABELS[c]}</td><td className="num">{pct(report[c].precision, 1)}</td>
                <td className="num">{pct(report[c].recall, 1)}</td><td className="num">{pct(report[c]['f1-score'], 1)}</td>
                <td className="num">{report[c].support}</td></tr>))}</tbody>
          </table></TableWrap>
          <p className="hint">Accuracy is measured on data from the same testbed generator; validate on real strongSwan captures before quoting it for production traffic.</p>
        </Card>
      </div>
      <Card title="Features" subtitle={`${model.n_features} direction-agnostic size and timing statistics per 10 s window`}>
        <div className="chips">{model.feature_names.map((f: string) => <span className="chip chip-muted" key={f}>{titleCase(f)}</span>)}</div>
      </Card>
    </div>
  );
}

function Evaluation() {
  const [result, setResult] = useState<Loose>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scenarios, setScenarios] = useState(24);
  useEffect(() => { api.latestEvaluation().then(setResult).catch(() => {}); }, []);

  const run = async () => {
    setBusy(true); setError(null);
    try { setResult(await api.runEvaluation(scenarios, 2024)); } catch (e) { setError((e as Error).message); }
    setBusy(false);
  };

  const available = result && result.fields;
  return (
    <div className="stack">
      {error && <ErrorBanner message={error} />}
      <Card title="End-to-end identification accuracy"
        subtitle="Unseen matrix scenarios → PCAP → full pipeline → compared field-by-field with the configuration that produced them"
        actions={<div className="form-inline">
          <label>Scenarios <input type="number" min={4} max={60} value={scenarios} onChange={(e) => setScenarios(Number(e.target.value))} /></label>
          <button className="btn btn-primary btn-sm" disabled={busy} onClick={run}>{busy ? 'Running… (≈1 min)' : 'Run evaluation'}</button>
        </div>}>
        {!available ? <p className="muted">No evaluation yet. Run one, or use <span className="mono">python -m backend.ml.evaluation</span>.</p> : (
          <>
            <div className="kpi-row">
              <StatTile label="Decided fields correct" value={pct(result.overall_accuracy, 1)} sub={`${result.scenarios_evaluated} captures`} />
              <StatTile label="Single-application windows" value={pct(result.traffic_pure_window_accuracy, 1)}
                sub={`${result.pure_windows ?? '—'} windows ≥ 80% inside one application`} />
              <StatTile label="All traffic windows" value={pct(result.traffic_window_accuracy, 1)}
                sub={`${result.traffic_windows} windows · unsmoothed ${pct(result.traffic_window_accuracy_unsmoothed, 1)}`} />
              <StatTile label="Network impairment" value={result.impairment ?? 'none'} sub="jitter · loss · multiplexed flows" />
              <StatTile label="Run time" value={`${result.seconds} s`} sub={result.evaluated_at} />
            </div>
            <BarList items={[...result.fields].sort((a: Loose, b: Loose) => a.field.localeCompare(b.field)).map((f: Loose) => ({
              key: f.field, label: f.field, value: f.accuracy,
              display: f.accuracy === null ? 'abstained' : `${pct(f.accuracy, 1)} · coverage ${pct(f.coverage)}`,
              note: <span className="muted text-xs">{f.correct} correct · {f.wrong} wrong · {f.abstained} not observable</span>,
            }))} />
            <p className="hint">{result.note}</p>
          </>
        )}
      </Card>
      {available && (
        <Card title="Per-scenario results">
          <TableWrap><table className="data-table">
            <thead><tr><th>Scenario</th><th>Configuration</th><th>Traffic</th><th className="num">Accuracy</th><th>Misses</th></tr></thead>
            <tbody>{result.scenarios.map((s: Loose) => (
              <tr key={s.name}>
                <td>{s.name}</td>
                <td className="text-xs">IKEv{s.config.ike_version}{s.config.aggressive ? ' aggr' : ''} · {s.config.ike_suite} · {s.config.esp_suite} ·
                  {' '}{s.config.mode} · IPv{s.config.ip_version}{s.config.nat_t ? ' · NAT-T' : ''} · {s.config.auth} · PFS {s.config.pfs ? 'on' : 'off'}</td>
                <td className="text-xs">{s.traffic.join(', ')}</td>
                <td className="num">{pct(s.accuracy)}</td>
                <td className="text-xs">{s.wrong.length ? <StatusPill status="serious" label={s.wrong.join(', ')} /> : <span className="muted">none</span>}</td>
              </tr>))}</tbody>
          </table></TableWrap>
        </Card>
      )}
    </div>
  );
}

function Benchmark() {
  const [result, setResult] = useState<Loose>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [count, setCount] = useState(40);
  useEffect(() => { api.benchmarkLatest().then(setResult).catch(() => {}); }, []);

  const run = async () => {
    setBusy(true); setError(null);
    try { setResult(await api.runBenchmark(count, 99)); } catch (e) { setError((e as Error).message); }
    setBusy(false);
  };

  return (
    <div className="stack">
      {error && <ErrorBanner message={error} />}
      <Card title="Does SecurIQ catch misconfigurations it has never seen?"
        subtitle="Random configurations with 0–3 injected weaknesses (weak DH, 3DES, ESP-NULL, MD5, PFS off, long lifetime, Aggressive-mode PSK, IKEv1, replay, counter reset, weak proposals, Vendor ID). Ground truth is the configuration; detection is what the pipeline finds in the PCAP."
        actions={<div className="form-inline">
          <label>Captures <input type="number" min={8} max={120} value={count} onChange={(e) => setCount(Number(e.target.value))} /></label>
          <button className="btn btn-primary btn-sm" disabled={busy} onClick={run}>{busy ? 'Running… (≈1–2 min)' : 'Run benchmark'}</button>
        </div>}>
        {!result?.available ? <p className="muted">No benchmark yet. Run one, or <span className="mono">python -m backend.ml.benchmark --count 40</span>.</p> : (
          <>
            <div className="kpi-row">
              <StatTile label="Detection rate (recall)" value={pct(result.detection_rate, 1)} sub={`${result.detected} of ${result.injected_total} injected weaknesses`} />
              <StatTile label="Precision" value={pct(result.precision, 1)} sub={`${result.false_positives} false detections`} />
              <StatTile label="Clean-capture false alarms" value={pct(result.clean_false_alarm_rate, 1)} sub={`${result.clean_captures} clean captures`} />
              <StatTile label="Captures" value={result.captures} sub={`seed ${result.seed} · ${result.seconds} s`} />
            </div>
            <TableWrap>
              <table className="data-table">
                <thead><tr><th>Misconfiguration</th><th className="num">TP</th><th className="num">FN</th><th className="num">FP</th>
                  <th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th></tr></thead>
                <tbody>{result.per_type.map((t: Loose) => (
                  <tr key={t.type}>
                    <td className="text-primary">{t.label}</td>
                    <td className="num">{t.tp}</td><td className="num">{t.fn}</td><td className="num">{t.fp}</td>
                    <td className="num">{pct(t.precision, 0)}</td><td className="num">{pct(t.recall, 0)}</td><td className="num">{pct(t.f1, 0)}</td>
                  </tr>))}</tbody>
              </table>
            </TableWrap>
            <p className="hint">{result.note}</p>
          </>
        )}
      </Card>
      {result?.available && (
        <Card title="Per-capture results">
          <TableWrap>
            <table className="data-table">
              <thead><tr><th>Capture</th><th>Injected</th><th>Detected</th><th>Missed</th><th>False alarms</th><th className="num">Score</th></tr></thead>
              <tbody>{result.cases.map((c: Loose) => (
                <tr key={c.name}>
                  <td className="mono text-xs">{c.name}</td>
                  <td className="text-xs">{c.expected.join(', ') || <span className="muted">clean</span>}</td>
                  <td className="text-xs">{c.detected.join(', ') || '—'}</td>
                  <td className="text-xs">{c.missed.length ? <StatusPill status="serious" label={c.missed.join(', ')} /> : <span className="muted">none</span>}</td>
                  <td className="text-xs">{c.false_alarms.length ? <StatusPill status="warning" label={c.false_alarms.join(', ')} /> : <span className="muted">none</span>}</td>
                  <td className="num">{c.score ?? '—'}</td>
                </tr>))}</tbody>
            </table>
          </TableWrap>
        </Card>
      )}
    </div>
  );
}
