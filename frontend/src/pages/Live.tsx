import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ShareBar, ThroughputChart, TrafficTimeline } from '../components/charts';
import { Page } from '../components/Layout';
import { Card, ErrorBanner, KeyValue, SeverityBadge, SourceBadge, StatTile, StatusPill, TableWrap } from '../components/ui';
import { useLiveSession } from '../hooks/useLiveSession';
import { displayValue, pct, score, scoreStatus, timeAgo, type Status } from '../lib/format';
import { api } from '../services/api';
import type { Loose, TrafficSummary } from '../types';

const FIELD_LABELS: Record<string, string> = {
  ipsec_protocols: 'IPsec protocol', ike_version: 'IKE version', exchange_mode: 'Exchange mode',
  mode: 'Tunnel / transport', ike_encryption: 'IKE SA encryption', key_exchange: 'Key exchange',
  esp_encryption: 'ESP encryption', esp_integrity: 'ESP integrity', authentication_method: 'Authentication',
  pfs: 'Perfect Forward Secrecy', nat_traversal: 'NAT traversal', ip_version: 'IP version',
  replay_protection: 'Replay protection', traffic_types: 'Traffic inside the tunnel',
};

const STATUS_PILL: Record<string, Status> = {
  running: 'good', finalizing: 'warning', finished: 'none', stopped: 'none', error: 'critical', connecting: 'none',
};

export default function Live() {
  const [params] = useSearchParams();
  const sessionId = params.get('session');
  return (
    <Page title="Live monitor" subtitle="Streaming analysis: events, traffic classes and alerts as packets arrive">
      {sessionId ? <SessionView id={sessionId} /> : <StartPanel />}
    </Page>
  );
}

function StartPanel() {
  const navigate = useNavigate();
  const [caps, setCaps] = useState<Loose>(null);
  const [captures, setCaptures] = useState<{ id: string; label: string }[]>([]);
  const [sessions, setSessions] = useState<Loose[]>([]);
  const [mode, setMode] = useState<'replay' | 'interface'>('replay');
  const [fileId, setFileId] = useState('');
  const [speed, setSpeed] = useState(10);
  const [iface, setIface] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.liveCapabilities().then((c) => { setCaps(c); setIface(c.interfaces?.[0] ?? ''); }).catch((e) => setError(e.message));
    api.liveSessions().then((d) => setSessions(d.sessions)).catch(() => {});
    api.listUploads().then((d) => {
      const list = [
        ...d.samples.map((s: Loose) => ({ id: s.id, label: `Scenario · ${s.id.replace(/_/g, ' ')}` })),
        ...d.uploads.map((u: Loose) => ({ id: u.id, label: `Upload · ${u.original_name}` })),
      ];
      setCaptures(list);
      setFileId(list.find((c) => c.id === 'mixed_all_traffic_ikev2')?.id ?? list[0]?.id ?? '');
    }).catch(() => {});
  }, []);

  const start = async () => {
    setBusy(true); setError(null);
    try {
      const session = await api.liveStart(mode === 'replay' ? { source: 'replay', file_id: fileId, speed }
        : { source: 'interface', interface: iface });
      navigate(`/live?session=${session.id}`);
    } catch (e) { setError((e as Error).message); setBusy(false); }
  };

  return (
    <div className="stack">
      {error && <ErrorBanner message={error} />}
      <div className="grid-2">
        <Card title="Start a live session" subtitle="Every packet is decoded as it arrives; windows are classified the moment they close">
          <div className="segmented" role="radiogroup" aria-label="Source">
            <button role="radio" aria-checked={mode === 'replay'} className={mode === 'replay' ? 'active' : ''} onClick={() => setMode('replay')}>Replay a capture</button>
            <button role="radio" aria-checked={mode === 'interface'} className={mode === 'interface' ? 'active' : ''} onClick={() => setMode('interface')}>Network interface</button>
          </div>
          {mode === 'replay' ? (
            <div className="form-grid mt-md">
              <label>Capture
                <select value={fileId} onChange={(e) => setFileId(e.target.value)}>
                  {captures.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
                </select>
              </label>
              <label>Speed
                <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
                  {[1, 5, 10, 25, 50].map((s) => <option key={s} value={s}>{s}× real time</option>)}
                  <option value={0}>As fast as possible (benchmark)</option>
                </select>
              </label>
              <p className="hint">Replays the capture paced by its own timestamps — the same engine that watches a live interface.</p>
            </div>
          ) : caps?.live_capture ? (
            <div className="form-grid mt-md">
              <label>Interface
                <select value={iface} onChange={(e) => setIface(e.target.value)}>
                  {caps.interfaces.map((i: string) => <option key={i} value={i}>{i}</option>)}
                </select>
              </label>
              <div className="muted text-xs">Backend: {caps.tools.join(', ') || 'Scapy'} · filter <span className="mono">{caps.default_filter}</span></div>
              <p className="hint">The session is recorded; when you stop it the recording is analysed in full and saved.</p>
            </div>
          ) : (
            <p className="muted mt-md">{caps?.note ?? 'Checking capture backends…'}</p>
          )}
          <button className="btn btn-primary mt-md" disabled={busy || (mode === 'replay' ? !fileId : !caps?.live_capture || !iface)} onClick={start}>
            {busy ? 'Starting…' : 'Start'}</button>
        </Card>
        <Card title="Recent sessions">
          {sessions.length === 0 ? <p className="muted">No sessions yet.</p> : (
            <ul className="file-list">{sessions.map((s) => (
              <li key={s.id}>
                <span className="mono">{s.label}</span>
                <StatusPill status={STATUS_PILL[s.status] ?? 'none'} label={s.status} />
                <span className="muted text-xs">{timeAgo(s.created)}</span>
                <Link className="btn btn-sm btn-secondary" to={`/live?session=${s.id}`}>Open</Link>
              </li>))}</ul>
          )}
        </Card>
      </div>
    </div>
  );
}

function SessionView({ id }: { id: string }) {
  const live = useLiveSession(id);
  const [stopping, setStopping] = useState(false);
  const snap = live.snapshot;
  const running = live.status === 'running' || live.status === 'connecting';

  const throughput = live.rate.map((p) => ({ t: p.t, y: (p.bytes * 8) / 1e6 }));
  const latest = live.rate.length ? live.rate[live.rate.length - 1] : null;
  const flows = useMemo<TrafficSummary['flows']>(() => {
    const byFlow = new Map<string, Loose[]>();
    for (const w of live.windows) byFlow.set(w.flow_id, [...(byFlow.get(w.flow_id) ?? []), w]);
    return [...byFlow.entries()].map(([flowId, ws]) => ({
      flow_id: flowId, dominant_class: '', dominant_label: '', mix: {}, windows: ws.length, mean_confidence: 0,
      timeline: ws.sort((a, b) => a.window_start - b.window_start).slice(-40).map((w) => ({
        start: w.window_start, end: w.window_end, class: w.predicted_class, confidence: w.confidence, uncertain: w.uncertain })),
    }));
  }, [live.windows]);
  const t0 = snap ? snap.capture_time - snap.capture_elapsed : 0;

  const stop = async () => { setStopping(true); try { await api.liveStop(id); } catch { /* already finished */ } };

  return (
    <div className="stack">
      <div className="live-bar">
        <StatusPill status={STATUS_PILL[live.status] ?? 'none'} label={live.status === 'running' ? 'Live' : live.status} />
        {running && <span className="live-dot" aria-hidden />}
        <span className="muted text-sm">{live.source}</span>
        <span className="spacer" />
        {!live.connected && running && <span className="muted text-xs">reconnecting…</span>}
        {live.analysisId && <Link className="btn btn-sm btn-primary" to={`/security?id=${live.analysisId}`}>Open full report</Link>}
        {running && <button className="btn btn-sm btn-danger" disabled={stopping} onClick={stop}>{stopping ? 'Stopping…' : 'Stop'}</button>}
        <Link className="btn btn-sm btn-secondary" to="/live">New session</Link>
      </div>
      {live.error && <ErrorBanner message={live.error} />}
      {live.status === 'finalizing' && <div className="alert alert-warning">Stream ended — running the full batch analysis and saving the report…</div>}

      <div className="kpi-row">
        <StatTile label="Packets" value={live.totals.packets.toLocaleString()} sub={snap ? `${snap.capture_elapsed} s of capture` : '—'} />
        <StatTile label="Throughput" value={latest ? `${((latest.bytes * 8) / 1e6).toFixed(2)}` : '—'} sub={latest ? `Mbit/s · ${latest.packets} pkt/s` : 'Mbit/s'} />
        <StatTile label="IKE messages / SAs" value={`${live.totals.ike} / ${live.totals.sas}`} sub="Negotiations and new SPIs seen" />
        <StatTile label="Security score" value={score(snap?.security?.overall_score)} status={scoreStatus(snap?.security?.overall_score)}
          sub={snap ? `${snap.security.risk_level} · re-assessed every 3 s` : 'Waiting for first assessment'} />
        <StatTile label="AI confidence" value={pct(snap?.ai_confidence?.overall)} sub={`${live.windows.length} windows classified`} />
      </div>

      <div className="grid-hero">
        <Card title="Alerts" subtitle="Raised the moment a weakness becomes evident in the stream">
          {live.alerts.length === 0 ? <p className="muted">No alerts yet.</p> : (
            <ul className="alert-feed">{live.alerts.map((a) => (
              <li key={a.seq}>
                <SeverityBadge severity={a.data.severity} />
                <div><div className="text-primary">{a.data.title}</div>
                  <div className="muted text-xs">{a.data.id} · at {t0 ? `${Math.max(0, a.t - t0).toFixed(1)} s` : '—'} · {a.data.recommendation}</div></div>
              </li>))}</ul>
          )}
        </Card>
        <Card title="Throughput" subtitle="All IPsec traffic, last 2 minutes of capture time">
          <ThroughputChart points={throughput} value={(v) => (v === 0 ? '0' : v >= 10 ? v.toFixed(0) : v.toFixed(2))} />
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Live identification" subtitle="Updates as evidence accumulates">
          {!snap ? <p className="muted">Waiting for first assessment…</p> : (
            <TableWrap><table className="data-table">
              <tbody>{Object.keys(FIELD_LABELS).filter((k) => snap.profile[k]).map((k) => {
                const e = snap.profile[k];
                return (
                  <tr key={k}><td>{FIELD_LABELS[k]}</td>
                    <td className={`text-primary ${e.source === 'not_observable' ? 'muted' : ''}`}>{displayValue(e.value, e.display)}</td>
                    <td><SourceBadge source={e.source} confidence={e.confidence} /></td></tr>
                );
              })}</tbody>
            </table></TableWrap>
          )}
        </Card>
        <Card title="Traffic inside the tunnel" subtitle="Each 10-second window is classified as soon as it closes (causal HMM smoothing)">
          {live.windows.length === 0 ? <p className="muted">First window closes 10 s into the traffic…</p> : (
            <>
              {snap?.traffic?.mix && Object.keys(snap.traffic.mix).length > 0 && <ShareBar mix={snap.traffic.mix} />}
              <div className="mt-md"><TrafficTimeline flows={flows} /></div>
            </>
          )}
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Protocol events" subtitle="IKE exchanges and new Security Associations">
          <ol className="event-list">{live.log.slice(0, 30).map((e) => (
            <li key={e.seq}>
              <span className="event-time">{t0 ? `${Math.max(0, e.t - t0).toFixed(2)} s` : ''}</span>
              <span className={`chip chip-${e.type === 'ike' ? 'ike' : 'esp'}`}>{e.type === 'ike' ? 'IKE' : e.data.protocol}</span>
              <span>{e.type === 'ike'
                ? `${e.data.exchange}${e.data.response ? ' response' : ' request'}${e.data.encrypted ? ` · encrypted ${e.data.length} B` : ''}`
                : `New SA ${e.data.spi}${e.data.nat_t ? ' (UDP 4500)' : ''}`}</span>
              <span className="muted mono text-xs">{e.data.src} → {e.data.dst}</span>
            </li>))}</ol>
        </Card>
        <Card title="Engine performance">
          <KeyValue items={[
            { label: 'Full re-assessment time', value: snap?.metrics?.analysis_ms ? `${snap.metrics.analysis_ms} ms` : '—' },
            { label: 'Window → verdict delay (live)', value: snap?.metrics?.max_lag_s ? `${snap.metrics.max_lag_s} s` : 'n/a for accelerated replay' },
            { label: 'Threats now', value: snap?.threats?.length ? snap.threats.map((t: Loose) => `${t.name} (${t.risk_score})`).join(' · ') : '—' },
            { label: 'Stream', value: live.connected ? 'Connected (Server-Sent Events)' : running ? 'Reconnecting' : 'Closed' },
          ]} />
        </Card>
      </div>
    </div>
  );
}
