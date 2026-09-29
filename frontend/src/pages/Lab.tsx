import { Fragment, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Page } from '../components/Layout';
import { Card, ErrorBanner, Loading, StatTile, StatusPill } from '../components/ui';
import { rememberAnalysis } from '../hooks/useAnalysis';
import { TRAFFIC_CLASSES, TRAFFIC_LABELS, classColor, pct, score, scoreStatus, timeAgo } from '../lib/format';
import { api } from '../services/api';
import type { Loose } from '../types';

const STEPS = ['Generate configuration', 'Deploy VPN twin', 'Generate traffic', 'Capture packets', 'Analyse', 'Score'];

const PRESETS: { key: string; label: string; note: string; config: Loose; traffic: [string, number][] }[] = [
  { key: 'legacy', label: 'Legacy weak VPN', note: 'AES-128-CBC · HMAC-SHA1 · DH group 2 · PFS off · 24 h',
    config: { ike_version: 'IKEv2', ike_encryption: 'AES-128-CBC', ike_integrity: 'HMAC-SHA1-96', dh_group: 2, auth: 'psk',
      esp_suite: 'aes128-sha1', pfs: false, weak_proposals: true, vendor_id: true, ike_lifetime: 86400, child_lifetime: 28800 },
    traffic: [['voip', 25], ['web', 25], ['video', 20]] },
  { key: 'hardened', label: 'Hardened (golden)', note: 'AES-256-GCM · ECP-384 · PFS · certificates',
    config: { ike_version: 'IKEv2', ike_encryption: 'AES-256-GCM-16', ike_integrity: 'None (AEAD)', dh_group: 20, auth: 'rsa',
      esp_suite: 'aes256gcm16', pfs: true, weak_proposals: false, vendor_id: false, ike_lifetime: 14400, child_lifetime: 3600 },
    traffic: [['voip', 25], ['web', 25], ['video', 20]] },
  { key: 'aggressive', label: 'Aggressive-mode PSK', note: 'IKEv1 Aggressive · identity in cleartext · crackable PSK',
    config: { ike_version: 'IKEv1', exchange_mode: 'Aggressive Mode', ike_encryption: 'AES-128-CBC', ike_integrity: 'HMAC-SHA1-96',
      dh_group: 5, auth: 'psk', esp_suite: 'aes128-sha1', pfs: false, ike_lifetime: 86400 },
    traffic: [['chat', 25], ['email', 25]] },
  { key: 'null', label: 'ESP-NULL misconfiguration', note: 'Integrity only — payload readable on the wire',
    config: { esp_suite: 'null-sha256', pfs: false }, traffic: [['web', 25], ['icmp', 15]] },
  { key: 'replay', label: 'Replay attack', note: 'Duplicated ESP packets and a counter reset',
    config: { ike_encryption: 'AES-128-CBC', ike_integrity: 'HMAC-SHA2-256-128', dh_group: 19, esp_suite: 'aes128-sha256', anti_replay: false },
    traffic: [['file_transfer', 20], ['icmp', 15]] },
];

const optValue = (o: Loose) => (typeof o === 'object' && o !== null ? o.value : o);
const optLabel = (o: Loose) => (typeof o === 'object' && o !== null ? o.label : o === true ? 'On' : o === false ? 'Off' : String(o));

export default function Lab() {
  const [knobs, setKnobs] = useState<Loose[] | null>(null);
  const [defaults, setDefaults] = useState<Loose>(null);
  const [builds, setBuilds] = useState<Loose[]>([]);
  const [config, setConfig] = useState<Loose>({});
  const [traffic, setTraffic] = useState<[string, number][]>([['voip', 25], ['web', 25]]);
  const [impairment, setImpairment] = useState('none');
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(-1);
  const [result, setResult] = useState<Loose>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () => api.labBuilds().then((d) => { setBuilds(d.builds); setDefaults(d.defaults); setConfig((c: Loose) => (Object.keys(c).length ? c : d.defaults)); });
  useEffect(() => {
    api.simulatorOptions().then((d) => setKnobs(d.knobs)).catch((e) => setError(e.message));
    load().catch((e) => setError(e.message));
  }, []);

  const groups = useMemo(() => {
    const out: Record<string, Loose[]> = {};
    for (const k of knobs ?? []) (out[k.group] ??= []).push(k);
    return out;
  }, [knobs]);

  if (!knobs || !defaults) return <Page title="VPN lab">{error ? <ErrorBanner message={error} /> : <Loading />}</Page>;

  const applyPreset = (p: (typeof PRESETS)[number]) => {
    setConfig({ ...defaults, ...p.config }); setTraffic(p.traffic); setLabel(p.label); setResult(null);
  };
  const setKnob = (k: Loose, raw: string) => {
    const option = k.options.find((o: Loose) => String(optValue(o)) === raw);
    setConfig({ ...config, [k.key]: option !== undefined ? optValue(option) : raw });
  };

  const build = async () => {
    setBusy(true); setError(null); setResult(null); setStep(0);
    const tick = window.setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 650);
    try {
      const r = await api.labBuild({ config, traffic: traffic.map(([c, s]) => ({ class: c, seconds: s })), label, impairment });
      setResult(r);
      rememberAnalysis(r.analysis_id);
      load();
    } catch (e) { setError((e as Error).message); }
    window.clearInterval(tick);
    setStep(STEPS.length);
    setBusy(false);
  };

  const total = traffic.reduce((s, [, sec]) => s + sec, 0);
  return (
    <Page title="VPN lab" subtitle="A digital twin of an IPsec deployment: choose the configuration and the applications, and SecurIQ generates the negotiation and the encrypted traffic, captures it, and analyses the PCAP as if it came off a real link.">
      {error && <ErrorBanner message={error} />}
      <div className="preset-row">
        {PRESETS.map((p) => (
          <button key={p.key} className={`preset ${label === p.label ? 'active' : ''}`} onClick={() => applyPreset(p)}>
            <strong>{p.label}</strong><span>{p.note}</span>
          </button>
        ))}
      </div>

      <div className="grid-side">
        <Card title="Configuration" subtitle="The same settings a strongSwan profile would carry">
          <div className="lab-form">
            {Object.entries(groups).map(([group, ks]) => (
              <Fragment key={group}>
                <div className="lab-group">{group}</div>
                {ks.filter((k) => k.key !== 'exchange_mode' || config.ike_version === 'IKEv1').map((k) => (
                  <label key={k.key} className="field">{k.label}
                    <select value={String(config[k.key] ?? '')} onChange={(e) => setKnob(k, e.target.value)}>
                      {k.options.map((o: Loose) => <option key={String(optValue(o))} value={String(optValue(o))}>{optLabel(o)}</option>)}
                    </select>
                  </label>
                ))}
              </Fragment>
            ))}
            <div className="lab-group">Network</div>
            <label className="field">IP version
              <select value={config.ip_version ?? 4} onChange={(e) => setConfig({ ...config, ip_version: Number(e.target.value) })}>
                <option value={4}>IPv4</option><option value={6}>IPv6</option></select></label>
            <label className="field">NAT traversal
              <select value={String(Boolean(config.nat_t))} onChange={(e) => setConfig({ ...config, nat_t: e.target.value === 'true' })}>
                <option value="false">Off</option><option value="true">On (UDP 4500)</option></select></label>
            <label className="field">Network impairment
              <select value={impairment} onChange={(e) => setImpairment(e.target.value)}>
                {['none', 'light', 'moderate', 'heavy'].map((i) => <option key={i} value={i}>{i}</option>)}</select></label>
            <label className="field">Label
              <input type="text" value={label} maxLength={80} placeholder="Lab build" onChange={(e) => setLabel(e.target.value)} /></label>
          </div>
        </Card>

        <div className="stack">
          <Card title="Traffic inside the tunnel" subtitle={`${traffic.length} application segment(s) · ${total} s`}>
            <div className="traffic-builder">
              {traffic.map(([cls, sec], i) => (
                <div key={i} className="tb-row">
                  <span className="swatch" style={{ background: classColor(cls) }} />
                  <select aria-label={`Application ${i + 1}`} value={cls} onChange={(e) => setTraffic(traffic.map((t, j) => (j === i ? [e.target.value, t[1]] : t)))}>
                    {TRAFFIC_CLASSES.map((c) => <option key={c} value={c}>{TRAFFIC_LABELS[c]}</option>)}
                  </select>
                  <input type="number" aria-label={`Seconds for application ${i + 1}`} min={10} max={60} value={sec}
                    onChange={(e) => setTraffic(traffic.map((t, j) => (j === i ? [t[0], Number(e.target.value)] : t)))} />
                  <span className="muted text-xs">s</span>
                  <button className="btn btn-sm btn-ghost" aria-label="Remove" disabled={traffic.length === 1}
                    onClick={() => setTraffic(traffic.filter((_, j) => j !== i))}>✕</button>
                </div>
              ))}
              <button className="btn btn-sm btn-secondary" disabled={traffic.length >= 5}
                onClick={() => setTraffic([...traffic, ['chat', 20]])}>Add application</button>
              <div className="tb-strip" aria-hidden>
                {traffic.map(([c, s], i) => <span key={i} style={{ flexGrow: s, background: classColor(c) }} />)}
              </div>
            </div>
          </Card>
          <Card title="Run" className="accent"
            actions={<button className="btn btn-primary" onClick={build} disabled={busy}>{busy ? 'Building…' : 'Generate & analyse'}</button>}>
            <ol className="steps vertical">
              {STEPS.map((s, i) => (
                <li key={s} className={step > i || step === STEPS.length ? 'done' : step === i && busy ? 'active' : ''}>
                  <span className="step-n">{String(i + 1).padStart(2, '0')}</span>{s}
                </li>
              ))}
            </ol>
            <p className="hint">The twin is the testbed generator (byte-accurate cleartext IKE, RFC-sized encrypted messages, ESP framing per suite). The same configuration runs on real gateways with the strongSwan profile below.</p>
          </Card>
        </div>
      </div>

      {result && (
        <Card title="Result" className="mt-md accent" subtitle={`${result.packets?.toLocaleString()} packets captured · ${result.file_id}`}>
          <div className="kpi-row">
            <StatTile label="Security score" value={score(result.score)} status={scoreStatus(result.score)} sub={result.risk_level} />
            <StatTile label="Identification vs configuration" value={pct(result.identification_accuracy)} sub="Decided fields correct (ground truth)" />
          </div>
          <div className="grid-2">
            <div className="button-row">
              <Link className="btn btn-primary" to={`/security?id=${result.analysis_id}`}>Security assessment</Link>
              <Link className="btn btn-secondary" to={`/analysis?id=${result.analysis_id}&tab=truth`}>What the AI identified</Link>
              <Link className="btn btn-secondary" to={`/simulator?id=${result.analysis_id}&fix=1`}>Fix it in the simulator</Link>
            </div>
            <div>
              <span className="tile-label">strongSwan profile (backend/testbed/strongswan/profiles)</span>
              <pre className="code">{result.strongswan_profile}</pre>
            </div>
          </div>
        </Card>
      )}

      {builds.length > 0 && (
        <Card title="Previous lab builds" className="mt-md">
          <ul className="file-list">
            {builds.slice(0, 12).map((b) => (
              <li key={b.id}>
                <span className="mono">{b.label}</span>
                <span className="muted text-xs">{b.config?.ike_version} · {b.config?.ike_encryption} · DH {b.config?.dh_group} · PFS {b.config?.pfs ? 'on' : 'off'}</span>
                {b.derived_from && <StatusPill status="none" label="verification" />}
                <span className="muted text-xs">{timeAgo(b.created)}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </Page>
  );
}
