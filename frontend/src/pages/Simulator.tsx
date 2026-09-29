import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { FingerprintBadge, ScoreShift } from '../components/ipsec';
import { Page } from '../components/Layout';
import { Card, ErrorBanner, Loading, NoAnalysis, StatusPill, TableWrap } from '../components/ui';
import { rememberAnalysis, useAnalysisId } from '../hooks/useAnalysis';
import { ratingStatus, score } from '../lib/format';
import { api } from '../services/api';
import type { Loose } from '../types';

type Changes = Record<string, unknown>;
const STATUS_VAR: Record<string, string> = { good: 'var(--status-good)', warning: 'var(--status-warning)',
  serious: 'var(--status-serious)', critical: 'var(--status-critical)', none: 'var(--viz-muted)' };
const VERIFY_STEPS = ['Generate config', 'Deploy twin', 'Generate traffic', 'Capture packets', 'Analyse', 'Score'];

const optValue = (o: Loose) => (typeof o === 'object' && o !== null ? o.value : o);
const optLabel = (o: Loose) => (typeof o === 'object' && o !== null ? o.label : o === true ? 'On' : o === false ? 'Off' : String(o));
const fmt = (knob: Loose, value: unknown) => {
  if (value === null || value === undefined) return <span className="muted">not observable</span>;
  const match = (knob?.options ?? []).find((o: Loose) => optValue(o) === value);
  if (match) return optLabel(match);
  if (value === true) return 'On';
  if (value === false) return 'Off';
  if (typeof value === 'number' && knob?.key?.includes('lifetime')) return `${value / 3600} h`;
  return String(value);
};

export default function Simulator() {
  const id = useAnalysisId();
  const [params] = useSearchParams();
  const [base, setBase] = useState<Loose>(null);
  const [changes, setChanges] = useState<Changes>({});
  const [result, setResult] = useState<Loose>(null);
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [step, setStep] = useState(0);
  const [verified, setVerified] = useState<Loose>(null);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (!id) return;
    api.simulatorBaseline(id).then((b) => {
      setBase(b);
      setChanges(params.get('fix') ? b.recommended : {});
    }).catch((e) => setError(e.message));
  }, [id, params]);

  useEffect(() => {
    if (!id || !base) return;
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      api.simulate(id, changes).then(setResult).catch((e) => setError(e.message));
    }, 200);
    return () => window.clearTimeout(timer.current);
  }, [id, base, changes]);

  const groups = useMemo(() => {
    const out: Record<string, Loose[]> = {};
    for (const k of base?.knobs ?? []) (out[k.group] ??= []).push(k);
    return out;
  }, [base]);

  if (!id) return <Page title="What-if simulator"><NoAnalysis /></Page>;
  if (!base) return <Page title="What-if simulator">{error ? <ErrorBanner message={error} /> : <Loading />}</Page>;

  const set = (key: string, raw: string, knob: Loose) => {
    const next = { ...changes };
    if (raw === '') delete next[key];
    else {
      const option = knob.options.find((o: Loose) => String(optValue(o)) === raw);
      next[key] = option !== undefined ? optValue(option) : raw;
    }
    setChanges(next);
    setVerified(null);
  };

  const verify = async () => {
    setVerifying(true); setVerified(null); setError(null); setStep(0);
    const tick = window.setInterval(() => setStep((s) => Math.min(s + 1, VERIFY_STEPS.length - 1)), 700);
    try {
      const v = await api.verify(id, changes);
      setVerified(v);
      rememberAnalysis(id);
    } catch (e) { setError((e as Error).message); }
    window.clearInterval(tick);
    setStep(VERIFY_STEPS.length);
    setVerifying(false);
  };

  const cur = base.current;
  const changed = Object.keys(changes).length;
  const r = result?.valid ? result : null;

  return (
    <Page title="What-if simulator" subtitle={`${base.filename}: change the configuration and watch each factor move the posture. The same rule engine re-scores the capture; Verify renders the new configuration and measures it.`}
      meta={r && <><FingerprintBadge fp={r.fingerprint_before} /><span className="muted">→</span><FingerprintBadge fp={r.fingerprint_after} /></>}>
      {error && <ErrorBanner message={error} />}
      {result && !result.valid && <div className="alert alert-warning">{result.problems.join(' · ')}</div>}

      <div className="grid-side">
        <Card title="Configuration" subtitle="Current = what the analyzer observed or inferred. Proposed = your change."
          actions={<>
            <button className="btn btn-sm btn-primary" onClick={() => { setChanges(base.recommended); setVerified(null); }}
              disabled={!Object.keys(base.recommended).length}>Apply recommended fixes</button>
            <button className="btn btn-sm btn-secondary" onClick={() => { setChanges({}); setVerified(null); }} disabled={!changed}>Reset</button>
          </>}>
          <TableWrap>
            <table className="data-table sim-table">
              <thead><tr><th>Setting</th><th>Current</th><th>Proposed</th></tr></thead>
              <tbody>
                {Object.entries(groups).map(([group, knobs]) => (
                  <Fragment key={group}>
                    <tr className="group-row"><td colSpan={3}>{group}</td></tr>
                    {knobs.map((k) => {
                      const current = k.key === 'esp_suite' ? cur.esp_observed : cur[k.key];
                      const value = changes[k.key];
                      return (
                        <tr key={k.key}>
                          <td className="text-primary">{k.label}</td>
                          <td>{k.key === 'esp_suite' ? (current ?? <span className="muted">not observable</span>) : fmt(k, current)}</td>
                          <td>
                            <select aria-label={`Proposed ${k.label}`} className={value !== undefined ? 'changed' : ''}
                              value={value === undefined ? '' : String(value)} onChange={(e) => set(k.key, e.target.value, k)}>
                              <option value="">— unchanged —</option>
                              {k.options.map((o: Loose) => <option key={String(optValue(o))} value={String(optValue(o))}>{optLabel(o)}</option>)}
                            </select>
                          </td>
                        </tr>
                      );
                    })}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <p className="hint">ESP key length and IKEv2 lifetimes are not visible on the wire, so their current value shows as observed family or "not observable".</p>
        </Card>

        <div className="stack">
          <Card title="Modelled posture" className="accent">
            {!r ? <Loading label="Scoring…" /> : (
              <>
                <ScoreShift before={r.current.overall_score} after={r.proposed.overall_score}
                  note={<>{r.current.risk_level} → {r.proposed.risk_level}{r.proposed.score_cap ? ` · ${r.proposed.score_cap}` : ''}</>} />
                <div className={`verdict s-${r.delta > 0 ? 'good' : r.delta < 0 ? 'critical' : 'none'}`}>
                  <span aria-hidden>{r.delta > 0 ? '▲' : r.delta < 0 ? '▼' : '•'}</span> {r.verdict}
                  {changed ? ` · ${changed} change${changed > 1 ? 's' : ''}` : ''}
                </div>
                <div className="kv mt-md">
                  <div className="kv-row"><dt>Effective strength</dt><dd>{r.current.strength_bits ?? '—'} → {r.proposed.strength_bits ?? '—'} bits</dd></div>
                  <div className="kv-row"><dt>Golden policy</dt><dd>
                    <StatusPill status={r.policy_before.compliant ? 'good' : 'critical'} label={`${r.policy_before.counts.fail} fail`} /> →{' '}
                    <StatusPill status={r.policy_after.compliant ? 'good' : 'critical'} label={`${r.policy_after.counts.fail} fail`} /></dd></div>
                  <div className="kv-row"><dt>Findings resolved</dt><dd className="mono text-xs">{r.resolved.join(' ') || '—'}</dd></div>
                  <div className="kv-row"><dt>Findings introduced</dt><dd className="mono text-xs">{r.introduced.join(' ') || '—'}</dd></div>
                </div>
              </>
            )}
          </Card>
          {r && (
            <Card title="Category scores" subtitle="Grey tick = current · bar = proposed">
              <div className="dumbbells">
                {Object.entries(r.proposed.categories as Record<string, Loose>).map(([k, c]) => {
                  const before = r.current.categories[k].score;
                  const status = ratingStatus(c.rating);
                  return (
                    <div className="db-row" key={k}>
                      <span className="db-label">{c.label}</span>
                      <div className="db-track">
                        {c.score !== null && <span className="db-bar" style={{ width: `${c.score}%`, background: STATUS_VAR[status] }} />}
                        {before !== null && <span className="db-tick" style={{ left: `${before}%` }} title={`current ${before}`} />}
                      </div>
                      <span className="db-val">{score(before)} → {c.score === null ? 'n/a' : score(c.score)}</span>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}
        </div>
      </div>

      {r && r.factors.length > 0 && (
        <Card title="What each change contributes" className="mt-md"
          subtitle="Alone = applied on its own. Uncapped = its effect before the weakest-link cap. If removed = what the full proposal loses without it.">
          <TableWrap>
            <table className="data-table">
              <thead><tr><th>Change</th><th>From → to</th><th className="num">Alone</th><th className="num">Uncapped</th>
                <th className="num">If removed</th><th>Categories moved</th><th>Resolves</th></tr></thead>
              <tbody>{r.factors.map((f: Loose) => {
                const knob = base.knobs.find((k: Loose) => k.key === f.key);
                return (
                  <tr key={f.key}>
                    <td className="text-primary">{f.label}</td>
                    <td className="text-xs">{f.key === 'esp_suite' ? (f.from ?? '?') : fmt(knob, f.from)} → <b className="cipher">{fmt(knob, f.to)}</b></td>
                    <td className="num">{signed(f.delta_alone)}{f.capped_alone && <span className="muted" title="Capped by another finding"> ⌃</span>}</td>
                    <td className="num">{signed(f.delta_uncapped)}</td>
                    <td className="num">{signed(f.delta_if_removed)}</td>
                    <td className="text-xs">{f.categories.map((c: Loose) => `${c.label} ${signed(c.delta)}`).join(' · ') || '—'}</td>
                    <td className="mono text-xs">{f.resolves.join(' ') || '—'}</td>
                  </tr>
                );
              })}</tbody>
            </table>
          </TableWrap>
          <p className="hint">{r.note}</p>
        </Card>
      )}

      <Card title="Verify in the lab" className="mt-md accent"
        subtitle="Render the proposed configuration with this capture's traffic, capture it, and run the full pipeline from the PCAP alone."
        actions={<button className="btn btn-primary" onClick={verify} disabled={verifying || !changed || (result && !result.valid)}>
          {verifying ? 'Verifying…' : 'Verify proposed configuration'}</button>}>
        <ol className="steps">
          {VERIFY_STEPS.map((s, i) => (
            <li key={s} className={verifying ? (i < step ? 'done' : i === step ? 'active' : '') : verified ? 'done' : ''}>
              <span className="step-n">{String(i + 1).padStart(2, '0')}</span>{s}
            </li>
          ))}
        </ol>
        {!verified && !verifying && <p className="muted text-sm">{changed ? 'Ready: the twin uses compressed lab time, so rekeys happen every ~18 s.' : 'Propose at least one change first.'}</p>}
        {verified && (
          <div className="verify-result">
            <div className="grid-2">
              <div>
                <ScoreShift label="Measured security score" before={verified.before.score} after={verified.after.score}
                  note={`${verified.before.risk_level} → ${verified.after.risk_level} · identification on the new capture ${
                    verified.after.identification_accuracy === null ? 'n/a' : `${Math.round(verified.after.identification_accuracy * 100)}% correct`}`} />
                <div className="kv mt-md">
                  <div className="kv-row"><dt>Modelled</dt><dd>{score(r?.proposed.overall_score)}</dd></div>
                  <div className="kv-row"><dt>Measured</dt><dd>{score(verified.after.score)}</dd></div>
                  <div className="kv-row"><dt>Resolved</dt><dd className="mono text-xs">{verified.resolved.join(' ') || '—'}</dd></div>
                  <div className="kv-row"><dt>Still open</dt><dd className="text-xs">{verified.remaining.map((f: Loose) => `${f.id} (${f.severity})`).join(', ') || 'none'}</dd></div>
                </div>
                <div className="button-row mt-md">
                  <Link className="btn btn-sm btn-primary" to={`/security?id=${verified.analysis_id}`}>Open the verified capture</Link>
                  <Link className="btn btn-sm btn-secondary" to={`/drift?id=${verified.analysis_id}&baseline=${id}`}>Compare (drift view)</Link>
                </div>
              </div>
              <div>
                <span className="tile-label">strongSwan profile for the Docker lab</span>
                <pre className="code">{verified.strongswan_profile}</pre>
                <button className="btn btn-sm btn-secondary" onClick={() => navigator.clipboard?.writeText(verified.strongswan_profile)}>Copy profile</button>
              </div>
            </div>
            <p className="hint">{verified.note}</p>
          </div>
        )}
      </Card>
    </Page>
  );
}

const signed = (v: number | null | undefined) => (v === null || v === undefined ? '—' : `${v > 0 ? '+' : ''}${v}`);
