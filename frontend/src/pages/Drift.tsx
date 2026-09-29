import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { FingerprintBadge, ScoreShift } from '../components/ipsec';
import { Page } from '../components/Layout';
import { Card, ErrorBanner, Loading, StatusPill, TableWrap } from '../components/ui';
import { useAnalysisId } from '../hooks/useAnalysis';
import { displayValue, score, timeAgo, type Status } from '../lib/format';
import { api } from '../services/api';
import type { Loose } from '../types';

const DIRECTION: Record<string, { status: Status; label: string }> = {
  degraded: { status: 'critical', label: 'weakened' },
  improved: { status: 'good', label: 'strengthened' },
  changed: { status: 'warning', label: 'changed' },
  visibility: { status: 'none', label: 'visibility only' },
};

const BANNER: Record<string, { cls: string; text: string }> = {
  degraded: { cls: 'alert-critical', text: 'Security configuration drift detected: the deployment got weaker' },
  improved: { cls: 'alert-good', text: 'Configuration changed, and every change strengthened the deployment' },
  changed: { cls: 'alert-warning', text: 'Configuration drift detected: settings changed' },
  no_drift: { cls: 'alert-good', text: 'No configuration drift: both captures show the same configuration' },
};

export default function Drift() {
  const id = useAnalysisId();
  const [params, setParams] = useSearchParams();
  const [list, setList] = useState<Loose[] | null>(null);
  const [state, setState] = useState<{ key: string; data: Loose }>({ key: '', data: null });
  const [error, setError] = useState<string | null>(null);
  const target = params.get('id') ?? id ?? list?.[0]?.analysis_id ?? null;
  const baseline = params.get('baseline') ?? undefined;

  useEffect(() => { api.fingerprints().then((d) => setList(d.analyses)).catch((e) => setError(e.message)); }, []);
  const key = `${target}|${baseline ?? ''}`;
  useEffect(() => {
    if (!target) return;
    let cancelled = false;
    api.drift(target, baseline).then((data) => { if (!cancelled) setState({ key, data }); })
      .catch((e) => { if (!cancelled) setError(e.message); });
    return () => { cancelled = true; };
  }, [target, baseline, key]);
  const result = state.key === key ? state.data : null;

  const groups = useMemo(() => {
    const out = new Map<string, Loose[]>();
    for (const a of list ?? []) {
      const key = (a.endpoints ?? []).join(' ↔ ') || 'unknown endpoints';
      out.set(key, [...(out.get(key) ?? []), a]);
    }
    return [...out.entries()];
  }, [list]);

  const choose = (key: 'id' | 'baseline', value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    if (key === 'id' && !next.get('id') && target) next.set('id', target);
    setParams(next);
  };

  if (!list) return <Page title="Drift detection">{error ? <ErrorBanner message={error} /> : <Loading />}</Page>;
  const banner = result && BANNER[result.status];

  return (
    <Page title="Drift detection" subtitle="Every capture gets a configuration fingerprint. Compare two captures of the same VPN and see exactly which settings changed, and in which direction.">
      {error && <ErrorBanner message={error} />}
      <Card title="Compare" subtitle="Baseline defaults to the previous capture of the same gateways">
        <div className="form-inline compare-form">
          <label className="field">Baseline (earlier)
            <select value={baseline ?? ''} onChange={(e) => choose('baseline', e.target.value)}>
              <option value="">Automatic: previous capture of the same endpoints</option>
              {list.filter((a) => a.analysis_id !== target).map((a) => (
                <option key={a.analysis_id} value={a.analysis_id}>{a.filename} · {a.fingerprint} · {timeAgo(a.created)}</option>))}
            </select>
          </label>
          <label className="field">Target (current)
            <select value={target ?? ''} onChange={(e) => choose('id', e.target.value)}>
              {list.map((a) => <option key={a.analysis_id} value={a.analysis_id}>{a.filename} · {a.fingerprint} · {timeAgo(a.created)}</option>)}
            </select>
          </label>
        </div>
      </Card>

      {!result ? <Loading /> : result.status === 'no_baseline' ? (
        <div className="alert alert-info mt-md">{result.note}. Analyse another capture of these gateways, or pick a baseline above.</div>
      ) : (
        <>
          <div className={`alert ${banner.cls} drift-banner mt-md`} role="status">
            <strong>{banner.text}.</strong>{' '}
            {result.changes.filter((c: Loose) => c.direction !== 'visibility').length} setting(s) changed ·
            score {result.score_delta > 0 ? '+' : ''}{result.score_delta ?? '—'}
          </div>
          <div className="grid-2">
            {(['base', 'target'] as const).map((side) => {
              const s = result[side];
              return (
                <Card key={side} title={side === 'base' ? 'Baseline' : 'Target'} subtitle={`${s.filename} · ${timeAgo(s.created)}`}
                  actions={<Link className="btn btn-sm btn-secondary" to={`/analysis?id=${s.analysis_id}`}>Open</Link>}>
                  <FingerprintBadge fp={s.fingerprint} large />
                  <div className="row mt-md"><span className="tile-label nomb">Score</span><strong className="big-num">{score(s.score)}</strong>
                    <span className="muted">{s.risk_level}</span></div>
                </Card>
              );
            })}
          </div>
          <div className="grid-side mt-md">
            <Card title="Component diff" subtitle="Direction is judged by cryptographic strength (NIST SP 800-57), not by preference">
              <TableWrap>
                <table className="data-table">
                  <thead><tr><th>Component</th><th>Baseline</th><th>Target</th><th>Change</th></tr></thead>
                  <tbody>
                    {result.base.fingerprint.components.map((c: Loose) => {
                      const change = result.changes.find((x: Loose) => x.key === c.key);
                      const d = change && DIRECTION[change.direction];
                      const after = result.target.fingerprint.components.find((x: Loose) => x.key === c.key)?.value;
                      return (
                        <tr key={c.key} className={change ? 'drift-row' : ''}>
                          <td className="text-primary">{c.label}</td>
                          <td>{c.value === null ? <span className="muted">not observable</span> : displayValue(c.value)}</td>
                          <td>{after === null || after === undefined ? <span className="muted">not observable</span> : displayValue(after)}</td>
                          <td>{d ? <StatusPill status={d.status} label={d.label} /> : <span className="muted">same</span>}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </TableWrap>
            </Card>
            <div className="stack">
              <Card title="Posture change">
                <ScoreShift before={result.base.score} after={result.target.score} />
                <div className="kv mt-md">
                  <div className="kv-row"><dt>New findings</dt><dd className="mono text-xs">{result.new_findings.join(' ') || '—'}</dd></div>
                  <div className="kv-row"><dt>Resolved findings</dt><dd className="mono text-xs">{result.resolved_findings.join(' ') || '—'}</dd></div>
                  <div className="kv-row"><dt>Same gateways</dt><dd>{result.same_endpoints ? 'yes' : 'no'}</dd></div>
                </div>
              </Card>
              <Card title="Categories">
                <ul className="plain-list">{result.categories.filter((c: Loose) => c.delta).map((c: Loose) => (
                  <li key={c.key} className="row"><StatusPill status={c.delta > 0 ? 'good' : 'critical'} label={`${c.delta > 0 ? '+' : ''}${c.delta}`} />{c.label}
                    <span className="muted text-xs">{score(c.before)} → {score(c.after)}</span></li>))}
                  {!result.categories.some((c: Loose) => c.delta) && <li className="muted">No category moved.</li>}
                </ul>
              </Card>
            </div>
          </div>
        </>
      )}

      <h2 className="section-title"><span className="hex">0x20</span> Fingerprints by gateway pair</h2>
      {groups.map(([endpoints, items]) => (
        <Card key={endpoints} title={endpoints} subtitle={`${items.length} capture(s) · ${new Set(items.map((a) => a.fingerprint)).size} distinct configuration(s)`}>
          <ol className="fp-timeline">
            {items.map((a, i) => {
              const prev = items[i + 1];
              const changed = prev && prev.fingerprint !== a.fingerprint;
              return (
                <li key={a.analysis_id} className={changed ? 'changed' : ''}>
                  <span className="fp-id-sm">{a.fingerprint}</span>
                  <span className="text-sm">{a.filename}</span>
                  <span className="muted text-xs">{a.label}</span>
                  <span className="muted text-xs">{timeAgo(a.created)}</span>
                  {prev && <Link className="btn btn-sm btn-ghost" to={`/drift?id=${a.analysis_id}&baseline=${prev.analysis_id}`}>Diff vs previous</Link>}
                </li>
              );
            })}
          </ol>
        </Card>
      ))}
    </Page>
  );
}
