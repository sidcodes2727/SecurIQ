import { useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Page } from '../components/Layout';
import { useToast } from '../hooks/useToast';
import { ErrorBanner, Loading, StatusPill } from '../components/ui';
import { rememberAnalysis } from '../hooks/useAnalysis';
import { useFleet } from '../hooks/useFleet';
import { STATUS_ICON, TRAFFIC_LABELS, classColor, score, scoreStatus, severityStatus, timeAgo, type Status } from '../lib/format';
import { FIELDS, applyQuery, isActive, parse, toggleToken } from '../lib/query';
import type { FleetRow } from '../types';

interface Facet { key: string; label: string; values: (r: FleetRow) => { value: string; label: string }[] }

const one = (v: string | null | undefined, label?: string) => (v === null || v === undefined ? [] : [{ value: v, label: label ?? v }]);

const FACETS: Facet[] = [
  { key: 'risk', label: 'Risk', values: (r) => one(r.risk_level.split(' ')[0].toLowerCase(), r.risk_level) },
  { key: 'policy', label: 'Golden policy', values: (r) => one(r.policy_status.startsWith('Non') ? 'non' : 'compliant', r.policy_status.startsWith('Non') ? 'Non-compliant' : 'Compliant') },
  { key: 'sev', label: 'Finding severity', values: (r) => [...new Set(r.findings.map((f) => f.severity))].map((s) => ({ value: s.toLowerCase(), label: s })) },
  { key: 'finding', label: 'Findings', values: (r) => r.findings.map((f) => ({ value: f.id, label: `${f.id} ${f.title.split(':')[0]}` })) },
  { key: 'ike', label: 'IKE version', values: (r) => one(r.ike_version?.toLowerCase(), r.ike_version ?? undefined) },
  { key: 'exchange', label: 'Exchange', values: (r) => one(r.exchange_mode?.toLowerCase(), r.exchange_mode ?? undefined) },
  { key: 'enc', label: 'IKE cipher', values: (r) => one(r.ike_encryption?.toLowerCase(), r.ike_encryption ?? undefined) },
  { key: 'dh', label: 'DH group', values: (r) => (r.dh_group ? [{ value: String(r.dh_group), label: `${r.dh_group} · ${r.dh_name}` }] : []) },
  { key: 'esp', label: 'ESP cipher', values: (r) => one(r.esp_encryption?.toLowerCase(), r.esp_encryption ?? undefined) },
  { key: 'pfs', label: 'PFS', values: (r) => one(r.pfs ?? 'unknown', r.pfs ? `PFS ${r.pfs}` : 'not observable') },
  { key: 'mode', label: 'Mode', values: (r) => one((r.mode ?? 'unknown').toLowerCase(), r.mode ?? 'not observable') },
  { key: 'auth', label: 'Authentication', values: (r) => one((r.auth ?? 'unknown').toLowerCase(), r.auth ?? 'not observable') },
  { key: 'traffic', label: 'Traffic inside', values: (r) => r.traffic.map((t) => ({ value: t, label: TRAFFIC_LABELS[t] ?? t })) },
  { key: 'novelty', label: 'Novelty', values: (r) => one(r.novelty) },
  { key: 'src', label: 'Source', values: (r) => one(r.source) },
];

type SortKey = 'filename' | 'score' | 'created' | 'dh_group' | 'findings' | 'policy_fail' | 'metadata_privacy';
const SAVED_KEY = 'securiq.savedViews';
const readSaved = (): { name: string; q: string }[] => { try { return JSON.parse(localStorage.getItem(SAVED_KEY) || '[]'); } catch { return []; } };

const EXAMPLES = ['dh:2 dh:5', 'pfs:off', 'policy:non', 'sev:critical', 'ike:v1', 'score<70', 'traffic:voip', '-src:lab'];

function riskStatus(row: FleetRow): Status { return scoreStatus(row.score); }

export default function Explorer() {
  const navigate = useNavigate();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const { rows, error } = useFleet();
  const q = params.get('q') ?? '';
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'score', dir: 1 });
  const [saved, setSaved] = useState(readSaved);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({ exchange: true, novelty: true, src: true });

  const setQ = (next: string) => {
    const p = new URLSearchParams(params);
    if (next.trim()) p.set('q', next); else p.delete('q');
    setParams(p, { replace: true });
  };
  const tokens = useMemo(() => parse(q), [q]);
  const filtered = useMemo(() => (rows ? applyQuery(rows, tokens) : []), [rows, tokens]);

  const facetData = useMemo(() => {
    if (!rows) return [];
    return FACETS.map((f) => {
      const base = applyQuery(rows, tokens, f.key);
      const counts = new Map<string, { label: string; n: number }>();
      for (const row of base) {
        const seen = new Set<string>();
        for (const v of f.values(row)) {
          if (seen.has(v.value)) continue;
          seen.add(v.value);
          const c = counts.get(v.value) ?? { label: v.label, n: 0 };
          c.n += 1;
          counts.set(v.value, c);
        }
      }
      const values = [...counts.entries()].map(([value, c]) => ({ value, ...c }))
        .sort((a, b) => b.n - a.n || a.label.localeCompare(b.label));
      return { ...f, values, max: Math.max(1, ...values.map((v) => v.n)) };
    });
  }, [rows, tokens]);

  const sorted = useMemo(() => {
    const val = (r: FleetRow): number | string => {
      if (sort.key === 'findings') return r.findings.length;
      const v = r[sort.key];
      return v === null || v === undefined ? (typeof v === 'string' ? '' : -Infinity) : v as number | string;
    };
    return [...filtered].sort((a, b) => {
      const x = val(a), y = val(b);
      return (typeof x === 'string' ? x.localeCompare(String(y)) : (x as number) - (y as number)) * sort.dir;
    });
  }, [filtered, sort]);

  if (error) return <Page title="Object explorer"><ErrorBanner message={error} /></Page>;
  if (!rows) return <Page title="Object explorer"><Loading label="Indexing captures…" /></Page>;

  const invalid = tokens.filter((t) => !t.valid);
  const mean = filtered.length ? filtered.reduce((s, r) => s + (r.score ?? 0), 0) / filtered.length : null;
  const compliant = filtered.filter((r) => r.policy_fail === 0).length;
  const riskBands: [Status, string][] = [['critical', 'Score < 50'], ['serious', '50–69'], ['warning', '70–84'], ['good', '≥ 85']];
  const bandCount = (s: Status) => filtered.filter((r) => riskStatus(r) === s).length;

  const header = (key: SortKey, label: string, num = false) => (
    <th className={`sortable ${num ? 'num' : ''}`} aria-sort={sort.key === key ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none'}>
      <button onClick={() => setSort({ key, dir: sort.key === key ? (sort.dir === 1 ? -1 : 1) : 1 })}>
        {label}<span aria-hidden className="sort-mark">{sort.key === key ? (sort.dir === 1 ? '▲' : '▼') : '↕'}</span>
      </button>
    </th>
  );

  const exportCsv = () => {
    const cols: [string, (r: FleetRow) => unknown][] = [
      ['capture', (r) => r.filename], ['analysis_id', (r) => r.analysis_id], ['source', (r) => r.source], ['score', (r) => r.score],
      ['risk', (r) => r.risk_level], ['ike', (r) => r.ike_version], ['exchange', (r) => r.exchange_mode], ['ike_cipher', (r) => r.ike_encryption],
      ['dh_group', (r) => r.dh_group], ['esp', (r) => r.esp_encryption], ['pfs', (r) => r.pfs], ['mode', (r) => r.mode], ['auth', (r) => r.auth],
      ['policy', (r) => r.policy_status], ['fingerprint', (r) => r.fingerprint], ['gateways', (r) => r.gateways.join(' ')],
      ['findings', (r) => r.findings.map((f) => f.id).join(' ')], ['traffic', (r) => r.traffic.join(' ')],
    ];
    const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const csv = [cols.map((c) => c[0]).join(','), ...sorted.map((r) => cols.map(([, f]) => esc(f(r))).join(','))].join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url; a.download = `securiq-explorer-${sorted.length}.csv`; a.click();
    URL.revokeObjectURL(url);
    toast.push('Exported', `${sorted.length} capture(s) to CSV`, 'good');
  };

  const saveView = () => {
    const name = q.trim();
    if (!name) return;
    const next = [{ name, q }, ...saved.filter((s) => s.q !== q)].slice(0, 8);
    setSaved(next);
    try { localStorage.setItem(SAVED_KEY, JSON.stringify(next)); } catch { /* per-viewer convenience */ }
    toast.push('View saved', name, 'good');
  };
  const removeView = (qq: string) => {
    const next = saved.filter((s) => s.q !== qq);
    setSaved(next);
    try { localStorage.setItem(SAVED_KEY, JSON.stringify(next)); } catch { /* ignore */ }
  };

  return (
    <Page title="Object explorer" wide
      subtitle="Every capture as an object with its identified configuration, findings and traffic. Filter with facets or the query bar; results update as you type.">
      <div className="query-bar">
        <span className="query-prompt" aria-hidden>ƒ</span>
        <input type="text" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Query"
          placeholder="dh:2 pfs:off risk:high score<70 -src:lab finding:KE-001 …" spellCheck={false} />
        {q && <button className="btn btn-sm btn-ghost" onClick={() => setQ('')}>Clear</button>}
        <button className="btn btn-sm btn-secondary" onClick={saveView} disabled={!q.trim()}>Save view</button>
        <button className="btn btn-sm btn-secondary" onClick={exportCsv} disabled={!sorted.length}>Export CSV</button>
      </div>
      <div className="query-meta">
        {tokens.length > 0 ? tokens.map((t, i) => (
          <span key={i} className={`qtoken ${t.valid ? '' : 'invalid'} ${t.neg ? 'neg' : ''}`} title={t.error ?? (t.key ? FIELDS[t.key]?.label : 'text')}>
            {t.key ? <><b>{t.neg ? 'NOT ' : ''}{FIELDS[t.key]?.label ?? t.key}</b> {t.op === ':' ? '=' : t.op} {t.value}</> : <>text “{t.value}”</>}
            <button aria-label={`Remove ${t.raw}`} onClick={() => setQ(q.replace(t.raw, '').replace(/\s+/g, ' ').trim())}>×</button>
          </span>
        )) : (
          <span className="muted text-xs">Try: {EXAMPLES.map((e) => <button key={e} className="linkish" onClick={() => setQ(e)}>{e}</button>)}</span>
        )}
        {invalid.length > 0 && <span className="qerror">{invalid[0].error} · fields: {Object.keys(FIELDS).join(', ')}</span>}
      </div>
      {saved.length > 0 && (
        <div className="saved-views">
          <span className="tile-label nomb">Saved views</span>
          {saved.map((s) => (
            <span key={s.q} className={`saved ${s.q === q ? 'active' : ''}`}>
              <button onClick={() => setQ(s.q)}>{s.name}</button>
              <button aria-label={`Delete view ${s.name}`} onClick={() => removeView(s.q)}>×</button>
            </span>
          ))}
        </div>
      )}

      <div className="explorer">
        <aside className="facets" aria-label="Facets">
          {facetData.map((f) => (
            <section key={f.key} className="facet">
              <button className="facet-head" onClick={() => setCollapsed({ ...collapsed, [f.key]: !collapsed[f.key] })} aria-expanded={!collapsed[f.key]}>
                <span>{f.label}</span><span className="muted">{f.values.length}</span><span aria-hidden>{collapsed[f.key] ? '▸' : '▾'}</span>
              </button>
              {!collapsed[f.key] && (
                <ul>
                  {f.values.slice(0, f.key === 'finding' ? 12 : 10).map((v) => {
                    const on = isActive(tokens, f.key, v.value);
                    return (
                      <li key={v.value}>
                        <button className={`facet-value ${on ? 'on' : ''}`} onClick={() => setQ(toggleToken(q, f.key, v.value))} aria-pressed={on}>
                          <span className="facet-check" aria-hidden>{on ? '■' : '□'}</span>
                          <span className="facet-label">{f.key === 'traffic' && <span className="swatch" style={{ background: classColor(v.value) }} />}
                            {f.key === 'sev' && <span aria-hidden className={`sev-ic s-${severityStatus[v.label as keyof typeof severityStatus]}`}>{STATUS_ICON[severityStatus[v.label as keyof typeof severityStatus]]}</span>}
                            {v.label}</span>
                          <span className="facet-bar"><span style={{ width: `${(v.n / f.max) * 100}%` }} /></span>
                          <span className="facet-n">{v.n}</span>
                        </button>
                      </li>
                    );
                  })}
                  {f.values.length === 0 && <li className="muted text-xs">no values</li>}
                </ul>
              )}
            </section>
          ))}
        </aside>

        <section className="results">
          <div className="results-summary">
            <div><span className="big-num">{filtered.length}</span><span className="muted"> of {rows.length} captures</span></div>
            <div><span className="tile-label nomb">Mean score</span><strong>{mean === null ? '—' : mean.toFixed(1)}</strong></div>
            <div><span className="tile-label nomb">Policy compliant</span><strong>{compliant}/{filtered.length}</strong></div>
            <div className="risk-dist" role="img" aria-label={riskBands.map(([s, l]) => `${l} ${bandCount(s)}`).join(', ')}>
              <div className="risk-bar">
                {riskBands.map(([s]) => bandCount(s) ? <span key={s} className={`rb s-${s}`} style={{ flexGrow: bandCount(s) }} /> : null)}
              </div>
              <div className="risk-legend">{riskBands.map(([s, l]) => (
                <span key={s}><span aria-hidden className={`sev-ic s-${s}`}>{STATUS_ICON[s]}</span>{l} {bandCount(s)}</span>))}</div>
            </div>
          </div>
          <div className="table-wrap">
            <table className="data-table explorer-table">
              <thead><tr>
                {header('filename', 'Capture')}{header('score', 'Score', true)}<th>Risk</th><th>IKE</th><th>IKE cipher</th>
                {header('dh_group', 'DH', true)}<th>ESP</th><th>PFS</th><th>Auth</th>{header('policy_fail', 'Policy', true)}
                {header('findings', 'Findings', true)}<th>Traffic</th><th>Fingerprint</th>{header('created', 'Analysed', true)}
              </tr></thead>
              <tbody>
                {sorted.map((r) => (
                  <tr key={r.analysis_id} className="clickable" tabIndex={0}
                    onClick={() => { rememberAnalysis(r.analysis_id); navigate(`/analysis?id=${r.analysis_id}`); }}
                    onKeyDown={(e) => { if (e.key === 'Enter') { rememberAnalysis(r.analysis_id); navigate(`/analysis?id=${r.analysis_id}`); } }}>
                    <td className="text-primary">{r.filename}<div className="muted text-xs">{r.source} · {r.gateways.join(' ↔ ')}</div></td>
                    <td className="num">{score(r.score)}</td>
                    <td><StatusPill status={riskStatus(r)} label={r.risk_level.replace(' Risk', '')} /></td>
                    <td>{r.ike_version ?? '—'}{r.ike_version === 'IKEv1' && <div className="muted text-xs">{r.exchange_mode}</div>}</td>
                    <td className="text-xs">{r.ike_encryption ?? '—'}</td>
                    <td className="num">{r.dh_group ?? '—'}</td>
                    <td className="text-xs">{r.esp_encryption ?? '—'}</td>
                    <td>{r.pfs ?? <span className="muted">?</span>}</td>
                    <td className="text-xs">{r.auth ?? '—'}</td>
                    <td className="num">{r.policy_fail ? <StatusPill status="critical" label={`${r.policy_fail} fail`} /> : <StatusPill status="good" label="ok" />}</td>
                    <td className="num"><span className="sev-counts">
                      {(['Critical', 'High', 'Medium'] as const).map((s) => r.severity_counts[s] ? (
                        <span key={s} className={`sevc s-${severityStatus[s]}`} title={`${r.severity_counts[s]} ${s}`}>
                          <span aria-hidden>{STATUS_ICON[severityStatus[s]]}</span>{r.severity_counts[s]}</span>) : null)}
                      {!r.findings.length && <span className="muted">0</span>}</span></td>
                    <td><span className="traffic-dots">{r.traffic.map((t) => <span key={t} className="swatch" title={TRAFFIC_LABELS[t]} style={{ background: classColor(t) }} />)}</span></td>
                    <td className="mono text-xs">{r.fingerprint}</td>
                    <td className="num text-xs">{timeAgo(r.created)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {sorted.length === 0 && <p className="muted mt-md">No capture matches. Remove a filter above.</p>}
        </section>
      </div>
    </Page>
  );
}
