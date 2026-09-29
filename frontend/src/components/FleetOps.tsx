import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { rememberAnalysis } from '../hooks/useAnalysis';
import { useFleet } from '../hooks/useFleet';
import { STATUS_ICON, score, scoreStatus, severityStatus } from '../lib/format';
import { api } from '../services/api';
import type { Severity, TriageItem } from '../types';

const RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };

/** Operations band: every capture at a glance, the triage queue, and the weaknesses that recur. */
export function FleetOps() {
  const navigate = useNavigate();
  const { rows } = useFleet();
  const [triage, setTriage] = useState<{ items: TriageItem[]; counts: Record<string, number> } | null>(null);
  useEffect(() => { api.triage().then(setTriage).catch(() => {}); }, []);

  const recurring = useMemo(() => {
    const map = new Map<string, { id: string; title: string; severity: Severity; n: number }>();
    for (const r of rows ?? []) for (const f of r.findings) {
      const cur = map.get(f.id);
      if (cur) cur.n += 1; else map.set(f.id, { id: f.id, title: f.title.split(':')[0], severity: f.severity, n: 1 });
    }
    return [...map.values()].filter((f) => f.severity !== 'Low').sort((a, b) => RANK[a.severity] - RANK[b.severity] || b.n - a.n).slice(0, 7);
  }, [rows]);

  if (!rows || rows.length === 0) return null;
  const wall = [...rows].sort((a, b) => (a.score ?? 101) - (b.score ?? 101));
  const urgent = (triage?.items ?? []).filter((i) => i.status === 'new' && (i.severity === 'Critical' || i.severity === 'High')).slice(0, 5);
  const maxN = Math.max(1, ...recurring.map((r) => r.n));

  return (
    <section className="ops" aria-label="Fleet operations">
      <div className="ops-wall">
        <div className="ops-head">
          <span className="tile-label nomb">Fleet posture · worst first</span>
          <Link className="linkish" to="/explorer">Open explorer</Link>
        </div>
        <div className="wall">
          {wall.slice(0, 24).map((r) => {
            const st = scoreStatus(r.score);
            return (
              <button key={r.analysis_id} className={`wall-tile s-${st}`} title={`${r.filename} · ${r.risk_level}`}
                onClick={() => { rememberAnalysis(r.analysis_id); navigate(`/security?id=${r.analysis_id}`); }}>
                <span className="wall-top"><span aria-hidden className={`sev-ic s-${st}`}>{STATUS_ICON[st]}</span>
                  <span className="wall-score">{score(r.score)}</span></span>
                <span className="wall-name">{r.filename.replace(/\.pcapng?$/, '')}</span>
                <span className="wall-fp">{r.fingerprint}</span>
              </button>
            );
          })}
        </div>
      </div>

      <div className="ops-side">
        <div className="ops-card">
          <div className="ops-head"><span className="tile-label nomb">Triage queue</span><Link className="linkish" to="/inbox">Open inbox</Link></div>
          <div className="queue-counts">
            {[['new', 'New'], ['investigating', 'Investigating'], ['accepted', 'Accepted'], ['resolved', 'Resolved']].map(([k, l]) => (
              <Link key={k} to={`/inbox?status=${k}`} className="qc"><strong>{triage?.counts[k] ?? '—'}</strong><span>{l}</span></Link>
            ))}
          </div>
          <ul className="urgent">
            {urgent.map((i) => (
              <li key={i.key}><Link to={`/inbox?status=new&item=${encodeURIComponent(i.key)}`}>
                <span aria-hidden className={`sev-ic s-${severityStatus[i.severity]}`}>{STATUS_ICON[severityStatus[i.severity]]}</span>
                <span className="ellipsis"><b className="mono">{i.finding_id}</b> {i.filename}</span></Link></li>
            ))}
            {triage && urgent.length === 0 && <li className="muted text-xs">No untriaged critical or high findings.</li>}
          </ul>
        </div>
        <div className="ops-card">
          <div className="ops-head"><span className="tile-label nomb">Recurring weaknesses</span><Link className="linkish" to="/graph">Link graph</Link></div>
          <ul className="recurring">
            {recurring.map((f) => (
              <li key={f.id}><Link to={`/inbox?finding=${f.id}`}>
                <span aria-hidden className={`sev-ic s-${severityStatus[f.severity]}`}>{STATUS_ICON[severityStatus[f.severity]]}</span>
                <span className="ellipsis"><b className="mono">{f.id}</b> {f.title}</span>
                <span className="rec-bar"><span style={{ width: `${(f.n / maxN) * 100}%` }} /></span>
                <span className="rec-n">{f.n}</span></Link></li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
