import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { BarList, ThreatMatrixGrid } from '../components/charts';
import { EvidenceChainView, FingerprintBadge, PostureCard } from '../components/ipsec';
import { Page } from '../components/Layout';
import {
  Card, ErrorBanner, KeyValue, Loading, Meter, NoAnalysis, SeverityBadge, SourceBadge, StatusPill, TableWrap, Tabs,
} from '../components/ui';
import { useAnalysis, useIntel } from '../hooks/useAnalysis';
import { pct, ratingStatus, riskLevelStatus, score, scoreStatus, severityStatus } from '../lib/format';
import type { AnalysisRecord, Intel, Severity } from '../types';

type Tab = 'overview' | 'findings' | 'compliance' | 'threats' | 'actions';
const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
const STATUS_VAR = { good: 'var(--status-good)', warning: 'var(--status-warning)', serious: 'var(--status-serious)',
  critical: 'var(--status-critical)', none: 'var(--viz-muted)' };

export default function Security() {
  const { id, data, loading, error } = useAnalysis();
  const { intel } = useIntel(id);
  const [params] = useSearchParams();
  const [tab, setTab] = useState<Tab>((params.get('tab') as Tab) || 'overview');

  if (!id) return <Page title="Security assessment"><NoAnalysis /></Page>;
  if (loading || (!data && !error)) return <Page title="Security assessment"><Loading /></Page>;
  if (error || !data) return <Page title="Security assessment"><ErrorBanner message={error ?? 'Not found'} /></Page>;

  const s = data.security;
  return (
    <Page title="Security assessment" subtitle={`${data.parsed_metadata.filename} · every finding traced from packet to fix`}
      meta={intel && <FingerprintBadge fp={intel.fingerprint} />}>
      <Tabs active={tab} onChange={setTab} tabs={[
        { key: 'overview', label: 'Overview' },
        { key: 'findings', label: 'Findings', count: s.findings.length },
        { key: 'compliance', label: 'Compliance' },
        { key: 'threats', label: 'Threat matrix', count: data.threat_matrix.threat_count },
        { key: 'actions', label: 'Recommendations', count: s.recommendations.length },
      ]} />
      {tab === 'overview' && <Overview data={data} intel={intel} />}
      {tab === 'findings' && <Findings data={data} intel={intel} />}
      {tab === 'compliance' && <Compliance data={data} />}
      {tab === 'threats' && <Threats data={data} />}
      {tab === 'actions' && <Actions data={data} />}
    </Page>
  );
}

function Overview({ data, intel }: { data: AnalysisRecord; intel: Intel | null }) {
  const s = data.security;
  const ai = data.ai_confidence;
  const counts = s.severity_counts;
  return (
    <>
      {intel && (
        <Card title="Explainable verdict" className="accent mb-md" subtitle={intel.posture.method}>
          <PostureCard posture={intel.posture} analysisId={data.analysis_id} />
        </Card>
      )}
      <div className="grid-hero">
        <Card>
          <div className="hero-block">
            <div className="tile-label">Security score</div>
            <div className="hero-figure">{score(s.overall_score)}<span className="hero-unit">/100</span></div>
            <StatusPill status={scoreStatus(s.overall_score)} label={s.risk_level} />
            {s.score_cap && <p className="hint">Score {s.score_cap} (weakest-link rule; uncapped {score(s.uncapped_score)}).</p>}
            {s.provisional && <p className="hint">Provisional: under half of the weighted assessment has evidence.</p>}
            <div className="hero-meta">
              <div><span className="tile-label">Risk score</span><strong>{score(s.risk_score)}</strong></div>
              <div><span className="tile-label">Evidence coverage</span><strong>{pct(s.coverage)}</strong></div>
              <div><span className="tile-label">AI confidence</span><strong>{pct(ai.overall)}</strong></div>
            </div>
            <div className="chips mt-md">
              {SEVERITIES.filter((sev) => counts[sev]).map((sev) => <StatusPill key={sev} status={severityStatus[sev]} label={`${counts[sev]} ${sev}`} />)}
            </div>
          </div>
        </Card>
        <Card title="Category scores" subtitle="Status color + rating; categories without evidence are excluded, not guessed">
          <BarList max={100} items={Object.entries(s.categories).map(([key, c]) => ({
            key, label: c.label, value: c.score,
            display: c.score === null ? 'Not assessable' : `${score(c.score)} · ${c.rating}`,
            color: STATUS_VAR[ratingStatus(c.rating)],
            note: <span className="muted text-xs">weight {pct(c.weight)} · confidence {pct(c.confidence)}</span>,
          }))} />
        </Card>
      </div>

      <div className="grid-2 mt-md">
        <Card title="Effective cryptographic strength" subtitle="Weakest link of the negotiated suite (NIST SP 800-57)">
          {s.effective_strength.bits !== null ? (
            <>
              <div className="big-stat">{s.effective_strength.bits}<span className="hero-unit"> bits</span></div>
              <p className="text-sm">{s.effective_strength.rating} — limited by <strong>{s.effective_strength.limited_by}</strong></p>
              <BarList max={256} items={s.effective_strength.components.map((c) => ({
                key: c.role, label: `${c.role}: ${c.algorithm ?? '—'}`, value: c.bits, display: c.bits === null ? 'not observable' : `${c.bits} bits`,
              }))} emptyText="not observable" />
              {s.effective_strength.note && <p className="hint">{s.effective_strength.note}</p>}
            </>
          ) : <p className="muted">No algorithm observable.</p>}
        </Card>
        <Card title="AI confidence" subtitle={ai.formula}>
          <BarList items={[
            { key: 'id', label: 'Protocol identification', value: ai.identification },
            { key: 'cls', label: 'Traffic classification', value: ai.classification },
            { key: 'cov', label: 'Assessment coverage', value: ai.assessment_coverage },
          ]} emptyText="no classifiable traffic" />
          <p className="hint">{ai.fields_observed} fields observed · {ai.fields_inferred} inferred · {ai.fields_not_observable} not observable</p>
        </Card>
      </div>

      <Card title="Scoring breakdown" className="mt-md" subtitle={s.method}>
        <TableWrap>
          <table className="data-table">
            <thead><tr><th>Category</th><th className="num">Weight</th><th className="num">Score</th><th className="conf-col">Confidence</th><th>Rationale</th></tr></thead>
            <tbody>{Object.entries(s.categories).map(([key, c]) => (
              <tr key={key}><td className="text-primary">{c.label}</td><td className="num">{pct(c.weight)}</td>
                <td className="num">{score(c.score)}</td>
                <td className="conf-col"><div className="meter-row"><Meter value={c.score === null ? null : c.confidence} /><span className="num">{pct(c.confidence)}</span></div></td>
                <td className="evidence-cell">{c.rationale}</td></tr>))}</tbody>
          </table>
        </TableWrap>
      </Card>
    </>
  );
}

function Findings({ data, intel }: { data: AnalysisRecord; intel: Intel | null }) {
  const [filter, setFilter] = useState<Severity | 'all'>('all');
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const findings = data.security.findings.filter((f) => filter === 'all' || f.severity === filter);
  const isOpen = (id: string, severity: Severity) => open[id] ?? (severity === 'Critical' || severity === 'High');
  return (
    <>
      <div className="legend-note">
        Each finding is traced: <b className="cipher">packet</b> → extracted <b className="cipher">parameter</b> →
        security <b className="cipher">rule</b> → <b className="cipher">risk</b> → <b className="cipher">fix</b>.
        Rules are deterministic; no language model writes the verdict.
      </div>
      <div className="filter-row" role="group" aria-label="Filter by severity">
        {(['all', ...SEVERITIES] as const).map((sev) => (
          <button key={sev} className={`chip-button ${filter === sev ? 'active' : ''}`} onClick={() => setFilter(sev)}>
            {sev === 'all' ? `All (${data.security.findings.length})` : `${sev} (${data.security.severity_counts[sev] ?? 0})`}
          </button>
        ))}
      </div>
      {findings.map((f) => {
        const chain = intel?.chains[f.id];
        const expanded = isOpen(f.id, f.severity);
        return (
          <article className={`finding-card sev-${severityStatus[f.severity]}`} key={f.id}>
            <div className="finding-header">
              <SeverityBadge severity={f.severity} />
              <span className="finding-id">{f.id}</span>
              <span className="finding-title">{f.title}</span>
              <span className="spacer" />
              <SourceBadge source={f.evidence_source} confidence={f.evidence_source === 'not_observable' ? undefined : f.confidence} />
            </div>
            <div className="finding-description">{f.description}</div>
            {chain && (
              <button className="chain-toggle" aria-expanded={expanded} onClick={() => setOpen({ ...open, [f.id]: !expanded })}>
                {expanded ? '▾ Hide evidence chain' : '▸ Show evidence chain'}
              </button>
            )}
            {chain && expanded ? <EvidenceChainView chain={chain} /> : (
              <>
                <div className="finding-evidence">Evidence: {f.evidence}</div>
                <div className="finding-recommendation">→ {f.recommendation}</div>
              </>
            )}
          </article>
        );
      })}
      <p className="hint">Want to see what fixing these would do? <Link to={`/simulator?id=${data.analysis_id}&fix=1`}>Open the what-if simulator</Link>.</p>
    </>
  );
}

function Compliance({ data }: { data: AnalysisRecord }) {
  return (
    <div className="stack">
      {Object.entries(data.security.compliance).map(([key, p]) => (
        <Card key={key} title={p.name} subtitle={p.description} actions={
          <StatusPill status={p.status === 'Non-compliant' ? 'critical' : p.status.includes('warning') ? 'warning'
            : p.status.startsWith('Compliant') ? 'good' : 'none'} label={p.status} />}>
          <div className="compliance-meta">
            <span>Score <strong>{p.score ?? '—'}{p.score !== null && '%'}</strong></span>
            <span>Evidence coverage <strong>{pct(p.coverage)}</strong></span>
            <span className="muted">{p.counts.pass} pass · {p.counts.warn} warn · {p.counts.fail} fail · {p.counts.unknown} unknown</span>
          </div>
          <TableWrap>
            <table className="data-table">
              <tbody>{p.checks.map((c) => (
                <tr key={c.id}>
                  <td className="nowrap">{c.id}</td>
                  <td className="text-primary">{c.title}<div className="muted text-xs">{c.reference}</div></td>
                  <td><StatusPill status={c.status === 'pass' ? 'good' : c.status === 'warn' ? 'warning' : c.status === 'fail' ? 'critical' : 'none'}
                    label={c.status} /></td>
                  <td className="evidence-cell">{c.evidence}</td>
                </tr>))}</tbody>
            </table>
          </TableWrap>
        </Card>
      ))}
    </div>
  );
}

function Threats({ data }: { data: AnalysisRecord }) {
  const tm = data.threat_matrix;
  return (
    <div className="grid-threats">
      <Card title="Likelihood × impact" subtitle="Hover or focus a threat marker for details">
        <ThreatMatrixGrid matrix={tm} />
      </Card>
      <Card title="Threats" subtitle={`${tm.threat_count} of 9 IPsec threat categories triggered`}>
        <TableWrap>
          <table className="data-table">
            <thead><tr><th>#</th><th>Threat</th><th className="num">L</th><th className="num">I</th><th>Risk</th></tr></thead>
            <tbody>{tm.threats.map((t, i) => (
              <tr key={t.id}>
                <td>T{i + 1}</td>
                <td className="text-primary">{t.name}<div className="muted text-xs">{t.attack} · from {t.contributing_findings.join(', ')}</div>
                  <div className="text-xs">{t.description}</div></td>
                <td className="num">{t.likelihood}</td><td className="num">{t.impact}</td>
                <td><StatusPill status={riskLevelStatus(t.risk_level)} label={`${t.risk_score} ${t.risk_level}`} /></td>
              </tr>))}</tbody>
          </table>
        </TableWrap>
      </Card>
    </div>
  );
}

function Actions({ data }: { data: AnalysisRecord }) {
  const recs = data.security.recommendations;
  if (!recs.length) return <Card><p className="muted">No actions required.</p></Card>;
  return (
    <Card title="Prioritised actions">
      <ol className="action-list">
        {recs.map((r) => (
          <li key={r.finding_id}>
            <StatusPill status={severityStatus[r.severity]} label={r.priority} />
            <div><div className="text-primary">{r.action}</div><div className="muted text-xs">{r.finding_id} · {r.title}</div></div>
          </li>
        ))}
      </ol>
      <KeyValue items={[{ label: 'Basis', value: 'Each action resolves the listed finding; order follows severity.' }]} />
    </Card>
  );
}
