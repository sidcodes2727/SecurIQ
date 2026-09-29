import { useEffect, useState } from 'react';
import { FingerprintBadge, PostureCard } from '../components/ipsec';
import { Page } from '../components/Layout';
import { Card, ErrorBanner, Loading, NoAnalysis, SourceBadge, StatTile, StatusPill, TableWrap } from '../components/ui';
import { useAnalysisId, useIntel } from '../hooks/useAnalysis';
import { pct, riskLevelStatus, score, scoreStatus, severityStatus } from '../lib/format';
import { api } from '../services/api';
import type { Loose } from '../types';

export default function Reports() {
  const id = useAnalysisId();
  const { intel } = useIntel(id);
  const [report, setReport] = useState<Loose>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    api.getExecutiveReport(id).then(setReport).catch((e) => setError(e.message));
  }, [id]);

  if (!id) return <Page title="Reports"><NoAnalysis /></Page>;
  if (error) return <Page title="Reports"><ErrorBanner message={error} /></Page>;
  if (!report) return <Page title="Reports"><Loading /></Page>;

  return (
    <Page title="Reports" subtitle={report.capture.filename} meta={intel && <FingerprintBadge fp={intel.fingerprint} />}>
      <Card title="Download" subtitle="Printable HTML — use the browser’s Print → Save as PDF for a PDF copy">
        <div className="button-row">
          <a className="btn btn-primary" href={api.reportUrl(id, 'executive.html')} target="_blank" rel="noreferrer">Executive report</a>
          <a className="btn btn-secondary" href={api.reportUrl(id, 'technical.html')} target="_blank" rel="noreferrer">Technical report</a>
          <a className="btn btn-secondary" href={api.reportUrl(id, 'export.json')}>Full results (JSON)</a>
        </div>
      </Card>

      <h3 className="section-title">Executive summary preview</h3>
      <div className="kpi-row">
        <StatTile label="Security score" value={`${score(report.overall_security_score)}/100`}
          sub={<StatusPill status={scoreStatus(report.overall_security_score)} label={report.risk_level} />} />
        <StatTile label="Risk score" value={score(report.risk_score)} sub="100 − security score" />
        <StatTile label="AI confidence" value={pct(report.ai_confidence.overall)}
          sub={`identification ${pct(report.ai_confidence.identification)} · traffic ${pct(report.ai_confidence.classification)}`} />
        <StatTile label="Evidence coverage" value={pct(report.coverage)} sub={report.provisional ? 'Provisional score' : 'of weighted assessment'} />
      </div>

      <Card><p className="bottom-line"><strong>Bottom line.</strong> {report.bottom_line}</p></Card>
      {intel && (
        <Card title="Explainable verdict" className="mt-md accent" subtitle="Risk → evidence → impact → recommendation, as it appears in the executive report">
          <PostureCard posture={intel.posture} compact />
        </Card>
      )}
      {intel && (
        <div className="kpi-row mt-md">
          <StatTile label="Confidentiality" value={intel.metadata.confidentiality === null ? '—' : `${Math.round(intel.metadata.confidentiality)}%`} sub="Payload protection" />
          <StatTile label="Metadata privacy" value={intel.metadata.metadata_privacy === null ? '—' : `${Math.round(intel.metadata.metadata_privacy)}%`} sub="What an observer still learns" />
          <StatTile label="Golden policy" value={`${intel.policy.counts.fail} fail`} status={intel.policy.compliant ? 'good' : 'critical'} sub={intel.policy.status} />
          <StatTile label="Configuration" value={<span className="tile-text">{intel.novelty.status}</span>} sub={intel.fingerprint.label} />
        </div>
      )}

      <div className="grid-2 mt-md">
        <Card title="Priority actions">
          {report.top_recommendations.length === 0 ? <p className="muted">No actions required.</p> : (
            <ol className="action-list">{report.top_recommendations.map((r: Loose) => (
              <li key={r.finding_id}><StatusPill status={severityStatus[r.severity as keyof typeof severityStatus]} label={r.priority} />
                <div><div className="text-primary">{r.action}</div><div className="muted text-xs">{r.finding_id} · {r.title}</div></div></li>))}</ol>
          )}
        </Card>
        <Card title="What the AI identified">
          <TableWrap>
            <table className="data-table">
              <tbody>{report.vpn_summary.map((row: Loose) => (
                <tr key={row.key}><td>{row.label}</td><td className="text-primary">{row.value}</td>
                  <td><SourceBadge source={row.source} confidence={row.confidence} /></td></tr>))}</tbody>
            </table>
          </TableWrap>
        </Card>
      </div>

      <div className="grid-2 mt-md">
        <Card title="Top threats">
          <ul className="plain-list">{report.top_threats.map((t: Loose) => (
            <li key={t.name}><StatusPill status={riskLevelStatus(t.risk_level)} label={`${t.risk_score}`} /> {t.name}
              <span className="muted text-xs"> · L{t.likelihood} × I{t.impact}</span></li>))}</ul>
        </Card>
        <Card title="Compliance">
          <ul className="plain-list">{Object.values(report.compliance).map((p: Loose) => (
            <li key={p.name}><StatusPill status={p.status === 'Non-compliant' ? 'critical' : p.status.includes('warning') ? 'warning'
              : p.status.startsWith('Compliant') ? 'good' : 'none'} label={p.status} /> {p.name}
              <span className="muted text-xs"> · {p.score ?? '—'}{p.score !== null && '%'} on {pct(p.coverage)} coverage</span></li>))}</ul>
        </Card>
      </div>
    </Page>
  );
}
