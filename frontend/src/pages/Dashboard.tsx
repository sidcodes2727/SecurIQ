import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FleetOps } from '../components/FleetOps';
import { EncapsulationHero, FingerprintBadge, PostureCard } from '../components/ipsec';
import { Page } from '../components/Layout';
import { Card, EmptyState, StatTile, StatusPill, TableWrap } from '../components/ui';
import { pct, score, scoreStatus, timeAgo } from '../lib/format';
import { api } from '../services/api';
import type { AnalysisSummary, Health, Intel, Loose } from '../types';

const LOOP = [
  { n: '01', step: 'Attack', text: 'Build a weak VPN in the lab: AES-128-CBC, DH group 2, PFS off.', to: '/lab' },
  { n: '02', step: 'Observe', text: 'Parse IKE and ESP passively. Identify every property, with its evidence.', to: '/analysis', scoped: true },
  { n: '03', step: 'Explain', text: 'Packet → parameter → rule → risk → fix, for every finding.', to: '/security', scoped: true, tab: 'findings' },
  { n: '04', step: 'Fix', text: 'Change settings in the what-if simulator and watch each factor move the score.', to: '/simulator', scoped: true },
  { n: '05', step: 'Verify', text: 'Render the fixed configuration as a new capture and measure it again.', to: '/simulator', scoped: true },
];

export default function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null);
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [model, setModel] = useState<Loose>(null);
  const [evaluation, setEvaluation] = useState<Loose>(null);
  const [bench, setBench] = useState<Loose>(null);
  const [intel, setIntel] = useState<Intel | null>(null);
  const [fleet, setFleet] = useState<Loose[]>([]);

  useEffect(() => {
    api.health().then(setHealth).catch(() => {});
    api.getModelInfo().then(setModel).catch(() => {});
    api.latestEvaluation().then(setEvaluation).catch(() => {});
    api.benchmarkLatest().then(setBench).catch(() => {});
    api.policyFleet().then((d) => setFleet(d.analyses)).catch(() => {});
    api.listAnalyses().then((d) => {
      setAnalyses(d.analyses);
      if (d.analyses[0]) api.getIntel(d.analyses[0].analysis_id).then(setIntel).catch(() => {});
    }).catch(() => {});
  }, []);

  const criticalHigh = analyses.reduce((sum, a) => sum + (a.critical_high || 0), 0);
  const head = analyses[0];
  const compliant = fleet.filter((f) => f.counts?.fail === 0).length;

  return (
    <Page title="Operations" bare>
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow"><span className="hex">SIH 26160</span> NTRO · passive IPsec analysis</div>
          <h1 className="hero-title">Encrypted<br />is not<br /><span className="cipher">invisible.</span></h1>
          <p className="hero-lede">
            SecurIQ reads an IPsec VPN from a packet capture, without its keys. It identifies the protocol, the
            algorithms and the traffic hidden inside ESP, explains every risk from the packets up, and shows what
            changes would fix it before you touch a gateway.
          </p>
          <div className="button-row hero-cta">
            <Link className="btn btn-primary" to="/upload">Analyse a capture</Link>
            <Link className="btn btn-secondary" to="/lab">Build a VPN in the lab</Link>
          </div>
          <ul className="hero-facts">
            <li><strong className="src-o">Observed</strong><span>read from cleartext IKE</span></li>
            <li><strong className="src-i">Inferred</strong><span>from sizes and timing, with confidence</span></li>
            <li><strong>Not observable</strong><span>reported, never guessed</span></li>
          </ul>
        </div>
        <EncapsulationHero />
      </section>

      <div className="kpi-row">
        <StatTile label="Captures analysed" value={analyses.length} sub={head ? `Last ${timeAgo(head.created)}` : `${health?.sample_files ?? 0} testbed scenarios ready`} />
        <StatTile label="Critical / high findings" value={criticalHigh} status={criticalHigh ? 'critical' : 'good'} sub="Across all analyses" />
        <StatTile label="Golden-policy compliant" value={fleet.length ? `${compliant}/${fleet.length}` : '—'}
          sub={<Link to="/policy">Edit the policy</Link>} />
        <StatTile label="Traffic classifier" value={pct(model?.metrics?.accuracy, 1)}
          sub={model?.metrics?.roc_auc_ovr ? `ROC-AUC ${model.metrics.roc_auc_ovr.toFixed(3)} · held-out flows` : 'Held-out flows'} />
        <StatTile label="Misconfig detection" value={bench?.available ? pct(bench.detection_rate, 1) : '—'}
          sub={bench?.available ? `${bench.detected}/${bench.injected_total} injected · ${pct(bench.clean_false_alarm_rate)} false alarms`
            : <Link to="/testbed?tab=benchmark">Run the benchmark</Link>} />
        <StatTile label="Protocol identification" value={pct(evaluation?.overall_accuracy, 1)}
          sub={evaluation?.scenarios_evaluated ? `${evaluation.scenarios_evaluated} unseen captures` : <Link to="/testbed?tab=evaluation">Run evaluation</Link>} />
      </div>

      <FleetOps />

      <Card title="Latest assessment" subtitle={head?.filename}
        actions={head && <>
          {intel && <FingerprintBadge fp={intel.fingerprint} />}
          <Link className="btn btn-sm btn-secondary" to={`/security?id=${head.analysis_id}`}>Open</Link>
        </>}>
        {intel && head ? <PostureCard posture={intel.posture} analysisId={head.analysis_id} /> : (
          <EmptyState title="Nothing analysed yet">
            <p>Start with a testbed scenario (each ships with ground truth), or build your own VPN in the lab.</p>
            <div className="button-row mt-md">
              <Link className="btn btn-primary" to="/upload">Choose a capture</Link>
              <Link className="btn btn-secondary" to="/lab">Open the VPN lab</Link>
            </div>
          </EmptyState>
        )}
      </Card>

      <h2 className="section-title"><span className="hex">0x10</span> The loop: attack → observe → explain → fix → verify</h2>
      <ol className="loop">
        {LOOP.map((s) => (
          <li key={s.n}>
            <Link to={{ pathname: s.to, search: s.scoped && head ? `?id=${head.analysis_id}${s.tab ? `&tab=${s.tab}` : ''}` : '' }}>
              <span className="loop-n">{s.n}</span>
              <strong>{s.step}</strong>
              <p>{s.text}</p>
              <span className="loop-go" aria-hidden>→</span>
            </Link>
          </li>
        ))}
      </ol>

      <h2 className="section-title"><span className="hex">0x11</span> Recent analyses</h2>
      <Card>
        {analyses.length === 0 ? <p className="muted">No analyses yet.</p> : (
          <TableWrap>
            <table className="data-table">
              <thead><tr><th>Capture</th><th>Fingerprint</th><th>IKE</th><th className="num">Packets</th><th className="num">Score</th>
                <th>Risk</th><th className="num">Findings</th><th className="num">AI conf.</th><th /></tr></thead>
              <tbody>
                {analyses.slice(0, 12).map((a) => (
                  <tr key={a.analysis_id}>
                    <td className="text-primary">{a.filename}<div className="muted text-xs">{timeAgo(a.created)}</div></td>
                    <td className="mono text-xs">{a.fingerprint ?? '—'}<div className="muted">{a.fingerprint_label ?? ''}</div></td>
                    <td>{a.ike_version ?? '—'}</td>
                    <td className="num">{a.total_packets?.toLocaleString()}</td>
                    <td className="num">{score(a.security_score)}</td>
                    <td><StatusPill status={scoreStatus(a.security_score)} label={a.risk_level} /></td>
                    <td className="num">{a.findings_count}{a.critical_high ? <span className="muted"> ({a.critical_high} C/H)</span> : null}</td>
                    <td className="num">{pct(a.ai_confidence)}</td>
                    <td><Link className="btn btn-sm btn-secondary" to={`/analysis?id=${a.analysis_id}`}>View</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>
    </Page>
  );
}
