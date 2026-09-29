import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { FingerprintBadge } from '../components/ipsec';
import { Page } from '../components/Layout';
import { Card, ErrorBanner, Loading, NoAnalysis, SeverityBadge } from '../components/ui';
import { useAnalysisId, useIntel } from '../hooks/useAnalysis';
import { STATUS_ICON, classColor, type Status } from '../lib/format';
import type { Intel } from '../types';

type Node = Intel['surface']['nodes'][number];

const COL_X = [0, 340, 680, 1020];
const NODE_W = 250;
const HEIGHT: Record<string, number> = { gateway: 104, ike: 176, child: 150, traffic: 92 };
const GAP = 22;
const KIND_LABEL: Record<string, string> = { gateway: 'Gateway', ike: 'IKE SA · control', child: 'Child SA · ESP', traffic: 'Traffic inside' };

const statusOf = (s: string): Status =>
  s === 'critical' || s === 'serious' || s === 'warning' || s === 'good' ? s : 'none';

function layout(nodes: Node[]) {
  const pos = new Map<string, { x: number; y: number; h: number }>();
  const columns = [0, 1, 2, 3].map((layer) => nodes.filter((n) => n.layer === layer));
  const heights = columns.map((col) => col.reduce((sum, n) => sum + HEIGHT[n.kind] + GAP, -GAP));
  const H = Math.max(260, ...heights) + 40;
  columns.forEach((col, layer) => {
    let y = (H - Math.max(0, heights[layer])) / 2;
    for (const n of col) {
      pos.set(n.id, { x: COL_X[layer], y, h: HEIGHT[n.kind] });
      y += HEIGHT[n.kind] + GAP;
    }
  });
  return { pos, H };
}

export default function Surface() {
  const id = useAnalysisId();
  const { intel, error } = useIntel(id);
  const [selected, setSelected] = useState<string | null>(null);
  const graph = useMemo(() => (intel ? layout(intel.surface.nodes) : null), [intel]);

  if (!id) return <Page title="Attack surface"><NoAnalysis /></Page>;
  if (error) return <Page title="Attack surface"><ErrorBanner message={error} /></Page>;
  if (!intel || !graph) return <Page title="Attack surface"><Loading /></Page>;

  const { nodes, edges, layers, hidden_tunnels } = intel.surface;
  const rank = ['critical', 'serious', 'warning', 'low', 'good', 'unknown'];
  const worst = [...nodes].sort((a, b) => rank.indexOf(a.status) - rank.indexOf(b.status) || b.risks.length - a.risks.length)[0];
  const node = nodes.find((n) => n.id === selected) ?? worst;
  const W = COL_X[3] + NODE_W;

  return (
    <Page title="Attack surface" subtitle="The deployment as the analyzer reconstructed it, from gateways to the traffic inside each tunnel, with every risk pinned where it applies"
      meta={<FingerprintBadge fp={intel.fingerprint} />}>
      <div className="stack">
        <Card title="Deployment map" subtitle="Select a node for its evidence. Borders carry the worst severity at that point; the teal flow is encrypted ESP.">
          <div className="surface-wrap">
            <svg className="surface" viewBox={`0 0 ${W} ${graph.H + 30}`} role="img" aria-label="Attack surface graph">
              {layers.map((label, i) => (
                <text key={label} x={COL_X[i] + NODE_W / 2} y={16} textAnchor="middle" className="surface-layer">{label.toUpperCase()}</text>
              ))}
              {edges.map((e, i) => {
                const a = graph.pos.get(e.from), b = graph.pos.get(e.to);
                if (!a || !b) return null;
                const x1 = a.x + NODE_W, y1 = a.y + a.h / 2 + 20, x2 = b.x, y2 = b.y + b.h / 2 + 20;
                const mid = (x1 + x2) / 2;
                const esp = e.label === 'ESP tunnel';
                return (
                  <g key={i}>
                    <path d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`} className={`edge ${esp ? 'edge-esp' : e.label ? 'edge-ike' : 'edge-leaf'}`} />
                    {e.label && <text x={mid} y={Math.min(y1, y2) - 8} textAnchor="middle" className="edge-label">{esp ? 'ESP' : 'IKE'}</text>}
                  </g>
                );
              })}
              {nodes.map((n) => {
                const p = graph.pos.get(n.id)!;
                const status = statusOf(n.status);
                return (
                  <foreignObject key={n.id} x={p.x} y={p.y + 20} width={NODE_W} height={p.h}>
                    <button className={`snode s-${status} ${node?.id === n.id ? 'selected' : ''} k-${n.kind}`}
                      onClick={() => setSelected(n.id)} aria-pressed={node?.id === n.id}>
                      <span className="snode-kind">
                        {n.kind === 'traffic' && <span className="swatch" style={{ background: classColor(n.class ?? '') }} />}
                        {KIND_LABEL[n.kind]}
                        <span className="snode-status" aria-label={n.status}>{STATUS_ICON[status]}</span>
                      </span>
                      <strong>{n.title}</strong>
                      <span className="snode-sub">{n.subtitle}</span>
                      {n.kind !== 'traffic' && <span className="snode-facts">{n.facts.slice(0, n.kind === 'ike' ? 5 : 4).join(' · ')}</span>}
                      {n.risks.length > 0 && <span className="snode-risks">{n.risks.length} risk{n.risks.length > 1 ? 's' : ''}</span>}
                    </button>
                  </foreignObject>
                );
              })}
            </svg>
          </div>
          <ul className="legend">
            {(['critical', 'serious', 'warning', 'none', 'good'] as Status[]).map((s) => (
              <li key={s}><span className={`swatch status-sw s-${s}`} /><span aria-hidden>{STATUS_ICON[s]}</span>
                {{ critical: 'Critical', serious: 'High', warning: 'Medium', none: 'Low / informational', good: 'No weakness' }[s as string]}</li>
            ))}
            <li><span className="legend-line enc" />ESP (encrypted)</li>
            <li><span className="legend-line clear" />IKE negotiation</li>
          </ul>
          {hidden_tunnels > 0 && <p className="hint">{hidden_tunnels} smaller tunnel(s) not drawn.</p>}
        </Card>

        {node && (
          <Card title={`Selected: ${node.title}`} subtitle={`${KIND_LABEL[node.kind]} · ${node.subtitle}`}>
            <div className="grid-3">
            <div>
            {node.facts.length > 0 && (<><h4 className="subhead">What was identified</h4>
              <div className="chips">{node.facts.map((f) => <span key={f} className="chip">{f}</span>)}</div></>)}
            </div>
            <div>
            <h4 className="subhead">Risks at this point</h4>
            {node.risks.length === 0 ? <p className="muted text-sm">None raised by the rule engine.</p> : (
              <ul className="plain-list">
                {node.risks.map((r) => (
                  <li key={r.id} className="row"><SeverityBadge severity={r.severity} />
                    <Link to={`/security?id=${id}&tab=findings`}>{r.id}</Link><span className="text-sm">{r.title}</span></li>
                ))}
              </ul>
            )}
            </div>
            <div>
            {node.strengths.length > 0 && (<><h4 className="subhead">Holding up</h4>
              <ul className="checklist">{node.strengths.map((s) => <li key={s}><span className="ck ck-ok">✓</span><span>{s}</span></li>)}</ul></>)}
            <div className="button-row mt-md">
              <Link className="btn btn-sm btn-primary" to={`/simulator?id=${id}&fix=1`}>Simulate fixes</Link>
              <Link className="btn btn-sm btn-secondary" to={`/security?id=${id}&tab=findings`}>Evidence chains</Link>
            </div>
            </div>
            </div>
          </Card>
        )}
      </div>
    </Page>
  );
}
