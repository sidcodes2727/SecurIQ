import { useState, type PointerEvent, type ReactNode } from 'react';
import { useTooltip } from '../hooks/useTooltip';
import { STATUS_ICON, TRAFFIC_CLASSES, TRAFFIC_LABELS, classColor, classInk, pct, type Status } from '../lib/format';
import type { ThreatMatrix, TrafficSummary } from '../types';

function TipRow({ color, value, label }: { color?: string; value: ReactNode; label: ReactNode }) {
  return (
    <div className="tip-row">
      {color && <span className="tip-key" style={{ background: color }} />}
      <strong>{value}</strong>
      <span className="tip-label">{label}</span>
    </div>
  );
}

// ---------------------------------------------------------------- bar list (single series)

export interface BarItem {
  key: string;
  label: ReactNode;
  value: number | null;
  display?: string;
  color?: string;
  note?: ReactNode;
}

/** Horizontal bars from one baseline. One series → one hue unless the color carries status. */
export function BarList({ items, max = 1, format = (v: number) => pct(v), emptyText = 'Not assessable' }: {
  items: BarItem[]; max?: number; format?: (v: number) => string; emptyText?: string;
}) {
  const { bind, node } = useTooltip();
  return (
    <div className="bar-list">
      {items.map((item) => {
        const width = item.value === null ? 0 : Math.max(0, item.value / max) * 100;
        const text = item.value === null ? emptyText : item.display ?? format(item.value);
        return (
          <div className="bar-row" key={item.key}>
            <div className="bar-label">{item.label}</div>
            <div className="bar-track" {...bind(<TipRow color={item.color ?? 'var(--series-1)'} value={text} label={item.label} />)}
              aria-label={`${typeof item.label === 'string' ? item.label : item.key}: ${text}`}>
              {item.value !== null && (
                <span className="bar-fill" style={{ width: `${width}%`, background: item.color ?? 'var(--series-1)' }} />
              )}
            </div>
            <div className="bar-value">{text}</div>
            {item.note && <div className="bar-note">{item.note}</div>}
          </div>
        );
      })}
      {node}
    </div>
  );
}

// ---------------------------------------------------------------- traffic share (part-to-whole)

export function ClassLegend({ classes }: { classes: readonly string[] }) {
  return (
    <ul className="legend">
      {classes.map((c) => (
        <li key={c}><span className="swatch" style={{ background: classColor(c) }} />{TRAFFIC_LABELS[c] ?? c}</li>
      ))}
    </ul>
  );
}

export function ShareBar({ mix }: { mix: Record<string, number> }) {
  const { bind, node } = useTooltip();
  const ordered = TRAFFIC_CLASSES.filter((c) => (mix[c] ?? 0) > 0);
  return (
    <div>
      <div className="share-bar" role="img"
        aria-label={ordered.map((c) => `${TRAFFIC_LABELS[c]} ${pct(mix[c])}`).join(', ')}>
        {ordered.map((c) => (
          <span key={c} className="share-seg" style={{ flexGrow: mix[c], background: classColor(c) }}
            {...bind(<TipRow color={classColor(c)} value={pct(mix[c], 1)} label={TRAFFIC_LABELS[c]} />)}>
            {mix[c] >= 0.14 && <span className="seg-label" style={{ color: classInk(c) }}>{pct(mix[c])}</span>}
          </span>
        ))}
      </div>
      <ul className="legend">
        {ordered.map((c) => (
          <li key={c}><span className="swatch" style={{ background: classColor(c) }} />
            {TRAFFIC_LABELS[c]} <span className="legend-value">{pct(mix[c])}</span></li>
        ))}
      </ul>
      {node}
    </div>
  );
}

// ---------------------------------------------------------------- per-tunnel timeline

export function TrafficTimeline({ flows }: { flows: TrafficSummary['flows'] }) {
  const { bind, node } = useTooltip();
  const present = TRAFFIC_CLASSES.filter((c) => flows.some((f) => f.timeline.some((w) => w.class === c)));
  return (
    <div className="timeline">
      {flows.map((flow) => {
        const t0 = flow.timeline[0]?.start ?? 0;
        return (
          <div className="timeline-row" key={flow.flow_id}>
            <div className="timeline-label" title={flow.flow_id}>
              <span className="mono">{flow.flow_id.length > 23 ? `${flow.flow_id.slice(0, 23)}…` : flow.flow_id}</span>
              <span className="muted">{flow.windows} windows</span>
            </div>
            <div className="timeline-strip">
              {flow.timeline.map((w) => (
                <span key={w.start} className={`timeline-cell ${w.uncertain ? 'uncertain' : ''}`}
                  style={{ background: classColor(w.class) }}
                  {...bind(<>
                    <TipRow color={classColor(w.class)} value={pct(w.confidence)} label={TRAFFIC_LABELS[w.class]} />
                    <div className="tip-sub">{Math.round(w.start - t0)}–{Math.round(w.end - t0)} s
                      {w.uncertain ? ' · below 50% confidence' : ''}</div>
                  </>)}>
                  {w.uncertain && <span className="cell-mark" aria-hidden>?</span>}
                </span>
              ))}
            </div>
          </div>
        );
      })}
      <ClassLegend classes={present} />
      <p className="hint">Each cell is a 10-second window; faded cells marked “?” fell below 50% confidence.</p>
      {node}
    </div>
  );
}

// ---------------------------------------------------------------- threat matrix

const zone = (risk: number): Status => (risk >= 20 ? 'critical' : risk >= 12 ? 'serious' : risk >= 6 ? 'warning' : 'good');
const ZONE_LABEL: Record<string, string> = { critical: 'Critical ≥ 20', serious: 'High 12–19', warning: 'Medium 6–11', good: 'Low < 6' };

export function ThreatMatrixGrid({ matrix }: { matrix: ThreatMatrix }) {
  const { bind, node } = useTooltip();
  const index = new Map(matrix.threats.map((t, i) => [t.id, i + 1]));
  return (
    <div>
      <div className="tm-grid" role="grid" aria-label="Threat matrix: likelihood by impact">
        {[5, 4, 3, 2, 1].map((likelihood) => (
          <div className="tm-row" role="row" key={likelihood}>
            <div className="tm-axis" role="rowheader">L{likelihood}</div>
            {[1, 2, 3, 4, 5].map((impact) => {
              const risk = likelihood * impact;
              const ids = matrix.grid[likelihood - 1][impact - 1];
              return (
                <div key={impact} role="gridcell" className={`tm-cell z-${zone(risk)}`}
                  aria-label={`Likelihood ${likelihood}, impact ${impact}, risk ${risk}: ${ids.length} threats`}>
                  {ids.map((id) => {
                    const threat = matrix.threats.find((t) => t.id === id)!;
                    return (
                      <span key={id} className="tm-chip" {...bind(<>
                        <TipRow value={`Risk ${threat.risk_score}`} label={threat.name} />
                        <div className="tip-sub">L{threat.likelihood} × I{threat.impact} · {threat.attack}</div>
                      </>)}>T{index.get(id)}</span>
                    );
                  })}
                </div>
              );
            })}
          </div>
        ))}
        <div className="tm-row">
          <div className="tm-axis" />
          {[1, 2, 3, 4, 5].map((i) => <div key={i} className="tm-axis">I{i}</div>)}
        </div>
      </div>
      <ul className="legend">
        {(['good', 'warning', 'serious', 'critical'] as Status[]).map((s) => (
          <li key={s}><span className={`swatch zone-swatch z-${s}`} /><span aria-hidden>{STATUS_ICON[s]}</span> {ZONE_LABEL[s]}</li>
        ))}
      </ul>
      <p className="hint">L = likelihood, I = impact (1–5); risk = L × I.</p>
      {node}
    </div>
  );
}

// ---------------------------------------------------------------- live throughput (single-series line)

function niceMax(value: number): number {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const step = [1, 2, 2.5, 5, 10].find((s) => s * magnitude >= value) ?? 10;
  return step * magnitude;
}

export function ThroughputChart({ points, unit = 'Mbit/s', value }: {
  points: { t: number; y: number }[]; unit?: string; value: (y: number) => string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 640, H = 190, L = 44, R = 12, T = 10, B = 26;
  if (points.length < 2) return <p className="muted">Waiting for traffic…</p>;
  const t0 = points[0].t, t1 = points[points.length - 1].t;
  const span = Math.max(1, t1 - t0);
  const max = niceMax(Math.max(...points.map((p) => p.y)));
  const x = (t: number) => L + ((t - t0) / span) * (W - L - R);
  const y = (v: number) => T + (1 - v / max) * (H - T - B);
  const path = points.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p.y).toFixed(1)}`).join(' ');
  const area = `${path} L${x(t1).toFixed(1)},${y(0)} L${x(t0).toFixed(1)},${y(0)} Z`;
  const ticks = [0, max / 2, max];
  const active = hover === null ? null : points[hover];

  const onMove = (e: PointerEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const t = t0 + ((e.clientX - rect.left) / rect.width * W - L) / (W - L - R) * span;
    let best = 0;
    points.forEach((p, i) => { if (Math.abs(p.t - t) < Math.abs(points[best].t - t)) best = i; });
    setHover(best);
  };

  return (
    <div className="line-chart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" tabIndex={0}
        aria-label={`Throughput over the last ${Math.round(span)} seconds, latest ${value(points[points.length - 1].y)} ${unit}`}
        onPointerMove={onMove} onPointerLeave={() => setHover(null)}
        onFocus={() => setHover(points.length - 1)} onBlur={() => setHover(null)}>
        {ticks.map((v) => (
          <g key={v}>
            <line x1={L} x2={W - R} y1={y(v)} y2={y(v)} className="grid-line" />
            <text x={L - 6} y={y(v) + 4} textAnchor="end" className="axis-text">{value(v)}</text>
          </g>
        ))}
        <text x={L} y={H - 6} className="axis-text">−{Math.round(span)} s</text>
        <text x={W - R} y={H - 6} textAnchor="end" className="axis-text">now</text>
        <path d={area} className="line-area" />
        <path d={path} className="line-path" />
        {active && (
          <g>
            <line x1={x(active.t)} x2={x(active.t)} y1={T} y2={H - B} className="crosshair" />
            <circle cx={x(active.t)} cy={y(active.y)} r={4} className="line-dot" />
          </g>
        )}
      </svg>
      {active && (
        <div className="line-readout"><strong>{value(active.y)} {unit}</strong>
          <span className="muted"> at −{Math.round(t1 - active.t)} s</span></div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- heatmap (confusion matrix)

export function ConfusionHeatmap({ labels, matrix }: { labels: string[]; matrix: number[][] }) {
  const { bind, node } = useTooltip();
  return (
    <div className="table-wrap">
      <table className="heatmap">
        <thead>
          <tr><th className="corner">true ↓ / predicted →</th>
            {labels.map((l) => <th key={l} title={TRAFFIC_LABELS[l]}>{l.replace('_', ' ')}</th>)}</tr>
        </thead>
        <tbody>
          {matrix.map((row, i) => {
            const total = row.reduce((a, b) => a + b, 0) || 1;
            return (
              <tr key={labels[i]}>
                <th>{labels[i].replace('_', ' ')}</th>
                {row.map((v, j) => {
                  const share = v / total;
                  return (
                    <td key={j} style={{ background: `color-mix(in srgb, var(--series-1) ${Math.round(share * 90)}%, transparent)` }}
                      className={share > 0.55 ? 'on-dark' : ''}
                      {...bind(<TipRow value={`${v} (${pct(share)})`} label={`true ${labels[i]} → predicted ${labels[j]}`} />)}>
                      {v || ''}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
      {node}
    </div>
  );
}
