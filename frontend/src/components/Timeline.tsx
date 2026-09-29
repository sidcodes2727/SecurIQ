import { useEffect, useMemo, useRef, useState, type PointerEvent as RPointerEvent } from 'react';
import { useTooltip } from '../hooks/useTooltip';
import { TRAFFIC_LABELS, classColor } from '../lib/format';
import type { Loose, Prediction } from '../types';

interface Ev { t: number; lane: string; kind: 'ike' | 'rekey' | 'sa' | 'window' | 'anomaly'; label: string; detail: string; frames?: number[]; end?: number; cls?: string; enc?: boolean }

const LABEL_W = 176, LANE_H = 34, AXIS_H = 26, MINI_H = 46, PAD_R = 12;

function useElementWidth() {
  const [el, setEl] = useState<HTMLDivElement | null>(null);
  const [w, setW] = useState(900);
  useEffect(() => {
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setW(e.contentRect.width));
    ro.observe(el);
    return () => ro.disconnect();
  }, [el]);
  return { ref: setEl, el, w };
}

function niceStep(span: number) {
  const raw = span / 8;
  const mag = 10 ** Math.floor(Math.log10(raw || 1));
  return [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? mag * 10;
}

export function InvestigationTimeline({ analysis, classification }: { analysis: Loose; classification: Prediction[] }) {
  const { bind, node } = useTooltip();
  const { ref, el, w } = useElementWidth();
  const t0: number = analysis.capture_start;
  const T: number = Math.max(1, analysis.capture_duration || 1);
  const [range, setRange] = useState<[number, number]>([0, T]);
  const [picked, setPicked] = useState<number | null>(null);
  const brush = useRef<{ mode: 'new' | 'move' | 'l' | 'r' | 'pan'; x0: number; r0: [number, number] } | null>(null);

  const { events, tunnels } = useMemo(() => {
    const out: Ev[] = [];
    for (const s of analysis.ike_analysis?.sessions ?? []) {
      for (const m of s.message_sizes ?? []) {
        const rekey = m.exchange === 'CREATE_CHILD_SA' || m.exchange === 'QUICK_MODE';
        out.push({ t: m.timestamp - t0, lane: 'IKE', kind: rekey ? 'rekey' : 'ike', enc: m.encrypted, frames: m.frames,
          label: `${m.exchange} ${m.is_response ? 'response' : 'request'}`,
          detail: `${m.length} B · ${m.encrypted ? 'encrypted' : `cleartext: ${(m.payloads ?? []).join(', ')}`}` });
      }
    }
    const tunnelsList: Loose[] = [...(analysis.esp_analysis?.tunnels ?? [])].sort((a, b) => a.first_seen - b.first_seen).slice(0, 10);
    for (const tn of tunnelsList) {
      out.push({ t: tn.first_seen - t0, end: tn.last_seen - t0, lane: tn.id, kind: 'sa', label: `Tunnel ${tn.spi_a} / ${tn.spi_b ?? '—'}`,
        detail: `${tn.packet_count.toLocaleString()} packets · ${tn.duration_seconds.toFixed(1)} s · ${tn.peer_a} ↔ ${tn.peer_b}` });
    }
    for (const w of classification) {
      out.push({ t: w.window_start - t0, end: w.window_end - t0, lane: w.flow_id, kind: 'window', cls: w.predicted_class,
        label: `${w.predicted_label} · ${Math.round(w.confidence * 100)}%`, detail: `${w.packet_count} packets${w.novel ? ' · novel pattern' : ''}${w.uncertain ? ' · uncertain' : ''}` });
    }
    for (const sa of analysis.esp_analysis?.sa_info ?? []) {
      for (const e of sa.replay?.events ?? []) {
        if (e.time === null || e.time === undefined) continue;
        out.push({ t: e.time - t0, lane: 'Anomalies', kind: 'anomaly', frames: e.frame ? [e.frame] : [],
          label: e.kind === 'duplicate' ? 'Replayed sequence number' : e.kind === 'reset' ? 'Counter reset' : 'Reordered beyond window',
          detail: `SA ${sa.spi} · seq ${e.seq} (highest seen ${e.expected_above})` });
      }
    }
    out.sort((a, b) => a.t - b.t);
    return { events: out, tunnels: tunnelsList };
  }, [analysis, classification, t0]);

  const lanes = ['IKE', ...tunnels.map((t) => t.id), ...(events.some((e) => e.kind === 'anomaly') ? ['Anomalies'] : [])];
  const plotW = Math.max(200, w - LABEL_W - PAD_R);
  const [r0, r1] = range;
  const x = (t: number) => LABEL_W + ((t - r0) / (r1 - r0)) * plotW;
  const mx = (t: number) => LABEL_W + (t / T) * plotW;
  const H = lanes.length * LANE_H + AXIS_H;
  const step = niceStep(r1 - r0);
  const ticks: number[] = [];
  for (let t = Math.ceil(r0 / step) * step; t <= r1; t += step) ticks.push(t);
  const inView = events.filter((e) => (e.end ?? e.t) >= r0 && e.t <= r1);
  const laneY = (lane: string) => lanes.indexOf(lane) * LANE_H;

  // density for the minimap
  const bins = 120;
  const density = new Array(bins).fill(0);
  for (const e of events) if (e.kind !== 'sa') density[Math.min(bins - 1, Math.floor((e.t / T) * bins))] += e.kind === 'window' ? 1 : 2;
  const dmax = Math.max(1, ...density);

  const clamp = (a: number, b: number): [number, number] => {
    const span = Math.max(0.5, Math.min(T, b - a));
    const start = Math.max(0, Math.min(T - span, a));
    return [start, start + span];
  };
  const zoom = (factor: number, center = (r0 + r1) / 2) => {
    const span = (r1 - r0) * factor;
    setRange(clamp(center - (center - r0) * factor, center - (center - r0) * factor + span));
  };

  // wheel zoom over the main plot (non-passive so the page does not scroll)
  useEffect(() => {
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      const svg = (e.target as Element).closest('svg.tl-main');
      if (!svg) return;
      e.preventDefault();
      const rect = svg.getBoundingClientRect();
      const px = e.clientX - rect.left;
      if (px < LABEL_W) return;
      const center = r0 + ((px - LABEL_W) / plotW) * (r1 - r0);
      const factor = Math.exp(e.deltaY * 0.0015);
      const span = Math.max(0.5, Math.min(T, (r1 - r0) * factor));
      const a = center - ((center - r0) / (r1 - r0)) * span;
      setRange(clamp(a, a + span));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  });

  const miniT = (clientX: number, rect: DOMRect) => Math.max(0, Math.min(T, ((clientX - rect.left - LABEL_W) / plotW) * T));
  const onMiniDown = (e: RPointerEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const t = miniT(e.clientX, rect);
    const hx0 = mx(r0), hx1 = mx(r1), px = e.clientX - rect.left;
    const full = r1 - r0 >= T - 0.01;   // nothing selected yet: any drag starts a new selection
    const mode = !full && Math.abs(px - hx0) < 7 ? 'l' : !full && Math.abs(px - hx1) < 7 ? 'r' : !full && t > r0 && t < r1 ? 'move' : 'new';
    brush.current = { mode, x0: t, r0: range };
    e.currentTarget.setPointerCapture(e.pointerId);
    if (mode === 'new') setRange(clamp(t, t + 0.5));
  };
  const onMiniMove = (e: RPointerEvent<SVGSVGElement>) => {
    const b = brush.current;
    if (!b) return;
    const t = miniT(e.clientX, e.currentTarget.getBoundingClientRect());
    const d = t - b.x0;
    if (b.mode === 'new') setRange(clamp(Math.min(b.x0, t), Math.max(b.x0, t)));
    else if (b.mode === 'move') setRange(clamp(b.r0[0] + d, b.r0[1] + d));
    else if (b.mode === 'l') setRange(clamp(Math.min(t, b.r0[1] - 0.5), b.r0[1]));
    else if (b.mode === 'r') setRange(clamp(b.r0[0], Math.max(t, b.r0[0] + 0.5)));
  };
  const onMainDown = (e: RPointerEvent<SVGSVGElement>) => {
    if ((e.target as Element).closest('[data-ev]')) return;
    brush.current = { mode: 'pan', x0: e.clientX, r0: range };
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const onMainMove = (e: RPointerEvent<SVGSVGElement>) => {
    const b = brush.current;
    if (!b || b.mode !== 'pan') return;
    const dt = -((e.clientX - b.x0) / plotW) * (b.r0[1] - b.r0[0]);
    setRange(clamp(b.r0[0] + dt, b.r0[1] + dt));
  };
  const endDrag = () => { brush.current = null; };

  const focusOn = (i: number) => {
    const e = events[i];
    setPicked(i);
    const span = Math.min(T, Math.max(6, (e.end ?? e.t) - e.t + 6));
    setRange(clamp(e.t - span / 2, e.t + span / 2));
  };
  const zoomed = r0 > 0.01 || r1 < T - 0.01;

  return (
    <div className="tl" ref={ref}>
      <div className="tl-toolbar">
        <span className="mono text-xs">{r0.toFixed(1)} s – {r1.toFixed(1)} s of {T.toFixed(1)} s</span>
        <span className="spacer" />
        <span className="muted text-xs">{inView.length} events in view</span>
        <button className="hud-btn" onClick={() => zoom(0.6)} aria-label="Zoom in">+</button>
        <button className="hud-btn" onClick={() => zoom(1 / 0.6)} aria-label="Zoom out">−</button>
        <button className="hud-btn wide" onClick={() => setRange([0, T])} disabled={!zoomed}>Reset</button>
      </div>
      <svg className="tl-main" width={w} height={H} role="img" aria-label={`Investigation timeline, ${events.length} events`}
        onPointerDown={onMainDown} onPointerMove={onMainMove} onPointerUp={endDrag} onPointerCancel={endDrag}>
        <defs><clipPath id="tl-clip"><rect x={LABEL_W} y={0} width={plotW} height={H} /></clipPath></defs>
        {lanes.map((lane, i) => {
          const tn = tunnels.find((t) => t.id === lane);
          return (
            <g key={lane}>
              <rect x={0} y={i * LANE_H} width={w} height={LANE_H} className={`tl-lane ${i % 2 ? 'odd' : ''}`} />
              <text x={10} y={i * LANE_H + 15} className="tl-lane-label">{lane === 'IKE' ? 'IKE control' : lane === 'Anomalies' ? 'Anomalies' : `Tunnel ${i}`}</text>
              <text x={10} y={i * LANE_H + 27} className="tl-lane-sub">{tn ? `${tn.spi_a.slice(0, 10)} · ${tn.packet_count.toLocaleString()} pkts`
                : lane === 'IKE' ? 'messages · rekeys' : 'replay · reset'}</text>
            </g>
          );
        })}
        <g clipPath="url(#tl-clip)">
          {ticks.map((t) => <line key={t} x1={x(t)} x2={x(t)} y1={0} y2={H - AXIS_H} className="grid-line" />)}
          {events.map((e, i) => {
            if ((e.end ?? e.t) < r0 || e.t > r1) return null;
            const y = laneY(e.kind === 'window' ? e.lane : e.lane);
            if (y < 0) return null;
            const common = { 'data-ev': i, onClick: () => setPicked(i), className: `tl-ev k-${e.kind} ${picked === i ? 'picked' : ''} ${e.enc ? 'enc' : ''}`,
              ...bind(<><div className="tip-row"><strong>{e.label}</strong></div>
                <div className="tip-sub">{e.t.toFixed(3)} s{e.end !== undefined ? ` – ${e.end.toFixed(1)} s` : ''} · {e.detail}{e.frames?.length ? ` · frame #${e.frames[0]}` : ''}</div></>) };
            if (e.kind === 'sa') return <rect key={i} {...common} x={x(e.t)} y={y + LANE_H - 9} width={Math.max(2, x(e.end!) - x(e.t))} height={4} />;
            if (e.kind === 'window') return <rect key={i} {...common} x={x(e.t) + 1} y={y + 7} width={Math.max(2, x(e.end!) - x(e.t) - 2)} height={14}
              style={{ fill: classColor(e.cls!) }} />;
            if (e.kind === 'anomaly') return <g key={i} {...common} transform={`translate(${x(e.t)},${y + LANE_H / 2})`}>
              <circle r={9} className="tl-hit" /><path d="M0,-6 L6,5 L-6,5 Z" className="tl-anom" /></g>;
            if (e.kind === 'rekey') return <g key={i} {...common} transform={`translate(${x(e.t)},${y + LANE_H / 2})`}>
              <circle r={9} className="tl-hit" /><rect x={-4.5} y={-4.5} width={9} height={9} transform="rotate(45)" className="tl-rekey" /></g>;
            return <g key={i} {...common} transform={`translate(${x(e.t)},${y + LANE_H / 2})`}>
              <circle r={8} className="tl-hit" /><rect x={-2} y={-8} width={4} height={16} className={e.enc ? 'tl-ike enc' : 'tl-ike'} /></g>;
          })}
        </g>
        {ticks.map((t) => <text key={t} x={x(t)} y={H - 8} textAnchor="middle" className="axis-text">{(r1 - r0) < 10 ? t.toFixed(1) : Math.round(t)} s</text>)}
      </svg>

      <svg className="tl-mini" width={w} height={MINI_H} role="img" aria-label="Timeline overview: drag to select a range"
        onPointerDown={onMiniDown} onPointerMove={onMiniMove} onPointerUp={endDrag} onPointerCancel={endDrag}
        onDoubleClick={() => setRange([0, T])}>
        <text x={10} y={20} className="tl-lane-label">Overview</text>
        <text x={10} y={33} className="tl-lane-sub">drag to zoom</text>
        {density.map((d, i) => d ? <rect key={i} x={LABEL_W + (i / bins) * plotW} y={MINI_H - 6 - (d / dmax) * (MINI_H - 14)}
          width={Math.max(1, plotW / bins - 1)} height={(d / dmax) * (MINI_H - 14)} className="tl-density" /> : null)}
        <rect x={mx(r0)} y={2} width={Math.max(2, mx(r1) - mx(r0))} height={MINI_H - 6} className="tl-brush" />
        <rect x={mx(r0) - 3} y={8} width={6} height={MINI_H - 18} className="tl-handle" />
        <rect x={mx(r1) - 3} y={8} width={6} height={MINI_H - 18} className="tl-handle" />
      </svg>

      <ul className="tl-legend legend">
        <li><span className="legend-line clear" />IKE cleartext</li><li><span className="legend-line enc" />IKE encrypted</li>
        <li><span aria-hidden className="cipher">◆</span> Child SA rekey</li><li><span aria-hidden className="sev-ic s-critical">▲</span> Replay anomaly</li>
        {[...new Set(classification.map((c) => c.predicted_class))].map((c) => (
          <li key={c}><span className="swatch" style={{ background: classColor(c) }} />{TRAFFIC_LABELS[c]}</li>))}
      </ul>

      <div className="tl-events">
        <table className="data-table">
          <thead><tr><th className="num">Time</th><th>Lane</th><th>Event</th><th>Detail</th><th className="num">Frame</th></tr></thead>
          <tbody>
            {inView.filter((e) => e.kind !== 'window' || inView.length < 80).slice(0, 120).map((e) => {
              const i = events.indexOf(e);
              return (
                <tr key={i} className={`clickable ${picked === i ? 'picked-row' : ''}`} onClick={() => focusOn(i)}>
                  <td className="num">{e.t.toFixed(2)} s</td>
                  <td className="text-xs">{e.lane === 'IKE' || e.lane === 'Anomalies' ? e.lane : `Tunnel ${lanes.indexOf(e.lane)}`}</td>
                  <td className="text-primary">{e.kind === 'window' && <span className="swatch" style={{ background: classColor(e.cls!) }} />}
                    {e.kind === 'anomaly' && <span aria-hidden className="sev-ic s-critical">▲ </span>}{e.label}</td>
                  <td className="text-xs">{e.detail}</td>
                  <td className="num">{e.frames?.length ? `#${e.frames[0]}` : '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {node}
    </div>
  );
}
