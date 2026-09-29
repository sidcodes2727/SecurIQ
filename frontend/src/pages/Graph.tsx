import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as RPointerEvent, type WheelEvent as RWheelEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Page } from '../components/Layout';
import { ErrorBanner, Loading, StatusPill } from '../components/ui';
import { rememberAnalysis } from '../hooks/useAnalysis';
import { ForceLayout } from '../lib/force';
import { STATUS_ICON, classColor, scoreStatus, severityStatus, type Status } from '../lib/format';
import { fuzzy } from '../lib/fuzzy';
import { api } from '../services/api';
import type { FleetGraph, GraphNode } from '../types';

type NodeType = GraphNode['type'];
const TYPES: { type: NodeType; label: string }[] = [
  { type: 'capture', label: 'Captures' }, { type: 'gateway', label: 'Gateways' }, { type: 'fingerprint', label: 'Fingerprints' },
  { type: 'finding', label: 'Findings' }, { type: 'traffic', label: 'Traffic' }, { type: 'config', label: 'Config values' },
];
const RADIUS: Record<NodeType, number> = { capture: 11, gateway: 10, fingerprint: 10, finding: 9, traffic: 7, config: 7 };
const LINK_LENGTH: Record<string, number> = { between: 200, 'has config': 120, raised: 150, carries: 160, uses: 130 };
const RING: Record<NodeType, number> = { capture: 0.6, gateway: 1.8, fingerprint: 1.3, finding: 2.2, traffic: 2.4, config: 2 };

const nodeStatus = (n: GraphNode): Status =>
  n.type === 'capture' ? scoreStatus(n.score ?? null) : n.type === 'finding' && n.severity ? severityStatus[n.severity] : 'none';

function explorerQuery(n: GraphNode): string | null {
  switch (n.type) {
    case 'gateway': return `gw:${n.label}`;
    case 'fingerprint': return `fp:${n.label}`;
    case 'finding': return `finding:${n.finding_id}`;
    case 'traffic': return `traffic:${n.traffic_class}`;
    case 'config': {
      const [, kind, value] = n.id.split(':');
      const v = value ?? '';
      if (kind === 'dh') return `dh:${v.split(' ')[1]}`;
      if (kind === 'pfs') return `pfs:${v.split(' ')[1]}`;
      if (kind === 'auth') return `auth:${v.split(' ')[1]}`;
      if (kind === 'esp') return `esp:"${v.replace('ESP ', '')}"`;
      if (kind === 'enc') return `enc:"${v}"`;
      if (kind === 'ike') return `ike:${v.split(' ')[0]}`;
      return null;
    }
    default: return null;
  }
}

function Shape({ n, status }: { n: Pick<GraphNode, 'type' | 'traffic_class'>; status: Status }) {
  const r = RADIUS[n.type];
  const statusVar = status === 'none' ? 'var(--fg-3)' : `var(--status-${status})`;
  switch (n.type) {
    case 'capture':
      return <>
        <rect x={-r} y={-r} width={r * 2} height={r * 2} className="g-capture" style={{ stroke: statusVar }} />
        <text className="g-glyph" style={{ fill: statusVar }} textAnchor="middle" dy="4">{STATUS_ICON[status]}</text>
      </>;
    case 'gateway': return <circle r={r} className="g-gateway" />;
    case 'fingerprint': {
      const pts = Array.from({ length: 6 }, (_, i) => `${Math.cos(Math.PI / 3 * i) * r},${Math.sin(Math.PI / 3 * i) * r}`).join(' ');
      return <polygon points={pts} className="g-fp" />;
    }
    case 'finding':
      return <>
        <rect x={-r * 0.75} y={-r * 0.75} width={r * 1.5} height={r * 1.5} transform="rotate(45)" className="g-finding" style={{ fill: statusVar }} />
        <text className="g-glyph dark" textAnchor="middle" dy="3.5">{STATUS_ICON[status]}</text>
      </>;
    case 'traffic': return <circle r={r} className="g-traffic" style={{ fill: classColor(n.traffic_class ?? '') }} />;
    default: return <rect x={-r} y={-r * 0.7} width={r * 2} height={r * 1.4} rx={2} className="g-config" />;
  }
}

function useSize() {
  const [el, setEl] = useState<HTMLDivElement | null>(null);
  const [size, setSize] = useState({ w: 900, h: 620 });
  useEffect(() => {
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => setSize({ w: entry.contentRect.width, h: entry.contentRect.height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, [el]);
  return { el, ref: setEl, size };
}

export default function Graph() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [graph, setGraph] = useState<FleetGraph | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [types, setTypes] = useState<Set<NodeType>>(new Set(['capture', 'gateway', 'fingerprint', 'finding', 'traffic']));
  const [lowFindings, setLowFindings] = useState(false);
  const [selected, setSelected] = useState<string | null>(params.get('focus'));
  const [hover, setHover] = useState<string | null>(null);
  const [isolate, setIsolate] = useState<0 | 1 | 2>(0);
  const [labels, setLabels] = useState<'auto' | 'all'>('auto');
  const [search, setSearch] = useState('');
  const [view, setView] = useState({ k: 1, tx: 450, ty: 310 });
  const [snap, setSnap] = useState<Map<string, { x: number; y: number; pinned: boolean }>>(new Map());
  const dirty = useRef(false);
  const layout = useRef<ForceLayout | null>(null);
  const positions = useRef(new Map<string, { x: number; y: number }>());
  const drag = useRef<{ kind: 'node' | 'pan'; id?: string; sx: number; sy: number; moved: boolean; tx: number; ty: number } | null>(null);
  const { el: box, ref: boxRef, size } = useSize();
  const fitted = useRef(false);

  useEffect(() => { api.fleetGraph().then(setGraph).catch((e) => setError(e.message)); }, []);

  const byId = useMemo(() => new Map((graph?.nodes ?? []).map((n) => [n.id, n])), [graph]);
  const adjacency = useMemo(() => {
    const adj = new Map<string, Set<string>>();
    const add = (a: string, b: string) => { if (!adj.has(a)) adj.set(a, new Set()); adj.get(a)!.add(b); };
    for (const e of graph?.edges ?? []) { add(e.source, e.target); add(e.target, e.source); }
    return adj;
  }, [graph]);

  const visible = useMemo(() => {
    if (!graph) return new Set<string>();
    let ids = graph.nodes.filter((n) => types.has(n.type) && (n.type !== 'finding' || lowFindings || n.severity !== 'Low')).map((n) => n.id);
    if (isolate && selected && byId.has(selected)) {
      const keep = new Set([selected]);
      let frontier = [selected];
      for (let hop = 0; hop < isolate; hop++) {
        const next: string[] = [];
        for (const id of frontier) for (const nb of adjacency.get(id) ?? []) if (!keep.has(nb)) { keep.add(nb); next.push(nb); }
        frontier = next;
      }
      ids = ids.filter((id) => keep.has(id));
      if (!ids.includes(selected)) ids.push(selected);
    }
    return new Set(ids);
  }, [graph, types, lowFindings, isolate, selected, byId, adjacency]);

  const edges = useMemo(() => (graph?.edges ?? []).filter((e) => visible.has(e.source) && visible.has(e.target)), [graph, visible]);

  // (re)build the layout whenever the visible set changes, keeping existing positions
  useEffect(() => {
    if (!graph) return;
    for (const n of layout.current?.nodes ?? []) positions.current.set(n.id, { x: n.x, y: n.y });
    const nodes = [...visible].map((id) => {
      const n = byId.get(id)!;
      return { id, r: RADIUS[n.type] + 4, mass: n.type === 'capture' ? 2.2 : 1 + Math.min(n.degree, 6) * 0.15, ring: RING[n.type] };
    });
    layout.current = new ForceLayout(nodes, edges.map((e) => ({ source: e.source, target: e.target, length: LINK_LENGTH[e.kind] ?? 100,
      strength: e.kind === 'between' ? 0.03 : 0.07 })), positions.current);
    layout.current.run(positions.current.size ? 60 : 320);
    dirty.current = true;
  }, [graph, visible, edges, byId]);

  // animate until the layout cools; each frame publishes a snapshot of positions for rendering
  useEffect(() => {
    let raf = 0;
    const loop = () => {
      const l = layout.current;
      if (l && (l.alpha > 0.01 || dirty.current)) {
        if (l.alpha > 0.01) { l.tick(); l.tick(); }
        dirty.current = false;
        setSnap(new Map(l.nodes.map((n) => [n.id, { x: n.x, y: n.y, pinned: n.fx !== null }])));
      }
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, []);

  const fit = useCallback((ids?: Set<string>, pad = 60) => {
    const l = layout.current;
    if (!l) return;
    const b = l.bounds(ids);
    const k = Math.min(2.2, Math.max(0.25, Math.min((size.w - pad * 2) / (b.x1 - b.x0 || 1), (size.h - pad * 2) / (b.y1 - b.y0 || 1))));
    setView({ k, tx: size.w / 2 - ((b.x0 + b.x1) / 2) * k, ty: size.h / 2 - ((b.y0 + b.y1) / 2) * k });
  }, [size]);

  useEffect(() => {
    if (!layout.current || fitted.current || !snap.size || size.w < 100) return;
    fitted.current = true;
    const focus = params.get('focus');
    if (focus && byId.has(focus)) {
      const nb = new Set([focus, ...(adjacency.get(focus) ?? [])]);
      fit(new Set([...nb].filter((id) => visible.has(id))), 120);
    } else fit();
  });

  const select = (id: string | null, center = false) => {
    setSelected(id);
    const p = new URLSearchParams(params);
    if (id) p.set('focus', id); else p.delete('focus');
    setParams(p, { replace: true });
    if (id && center) {
      const n = layout.current?.get(id);
      if (n) setView((v) => ({ ...v, tx: size.w / 2 - n.x * v.k, ty: size.h / 2 - n.y * v.k }));
    }
  };

  // ---- pointer interaction: pan, zoom, drag, click
  const onPointerDown = (e: RPointerEvent<SVGSVGElement>) => {
    const nodeEl = (e.target as Element).closest('[data-node]');
    e.currentTarget.setPointerCapture(e.pointerId);
    drag.current = nodeEl
      ? { kind: 'node', id: nodeEl.getAttribute('data-node')!, sx: e.clientX, sy: e.clientY, moved: false, tx: view.tx, ty: view.ty }
      : { kind: 'pan', sx: e.clientX, sy: e.clientY, moved: false, tx: view.tx, ty: view.ty };
  };
  const onPointerMove = (e: RPointerEvent<SVGSVGElement>) => {
    const d = drag.current;
    if (!d) return;
    if (Math.abs(e.clientX - d.sx) + Math.abs(e.clientY - d.sy) > 4) d.moved = true;
    if (!d.moved) return;
    if (d.kind === 'pan') setView((v) => ({ ...v, tx: d.tx + e.clientX - d.sx, ty: d.ty + e.clientY - d.sy }));
    else {
      const n = layout.current?.get(d.id!);
      if (n) {
        const rect = e.currentTarget.getBoundingClientRect();
        n.fx = (e.clientX - rect.left - view.tx) / view.k;
        n.fy = (e.clientY - rect.top - view.ty) / view.k;
        layout.current!.reheat(0.25);
        dirty.current = true;
      }
    }
  };
  const onPointerUp = () => {
    const d = drag.current;
    drag.current = null;
    if (d && !d.moved) select(d.kind === 'node' ? d.id! : null);
  };
  const onWheel = (e: RWheelEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    setView((v) => {
      const k = Math.min(4, Math.max(0.2, v.k * Math.exp(-e.deltaY * 0.0015)));
      return { k, tx: mx - ((mx - v.tx) / v.k) * k, ty: my - ((my - v.ty) / v.k) * k };
    });
  };
  const release = (id: string | null) => {
    const n = id ? layout.current?.get(id) : null;
    if (n) { n.fx = null; n.fy = null; layout.current!.reheat(0.2); }
  };
  const relayout = () => {
    positions.current.clear();
    layout.current = null;
    fitted.current = false;
    setTypes(new Set(types));
  };
  const zoomBy = (factor: number) => setView((v) => {
    const k = Math.min(4, Math.max(0.2, v.k * factor));
    return { k, tx: size.w / 2 - ((size.w / 2 - v.tx) / v.k) * k, ty: size.h / 2 - ((size.h / 2 - v.ty) / v.k) * k };
  });

  // keep the page from scrolling while the wheel zooms the canvas
  useEffect(() => {
    if (!box) return;
    const stop = (e: WheelEvent) => e.preventDefault();
    box.addEventListener('wheel', stop, { passive: false });
    return () => box.removeEventListener('wheel', stop);
  }, [box]);

  const matches = useMemo(() => {
    if (!graph || !search.trim()) return [];
    return graph.nodes.map((n) => ({ n, m: fuzzy(search, n.label) ?? fuzzy(search, `${n.label} ${n.sub ?? ''}`) }))
      .filter((x) => x.m).sort((a, b) => b.m!.score - a.m!.score).slice(0, 8).map((x) => x.n);
  }, [graph, search]);

  const insights = useMemo(() => {
    if (!graph) return [];
    const out: { id: string; text: string; status: Status }[] = [];
    const findings = graph.nodes.filter((n) => n.type === 'finding' && n.captures.length > 1 && n.severity && ['Critical', 'High'].includes(n.severity))
      .sort((a, b) => b.captures.length - a.captures.length);
    for (const f of findings.slice(0, 2)) out.push({ id: f.id, status: severityStatus[f.severity!], text: `${f.label} recurs in ${f.captures.length} captures` });
    for (const gw of graph.nodes.filter((n) => n.type === 'gateway')) {
      const fps = new Set(graph.edges.filter((e) => e.target.startsWith('fingerprint:') && gw.captures.includes(e.source.slice(8))).map((e) => e.target));
      if (fps.size > 1) out.push({ id: gw.id, status: 'warning', text: `Gateway ${gw.label} seen with ${fps.size} different configurations` });
    }
    const shared = graph.nodes.filter((n) => n.type === 'fingerprint' && n.captures.length > 1).sort((a, b) => b.captures.length - a.captures.length);
    for (const fp of shared.slice(0, 1)) out.push({ id: fp.id, status: 'none', text: `Configuration ${fp.label} shared by ${fp.captures.length} captures` });
    return out.slice(0, 4);
  }, [graph]);

  if (error) return <Page title="Link graph"><ErrorBanner message={error} /></Page>;
  if (!graph) return <Page title="Link graph"><Loading label="Building the graph…" /></Page>;

  const sel = selected ? byId.get(selected) : null;
  const focusSet = new Set<string>();
  const anchor = hover ?? selected;
  if (anchor) { focusSet.add(anchor); for (const nb of adjacency.get(anchor) ?? []) focusSet.add(nb); }
  const matchSet = new Set(matches.map((n) => n.id));
  // labels: everything once zoomed in; otherwise the objects that matter most, plus whatever is in focus
  const showLabel = (n: GraphNode) => labels === 'all' || view.k >= 1.3 || focusSet.has(n.id) || matchSet.has(n.id)
    || (!anchor && (n.type === 'gateway' || n.type === 'capture' || (n.type === 'finding' && n.captures.length > 2 && n.severity !== 'Low')));

  // greedy label placement in screen space: higher-priority labels first, skip any that would overlap
  const labelled = new Set<string>();
  {
    const prio = (n: GraphNode) => (n.id === selected ? 0 : n.id === hover ? 1 : focusSet.has(n.id) ? 2 : matchSet.has(n.id) ? 3
      : n.type === 'gateway' ? 4 : n.type === 'finding' ? 5 : n.type === 'fingerprint' ? 6 : n.type === 'capture' ? 7 : 8) - Math.min(n.degree, 9) * 0.01;
    const boxes: [number, number, number, number][] = [];
    const candidates = [...visible].map((id) => byId.get(id)!).filter((n) => showLabel(n)).sort((a, b) => prio(a) - prio(b));
    for (const n of candidates) {
      const p = snap.get(n.id);
      if (!p) continue;
      const text = n.label.length > 26 ? 26 : n.label.length;
      const w = text * 6.1 * view.k, h = 12 * view.k;
      const cx = p.x * view.k + view.tx, cy = (p.y + RADIUS[n.type] + 10) * view.k + view.ty;
      const box: [number, number, number, number] = [cx - w / 2 - 2, cy - h / 2, cx + w / 2 + 2, cy + h / 2];
      const forced = n.id === selected || n.id === hover;
      if (!forced && boxes.some((b) => box[0] < b[2] && box[2] > b[0] && box[1] < b[3] && box[3] > b[1])) continue;
      boxes.push(box);
      labelled.add(n.id);
    }
  }

  const linked = sel ? [...(adjacency.get(sel.id) ?? [])].map((id) => byId.get(id)!).filter(Boolean) : [];
  const linkedByType = TYPES.map((t) => ({ ...t, items: linked.filter((n) => n.type === t.type) })).filter((g) => g.items.length);
  const q = sel ? explorerQuery(sel) : null;
  const reveal = (n: GraphNode) => { if (!visible.has(n.id)) setTypes(new Set([...types, n.type])); select(n.id, true); };

  return (
    <Page title="Link graph" wide subtitle="Every capture linked to its gateways, configuration, findings and traffic. Shared nodes expose patterns: one weak configuration across many tunnels, a gateway whose configuration drifted, a finding that recurs.">
      <div className="graph-toolbar">
        <div className="type-toggles" role="group" aria-label="Object types">
          {TYPES.map((t) => {
            const on = types.has(t.type);
            return (
              <button key={t.type} className={`type-toggle t-${t.type} ${on ? 'on' : ''}`} aria-pressed={on}
                onClick={() => { const next = new Set(types); if (on) next.delete(t.type); else next.add(t.type); setTypes(next); }}>
                <svg width="14" height="14" viewBox="-8 -8 16 16" aria-hidden><Shape n={{ type: t.type, traffic_class: 'web' }} status="none" /></svg>
                {t.label}<span className="count">{graph.counts[t.type] ?? 0}</span>
              </button>
            );
          })}
          <label className="check"><input type="checkbox" checked={lowFindings} onChange={(e) => setLowFindings(e.target.checked)} />Low findings</label>
        </div>
        <div className="graph-search">
          <input type="text" value={search} placeholder="Find an object…" aria-label="Find an object in the graph"
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && matches[0]) { reveal(matches[0]); setSearch(''); } if (e.key === 'Escape') setSearch(''); }} />
          {matches.length > 0 && (
            <ul className="graph-matches" role="listbox">
              {matches.map((n) => (
                <li key={n.id}><button onClick={() => { reveal(n); setSearch(''); }}>
                  <span className={`tchip t-${n.type}`}>{n.type}</span><span className="ellipsis">{n.label}</span></button></li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="graph-layout">
        <div className="graph-canvas" ref={boxRef}>
          <svg width={size.w} height={size.h} className="graph-svg" role="img" aria-label={`Link graph: ${visible.size} objects, ${edges.length} links`}
            onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onWheel={onWheel}
            onDoubleClick={(e) => release((e.target as Element).closest('[data-node]')?.getAttribute('data-node') ?? null)}>
            <defs>
              <pattern id="gdots" width="24" height="24" patternUnits="userSpaceOnUse">
                <circle cx="1" cy="1" r="1" fill="var(--line-2)" />
              </pattern>
            </defs>
            <rect width={size.w} height={size.h} fill="url(#gdots)" />
            {snap.size > 0 && (
              <g transform={`translate(${view.tx},${view.ty}) scale(${view.k})`}>
                {edges.map((e, i) => {
                  const s = snap.get(e.source), t = snap.get(e.target);
                  if (!s || !t) return null;
                  const on = anchor ? (e.source === anchor || e.target === anchor) : false;
                  return <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                    className={`g-edge k-${e.kind.replace(' ', '-')} ${on ? 'on' : anchor ? 'dim' : ''}`} />;
                })}
                {[...visible].map((id) => {
                  const n = byId.get(id)!;
                  const p = snap.get(id);
                  if (!p) return null;
                  const status = nodeStatus(n);
                  const dim = anchor && !focusSet.has(id);
                  return (
                    <g key={id} data-node={id} transform={`translate(${p.x},${p.y})`}
                      className={`g-node t-${n.type} ${selected === id ? 'selected' : ''} ${dim ? 'dim' : ''} ${matchSet.has(id) ? 'match' : ''} ${p.pinned ? 'pinned' : ''}`}
                      onPointerEnter={() => setHover(id)} onPointerLeave={() => setHover(null)}>
                      <circle r={RADIUS[n.type] + 7} className="g-halo" />
                      <Shape n={n} status={status} />
                      {labelled.has(id) && <text className="g-label" y={RADIUS[n.type] + 13} textAnchor="middle">
                        {n.label.length > 26 ? `${n.label.slice(0, 25)}…` : n.label}</text>}
                    </g>
                  );
                })}
              </g>
            )}
          </svg>
          <div className="graph-hud">
            <span>{visible.size} objects · {edges.length} links</span>
            <span className="spacer" />
            <button className="hud-btn" onClick={() => zoomBy(1.25)} aria-label="Zoom in">+</button>
            <button className="hud-btn" onClick={() => zoomBy(0.8)} aria-label="Zoom out">−</button>
            <button className="hud-btn wide" onClick={() => fit(isolate && selected ? visible : undefined)}>Fit</button>
            <button className="hud-btn wide" onClick={relayout}>Re-layout</button>
            <button className={`hud-btn wide ${labels === 'all' ? 'on' : ''}`} aria-pressed={labels === 'all'}
              onClick={() => setLabels(labels === 'all' ? 'auto' : 'all')}>Labels</button>
          </div>
          <div className="graph-hint">Drag to pan · wheel to zoom · drag a node to pin it, double-click to release · click to inspect</div>
        </div>

        <aside className="inspector" aria-label="Object inspector">
          {!sel ? (
            <div className="inspector-empty">
              <span className="tile-label">Inspector</span>
              <p>Select any object to see its properties and everything it links to.</p>
              {insights.length > 0 && (
                <div className="graph-insights">
                  <span className="tile-label nomb">Patterns found</span>
                  {insights.map((ins) => (
                    <button key={ins.id} className="insight" onClick={() => reveal(byId.get(ins.id)!)}>
                      <span aria-hidden className={`sev-ic s-${ins.status}`}>{STATUS_ICON[ins.status]}</span>{ins.text}
                    </button>
                  ))}
                </div>
              )}
              <span className="tile-label mt-md">Legend</span>
              <ul className="legend vertical">
                <li><svg width="14" height="14" viewBox="-8 -8 16 16" aria-hidden><rect x="-6" y="-6" width="12" height="12" className="g-capture" style={{ stroke: 'var(--fg-3)' }} /></svg>Capture: ring and glyph show its risk</li>
                <li><svg width="14" height="14" viewBox="-8 -8 16 16" aria-hidden><circle r="6" className="g-gateway" /></svg>Gateway (VPN peer)</li>
                <li><svg width="14" height="14" viewBox="-8 -8 16 16" aria-hidden><polygon points="6,0 3,5.2 -3,5.2 -6,0 -3,-5.2 3,-5.2" className="g-fp" /></svg>Configuration fingerprint</li>
                <li><svg width="14" height="14" viewBox="-8 -8 16 16" aria-hidden><rect x="-4.5" y="-4.5" width="9" height="9" transform="rotate(45)" className="g-finding" style={{ fill: 'var(--status-serious)' }} /></svg>Finding: colour and glyph show worst severity</li>
                <li><span className="swatch" style={{ background: classColor('voip') }} />Traffic class inside tunnels</li>
                <li><svg width="14" height="14" viewBox="-8 -8 16 16" aria-hidden><rect x="-6" y="-4" width="12" height="8" rx="2" className="g-config" /></svg>Configuration value (DH, cipher, PFS…)</li>
              </ul>
            </div>
          ) : (
            <div className="inspector-body">
              <div className="row"><span className={`tchip t-${sel.type}`}>{sel.type}</span>
                {sel.type === 'capture' && <StatusPill status={nodeStatus(sel)} label={String(sel.props.Risk ?? '')} />}
                {sel.type === 'finding' && sel.severity && <StatusPill status={severityStatus[sel.severity]} label={sel.severity} />}
                <span className="spacer" /><button className="btn btn-sm btn-ghost" onClick={() => select(null)} aria-label="Close inspector">✕</button></div>
              <h3 className="inspector-title">{sel.label}</h3>
              {sel.sub && <p className="muted text-sm">{sel.sub}</p>}
              <dl className="kv mt-md">{Object.entries(sel.props).map(([k, v]) => (
                <div className="kv-row" key={k}><dt>{k}</dt><dd>{String(v ?? '—')}</dd></div>))}</dl>
              <div className="button-row mt-md">
                <button className={`btn btn-sm ${isolate ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setIsolate(isolate === 0 ? 1 : isolate === 1 ? 2 : 0)}>
                  {isolate === 0 ? 'Isolate neighbourhood' : isolate === 1 ? 'Expand to 2 hops' : 'Show everything'}</button>
                {sel.analysis_id && <>
                  <button className="btn btn-sm btn-primary" onClick={() => { rememberAnalysis(sel.analysis_id!); navigate(`/security?id=${sel.analysis_id}`); }}>Open assessment</button>
                  <Link className="btn btn-sm btn-secondary" to={`/simulator?id=${sel.analysis_id}&fix=1`} onClick={() => rememberAnalysis(sel.analysis_id!)}>Simulate fixes</Link>
                </>}
                {sel.type === 'finding' && <Link className="btn btn-sm btn-primary" to={`/inbox?finding=${sel.finding_id}`}>Triage</Link>}
                {q && <Link className="btn btn-sm btn-secondary" to={`/explorer?q=${encodeURIComponent(q)}`}>Open in explorer</Link>}
                {sel.type === 'gateway' && sel.captures.length > 1 && <Link className="btn btn-sm btn-secondary" to={`/drift?id=${sel.captures[0]}`}>Drift</Link>}
              </div>
              <h4 className="subhead">Linked objects · {linked.length}</h4>
              {linkedByType.map((g) => (
                <div key={g.type} className="linked-group">
                  <span className="muted text-xs">{g.label} ({g.items.length})</span>
                  <ul>{g.items.slice(0, 12).map((n) => {
                    const s = nodeStatus(n);
                    return (
                      <li key={n.id}><button onClick={() => reveal(n)}>
                        {s !== 'none' && <span aria-hidden className={`sev-ic s-${s}`}>{STATUS_ICON[s]}</span>}
                        {n.type === 'traffic' && <span className="swatch" style={{ background: classColor(n.traffic_class ?? '') }} />}
                        <span className="ellipsis">{n.label}</span></button></li>
                    );
                  })}{g.items.length > 12 && <li className="muted text-xs">+{g.items.length - 12} more</li>}</ul>
                </div>
              ))}
            </div>
          )}
        </aside>
      </div>
    </Page>
  );
}
