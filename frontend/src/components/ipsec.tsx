import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTooltip } from '../hooks/useTooltip';
import { STATUS_ICON, pct, score, scoreStatus, severityStatus } from '../lib/format';
import type { Check, EvidenceChain, Fingerprint, Loose, Posture } from '../types';
import { SeverityBadge, SourceBadge, StatusPill } from './ui';

const frameList = (frames: number[]) => {
  if (!frames.length) return null;
  const sorted = [...frames].sort((a, b) => a - b);
  const contiguous = sorted.every((f, i) => i === 0 || f === sorted[i - 1] + 1);
  return contiguous && sorted.length > 2 ? `#${sorted[0]}–#${sorted[sorted.length - 1]}` : sorted.slice(0, 6).map((f) => `#${f}`).join(' ');
};

// ---------------------------------------------------------------- checklists

export function Checklist({ checks, caveats = [] }: { checks: Check[]; caveats?: string[] }) {
  return (
    <ul className="checklist">
      {checks.map((c, i) => (
        <li key={`c${i}`}>
          <span className={`ck ${c.ok === true ? 'ck-ok' : c.ok === false ? 'ck-bad' : 'ck-na'}`} aria-label={c.ok === true ? 'supports' : c.ok === false ? 'against' : 'neutral'}>
            {c.ok === true ? '✓' : c.ok === false ? '✕' : '·'}</span>
          <span>{c.text}</span>
        </li>
      ))}
      {caveats.map((c, i) => (
        <li key={`w${i}`}><span className="ck ck-warn" aria-label="limitation">!</span><span>{c}</span></li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------- evidence chain

export function EvidenceChainView({ chain }: { chain: EvidenceChain }) {
  const status = severityStatus[chain.risk.severity];
  return (
    <ol className="chain" aria-label={`Evidence chain for ${chain.finding_id}`}>
      <li className="chain-step">
        <span className="chain-n">01 · Packet</span>
        {chain.packets.length ? chain.packets.map((p, i) => (
          <div key={i} className="chain-body">
            <strong>{p.label}</strong>
            <span className="muted text-xs">{p.detail}</span>
            {p.frames.length > 0 && <span className="chain-frames">frames {frameList(p.frames)}</span>}
            {p.encrypted !== undefined && <span className={`chip ${p.encrypted ? 'chip-enc' : 'chip-clear'}`}>{p.encrypted ? 'encrypted' : 'cleartext'}</span>}
          </div>
        )) : <span className="muted text-xs">Derived from capture-wide statistics</span>}
      </li>
      <li className="chain-step">
        <span className="chain-n">02 · Parameter</span>
        {chain.parameters.length ? chain.parameters.map((p, i) => (
          <div key={i} className="chain-body">
            <span className="muted text-xs">{p.label}</span>
            <strong>{p.value}</strong>
            {p.source && p.source !== 'simulated' && <SourceBadge source={p.source as 'observed'} confidence={p.confidence} />}
          </div>
        )) : <span className="muted text-xs">—</span>}
      </li>
      <li className="chain-step">
        <span className="chain-n">03 · Rule</span>
        <div className="chain-body"><strong>{chain.rule.statement}</strong><span className="muted text-xs mono">{chain.rule.reference}</span></div>
      </li>
      <li className={`chain-step risk s-${status}`}>
        <span className="chain-n">04 · Risk</span>
        <div className="chain-body"><SeverityBadge severity={chain.risk.severity} /><span className="text-xs">{chain.risk.impact}</span></div>
      </li>
      <li className="chain-step fix">
        <span className="chain-n">05 · Fix</span>
        <div className="chain-body"><strong>{chain.recommendation}</strong></div>
      </li>
    </ol>
  );
}

// ---------------------------------------------------------------- posture explanation

export function PostureCard({ posture, analysisId, compact }: { posture: Posture; analysisId?: string; compact?: boolean }) {
  const status = scoreStatus(posture.score);
  return (
    <div className={`posture ${compact ? 'compact' : ''}`}>
      <div className="posture-risk">
        <span className="tile-label">Risk</span>
        <div className={`posture-level s-${status}`}><span aria-hidden>{STATUS_ICON[status]}</span>{posture.headline}</div>
        <div className="posture-score">{score(posture.score)}<span className="hero-unit">/100</span></div>
        {posture.cap && <span className="muted text-xs">{posture.cap}</span>}
      </div>
      <div className="posture-body">
        <div className="posture-row">
          <span className="tile-label">Evidence</span>
          <div className="posture-evidence">
            {posture.evidence.length === 0 ? <span className="muted">No weakness in the observable configuration.</span>
              : posture.evidence.map((e, i) => (
                <span key={i} className={`evidence-chip s-${severityStatus[e.severity]}`} title={`${e.finding} · ${e.severity}`}>
                  <span aria-hidden className="pill-icon">{STATUS_ICON[severityStatus[e.severity]]}</span>{e.text}
                  {e.source === 'inferred' && <em> · inferred {pct(e.confidence)}</em>}
                </span>
              ))}
          </div>
        </div>
        <div className="posture-row"><span className="tile-label">Impact</span><p>{posture.impact}</p></div>
        <div className="posture-row">
          <span className="tile-label">Recommendation</span>
          <ol className="posture-recs">{posture.recommendations.map((r) => <li key={r}>{r}</li>)}</ol>
        </div>
        {analysisId && !compact && (
          <div className="button-row">
            <Link className="btn btn-sm btn-secondary" to={`/security?id=${analysisId}&tab=findings`}>Evidence chains</Link>
            <Link className="btn btn-sm btn-primary" to={`/simulator?id=${analysisId}&fix=1`}>Simulate the fix</Link>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- fingerprint

export function FingerprintBadge({ fp, large }: { fp: Fingerprint; large?: boolean }) {
  return (
    <div className={`fp-badge ${large ? 'large' : ''}`} title={`sha256 ${fp.sha256}`}>
      <span className="fp-label">IPSEC-FP</span>
      <span className="fp-id">{fp.id}</span>
      {large && <span className="fp-desc">{fp.label}</span>}
      {large && <span className="muted text-xs">{fp.observed_components}/{fp.total_components} components observed</span>}
    </div>
  );
}

// ---------------------------------------------------------------- IKE ladder (sequence diagram)

export function IkeLadder({ session, start }: { session: Loose; start: number }) {
  const { bind, node } = useTooltip();
  const msgs: Loose[] = (session?.message_sizes ?? []).slice(0, 28);
  if (!msgs.length) return <p className="muted">No IKE messages.</p>;
  const W = 760, lane = 150, L = lane, R = W - lane, top = 46, row = 38;
  const H = top + msgs.length * row + 18;
  return (
    <div className="ladder">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`IKE message sequence: ${msgs.length} messages`}>
        <text x={L} y={16} textAnchor="middle" className="ladder-head">INITIATOR</text>
        <text x={L} y={30} textAnchor="middle" className="ladder-ip">{session.initiator_ip}</text>
        <text x={R} y={16} textAnchor="middle" className="ladder-head">RESPONDER</text>
        <text x={R} y={30} textAnchor="middle" className="ladder-ip">{session.responder_ip}</text>
        <line x1={L} x2={L} y1={36} y2={H - 6} className="ladder-lane" />
        <line x1={R} x2={R} y1={36} y2={H - 6} className="ladder-lane" />
        {msgs.map((m, i) => {
          const y = top + i * row + 14;
          const fromI = m.from_initiator;
          const x1 = fromI ? L : R, x2 = fromI ? R - 6 : L + 6;
          const enc = m.encrypted;
          const label = `${m.exchange}${m.is_response ? ' ←' : ''}`;
          const payloads: string[] = m.payloads ?? [];
          return (
            <g key={i} className={`ladder-msg ${enc ? 'enc' : 'clear'}`} {...bind(<>
              <div className="tip-row"><strong>{m.exchange} {m.is_response ? 'response' : 'request'}</strong></div>
              <div className="tip-sub">{m.length} B · {enc ? 'encrypted (SK payload)' : `cleartext: ${payloads.join(', ')}`}
                {m.fragments ? ` · ${m.fragments} fragments` : ''}{m.frames?.length ? ` · frames ${frameList(m.frames)}` : ''}</div>
            </>)}>
              <rect x={0} y={y - 16} width={W} height={row - 4} className="ladder-hit" />
              <text x={8} y={y + 4} className="ladder-time">{(m.timestamp - start).toFixed(2)}s</text>
              <line x1={x1} x2={x2} y1={y} y2={y} className="ladder-arrow" markerEnd={enc ? 'url(#arrow-enc)' : 'url(#arrow-clear)'} />
              <text x={(L + R) / 2} y={y - 6} textAnchor="middle" className="ladder-label">{label}</text>
              <text x={(L + R) / 2} y={y + 13} textAnchor="middle" className="ladder-sub">
                {enc ? `▣ encrypted · ${m.length} B` : `${payloads.slice(0, 5).join(' · ')} · ${m.length} B`}</text>
              {m.frames?.length > 0 && <text x={W - 8} y={y + 4} textAnchor="end" className="ladder-time">#{m.frames[0]}</text>}
            </g>
          );
        })}
        <defs>
          <marker id="arrow-enc" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0L8 4L0 8z" className="ladder-head-enc" /></marker>
          <marker id="arrow-clear" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0L8 4L0 8z" className="ladder-head-clear" /></marker>
        </defs>
      </svg>
      <ul className="legend">
        <li><span className="legend-line clear" />Cleartext (readable by any observer)</li>
        <li><span className="legend-line enc" />Encrypted (SK payload)</li>
      </ul>
      {(session.message_sizes?.length ?? 0) > msgs.length && <p className="hint">First {msgs.length} of {session.message_sizes.length} messages.</p>}
      {node}
    </div>
  );
}

// ---------------------------------------------------------------- ESP packet anatomy

interface Field { label: string; bytes: string; kind: 'clear' | 'enc' | 'tag'; grow?: number; note?: string }

export function EspAnatomy({ fp, mode, ipVersion, natT, avgLen }: {
  fp: Loose; mode?: string | null; ipVersion?: string | null; natT?: boolean; avgLen?: number;
}) {
  const identified = fp?.status === 'identified';
  const iv = identified ? `${fp.iv_len} B` : '? B';
  const icv = identified ? `${(fp.icv_len_candidates ?? []).join('/')} B` : '? B';
  const block = identified ? fp.block_size : null;
  const outer = ipVersion === 'IPv6' ? '40 B' : '20 B';
  const fields: Field[] = [
    { label: `Outer ${ipVersion ?? 'IP'}`, bytes: outer, kind: 'clear', note: 'gateway addresses' },
    ...(natT ? [{ label: 'UDP 4500', bytes: '8 B', kind: 'clear' as const, note: 'NAT-T' }] : []),
    { label: 'SPI', bytes: '4 B', kind: 'clear', note: 'identifies the SA' },
    { label: 'Seq', bytes: '4 B', kind: 'clear', note: 'anti-replay counter' },
    { label: 'IV', bytes: iv, kind: 'clear', note: identified ? 'size from residue' : 'unknown' },
    { label: mode === 'Transport' ? 'TCP/UDP + data' : mode === 'Tunnel' ? 'Inner IP + TCP/UDP + data' : 'Inner packet', bytes: 'variable', kind: 'enc', grow: 6, note: 'encrypted' },
    { label: 'Pad · len · NH', bytes: block ? `→ ${block}-B blocks` : '0–255 B', kind: 'enc', grow: 1.4, note: 'encrypted trailer' },
    { label: 'ICV', bytes: icv, kind: 'tag', note: 'integrity tag' },
  ];
  return (
    <div className="anatomy">
      <div className="anatomy-strip" role="img" aria-label="ESP packet layout as inferred from lengths">
        {fields.map((f) => (
          <div key={f.label} className={`af af-${f.kind}`} style={{ flexGrow: f.grow ?? 1 }}>
            <span className="af-label">{f.label}</span><span className="af-bytes">{f.bytes}</span>
          </div>
        ))}
      </div>
      <div className="anatomy-scale">
        <span className="clear-range">◀ visible to an observer ▶</span>
        <span className="enc-range">◀ encrypted ▶</span>
        <span className="tag-range">auth</span>
      </div>
      {identified && (
        <p className="anatomy-eq mono">
          ESP payload length = IV({fp.iv_len}) + ⌈(inner + 2) / {block}⌉·{block} + ICV({(fp.icv_len_candidates ?? []).join('|')})
          {avgLen ? ` · mean ${avgLen.toFixed(0)} B` : ''}
        </p>
      )}
      {!identified && <p className="hint">{fp?.evidence ?? 'Framing not identified.'}</p>}
    </div>
  );
}

// ---------------------------------------------------------------- replay / sequence-number chart

export function ReplayChart({ sa }: { sa: Loose }) {
  const trace: [number, number, number][] = sa?.replay?.trace ?? [];
  const events: Loose[] = sa?.replay?.events ?? [];
  const [hover, setHover] = useState<number | null>(null);
  if (trace.length < 2) return <p className="muted">Too few packets to plot.</p>;
  const W = 720, H = 220, L = 58, R = 14, T = 12, B = 28;
  const maxI = trace[trace.length - 1][0] || 1;
  const maxS = Math.max(...trace.map((p) => p[1]), 1);
  const x = (i: number) => L + (i / maxI) * (W - L - R);
  const y = (s: number) => T + (1 - s / maxS) * (H - T - B);
  const eventIdx = new Set(events.map((e) => e.i));
  const path = trace.filter((p) => !eventIdx.has(p[0])).map((p, k) => `${k ? 'L' : 'M'}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(' ');
  const active = hover === null ? null : events[hover];
  return (
    <div className="replay">
      <div className="line-chart">
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Sequence numbers of SA ${sa.spi}: ${events.length} anomalies`}>
          {[0, maxS / 2, maxS].map((v) => (
            <g key={v}><line x1={L} x2={W - R} y1={y(v)} y2={y(v)} className="grid-line" />
              <text x={L - 6} y={y(v) + 4} textAnchor="end" className="axis-text">{Math.round(v)}</text></g>
          ))}
          <text x={L} y={H - 8} className="axis-text">packet 1</text>
          <text x={W - R} y={H - 8} textAnchor="end" className="axis-text">packet {maxI + 1}</text>
          <path d={path} className="seq-path" />
          {events.map((e, k) => (
            <g key={k} tabIndex={0} onPointerEnter={() => setHover(k)} onPointerLeave={() => setHover(null)}
              onFocus={() => setHover(k)} onBlur={() => setHover(null)} className="seq-event">
              <circle cx={x(e.i)} cy={y(e.seq)} r={9} className="seq-hit" />
              <circle cx={x(e.i)} cy={y(e.seq)} r={4.5} className={`seq-dot k-${e.kind}`} />
            </g>
          ))}
        </svg>
      </div>
      <div className="line-readout">
        {active ? <><strong>{active.kind.replace('_', ' ')}</strong> · seq {active.seq} at packet {active.i + 1}
          {active.frame ? ` · frame #${active.frame}` : ''} · highest seen before: {active.expected_above}</>
          : <span className="muted">{events.length ? 'Hover a red marker for the anomaly' : 'Monotonic: no anomalies on this SA'}</span>}
      </div>
      {events.slice(0, 3).map((e, k) => <SequenceExcerpt key={k} event={e} />)}
    </div>
  );
}

function SequenceExcerpt({ event }: { event: Loose }) {
  const at = event.i - event.context_start;
  return (
    <div className="seq-excerpt">
      {event.context.map((s: number, k: number) => (
        <span key={k} className="seq-item">
          <span className={`seq-box ${k === at ? `bad k-${event.kind}` : ''}`}>{s}</span>
          {k < event.context.length - 1 && <span className="seq-arrow" aria-hidden>→</span>}
        </span>
      ))}
      <span className="seq-note">↑ {event.kind === 'duplicate' ? 'REPLAY: sequence number already seen'
        : event.kind === 'reset' ? 'COUNTER RESET without a new SPI' : 'reordered beyond the 64-packet window'}
        {event.frame ? ` · frame #${event.frame}` : ''}</span>
    </div>
  );
}

// ---------------------------------------------------------------- encapsulation hero

const HEX = '0123456789abcdef';
function useScramble(length: number, active: boolean) {
  const reduce = useMemo(() => typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches, []);
  const make = () => Array.from({ length }, () => HEX[Math.floor(Math.random() * 16)]).join('');
  const [text, setText] = useState(make);
  useEffect(() => {
    if (!active || reduce) return;
    const timer = window.setInterval(() => setText(make()), 140);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, reduce, length]);
  return text.replace(/(.{2})/g, '$1 ').trim();
}

export function EncapsulationHero() {
  const cipher = useScramble(48, true);
  return (
    <figure className="encap" aria-label="How ESP tunnel mode encapsulates a packet, and what an observer can still see">
      <div className="encap-head"><span>ESP tunnel mode · RFC 4303</span><span className="scene-live"><span className="led cipher" />illustration</span></div>
      <div className="encap-body">
        <div className="encap-label">Inside site A · cleartext</div>
        <div className="pkt-row">
          <div className="pf pf-clear" style={{ flexGrow: 2 }}><b>IPv4</b><span>10.1.0.5 → 10.2.0.9</span></div>
          <div className="pf pf-clear" style={{ flexGrow: 1.4 }}><b>TCP</b><span>51000 → 443</span></div>
          <div className="pf pf-clear" style={{ flexGrow: 3 }}><b>Payload</b><span>GET /q3-report.pdf</span></div>
        </div>
        <div className="encap-arrow">
          <span className="line" /><span className="encap-op">encrypt + encapsulate · AES-256-GCM · SPI 0x6c2f19a4</span><span className="line" />
        </div>
        <div className="encap-label">On the wire · what anyone on the path sees</div>
        <div className="pkt-row wire">
          <div className="pf pf-clear" style={{ flexGrow: 2 }}><b>IPv4</b><span>198.51.100.10 → 203.0.113.20</span></div>
          <div className="pf pf-clear" style={{ flexGrow: 1 }}><b>SPI</b><span>6c2f19a4</span></div>
          <div className="pf pf-clear" style={{ flexGrow: 1 }}><b>Seq</b><span>00000412</span></div>
          <div className="pf pf-clear" style={{ flexGrow: .8 }}><b>IV</b><span>8 B</span></div>
          <div className="pf pf-enc" style={{ flexGrow: 5 }}><b>Encrypted inner packet</b><span className="hexrun">{cipher}</span></div>
          <div className="pf pf-tag" style={{ flexGrow: .8 }}><b>ICV</b><span>16 B</span></div>
        </div>
        <div className="encap-grid">
          <div>
            <span className="tile-label">Still observable</span>
            <div className="chips">{['gateway IPs', 'SPI', 'sequence', 'length 1 428 B', 'timing', 'IKE_SA_INIT'].map((c) => <span key={c} className="chip chip-clear">{c}</span>)}</div>
          </div>
          <div>
            <span className="tile-label">Hidden</span>
            <div className="chips">{['inner hosts', 'ports', 'payload', 'Child SA proposal'].map((c) => <span key={c} className="chip chip-enc">{c}</span>)}</div>
          </div>
        </div>
      </div>
    </figure>
  );
}

// ---------------------------------------------------------------- before → after

export function ScoreShift({ before, after, label = 'Security score', note }: {
  before: number | null; after: number | null; label?: string; note?: ReactNode;
}) {
  const delta = before === null || after === null ? null : Math.round((after - before) * 10) / 10;
  return (
    <div className="shift">
      <span className="tile-label">{label}</span>
      <div className="shift-row">
        <span className="shift-val">{score(before)}</span>
        <span className="shift-arrow" aria-hidden>→</span>
        <span className="shift-val after">{score(after)}</span>
        {delta !== null && delta !== 0 && (
          <StatusPill status={delta > 0 ? 'good' : 'critical'} label={`${delta > 0 ? '+' : ''}${delta}`} />
        )}
      </div>
      {note && <div className="muted text-xs">{note}</div>}
    </div>
  );
}
