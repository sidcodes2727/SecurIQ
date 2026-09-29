import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { rememberAnalysis, useAnalysisId } from '../hooks/useAnalysis';
import { fuzzy, highlight } from '../lib/fuzzy';
import { TRAFFIC_LABELS, severityStatus, type Status } from '../lib/format';
import { api } from '../services/api';
import type { FleetRow, Loose } from '../types';
import { toggleRail } from '../lib/events';
import { NAV, ROUTES } from '../lib/nav';
import { useToast } from '../hooks/useToast';


interface Cmd {
  id: string;
  group: 'Recent' | 'Actions' | 'Pages' | 'Captures' | 'Findings' | 'Gateways' | 'Fingerprints';
  title: string;
  sub?: string;
  tag?: string;
  keywords?: string;
  status?: Status;
  run: () => void | Promise<void>;
}

const GROUP_ORDER: Cmd['group'][] = ['Recent', 'Actions', 'Pages', 'Captures', 'Findings', 'Gateways', 'Fingerprints'];
// existing objects outrank actions that would redo work
const GROUP_BOOST: Partial<Record<Cmd['group'], number>> = { Captures: 10, Findings: 8, Pages: 6, Gateways: 6, Fingerprints: 6 };
const RECENT_KEY = 'securiq.recentCommands';
const readRecent = (): string[] => { try { return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); } catch { return []; } };
const saveRecent = (id: string) => {
  try { localStorage.setItem(RECENT_KEY, JSON.stringify([id, ...readRecent().filter((x) => x !== id)].slice(0, 6))); } catch { /* optional */ }
};

const inInput = (e: KeyboardEvent) => {
  const el = e.target as HTMLElement | null;
  return !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable);
};

export default function CommandPalette() {
  const navigate = useNavigate();
  const scopedId = useAnalysisId();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [help, setHelp] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const [rows, setRows] = useState<FleetRow[]>([]);
  const [samples, setSamples] = useState<Loose[]>([]);
  const loadedAt = useRef(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const pendingG = useRef(0);

  const load = useCallback(() => {
    if (Date.now() - loadedAt.current < 15000) return;
    loadedAt.current = Date.now();
    api.fleetObjects().then((d) => setRows(d.rows)).catch(() => {});
    api.listUploads().then((d) => setSamples(d.samples)).catch(() => {});
  }, []);

  const show = useCallback(() => { setQuery(''); setActive(0); setOpen(true); setHelp(false); load(); }, [load]);

  // global shortcuts
  useEffect(() => {
    const onOpen = () => show();
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (open) setOpen(false); else show(); return; }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') { e.preventDefault(); toggleRail(); return; }
      if (open || inInput(e) || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === '/') { e.preventDefault(); show(); return; }
      if (e.key === '?') { e.preventDefault(); setHelp((h) => !h); return; }
      if (e.key === 'Escape') { setHelp(false); return; }
      if (pendingG.current && Date.now() - pendingG.current < 1200) {
        pendingG.current = 0;
        const route = ROUTES.find((r) => r.key === e.key.toLowerCase());
        if (route) {
          e.preventDefault();
          navigate({ pathname: route.to, search: route.scoped && scopedId ? `?id=${scopedId}` : '' });
        }
        return;
      }
      if (e.key === 'g') pendingG.current = Date.now();
    };
    window.addEventListener('securiq:palette', onOpen);
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('securiq:palette', onOpen); window.removeEventListener('keydown', onKey); };
  }, [open, show, navigate, scopedId]);


  const commands = useMemo<Cmd[]>(() => {
    const go = (path: string) => () => navigate(path);
    const scoped = (path: string) => scopedId ? `${path}${path.includes('?') ? '&' : '?'}id=${scopedId}` : path;
    const out: Cmd[] = [];
    for (const r of ROUTES) {
      out.push({ id: `page:${r.to}`, group: 'Pages', title: r.label, sub: `${r.section} · g ${r.key}`, tag: r.num,
        keywords: r.section, run: go(r.scoped ? scoped(r.to) : r.to) });
    }
    const analyse = (sampleId: string, label: string) => async () => {
      toast.push('Analysing', label);
      try {
        const res = await api.analyze(sampleId);
        rememberAnalysis(res.analysis_id);
        toast.push('Analysis complete', `${label} · score ${res.summary.security_score}`, 'good');
        navigate(`/security?id=${res.analysis_id}`);
      } catch (e) { toast.push('Analysis failed', (e as Error).message, 'critical'); }
    };
    for (const s of samples) {
      out.push({ id: `analyse:${s.id}`, group: 'Actions', title: `Analyse sample: ${s.id.replace(/_/g, ' ')}`,
        sub: s.description, tag: 'run', keywords: 'analyse testbed scenario pcap', run: analyse(s.id, s.id.replace(/_/g, ' ')) });
    }
    out.push(
      { id: 'act:inbox-new', group: 'Actions', title: 'Triage new findings', sub: 'Open the inbox filtered to untriaged items', tag: 'go', run: go('/inbox?status=new') },
      { id: 'act:graph', group: 'Actions', title: 'Investigate the fleet as a link graph', sub: 'Captures, gateways, configurations and findings', tag: 'go', run: go('/graph') },
      { id: 'act:weak', group: 'Actions', title: 'Find captures with weak key exchange', sub: 'Explorer: dh:2 or dh:5', tag: 'query', run: go('/explorer?q=dh:2%20dh:5') },
      { id: 'act:nopfs', group: 'Actions', title: 'Find captures without PFS', sub: 'Explorer: pfs:off', tag: 'query', run: go('/explorer?q=pfs:off') },
      { id: 'act:noncompliant', group: 'Actions', title: 'Find policy violations', sub: 'Explorer: policy:non', tag: 'query', run: go('/explorer?q=policy:non') },
      { id: 'act:lab', group: 'Actions', title: 'Build a VPN in the lab', sub: 'Digital twin: configuration → capture → analysis', tag: 'go', run: go('/lab') },
      { id: 'act:bench', group: 'Actions', title: 'Run the misconfiguration benchmark', sub: 'Testbed & model → benchmark', tag: 'go', run: go('/testbed?tab=benchmark') },
      { id: 'act:live', group: 'Actions', title: 'Start a live replay', sub: 'Stream a capture through the real-time engine', tag: 'go', run: go('/live') },
      { id: 'act:rail', group: 'Actions', title: 'Toggle navigation rail', sub: 'Ctrl+B', tag: 'ui', run: toggleRail },
      { id: 'act:help', group: 'Actions', title: 'Keyboard shortcuts', sub: '?', tag: 'ui', run: () => setHelp(true) },
    );
    if (scopedId) {
      out.push(
        { id: 'act:fix', group: 'Actions', title: 'Simulate the recommended fixes', sub: 'What-if simulator for the capture in scope', tag: 'scope', run: go(`/simulator?id=${scopedId}&fix=1`) },
        { id: 'act:chains', group: 'Actions', title: 'Show evidence chains', sub: 'Security assessment → findings', tag: 'scope', run: go(`/security?id=${scopedId}&tab=findings`) },
        { id: 'act:timeline', group: 'Actions', title: 'Open the investigation timeline', sub: 'IKE, tunnels, traffic and anomalies on one axis', tag: 'scope', run: go(`/analysis?id=${scopedId}&tab=timeline`) },
        { id: 'act:report', group: 'Actions', title: 'Open the executive report', sub: 'Printable HTML', tag: 'scope', run: () => { window.open(api.reportUrl(scopedId, 'executive.html'), '_blank'); } },
      );
    }
    const gateways = new Map<string, number>();
    const fps = new Map<string, FleetRow>();
    const findings = new Map<string, { title: string; severity: Loose; count: number; first: string }>();
    for (const row of rows) {
      out.push({ id: `cap:${row.analysis_id}`, group: 'Captures', title: row.filename,
        sub: `${row.risk_level} · ${row.score ?? '—'} · ${row.fingerprint} · ${row.fingerprint_label}`,
        keywords: `${row.ike_version} ${row.ike_encryption} ${row.dh_name} ${row.traffic.map((t) => TRAFFIC_LABELS[t]).join(' ')}`,
        status: row.findings.some((f) => f.severity === 'Critical') ? 'critical' : row.findings.some((f) => f.severity === 'High') ? 'serious' : undefined,
        tag: row.source, run: () => { rememberAnalysis(row.analysis_id); navigate(`/analysis?id=${row.analysis_id}`); } });
      row.gateways.forEach((g) => gateways.set(g, (gateways.get(g) ?? 0) + 1));
      if (!fps.has(row.fingerprint)) fps.set(row.fingerprint, row);
      for (const f of row.findings) {
        const cur = findings.get(f.id);
        if (cur) cur.count += 1;
        else findings.set(f.id, { title: f.title.split(':')[0], severity: f.severity, count: 1, first: row.analysis_id });
      }
    }
    for (const [id, f] of findings) {
      out.push({ id: `finding:${id}`, group: 'Findings', title: `${id} ${f.title}`, sub: `${f.severity} · in ${f.count} capture(s)`,
        status: severityStatus[f.severity as keyof typeof severityStatus], tag: f.severity,
        run: go(`/inbox?finding=${encodeURIComponent(id)}`) });
    }
    for (const [ip, n] of gateways) {
      out.push({ id: `gw:${ip}`, group: 'Gateways', title: ip, sub: `VPN gateway · ${n} capture(s)`, tag: 'gw',
        run: go(`/graph?focus=${encodeURIComponent(`gateway:${ip}`)}`) });
    }
    for (const [fp, row] of fps) {
      out.push({ id: `fp:${fp}`, group: 'Fingerprints', title: fp, sub: row.fingerprint_label, tag: 'fp',
        run: go(`/explorer?q=${encodeURIComponent(`fp:${fp}`)}`) });
    }
    return out;
  }, [rows, samples, scopedId, navigate, toast]);

  const results = useMemo(() => {
    let q = query.trim();
    let only: Cmd['group'][] | null = null;
    if (q.startsWith('>')) { only = ['Actions']; q = q.slice(1).trim(); }
    else if (q.startsWith('#')) { only = ['Findings']; q = q.slice(1).trim(); }
    else if (q.startsWith('@')) { only = ['Gateways', 'Fingerprints', 'Captures']; q = q.slice(1).trim(); }
    const pool = only ? commands.filter((c) => only!.includes(c.group)) : commands;
    let scored: { cmd: Cmd; score: number; hits: number[] }[];
    if (!q) {
      const recent = readRecent().map((id) => commands.find((c) => c.id === id)).filter(Boolean) as Cmd[];
      const base = only ? pool : [
        ...recent.map((c) => ({ ...c, group: 'Recent' as const })),
        ...pool.filter((c) => c.group === 'Actions' && !c.id.startsWith('analyse:')).slice(0, 6),
        ...pool.filter((c) => c.group === 'Pages'),
        ...pool.filter((c) => c.group === 'Captures').slice(0, 5),
      ];
      scored = base.map((cmd) => ({ cmd, score: 0, hits: [] }));
    } else {
      scored = [];
      for (const cmd of pool) {
        const onTitle = fuzzy(q, cmd.title);
        const onAll = onTitle ?? fuzzy(q, `${cmd.title} ${cmd.sub ?? ''} ${cmd.keywords ?? ''}`);
        if (onAll) scored.push({ cmd, score: onAll.score + (onTitle ? 25 : 0) + (GROUP_BOOST[cmd.group] ?? 0) - (cmd.id.startsWith('analyse:') ? 12 : 0), hits: onTitle?.indices ?? [] });
      }
      scored.sort((a, b) => b.score - a.score);
    }
    const grouped = new Map<string, typeof scored>();
    for (const s of scored) {
      const g = grouped.get(s.cmd.group) ?? [];
      if (g.length < (q ? 7 : 12)) g.push(s);
      grouped.set(s.cmd.group, g);
    }
    const order = q ? [...grouped.keys()].sort((a, b) => (grouped.get(b)![0].score - grouped.get(a)![0].score))
      : GROUP_ORDER.filter((g) => grouped.has(g));
    let n = 0;
    return order.map((g) => ({ group: g, items: grouped.get(g)!.map((it) => ({ ...it, index: n++ })) }));
  }, [commands, query]);

  const flat = useMemo(() => results.flatMap((r) => r.items), [results]);

  useEffect(() => {
    list.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const run = (cmd: Cmd) => {
    saveRecent(cmd.id.replace(/^recent:/, ''));
    setOpen(false);
    void cmd.run();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, flat.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); if (flat[active]) run(flat[active].cmd); }
    else if (e.key === 'Escape') { e.preventDefault(); setOpen(false); }
  };

  return (
    <>
      {open && (
        <div className="palette-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setOpen(false); }}>
          <div className="palette" role="dialog" aria-modal="true" aria-label="Command palette">
            <div className="palette-input">
              <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden fill="none" stroke="currentColor" strokeWidth="1.6">
                <circle cx="7" cy="7" r="5" /><path d="M11 11l3.5 3.5" /></svg>
              <input ref={input} autoFocus value={query} role="combobox" aria-expanded="true" aria-controls="palette-list"
                aria-activedescendant={flat[active] ? `pal-${active}` : undefined}
                placeholder="Search captures, findings, gateways, fingerprints — or type > for actions"
                onChange={(e) => { setQuery(e.target.value); setActive(0); }} onKeyDown={onKeyDown} />
              <kbd>esc</kbd>
            </div>
            <div className="palette-list" id="palette-list" role="listbox" ref={list}>
              {flat.length === 0 && <div className="palette-empty">No match. Try a filename, a finding id like KE-001, an IP, or a fingerprint.</div>}
              {results.map((section) => (
                <div key={section.group} role="group" aria-label={section.group}>
                  <div className="palette-group">{section.group}</div>
                  {section.items.map(({ cmd, hits, index: i }) => {
                    return (
                      <div key={`${section.group}-${cmd.id}`} id={`pal-${i}`} data-index={i} role="option" aria-selected={i === active}
                        className={`palette-item ${i === active ? 'active' : ''}`}
                        onMouseMove={() => setActive(i)} onMouseDown={(e) => { e.preventDefault(); run(cmd); }}>
                        <span className={`palette-tag ${cmd.status ? `s-${cmd.status}` : ''}`}>{cmd.tag ?? '·'}</span>
                        <span className="palette-text">
                          <span className="palette-title">{highlight(cmd.title, hits).map((seg, k) =>
                            seg.hit ? <mark key={k}>{seg.text}</mark> : <span key={k}>{seg.text}</span>)}</span>
                          {cmd.sub && <span className="palette-sub">{cmd.sub}</span>}
                        </span>
                        {i === active && <span className="palette-enter" aria-hidden>↵</span>}
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
            <div className="palette-foot">
              <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span>
              <span><kbd>&gt;</kbd> actions</span><span><kbd>#</kbd> findings</span><span><kbd>@</kbd> objects</span>
              <span className="spacer" /><span>{rows.length} captures indexed</span>
            </div>
          </div>
        </div>
      )}
      {help && (
        <div className="palette-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setHelp(false); }}>
          <div className="shortcuts" role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">
            <div className="card-header"><h3 className="card-title">Keyboard shortcuts</h3>
              <button className="btn btn-sm btn-ghost" onClick={() => setHelp(false)}>Close</button></div>
            <div className="shortcut-grid">
              <div><kbd>Ctrl</kbd><kbd>K</kbd> or <kbd>/</kbd><span>Search and commands</span></div>
              <div><kbd>Ctrl</kbd><kbd>B</kbd><span>Collapse navigation</span></div>
              <div><kbd>?</kbd><span>This help</span></div>
              {NAV.flatMap((g) => g.items).map((r) => (
                <div key={r.to}><kbd>g</kbd><kbd>{r.key}</kbd><span>{r.label}</span></div>
              ))}
              <div><kbd>j</kbd><kbd>k</kbd><span>Inbox: next / previous finding</span></div>
              <div><kbd>i</kbd><kbd>a</kbd><kbd>r</kbd><kbd>f</kbd><span>Inbox: investigate / accept / resolve / false positive</span></div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
