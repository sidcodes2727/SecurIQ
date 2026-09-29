import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { EvidenceChainView } from '../components/ipsec';
import { Page } from '../components/Layout';
import { useToast } from '../hooks/useToast';
import { ErrorBanner, Loading, SeverityBadge } from '../components/ui';
import { rememberAnalysis } from '../hooks/useAnalysis';
import { STATUS_ICON, severityStatus, timeAgo } from '../lib/format';
import { api } from '../services/api';
import type { Intel, Severity, TriageItem } from '../types';

const STATUSES: { key: string; label: string; icon: string; hotkey: string }[] = [
  { key: 'new', label: 'New', icon: '●', hotkey: 'n' },
  { key: 'investigating', label: 'Investigating', icon: '◐', hotkey: 'i' },
  { key: 'accepted', label: 'Risk accepted', icon: '◆', hotkey: 'a' },
  { key: 'resolved', label: 'Resolved', icon: '✓', hotkey: 'r' },
  { key: 'false_positive', label: 'False positive', icon: '⊘', hotkey: 'f' },
];
const STATUS_BY_KEY = Object.fromEntries(STATUSES.map((s) => [s.key, s]));
const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low'];
type GroupBy = 'finding' | 'capture' | 'none';

const inInput = (e: KeyboardEvent) => {
  const el = e.target as HTMLElement | null;
  return !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT');
};

export default function Inbox() {
  const navigate = useNavigate();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const [items, setItems] = useState<TriageItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [groupBy, setGroupBy] = useState<GroupBy>('finding');
  const [search, setSearch] = useState('');
  const [intel, setIntel] = useState<Record<string, Intel>>({});
  const [draft, setDraft] = useState<{ key: string; text: string } | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const status = params.get('status') ?? (params.get('finding') ? 'all' : 'new');
  const findingFilter = params.get('finding');
  const sevFilter = params.get('sev');
  const activeKey = params.get('item');

  const setParam = (key: string, value: string | null) => {
    const p = new URLSearchParams(params);
    if (value === null) p.delete(key); else p.set(key, value);
    setParams(p, { replace: true });
  };

  const load = useCallback(() => {
    api.triage().then((d) => setItems(d.items)).catch((e) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const scoped = useMemo(() => (items ?? []).filter((i) =>
    (!findingFilter || i.finding_id === findingFilter) && (!sevFilter || i.severity === sevFilter)
    && (!search || `${i.finding_id} ${i.title} ${i.filename} ${i.fingerprint}`.toLowerCase().includes(search.toLowerCase()))), [items, findingFilter, sevFilter, search]);
  const counts = useMemo(() => {
    const c: Record<string, number> = { all: scoped.length };
    for (const s of STATUSES) c[s.key] = scoped.filter((i) => i.status === s.key).length;
    return c;
  }, [scoped]);
  const visible = useMemo(() => scoped.filter((i) => status === 'all' || i.status === status), [scoped, status]);

  const groups = useMemo(() => {
    if (groupBy === 'none') return [{ key: 'all', title: `${visible.length} findings`, items: visible }];
    const map = new Map<string, TriageItem[]>();
    for (const i of visible) {
      const k = groupBy === 'finding' ? i.finding_id : i.analysis_id;
      map.set(k, [...(map.get(k) ?? []), i]);
    }
    return [...map.entries()].map(([key, list]) => ({
      key, items: list,
      title: groupBy === 'finding' ? `${key} · ${list[0].title.split(':')[0]}` : list[0].filename,
    }));
  }, [visible, groupBy]);
  const ordered = useMemo(() => groups.flatMap((g) => g.items), [groups]);
  const active = ordered.find((i) => i.key === activeKey) ?? ordered[0] ?? null;

  const note = active && draft?.key === active.key ? draft.text : active?.note ?? '';
  const setNote = (text: string) => { if (active) setDraft({ key: active.key, text }); };
  useEffect(() => {
    if (!active || intel[active.analysis_id]) return;
    api.getIntel(active.analysis_id).then((d) => setIntel((m) => ({ ...m, [active.analysis_id]: d }))).catch(() => {});
  }, [active, intel]);
  // keep the active finding visible by scrolling the list itself, never the page
  useEffect(() => {
    const list = listRef.current;
    const row = active ? list?.querySelector<HTMLElement>(`[data-key="${active.key}"]`) : null;
    if (!list || !row) return;
    const top = row.offsetTop, bottom = top + row.offsetHeight;   // the list is the offset parent
    if (top < list.scrollTop + 40) list.scrollTop = Math.max(0, top - 40);
    else if (bottom > list.scrollTop + list.clientHeight) list.scrollTop = bottom - list.clientHeight;
  }, [active]);

  const apply = useCallback(async (keys: string[], next: string | undefined, noteText?: string) => {
    if (!keys.length) return;
    setItems((list) => list?.map((i) => keys.includes(i.key) ? { ...i, status: next ?? i.status, note: noteText ?? i.note, updated: Date.now() / 1000 } : i) ?? null);
    try {
      await api.updateTriage(keys, next, noteText);
      toast.push(next ? `${keys.length} finding(s) → ${STATUS_BY_KEY[next].label}` : 'Note saved', undefined, 'good');
    } catch (e) { toast.push('Update failed', (e as Error).message, 'critical'); load(); }
  }, [toast, load]);

  // keyboard triage: j/k move, x check, n/i/a/r/f set status, enter opens the capture
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (inInput(e) || e.ctrlKey || e.metaKey || e.altKey || !active) return;
      const idx = ordered.findIndex((i) => i.key === active.key);
      if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); const n = ordered[Math.min(idx + 1, ordered.length - 1)]; if (n) setParam('item', n.key); }
      else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); const n = ordered[Math.max(idx - 1, 0)]; if (n) setParam('item', n.key); }
      else if (e.key === 'x') { const next = new Set(checked); if (next.has(active.key)) next.delete(active.key); else next.add(active.key); setChecked(next); }
      else if (e.key === 'Enter') { rememberAnalysis(active.analysis_id); navigate(`/security?id=${active.analysis_id}&tab=findings`); }
      else {
        const s = STATUSES.find((x) => x.hotkey === e.key);
        if (s) {
          e.preventDefault();
          const keys = checked.size ? [...checked] : [active.key];
          void apply(keys, s.key);
          if (!checked.size && status !== 'all' && s.key !== status) {
            const n = ordered[idx + 1] ?? ordered[idx - 1];
            if (n) setParam('item', n.key);
          }
          setChecked(new Set());
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  if (error) return <Page title="Triage inbox"><ErrorBanner message={error} /></Page>;
  if (!items) return <Page title="Triage inbox"><Loading label="Gathering findings…" /></Page>;

  const chain = active ? intel[active.analysis_id]?.chains[active.finding_id] : null;
  const occurrences = active ? (items ?? []).filter((i) => i.finding_id === active.finding_id && i.key !== active.key) : [];
  const toggleGroup = (list: TriageItem[]) => {
    const next = new Set(checked);
    const all = list.every((i) => next.has(i.key));
    for (const i of list) if (all) next.delete(i.key); else next.add(i.key);
    setChecked(next);
  };

  return (
    <Page title="Triage inbox" wide
      subtitle="Every finding from every capture, in one queue. Mark it investigating, accept the risk, resolve it or dismiss it as a false positive; decisions persist on the server.">
      <div className="inbox">
        <aside className="inbox-rail" aria-label="Filters">
          <span className="tile-label">Status</span>
          <ul className="status-list">
            <li><button className={status === 'all' ? 'on' : ''} onClick={() => setParam('status', 'all')}>
              <span aria-hidden>≡</span>All<span className="n">{counts.all}</span></button></li>
            {STATUSES.map((s) => (
              <li key={s.key}><button className={status === s.key ? 'on' : ''} onClick={() => setParam('status', s.key)}>
                <span aria-hidden className={`wf wf-${s.key}`}>{s.icon}</span>{s.label}<span className="n">{counts[s.key]}</span></button></li>
            ))}
          </ul>
          <span className="tile-label mt-md">Severity</span>
          <div className="chips">
            {SEVERITIES.map((s) => (
              <button key={s} className={`chip-button ${sevFilter === s ? 'active' : ''}`} onClick={() => setParam('sev', sevFilter === s ? null : s)}>
                <span aria-hidden className={`sev-ic s-${severityStatus[s]}`}>{STATUS_ICON[severityStatus[s]]}</span> {s}</button>
            ))}
          </div>
          {findingFilter && (
            <div className="filter-note">Finding <b className="mono">{findingFilter}</b>
              <button className="btn btn-sm btn-ghost" onClick={() => setParam('finding', null)}>clear</button></div>
          )}
          <label className="field mt-md">Group by
            <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as GroupBy)}>
              <option value="finding">Finding</option><option value="capture">Capture</option><option value="none">No grouping</option>
            </select></label>
          <label className="field mt-md">Search
            <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="id, title, capture…" /></label>
          <div className="hotkeys">
            <span className="tile-label">Keys</span>
            <span><kbd>j</kbd><kbd>k</kbd> move · <kbd>x</kbd> select</span>
            <span><kbd>i</kbd> investigate · <kbd>a</kbd> accept</span>
            <span><kbd>r</kbd> resolve · <kbd>f</kbd> false positive</span>
            <span><kbd>n</kbd> reopen · <kbd>↵</kbd> open capture</span>
          </div>
        </aside>

        <section className="inbox-list" ref={listRef} aria-label="Findings">
          {checked.size > 0 && (
            <div className="bulk-bar" role="toolbar" aria-label="Bulk actions">
              <strong>{checked.size} selected</strong>
              {STATUSES.filter((s) => s.key !== 'new').map((s) => (
                <button key={s.key} className="btn btn-sm btn-secondary" onClick={() => { void apply([...checked], s.key); setChecked(new Set()); }}>
                  <span aria-hidden>{s.icon}</span> {s.label}</button>
              ))}
              <button className="btn btn-sm btn-ghost" onClick={() => setChecked(new Set())}>Clear</button>
            </div>
          )}
          {ordered.length === 0 && (
            <div className="inbox-empty"><span aria-hidden className="big-check">✓</span>
              <p>Nothing {status === 'all' ? '' : `marked “${STATUS_BY_KEY[status]?.label ?? status}”`} here.</p>
              {status !== 'all' && <button className="btn btn-sm btn-secondary" onClick={() => setParam('status', 'all')}>Show all findings</button>}</div>
          )}
          {groups.map((g) => (
            <div key={g.key} className="inbox-group">
              {groupBy !== 'none' && (
                <div className="inbox-group-head">
                  <input type="checkbox" aria-label={`Select all in ${g.title}`} checked={g.items.every((i) => checked.has(i.key))} onChange={() => toggleGroup(g.items)} />
                  <span className="ellipsis">{g.title}</span><span className="muted">{g.items.length}</span>
                </div>
              )}
              {g.items.map((i) => (
                <div key={i.key} data-key={i.key} className={`inbox-item ${active?.key === i.key ? 'active' : ''} sev-${severityStatus[i.severity]}`}
                  role="button" tabIndex={-1} onClick={() => setParam('item', i.key)}>
                  <input type="checkbox" aria-label={`Select ${i.finding_id} in ${i.filename}`} checked={checked.has(i.key)}
                    onClick={(e) => e.stopPropagation()}
                    onChange={() => { const next = new Set(checked); if (next.has(i.key)) next.delete(i.key); else next.add(i.key); setChecked(next); }} />
                  <span aria-hidden className={`sev-ic s-${severityStatus[i.severity]}`}>{STATUS_ICON[severityStatus[i.severity]]}</span>
                  <span className="inbox-main">
                    <span className="inbox-title"><b className="mono">{i.finding_id}</b> {i.title}</span>
                    <span className="inbox-sub">{groupBy === 'capture' ? i.fingerprint : i.filename} · {timeAgo(i.created)}</span>
                  </span>
                  <span className={`wf-chip wf-${i.status}`}><span aria-hidden>{STATUS_BY_KEY[i.status]?.icon}</span>{STATUS_BY_KEY[i.status]?.label}</span>
                </div>
              ))}
            </div>
          ))}
        </section>

        <section className="inbox-detail" aria-label="Finding detail">
          {!active ? <p className="muted">Select a finding.</p> : (
            <>
              <div className="row"><SeverityBadge severity={active.severity} /><span className="mono muted">{active.finding_id}</span>
                <span className="spacer" /><span className="muted text-xs">{active.filename}</span></div>
              <h2 className="detail-title">{active.title}</h2>
              <div className="segmented wf-seg" role="radiogroup" aria-label="Triage status">
                {STATUSES.map((s) => (
                  <button key={s.key} role="radio" aria-checked={active.status === s.key} className={active.status === s.key ? 'active' : ''}
                    onClick={() => void apply([active.key], s.key)} title={`Shortcut: ${s.hotkey}`}>
                    <span aria-hidden>{s.icon}</span> {s.label}</button>
                ))}
              </div>
              {chain ? <EvidenceChainView chain={chain} /> : <Loading label="Loading evidence chain…" />}
              <div className="note-box">
                <label className="field" htmlFor="triage-note">Analyst note</label>
                <textarea id="triage-note" rows={3} value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000}
                  placeholder="Why this decision? Ticket number, owner, compensating control…"
                  onKeyDown={(e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) void apply([active.key], undefined, note); }} />
                <div className="row"><button className="btn btn-sm btn-primary" disabled={note === active.note} onClick={() => void apply([active.key], undefined, note)}>Save note</button>
                  <span className="muted text-xs">Ctrl+Enter</span></div>
              </div>
              <div className="button-row mt-md">
                <Link className="btn btn-sm btn-secondary" to={`/security?id=${active.analysis_id}&tab=findings`} onClick={() => rememberAnalysis(active.analysis_id)}>Open assessment</Link>
                <Link className="btn btn-sm btn-secondary" to={`/simulator?id=${active.analysis_id}&fix=1`} onClick={() => rememberAnalysis(active.analysis_id)}>Simulate the fix</Link>
                <Link className="btn btn-sm btn-secondary" to={`/graph?focus=${encodeURIComponent(`finding:${active.finding_id}`)}`}>Show in graph</Link>
              </div>
              {occurrences.length > 0 && (
                <>
                  <h4 className="subhead">Same finding in {occurrences.length} other capture(s)</h4>
                  <ul className="occ-list">{occurrences.slice(0, 8).map((o) => (
                    <li key={o.key}><button onClick={() => { setParam('status', 'all'); setParam('item', o.key); }}>
                      <span className="ellipsis">{o.filename}</span><span className={`wf-chip wf-${o.status}`}>{STATUS_BY_KEY[o.status]?.label}</span></button></li>
                  ))}</ul>
                </>
              )}
              {active.history.length > 0 && (
                <>
                  <h4 className="subhead">History</h4>
                  <ol className="history">{active.history.slice().reverse().map((h, k) => (
                    <li key={k}><span className="muted mono text-xs">{timeAgo(h.at)}</span> {STATUS_BY_KEY[h.from]?.label} → <b>{STATUS_BY_KEY[h.to]?.label}</b></li>
                  ))}</ol>
                </>
              )}
            </>
          )}
        </section>
      </div>
    </Page>
  );
}
