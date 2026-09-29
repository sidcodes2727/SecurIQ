import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { useAnalysisId, usePolling } from '../hooks/useAnalysis';
import { api } from '../services/api';
import type { AnalysisSummary, Health } from '../types';
import { openPalette, toggleRail } from '../lib/events';
import { NAV, routeFor } from '../lib/nav';

/** Encapsulation mark: an inner packet inside an outer one, with the tunnel running through. */
export function BrandMark({ className = 'brand-mark' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 22 22" aria-hidden fill="none" stroke="currentColor" strokeWidth="1.4">
      <rect x="1.5" y="3.5" width="19" height="15" />
      <path d="M1.5 11h3.5M17 11h3.5" />
      <rect x="6.5" y="7.5" width="9" height="7" fill="currentColor" fillOpacity=".18" />
      <path d="M9 11h4" strokeWidth="1.8" />
    </svg>
  );
}

/** The capture currently in scope (for the rail footer and topbar chip). */
function useScopedCapture() {
  const id = useAnalysisId();
  const [summary, setSummary] = useState<AnalysisSummary | null>(null);
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    api.listAnalyses().then((d) => {
      if (!cancelled) setSummary(d.analyses.find((a) => a.analysis_id === id) ?? null);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [id]);
  return id && summary?.analysis_id === id ? summary : null;
}

export function Sidebar() {
  const id = useAnalysisId();
  const scoped = useScopedCapture();
  const [open, setOpen] = useState(false);

  return (
    <aside className={`rail ${open ? 'open' : ''}`}>
      <div className="rail-head">
        <Link to="/" className="rail-brand" aria-label="SecurIQ home" onClick={() => setOpen(false)}>
          <BrandMark /><span className="brand-text"><span className="brand-word">SecurIQ</span><span className="brand-sub">IPsec intelligence</span></span>
        </Link>
        <button className="rail-menu" aria-expanded={open} aria-label="Toggle navigation" onClick={() => setOpen(!open)}>
          <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden stroke="currentColor" strokeWidth="1.4">
            {open ? <path d="M3 3l10 10M13 3L3 13" /> : <path d="M2 4h12M2 8h12M2 12h12" />}
          </svg>
        </button>
      </div>
      <nav className="rail-nav" aria-label="Main">
        {NAV.map((group) => (
          <div className="nav-group" key={group.section}>
            <div className="nav-group-title">{group.section}</div>
            {group.items.map((item) => (
              <NavLink key={item.to} end={item.end} onClick={() => setOpen(false)} title={`${item.label}  (g ${item.key})`}
                to={{ pathname: item.to, search: item.scoped && id ? `?id=${id}` : '' }}
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                <span className="nav-num" aria-hidden>{item.num}</span><span className="nav-label">{item.label}</span>
                {item.badge && <span className="nav-badge">{item.badge}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="rail-foot">
        {scoped ? (
          <>
            <span>In scope</span>
            <span className="sa" title={scoped.filename}>{scoped.filename}</span>
            {scoped.fingerprint && <span className="sa">FP <b>{scoped.fingerprint}</b></span>}
          </>
        ) : <span>SIH 26160 · NTRO<br />Passive, keyless analysis</span>}
        <button className="rail-collapse" onClick={toggleRail} title="Collapse navigation (Ctrl+B)" aria-label="Collapse navigation">
          <span aria-hidden>⇤</span>
        </button>
      </div>
    </aside>
  );
}

/** Slim status strip: search, where you are, which capture is in scope, backend and classifier state. */
export function Topbar() {
  const { pathname } = useLocation();
  const route = routeFor(pathname);
  const scoped = useScopedCapture();
  const [health, setHealth] = useState<Health | null>(null);
  const [offline, setOffline] = useState(false);
  const load = useCallback(() => {
    api.health().then((h) => { setHealth(h); setOffline(false); }).catch(() => setOffline(true));
  }, []);
  useEffect(load, [load]);
  usePolling(load, 4000, offline || !health || health.model_training || !health.model_trained);

  const backend = offline ? 'Backend offline' : health ? `Engine v${health.version}` : 'Connecting';
  const model = !health ? null : health.model_training ? 'Model training' : health.model_trained ? 'Model ready' : 'Model not ready';
  return (
    <div className="topbar">
      <button className="rail-toggle" onClick={toggleRail} aria-label="Toggle navigation (Ctrl+B)" title="Toggle navigation (Ctrl+B)">
        <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden fill="none" stroke="currentColor" strokeWidth="1.4">
          <rect x="1.5" y="2.5" width="13" height="11" /><path d="M5.5 2.5v11" /></svg>
      </button>
      <div className="crumbs">
        <span>SecurIQ</span><span className="sep">›</span><span>{route.section}</span><span className="sep">›</span>
        <span className="here">{route.label}</span>
      </div>
      <button className="search-pill" onClick={openPalette} aria-label="Search and commands (Ctrl+K)">
        <svg width="13" height="13" viewBox="0 0 16 16" aria-hidden fill="none" stroke="currentColor" strokeWidth="1.6">
          <circle cx="7" cy="7" r="5" /><path d="M11 11l3.5 3.5" /></svg>
        <span>Search captures, findings, gateways, actions…</span>
        <kbd>Ctrl K</kbd>
      </button>
      <div className="topbar-status" role="status">
        {scoped && route.scoped && (
          <Link className="sa-chip" to={`/analysis?id=${scoped.analysis_id}`} title="Capture in scope">
            <span className="led cipher" /><span className="fname">{scoped.filename}</span>
            {scoped.fingerprint && <span className="fp">{scoped.fingerprint}</span>}
          </Link>
        )}
        <span className="readout"><span className={`led ${offline ? 'offline' : health ? 'online' : ''}`} />{backend}</span>
        {model && <span className="readout hide-sm"><span className={`led ${health?.model_training ? 'busy' : health?.model_trained ? 'online' : ''}`} />{model}</span>}
      </div>
    </div>
  );
}

const RULER = [
  ' 0                   1                   2                   3',
  ' 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1',
  '+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+',
  '|               Security Parameters Index (SPI)                 |',
  '+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+',
  '|                      Sequence Number                          |',
  '+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+',
].join('\n');

export function Page({ title, subtitle, bare, meta, wide, children }: {
  title: string; subtitle?: ReactNode; bare?: boolean; meta?: ReactNode; wide?: boolean; children: ReactNode;
}) {
  const { pathname } = useLocation();
  const route = routeFor(pathname);
  return (
    <div className={`page-container ${wide ? 'wide' : ''}`}>
      {!bare && (
        <header className="page-head">
          {!meta && <pre className="ruler" aria-hidden>{RULER}</pre>}
          <div className="page-head-grid">
            <div>
              <div className="eyebrow"><span className="hex">{route.num}</span> {route.section}</div>
              <h1 className="page-title">{title}</h1>
              {subtitle && <p className="page-sub">{subtitle}</p>}
            </div>
            {meta && <div className="page-meta">{meta}</div>}
          </div>
        </header>
      )}
      {children}
    </div>
  );
}
