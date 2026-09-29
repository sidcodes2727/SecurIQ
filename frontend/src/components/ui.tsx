import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { SOURCE_LABEL, STATUS_ICON, pct, severityStatus, type Status } from '../lib/format';
import type { Severity, Source } from '../types';

export function Card({ title, subtitle, actions, children, className = '' }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-header">
          <div>
            {title && <h3 className="card-title">{title}</h3>}
            {subtitle && <div className="card-subtitle">{subtitle}</div>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function EmptyState({ icon = '◎', title, children }: { icon?: string; title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-icon" aria-hidden>{icon}</div>
      <h3>{title}</h3>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function NoAnalysis() {
  return (
    <Card>
      <EmptyState title="No analysis selected">
        <p>Analyse a testbed sample or upload a capture to see results here.</p>
        <Link className="btn btn-primary mt-md" to="/upload">Choose a capture</Link>
      </EmptyState>
    </Card>
  );
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="loading-spinner" role="status">
      <div className="spinner" />
      <p>{label}</p>
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return <div className="error-banner" role="alert">{message}</div>;
}

export function Tabs<T extends string>({ tabs, active, onChange }: {
  tabs: { key: T; label: string; count?: number }[]; active: T; onChange: (key: T) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.key} role="tab" aria-selected={active === t.key}
          className={`tab ${active === t.key ? 'active' : ''}`} onClick={() => onChange(t.key)}>
          {t.label}{t.count !== undefined && <span className="tab-count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function StatTile({ label, value, sub, status }: {
  label: string; value: ReactNode; sub?: ReactNode; status?: Status;
}) {
  return (
    <div className="tile">
      <div className="tile-label">{label}</div>
      <div className="tile-value">
        {status && status !== 'none' && <span className={`status-dot-sm s-${status}`} aria-hidden />}
        {value}
      </div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  );
}

export function StatusPill({ status, label }: { status: Status; label: string }) {
  return (
    <span className={`pill s-${status}`}>
      <span className="pill-icon" aria-hidden>{STATUS_ICON[status]}</span>{label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <StatusPill status={severityStatus[severity]} label={severity} />;
}

export function SourceBadge({ source, confidence }: { source: Source; confidence?: number }) {
  return (
    <span className={`source src-${source}`} title={
      source === 'observed' ? 'Read directly from cleartext protocol fields'
        : source === 'inferred' ? 'Derived from side channels (sizes, timing)'
          : 'Cannot be determined passively from this capture'}>
      {SOURCE_LABEL[source]}
      {source !== 'not_observable' && confidence !== undefined && <span className="source-conf">{pct(confidence)}</span>}
    </span>
  );
}

/** Horizontal meter: the unfilled track is a lighter step of the fill's own hue. */
export function Meter({ value, status = 'none', label }: { value: number | null; status?: Status; label?: string }) {
  const width = value === null ? 0 : Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className={`meter m-${status}`} role="meter" aria-valuemin={0} aria-valuemax={100}
      aria-valuenow={value === null ? undefined : Math.round(width)} aria-label={label}>
      <span style={{ width: `${width}%` }} />
    </div>
  );
}

export function KeyValue({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="kv">
      {items.map((item) => (
        <div key={item.label} className="kv-row">
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function TableWrap({ children }: { children: ReactNode }) {
  return <div className="table-wrap">{children}</div>;
}
