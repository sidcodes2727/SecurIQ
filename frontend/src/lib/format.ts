import type { Severity, Source } from '../types';

// Traffic classes in fixed order: color follows the class, never its rank.
export const TRAFFIC_CLASSES = ['icmp', 'web', 'voip', 'video', 'email', 'chat', 'file_transfer'] as const;

export const TRAFFIC_LABELS: Record<string, string> = {
  icmp: 'ICMP (ping)',
  web: 'Web browsing',
  voip: 'VoIP call',
  video: 'Video streaming',
  email: 'E-mail',
  chat: 'Chat / WhatsApp-like',
  file_transfer: 'File transfer',
};

export const classColor = (cls: string) => {
  const slot = TRAFFIC_CLASSES.indexOf(cls as (typeof TRAFFIC_CLASSES)[number]);
  return slot >= 0 ? `var(--series-${slot + 1})` : 'var(--viz-muted)';
};

/** Ink for a label placed inside a filled segment, chosen by the fill's luminance. */
export const classInk = (cls: string) => (cls === 'video' || cls === 'file_transfer' ? '#0b0b0b' : '#ffffff');

export const pct = (value: number | null | undefined, digits = 0) => {
  if (value === null || value === undefined) return '—';
  if (value > 0 && value * 100 < 0.5 * 10 ** -digits) return `<${(10 ** -digits).toFixed(digits)}%`;
  return `${(value * 100).toFixed(digits)}%`;
};

export const score = (value: number | null | undefined) =>
  value === null || value === undefined ? '—' : Number.isInteger(value) ? String(value) : value.toFixed(1);

export type Status = 'good' | 'warning' | 'serious' | 'critical' | 'none';

export const scoreStatus = (value: number | null | undefined): Status =>
  value === null || value === undefined ? 'none'
    : value >= 85 ? 'good' : value >= 70 ? 'warning' : value >= 50 ? 'serious' : 'critical';

// Low findings are neutral: a green check would read as "passed".
export const severityStatus: Record<Severity, Status> = {
  Critical: 'critical', High: 'serious', Medium: 'warning', Low: 'none', Informational: 'none',
};

/** Category ratings from the scoring engine (Excellent ≥ 90, Good ≥ 75, Moderate ≥ 55, Weak ≥ 35, Critical). */
export const ratingStatus = (rating: string): Status =>
  rating === 'Excellent' || rating === 'Good' ? 'good' : rating === 'Moderate' ? 'warning'
    : rating === 'Weak' ? 'serious' : rating === 'Critical' ? 'critical' : 'none';

export const riskLevelStatus = (level: string): Status =>
  level === 'Critical' ? 'critical' : level === 'High' ? 'serious' : level === 'Medium' ? 'warning'
    : level === 'Low' ? 'good' : 'none';

export const STATUS_ICON: Record<Status, string> = {
  good: '✓', warning: '!', serious: '▲', critical: '✕', none: '•',
};

export const SOURCE_LABEL: Record<Source, string> = {
  observed: 'Observed', inferred: 'Inferred', not_observable: 'Not observable',
};

export const displayValue = (value: unknown, display?: string): string => {
  if (display) return display;
  if (value === null || value === undefined) return 'Not observable';
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  return String(value);
};

export const titleCase = (key: string) =>
  key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

export const bytes = (n: number) =>
  n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;

export const compact = (n: number | null | undefined) =>
  n === null || n === undefined ? '—' : Intl.NumberFormat('en', { notation: 'compact' }).format(n);

export const timeAgo = (epochSeconds: number) => {
  const s = Math.max(0, Date.now() / 1000 - epochSeconds);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
};
