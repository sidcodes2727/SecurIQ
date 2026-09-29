/**
 * Object-explorer query language.
 *
 *   dh:2 dh:5 pfs:off risk:high score<60 -src:lab finding:KE "weak vpn"
 *
 * Same field → OR; different fields → AND; a leading "-" negates; free words must all appear in the
 * capture's name, fingerprint or gateways. Numeric fields accept <, >, <=, >=, :.
 */
import type { FleetRow } from '../types';
import { TRAFFIC_LABELS } from './format';

type Kind = 'text' | 'num' | 'list' | 'bool';
type Match = 'contains' | 'prefix' | 'equals';

interface Field { label: string; kind: Kind; match?: Match; get: (r: FleetRow) => unknown }

export const FIELDS: Record<string, Field> = {
  ike: { label: 'IKE version', kind: 'text', match: 'contains', get: (r) => r.ike_version },
  exchange: { label: 'Exchange mode', kind: 'text', match: 'contains', get: (r) => r.exchange_mode },
  enc: { label: 'IKE cipher', kind: 'text', match: 'contains', get: (r) => r.ike_encryption },
  integ: { label: 'IKE integrity', kind: 'text', match: 'contains', get: (r) => r.ike_integrity },
  dh: { label: 'DH group', kind: 'num', get: (r) => r.dh_group },
  esp: { label: 'ESP cipher', kind: 'text', match: 'contains', get: (r) => r.esp_encryption },
  pfs: { label: 'PFS', kind: 'text', match: 'equals', get: (r) => r.pfs ?? 'unknown' },
  mode: { label: 'Mode', kind: 'text', match: 'prefix', get: (r) => r.mode ?? 'unknown' },
  auth: { label: 'Authentication', kind: 'text', match: 'prefix', get: (r) => r.auth ?? 'unknown' },
  risk: { label: 'Risk', kind: 'text', match: 'prefix', get: (r) => r.risk_level },
  policy: { label: 'Golden policy', kind: 'text', match: 'prefix', get: (r) => r.policy_status },
  novelty: { label: 'Novelty', kind: 'text', match: 'prefix', get: (r) => r.novelty },
  src: { label: 'Source', kind: 'text', match: 'prefix', get: (r) => r.source },
  ip: { label: 'IP version', kind: 'text', match: 'contains', get: (r) => r.ip_version },
  nat: { label: 'NAT-T', kind: 'bool', get: (r) => r.nat_t },
  traffic: { label: 'Traffic', kind: 'list', match: 'prefix', get: (r) => r.traffic },
  finding: { label: 'Finding', kind: 'list', match: 'prefix', get: (r) => r.findings.map((f) => f.id) },
  sev: { label: 'Severity', kind: 'list', match: 'prefix', get: (r) => r.findings.map((f) => f.severity) },
  gw: { label: 'Gateway', kind: 'list', match: 'contains', get: (r) => r.gateways },
  fp: { label: 'Fingerprint', kind: 'text', match: 'prefix', get: (r) => r.fingerprint },
  score: { label: 'Score', kind: 'num', get: (r) => r.score },
  bits: { label: 'Strength (bits)', kind: 'num', get: (r) => r.strength_bits },
  privacy: { label: 'Metadata privacy', kind: 'num', get: (r) => r.metadata_privacy },
  packets: { label: 'Packets', kind: 'num', get: (r) => r.packets },
};

export interface Token { raw: string; key: string | null; op: ':' | '<' | '>' | '<=' | '>='; value: string; neg: boolean; valid: boolean; error?: string }

export function tokenize(q: string): string[] {
  const out: string[] = [];
  const re = /(-?[a-z]+(?:<=|>=|:|<|>)"[^"]*"|-?[a-z]+(?:<=|>=|:|<|>)\S+|"[^"]*"|\S+)/gi;
  for (const m of q.matchAll(re)) out.push(m[0]);
  return out;
}

export function parse(q: string): Token[] {
  return tokenize(q).map((raw) => {
    const m = raw.match(/^(-?)([a-z]+)(<=|>=|:|<|>)(.+)$/i);
    if (!m) return { raw, key: null, op: ':', value: raw.replace(/^"|"$/g, ''), neg: false, valid: true };
    const [, neg, key, op, rawValue] = m;
    const value = rawValue.replace(/^"|"$/g, '');
    const field = FIELDS[key.toLowerCase()];
    if (!field) return { raw, key: key.toLowerCase(), op: op as Token['op'], value, neg: !!neg, valid: false, error: `Unknown field "${key}"` };
    if (op !== ':' && field.kind !== 'num') return { raw, key: key.toLowerCase(), op: op as Token['op'], value, neg: !!neg, valid: false, error: `${key} is not numeric` };
    if (field.kind === 'num' && Number.isNaN(Number(value))) return { raw, key: key.toLowerCase(), op: op as Token['op'], value, neg: !!neg, valid: false, error: `${key} needs a number` };
    return { raw, key: key.toLowerCase(), op: op as Token['op'], value, neg: !!neg, valid: true };
  });
}

const norm = (v: unknown) => String(v ?? '').toLowerCase();

function matchOne(field: Field, token: Token, row: FleetRow): boolean {
  const raw = field.get(row);
  const want = token.value.toLowerCase();
  if (field.kind === 'num') {
    if (raw === null || raw === undefined) return false;
    const n = Number(raw), v = Number(token.value);
    switch (token.op) {
      case '<': return n < v;
      case '>': return n > v;
      case '<=': return n <= v;
      case '>=': return n >= v;
      default: return n === v;
    }
  }
  if (field.kind === 'bool') return ['yes', 'true', 'on', '1'].includes(want) ? !!raw : !raw;
  const values = field.kind === 'list' ? (raw as unknown[]).flatMap((x) => [x, TRAFFIC_LABELS[String(x)] ?? '']) : [raw];
  return values.some((x) => {
    const s = norm(x);
    if (!s) return false;
    return field.match === 'equals' ? s === want : field.match === 'prefix' ? s.startsWith(want) : s.includes(want);
  });
}

/** Rows matching every token except (optionally) the positive tokens of one field — used for facet counts. */
export function applyQuery(rows: FleetRow[], tokens: Token[], exceptKey?: string): FleetRow[] {
  const valid = tokens.filter((t) => t.valid);
  const byKey = new Map<string, Token[]>();
  for (const t of valid) if (t.key && !t.neg && t.key !== exceptKey) byKey.set(t.key, [...(byKey.get(t.key) ?? []), t]);
  const negs = valid.filter((t) => t.key && t.neg);
  const words = valid.filter((t) => !t.key).map((t) => t.value.toLowerCase());
  return rows.filter((row) => {
    for (const [key, list] of byKey) if (!list.some((t) => matchOne(FIELDS[key], t, row))) return false;
    for (const t of negs) if (matchOne(FIELDS[t.key!], t, row)) return false;
    if (words.length) {
      const hay = `${row.filename} ${row.fingerprint} ${row.fingerprint_label} ${row.gateways.join(' ')}`.toLowerCase();
      if (!words.every((w) => hay.includes(w))) return false;
    }
    return true;
  });
}

export const quote = (v: string) => (/\s/.test(v) ? `"${v}"` : v);

/** Toggle `key:value` in the query text (facet clicks). */
export function toggleToken(q: string, key: string, value: string): string {
  const tokens = parse(q);
  const hit = tokens.find((t) => t.key === key && !t.neg && t.op === ':' && t.value.toLowerCase() === value.toLowerCase());
  if (hit) return tokenize(q).filter((raw) => raw !== hit.raw).join(' ');
  return `${q.trim()} ${key}:${quote(value)}`.trim();
}

export const isActive = (tokens: Token[], key: string, value: string) =>
  tokens.some((t) => t.key === key && !t.neg && t.op === ':' && t.value.toLowerCase() === value.toLowerCase());
