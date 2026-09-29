import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Page } from '../components/Layout';
import { Card, ErrorBanner, Loading, SourceBadge, StatusPill, TableWrap } from '../components/ui';
import { useAnalysisId } from '../hooks/useAnalysis';
import { timeAgo } from '../lib/format';
import { api } from '../services/api';
import type { Loose, PolicyResult } from '../types';

const DH = [2, 5, 14, 15, 16, 19, 20, 21, 31];
const DH_NAME: Record<number, string> = { 2: 'MODP-1024', 5: 'MODP-1536', 14: 'MODP-2048', 15: 'MODP-3072', 16: 'MODP-4096',
  19: 'ECP-256', 20: 'ECP-384', 21: 'ECP-521', 31: 'Curve25519' };
const HOURS = [3600, 14400, 28800, 86400, 604800];
const STATUS = { pass: 'good', fail: 'critical', unknown: 'none' } as const;

function toggle<T>(list: T[], item: T): T[] {
  return list.includes(item) ? list.filter((x) => x !== item) : [...list, item];
}

function yaml(p: Loose): string {
  const list = (xs: unknown[]) => xs.map((x) => `\n  - ${x}`).join('');
  return [
    `name: ${p.name}`,
    `allowed_ike_versions:${list(p.allowed_ike_versions)}`,
    `allow_aggressive_mode: ${p.allow_aggressive_mode}`,
    `min_ike_encryption_bits: ${p.min_ike_encryption_bits}`,
    `require_aead_esp: ${p.require_aead_esp}`,
    `min_esp_encryption_bits: ${p.min_esp_encryption_bits}`,
    `forbidden_integrity:${list(p.forbidden_integrity)}`,
    `allowed_dh:${list(p.allowed_dh_groups.map((g: number) => `group${g}`))}`,
    `pfs: ${p.require_pfs ? 'required' : 'optional'}`,
    `allowed_modes:${list(p.allowed_modes.map((m: string) => m.toLowerCase()))}`,
    `max_ike_sa_lifetime: ${p.max_ike_lifetime_s}`,
    `max_child_sa_lifetime: ${p.max_child_lifetime_s}`,
    `allowed_auth:${list(p.allowed_auth)}`,
    `require_replay_integrity: ${p.require_replay_integrity}`,
    `forbid_weak_proposals: ${p.forbid_weak_proposals}`,
    `forbid_vendor_ids: ${p.forbid_vendor_ids}`,
    `allow_nat_t: ${p.allow_nat_t}`,
  ].join('\n');
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <div className="policy-field"><span className="field">{label}</span><div className="policy-control">{children}</div></div>;
}

export default function Policy() {
  const id = useAnalysisId();
  const [policy, setPolicy] = useState<Loose>(null);
  const [saved, setSaved] = useState<Loose>(null);
  const [evaluation, setEvaluation] = useState<PolicyResult | null>(null);
  const [fleet, setFleet] = useState<Loose[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    if (id) api.evaluatePolicy(id).then(setEvaluation).catch(() => setEvaluation(null));
    api.policyFleet().then((d) => setFleet(d.analyses)).catch(() => {});
  }, [id]);

  useEffect(() => {
    api.getPolicy().then((d) => { setPolicy(d.policy); setSaved(d.policy); }).catch((e) => setError(e.message));
  }, []);
  useEffect(refresh, [refresh]);

  if (!policy) return <Page title="Golden policy">{error ? <ErrorBanner message={error} /> : <Loading />}</Page>;
  const dirty = JSON.stringify(policy) !== JSON.stringify(saved);
  const set = (key: string, value: unknown) => setPolicy({ ...policy, [key]: value });

  const save = async () => {
    setBusy(true); setError(null);
    try { const d = await api.savePolicy(policy); setPolicy(d.policy); setSaved(d.policy); refresh(); }
    catch (e) { setError((e as Error).message); }
    setBusy(false);
  };
  const reset = async () => {
    setBusy(true);
    try { const d = await api.resetPolicy(); setPolicy(d.policy); setSaved(d.policy); refresh(); } catch { /* keep form */ }
    setBusy(false);
  };

  return (
    <Page title="Golden policy" subtitle="State the configuration your organisation requires. Every capture is checked against it; a requirement the capture cannot show is reported as unknown, never as a pass.">
      {error && <ErrorBanner message={error} />}
      <div className="grid-side policy-grid">
        <Card title="Policy" subtitle={dirty ? 'Unsaved changes' : 'Saved on the analysis server'}
          actions={<>
            <button className="btn btn-sm btn-primary" disabled={!dirty || busy} onClick={save}>Save policy</button>
            <button className="btn btn-sm btn-secondary" disabled={busy} onClick={reset}>Restore default</button>
          </>}>
          <div className="policy-form">
            <Field label="IKE versions">
              {['IKEv2', 'IKEv1'].map((v) => <label key={v} className="check"><input type="checkbox" checked={policy.allowed_ike_versions.includes(v)}
                onChange={() => set('allowed_ike_versions', toggle(policy.allowed_ike_versions, v))} />{v}</label>)}
              <label className="check"><input type="checkbox" checked={policy.allow_aggressive_mode}
                onChange={(e) => set('allow_aggressive_mode', e.target.checked)} />allow Aggressive Mode</label>
            </Field>
            <Field label="IKE SA encryption">
              <select value={policy.min_ike_encryption_bits} onChange={(e) => set('min_ike_encryption_bits', Number(e.target.value))}>
                {[112, 128, 192, 256].map((b) => <option key={b} value={b}>≥ {b}-bit</option>)}
              </select>
            </Field>
            <Field label="ESP encryption">
              <label className="check"><input type="checkbox" checked={policy.require_aead_esp}
                onChange={(e) => set('require_aead_esp', e.target.checked)} />require AEAD (GCM / ChaCha20)</label>
              <select value={policy.min_esp_encryption_bits} onChange={(e) => set('min_esp_encryption_bits', Number(e.target.value))}>
                {[128, 192, 256].map((b) => <option key={b} value={b}>≥ {b}-bit</option>)}
              </select>
            </Field>
            <Field label="Forbidden integrity">
              {['MD5', 'SHA1'].map((v) => <label key={v} className="check"><input type="checkbox" checked={policy.forbidden_integrity.includes(v)}
                onChange={() => set('forbidden_integrity', toggle(policy.forbidden_integrity, v))} />{v}</label>)}
            </Field>
            <Field label="Allowed DH groups">
              <div className="check-grid">
                {DH.map((g) => <label key={g} className="check"><input type="checkbox" checked={policy.allowed_dh_groups.includes(g)}
                  onChange={() => set('allowed_dh_groups', toggle(policy.allowed_dh_groups, g).sort((a: number, b: number) => a - b))} />
                  {g} <span className="muted">{DH_NAME[g]}</span></label>)}
              </div>
            </Field>
            <Field label="Forward secrecy">
              <label className="check"><input type="checkbox" checked={policy.require_pfs} onChange={(e) => set('require_pfs', e.target.checked)} />PFS required</label>
            </Field>
            <Field label="Modes">
              {['Tunnel', 'Transport'].map((v) => <label key={v} className="check"><input type="checkbox" checked={policy.allowed_modes.includes(v)}
                onChange={() => set('allowed_modes', toggle(policy.allowed_modes, v))} />{v}</label>)}
            </Field>
            <Field label="Max lifetimes">
              <select aria-label="Maximum IKE SA lifetime" value={policy.max_ike_lifetime_s} onChange={(e) => set('max_ike_lifetime_s', Number(e.target.value))}>
                {HOURS.map((h) => <option key={h} value={h}>IKE SA ≤ {h / 3600} h</option>)}
              </select>
              <select aria-label="Maximum Child SA lifetime" value={policy.max_child_lifetime_s} onChange={(e) => set('max_child_lifetime_s', Number(e.target.value))}>
                {[1800, ...HOURS].map((h) => <option key={h} value={h}>Child SA ≤ {h / 3600} h</option>)}
              </select>
            </Field>
            <Field label="Authentication">
              {['certificate', 'eap', 'psk'].map((v) => <label key={v} className="check"><input type="checkbox" checked={policy.allowed_auth.includes(v)}
                onChange={() => set('allowed_auth', toggle(policy.allowed_auth, v))} />{v.toUpperCase()}</label>)}
            </Field>
            <Field label="Hardening">
              {([['require_replay_integrity', 'no replayed / reset sequence numbers'], ['forbid_weak_proposals', 'no weak fallback proposals'],
                ['forbid_vendor_ids', 'no product-identifying Vendor IDs'], ['allow_nat_t', 'NAT traversal allowed']] as const).map(([k, label]) => (
                <label key={k} className="check"><input type="checkbox" checked={policy[k]} onChange={(e) => set(k, e.target.checked)} />{label}</label>
              ))}
            </Field>
          </div>
        </Card>
        <Card title="As code" subtitle="policy.yaml — what the engine enforces">
          <pre className="code">{yaml(policy)}</pre>
        </Card>
      </div>

      <Card title="Compliance of the capture in scope" className="mt-md"
        subtitle={evaluation ? `${evaluation.counts.pass} pass · ${evaluation.counts.fail} fail · ${evaluation.counts.unknown} not observable` : 'Select an analysis first'}
        actions={evaluation && <StatusPill status={evaluation.compliant ? 'good' : 'critical'} label={evaluation.status} />}>
        {!id ? <p className="muted">No analysis in scope. <Link to="/upload">Analyse a capture</Link>.</p> : !evaluation ? <Loading /> : (
          <TableWrap>
            <table className="data-table">
              <thead><tr><th>Requirement</th><th>Observed</th><th>Basis</th><th>Status</th></tr></thead>
              <tbody>{evaluation.rows.map((row) => (
                <tr key={row.key + row.requirement}>
                  <td className="text-primary">{row.requirement}</td>
                  <td>{row.observed}</td>
                  <td>{row.source && ['observed', 'inferred', 'not_observable'].includes(row.source) ? <SourceBadge source={row.source as 'observed'} /> : <span className="muted">—</span>}</td>
                  <td><StatusPill status={STATUS[row.status]} label={row.status === 'unknown' ? 'not observable' : row.status} /></td>
                </tr>))}</tbody>
            </table>
          </TableWrap>
        )}
        {evaluation && !evaluation.compliant && id && (
          <p className="hint">See which changes would make it compliant: <Link to={`/simulator?id=${id}&fix=1`}>what-if simulator</Link>.</p>
        )}
      </Card>

      <Card title="Fleet view" className="mt-md" subtitle="Every stored capture against the saved policy">
        {fleet.length === 0 ? <p className="muted">No analyses yet.</p> : (
          <TableWrap>
            <table className="data-table">
              <thead><tr><th>Capture</th><th>Status</th><th className="num">Pass</th><th className="num">Fail</th><th className="num">Unknown</th><th /></tr></thead>
              <tbody>{fleet.map((f) => (
                <tr key={f.analysis_id}>
                  <td className="text-primary">{f.filename}<div className="muted text-xs">{timeAgo(f.created)}</div></td>
                  <td><StatusPill status={f.counts.fail ? 'critical' : 'good'} label={f.status} /></td>
                  <td className="num">{f.counts.pass}</td><td className="num">{f.counts.fail}</td><td className="num">{f.counts.unknown}</td>
                  <td><Link className="btn btn-sm btn-secondary" to={`/policy?id=${f.analysis_id}`}>Inspect</Link></td>
                </tr>))}</tbody>
            </table>
          </TableWrap>
        )}
      </Card>
    </Page>
  );
}
