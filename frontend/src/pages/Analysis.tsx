import { Fragment, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Checklist, EspAnatomy, FingerprintBadge, IkeLadder, ReplayChart } from '../components/ipsec';
import { Page } from '../components/Layout';
import { InvestigationTimeline } from '../components/Timeline';
import {
  Card, ErrorBanner, KeyValue, Loading, Meter, NoAnalysis, SourceBadge, StatTile, StatusPill, TableWrap, Tabs,
} from '../components/ui';
import { useAnalysis, useIntel } from '../hooks/useAnalysis';
import { bytes, displayValue, pct } from '../lib/format';
import { api } from '../services/api';
import type { AnalysisRecord, Evidence, Intel, Loose } from '../types';

const PROFILE_LABELS: Record<string, string> = {
  ipsec_protocols: 'IPsec protocol',
  ike_version: 'IKE version',
  exchange_mode: 'Exchange mode',
  mode: 'Tunnel / transport mode',
  ike_encryption: 'IKE SA encryption',
  ike_integrity: 'IKE SA integrity',
  ike_prf: 'IKE SA PRF',
  key_exchange: 'Key exchange',
  esp_encryption: 'ESP (Child SA) encryption',
  esp_integrity: 'ESP (Child SA) integrity',
  authentication_method: 'Authentication',
  pfs: 'Perfect Forward Secrecy',
  ike_lifetime: 'IKE SA lifetime',
  child_sa_lifetime: 'Child SA lifetime',
  replay_protection: 'Replay protection',
  nat_traversal: 'NAT traversal',
  ip_version: 'IP version',
  implementation: 'Implementation',
  traffic_types: 'Traffic inside the tunnel',
};

type Tab = 'identification' | 'ike' | 'esp' | 'truth' | 'timeline' | 'packets';

export default function Analysis() {
  const { id, data, loading, error } = useAnalysis();
  const { intel } = useIntel(id);
  const [params] = useSearchParams();
  const [tab, setTab] = useState<Tab>((params.get('tab') as Tab) || 'identification');

  if (!id) return <Page title="Protocol identification"><NoAnalysis /></Page>;
  if (loading || (!data && !error)) return <Page title="Protocol identification"><Loading label="Loading analysis…" /></Page>;
  if (error || !data) return <Page title="Protocol identification"><ErrorBanner message={error ?? 'Not found'} /></Page>;

  const analysis = data.ipsec_analysis;
  const profile: Record<string, Evidence> = analysis.profile;
  const meta = data.parsed_metadata;
  const tabs: { key: Tab; label: string; count?: number }[] = [
    { key: 'identification', label: 'Identification' },
    { key: 'ike', label: 'IKE negotiation' },
    { key: 'esp', label: 'ESP / AH' },
    ...(data.ground_truth ? [{ key: 'truth' as Tab, label: 'Ground truth', count: data.ground_truth.rows.length }] : []),
    { key: 'timeline', label: 'Timeline' },
    { key: 'packets', label: 'Packets' },
  ];

  return (
    <Page title="Protocol identification" subtitle={`${meta.filename} · what the VPN is, and the evidence for each claim`}
      meta={intel && <FingerprintBadge fp={intel.fingerprint} large />}>
      <div className="capture-strip">
        <span>{meta.total_packets.toLocaleString()} packets</span>
        <span>{bytes(meta.file_size)}</span>
        <span>{analysis.capture_duration?.toFixed(1)} s captured</span>
        <span>parsed in {meta.parse_duration_ms} ms</span>
        <span>full pipeline {data.pipeline_seconds} s</span>
        <span className="mono muted">sha256 {meta.file_hash}</span>
      </div>

      <div className="kpi-row">
        {(['ipsec_protocols', 'ike_version', 'mode', 'esp_encryption', 'pfs'] as const).map((key) => (
          <StatTile key={key} label={PROFILE_LABELS[key]} value={<span className="tile-text">{displayValue(profile[key]?.value)}</span>}
            sub={profile[key] && <SourceBadge source={profile[key].source} confidence={profile[key].confidence} />} />
        ))}
      </div>

      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === 'identification' && <IdentificationTab profile={profile} data={data} intel={intel} />}
      {tab === 'ike' && <IkeTab ike={analysis.ike_analysis} start={analysis.capture_start} />}
      {tab === 'esp' && <EspTab analysis={analysis} />}
      {tab === 'truth' && data.ground_truth && <GroundTruthTab data={data} />}
      {tab === 'timeline' && <Card title="Investigation timeline" subtitle="IKE control traffic, every tunnel's lifetime with the application inside it, rekeys and replay anomalies on one axis. Wheel or drag the overview to zoom; drag to pan; select an event to jump to it."><InvestigationTimeline analysis={analysis} classification={data.classification} /></Card>}
      {tab === 'packets' && <PacketsTab id={data.analysis_id} start={analysis.capture_start} />}
    </Page>
  );
}

function IdentificationTab({ profile, data, intel }: { profile: Record<string, Evidence>; data: AnalysisRecord; intel: Intel | null }) {
  const ai = data.ai_confidence;
  const [open, setOpen] = useState<string | null>(null);
  const novelty = intel?.novelty;
  return (
    <>
      <div className="legend-note">
        <SourceBadge source="observed" /> read from cleartext fields ·
        <SourceBadge source="inferred" /> derived from sizes / timing, with confidence ·
        <SourceBadge source="not_observable" /> cannot be determined passively, never guessed ·
        <span>Select a row for its evidence checklist.</span>
      </div>
      <Card>
        <TableWrap>
          <table className="data-table evidence-table">
            <thead><tr><th /><th>Property</th><th>Value</th><th>Basis</th><th className="conf-col">Confidence</th><th>Evidence</th></tr></thead>
            <tbody>
              {Object.keys(PROFILE_LABELS).filter((k) => profile[k]).map((key) => {
                const e = profile[key];
                const checks = intel?.checks[key];
                const expanded = open === key;
                return (
                  <Fragment key={key}>
                    <tr className={checks ? 'clickable' : ''} aria-expanded={checks ? expanded : undefined}
                      onClick={() => checks && setOpen(expanded ? null : key)}>
                      <td className="expander">{checks ? (expanded ? '▾' : '▸') : ''}</td>
                      <td className="text-primary">{PROFILE_LABELS[key]}</td>
                      <td className={`value-cell ${e.source === 'not_observable' ? 'unknown' : ''}`}>
                        {displayValue(e.value, e.display as string | undefined)}</td>
                      <td><SourceBadge source={e.source} /></td>
                      <td className="conf-col">{e.source !== 'not_observable' && (
                        <div className="meter-row"><Meter value={e.confidence}
                          label={`${PROFILE_LABELS[key]} confidence`} />
                          <span className="num">{pct(e.confidence)}</span></div>)}</td>
                      <td className="evidence-cell">{e.evidence}{e.method && <div className="muted text-xs">Method: {e.method}</div>}</td>
                    </tr>
                    {expanded && checks && (
                      <tr className="detail-row"><td /><td colSpan={5}>
                        <div className="check-panel">
                          <span className="tile-label">Why {displayValue(e.value, e.display as string | undefined)} ·{' '}
                            {e.source === 'observed' ? 'observed' : `${pct(e.confidence)} confidence`}</span>
                          <Checklist checks={checks.checks} caveats={checks.caveats} />
                        </div>
                      </td></tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      </Card>
      <div className="grid-2 mt-md">
        {novelty && (
          <Card title="Known or novel configuration?" subtitle={novelty.method}
            actions={<StatusPill status={novelty.status === 'known' ? 'good' : novelty.status === 'unusual' ? 'warning' : 'serious'}
              label={novelty.status === 'known' ? 'known configuration' : novelty.status === 'unusual' ? 'unusual' : 'novel'} />}>
            {novelty.signals.length === 0
              ? <p className="text-sm">Every parameter is a registered, commonly deployed value, and all traffic windows resemble the training data.</p>
              : (
                <ul className="checklist">{novelty.signals.map((sig, i) => (
                  <li key={i}><span className={`ck ${sig.level === 'novel' ? 'ck-bad' : sig.level === 'unusual' ? 'ck-warn' : 'ck-na'}`}>
                    {sig.level === 'novel' ? '✕' : sig.level === 'unusual' ? '!' : 'i'}</span><span>{sig.text}</span></li>))}</ul>
              )}
          </Card>
        )}
        <Card title="Identification confidence" subtitle={ai.formula}>
          <KeyValue items={[
            { label: 'Fields observed from cleartext', value: ai.fields_observed },
            { label: 'Fields inferred from side channels', value: ai.fields_inferred },
            { label: 'Fields not observable', value: ai.fields_not_observable },
            { label: 'Mean confidence of determined fields', value: pct(ai.identification) },
          ]} />
        </Card>
      </div>
    </>
  );
}

function IkeTab({ ike, start }: { ike: Loose; start: number }) {
  if (!ike.detected) return <Card><p className="muted">{ike.message}</p></Card>;
  const chosen = ike.chosen_suite ?? {};
  const pfs = ike.pfs ?? {};
  const session = ike.sessions?.find((x: Loose) => x.init_spi === ike.primary_session) ?? ike.sessions?.[0];
  return (
    <div className="stack">
      {session && (
        <Card title="Negotiation ladder" subtitle={`IKE SA ${session.init_spi} · white = cleartext payloads anyone can read, teal = encrypted SK payload whose content is only inferable from its size`}>
          <IkeLadder session={session} start={start} />
        </Card>
      )}
      {ike.identities?.length > 0 && (
        <div className="alert alert-critical">
          <strong>Identities sent in cleartext.</strong> {ike.identities.map((i: Loose) => `${i.id_type} “${i.value}” (${i.sender})`).join(' · ')}
        </div>
      )}
      {ike.downgrade_surface?.length > 0 && (
        <div className="alert alert-warning">
          <strong>Downgrade surface.</strong> The initiator also offers {ike.downgrade_surface.join(', ')}.
        </div>
      )}
      <div className="grid-2">
        <Card title="Negotiation" subtitle="From cleartext IKE_SA_INIT / Main-Aggressive Mode messages">
          <KeyValue items={[
            { label: 'Version', value: ike.version },
            { label: 'Exchange mode', value: ike.exchange_mode },
            { label: 'Exchanges seen', value: ike.exchange_types.join(', ') },
            { label: 'IKE SAs', value: ike.session_count },
            { label: 'Signature hashes offered', value: ike.signature_hashes?.join(', ') || '—' },
            { label: 'Cookie challenge (DoS protection)', value: ike.cookie_challenge ? 'Yes' : 'No' },
          ]} />
        </Card>
        <Card title="Selected IKE SA suite" subtitle={chosen.source === 'responder' ? 'Responder’s choice (observed)' : chosen.source}>
          <KeyValue items={[
            { label: 'Encryption', value: chosen.encryption ?? '—' },
            { label: 'Integrity', value: chosen.integrity ?? '—' },
            { label: 'PRF', value: chosen.prf ?? '—' },
            { label: 'Diffie-Hellman', value: chosen.dh_group_name ? `${chosen.dh_group_name} (group ${chosen.dh_group})` : '—' },
            ...(chosen.auth_method ? [{ label: 'Authentication', value: chosen.auth_method }] : []),
            ...(chosen.life_seconds ? [{ label: 'Lifetime', value: `${chosen.life_seconds.toLocaleString()} s` }] : []),
          ]} />
        </Card>
      </div>

      <Card title="Offered proposals" subtitle="What the initiator was willing to accept — visible to any observer">
        <TableWrap>
          <table className="data-table">
            <thead><tr><th>#</th><th>Protocol</th><th>Encryption</th><th>Integrity</th><th>PRF</th><th>DH groups</th><th>Auth / lifetime</th></tr></thead>
            <tbody>
              {ike.offered_proposals.map((p: Loose, i: number) => (
                <tr key={i}>
                  <td>{p.number}{p.transform_number ? `.${p.transform_number}` : ''}</td>
                  <td>{p.protocol}</td><td>{p.encryption.join(', ')}</td><td>{p.integrity.join(', ') || '—'}</td>
                  <td>{p.prf.join(', ')}</td><td>{p.dh_groups.join(', ')}</td>
                  <td>{p.auth_method ?? ''}{p.life_seconds ? ` · ${p.life_seconds} s` : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Card>

      <div className="grid-2">
        <Card title="Vendor IDs" subtitle="Cleartext product and feature fingerprints">
          {ike.vendor_ids.length === 0 ? <p className="muted">None sent.</p> : (
            <ul className="plain-list">{ike.vendor_ids.map((v: Loose) => (
              <li key={v.hex}>{v.name}{v.reveals_implementation && <StatusPill status="warning" label="reveals product" />}
                <div className="mono muted text-xs">{v.hex.slice(0, 32)}</div></li>))}</ul>
          )}
        </Card>
        <Card title="Notifications">
          <div className="chips">{ike.notifies.map((n: Loose) => <span className="chip" key={n.type}>{n.name}</span>)}</div>
        </Card>
      </div>

      <Card title="Child SA negotiations — PFS size analysis"
        subtitle="The KE payload travels inside encrypted CREATE_CHILD_SA / Quick Mode messages; its presence shows in the message size">
        <p className="text-sm">{pfs.evidence}</p>
        {pfs.exchanges?.length > 0 && (
          <TableWrap>
            <table className="data-table">
              <thead><tr><th className="num">Message ID</th><th className="num">Size</th><th>Measured</th><th className="num">Threshold</th><th>Kind</th><th>KE payload</th></tr></thead>
              <tbody>{pfs.exchanges.map((d: Loose, i: number) => (
                <tr key={i}><td className="num">{d.message_id}</td><td className="num">{d.length} B</td><td>{d.measured ?? 'cleartext'}</td>
                  <td className="num">{d.threshold ? `${d.threshold} B` : '—'}</td><td>{d.kind.replace('_', ' ')}</td>
                  <td>{d.pfs === null || d.pfs === undefined ? '—' : d.pfs ? 'present' : 'absent'}</td></tr>))}</tbody>
            </table>
          </TableWrap>
        )}
      </Card>
    </div>
  );
}

function EspTab({ analysis }: { analysis: Loose }) {
  const esp = analysis.esp_analysis;
  const ah = analysis.ah_analysis;
  const nat = analysis.nat_t_analysis;
  const fp = esp.fingerprint ?? {};
  const sas: Loose[] = esp.sa_info ?? [];
  const ranked = [...sas].sort((a, b) => (b.replay?.events?.length ?? 0) - (a.replay?.events?.length ?? 0) || b.packet_count - a.packet_count);
  const [pick, setPick] = useState<string | null>(null);
  const chosen = sas.find((sa) => `${sa.spi}|${sa.src}` === pick) ?? ranked[0];
  const profile = analysis.profile ?? {};
  const meanLen = sas.length ? sas.reduce((sum, sa) => sum + sa.avg_payload_size * sa.packet_count, 0) / Math.max(1, esp.packet_count) : undefined;
  return (
    <div className="stack">
      {esp.detected ? (
        <>
          <Card title="ESP packet anatomy" subtitle="Reconstructed from payload lengths alone: an ESP payload is IV ‖ padded ciphertext ‖ ICV, so the length residue reveals block size and ICV">
            <EspAnatomy fp={fp} mode={profile.mode?.value} ipVersion={profile.ip_version?.value} natT={nat.detected} avgLen={meanLen} />
          </Card>
          <div className="grid-2">
            <Card title="ESP length fingerprint" subtitle="Which cipher family the framing allows, and how sure that is">
              <KeyValue items={[
                { label: 'Inferred suite', value: fp.suite ?? fp.status },
                { label: 'Block size / IV', value: fp.block_size ? `${fp.block_size} B / ${fp.iv_len} B` : '—' },
                { label: 'ICV length', value: fp.icv_len_candidates?.length ? `${fp.icv_len_candidates.join(' or ')} B` : '—' },
                { label: 'Distinct lengths', value: `${fp.distinct_lengths} across ${fp.packets} packets` },
                { label: 'Confidence', value: pct(fp.confidence) },
              ]} />
              <p className="hint">{fp.evidence}</p>
            </Card>
            <Card title="Mode & confidentiality checks">
              <KeyValue items={[
                { label: 'Mode inference', value: esp.mode_inference.value ? `${esp.mode_inference.value} (${pct(esp.mode_inference.confidence)})` : 'undetermined' },
                { label: 'ESP-NULL test', value: esp.null_encryption.suspected ? 'Cleartext payloads detected' : 'Payloads look encrypted' },
                { label: 'Replay: duplicates / resets', value: `${esp.replay_summary.duplicates} / ${esp.replay_summary.counter_resets}` },
                { label: 'Max reorder depth', value: esp.replay_summary.max_reorder_depth },
                { label: 'NAT traversal', value: nat.detected ? `Yes — ${nat.encapsulation}` : 'No' },
              ]} />
              <p className="hint">{esp.mode_inference.evidence}</p>
            </Card>
          </div>
          <Card title="Anti-replay: sequence numbers"
            subtitle="Every SA's 32-bit counter must rise monotonically (RFC 4303 §3.3.3). A repeat is a replay; a drop back to 1 without a new SPI is a counter reset."
            actions={sas.length > 1 && (
              <select aria-label="Security Association" value={chosen ? `${chosen.spi}|${chosen.src}` : ''} onChange={(e) => setPick(e.target.value)}>
                {ranked.slice(0, 30).map((sa) => (
                  <option key={`${sa.spi}|${sa.src}`} value={`${sa.spi}|${sa.src}`}>
                    {sa.spi} · {sa.packet_count} pkts{sa.replay?.events?.length ? ` · ${sa.replay.events.length} anomalies` : ''}</option>))}
              </select>
            )}>
            {chosen ? <ReplayChart sa={chosen} /> : <p className="muted">No SA.</p>}
          </Card>
          <Card title="Security Associations" subtitle="One SPI per direction; paired into bidirectional tunnels for classification. Select a row to plot its sequence numbers.">
            <TableWrap>
              <table className="data-table">
                <thead><tr><th>SPI</th><th>Direction</th><th className="num">Packets</th><th className="num">Duration</th>
                  <th className="num">Seq range</th><th>Fingerprint</th><th>Replay</th></tr></thead>
                <tbody>{sas.slice(0, 50).map((sa: Loose) => (
                  <tr key={`${sa.spi}-${sa.src}`} className="clickable" onClick={() => setPick(`${sa.spi}|${sa.src}`)}>
                    <td className="mono text-xs">{sa.spi}</td><td>{sa.src} → {sa.dst}</td><td className="num">{sa.packet_count.toLocaleString()}</td>
                    <td className="num">{sa.duration.toFixed(1)} s</td><td className="num">{sa.min_seq}–{sa.max_seq}</td>
                    <td>{sa.fingerprint.suite ?? sa.fingerprint.status.replace('_', ' ')}</td>
                    <td>{sa.replay.duplicates || sa.replay.counter_resets
                      ? <StatusPill status="serious" label={`${sa.replay.duplicates} dup · ${sa.replay.counter_resets} reset`} />
                      : <span className="muted">clean</span>}</td>
                  </tr>))}</tbody>
              </table>
            </TableWrap>
          </Card>
        </>
      ) : <Card><p className="muted">No ESP traffic in this capture.</p></Card>}
      {ah.detected && (
        <Card title="Authentication Header (AH)" subtitle={ah.note}>
          <KeyValue items={[
            { label: 'Mode (observed from Next Header)', value: ah.mode },
            { label: 'Inner protocols (cleartext)', value: ah.inner_protocols.join(', ') },
            { label: 'ICV length → integrity', value: `${ah.icv_len} B → ${ah.integrity}` },
            { label: 'Packets', value: ah.packet_count },
          ]} />
        </Card>
      )}
    </div>
  );
}

function GroundTruthTab({ data }: { data: AnalysisRecord }) {
  const gt = data.ground_truth!;
  return (
    <Card title={`Scenario: ${gt.scenario}`} subtitle={gt.description}
      actions={<StatusPill status={gt.correct === gt.decided ? 'good' : 'warning'} label={`${gt.correct}/${gt.decided} correct`} />}>
      <TableWrap>
        <table className="data-table">
          <thead><tr><th>Field</th><th>Testbed configuration</th><th>AI result</th><th>Status</th></tr></thead>
          <tbody>{gt.rows.map((r) => (
            <tr key={r.field}>
              <td className="text-primary">{r.field}</td><td>{displayValue(r.expected)}</td>
              <td>{r.predicted === null ? <span className="muted">not observable</span> : displayValue(r.predicted)}</td>
              <td><StatusPill status={r.status === 'correct' ? 'good' : r.status === 'wrong' ? 'critical' : 'none'}
                label={r.observable ? r.status : 'not observable in capture'} /></td>
            </tr>))}</tbody>
        </table>
      </TableWrap>
    </Card>
  );
}

function PacketsTab({ id, start }: { id: string; start: number }) {
  const [page, setPage] = useState(0);
  const [data, setData] = useState<Loose>(null);
  const size = 100;
  useEffect(() => { api.getPackets(id, size, page * size).then(setData).catch(() => setData(null)); }, [id, page]);
  if (!data) return <Loading />;
  const pages = Math.ceil(data.stored / size);
  return (
    <Card title="Packets" subtitle={`${data.total.toLocaleString()} parsed · first ${data.stored.toLocaleString()} stored for inspection`}
      actions={<div className="pager">
        <button className="btn btn-sm btn-secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
        <span className="muted text-sm">{page + 1} / {Math.max(pages, 1)}</span>
        <button className="btn btn-sm btn-secondary" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
      </div>}>
      <TableWrap>
        <table className="data-table">
          <thead><tr><th className="num">Frame</th><th className="num">Time</th><th>Type</th><th>Source → destination</th><th>Detail</th><th className="num">Length</th></tr></thead>
          <tbody>{data.packets.map((p: Loose) => (
            <tr key={p.index}>
              <td className="num">{p.index}</td><td className="num">{(p.timestamp - start).toFixed(3)}</td>
              <td>{p.protocol_type}</td><td>{p.src_ip} → {p.dst_ip}</td>
              <td>{p.ike ? `${p.ike.exchange_type} ${p.ike.response_flag ? 'resp' : ''} [${p.ike.payload_types.join(', ')}]`
                : p.spi ? `SPI ${p.spi} seq ${p.seq_num}${p.esp_payload_len ? ` · ${p.esp_payload_len} B` : ''}` : ''}</td>
              <td className="num">{p.length}</td>
            </tr>))}</tbody>
        </table>
      </TableWrap>
    </Card>
  );
}
