import { Fragment, useEffect, useMemo, useState } from 'react';
import { BarList, ShareBar, TrafficTimeline } from '../components/charts';
import { Checklist } from '../components/ipsec';
import { Page } from '../components/Layout';
import { Card, ErrorBanner, KeyValue, Loading, Meter, NoAnalysis, StatTile, StatusPill, TableWrap } from '../components/ui';
import { useAnalysis, useIntel } from '../hooks/useAnalysis';
import { TRAFFIC_CLASSES, TRAFFIC_LABELS, classColor, pct, titleCase } from '../lib/format';
import { api } from '../services/api';
import type { Intel, Loose, Prediction } from '../types';

export default function Classification() {
  const { id, data, loading, error } = useAnalysis();
  const { intel } = useIntel(id);
  const [model, setModel] = useState<Loose>(null);
  const [open, setOpen] = useState<number | null>(null);
  useEffect(() => { api.getModelInfo().then(setModel).catch(() => {}); }, []);

  const distributions = useMemo(() => {
    const byFlow = new Map<string, Prediction[]>();
    for (const w of data?.classification ?? []) byFlow.set(w.flow_id, [...(byFlow.get(w.flow_id) ?? []), w]);
    return [...byFlow.entries()].map(([flow, ws]) => {
      const mean: Record<string, number> = {};
      for (const c of TRAFFIC_CLASSES) mean[c] = ws.reduce((s, w) => s + (w.all_probabilities?.[c] ?? 0), 0) / ws.length;
      const sorted = Object.fromEntries(Object.entries(mean).sort((a, b) => b[1] - a[1]));
      return { flow, windows: ws.length, mix: sorted };
    });
  }, [data]);

  const title = 'Traffic & metadata';
  if (!id) return <Page title={title}><NoAnalysis /></Page>;
  if (loading || (!data && !error)) return <Page title={title}><Loading /></Page>;
  if (error || !data) return <Page title={title}><ErrorBanner message={error ?? 'Not found'} /></Page>;

  const traffic = data.traffic;
  const windows = data.classification;
  const t0 = windows[0]?.window_start ?? 0;

  return (
    <Page title={title} subtitle="What runs inside the encrypted tunnel, from sizes and timing alone, and everything else an eavesdropper still learns">
      {traffic.note && <div className="alert alert-warning">{traffic.note}</div>}
      <div className="kpi-row">
        <StatTile label="Windows classified" value={traffic.windows} sub="10-second windows per tunnel" />
        <StatTile label="Classification confidence" value={pct(traffic.mean_confidence)} sub="Packet-weighted, calibrated" />
        <StatTile label="Uncertain windows" value={traffic.uncertain_windows ?? 0} sub="Below 50%: often at application switches" />
        <StatTile label="Novel windows" value={traffic.novel_windows ?? 0} status={traffic.novel_windows ? 'warning' : undefined}
          sub="Unlike anything in the training data" />
        <StatTile label="Tunnels (SA pairs)" value={traffic.flows.length} sub="Each rekey starts a new pair" />
      </div>

      {intel && <MetadataLeakage meta={intel.metadata} />}

      {traffic.windows > 0 && (
        <>
          <div className="grid-2 mt-md">
            <Card title="Traffic mix" subtitle="Share of classified time (10-second windows)">
              <ShareBar mix={traffic.mix} />
            </Card>
            <Card title="Per-tunnel probability" subtitle="Mean calibrated probability per class, across each tunnel's windows">
              <div className="dist-list">
                {distributions.map((d) => (
                  <div key={d.flow} className="dist">
                    <div className="dist-head"><span className="mono text-xs">{d.flow.slice(0, 23)}</span><span className="muted text-xs">{d.windows} windows</span></div>
                    <div className="share-bar thin" role="img" aria-label={Object.entries(d.mix).map(([c, v]) => `${TRAFFIC_LABELS[c]} ${pct(v)}`).join(', ')}>
                      {Object.entries(d.mix).filter(([, v]) => v >= 0.01).map(([c, v]) => (
                        <span key={c} className="share-seg" style={{ flexGrow: v, background: classColor(c) }} title={`${TRAFFIC_LABELS[c]} ${pct(v, 1)}`} />
                      ))}
                    </div>
                    <div className="dist-values">
                      {Object.entries(d.mix).slice(0, 4).map(([c, v]) => (
                        <span key={c}><span className="swatch" style={{ background: classColor(c) }} />{TRAFFIC_LABELS[c]} <b>{pct(v)}</b></span>
                      ))}
                      <span className="muted">other {pct(Object.values(d.mix).slice(4).reduce((s, v) => s + v, 0))}</span>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          <Card title="Traffic over time" subtitle="Each tunnel's windows, coloured by predicted application" className="mt-md">
            <TrafficTimeline flows={traffic.flows} />
          </Card>

          <Card title="Window predictions" subtitle="Select a row for the evidence behind it: what supports the label, and what makes it uncertain" className="mt-md">
            <TableWrap>
              <table className="data-table">
                <thead><tr><th /><th className="num">Start</th><th>Tunnel</th><th>Prediction</th><th className="conf-col">Confidence</th>
                  <th>Runner-up</th><th className="num">Packets</th><th>Novelty</th></tr></thead>
                <tbody>
                  {windows.map((w, i) => (
                    <Fragment key={i}>
                      <tr className="clickable" onClick={() => setOpen(open === i ? null : i)} aria-expanded={open === i}>
                        <td className="expander">{open === i ? '▾' : '▸'}</td>
                        <td className="num">{Math.round(w.window_start - t0)} s</td>
                        <td className="mono text-xs">{w.flow_id.slice(0, 21)}</td>
                        <td className="text-primary"><span className="swatch" style={{ background: classColor(w.predicted_class) }} />
                          {w.predicted_label}{w.uncertain && <span className="muted"> (uncertain)</span>}</td>
                        <td className="conf-col"><div className="meter-row"><Meter value={w.confidence} /><span className="num">{pct(w.confidence)}</span></div></td>
                        <td>{w.top_predictions[1] ? `${TRAFFIC_LABELS[w.top_predictions[1].class]} ${pct(w.top_predictions[1].confidence)}` : '—'}</td>
                        <td className="num">{w.packet_count}</td>
                        <td>{w.novel ? <StatusPill status="warning" label="novel" /> : <span className="muted text-xs">known</span>}</td>
                      </tr>
                      {open === i && (
                        <tr className="detail-row"><td /><td colSpan={7}>
                          <div className="grid-2">
                            <div className="check-panel">
                              <span className="tile-label">Prediction: {w.predicted_label} · {pct(w.confidence)}</span>
                              <Checklist checks={(w.reasoning?.supports ?? []).map((t) => ({ ok: true, text: t }))}
                                caveats={w.reasoning?.caveats ?? []} />
                            </div>
                            <div>
                              <span className="tile-label">Most influential features vs the typical {w.predicted_label} window</span>
                              <table className="mini-table"><tbody>{w.explanation.map((e) => (
                                <tr key={e.feature}><td>{titleCase(e.feature)}</td><td className="num">{e.value.toFixed(3)}</td>
                                  <td className="num muted">typical {e.class_median?.toFixed(3) ?? '—'}</td></tr>))}</tbody></table>
                              {w.novelty_score !== undefined && <p className="hint">Novelty distance {w.novelty_score.toFixed(2)}× the threshold (&gt; 1 = novel)</p>}
                            </div>
                          </div>
                        </td></tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </Card>
        </>
      )}

      {model?.is_trained && (
        <div className="grid-2 mt-md">
          <Card title="Classifier" subtitle={`${model.model_type} · ${model.n_features} features · trained ${model.trained_at ?? ''}`}>
            <KeyValue items={[
              { label: 'Accuracy (held-out flows)', value: pct(model.metrics.accuracy, 1) },
              { label: 'Macro F1', value: pct(model.metrics.f1_macro, 1) },
              { label: 'ROC-AUC (macro, one-vs-rest)', value: model.metrics.roc_auc_ovr?.toFixed(3) ?? '—' },
              { label: 'Group CV', value: `${pct(model.metrics.cv_mean_accuracy, 1)} ± ${pct(model.metrics.cv_std_accuracy, 1)}` },
              { label: 'Calibration error (ECE)', value: `${pct(model.metrics.calibration?.ece_after, 1)} (was ${pct(model.metrics.calibration?.ece_before, 1)})` },
              { label: 'Temporal smoothing', value: model.smoothing },
              { label: 'Novelty detector', value: model.novelty_detector ?? '—' },
            ]} />
            <h4 className="subhead">Robustness on held-out windows</h4>
            <BarList items={[
              ...Object.entries(model.metrics.accuracy_by_impairment ?? {}).map(([k, v]) => ({ key: `imp-${k}`, label: `Impairment: ${k}`, value: v as number })),
              ...(model.metrics.stress_accuracy ? [{ key: 'stress', label: 'Unseen heavy-impairment set', value: model.metrics.stress_accuracy as number }] : []),
              ...Object.entries(model.metrics.accuracy_by_suite_family ?? {}).map(([k, v]) => ({ key: `s-${k}`, label: k, value: v as number })),
            ]} format={(v) => pct(v, 1)} />
          </Card>
          <Card title="Feature importance" subtitle="Permutation importance on held-out flows, top 12">
            <BarList items={model.feature_importance.slice(0, 12).map((f: Loose) => ({ key: f.feature, label: titleCase(f.feature), value: f.importance }))}
              max={model.feature_importance[0]?.importance || 1} format={(v) => pct(v, 1)} />
          </Card>
        </div>
      )}
    </Page>
  );
}

function MetadataLeakage({ meta }: { meta: Intel['metadata'] }) {
  return (
    <Card title="Metadata leakage" className="accent" subtitle={meta.method}>
      <div className="leak">
        <div className="leak-gauges">
          <div className="leak-gauge">
            <span className="tile-label">Confidentiality</span>
            <div className="leak-num">{meta.confidentiality === null ? '—' : Math.round(meta.confidentiality)}<span className="hero-unit">%</span></div>
            <Meter value={meta.confidentiality === null ? null : meta.confidentiality / 100} status="none" label="Confidentiality" />
            <span className="muted text-xs">Can an observer read the payload? (cipher strength)</span>
          </div>
          <div className="leak-gauge">
            <span className="tile-label">Metadata privacy</span>
            <div className="leak-num">{meta.metadata_privacy === null ? '—' : Math.round(meta.metadata_privacy)}<span className="hero-unit">%</span></div>
            <Meter value={meta.metadata_privacy === null ? null : meta.metadata_privacy / 100} status="none" label="Metadata privacy" />
            <span className="muted text-xs">What can an observer still learn? (10 dimensions)</span>
          </div>
        </div>
        <div className="leak-body">
          <ul className="observer">
            {meta.statements.map((s) => <li key={s}>{s}</li>)}
          </ul>
          <div className="grid-2 leak-split">
            <div><span className="tile-label">Observer sees</span>
              <div className="chips">{meta.observer_sees.map((c) => <span key={c} className="chip chip-clear">{c}</span>)}</div></div>
            <div><span className="tile-label">Not exposed</span>
              <div className="chips">{meta.observer_cannot_see.map((c) => <span key={c} className="chip chip-enc">{c}</span>)}</div></div>
          </div>
        </div>
      </div>
      <TableWrap>
        <table className="data-table mt-md">
          <thead><tr><th>Dimension</th><th className="conf-col">Exposure</th><th className="num">Weight</th><th>Why</th></tr></thead>
          <tbody>{meta.dimensions.map((d) => (
            <tr key={d.key}>
              <td className="text-primary">{d.label}</td>
              <td className="conf-col">{d.exposed === null ? <span className="muted">unknown</span> : (
                <div className="meter-row"><Meter value={d.exposed} label={`${d.label} exposure`} />
                  <span className="num">{pct(d.exposed)}</span></div>)}</td>
              <td className="num">{d.weight}</td>
              <td className="evidence-cell">{d.detail}</td>
            </tr>))}</tbody>
        </table>
      </TableWrap>
    </Card>
  );
}
