import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Page } from '../components/Layout';
import { Card, ErrorBanner } from '../components/ui';
import { rememberAnalysis } from '../hooks/useAnalysis';
import { TRAFFIC_LABELS, bytes } from '../lib/format';
import { api } from '../services/api';
import type { Loose } from '../types';

export default function Upload() {
  const navigate = useNavigate();
  const input = useRef<HTMLInputElement>(null);
  const [lists, setLists] = useState<{ uploads: Loose[]; samples: Loose[]; lab?: Loose[] }>({ uploads: [], samples: [] });
  const [busy, setBusy] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [capture, setCapture] = useState<Loose>(null);
  const [duration, setDuration] = useState(30);
  const [iface, setIface] = useState('');

  const refresh = () => api.listUploads().then(setLists).catch((e) => setError(e.message));
  useEffect(() => {
    refresh();
    api.captureInterfaces().then(setCapture).catch(() => {});
  }, []);

  const analyze = async (fileId: string) => {
    setBusy(fileId);
    setError(null);
    try {
      const res = await api.analyze(fileId);
      rememberAnalysis(res.analysis_id);
      navigate(`/analysis?id=${res.analysis_id}`);
    } catch (e) {
      setError(`Analysis failed: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  const upload = async (file: File) => {
    setBusy('upload');
    setError(null);
    try {
      const res = await api.uploadFile(file);
      await refresh();
      await analyze(res.file_id);
    } catch (e) {
      setError((e as Error).message);
      setBusy(null);
    }
  };

  const startCapture = async () => {
    setBusy('capture');
    setError(null);
    try {
      const res = await api.startCapture({ duration, filter: capture?.default_filter, interface: iface || undefined });
      await analyze(res.file_id);
    } catch (e) {
      setError((e as Error).message);
      setBusy(null);
    }
  };

  return (
    <Page title="Captures & samples" subtitle="Upload a capture, analyse a testbed scenario, or capture live">
      {error && <ErrorBanner message={error} />}

      <div className="grid-upload">
        <div className={`upload-zone ${dragOver ? 'drag-over' : ''}`} role="button" tabIndex={0}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) upload(f); }}
          onClick={() => input.current?.click()}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') input.current?.click(); }}>
          <input ref={input} type="file" accept=".pcap,.pcapng,.cap" hidden
            onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); e.target.value = ''; }} />
          <div className="upload-icon" aria-hidden>{busy === 'upload' ? '⏳' : '⇪'}</div>
          <h3>{busy === 'upload' ? 'Uploading and analysing…' : 'Drop a PCAP / PCAPNG here'}</h3>
          <p>or click to browse · up to 100 MB · Wireshark, tcpdump, dumpcap captures</p>
          <p className="hint">Capture from before the tunnel comes up to see the IKE negotiation, and across a rekey to assess PFS.</p>
        </div>

        <Card title="Live capture" subtitle="Bounded sniff of IKE / ESP / AH, then analysed">
          {capture?.available ? (
            <div className="form-grid">
              <label>Interface
                <select value={iface} onChange={(e) => setIface(e.target.value)}>
                  <option value="">Default</option>
                  {capture.interfaces.map((i: string) => <option key={i} value={i}>{i}</option>)}
                </select>
              </label>
              <label>Duration (s)
                <input type="number" min={1} max={120} value={duration} onChange={(e) => setDuration(Number(e.target.value))} />
              </label>
              <div className="muted text-xs mono">{capture.default_filter}</div>
              <button className="btn btn-primary" disabled={busy !== null} onClick={startCapture}>
                {busy === 'capture' ? `Capturing ${duration} s…` : 'Start capture'}</button>
            </div>
          ) : (
            <p className="muted">{capture?.note ?? 'Checking capture support…'}</p>
          )}
        </Card>
      </div>

      <Card title="Testbed scenarios" subtitle="Generated from the configuration matrix — each has ground truth to check the AI against"
        className="mt-md">
        <div className="sample-grid">
          {lists.samples.map((s) => (
            <article className="sample-card" key={s.id}>
              <h4>{s.id.replace(/_/g, ' ')}</h4>
              <p>{s.description}</p>
              <div className="chips">
                <span className="chip">{s.highlights.ike}</span>
                <span className="chip">{s.highlights.esp}</span>
                <span className="chip">{s.highlights.mode}</span>
                <span className="chip">{s.highlights.ip}</span>
                {s.highlights.traffic.map((t: string) => <span className="chip chip-muted" key={t}>{TRAFFIC_LABELS[t] ?? t}</span>)}
              </div>
              <div className="sample-foot">
                <span className="muted text-xs">{s.packets?.toLocaleString()} packets</span>
                <button className="btn btn-sm btn-primary" disabled={busy !== null} onClick={() => analyze(s.id)}>
                  {busy === s.id ? 'Analysing…' : 'Analyse'}</button>
              </div>
            </article>
          ))}
          {lists.samples.length === 0 && <p className="muted">Samples are being generated on the backend…</p>}
        </div>
      </Card>

      {(lists.lab?.length ?? 0) > 0 && (
        <Card title="VPN lab builds" className="mt-md" subtitle="Captures generated by the digital twin, with ground truth"
          actions={<Link className="btn btn-sm btn-secondary" to="/lab">New lab build</Link>}>
          <ul className="file-list">
            {lists.lab!.slice(0, 10).map((b) => (
              <li key={b.id}>
                <span className="mono">{b.label}</span>
                <span className="muted text-xs">{b.config?.ike_version} · {b.config?.ike_encryption} · DH {b.config?.dh_group}</span>
                <button className="btn btn-sm btn-secondary" disabled={busy !== null} onClick={() => analyze(b.id)}>
                  {busy === b.id ? 'Analysing…' : 'Analyse'}</button>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card title="Your uploads" className="mt-md">
        {lists.uploads.length === 0 ? <p className="muted">No uploads yet.</p> : (
          <ul className="file-list">
            {lists.uploads.map((f) => (
              <li key={f.id}>
                <span className="mono">{f.original_name}</span>
                <span className="muted text-xs">{bytes(f.size)}</span>
                <button className="btn btn-sm btn-secondary" disabled={busy !== null} onClick={() => analyze(f.id)}>
                  {busy === f.id ? 'Analysing…' : 'Analyse'}</button>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </Page>
  );
}
