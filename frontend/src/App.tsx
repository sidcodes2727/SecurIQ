import { BrowserRouter, Routes, Route, NavLink, useNavigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import './index.css';
import { api } from './services/api';

// ========== Layout Components ==========

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">🛡️</div>
        <h1>VPN Analyzer</h1>
      </div>
      <nav className="sidebar-nav">
        <div className="nav-section">
          <div className="nav-section-title">Overview</div>
          <NavLink to="/" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} end>
            <span className="nav-icon">📊</span><span>Dashboard</span>
          </NavLink>
        </div>
        <div className="nav-section">
          <div className="nav-section-title">Capture</div>
          <NavLink to="/upload" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="nav-icon">📁</span><span>Upload PCAP</span>
          </NavLink>
        </div>
        <div className="nav-section">
          <div className="nav-section-title">Analysis</div>
          <NavLink to="/analysis" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="nav-icon">🔍</span><span>VPN Analysis</span>
          </NavLink>
          <NavLink to="/classification" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="nav-icon">🤖</span><span>Traffic Classification</span>
          </NavLink>
          <NavLink to="/security" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="nav-icon">🔒</span><span>Security Assessment</span>
          </NavLink>
        </div>
        <div className="nav-section">
          <div className="nav-section-title">Reports</div>
          <NavLink to="/reports" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="nav-icon">📋</span><span>Reports</span>
          </NavLink>
          <NavLink to="/dataset" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <span className="nav-icon">🗃️</span><span>Dataset & Model</span>
          </NavLink>
        </div>
      </nav>
    </aside>
  );
}

function Header({ title }: { title: string }) {
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    api.health().then(setHealth).catch(() => {});
  }, []);

  return (
    <header className="header">
      <div className="header-left">
        <h2 className="header-title">{title}</h2>
      </div>
      <div className="header-right">
        <div className="status-badge">
          <div className={`status-dot ${health ? 'online' : ''}`}></div>
          <span>{health ? 'Backend Online' : 'Connecting...'}</span>
        </div>
        <div className="status-badge">
          <span>🤖 Model: {health?.model_trained ? '✅ Trained' : '⏳ Not Ready'}</span>
        </div>
      </div>
    </header>
  );
}

// ========== Page Components ==========

function DashboardPage() {
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const navigate = useNavigate();

  useEffect(() => {
    api.health().then(setHealth).catch(() => {});
    api.listAnalyses().then(d => setAnalyses(d.analyses || [])).catch(() => {});
  }, []);

  return (
    <div className="page-container">
      <Header title="Dashboard" />
      <div className="stats-grid">
        <div className="stat-card" onClick={() => navigate('/upload')} style={{ cursor: 'pointer' }}>
          <div className="stat-icon">📁</div>
          <div className="stat-value">{health?.sample_files || 0}</div>
          <div className="stat-label">Sample Files Available</div>
          <div className="stat-glow" style={{ background: 'var(--accent-cyan)' }}></div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🔍</div>
          <div className="stat-value">{analyses.length}</div>
          <div className="stat-label">Analyses Completed</div>
          <div className="stat-glow" style={{ background: 'var(--accent-green)' }}></div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">⚠️</div>
          <div className="stat-value">
            {analyses.length > 0
              ? analyses.reduce((sum, a) => sum + (a.findings_count || 0), 0)
              : '—'}
          </div>
          <div className="stat-label">Total Findings</div>
          <div className="stat-glow" style={{ background: 'var(--accent-orange)' }}></div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🤖</div>
          <div className="stat-value">{health?.model_trained ? 'Ready' : 'N/A'}</div>
          <div className="stat-label">ML Model Status</div>
          <div className="stat-glow" style={{ background: 'var(--accent-purple)' }}></div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">🚀 Quick Start</div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)' }}>
            <button className="btn btn-primary" onClick={() => navigate('/upload')}>
              📁 Upload PCAP for Analysis
            </button>
            <button className="btn btn-secondary" onClick={() => navigate('/dataset')}>
              🗃️ View Dataset & Model Info
            </button>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">📋 Recent Analyses</div>
          </div>
          {analyses.length === 0 ? (
            <div className="empty-state">
              <p>No analyses yet. Upload a PCAP to get started.</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr><th>ID</th><th>Score</th><th>Risk</th><th>Action</th></tr>
              </thead>
              <tbody>
                {analyses.slice(0, 5).map(a => (
                  <tr key={a.analysis_id}>
                    <td>{a.analysis_id}</td>
                    <td>{a.security_score}/100</td>
                    <td><span className={`badge badge-${a.risk_level?.includes('Critical') ? 'critical' : a.risk_level?.includes('High') ? 'high' : a.risk_level?.includes('Moderate') ? 'medium' : 'success'}`}>{a.risk_level}</span></td>
                    <td><button className="btn btn-sm btn-secondary" onClick={() => navigate(`/analysis?id=${a.analysis_id}`)}>View</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="card mt-md">
        <div className="card-header">
          <div className="card-title">ℹ️ About This System</div>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: '1.8' }}>
          The <strong>AI-Powered IPsec VPN Protocol Analyzer</strong> is a comprehensive security assessment framework that
          analyzes IPsec VPN traffic from PCAP files. It uses protocol parsing for observable VPN parameters,
          machine learning for encrypted traffic classification, and transparent rule-based scoring for security assessment.
          The system identifies IKE version, encryption algorithms, DH groups, PFS status, NAT-T, and more—marking
          unobservable fields honestly instead of guessing.
        </p>
      </div>
    </div>
  );
}

function UploadPage() {
  const [uploads, setUploads] = useState<any>({ uploads: [], samples: [] });
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [result, setResult] = useState<any>(null);
  const navigate = useNavigate();

  useEffect(() => {
    api.listUploads().then(setUploads).catch(() => {});
  }, []);

  const handleUpload = async (file: File) => {
    setUploading(true);
    try {
      const res = await api.uploadFile(file);
      setResult(res);
      api.listUploads().then(setUploads);
    } catch (e: any) {
      alert(e.message);
    }
    setUploading(false);
  };

  const handleAnalyze = async (fileId: string) => {
    setAnalyzing(fileId);
    try {
      const res = await api.analyze(fileId);
      navigate(`/analysis?id=${res.analysis_id}`);
    } catch (e: any) {
      alert('Analysis failed: ' + e.message);
    }
    setAnalyzing(null);
  };

  return (
    <div className="page-container">
      <Header title="Upload PCAP" />

      <div
        className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => {
          e.preventDefault();
          setDragOver(false);
          const file = e.dataTransfer.files[0];
          if (file) handleUpload(file);
        }}
        onClick={() => {
          const input = document.createElement('input');
          input.type = 'file';
          input.accept = '.pcap,.pcapng,.cap';
          input.onchange = (e: any) => {
            const file = e.target.files[0];
            if (file) handleUpload(file);
          };
          input.click();
        }}
      >
        <div className="upload-icon">{uploading ? '⏳' : '📤'}</div>
        <h3>{uploading ? 'Uploading...' : 'Drop PCAP/PCAPNG file here'}</h3>
        <p>or click to browse • Max 100MB • .pcap, .pcapng, .cap</p>
      </div>

      {result && (
        <div className="card mt-md">
          <div className="card-title" style={{ color: 'var(--accent-green)' }}>
            ✅ {result.filename} uploaded successfully ({(result.size / 1024).toFixed(1)} KB)
          </div>
          <button className="btn btn-primary mt-md" onClick={() => handleAnalyze(result.file_id)}>
            🔍 Analyze Now
          </button>
        </div>
      )}

      <div className="grid-2 mt-md">
        <div className="card">
          <div className="card-header">
            <div className="card-title">📁 Your Uploads</div>
          </div>
          {uploads.uploads?.length === 0 ? (
            <div className="empty-state"><p>No files uploaded yet.</p></div>
          ) : (
            uploads.uploads?.map((f: any) => (
              <div key={f.id} className="prop-item">
                <span className="prop-label">{f.original_name}</span>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={() => handleAnalyze(f.id)}
                  disabled={analyzing === f.id}
                >
                  {analyzing === f.id ? '⏳ Analyzing...' : '🔍 Analyze'}
                </button>
              </div>
            ))
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">🧪 Sample Files</div>
            <div className="card-subtitle">Pre-generated test scenarios</div>
          </div>
          {uploads.samples?.length === 0 ? (
            <div className="empty-state"><p>No samples yet. They'll be generated on backend startup.</p></div>
          ) : (
            uploads.samples?.map((f: any) => (
              <div key={f.id} className="prop-item">
                <span className="prop-label">{f.original_name}</span>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={() => handleAnalyze(f.id)}
                  disabled={analyzing === f.id}
                >
                  {analyzing === f.id ? '⏳ Analyzing...' : '🔍 Analyze'}
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function AnalysisPage() {
  const [analysisId, setAnalysisId] = useState('');
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id') || localStorage.getItem('lastAnalysisId');
    if (id) {
      setAnalysisId(id);
      localStorage.setItem('lastAnalysisId', id);
      loadAnalysis(id);
    }
  }, []);

  const loadAnalysis = async (id: string) => {
    setLoading(true);
    try {
      const res = await api.getAnalysis(id);
      setData(res);
    } catch (e: any) {
      alert(e.message);
    }
    setLoading(false);
  };

  if (loading) return <div className="page-container"><Header title="VPN Analysis" /><div className="loading-spinner"><div className="spinner"></div><p>Analyzing packets...</p></div></div>;

  if (!data) return (
    <div className="page-container">
      <Header title="VPN Analysis" />
      <div className="card">
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <h3>No Analysis Selected</h3>
          <p>Upload and analyze a PCAP file first, or select a previous analysis.</p>
        </div>
      </div>
    </div>
  );

  const profile = data.ipsec_analysis?.vpn_profile || {};
  const ike = data.ipsec_analysis?.ike_analysis || {};
  const esp = data.ipsec_analysis?.esp_analysis || {};
  const nat = data.ipsec_analysis?.nat_t_analysis || {};
  const ipInfo = data.ipsec_analysis?.ip_analysis || {};

  return (
    <div className="page-container">
      <Header title="VPN Analysis" />
      <div className="tabs">
        {['overview', 'ike', 'esp', 'packets'].map(tab => (
          <button key={tab} className={`tab ${activeTab === tab ? 'active' : ''}`} onClick={() => setActiveTab(tab)}>
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div className="grid-2">
          <div className="card">
            <div className="card-header"><div className="card-title">🛡️ VPN Profile</div></div>
            <ul className="prop-list">
              <li className="prop-item"><span className="prop-label">IPsec Protocol</span><span className={`prop-value ${profile.ipsec_protocol?.includes('Not') ? 'unknown' : ''}`}>{profile.ipsec_protocol?.join(', ')}</span></li>
              <li className="prop-item"><span className="prop-label">IKE Version</span><span className={`prop-value ${profile.ike_version === 'Not Observable' ? 'unknown' : ''}`}>{profile.ike_version}</span></li>
              <li className="prop-item"><span className="prop-label">Mode</span><span className={`prop-value ${profile.mode === 'Not Observable' ? 'unknown' : ''}`}>{profile.mode}</span></li>
              <li className="prop-item"><span className="prop-label">Encryption</span><span className={`prop-value ${profile.encryption === 'Not Observable' ? 'unknown' : ''}`}>{profile.encryption}</span></li>
              <li className="prop-item"><span className="prop-label">Integrity</span><span className={`prop-value ${profile.integrity === 'Not Observable' ? 'unknown' : ''}`}>{profile.integrity}</span></li>
              <li className="prop-item"><span className="prop-label">DH Group</span><span className={`prop-value ${profile.dh_group === 'Not Observable' ? 'unknown' : ''}`}>{profile.dh_group}</span></li>
              <li className="prop-item"><span className="prop-label">PFS</span><span className={`prop-value ${profile.pfs === 'Not Observable' ? 'unknown' : ''}`}>{String(profile.pfs)}</span></li>
              <li className="prop-item"><span className="prop-label">NAT-T</span><span className="prop-value">{profile.nat_t ? '✅ Detected' : '❌ Not Detected'}</span></li>
              <li className="prop-item"><span className="prop-label">IP Version</span><span className="prop-value">{profile.ip_version}</span></li>
              <li className="prop-item"><span className="prop-label">Total SAs</span><span className="prop-value">{profile.total_sas}</span></li>
            </ul>
          </div>

          <div className="card">
            <div className="card-header"><div className="card-title">📊 Capture Statistics</div></div>
            <ul className="prop-list">
              <li className="prop-item"><span className="prop-label">Total Packets</span><span className="prop-value">{data.parsed_metadata?.total_packets}</span></li>
              <li className="prop-item"><span className="prop-label">Parsed Packets</span><span className="prop-value">{data.parsed_metadata?.parsed_packets}</span></li>
              <li className="prop-item"><span className="prop-label">IKE Packets</span><span className="prop-value">{data.parsed_summary?.ike || 0}</span></li>
              <li className="prop-item"><span className="prop-label">ESP Packets</span><span className="prop-value">{data.parsed_summary?.esp || 0}</span></li>
              <li className="prop-item"><span className="prop-label">AH Packets</span><span className="prop-value">{data.parsed_summary?.ah || 0}</span></li>
              <li className="prop-item"><span className="prop-label">NAT-T IKE</span><span className="prop-value">{data.parsed_summary?.ike_natt || 0}</span></li>
              <li className="prop-item"><span className="prop-label">IPv4</span><span className="prop-value">{data.parsed_summary?.ipv4 || 0}</span></li>
              <li className="prop-item"><span className="prop-label">IPv6</span><span className="prop-value">{data.parsed_summary?.ipv6 || 0}</span></li>
              <li className="prop-item"><span className="prop-label">Parse Time</span><span className="prop-value">{data.parsed_metadata?.parse_duration_ms}ms</span></li>
              <li className="prop-item"><span className="prop-label">File Size</span><span className="prop-value">{(data.parsed_metadata?.file_size / 1024).toFixed(1)} KB</span></li>
            </ul>
          </div>
        </div>
      )}

      {activeTab === 'ike' && (
        <div>
          <div className="card mb-md">
            <div className="card-header"><div className="card-title">🔑 IKE Negotiation</div></div>
            {!ike.detected ? (
              <p className="text-muted">No IKE packets found in this capture. Algorithm details cannot be determined from ESP traffic alone.</p>
            ) : (
              <>
                <ul className="prop-list">
                  <li className="prop-item"><span className="prop-label">Version</span><span className="prop-value">{ike.version}</span></li>
                  <li className="prop-item"><span className="prop-label">Packet Count</span><span className="prop-value">{ike.packet_count}</span></li>
                  <li className="prop-item"><span className="prop-label">Exchange Types</span><span className="prop-value">{ike.exchange_types?.join(', ')}</span></li>
                  <li className="prop-item"><span className="prop-label">Mode</span><span className="prop-value">{ike.mode}</span></li>
                </ul>
                {ike.chosen_algorithms && (
                  <div className="mt-md">
                    <h4 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: 'var(--space-sm)' }}>Negotiated Algorithms</h4>
                    <ul className="prop-list">
                      {Object.entries(ike.chosen_algorithms).map(([k, v]) => (
                        <li className="prop-item" key={k}>
                          <span className="prop-label">{k.replace(/_/g, ' ')}</span>
                          <span className={`prop-value ${v === 'Not Observable' ? 'unknown' : ''}`}>{String(v)}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>
          {ike.pfs_detected && (
            <div className="card">
              <div className="card-title">🔐 Perfect Forward Secrecy</div>
              <ul className="prop-list mt-md">
                <li className="prop-item"><span className="prop-label">Detected</span><span className="prop-value">{String(ike.pfs_detected.detected)}</span></li>
                <li className="prop-item"><span className="prop-label">Reason</span><span className="prop-value" style={{ fontSize: '12px', maxWidth: '400px', textAlign: 'right' }}>{ike.pfs_detected.reason}</span></li>
              </ul>
            </div>
          )}
        </div>
      )}

      {activeTab === 'esp' && (
        <div>
          <div className="card">
            <div className="card-header"><div className="card-title">🔒 ESP Security Associations</div></div>
            {!esp.detected ? (
              <p className="text-muted">No ESP traffic detected.</p>
            ) : (
              <table className="data-table">
                <thead>
                  <tr><th>SPI</th><th>Packets</th><th>Duration</th><th>Avg Size</th><th>Seq Range</th><th>Gaps</th></tr>
                </thead>
                <tbody>
                  {esp.sa_info?.map((sa: any, i: number) => (
                    <tr key={i}>
                      <td>{sa.spi}</td>
                      <td>{sa.packet_count}</td>
                      <td>{sa.duration?.toFixed(2)}s</td>
                      <td>{sa.avg_payload_size} B</td>
                      <td>{sa.min_seq} - {sa.max_seq}</td>
                      <td>{sa.seq_gaps?.length || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          {nat.detected && (
            <div className="card mt-md">
              <div className="card-title">🔄 NAT Traversal</div>
              <ul className="prop-list mt-md">
                <li className="prop-item"><span className="prop-label">NAT-T Detected</span><span className="prop-value text-green">Yes</span></li>
                <li className="prop-item"><span className="prop-label">Encapsulation</span><span className="prop-value">{nat.encapsulation}</span></li>
                <li className="prop-item"><span className="prop-label">NAT-T IKE Packets</span><span className="prop-value">{nat.nat_t_ike_packets}</span></li>
                <li className="prop-item"><span className="prop-label">NAT-T ESP Packets</span><span className="prop-value">{nat.nat_t_esp_packets}</span></li>
              </ul>
            </div>
          )}
        </div>
      )}

      {activeTab === 'packets' && (
        <div className="card">
          <div className="card-title">📦 Packet Details</div>
          <p className="text-muted text-sm mb-md">Timeline events from the capture</p>
          {data.ipsec_analysis?.timeline?.slice(0, 30).map((evt: any, i: number) => (
            <div key={i} className="finding-card">
              <div className="finding-header">
                <span className={`badge ${evt.type === 'IKE' ? 'badge-low' : 'badge-info'}`}>{evt.type}</span>
                <span className="finding-title">{evt.description}</span>
              </div>
              <div className="finding-evidence">
                {evt.src} → {evt.dst}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ClassificationPage() {
  const [analysisId, setAnalysisId] = useState('');
  const [data, setData] = useState<any>(null);
  const [modelInfo, setModelInfo] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id') || localStorage.getItem('lastAnalysisId');
    if (id) { 
      setAnalysisId(id); 
      localStorage.setItem('lastAnalysisId', id);
      loadClassification(id); 
    }
    api.getModelInfo().then(setModelInfo).catch(() => {});
  }, []);

  const loadClassification = async (id: string) => {
    setLoading(true);
    try {
      const res = await api.classifyTraffic(id);
      setData(res);
    } catch (e: any) { alert(e.message); }
    setLoading(false);
  };

  const trafficColors: Record<string, string> = {
    icmp: 'var(--accent-cyan)',
    web: 'var(--accent-green)',
    voip: 'var(--accent-purple)',
    video: 'var(--accent-orange)',
    email: 'var(--accent-yellow)',
    chat: '#ff69b4',
    file_transfer: 'var(--accent-red)',
  };

  return (
    <div className="page-container">
      <Header title="Traffic Classification" />

      {!data?.classification?.length ? (
        <div className="card">
          <div className="empty-state">
            <div className="empty-icon">🤖</div>
            <h3>No Classification Results</h3>
            <p>Analyze a PCAP file first, then view classification results here.</p>
            {analysisId && <button className="btn btn-primary mt-md" onClick={() => loadClassification(analysisId)}>Run Classification</button>}
          </div>
        </div>
      ) : (
        <>
          <div className="stats-grid">
            {data.classification.map((c: any, i: number) => (
              <div className="stat-card" key={i}>
                <div className="stat-icon" style={{ fontSize: '20px' }}>
                  {c.predicted_class === 'web' ? '🌐' : c.predicted_class === 'voip' ? '📞' :
                   c.predicted_class === 'video' ? '🎬' : c.predicted_class === 'email' ? '📧' :
                   c.predicted_class === 'chat' ? '💬' : c.predicted_class === 'icmp' ? '📡' : '📁'}
                </div>
                <div className="stat-value" style={{ color: trafficColors[c.predicted_class] || 'var(--text-primary)', fontSize: '18px' }}>
                  {c.predicted_class.replace('_', ' ').toUpperCase()}
                </div>
                <div className="stat-label">SPI: {c.spi}</div>
                <div style={{ marginTop: 'var(--space-sm)' }}>
                  <div className="score-bar-container">
                    <div className="score-bar">
                      <div className="score-fill" style={{
                        width: `${c.confidence * 100}%`,
                        background: trafficColors[c.predicted_class] || 'var(--accent-cyan)',
                      }}></div>
                    </div>
                    <span className="score-value">{(c.confidence * 100).toFixed(1)}%</span>
                  </div>
                </div>
                <div className="stat-glow" style={{ background: trafficColors[c.predicted_class] || 'var(--accent-cyan)' }}></div>
              </div>
            ))}
          </div>

          <div className="card mt-md">
            <div className="card-title">📊 Detailed Predictions</div>
            <table className="data-table mt-md">
              <thead>
                <tr><th>SPI</th><th>Prediction</th><th>Confidence</th><th>2nd Choice</th><th>3rd Choice</th></tr>
              </thead>
              <tbody>
                {data.classification.map((c: any, i: number) => (
                  <tr key={i}>
                    <td>{c.spi}</td>
                    <td style={{ color: trafficColors[c.predicted_class] }}>{c.predicted_class}</td>
                    <td>{(c.confidence * 100).toFixed(1)}%</td>
                    <td>{c.top_predictions?.[1]?.class} ({(c.top_predictions?.[1]?.confidence * 100).toFixed(1)}%)</td>
                    <td>{c.top_predictions?.[2]?.class} ({(c.top_predictions?.[2]?.confidence * 100).toFixed(1)}%)</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {modelInfo && (
        <div className="card mt-md">
          <div className="card-header">
            <div className="card-title">🧠 Model Information</div>
          </div>
          <div className="grid-2">
            <ul className="prop-list">
              <li className="prop-item"><span className="prop-label">Model Type</span><span className="prop-value">{modelInfo.model_type}</span></li>
              <li className="prop-item"><span className="prop-label">Trained</span><span className="prop-value">{modelInfo.is_trained ? '✅ Yes' : '❌ No'}</span></li>
              <li className="prop-item"><span className="prop-label">Features</span><span className="prop-value">{modelInfo.n_features}</span></li>
              <li className="prop-item"><span className="prop-label">Estimators</span><span className="prop-value">{modelInfo.n_estimators}</span></li>
              {modelInfo.metrics?.accuracy && (
                <>
                  <li className="prop-item"><span className="prop-label">Accuracy</span><span className="prop-value text-green">{(modelInfo.metrics.accuracy * 100).toFixed(1)}%</span></li>
                  <li className="prop-item"><span className="prop-label">F1 Score</span><span className="prop-value text-green">{(modelInfo.metrics.f1_score * 100).toFixed(1)}%</span></li>
                  <li className="prop-item"><span className="prop-label">CV Accuracy</span><span className="prop-value">{(modelInfo.metrics.cv_mean_accuracy * 100).toFixed(1)}% ± {(modelInfo.metrics.cv_std_accuracy * 100).toFixed(1)}%</span></li>
                </>
              )}
            </ul>
            <div>
              <h4 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: 'var(--space-sm)' }}>Top Feature Importances</h4>
              {modelInfo.feature_importance?.slice(0, 10).map((f: any, i: number) => (
                <div key={i} style={{ marginBottom: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '2px' }}>
                    <span className="text-mono">{f.feature}</span>
                    <span className="text-accent">{(f.importance * 100).toFixed(1)}%</span>
                  </div>
                  <div className="score-bar">
                    <div className="score-fill" style={{
                      width: `${f.importance * 100 / (modelInfo.feature_importance[0]?.importance || 1)}%`,
                      background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-green))',
                    }}></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SecurityPage() {
  const [data, setData] = useState<any>(null);
  const [threatMatrix, setThreatMatrix] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id') || localStorage.getItem('lastAnalysisId');
    if (id) {
      localStorage.setItem('lastAnalysisId', id);
      loadSecurity(id);
    }
  }, []);

  const loadSecurity = async (id: string) => {
    setLoading(true);
    try {
      const [sec, tm] = await Promise.all([
        api.getSecurity(id),
        api.getThreatMatrix(id),
      ]);
      setData(sec);
      setThreatMatrix(tm);
    } catch (e: any) { alert(e.message); }
    setLoading(false);
  };

  if (!data) return (
    <div className="page-container">
      <Header title="Security Assessment" />
      <div className="card"><div className="empty-state"><div className="empty-icon">🔒</div><h3>No Assessment Available</h3><p>Analyze a PCAP file first.</p></div></div>
    </div>
  );

  const scoreColor = (score: number) =>
    score >= 85 ? 'var(--score-excellent)' : score >= 70 ? 'var(--score-good)' :
    score >= 50 ? 'var(--score-moderate)' : score >= 30 ? 'var(--score-poor)' : 'var(--score-critical)';

  const severityBadge = (sev: string) => {
    const map: Record<string, string> = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Informational: 'info' };
    return map[sev] || 'info';
  };

  return (
    <div className="page-container">
      <Header title="Security Assessment" />
      <div className="tabs">
        {['overview', 'findings', 'threats', 'recommendations'].map(tab => (
          <button key={tab} className={`tab ${activeTab === tab ? 'active' : ''}`} onClick={() => setActiveTab(tab)}>
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <>
          <div className="grid-3" style={{ marginBottom: 'var(--space-lg)' }}>
            <div className="card" style={{ textAlign: 'center' }}>
              <div className="risk-gauge">
                <div style={{ fontSize: '64px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: scoreColor(data.overall_score), lineHeight: 1 }}>
                  {data.overall_score}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '4px' }}>out of 100</div>
                <div className="gauge-label" style={{ color: scoreColor(data.overall_score), marginTop: 'var(--space-sm)' }}>
                  {data.risk_level}
                </div>
              </div>
            </div>
            <div className="card" style={{ gridColumn: 'span 2' }}>
              <div className="card-title mb-md">Category Scores</div>
              {Object.entries(data.categories || {}).map(([key, cat]: [string, any]) => (
                <div key={key} style={{ marginBottom: 'var(--space-md)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                    <span>{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
                    <span style={{ color: scoreColor(cat.score), fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                      {cat.score}/100 — {cat.rating}
                    </span>
                  </div>
                  <div className="score-bar">
                    <div className="score-fill" style={{ width: `${cat.score}%`, background: scoreColor(cat.score) }}></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-title">📊 Scoring Breakdown</div>
            <table className="data-table mt-md">
              <thead><tr><th>Category</th><th>Weight</th><th>Score</th><th>Weighted</th><th>Rationale</th></tr></thead>
              <tbody>
                {Object.entries(data.categories || {}).map(([key, cat]: [string, any]) => (
                  <tr key={key}>
                    <td style={{ fontFamily: 'var(--font-primary)' }}>{key.replace(/_/g, ' ')}</td>
                    <td>{((data.scoring_weights?.[key] || 0) * 100).toFixed(0)}%</td>
                    <td style={{ color: scoreColor(cat.score) }}>{cat.score}</td>
                    <td>{(cat.score * (data.scoring_weights?.[key] || 0)).toFixed(1)}</td>
                    <td style={{ fontSize: '11px', maxWidth: '400px', fontFamily: 'var(--font-primary)' }}>{cat.rationale}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {activeTab === 'findings' && (
        <div>
          <div className="mb-md" style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            {data.findings?.length || 0} findings discovered
          </div>
          {data.findings?.map((f: any, i: number) => (
            <div className="finding-card" key={i}>
              <div className="finding-header">
                <span className={`badge badge-${severityBadge(f.severity)}`}>{f.severity}</span>
                <span className="finding-id">{f.id}</span>
                <span className="finding-title">{f.title}</span>
              </div>
              <div className="finding-description">{f.description}</div>
              <div className="finding-evidence">Evidence: {f.evidence}</div>
              <div className="finding-recommendation">💡 {f.recommendation}</div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'threats' && threatMatrix && (
        <div>
          <div className="card mb-md">
            <div className="card-title">🎯 Threat Matrix Summary</div>
            <ul className="prop-list mt-md">
              <li className="prop-item"><span className="prop-label">Threats Identified</span><span className="prop-value">{threatMatrix.threat_count}</span></li>
              <li className="prop-item"><span className="prop-label">Max Risk Score</span><span className="prop-value" style={{ color: scoreColor(100 - threatMatrix.max_risk_score) }}>{threatMatrix.max_risk_score}</span></li>
              <li className="prop-item"><span className="prop-label">Average Risk</span><span className="prop-value">{threatMatrix.average_risk_score}</span></li>
            </ul>
          </div>
          <table className="data-table">
            <thead><tr><th>Threat</th><th>MITRE</th><th>Likelihood</th><th>Impact</th><th>Risk Score</th><th>Level</th></tr></thead>
            <tbody>
              {threatMatrix.threats?.map((t: any, i: number) => (
                <tr key={i}>
                  <td style={{ fontFamily: 'var(--font-primary)' }}>{t.name}</td>
                  <td>{t.mitre_tactic}</td>
                  <td>{(t.likelihood * 100).toFixed(0)}%</td>
                  <td>{(t.impact * 100).toFixed(0)}%</td>
                  <td style={{ color: scoreColor(100 - t.risk_score) }}>{t.risk_score}</td>
                  <td><span className={`badge badge-${t.risk_level === 'Critical' ? 'critical' : t.risk_level === 'High' ? 'high' : t.risk_level === 'Medium' ? 'medium' : 'low'}`}>{t.risk_level}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'recommendations' && (
        <div>
          {data.recommendations?.length === 0 ? (
            <div className="card"><div className="empty-state"><div className="empty-icon">✅</div><h3>No Critical Recommendations</h3><p>The VPN configuration meets security standards.</p></div></div>
          ) : (
            data.recommendations?.map((r: any, i: number) => (
              <div className="finding-card" key={i}>
                <div className="finding-header">
                  <span className={`badge ${r.priority === 'High' ? 'badge-high' : 'badge-medium'}`}>{r.priority} Priority</span>
                  <span className="finding-id">{r.finding_id}</span>
                  <span className="finding-title">{r.category}</span>
                </div>
                <div className="finding-description">{r.action}</div>
                <div className="text-sm text-muted">{r.impact}</div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

function ReportsPage() {
  const [executive, setExecutive] = useState<any>(null);
  const [technical, setTechnical] = useState<any>(null);
  const [activeTab, setActiveTab] = useState('executive');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id') || localStorage.getItem('lastAnalysisId');
    if (id) {
      localStorage.setItem('lastAnalysisId', id);
      api.getExecutiveReport(id).then(setExecutive).catch(() => {});
      api.getTechnicalReport(id).then(setTechnical).catch(() => {});
    }
  }, []);

  if (!executive) return (
    <div className="page-container">
      <Header title="Reports" />
      <div className="card"><div className="empty-state"><div className="empty-icon">📋</div><h3>No Reports Available</h3><p>Complete an analysis first, then add ?id=ANALYSIS_ID to the URL.</p></div></div>
    </div>
  );

  const scoreColor = (s: number) => s >= 85 ? 'var(--score-excellent)' : s >= 70 ? 'var(--score-good)' : s >= 50 ? 'var(--score-moderate)' : 'var(--score-critical)';

  return (
    <div className="page-container">
      <Header title="Reports" />
      <div className="tabs">
        <button className={`tab ${activeTab === 'executive' ? 'active' : ''}`} onClick={() => setActiveTab('executive')}>Executive Summary</button>
        <button className={`tab ${activeTab === 'technical' ? 'active' : ''}`} onClick={() => setActiveTab('technical')}>Technical Report</button>
      </div>

      {activeTab === 'executive' && executive && (
        <div>
          <div className="grid-3 mb-lg">
            <div className="stat-card" style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '48px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: scoreColor(executive.overall_security_score) }}>
                {executive.overall_security_score}
              </div>
              <div className="stat-label">Security Score</div>
              <div style={{ color: scoreColor(executive.overall_security_score), fontWeight: 600, fontSize: '14px', marginTop: '4px' }}>{executive.risk_level}</div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">⚠️</div>
              <div className="stat-value">{executive.key_findings?.total_findings}</div>
              <div className="stat-label">Total Findings</div>
              <div style={{ marginTop: 'var(--space-sm)', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                {executive.key_findings?.critical > 0 && <span className="badge badge-critical">{executive.key_findings.critical} Critical</span>}
                {executive.key_findings?.high > 0 && <span className="badge badge-high">{executive.key_findings.high} High</span>}
                {executive.key_findings?.medium > 0 && <span className="badge badge-medium">{executive.key_findings.medium} Medium</span>}
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">🤖</div>
              <div className="stat-value">{executive.ai_confidence ? `${(executive.ai_confidence * 100).toFixed(1)}%` : 'N/A'}</div>
              <div className="stat-label">AI Confidence</div>
            </div>
          </div>

          <div className="grid-2">
            <div className="card">
              <div className="card-title">🛡️ VPN Summary</div>
              <ul className="prop-list mt-md">
                {Object.entries(executive.vpn_summary || {}).map(([k, v]) => (
                  <li className="prop-item" key={k}>
                    <span className="prop-label">{k.replace(/_/g, ' ')}</span>
                    <span className="prop-value">{String(v)}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="card">
              <div className="card-title">📊 Category Scores</div>
              <ul className="prop-list mt-md">
                {Object.entries(executive.category_scores || {}).map(([k, v]: [string, any]) => (
                  <li className="prop-item" key={k}>
                    <span className="prop-label">{k.replace(/_/g, ' ')}</span>
                    <span className="prop-value" style={{ color: scoreColor(v.score) }}>{v.score} — {v.rating}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {executive.top_recommendations?.length > 0 && (
            <div className="card mt-md">
              <div className="card-title">💡 Top Recommendations</div>
              {executive.top_recommendations.map((r: any, i: number) => (
                <div className="finding-card" key={i}>
                  <div className="finding-header">
                    <span className={`badge ${r.priority === 'High' ? 'badge-high' : 'badge-medium'}`}>{r.priority}</span>
                    <span className="finding-title">{r.category}</span>
                  </div>
                  <div className="finding-description">{r.action}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'technical' && technical && (
        <div className="card">
          <div className="card-title">📋 Full Technical Report</div>
          <p className="text-muted text-sm mb-md">Generated: {technical.generated_at}</p>
          <pre style={{
            background: 'var(--bg-secondary)',
            padding: 'var(--space-lg)',
            borderRadius: 'var(--radius-md)',
            overflow: 'auto',
            maxHeight: '600px',
            fontSize: '12px',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-secondary)',
            lineHeight: 1.6,
          }}>
            {JSON.stringify(technical, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function DatasetPage() {
  const [datasetInfo, setDatasetInfo] = useState<any>(null);
  const [modelInfo, setModelInfo] = useState<any>(null);
  const [generating, setGenerating] = useState(false);
  const [training, setTraining] = useState(false);

  useEffect(() => {
    api.getDatasetInfo().then(setDatasetInfo).catch(() => {});
    api.getModelInfo().then(setModelInfo).catch(() => {});
  }, []);

  const generateDataset = async () => {
    setGenerating(true);
    try {
      await api.generateDataset();
      const info = await api.getDatasetInfo();
      setDatasetInfo(info);
    } catch (e: any) { alert(e.message); }
    setGenerating(false);
  };

  const trainModel = async () => {
    setTraining(true);
    try {
      await api.trainModel();
      const info = await api.getModelInfo();
      setModelInfo(info);
    } catch (e: any) { alert(e.message); }
    setTraining(false);
  };

  return (
    <div className="page-container">
      <Header title="Dataset & Model" />
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">🗃️ Synthetic Dataset</div>
          </div>
          {datasetInfo?.exists ? (
            <ul className="prop-list">
              <li className="prop-item"><span className="prop-label">Total Samples</span><span className="prop-value">{datasetInfo.total_samples}</span></li>
              <li className="prop-item"><span className="prop-label">Classes</span><span className="prop-value">{datasetInfo.classes?.length}</span></li>
              <li className="prop-item"><span className="prop-label">Per Class</span><span className="prop-value">{datasetInfo.samples_per_class}</span></li>
              <li className="prop-item"><span className="prop-label">Seed</span><span className="prop-value">{datasetInfo.seed}</span></li>
            </ul>
          ) : (
            <p className="text-muted">No dataset generated yet.</p>
          )}
          <button className="btn btn-primary mt-md" onClick={generateDataset} disabled={generating}>
            {generating ? '⏳ Generating...' : '🔄 Regenerate Dataset'}
          </button>

          {datasetInfo?.profiles && (
            <div className="mt-md">
              <h4 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: 'var(--space-sm)' }}>Traffic Profiles</h4>
              {Object.entries(datasetInfo.profiles).map(([k, v]) => (
                <div key={k} className="prop-item">
                  <span className="prop-label text-mono">{k}</span>
                  <span className="prop-value" style={{ fontSize: '11px', maxWidth: '250px', textAlign: 'right', fontFamily: 'var(--font-primary)' }}>{String(v)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">🧠 ML Model</div>
          </div>
          {modelInfo?.is_trained ? (
            <>
              <ul className="prop-list">
                <li className="prop-item"><span className="prop-label">Type</span><span className="prop-value">{modelInfo.model_type}</span></li>
                <li className="prop-item"><span className="prop-label">Status</span><span className="prop-value text-green">✅ Trained</span></li>
                <li className="prop-item"><span className="prop-label">Features</span><span className="prop-value">{modelInfo.n_features}</span></li>
                {modelInfo.metrics?.accuracy && (
                  <>
                    <li className="prop-item"><span className="prop-label">Accuracy</span><span className="prop-value text-green">{(modelInfo.metrics.accuracy * 100).toFixed(2)}%</span></li>
                    <li className="prop-item"><span className="prop-label">F1 Score</span><span className="prop-value text-green">{(modelInfo.metrics.f1_score * 100).toFixed(2)}%</span></li>
                    <li className="prop-item"><span className="prop-label">CV Accuracy</span><span className="prop-value">{(modelInfo.metrics.cv_mean_accuracy * 100).toFixed(2)}%</span></li>
                    <li className="prop-item"><span className="prop-label">Train Samples</span><span className="prop-value">{modelInfo.metrics.training_samples}</span></li>
                    <li className="prop-item"><span className="prop-label">Test Samples</span><span className="prop-value">{modelInfo.metrics.test_samples}</span></li>
                  </>
                )}
              </ul>

              {modelInfo.metrics?.confusion_matrix && (
                <div className="mt-md">
                  <h4 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: 'var(--space-sm)' }}>Confusion Matrix</h4>
                  <div style={{ overflow: 'auto' }}>
                    <table className="data-table" style={{ fontSize: '11px' }}>
                      <thead>
                        <tr>
                          <th></th>
                          {modelInfo.classes?.map((c: string) => <th key={c}>{c.slice(0, 5)}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {modelInfo.metrics.confusion_matrix.map((row: number[], i: number) => (
                          <tr key={i}>
                            <td style={{ fontFamily: 'var(--font-primary)', fontWeight: 600 }}>{modelInfo.classes[i]}</td>
                            {row.map((val: number, j: number) => (
                              <td key={j} style={{
                                background: i === j ? 'rgba(0, 255, 136, 0.1)' : val > 0 ? 'rgba(255, 59, 92, 0.1)' : 'transparent',
                                fontWeight: i === j ? 700 : 400,
                                color: i === j ? 'var(--accent-green)' : val > 0 ? 'var(--accent-red)' : 'var(--text-tertiary)',
                              }}>{val}</td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          ) : (
            <p className="text-muted">Model not trained yet.</p>
          )}
          <button className="btn btn-primary mt-md" onClick={trainModel} disabled={training}>
            {training ? '⏳ Training...' : '🔄 Retrain Model'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ========== Main App ==========

function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/analysis" element={<AnalysisPage />} />
            <Route path="/classification" element={<ClassificationPage />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/dataset" element={<DatasetPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
