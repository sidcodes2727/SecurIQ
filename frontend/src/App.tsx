import { BrowserRouter, Routes, Route, NavLink, useNavigate } from 'react-router-dom';
import { useState, useEffect, useRef } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { useGSAP } from '@gsap/react';
import './index.css';
import { api } from './services/api';

gsap.registerPlugin(ScrollTrigger);

// ========== Utility: Animated Counter ==========

function AnimatedCounter({ value, duration = 1.2, suffix = '' }: { value: number | string; duration?: number; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const numVal = typeof value === 'string' ? parseFloat(value) || 0 : value;

  useEffect(() => {
    if (!ref.current || isNaN(numVal)) {
      if (ref.current) ref.current.textContent = String(value);
      return;
    }
    const counter = { val: 0 };
    gsap.to(counter, {
      val: numVal,
      duration,
      ease: 'power2.out',
      onUpdate: () => {
        if (ref.current) ref.current.textContent = Math.round(counter.val) + suffix;
      },
    });
  }, [numVal, duration, suffix, value]);

  return <span ref={ref} className="counter-value">0</span>;
}

// ========== Particle Canvas ==========

function ParticleBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId: number;
    const particles: { x: number; y: number; vx: number; vy: number; r: number; a: number; p: number }[] = [];
    const COUNT = 40;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };

    const init = () => {
      resize();
      for (let i = 0; i < COUNT; i++) {
        particles.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          vx: (Math.random() - 0.5) * 0.15,
          vy: (Math.random() - 0.5) * 0.15,
          r: Math.random() * 1.2 + 0.3,
          a: Math.random() * 0.15 + 0.03,
          p: Math.random() * Math.PI * 2,
        });
      }
    };

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;
        p.p += 0.008;
        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;

        const alpha = p.a * (0.7 + Math.sin(p.p) * 0.3);
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(34, 211, 238, ${alpha})`;
        ctx.fill();

        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = dx * dx + dy * dy;
          if (dist < 15000) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(34, 211, 238, ${0.02 * (1 - dist / 15000)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }
      animId = requestAnimationFrame(draw);
    };

    init();
    draw();
    window.addEventListener('resize', resize);
    return () => { cancelAnimationFrame(animId); window.removeEventListener('resize', resize); };
  }, []);

  return <canvas ref={canvasRef} className="particle-canvas" />;
}

// ========== Ticker ==========

function LiveTicker() {
  const items = [
    'AES-256-GCM', 'IKEv2', 'ESP TUNNEL', 'SHA-384',
    'DH GROUP 20', 'PFS ENABLED', 'NAT-T', 'X.509 CERT',
    'HMAC-SHA256', 'ECP-384', 'ANTI-REPLAY', 'RSA-4096',
  ];
  return (
    <div className="ticker">
      <div className="ticker-inner">
        {[...items, ...items].map((item, i) => (
          <span className="ticker-item" key={i}>
            <span className="ticker-dot" />
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}

// ========== GSAP Page Wrapper ==========

function AnimatedPage({ children }: { children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);

  useGSAP(() => {
    if (!ref.current) return;

    gsap.fromTo(ref.current,
      { opacity: 0, y: 16 },
      { opacity: 1, y: 0, duration: 0.45, ease: 'power2.out' }
    );

    // Stagger cards
    const cards = ref.current.querySelectorAll('.card, .stat-card, .finding-card');
    if (cards.length) {
      gsap.fromTo(cards,
        { opacity: 0, y: 20 },
        { opacity: 1, y: 0, duration: 0.4, ease: 'power2.out', stagger: 0.05, delay: 0.1 }
      );
    }

    // Animate score fills
    const fills = ref.current.querySelectorAll('.score-fill');
    fills.forEach(fill => {
      gsap.fromTo(fill,
        { scaleX: 0 },
        { scaleX: 1, duration: 0.8, ease: 'power2.out', delay: 0.4, transformOrigin: 'left center' }
      );
    });

  }, { scope: ref });

  return <div ref={ref} className="page-container">{children}</div>;
}

// ========== Sidebar ==========

function Sidebar() {
  const sidebarRef = useRef<HTMLElement>(null);

  useGSAP(() => {
    if (!sidebarRef.current) return;
    const items = sidebarRef.current.querySelectorAll('.nav-item');
    gsap.fromTo(items,
      { opacity: 0, x: -12 },
      { opacity: 1, x: 0, duration: 0.3, ease: 'power2.out', stagger: 0.03, delay: 0.2 }
    );
  }, { scope: sidebarRef });

  return (
    <aside className="sidebar" ref={sidebarRef}>
      <div className="sidebar-logo">
        <div className="logo-icon">🛡️</div>
        <h1>Secur<span>IQ</span></h1>
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
      <div className="sidebar-footer">
        <div className="sidebar-pulse">
          <span className="pulse-dot" />
          <span>System Active</span>
        </div>
      </div>
    </aside>
  );
}

// ========== Header ==========

function Header({ title }: { title: string }) {
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    api.health().then(setHealth).catch(() => {});
  }, []);

  return (
    <header className="header">
      <div className="header-left">
        <h2 className="header-title glitch-text" data-text={title}>{title}</h2>
      </div>
      <div className="header-right">
        <div className="status-badge">
          <div className={`status-dot ${health ? 'online' : ''}`} />
          <span>{health ? 'Online' : 'Connecting...'}</span>
        </div>
        <div className="status-badge">
          <span>Model: {health?.model_trained ? '✅' : '⏳'}</span>
        </div>
      </div>
    </header>
  );
}

// ========== Dashboard ==========

function DashboardPage() {
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const navigate = useNavigate();

  useEffect(() => {
    api.health().then(setHealth).catch(() => {});
    api.listAnalyses().then(d => setAnalyses(d.analyses || [])).catch(() => {});
  }, []);

  return (
    <AnimatedPage>
      <Header title="Dashboard" />

      {/* Hero */}
      <div className="hero-section">
        <h1 className="hero-title">
          IPsec VPN <span className="accent">Analyzer</span>
        </h1>
        <p className="hero-subtitle">
          AI-powered protocol analysis, encrypted traffic classification, and transparent security scoring.
        </p>
      </div>

      <LiveTicker />

      {/* Stats */}
      <div className="stats-grid">
        <div className="stat-card" onClick={() => navigate('/upload')} style={{ cursor: 'pointer' }}>
          <div className="stat-icon">📁</div>
          <div className="stat-value"><AnimatedCounter value={health?.sample_files || 0} /></div>
          <div className="stat-label">Sample Files</div>
          <div className="stat-glow" style={{ background: 'var(--accent)' }} />
        </div>
        <div className="stat-card">
          <div className="stat-icon">🔍</div>
          <div className="stat-value"><AnimatedCounter value={analyses.length} /></div>
          <div className="stat-label">Analyses Done</div>
          <div className="stat-glow" style={{ background: 'var(--accent2)' }} />
        </div>
        <div className="stat-card">
          <div className="stat-icon">⚠️</div>
          <div className="stat-value">
            {analyses.length > 0
              ? <AnimatedCounter value={analyses.reduce((sum, a) => sum + (a.findings_count || 0), 0)} />
              : '—'}
          </div>
          <div className="stat-label">Total Findings</div>
          <div className="stat-glow" style={{ background: 'var(--sev-medium)' }} />
        </div>
        <div className="stat-card">
          <div className="stat-icon">🤖</div>
          <div className="stat-value" style={{ color: health?.model_trained ? 'var(--accent2)' : 'var(--text-tertiary)' }}>
            {health?.model_trained ? 'Ready' : 'N/A'}
          </div>
          <div className="stat-label">ML Model</div>
          <div className="stat-glow" style={{ background: 'var(--accent)' }} />
        </div>
      </div>

      {/* Quick Actions + Recent Analyses */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">⚡ Quick Actions</div>
          </div>
          <div className="quick-actions">
            <button className="quick-action-btn" onClick={() => navigate('/upload')}>
              <span className="action-icon">📤</span>
              <div>
                <div>Upload PCAP</div>
                <div className="action-label">Analyze a capture file</div>
              </div>
            </button>
            <button className="quick-action-btn" onClick={() => navigate('/dataset')}>
              <span className="action-icon">🗃️</span>
              <div>
                <div>Dataset & Model</div>
                <div className="action-label">View ML pipeline</div>
              </div>
            </button>
            <button className="quick-action-btn" onClick={() => navigate('/security')}>
              <span className="action-icon">🔒</span>
              <div>
                <div>Security Check</div>
                <div className="action-label">View assessments</div>
              </div>
            </button>
            <button className="quick-action-btn" onClick={() => navigate('/reports')}>
              <span className="action-icon">📋</span>
              <div>
                <div>Reports</div>
                <div className="action-label">Executive & technical</div>
              </div>
            </button>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">📋 Recent Analyses</div>
          </div>
          {analyses.length === 0 ? (
            <div className="empty-state" style={{ padding: 'var(--space-xl)' }}>
              <p>No analyses yet. Upload a PCAP to get started.</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr><th>ID</th><th>Score</th><th>Risk</th><th></th></tr>
              </thead>
              <tbody>
                {analyses.slice(0, 5).map(a => (
                  <tr key={a.analysis_id}>
                    <td>{a.analysis_id}</td>
                    <td>{a.security_score}/100</td>
                    <td>
                      <span className={`badge badge-${a.risk_level?.includes('Critical') ? 'critical' : a.risk_level?.includes('High') ? 'high' : a.risk_level?.includes('Moderate') ? 'medium' : 'success'}`}>
                        {a.risk_level}
                      </span>
                    </td>
                    <td><button className="btn btn-ghost btn-sm" onClick={() => navigate(`/analysis?id=${a.analysis_id}`)}>View →</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* About */}
      <div className="info-banner mt-md">
        <span className="banner-icon">ℹ️</span>
        <p>
          The <strong>AI-Powered IPsec VPN Protocol Analyzer</strong> analyzes IPsec VPN traffic from PCAP files using protocol parsing for observable VPN parameters,
          machine learning for encrypted traffic classification, and transparent rule-based scoring for security assessment.
          It identifies IKE version, encryption algorithms, DH groups, PFS status, NAT-T, and more.
        </p>
      </div>
    </AnimatedPage>
  );
}

// ========== Upload Page ==========

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
    } catch (e: any) { alert(e.message); }
    setUploading(false);
  };

  const handleAnalyze = async (fileId: string) => {
    setAnalyzing(fileId);
    try {
      const res = await api.analyze(fileId);
      navigate(`/analysis?id=${res.analysis_id}`);
    } catch (e: any) { alert('Analysis failed: ' + e.message); }
    setAnalyzing(null);
  };

  return (
    <AnimatedPage>
      <Header title="Upload PCAP" />

      <div
        className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => {
          e.preventDefault(); setDragOver(false);
          const file = e.dataTransfer.files[0];
          if (file) handleUpload(file);
        }}
        onClick={() => {
          const input = document.createElement('input');
          input.type = 'file';
          input.accept = '.pcap,.pcapng,.cap';
          input.onchange = (e: any) => { const file = e.target.files[0]; if (file) handleUpload(file); };
          input.click();
        }}
      >
        <div className="upload-icon">{uploading ? '⏳' : '📤'}</div>
        <h3>{uploading ? 'Uploading...' : 'Drop PCAP/PCAPNG file here'}</h3>
        <p>or click to browse • Max 100MB • .pcap, .pcapng, .cap</p>
      </div>

      {result && (
        <div className="card mt-md">
          <div className="card-title" style={{ color: 'var(--accent2)' }}>
            ✅ {result.filename} uploaded ({(result.size / 1024).toFixed(1)} KB)
          </div>
          <button className="btn btn-primary mt-sm" onClick={() => handleAnalyze(result.file_id)}>🔍 Analyze Now</button>
        </div>
      )}

      <div className="grid-2 mt-md">
        <div className="card">
          <div className="card-header"><div className="card-title">📁 Your Uploads</div></div>
          {uploads.uploads?.length === 0 ? (
            <div className="empty-state" style={{ padding: 'var(--space-lg)' }}><p>No files uploaded yet.</p></div>
          ) : (
            uploads.uploads?.map((f: any) => (
              <div key={f.id} className="prop-item">
                <span className="prop-label">{f.original_name}</span>
                <button className="btn btn-sm btn-primary" onClick={() => handleAnalyze(f.id)} disabled={analyzing === f.id}>
                  {analyzing === f.id ? '⏳...' : '🔍 Analyze'}
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
            <div className="empty-state" style={{ padding: 'var(--space-lg)' }}><p>No samples yet.</p></div>
          ) : (
            uploads.samples?.map((f: any) => (
              <div key={f.id} className="prop-item">
                <span className="prop-label">{f.original_name}</span>
                <button className="btn btn-sm btn-primary" onClick={() => handleAnalyze(f.id)} disabled={analyzing === f.id}>
                  {analyzing === f.id ? '⏳...' : '🔍 Analyze'}
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </AnimatedPage>
  );
}

// ========== Analysis Page ==========

function AnalysisPage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id') || localStorage.getItem('lastAnalysisId');
    if (id) {
      localStorage.setItem('lastAnalysisId', id);
      loadAnalysis(id);
    }
  }, []);

  const loadAnalysis = async (id: string) => {
    setLoading(true);
    try { setData(await api.getAnalysis(id)); } catch (e: any) { alert(e.message); }
    setLoading(false);
  };

  if (loading) return <AnimatedPage><Header title="VPN Analysis" /><div className="loading-spinner"><div className="spinner" /><p>Analyzing packets...</p></div></AnimatedPage>;

  if (!data) return (
    <AnimatedPage><Header title="VPN Analysis" />
      <div className="card"><div className="empty-state"><div className="empty-icon">🔍</div><h3>No Analysis Selected</h3><p>Upload and analyze a PCAP file first.</p></div></div>
    </AnimatedPage>
  );

  const profile = data.ipsec_analysis?.vpn_profile || {};
  const ike = data.ipsec_analysis?.ike_analysis || {};
  const esp = data.ipsec_analysis?.esp_analysis || {};
  const nat = data.ipsec_analysis?.nat_t_analysis || {};

  return (
    <AnimatedPage>
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
              {[
                ['IPsec Protocol', profile.ipsec_protocol?.join(', ')],
                ['IKE Version', profile.ike_version],
                ['Mode', profile.mode],
                ['Encryption', profile.encryption],
                ['Integrity', profile.integrity],
                ['DH Group', profile.dh_group],
                ['PFS', String(profile.pfs)],
                ['NAT-T', profile.nat_t ? '✅ Detected' : '❌ Not Detected'],
                ['IP Version', profile.ip_version],
                ['Total SAs', profile.total_sas],
              ].map(([label, val]) => (
                <li className="prop-item" key={label as string}>
                  <span className="prop-label">{label}</span>
                  <span className={`prop-value ${String(val) === 'Not Observable' ? 'unknown' : ''}`}>{val}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="card">
            <div className="card-header"><div className="card-title">📊 Capture Stats</div></div>
            <ul className="prop-list">
              {[
                ['Total Packets', data.parsed_metadata?.total_packets],
                ['Parsed Packets', data.parsed_metadata?.parsed_packets],
                ['IKE Packets', data.parsed_summary?.ike || 0],
                ['ESP Packets', data.parsed_summary?.esp || 0],
                ['AH Packets', data.parsed_summary?.ah || 0],
                ['NAT-T IKE', data.parsed_summary?.ike_natt || 0],
                ['IPv4', data.parsed_summary?.ipv4 || 0],
                ['IPv6', data.parsed_summary?.ipv6 || 0],
                ['Parse Time', `${data.parsed_metadata?.parse_duration_ms}ms`],
                ['File Size', `${(data.parsed_metadata?.file_size / 1024).toFixed(1)} KB`],
              ].map(([label, val]) => (
                <li className="prop-item" key={label as string}>
                  <span className="prop-label">{label}</span>
                  <span className="prop-value">{val}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {activeTab === 'ike' && (
        <div>
          <div className="card mb-md">
            <div className="card-header"><div className="card-title">🔑 IKE Negotiation</div></div>
            {!ike.detected ? (
              <p className="text-muted">No IKE packets found in this capture.</p>
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
                <thead><tr><th>SPI</th><th>Packets</th><th>Duration</th><th>Avg Size</th><th>Seq Range</th><th>Gaps</th></tr></thead>
                <tbody>
                  {esp.sa_info?.map((sa: any, i: number) => (
                    <tr key={i}><td>{sa.spi}</td><td>{sa.packet_count}</td><td>{sa.duration?.toFixed(2)}s</td><td>{sa.avg_payload_size} B</td><td>{sa.min_seq} - {sa.max_seq}</td><td>{sa.seq_gaps?.length || 0}</td></tr>
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
          <div className="card-title">📦 Packet Timeline</div>
          <p className="text-muted text-sm mb-md">Events from the capture</p>
          {data.ipsec_analysis?.timeline?.slice(0, 30).map((evt: any, i: number) => (
            <div key={i} className="finding-card">
              <div className="finding-header">
                <span className={`badge ${evt.type === 'IKE' ? 'badge-low' : 'badge-info'}`}>{evt.type}</span>
                <span className="finding-title">{evt.description}</span>
              </div>
              <div className="finding-evidence">{evt.src} → {evt.dst}</div>
            </div>
          ))}
        </div>
      )}
    </AnimatedPage>
  );
}

// ========== Classification Page ==========

function ClassificationPage() {
  const [analysisId, setAnalysisId] = useState('');
  const [data, setData] = useState<any>(null);
  const [modelInfo, setModelInfo] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id') || localStorage.getItem('lastAnalysisId');
    if (id) { setAnalysisId(id); localStorage.setItem('lastAnalysisId', id); loadClassification(id); }
    api.getModelInfo().then(setModelInfo).catch(() => {});
  }, []);

  const loadClassification = async (id: string) => {
    setLoading(true);
    try { setData(await api.classifyTraffic(id)); } catch (e: any) { alert(e.message); }
    setLoading(false);
  };

  const trafficColors: Record<string, string> = {
    icmp: 'var(--accent)', web: 'var(--accent2)', voip: 'var(--accent-dim)',
    video: 'var(--accent2-dim)', email: 'var(--gray-200)', chat: 'var(--accent-muted)',
    file_transfer: 'var(--gray-300)',
  };

  return (
    <AnimatedPage>
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
                  {c.predicted_class === 'web' ? '🌐' : c.predicted_class === 'voip' ? '📞' : c.predicted_class === 'video' ? '🎬' : c.predicted_class === 'email' ? '📧' : c.predicted_class === 'chat' ? '💬' : c.predicted_class === 'icmp' ? '📡' : '📁'}
                </div>
                <div className="stat-value" style={{ color: trafficColors[c.predicted_class] || 'var(--text-primary)', fontSize: '18px' }}>
                  {c.predicted_class.replace('_', ' ').toUpperCase()}
                </div>
                <div className="stat-label">SPI: {c.spi}</div>
                <div style={{ marginTop: 'var(--space-sm)' }}>
                  <div className="score-bar-container">
                    <div className="score-bar">
                      <div className="score-fill" style={{ width: `${c.confidence * 100}%`, background: trafficColors[c.predicted_class] || 'var(--accent)' }} />
                    </div>
                    <span className="score-value">{(c.confidence * 100).toFixed(1)}%</span>
                  </div>
                </div>
                <div className="stat-glow" style={{ background: trafficColors[c.predicted_class] || 'var(--accent)' }} />
              </div>
            ))}
          </div>

          <div className="card">
            <div className="card-title">📊 Detailed Predictions</div>
            <table className="data-table mt-md">
              <thead><tr><th>SPI</th><th>Prediction</th><th>Confidence</th><th>2nd Choice</th><th>3rd Choice</th></tr></thead>
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
          <div className="card-header"><div className="card-title">🧠 Model Info</div></div>
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
                </>
              )}
            </ul>
            <div>
              <h4 style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: 'var(--space-sm)' }}>Feature Importance</h4>
              {modelInfo.feature_importance?.slice(0, 8).map((f: any, i: number) => (
                <div key={i} style={{ marginBottom: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '2px' }}>
                    <span className="text-mono">{f.feature}</span>
                    <span className="text-accent">{(f.importance * 100).toFixed(1)}%</span>
                  </div>
                  <div className="score-bar">
                    <div className="score-fill" style={{ width: `${f.importance * 100 / (modelInfo.feature_importance[0]?.importance || 1)}%`, background: 'linear-gradient(90deg, var(--accent), var(--accent2))' }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </AnimatedPage>
  );
}

// ========== Security Page ==========

function SecurityPage() {
  const [data, setData] = useState<any>(null);
  const [threatMatrix, setThreatMatrix] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id') || localStorage.getItem('lastAnalysisId');
    if (id) { localStorage.setItem('lastAnalysisId', id); loadSecurity(id); }
  }, []);

  const loadSecurity = async (id: string) => {
    setLoading(true);
    try {
      const [sec, tm] = await Promise.all([api.getSecurity(id), api.getThreatMatrix(id)]);
      setData(sec); setThreatMatrix(tm);
    } catch (e: any) { alert(e.message); }
    setLoading(false);
  };

  if (!data) return (
    <AnimatedPage><Header title="Security Assessment" />
      <div className="card"><div className="empty-state"><div className="empty-icon">🔒</div><h3>No Assessment Available</h3><p>Analyze a PCAP file first.</p></div></div>
    </AnimatedPage>
  );

  const scoreColor = (s: number) => s >= 85 ? 'var(--score-excellent)' : s >= 70 ? 'var(--score-good)' : s >= 50 ? 'var(--score-moderate)' : s >= 30 ? 'var(--score-poor)' : 'var(--score-critical)';
  const sevBadge = (sev: string) => ({ Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Informational: 'info' }[sev] || 'info');

  return (
    <AnimatedPage>
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
          <div className="grid-3 mb-lg">
            <div className="card" style={{ textAlign: 'center' }}>
              <div className="risk-gauge">
                <div style={{ fontSize: '60px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: scoreColor(data.overall_score), lineHeight: 1, letterSpacing: '-2px' }}>
                  <AnimatedCounter value={data.overall_score} duration={1.5} />
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px', textTransform: 'uppercase', letterSpacing: '2px' }}>out of 100</div>
                <div className="gauge-label" style={{ color: scoreColor(data.overall_score), marginTop: 'var(--space-sm)' }}>{data.risk_level}</div>
              </div>
            </div>
            <div className="card" style={{ gridColumn: 'span 2' }}>
              <div className="card-title mb-md">Category Scores</div>
              {Object.entries(data.categories || {}).map(([key, cat]: [string, any]) => (
                <div key={key} style={{ marginBottom: 'var(--space-md)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                    <span>{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
                    <span style={{ color: scoreColor(cat.score), fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{cat.score}/100 — {cat.rating}</span>
                  </div>
                  <div className="score-bar">
                    <div className="score-fill" style={{ width: `${cat.score}%`, background: scoreColor(cat.score) }} />
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
          <div className="mb-md" style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{data.findings?.length || 0} findings discovered</div>
          {data.findings?.map((f: any, i: number) => (
            <div className="finding-card" key={i}>
              <div className="finding-header">
                <span className={`badge badge-${sevBadge(f.severity)}`}>{f.severity}</span>
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
            <thead><tr><th>Threat</th><th>MITRE</th><th>Likelihood</th><th>Impact</th><th>Risk</th><th>Level</th></tr></thead>
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
            <div className="card"><div className="empty-state"><div className="empty-icon">✅</div><h3>No Critical Recommendations</h3><p>VPN configuration meets standards.</p></div></div>
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
    </AnimatedPage>
  );
}

// ========== Reports Page ==========

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
    <AnimatedPage><Header title="Reports" />
      <div className="card"><div className="empty-state"><div className="empty-icon">📋</div><h3>No Reports Available</h3><p>Complete an analysis first.</p></div></div>
    </AnimatedPage>
  );

  const scoreColor = (s: number) => s >= 85 ? 'var(--score-excellent)' : s >= 70 ? 'var(--score-good)' : s >= 50 ? 'var(--score-moderate)' : 'var(--score-critical)';

  return (
    <AnimatedPage>
      <Header title="Reports" />
      <div className="tabs">
        <button className={`tab ${activeTab === 'executive' ? 'active' : ''}`} onClick={() => setActiveTab('executive')}>Executive Summary</button>
        <button className={`tab ${activeTab === 'technical' ? 'active' : ''}`} onClick={() => setActiveTab('technical')}>Technical Report</button>
      </div>

      {activeTab === 'executive' && executive && (
        <div>
          <div className="grid-3 mb-lg">
            <div className="stat-card" style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '48px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: scoreColor(executive.overall_security_score), letterSpacing: '-2px' }}>
                <AnimatedCounter value={executive.overall_security_score} duration={1.5} />
              </div>
              <div className="stat-label">Security Score</div>
              <div style={{ color: scoreColor(executive.overall_security_score), fontWeight: 600, fontSize: '13px', marginTop: '4px' }}>{executive.risk_level}</div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">⚠️</div>
              <div className="stat-value"><AnimatedCounter value={executive.key_findings?.total_findings || 0} /></div>
              <div className="stat-label">Total Findings</div>
              <div style={{ marginTop: 'var(--space-sm)', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                {executive.key_findings?.critical > 0 && <span className="badge badge-critical">{executive.key_findings.critical} Crit</span>}
                {executive.key_findings?.high > 0 && <span className="badge badge-high">{executive.key_findings.high} High</span>}
                {executive.key_findings?.medium > 0 && <span className="badge badge-medium">{executive.key_findings.medium} Med</span>}
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
                  <li className="prop-item" key={k}><span className="prop-label">{k.replace(/_/g, ' ')}</span><span className="prop-value">{String(v)}</span></li>
                ))}
              </ul>
            </div>
            <div className="card">
              <div className="card-title">📊 Category Scores</div>
              <ul className="prop-list mt-md">
                {Object.entries(executive.category_scores || {}).map(([k, v]: [string, any]) => (
                  <li className="prop-item" key={k}><span className="prop-label">{k.replace(/_/g, ' ')}</span><span className="prop-value" style={{ color: scoreColor(v.score) }}>{v.score} — {v.rating}</span></li>
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
          <div className="card-title">📋 Technical Report</div>
          <p className="text-muted text-sm mb-md">Generated: {technical.generated_at}</p>
          <pre style={{ background: 'var(--bg-secondary)', padding: 'var(--space-lg)', borderRadius: 'var(--radius-md)', overflow: 'auto', maxHeight: '600px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', lineHeight: 1.6, border: '1px solid var(--border)' }}>
            {JSON.stringify(technical, null, 2)}
          </pre>
        </div>
      )}
    </AnimatedPage>
  );
}

// ========== Dataset Page ==========

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
    try { await api.generateDataset(); setDatasetInfo(await api.getDatasetInfo()); } catch (e: any) { alert(e.message); }
    setGenerating(false);
  };

  const trainModel = async () => {
    setTraining(true);
    try { await api.trainModel(); setModelInfo(await api.getModelInfo()); } catch (e: any) { alert(e.message); }
    setTraining(false);
  };

  return (
    <AnimatedPage>
      <Header title="Dataset & Model" />
      <div className="grid-2">
        <div className="card">
          <div className="card-header"><div className="card-title">🗃️ Synthetic Dataset</div></div>
          {datasetInfo?.exists ? (
            <ul className="prop-list">
              <li className="prop-item"><span className="prop-label">Total Samples</span><span className="prop-value">{datasetInfo.total_samples}</span></li>
              <li className="prop-item"><span className="prop-label">Classes</span><span className="prop-value">{datasetInfo.classes?.length}</span></li>
              <li className="prop-item"><span className="prop-label">Per Class</span><span className="prop-value">{datasetInfo.samples_per_class}</span></li>
              <li className="prop-item"><span className="prop-label">Seed</span><span className="prop-value">{datasetInfo.seed}</span></li>
            </ul>
          ) : <p className="text-muted">No dataset generated yet.</p>}
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
          <div className="card-header"><div className="card-title">🧠 ML Model</div></div>
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
                        <tr><th></th>{modelInfo.classes?.map((c: string) => <th key={c}>{c.slice(0, 5)}</th>)}</tr>
                      </thead>
                      <tbody>
                        {modelInfo.metrics.confusion_matrix.map((row: number[], i: number) => (
                          <tr key={i}>
                            <td style={{ fontFamily: 'var(--font-primary)', fontWeight: 600 }}>{modelInfo.classes[i]}</td>
                            {row.map((val: number, j: number) => (
                              <td key={j} style={{
                                background: i === j ? 'rgba(52, 211, 153, 0.08)' : val > 0 ? 'rgba(239, 68, 68, 0.05)' : 'transparent',
                                fontWeight: i === j ? 700 : 400,
                                color: i === j ? 'var(--accent2)' : val > 0 ? 'var(--sev-critical)' : 'var(--text-muted)',
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
          ) : <p className="text-muted">Model not trained yet.</p>}
          <button className="btn btn-primary mt-md" onClick={trainModel} disabled={training}>
            {training ? '⏳ Training...' : '🔄 Retrain Model'}
          </button>
        </div>
      </div>
    </AnimatedPage>
  );
}

// ========== App ==========

function App() {
  return (
    <BrowserRouter>
      <div className="bg-grid" />
      <ParticleBackground />

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
