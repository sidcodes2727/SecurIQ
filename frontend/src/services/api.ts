import type { AnalysisRecord, AnalysisSummary, FleetGraph, FleetRow, Health, Intel, Loose, Security, ThreatMatrix, TriageItem } from '../types';

export const API_BASE: string = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000/api';

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${url}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    const detail = typeof error.detail === 'string' ? error.detail : JSON.stringify(error.detail);
    throw new Error(detail || 'Request failed');
  }
  return response.json();
}

const post = <T>(url: string, body?: unknown) =>
  request<T>(url, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });

export const api = {
  health: () => request<Health>('/health'),

  uploadFile: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await fetch(`${API_BASE}/upload`, { method: 'POST', body: formData });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(error.detail);
    }
    return response.json() as Promise<{ file_id: string; filename: string; size: number }>;
  },
  listUploads: () => request<{ uploads: Loose[]; samples: Loose[]; lab?: Loose[] }>('/upload/list'),

  analyze: (fileId: string) => post<{ analysis_id: string; summary: Loose }>(`/analyze/${encodeURIComponent(fileId)}`),
  getAnalysis: (id: string) => request<AnalysisRecord>(`/analysis/${encodeURIComponent(id)}`),
  getPackets: (id: string, limit = 100, offset = 0) =>
    request<{ total: number; stored: number; packets: Loose[] }>(
      `/analysis/${encodeURIComponent(id)}/packets?limit=${limit}&offset=${offset}`),
  listAnalyses: () => request<{ analyses: AnalysisSummary[] }>('/analyses'),

  getSecurity: (id: string) => request<Security>(`/security/${encodeURIComponent(id)}`),
  getThreatMatrix: (id: string) => request<ThreatMatrix>(`/security/${encodeURIComponent(id)}/threat-matrix`),

  getModelInfo: () => request<Loose>('/ml/model-info'),
  trainModel: () => post<Loose>('/ml/train'),

  getExecutiveReport: (id: string) => request<Loose>(`/reports/${encodeURIComponent(id)}/executive`),
  reportUrl: (id: string, kind: 'executive.html' | 'technical.html' | 'export.json') =>
    `${API_BASE}/reports/${encodeURIComponent(id)}/${kind}`,

  getDatasetInfo: () => request<Loose>('/dataset/info'),
  generateDataset: (count: number, seed: number) => post<Loose>('/dataset/generate', { count, seed }),
  downloadUrl: (name: string) => `${API_BASE}/dataset/download/${encodeURIComponent(name)}`,

  getMatrix: () => request<Loose>('/testbed/matrix'),
  getScenarios: () => request<{ scenarios: Loose[] }>('/testbed/scenarios'),
  regenerateSamples: () => post<Loose>('/samples/generate'),

  latestEvaluation: () => request<Loose>('/evaluation/latest'),
  runEvaluation: (scenarios: number, seed: number) => post<Loose>('/evaluation/run', { scenarios, seed }),

  liveCapabilities: () => request<Loose>('/live/capabilities'),
  liveStart: (body: { source: 'replay' | 'interface'; file_id?: string; speed?: number; interface?: string }) =>
    post<Loose>('/live/start', body),
  liveStatus: (id: string) => request<Loose>(`/live/${encodeURIComponent(id)}`),
  liveStop: (id: string) => post<Loose>(`/live/${encodeURIComponent(id)}/stop`),
  liveSessions: () => request<{ sessions: Loose[] }>('/live/sessions'),
  liveEventsUrl: (id: string) => `${API_BASE}/live/${encodeURIComponent(id)}/events`,

  // decision support
  getIntel: (id: string) => request<Intel>(`/intel/${encodeURIComponent(id)}`),
  simulatorBaseline: (id: string) => request<Loose>(`/simulator/${encodeURIComponent(id)}/baseline`),
  simulate: (id: string, changes: Record<string, unknown>) => post<Loose>(`/simulator/${encodeURIComponent(id)}`, { changes }),
  verify: (id: string, changes: Record<string, unknown>) => post<Loose>(`/simulator/${encodeURIComponent(id)}/verify`, { changes }),
  getPolicy: () => request<{ policy: Loose; default: Loose }>('/policy'),
  savePolicy: (policy: Loose) => post<{ policy: Loose }>('/policy', { policy }),
  resetPolicy: () => post<{ policy: Loose }>('/policy/reset'),
  evaluatePolicy: (id: string) => request<Loose>(`/policy/evaluate/${encodeURIComponent(id)}`),
  policyFleet: () => request<{ analyses: Loose[] }>('/policy/fleet'),
  fingerprints: () => request<{ analyses: Loose[] }>('/fingerprints'),
  drift: (target: string, baseline?: string) =>
    request<Loose>(`/drift/${encodeURIComponent(target)}${baseline ? `?baseline=${encodeURIComponent(baseline)}` : ''}`),
  labBuild: (body: { config: Loose; traffic: { class: string; seconds: number }[]; label?: string; impairment?: string }) =>
    post<Loose>('/lab/build', body),
  labBuilds: () => request<{ builds: Loose[]; defaults: Loose }>('/lab/builds'),
  simulatorOptions: () => request<{ knobs: Loose[] }>('/simulator/options'),
  benchmarkLatest: () => request<Loose>('/benchmark/latest'),
  runBenchmark: (count: number, seed: number) => post<Loose>('/benchmark/run', { count, seed }),

  // fleet: explorer, link graph, triage
  fleetObjects: () => request<{ rows: FleetRow[] }>('/fleet/objects'),
  fleetGraph: () => request<FleetGraph>('/fleet/graph'),
  triage: () => request<{ items: TriageItem[]; counts: Record<string, number>; statuses: string[] }>('/triage'),
  updateTriage: (keys: string[], status?: string, note?: string) => post<{ updated: number }>('/triage', { keys, status, note }),

  captureInterfaces: () => request<Loose>('/capture/interfaces'),
  startCapture: (body: { interface?: string; duration: number; filter: string }) =>
    post<{ file_id: string; packets: number }>('/capture/start', body),
};
