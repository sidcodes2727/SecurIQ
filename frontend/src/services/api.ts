const API_BASE = 'http://localhost:8000/api';

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${url}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || 'Request failed');
  }
  return response.json();
}

export const api = {
  // Health
  health: () => request<any>('/health'),

  // Upload
  uploadFile: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await fetch(`${API_BASE}/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(error.detail);
    }
    return response.json();
  },
  listUploads: () => request<any>('/upload/list'),

  // Analysis
  analyze: (fileId: string) => request<any>(`/analyze/${fileId}`, { method: 'POST' }),
  getAnalysis: (analysisId: string) => request<any>(`/analysis/${analysisId}`),
  getPackets: (analysisId: string, limit = 100, offset = 0) =>
    request<any>(`/analysis/${analysisId}/packets?limit=${limit}&offset=${offset}`),
  listAnalyses: () => request<any>('/analyses'),

  // Security
  getSecurity: (analysisId: string) => request<any>(`/security/${analysisId}`),
  getFindings: (analysisId: string) => request<any>(`/security/${analysisId}/findings`),
  getThreatMatrix: (analysisId: string) => request<any>(`/security/${analysisId}/threat-matrix`),

  // ML
  classifyTraffic: (analysisId: string) => request<any>(`/ml/classify/${analysisId}`),
  getModelInfo: () => request<any>('/ml/model-info'),
  trainModel: () => request<any>('/ml/train', { method: 'POST' }),

  // Reports
  getExecutiveReport: (analysisId: string) => request<any>(`/reports/${analysisId}/executive`),
  getTechnicalReport: (analysisId: string) => request<any>(`/reports/${analysisId}/technical`),

  // Dataset
  generateDataset: () => request<any>('/dataset/generate', { method: 'POST' }),
  getDatasetInfo: () => request<any>('/dataset/info'),

  // Samples
  generateSamples: () => request<any>('/samples/generate', { method: 'POST' }),
};
