// Shapes of the SecurIQ API responses the dashboard relies on.

export type Source = 'observed' | 'inferred' | 'not_observable';
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export interface Evidence {
  value: string | number | boolean | null;
  source: Source;
  confidence: number;
  evidence: string;
  method?: string | null;
  display?: string;
  [extra: string]: unknown;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  evidence: string;
  recommendation: string;
  evidence_source: Source;
  confidence: number;
}

export interface Category {
  label: string;
  score: number | null;
  confidence: number;
  rating: string;
  rationale: string;
  weight: number;
  findings: Finding[];
}

export interface ComplianceCheck {
  id: string;
  title: string;
  reference: string;
  status: 'pass' | 'warn' | 'fail' | 'unknown';
  evidence: string;
}

export interface ComplianceProfile {
  name: string;
  description: string;
  status: string;
  score: number | null;
  coverage: number;
  counts: Record<string, number>;
  checks: ComplianceCheck[];
}

export interface Recommendation {
  priority: string;
  finding_id: string;
  title: string;
  action: string;
  severity: Severity;
}

export interface Security {
  overall_score: number | null;
  uncapped_score: number | null;
  score_cap: string | null;
  risk_score: number | null;
  risk_level: string;
  coverage: number;
  provisional: boolean;
  categories: Record<string, Category>;
  findings: Finding[];
  severity_counts: Record<Severity, number>;
  recommendations: Recommendation[];
  compliance: Record<string, ComplianceProfile>;
  effective_strength: { bits: number | null; limited_by: string | null; rating: string; note?: string;
    components: { role: string; algorithm: string | null; bits: number | null }[] };
  method: string;
}

export interface Threat {
  id: string;
  name: string;
  description: string;
  attack: string;
  likelihood: number;
  impact: number;
  risk_score: number;
  risk_level: string;
  contributing_findings: string[];
}

export interface ThreatMatrix {
  threats: Threat[];
  grid: string[][][];
  max_risk_score: number;
  threat_count: number;
  critical_count: number;
  high_count: number;
}

export interface Prediction {
  flow_id: string;
  window_start: number;
  window_end: number;
  packet_count: number;
  predicted_class: string;
  predicted_label: string;
  confidence: number;
  uncertain: boolean;
  top_predictions: { class: string; confidence: number }[];
  all_probabilities: Record<string, number>;
  explanation: { feature: string; value: number; class_median: number | null }[];
  reasoning?: { supports: string[]; caveats: string[] };
  novel?: boolean;
  novelty_score?: number;
}

export interface TrafficSummary {
  flows: { flow_id: string; dominant_class: string; dominant_label: string; mix: Record<string, number>;
    windows: number; mean_confidence: number;
    timeline: { start: number; end: number; class: string; confidence: number; uncertain: boolean }[] }[];
  mix: Record<string, number>;
  mean_confidence: number | null;
  windows: number;
  uncertain_windows?: number;
  novel_windows?: number;
  note?: string | null;
}

export interface AiConfidence {
  overall: number;
  identification: number;
  classification: number | null;
  assessment_coverage: number;
  fields_total: number;
  fields_observed: number;
  fields_inferred: number;
  fields_not_observable: number;
  formula: string;
}

export interface GroundTruth {
  scenario: string;
  description?: string;
  rows: { field: string; expected: unknown; predicted: unknown; status: 'correct' | 'wrong' | 'abstained';
    observable: boolean }[];
  correct: number;
  decided: number;
  total: number;
  accuracy: number | null;
  window_accuracy: number | null;
}

// Large nested analyzer output; typed loosely where the UI only renders it.
export type Loose = any;

export interface AnalysisRecord {
  analysis_id: string;
  file_id: string;
  created: number;
  parsed_metadata: { filename: string; file_size: number; total_packets: number; parse_duration_ms: number;
    file_hash: string; truncated: boolean };
  parsed_summary: Record<string, number>;
  ipsec_analysis: Loose;
  classification: Prediction[];
  traffic: TrafficSummary;
  security: Security;
  threat_matrix: ThreatMatrix;
  ai_confidence: AiConfidence;
  ground_truth: GroundTruth | null;
  pipeline_seconds: number;
  source: { file_id: string; is_sample: boolean; lab?: boolean; derived_from?: string };
  intel?: Intel;
}

export interface AnalysisSummary {
  analysis_id: string;
  file_id: string;
  filename: string;
  created: number;
  total_packets: number;
  security_score: number | null;
  risk_level: string;
  findings_count: number;
  critical_high: number;
  ike_version: string | null;
  ai_confidence: number | null;
  fingerprint?: string | null;
  fingerprint_label?: string | null;
  endpoints?: string[] | null;
}

export interface Health {
  status: string;
  version: string;
  model_trained: boolean;
  model_training: boolean;
  model_error: string | null;
  samples_ready: boolean;
  sample_files: number;
}

// ---------------------------------------------------------------- decision-support layer

export interface ChainParameter { label: string; value: string; source?: string; confidence?: number; evidence?: string; method?: string }
export interface ChainPacket { label: string; detail: string; frames: number[]; encrypted?: boolean }
export interface EvidenceChain {
  finding_id: string;
  packets: ChainPacket[];
  parameters: ChainParameter[];
  rule: { statement: string; reference: string; id: string };
  risk: { severity: Severity; impact: string; confidence?: number; source?: string };
  recommendation: string;
}

export interface Posture {
  risk_level: string;
  headline: string;
  score: number | null;
  evidence: { text: string; finding: string; severity: Severity; source?: string; confidence?: number }[];
  impact: string;
  recommendations: string[];
  cap: string | null;
  coverage: number;
  method: string;
}

export interface Check { ok: boolean | null; text: string }
export interface Fingerprint {
  id: string; sha256: string; label: string; canonical: string;
  components: { key: string; label: string; value: unknown }[];
  observed_components: number; total_components: number; endpoints: string[];
}

export interface Intel {
  version: number;
  chains: Record<string, EvidenceChain>;
  posture: Posture;
  checks: Record<string, { checks: Check[]; caveats: string[] }>;
  novelty: { status: 'known' | 'unusual' | 'novel'; signals: { level: string; text: string }[]; nearest_known: Loose; method: string };
  metadata: {
    confidentiality: number | null; metadata_privacy: number | null;
    dimensions: { key: string; label: string; exposed: number | null; weight: number; detail: string; source: string }[];
    statements: string[]; observer_sees: string[]; observer_cannot_see: string[]; method: string;
  };
  fingerprint: Fingerprint;
  surface: {
    nodes: { id: string; layer: number; kind: string; title: string; subtitle: string; facts: string[];
      risks: { id: string; title: string; severity: Severity }[]; strengths: string[]; status: string; class?: string }[];
    edges: { from: string; to: string; label: string }[];
    hidden_tunnels: number; layers: string[];
  };
  policy: PolicyResult;
}

export interface PolicyResult {
  policy_name: string;
  rows: { key: string; requirement: string; observed: string; status: 'pass' | 'fail' | 'unknown'; source?: string | null }[];
  counts: { pass: number; fail: number; unknown: number };
  compliant: boolean;
  status: string;
  score: number | null;
}

// ---------------------------------------------------------------- fleet

export interface FleetRow {
  analysis_id: string; filename: string; created: number; packets: number; duration: number; source: string;
  score: number | null; risk_level: string; coverage: number; strength_bits: number | null;
  ike_version: string | null; exchange_mode: string | null; ike_encryption: string | null; ike_integrity: string | null;
  dh_group: number | null; dh_name: string | null; esp_encryption: string | null; esp_integrity: string | null;
  pfs: 'on' | 'off' | null; mode: string | null; auth: string | null; nat_t: boolean; ip_version: string | null;
  implementation: string | null; gateways: string[]; fingerprint: string; fingerprint_label: string;
  policy_status: string; policy_fail: number; novelty: string; confidentiality: number | null; metadata_privacy: number | null;
  traffic: string[]; traffic_confidence: number | null;
  findings: { id: string; title: string; severity: Severity; source?: string; confidence?: number }[];
  severity_counts: Record<string, number>; tunnels: number; sas: number; replay_anomalies: number;
}

export interface GraphNode {
  id: string; type: 'capture' | 'gateway' | 'fingerprint' | 'finding' | 'traffic' | 'config'; label: string; sub?: string;
  captures: string[]; degree: number; severity?: Severity | null; score?: number | null; analysis_id?: string;
  finding_id?: string; traffic_class?: string; props: Record<string, unknown>;
}
export interface FleetGraph { nodes: GraphNode[]; edges: { source: string; target: string; kind: string }[]; counts: Record<string, number>; captures: number }

export interface TriageItem {
  key: string; analysis_id: string; filename: string; created: number; fingerprint: string; gateways: string[];
  finding_id: string; title: string; severity: Severity; source?: string; confidence?: number;
  status: string; note: string; updated: number | null; history: { at: number; from: string; to: string }[];
}
