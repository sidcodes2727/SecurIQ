import { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { Loose } from '../types';

export interface LiveEvent { seq: number; type: string; t: number; data: Loose }
export interface RatePoint { t: number; packets: number; bytes: number; esp: number; ike: number }

export interface LiveState {
  status: string;
  source: string;
  error: string | null;
  analysisId: string | null;
  snapshot: Loose | null;
  rate: RatePoint[];
  windows: Loose[];
  alerts: LiveEvent[];
  log: LiveEvent[];
  totals: { packets: number; bytes: number; ike: number; sas: number };
  connected: boolean;
}

const EMPTY: LiveState = {
  status: 'connecting', source: '', error: null, analysisId: null, snapshot: null, rate: [], windows: [],
  alerts: [], log: [], totals: { packets: 0, bytes: 0, ike: 0, sas: 0 }, connected: false,
};

function reduce(state: LiveState, event: LiveEvent): LiveState {
  const d = event.data;
  switch (event.type) {
    case 'status':
      return { ...state, status: d.status, source: d.source ?? state.source, error: d.error ?? state.error,
        analysisId: d.analysis_id ?? state.analysisId };
    case 'rate': {
      const byT = new Map(state.rate.map((p) => [p.t, p]));
      for (const p of d.series as RatePoint[]) byT.set(p.t, p);
      const rate = [...byT.values()].sort((a, b) => a.t - b.t).slice(-120);
      return { ...state, rate, totals: { ...state.totals, packets: d.total_packets, bytes: d.total_bytes } };
    }
    case 'window':
      return { ...state, windows: [...state.windows, d].slice(-600) };
    case 'alert':
      return { ...state, alerts: [event, ...state.alerts].slice(0, 100) };
    case 'ike':
      return { ...state, log: [event, ...state.log].slice(0, 80), totals: { ...state.totals, ike: state.totals.ike + 1 } };
    case 'sa':
      return { ...state, log: [event, ...state.log].slice(0, 80), totals: { ...state.totals, sas: state.totals.sas + 1 } };
    case 'snapshot':
      return { ...state, snapshot: d, totals: { ...state.totals, packets: d.counts.total, bytes: d.bytes } };
    case 'analysis':
      return { ...state, analysisId: d.analysis_id };
    default:
      return state;
  }
}

const TYPES = ['status', 'rate', 'window', 'alert', 'ike', 'sa', 'snapshot', 'analysis'];

/** Subscribes to a live session's Server-Sent Events and folds them into dashboard state. */
export function useLiveSession(sessionId: string | null): LiveState {
  const [state, setState] = useState<{ id: string | null; value: LiveState }>({ id: null, value: EMPTY });

  useEffect(() => {
    if (!sessionId) return;
    const source = new EventSource(api.liveEventsUrl(sessionId));
    const handle = (message: MessageEvent) => {
      const event = JSON.parse(message.data) as LiveEvent;
      setState((prev) => ({ id: sessionId, value: reduce(prev.id === sessionId ? prev.value : EMPTY, event) }));
    };
    TYPES.forEach((t) => source.addEventListener(t, handle as EventListener));
    source.addEventListener('end', () => source.close());
    source.onopen = () => setState((prev) => ({ id: sessionId, value: { ...(prev.id === sessionId ? prev.value : EMPTY), connected: true } }));
    source.onerror = () => setState((prev) => ({ id: sessionId, value: { ...(prev.id === sessionId ? prev.value : EMPTY), connected: false } }));
    return () => source.close();
  }, [sessionId]);

  return state.id === sessionId ? state.value : EMPTY;
}
