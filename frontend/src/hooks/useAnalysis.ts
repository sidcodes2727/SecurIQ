import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../services/api';
import type { AnalysisRecord, Intel } from '../types';

const STORAGE_KEY = 'securiq.lastAnalysisId';

function readStored(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

export function rememberAnalysis(id: string) {
  try {
    localStorage.setItem(STORAGE_KEY, id);
  } catch {
    /* storage unavailable (private mode) — the ?id= URL still works */
  }
}

/** The analysis in scope: ?id= in the URL, else the last one opened in this browser. */
export function useAnalysisId(): string | null {
  const [params] = useSearchParams();
  const fromUrl = params.get('id');
  useEffect(() => {
    if (fromUrl) rememberAnalysis(fromUrl);
  }, [fromUrl]);
  return fromUrl || readStored();
}

export function useAnalysis() {
  const id = useAnalysisId();
  const [state, setState] = useState<{ id: string | null; data: AnalysisRecord | null; error: string | null }>(
    { id: null, data: null, error: null });

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    api.getAnalysis(id).then(
      (data) => { if (!cancelled) setState({ id, data, error: null }); },
      (e: Error) => { if (!cancelled) setState({ id, data: null, error: e.message }); },
    );
    return () => { cancelled = true; };
  }, [id]);

  const current = state.id === id;
  return {
    id,
    data: current ? state.data : null,
    error: current ? state.error : null,
    loading: Boolean(id) && !current,
  };
}

/** Poll a loader every `ms` while `active` is true. */
export function usePolling(loader: () => void, ms: number, active: boolean) {
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(loader, ms);
    return () => window.clearInterval(timer);
  }, [loader, ms, active]);
}

/** Decision-support layer for an analysis (explanations, fingerprint, policy, surface…). */
export function useIntel(id: string | null) {
  const [state, setState] = useState<{ id: string | null; data: Intel | null; error: string | null }>(
    { id: null, data: null, error: null });
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    api.getIntel(id).then(
      (data) => { if (!cancelled) setState({ id, data, error: null }); },
      (e: Error) => { if (!cancelled) setState({ id, data: null, error: e.message }); },
    );
    return () => { cancelled = true; };
  }, [id]);
  return state.id === id ? { intel: state.data, error: state.error } : { intel: null, error: null };
}
