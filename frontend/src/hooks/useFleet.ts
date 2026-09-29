import { useCallback, useEffect, useState } from 'react';
import { api } from '../services/api';
import type { FleetRow } from '../types';

let cache: { at: number; rows: FleetRow[] } | null = null;

/** Every stored capture as a flat object row (shared, briefly cached across pages). */
export function useFleet() {
  const [rows, setRows] = useState<FleetRow[] | null>(cache?.rows ?? null);
  const [error, setError] = useState<string | null>(null);
  const reload = useCallback(() => {
    api.fleetObjects().then((d) => { cache = { at: Date.now(), rows: d.rows }; setRows(d.rows); setError(null); })
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(() => {
    if (!cache || Date.now() - cache.at > 10000) reload();
  }, [reload]);
  return { rows, error, reload };
}
