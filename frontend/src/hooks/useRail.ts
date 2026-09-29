import { useEffect, useState } from 'react';

const COLLAPSE_KEY = 'securiq.railCollapsed';
function readCollapsed() {
  try { return localStorage.getItem(COLLAPSE_KEY) === '1'; } catch { return false; }
}

/** Rail collapse state, shared with the palette through a window event. */
export function useRailCollapsed() {
  const [collapsed, setCollapsed] = useState(readCollapsed);
  useEffect(() => {
    const toggle = () => setCollapsed((c) => {
      try { localStorage.setItem(COLLAPSE_KEY, c ? '0' : '1'); } catch { /* per-viewer convenience only */ }
      return !c;
    });
    window.addEventListener('securiq:toggle-rail', toggle);
    return () => window.removeEventListener('securiq:toggle-rail', toggle);
  }, []);
  return collapsed;
}

