import { useCallback, useMemo, useRef, useState, type ReactNode } from 'react';
import { ToastContext, type Tone } from '../hooks/useToast';

interface Toast { id: number; title: string; body?: string; tone: Tone }

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);
  const push = useCallback((title: string, body?: string, tone: Tone = 'info') => {
    const id = next.current++;
    setToasts((list) => [...list.slice(-3), { id, title, body, tone }]);
    window.setTimeout(() => setToasts((list) => list.filter((t) => t.id !== id)), 4200);
  }, []);
  const api = useMemo(() => ({ push }), [push]);
  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast t-${t.tone}`}>
            <span className="toast-icon" aria-hidden>{t.tone === 'good' ? '✓' : t.tone === 'critical' ? '✕' : '›'}</span>
            <div><strong>{t.title}</strong>{t.body && <p>{t.body}</p>}</div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
