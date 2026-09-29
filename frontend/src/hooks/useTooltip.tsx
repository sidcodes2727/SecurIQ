import { useState, type FocusEvent, type PointerEvent, type ReactNode } from 'react';

interface Tip { x: number; y: number; content: ReactNode }

/** One tooltip per chart; every mark is focusable and shows the same readout on focus as on hover. */
export function useTooltip() {
  const [tip, setTip] = useState<Tip | null>(null);
  const bind = (content: ReactNode) => ({
    tabIndex: 0,
    onPointerMove: (e: PointerEvent) => setTip({ x: e.clientX, y: e.clientY, content }),
    onPointerLeave: () => setTip(null),
    onFocus: (e: FocusEvent<Element>) => {
      const r = e.currentTarget.getBoundingClientRect();
      setTip({ x: r.left + r.width / 2, y: r.top, content });
    },
    onBlur: () => setTip(null),
  });
  const node = tip && (
    <div className="viz-tooltip" role="tooltip"
      style={{ left: Math.min(Math.max(tip.x, 140), window.innerWidth - 140), top: tip.y }}>
      {tip.content}
    </div>
  );
  return { bind, node };
}
