/**
 * Minimal force-directed layout for the link graph (a few hundred nodes at most):
 * pairwise repulsion, spring links, weak gravity, velocity damping and a cooling schedule.
 * Positions start from a hash of the node id, so the same graph lays out the same way every time.
 */
export interface SimNode { id: string; x: number; y: number; vx: number; vy: number; r: number; fx: number | null; fy: number | null; mass: number }
export interface SimLink { s: SimNode; t: SimNode; length: number; strength: number }

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0) / 4294967295;
}

export class ForceLayout {
  nodes: SimNode[] = [];
  links: SimLink[] = [];
  alpha = 1;
  private index = new Map<string, SimNode>();

  constructor(nodes: { id: string; r: number; mass?: number; ring?: number }[], links: { source: string; target: string; length: number; strength?: number }[],
    previous?: Map<string, { x: number; y: number }>) {
    for (const n of nodes) {
      const prev = previous?.get(n.id);
      const angle = hash(n.id) * Math.PI * 2;
      const radius = (n.ring ?? 1) * 160 + hash(`${n.id}#r`) * 80;
      const node: SimNode = { id: n.id, x: prev?.x ?? Math.cos(angle) * radius, y: prev?.y ?? Math.sin(angle) * radius,
        vx: 0, vy: 0, r: n.r, fx: null, fy: null, mass: n.mass ?? 1 };
      this.nodes.push(node);
      this.index.set(n.id, node);
    }
    for (const l of links) {
      const s = this.index.get(l.source), t = this.index.get(l.target);
      if (s && t) this.links.push({ s, t, length: l.length, strength: l.strength ?? 0.06 });
    }
    if (previous?.size) this.alpha = 0.35;
  }

  get(id: string) { return this.index.get(id); }

  tick(): void {
    const { nodes, links } = this;
    const a = this.alpha;
    for (let i = 0; i < nodes.length; i++) {
      const p = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const q = nodes[j];
        let dx = q.x - p.x, dy = q.y - p.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) { dx = (hash(p.id + q.id) - 0.5) * 2; dy = (hash(q.id + p.id) - 0.5) * 2; d2 = dx * dx + dy * dy + 1; }
        const min = p.r + q.r + 14;
        const force = (5200 * a) / d2 + (d2 < min * min ? (min - Math.sqrt(d2)) * 0.4 * a : 0);
        const d = Math.sqrt(d2);
        const fx = (dx / d) * force, fy = (dy / d) * force;
        p.vx -= fx / p.mass; p.vy -= fy / p.mass; q.vx += fx / q.mass; q.vy += fy / q.mass;
      }
    }
    for (const l of links) {
      const dx = l.t.x - l.s.x, dy = l.t.y - l.s.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const k = ((d - l.length) / d) * l.strength * a;
      l.s.vx += dx * k / l.s.mass; l.s.vy += dy * k / l.s.mass;
      l.t.vx -= dx * k / l.t.mass; l.t.vy -= dy * k / l.t.mass;
    }
    for (const n of nodes) {
      n.vx -= n.x * 0.004 * a; n.vy -= n.y * 0.004 * a;
      if (n.fx !== null && n.fy !== null) { n.x = n.fx; n.y = n.fy; n.vx = 0; n.vy = 0; continue; }
      n.vx *= 0.62; n.vy *= 0.62;
      n.x += Math.max(-40, Math.min(40, n.vx)); n.y += Math.max(-40, Math.min(40, n.vy));
    }
    this.alpha = Math.max(0, this.alpha * 0.985 - 0.0005);
  }

  run(ticks: number) { for (let i = 0; i < ticks && this.alpha > 0.002; i++) this.tick(); }

  reheat(to = 0.4) { this.alpha = Math.max(this.alpha, to); }

  bounds(ids?: Set<string>) {
    const list = ids ? this.nodes.filter((n) => ids.has(n.id)) : this.nodes;
    if (!list.length) return { x0: -100, y0: -100, x1: 100, y1: 100 };
    return {
      x0: Math.min(...list.map((n) => n.x - n.r)), y0: Math.min(...list.map((n) => n.y - n.r)),
      x1: Math.max(...list.map((n) => n.x + n.r)), y1: Math.max(...list.map((n) => n.y + n.r)),
    };
  }
}
