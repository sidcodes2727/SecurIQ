// Navigation model shared by the rail, the topbar, the command palette and keyboard shortcuts.
export interface NavItem { to: string; num: string; label: string; end?: boolean; scoped?: boolean; badge?: string; key?: string }

export const NAV: { section: string; items: NavItem[] }[] = [
  { section: 'Overview', items: [{ to: '/', num: '0x01', label: 'Operations', end: true, key: 'd' }] },
  { section: 'Investigate', items: [
    { to: '/inbox', num: '0x02', label: 'Triage inbox', key: 'i' },
    { to: '/explorer', num: '0x03', label: 'Object explorer', key: 'e' },
    { to: '/graph', num: '0x04', label: 'Link graph', key: 'g' },
  ] },
  { section: 'Capture', items: [
    { to: '/upload', num: '0x05', label: 'Captures & samples', key: 'c' },
    { to: '/live', num: '0x06', label: 'Live monitor', key: 'v' },
    { to: '/lab', num: '0x07', label: 'VPN lab', badge: 'twin', key: 'l' },
  ] },
  { section: 'Analyse', items: [
    { to: '/analysis', num: '0x08', label: 'Protocol identification', scoped: true, key: 'a' },
    { to: '/classification', num: '0x09', label: 'Traffic & metadata', scoped: true, key: 'm' },
    { to: '/security', num: '0x0A', label: 'Security assessment', scoped: true, key: 's' },
    { to: '/surface', num: '0x0B', label: 'Attack surface', scoped: true, key: 'x' },
  ] },
  { section: 'Decide', items: [
    { to: '/simulator', num: '0x0C', label: 'What-if simulator', scoped: true, key: 'w' },
    { to: '/policy', num: '0x0D', label: 'Golden policy', scoped: true, key: 'p' },
    { to: '/drift', num: '0x0E', label: 'Drift detection', scoped: true, key: 'f' },
  ] },
  { section: 'Output', items: [{ to: '/reports', num: '0x0F', label: 'Reports', scoped: true, key: 'r' }] },
  { section: 'Research', items: [{ to: '/testbed', num: '0x10', label: 'Testbed & model', key: 't' }] },
];

export const ROUTES = NAV.flatMap((g) => g.items.map((item) => ({ ...item, section: g.section })));
export const routeFor = (pathname: string) =>
  ROUTES.find((r) => (r.end ? pathname === r.to : pathname.startsWith(r.to)))
  ?? (pathname === '/dataset' ? ROUTES[ROUTES.length - 1] : ROUTES[0]);

