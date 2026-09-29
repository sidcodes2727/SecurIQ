import { lazy, Suspense } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import CommandPalette from './components/CommandPalette';
import { Sidebar, Topbar } from './components/Layout';
import { Loading } from './components/ui';
import { useRailCollapsed } from './hooks/useRail';

// every page is its own chunk, loaded on first visit
const Analysis = lazy(() => import('./pages/Analysis'));
const Classification = lazy(() => import('./pages/Classification'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Drift = lazy(() => import('./pages/Drift'));
const Explorer = lazy(() => import('./pages/Explorer'));
const Graph = lazy(() => import('./pages/Graph'));
const Inbox = lazy(() => import('./pages/Inbox'));
const Lab = lazy(() => import('./pages/Lab'));
const Live = lazy(() => import('./pages/Live'));
const Policy = lazy(() => import('./pages/Policy'));
const Reports = lazy(() => import('./pages/Reports'));
const Security = lazy(() => import('./pages/Security'));
const Simulator = lazy(() => import('./pages/Simulator'));
const Surface = lazy(() => import('./pages/Surface'));
const Testbed = lazy(() => import('./pages/Testbed'));
const Upload = lazy(() => import('./pages/Upload'));
import { ToastProvider } from './components/Toasts';

function Shell() {
  const collapsed = useRailCollapsed();
  return (
    <div className={`app-layout ${collapsed ? 'rail-collapsed' : ''}`}>
      <Sidebar />
      <main className="main-content">
        <Topbar />
        <Suspense fallback={<div className="page-container"><Loading /></div>}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/inbox" element={<Inbox />} />
          <Route path="/explorer" element={<Explorer />} />
          <Route path="/graph" element={<Graph />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/live" element={<Live />} />
          <Route path="/lab" element={<Lab />} />
          <Route path="/surface" element={<Surface />} />
          <Route path="/simulator" element={<Simulator />} />
          <Route path="/policy" element={<Policy />} />
          <Route path="/drift" element={<Drift />} />
          <Route path="/analysis" element={<Analysis />} />
          <Route path="/classification" element={<Classification />} />
          <Route path="/security" element={<Security />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/testbed" element={<Testbed />} />
          <Route path="/dataset" element={<Testbed />} />
        </Routes>
        </Suspense>
      </main>
      <CommandPalette />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <Shell />
      </ToastProvider>
    </BrowserRouter>
  );
}
