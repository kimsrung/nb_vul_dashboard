import React, { useState, useEffect, useRef, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { AssetsPage } from './pages/AssetsPage';
import { AssetDetailPage } from './pages/AssetDetailPage';
import { AlertsPage } from './pages/AlertsPage';
import { MispPage } from './pages/MispPage';
import { SettingsPage } from './pages/SettingsPage';
import { UsersPage } from './pages/UsersPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { LoginPage } from './pages/LoginPage';
import { DashboardSummary, apiClient } from './api/client';

const MainApp: React.FC = () => {
  const { isAuthenticated, isAdmin, isAnalyst } = useAuth();
  const location = useLocation();
  const lastFetchTimeRef = useRef<number>(0);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [isLoadingSummary, setIsLoadingSummary] = useState<boolean>(true);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(() => {
    return localStorage.getItem('sidebar_collapsed') === 'true';
  });

  const handleToggleSidebar = () => {
    setIsSidebarCollapsed((prev) => {
      const next = !prev;
      localStorage.setItem('sidebar_collapsed', String(next));
      return next;
    });
  };

  const fetchSummary = useCallback(async (force = false) => {
    if (!isAuthenticated) return;
    const now = Date.now();
    // 30-second client cache: Skip if visited within 30 seconds unless explicitly forced
    if (!force && lastFetchTimeRef.current > 0 && now - lastFetchTimeRef.current < 30000) {
      return;
    }

    try {
      if (!summary) {
        setIsLoadingSummary(true);
      }
      const res = await apiClient.get('/dashboard/summary');
      setSummary(res.data);
      lastFetchTimeRef.current = Date.now();
    } catch (err) {
      console.error('Failed to fetch dashboard summary', err);
    } finally {
      setIsLoadingSummary(false);
    }
  }, [isAuthenticated, summary]);

  // Request summary only when user actually navigates to the Dashboard view
  useEffect(() => {
    if (isAuthenticated && (location.pathname === '/dashboard' || location.pathname === '/')) {
      fetchSummary(false);
    }
  }, [isAuthenticated, location.pathname, fetchSummary]);

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return (
    <div className="h-screen w-full max-w-full bg-background flex flex-col overflow-hidden">
      <Navbar 
        onSyncTriggered={() => fetchSummary(true)} 
        syncStatus={summary?.sync_status} 
        isSidebarCollapsed={isSidebarCollapsed}
        onToggleSidebar={handleToggleSidebar}
      />
      <div className="flex-1 flex overflow-hidden relative">
        <Sidebar
          activeAlertCount={summary?.active_alerts}
          isCollapsed={isSidebarCollapsed}
          onToggleCollapse={handleToggleSidebar}
        />
        <main className="flex-1 h-full overflow-y-auto">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage summary={summary} isLoading={isLoadingSummary} />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/assets/:id" element={<AssetDetailPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/misp" element={(isAdmin || isAnalyst) ? <MispPage /> : <Navigate to="/dashboard" replace />} />
            <Route path="/users" element={isAdmin ? <UsersPage /> : <Navigate to="/dashboard" replace />} />
            <Route path="/audit-logs" element={<AuditLogsPage />} />
            <Route path="/settings" element={isAdmin ? <SettingsPage /> : <Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
};

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <MainApp />
      </AuthProvider>
    </BrowserRouter>
  );
}
