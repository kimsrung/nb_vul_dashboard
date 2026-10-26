import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
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
  const { isAuthenticated, isAdmin } = useAuth();
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

  const fetchSummary = async () => {
    if (!isAuthenticated) return;
    try {
      const res = await apiClient.get('/dashboard/summary');
      setSummary(res.data);
    } catch (err) {
      console.error('Failed to fetch dashboard summary', err);
    } finally {
      setIsLoadingSummary(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated) {
      fetchSummary();
      const interval = setInterval(fetchSummary, 20000); // 20s polling
      return () => clearInterval(interval);
    }
  }, [isAuthenticated]);

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return (
    <div className="h-screen w-screen bg-background flex flex-col overflow-hidden">
      <Navbar 
        onSyncTriggered={fetchSummary} 
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
            <Route path="/dashboard" element={<DashboardPage summary={summary} isLoading={isLoadingSummary} onRefreshSummary={fetchSummary} />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/assets/:id" element={<AssetDetailPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/misp" element={isAdmin ? <MispPage /> : <Navigate to="/dashboard" replace />} />
            <Route path="/users" element={isAdmin ? <UsersPage /> : <Navigate to="/dashboard" replace />} />
            <Route path="/audit-logs" element={<AuditLogsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
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
