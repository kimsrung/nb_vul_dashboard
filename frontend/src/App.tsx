import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { AssetsPage } from './pages/AssetsPage';
import { AssetDetailPage } from './pages/AssetDetailPage';
import { AlertsPage } from './pages/AlertsPage';
import { SettingsPage } from './pages/SettingsPage';
import { UsersPage } from './pages/UsersPage';
import { MispFeedPage } from './pages/MispFeedPage';
import { LoginPage } from './pages/LoginPage';
import { DashboardSummary, apiClient } from './api/client';

const MainApp: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [selectedAssetId, setSelectedAssetId] = useState<number | null>(null);
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

  const handleSelectAsset = (assetId: number) => {
    setSelectedAssetId(assetId);
    setCurrentTab('asset-detail');
  };

  const handleBackToAssets = () => {
    setSelectedAssetId(null);
    setCurrentTab('assets');
  };

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
          currentTab={currentTab === 'asset-detail' ? 'assets' : currentTab}
          setCurrentTab={(tab) => {
            setSelectedAssetId(null);
            setCurrentTab(tab);
          }}
          activeAlertCount={summary?.active_alerts}
          isCollapsed={isSidebarCollapsed}
          onToggleCollapse={handleToggleSidebar}
        />
        <main className="flex-1 h-full overflow-y-auto">
          {currentTab === 'dashboard' && (
            <DashboardPage
              summary={summary}
              isLoading={isLoadingSummary}
              onSelectAsset={handleSelectAsset}
              onNavigateTab={(tab) => {
                setSelectedAssetId(null);
                setCurrentTab(tab);
              }}
            />
          )}

          {currentTab === 'assets' && (
            <AssetsPage onSelectAsset={handleSelectAsset} />
          )}

          {currentTab === 'asset-detail' && selectedAssetId && (
            <AssetDetailPage
              assetId={selectedAssetId}
              onBack={handleBackToAssets}
            />
          )}

          {currentTab === 'alerts' && (
            <AlertsPage onSelectAsset={handleSelectAsset} />
          )}

          {currentTab === 'misp' && (
            <MispFeedPage onSelectAsset={handleSelectAsset} />
          )}

          {currentTab === 'users' && <UsersPage />}

          {currentTab === 'settings' && <SettingsPage />}
        </main>
      </div>
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}
