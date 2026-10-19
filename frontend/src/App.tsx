import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { AssetsPage } from './pages/AssetsPage';
import { AssetDetailPage } from './pages/AssetDetailPage';
import { AlertsPage } from './pages/AlertsPage';
import { SettingsPage } from './pages/SettingsPage';
import { LoginPage } from './pages/LoginPage';
import { DashboardSummary, apiClient } from './api/client';

const MainApp: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [selectedAssetId, setSelectedAssetId] = useState<number | null>(null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [isLoadingSummary, setIsLoadingSummary] = useState<boolean>(true);

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
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar onSyncTriggered={fetchSummary} syncStatus={summary?.sync_status} />
      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          currentTab={currentTab === 'asset-detail' ? 'assets' : currentTab}
          setCurrentTab={(tab) => {
            setSelectedAssetId(null);
            setCurrentTab(tab);
          }}
          activeAlertCount={summary?.active_alerts}
        />
        <main className="flex-1 overflow-y-auto">
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
