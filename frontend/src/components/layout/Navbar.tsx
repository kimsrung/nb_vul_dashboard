import React, { useState } from 'react';
import { Shield, RefreshCw, User, LogOut, CheckCircle2, AlertCircle, PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { apiClient } from '../../api/client';

interface NavbarProps {
  onSyncTriggered?: () => void;
  syncStatus?: string;
  isSidebarCollapsed?: boolean;
  onToggleSidebar?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ 
  onSyncTriggered, 
  syncStatus = 'Idle',
  isSidebarCollapsed = false,
  onToggleSidebar,
}) => {
  const { username, role, logout, isAdmin } = useAuth();
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);
  const [isError, setIsError] = useState<boolean>(false);

  const handleSyncNow = async () => {
    setIsSyncing(true);
    setIsError(false);
    setSyncFeedback('Initiating Qualys sync...');

    try {
      await apiClient.post('/dashboard/sync');

      // Poll sync status until finished or error
      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await apiClient.get('/dashboard/sync-status');
          const data = statusRes.data;
          if (data.status === 'Idle') {
            clearInterval(pollInterval);
            setIsSyncing(false);
            setIsError(false);
            setSyncFeedback(data.message || 'Sync completed successfully');
            if (onSyncTriggered) onSyncTriggered();
            setTimeout(() => setSyncFeedback(null), 6000);
          } else if (data.status === 'Error') {
            clearInterval(pollInterval);
            setIsSyncing(false);
            setIsError(true);
            setSyncFeedback(data.message || 'Qualys sync failed');
          } else {
            setSyncFeedback(data.message || 'Sync in progress...');
          }
        } catch {
          // ignore poll error
        }
      }, 1500);

      // Safety timeout after 2 minutes
      setTimeout(() => {
        clearInterval(pollInterval);
        setIsSyncing(false);
      }, 120000);
    } catch (err: any) {
      setIsSyncing(false);
      setIsError(true);
      setSyncFeedback(err.response?.data?.detail || 'Failed to start sync');
      setTimeout(() => setSyncFeedback(null), 6000);
    }
  };

  return (
    <header className="h-16 shrink-0 border-b border-surfaceBorder bg-surface/90 backdrop-blur-md px-4 sm:px-6 flex items-center justify-between sticky top-0 z-40 select-none">
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-slate-800/80 transition-colors border border-slate-800"
            title={isSidebarCollapsed ? "Expand sidebar navigation" : "Collapse sidebar navigation"}
            aria-label="Toggle navigation"
          >
            {isSidebarCollapsed ? (
              <PanelLeftOpen className="w-4 h-4 text-sky-400" />
            ) : (
              <PanelLeftClose className="w-4 h-4 text-slate-400" />
            )}
          </button>
        )}
        <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            Qualys Risk Alert
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
              KB Remediation
            </span>
          </h1>
          <p className="text-[11px] text-slate-400">Host Detection & Threat Intelligence Engine</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Sync Status & Button */}
        {syncFeedback && (
          <div
            className={`text-xs flex items-center gap-1.5 font-medium px-3 py-1 rounded-lg border max-w-md truncate animate-fade-in ${
              isError
                ? 'bg-red-950/60 text-red-300 border-red-800/60'
                : 'bg-sky-950/40 text-sky-300 border-sky-800/40'
            }`}
          >
            {isError ? (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
            )}
            <span className="truncate">{syncFeedback}</span>
          </div>
        )}

        {isAdmin && (
          <button
            onClick={handleSyncNow}
            disabled={isSyncing || syncStatus === 'Syncing'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition-all hover:border-slate-600 disabled:opacity-50"
            title="Fetch latest Detections and KnowledgeBase updates"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isSyncing || syncStatus === 'Syncing' ? 'animate-spin' : ''}`} />
            <span>{isSyncing || syncStatus === 'Syncing' ? 'Syncing...' : 'Sync Now'}</span>
          </button>
        )}

        {/* User profile & Role Badge */}
        <div className="flex items-center gap-2 pl-2 border-l border-surfaceBorder">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
            <User className="w-4 h-4" />
          </div>
          <div className="text-left hidden sm:block">
            <div className="text-xs font-semibold text-slate-200">{username}</div>
            <div className="flex items-center gap-1">
              <span
                className={`text-[10px] font-mono px-1.5 rounded uppercase font-semibold ${
                  role === 'admin'
                    ? 'bg-purple-950/60 text-purple-300 border border-purple-800/40'
                    : role === 'analyst'
                    ? 'bg-indigo-950/60 text-indigo-300 border border-indigo-800/40'
                    : role === 'owner'
                    ? 'bg-sky-950/60 text-sky-300 border border-sky-800/40'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}
              >
                {role}
              </span>
            </div>
          </div>
          <button
            onClick={logout}
            className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors ml-1"
            title="Log out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
