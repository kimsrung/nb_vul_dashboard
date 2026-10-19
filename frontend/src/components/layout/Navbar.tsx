import React, { useState } from 'react';
import { Shield, RefreshCw, User, LogOut, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { apiClient } from '../../api/client';

interface NavbarProps {
  onSyncTriggered?: () => void;
  syncStatus?: string;
}

export const Navbar: React.FC<NavbarProps> = ({ onSyncTriggered, syncStatus = 'Idle' }) => {
  const { username, role, logout, isAdmin } = useAuth();
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);

  const handleSyncNow = async () => {
    setIsSyncing(true);
    setSyncFeedback(null);
    try {
      const res = await apiClient.post('/dashboard/sync');
      setSyncFeedback(res.data.message || 'Sync started');
      if (onSyncTriggered) onSyncTriggered();
      setTimeout(() => setSyncFeedback(null), 4000);
    } catch (err: any) {
      setSyncFeedback(err.response?.data?.detail || 'Sync failed to start');
      setTimeout(() => setSyncFeedback(null), 4000);
    } finally {
      setIsSyncing(false);
    }
  };

  return (
    <header className="h-16 border-b border-surfaceBorder bg-surface/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      <div className="flex items-center gap-3">
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
          <div className="text-xs text-sky-400 flex items-center gap-1 font-medium bg-sky-950/40 px-2.5 py-1 rounded-lg border border-sky-800/40 animate-fade-in">
            <CheckCircle2 className="w-3.5 h-3.5" /> {syncFeedback}
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
              <span className={`text-[10px] font-mono px-1.5 rounded uppercase font-semibold ${role === 'admin' ? 'bg-purple-950/50 text-purple-300 border border-purple-800/40' : 'bg-slate-800 text-slate-400'}`}>
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
