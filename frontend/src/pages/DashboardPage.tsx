import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert, Server, AlertTriangle, Bug, Flame, ArrowUpRight,
  Activity, ArrowUpDown, ArrowUp, ArrowDown, RefreshCw, ChevronDown,
  CheckCircle2, AlertCircle, X
} from 'lucide-react';
import { DashboardSummary, AssetListItem, apiClient } from '../api/client';
import { RiskBadge } from '../components/common/RiskBadge';
import { TablePagination } from '../components/common/TablePagination';
import { formatDateYMD } from '../utils/date';
import { useAuth } from '../context/AuthContext';

interface DashboardPageProps {
  summary: DashboardSummary | null;
  isLoading: boolean;
  onRefreshSummary?: () => void;
  onSelectAsset?: (assetId: number) => void;
  onNavigateTab?: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  summary,
  isLoading,
  onRefreshSummary,
  onSelectAsset,
  onNavigateTab,
}) => {
  const navigate = useNavigate();
  const { isAdmin } = useAuth();

  // Qualys Sync state (Admin Only)
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);
  const [isSyncError, setIsSyncError] = useState<boolean>(false);
  const [isSyncMenuOpen, setIsSyncMenuOpen] = useState<boolean>(false);

  const handleSyncNow = async (mode: 'delta' | 'full' = 'delta') => {
    setIsSyncMenuOpen(false);
    setIsSyncing(true);
    setIsSyncError(false);
    setSyncFeedback(
      mode === 'full'
        ? 'Initiating complete Qualys inventory reconciliation & KnowledgeBase sync...'
        : 'Initiating fast incremental Qualys delta sync (updated detections since watermark)...'
    );

    try {
      await apiClient.post(`/dashboard/sync?mode=${mode}`);

      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await apiClient.get('/dashboard/sync-status');
          const data = statusRes.data;
          if (data.status === 'Idle') {
            clearInterval(pollInterval);
            setIsSyncing(false);
            setIsSyncError(false);
            setSyncFeedback(data.message || 'Sync completed successfully');
            if (onRefreshSummary) onRefreshSummary();
            setTimeout(() => setSyncFeedback(null), 6000);
          } else if (data.status === 'Error') {
            clearInterval(pollInterval);
            setIsSyncing(false);
            setIsSyncError(true);
            setSyncFeedback(data.message || 'Qualys sync failed');
          } else {
            setSyncFeedback(data.message || 'Sync in progress...');
          }
        } catch {
          // ignore poll error
        }
      }, 1500);

      setTimeout(() => {
        clearInterval(pollInterval);
        setIsSyncing(false);
      }, 120000);
    } catch (err: any) {
      setIsSyncing(false);
      setIsSyncError(true);
      setSyncFeedback(err.response?.data?.detail || 'Failed to start sync');
      setTimeout(() => setSyncFeedback(null), 6000);
    }
  };

  const handleSelectAsset = (assetId: number) => {
    if (onSelectAsset) {
      onSelectAsset(assetId);
    } else {
      navigate(`/assets/${assetId}`);
    }
  };
  const handleNavigateTab = (tab: string) => {
    if (onNavigateTab) {
      onNavigateTab(tab);
    } else {
      navigate(`/${tab}`);
    }
  };

  const [sortField, setSortField] = useState<string>('risk_score');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(5);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder(field === 'risk_score' || field === 'critical_vulns' ? 'desc' : 'asc');
    }
    setCurrentPage(1);
  };

  if (!summary && isLoading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-slate-400">Loading Qualys Risk Telemetry...</p>
        </div>
      </div>
    );
  }

  if (!summary) {
    return null;
  }

  const riskyAssets = summary?.recent_risky_assets || [];
  const sortedAssets = [...riskyAssets].sort((a, b) => {
    let aVal: any = a[sortField as keyof AssetListItem];
    let bVal: any = b[sortField as keyof AssetListItem];

    if (sortField === 'server_name') {
      aVal = a.server_name || a.fqdn || '';
      bVal = b.server_name || b.fqdn || '';
    }

    if (typeof aVal === 'string') {
      aVal = aVal.toLowerCase();
      bVal = (bVal || '').toLowerCase();
    }

    if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1;
    if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1;
    return 0;
  });

  const totalPages = Math.max(1, Math.ceil(sortedAssets.length / pageSize));
  const paginatedAssets = sortedAssets.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const riskyPercent = summary.total_assets > 0 ? Math.round((summary.risky_assets / summary.total_assets) * 100) : 0;

  return (
    <div className="p-6 max-w-8xl mx-auto space-y-6">
      {/* Welcome Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-sky-950/40 border border-surfaceBorder shadow-xl">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold text-primary-400 uppercase tracking-wider mb-1">
            <Activity className="w-4 h-4" /> Real-Time Vulnerability & Threat Posture
          </div>
          <h2 className="text-2xl font-black text-slate-100">
            Internal Risk Alert Dashboard
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Correlating Qualys Host Detections with KnowledgeBase remediation and threat intelligence.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-4 bg-slate-950/60 p-3 rounded-xl border border-slate-800">
            <div className="text-right space-y-0.5">
              <div className="flex items-center justify-end gap-1.5">
                <span className="text-[10px] text-slate-400 font-medium">Last Delta:</span>
                <span className="text-xs font-mono font-semibold text-slate-200">
                  {formatDateYMD(summary.last_sync_time, 'Never')}
                </span>
              </div>
              <div className="flex items-center justify-end gap-1.5 text-[11px]">
                <span className="text-[10px] text-slate-400 font-medium">Last Full:</span>
                <span className="text-[11px] font-mono text-slate-300">
                  {formatDateYMD(summary.last_full_sync_time, 'Not run yet')}
                </span>
                <span className="text-[9px] uppercase tracking-wider font-semibold px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
                  {summary.last_sync_mode === 'full' ? 'Full Sync' : 'Delta Sync'}
                </span>
              </div>
            </div>
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shrink-0" title="Sync pipeline operational" />
          </div>

          <div className="flex items-center gap-2 relative">
            <button
              onClick={() => onRefreshSummary && onRefreshSummary()}
              disabled={isLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            {isAdmin && (
              <div className="relative inline-flex rounded-lg shadow-md shadow-sky-600/20">
                <button
                  onClick={() => handleSyncNow('delta')}
                  disabled={isSyncing}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-l-lg bg-sky-600 hover:bg-sky-500 text-xs font-bold text-white transition-all disabled:opacity-50 border-r border-sky-700/60 cursor-pointer"
                  title="Trigger fast incremental Qualys delta sync (updated detections only)"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                  <span>{isSyncing ? 'Syncing...' : 'Sync Delta'}</span>
                </button>
                <button
                  onClick={() => setIsSyncMenuOpen((prev) => !prev)}
                  disabled={isSyncing}
                  className="px-1.5 py-1.5 rounded-r-lg bg-sky-600 hover:bg-sky-500 text-white transition-all disabled:opacity-50 cursor-pointer"
                  title="Choose Qualys Sync Mode"
                >
                  <ChevronDown className="w-3.5 h-3.5" />
                </button>

                {isSyncMenuOpen && (
                  <div className="absolute right-0 top-full mt-1.5 w-60 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl py-1 z-50 animate-in fade-in zoom-in-95 duration-150">
                    <button
                      onClick={() => handleSyncNow('delta')}
                      className="w-full text-left px-3.5 py-2 hover:bg-slate-800/80 transition-colors flex flex-col gap-0.5 border-b border-slate-800 cursor-pointer"
                    >
                      <span className="text-xs font-bold text-sky-300 flex items-center justify-between">
                        Smart Delta Sync
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-sky-500/20 text-sky-300">Fast</span>
                      </span>
                      <span className="text-[11px] text-slate-400">
                        Fetches only detections updated since last watermark
                      </span>
                    </button>
                    <button
                      onClick={() => handleSyncNow('full')}
                      className="w-full text-left px-3.5 py-2 hover:bg-slate-800/80 transition-colors flex flex-col gap-0.5 cursor-pointer"
                    >
                      <span className="text-xs font-bold text-amber-300 flex items-center justify-between">
                        Full Reconciliation Sync
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300">Deep</span>
                      </span>
                      <span className="text-[11px] text-slate-400">
                        Paginates all hosts & identifies decommissioned assets
                      </span>
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Sync Feedback Banner */}
      {syncFeedback && (
        <div
          className={`p-3 rounded-lg border text-xs flex items-center justify-between animate-in fade-in duration-200 ${
            isSyncError
              ? 'bg-red-950/60 text-red-300 border-red-800/80'
              : 'bg-sky-950/60 text-sky-300 border-sky-800/80'
          }`}
        >
          <div className="flex items-center gap-2">
            {isSyncError ? (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
            )}
            <span>{syncFeedback}</span>
          </div>
          <button
            onClick={() => setSyncFeedback(null)}
            className="text-slate-400 hover:text-slate-200 p-0.5 rounded cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Assets */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Assets Monitored</span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">{summary.total_assets}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
            <span>Scoped in Qualys</span>
            <span className="text-emerald-400 font-semibold">100% active</span>
          </div>
        </div>

        {/* Risky Assets Flagged */}
        <div className="p-5 rounded-xl bg-surface border border-red-900/30 hover:border-red-700/50 transition-all relative overflow-hidden">
          <div className="absolute -right-4 -bottom-4 w-20 h-20 bg-red-500/5 rounded-full blur-xl pointer-events-none" />
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Flagged Risky Assets</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400 font-mono flex items-baseline gap-2">
            {summary.risky_assets}
            <span className="text-xs text-red-400/80 font-normal">({riskyPercent}% fleet)</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Breaching risk score or SLA rules
          </div>
        </div>

        {/* Critical & High Vulns */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Critical & High Vulns</span>
            <Bug className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono flex items-baseline gap-2">
            {summary.critical_vulns + summary.high_vulns}
            <span className="text-xs text-slate-400 font-normal font-sans">
              ({summary.critical_vulns} Crit / {summary.high_vulns} High)
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Total active findings: {summary.total_vulns}
          </div>
        </div>

        {/* Active Alerts */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Active Security Alerts</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">{summary.active_alerts}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
            <span>Pending remediation</span>
            <button
              onClick={() => handleNavigateTab('alerts')}
              className="text-primary-400 hover:text-primary-300 font-semibold"
            >
              View Feed &rarr;
            </button>
          </div>
        </div>
      </div>

      {/* Middle Row: Risk Breakdown + Threat Intel RTIs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Flame className="w-4 h-4 text-orange-400" /> Asset Risk Tier Breakdown
          </h3>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-red-400 font-medium">Critical Risk (Score &ge; 80)</span>
                <span className="text-slate-300 font-mono font-bold">{summary.risk_distribution.critical}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-red-500 rounded-full"
                  style={{
                    width: `${summary.total_assets ? (summary.risk_distribution.critical / summary.total_assets) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-amber-400 font-medium">High Risk (Score 40-79)</span>
                <span className="text-slate-300 font-mono font-bold">{summary.risk_distribution.high}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full"
                  style={{
                    width: `${summary.total_assets ? (summary.risk_distribution.high / summary.total_assets) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-yellow-300 font-medium">Medium Risk (Score 15-39)</span>
                <span className="text-slate-300 font-mono font-bold">{summary.risk_distribution.medium}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-yellow-400 rounded-full"
                  style={{
                    width: `${summary.total_assets ? (summary.risk_distribution.medium / summary.total_assets) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-emerald-400 font-medium">Low Risk (Score &lt; 15)</span>
                <span className="text-slate-300 font-mono font-bold">{summary.risk_distribution.low}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full"
                  style={{
                    width: `${summary.total_assets ? (summary.risk_distribution.low / summary.total_assets) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Real-Time Threat Indicators */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400" /> Qualys Real-Time Threat Intel (RTI)
          </h3>
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-red-950/20 border border-red-900/30">
              <div className="text-[11px] text-red-300 font-medium">Ransomware</div>
              <div className="text-xl font-bold text-red-400 font-mono mt-1">
                {summary.threat_intel_summary.ransomware}
              </div>
              <div className="text-[10px] text-slate-400">Weaponized variants</div>
            </div>

            <div className="p-3 rounded-lg bg-orange-950/20 border border-orange-900/30">
              <div className="text-[11px] text-orange-300 font-medium">Exploit in Wild</div>
              <div className="text-xl font-bold text-orange-400 font-mono mt-1">
                {summary.threat_intel_summary.active_exploit}
              </div>
              <div className="text-[10px] text-slate-400">Active exploitation</div>
            </div>

            <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-900/30">
              <div className="text-[11px] text-blue-300 font-medium">Public Exploit</div>
              <div className="text-xl font-bold text-blue-400 font-mono mt-1">
                {summary.threat_intel_summary.public_exploit}
              </div>
              <div className="text-[10px] text-slate-400">PoC / Exploit kit</div>
            </div>

            <div className="p-3 rounded-lg bg-purple-950/20 border border-purple-900/30">
              <div className="text-[11px] text-purple-300 font-medium">Zero-Day</div>
              <div className="text-xl font-bold text-purple-400 font-mono mt-1">
                {summary.threat_intel_summary.zero_day}
              </div>
              <div className="text-[10px] text-slate-400">Unpatched exposure</div>
            </div>
          </div>
        </div>

        {/* OS Family Breakdown */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Server className="w-4 h-4 text-sky-400" /> Operating System Footprint
          </h3>
          <div className="space-y-2.5">
            {summary.top_os_families.map((os) => (
              <div key={os.name} className="flex items-center justify-between text-xs p-2 rounded-lg bg-slate-900/50">
                <span className="font-medium text-slate-300">{os.name}</span>
                <span className="font-mono font-bold text-sky-400 bg-sky-950/40 px-2 py-0.5 rounded border border-sky-800/30">
                  {os.count} {os.count === 1 ? 'host' : 'hosts'}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Flagged Risky Assets Table */}
      <div className="p-5 rounded-xl bg-surface border border-surfaceBorder space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" /> Flagged Risky Assets Requiring Immediate Remediation
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Ranked by composite threat score (Qualys Severity + RTI Exploits + SLA Breaches)
            </p>
          </div>
          <button
            onClick={() => handleNavigateTab('assets')}
            className="text-xs font-semibold text-primary-400 hover:text-primary-300 flex items-center gap-1"
          >
            View All Assets <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto rounded-xl border border-surfaceBorder">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder select-none">
              <tr>
                <th
                  onClick={() => handleSort('ip_address')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Name & Host IP</span>
                    {sortField === 'ip_address' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('os_name')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Operating System</span>
                    {sortField === 'os_name' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('critical_vulns')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Critical / High</span>
                    {sortField === 'critical_vulns' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('risk_score')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Risk Tier & Score</span>
                    {sortField === 'risk_score' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th className="py-3 px-4 text-right font-semibold">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {paginatedAssets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    No flagged risky assets at this time.
                  </td>
                </tr>
              ) : (
                paginatedAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-mono font-bold text-slate-100">{asset.server_name || asset.fqdn || 'No FQDN'}</div>
                      <div className="text-[11px] text-sky-400 font-mono font-medium">{asset.ip_address}</div>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{asset.os_name}</td>
                    <td className="py-3 px-4 font-mono">
                      <span className="text-red-400 font-bold">{asset.critical_vulns} Crit</span> /{' '}
                      <span className="text-amber-400 font-bold">{asset.high_vulns} High</span>
                    </td>
                    <td className="py-3 px-4">
                      <RiskBadge level={asset.risk_level} score={asset.risk_score} />
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleSelectAsset(asset.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 hover:text-sky-300 font-semibold border border-slate-700 transition-colors text-[11px]"
                      >
                        Inspect Findings
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Dashboard Pagination */}
        {riskyAssets.length > 5 && (
          <TablePagination
            currentPage={currentPage}
            totalPages={totalPages}
            totalItems={sortedAssets.length}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={setPageSize}
            pageSizeOptions={[5, 10, 20]}
            label="risky servers"
          />
        )}
      </div>
    </div>
  );
};
