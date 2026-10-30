import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Search, RefreshCw, Server, RotateCw, RotateCcw,
  Trash2, AlertTriangle, X, CheckCircle2, AlertCircle, ArrowUp, ArrowDown,
  Calendar, ShieldAlert, Activity, ChevronDown,
  UserCheck, Pencil, Mail, Users, Zap, Database
} from 'lucide-react';
import { AssetListItem, PaginatedAssetsResponse, OwnerOption, apiClient } from '../api/client';
import { SeverityPills } from '../components/common/SeverityPills';
import { useAuth } from '../context/AuthContext';
import { TablePagination } from '../components/common/TablePagination';
import { formatDateTimeYMD } from '../utils/date';
import { EditAssetModal } from '../components/assets/EditAssetModal';

interface AssetsPageProps {
  onSelectAsset?: (assetId: number) => void;
}

export const AssetsPage: React.FC<AssetsPageProps> = ({ onSelectAsset }) => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialSearch = searchParams.get('search') || '';

  const { isOwner, canAssignOwner, isAdmin } = useAuth();
  const [assets, setAssets] = useState<AssetListItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Deletion modal state (Admin Only)
  const [deletingAsset, setDeletingAsset] = useState<AssetListItem | null>(null);
  const [deleteReason, setDeleteReason] = useState<string>('');
  const [isDeleting, setIsDeleting] = useState<boolean>(false);
  const [deleteSuccessMsg, setDeleteSuccessMsg] = useState<string | null>(null);

  // Qualys Sync state (Admin Only)
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncProgress, setSyncProgress] = useState<number | null>(null);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);
  const [isSyncError, setIsSyncError] = useState<boolean>(false);
  const [isSyncMenuOpen, setIsSyncMenuOpen] = useState<boolean>(false);

  // Filters
  const [search, setSearch] = useState<string>(initialSearch);
  const [riskFilter, setRiskFilter] = useState<string>('');
  const [osFilter, setOsFilter] = useState<string>('');
  const [riskyOnly, setRiskyOnly] = useState<boolean>(false);
  const [ownerFilter, setOwnerFilter] = useState<string>('');

  // Sorting
  const [sortBy, setSortBy] = useState<string>('vulns');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const handleSelectAsset = onSelectAsset ?? ((assetId: number) => {
    navigate(`/assets/${assetId}`);
  });

  // Available owners for assignment
  const [availableOwners, setAvailableOwners] = useState<OwnerOption[]>([]);
  const [editingAsset, setEditingAsset] = useState<AssetListItem | null>(null);

  const handleAssetSaved = (updated: AssetListItem) => {
    setAssets((prev) =>
      prev.map((a) => (a.id === updated.id ? { ...a, ...updated } : a))
    );
  };

  const fetchOwners = async () => {
    if (!canAssignOwner) return;
    try {
      const res = await apiClient.get<OwnerOption[]>('/auth/owners');
      setAvailableOwners(res.data);
    } catch (err) {
      console.error('Failed to load available owners', err);
    }
  };

  const fetchAssets = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
      };
      if (search.trim()) params.search = search.trim();
      if (riskFilter) params.risk_level = riskFilter;
      if (osFilter) params.os_family = osFilter;
      if (riskyOnly) params.is_risky = true;
      if (ownerFilter) params.owner_id = ownerFilter;

      const res = await apiClient.get<PaginatedAssetsResponse>('/assets', { params });
      setAssets(res.data.items);
      setTotal(res.data.total);
      setTotalPages(res.data.total_pages);
    } catch (err) {
      console.error('Failed to load assets', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchOwners();
  }, [canAssignOwner]);

  useEffect(() => {
    fetchAssets();
  }, [page, pageSize, riskFilter, osFilter, riskyOnly, ownerFilter, sortBy, sortOrder]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAssets();
  };

  const handleResetFilters = () => {
    setSearch('');
    setRiskFilter('');
    setOsFilter('');
    setRiskyOnly(false);
    setOwnerFilter('');
    setSearchParams((prev) => {
      prev.delete('search');
      return prev;
    });
    setPage(1);
  };

  const handleConfirmDelete = async () => {
    if (!deletingAsset) return;
    setIsDeleting(true);
    try {
      const res = await apiClient.delete(`/assets/${deletingAsset.id}`, {
        data: { reason: deleteReason.trim() || undefined },
      });
      setDeleteSuccessMsg(res.data.message || 'Asset successfully removed from alert system.');
      setDeletingAsset(null);
      setDeleteReason('');
      fetchAssets();
      setTimeout(() => setDeleteSuccessMsg(null), 5000);
    } catch (err: any) {
      console.error('Failed to remove asset', err);
      alert(err.response?.data?.detail || 'Failed to remove asset. Admin permissions required.');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleSyncNow = async (mode: 'delta' | 'full' = 'delta') => {
    setIsSyncMenuOpen(false);
    setIsSyncing(true);
    setSyncProgress(0);
    setIsSyncError(false);
    setSyncFeedback(
      mode === 'full'
        ? 'Initiating complete Qualys inventory reconciliation & KnowledgeBase sync...'
        : 'Initiating fast incremental Qualys delta sync (updated detections since watermark)...'
    );

    try {
      await apiClient.post(`/sync/qualys?mode=${mode}`);

      // Poll sync status until finished or error
      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await apiClient.get<any>('/sync/status?source=qualys');
          const data = statusRes.data;
          if (data.is_running && data.active_job) {
            setSyncProgress(data.active_job.progress_pct);
            setSyncFeedback(data.active_job.message || `Qualys sync in progress (${data.active_job.progress_pct}%)...`);
          } else if (!data.is_running && data.latest_completed_job) {
            clearInterval(pollInterval);
            setIsSyncing(false);
            setSyncProgress(null);
            const isSuccess = data.latest_completed_job.status === 'completed';
            setIsSyncError(!isSuccess);
            setSyncFeedback(data.latest_completed_job.message || (isSuccess ? 'Qualys sync completed successfully.' : 'Qualys sync failed.'));
            if (isSuccess) {
              fetchAssets();
            }
            setTimeout(() => setSyncFeedback(null), 6000);
          }
        } catch {
          // ignore poll error
        }
      }, 1500);

      // Safety timeout after 5 minutes
      setTimeout(() => {
        clearInterval(pollInterval);
        setIsSyncing(false);
        setSyncProgress(null);
      }, 300000);
    } catch (err: any) {
      setIsSyncing(false);
      setSyncProgress(null);
      setIsSyncError(true);
      setSyncFeedback(err.response?.data?.detail || 'Failed to start sync');
      setTimeout(() => setSyncFeedback(null), 6000);
    }
  };

  const isFiltered = Boolean(search || riskFilter || osFilter || riskyOnly || ownerFilter);

  return (
    <div className="p-6 max-w-8xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Server className="w-5 h-5 text-sky-400" /> Asset Inventory & Risk Scoring
            </h2>
            {isOwner && (
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-sky-950 text-sky-400 border border-sky-800">
                Owner View (Scoped to your hosts)
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Qualys scanned assets with automated risk scoring, ownership auditing, and step-by-step Knowledge Based(KB) remediation.
          </p>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-center shrink-0 relative flex-nowrap">
          <button
            onClick={() => {
              fetchAssets();
              fetchOwners();
            }}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            <RotateCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''} shrink-0`} />
            <span className="whitespace-nowrap">Refresh</span>
          </button>
          {isAdmin && (
            <div className="relative inline-flex rounded-lg shadow-md shadow-sky-600/20 shrink-0 flex-nowrap whitespace-nowrap">
              <button
                onClick={() => handleSyncNow('delta')}
                disabled={isSyncing}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-l-lg bg-sky-600 hover:bg-sky-500 text-xs font-bold text-white transition-all disabled:opacity-50 border-r border-sky-700/60 cursor-pointer whitespace-nowrap shrink-0"
                title="Trigger fast incremental Qualys delta sync (updated detections only)"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''} shrink-0`} />
                <span className="whitespace-nowrap">
                  {isSyncing ? (syncProgress !== null ? `Syncing (${syncProgress}%)...` : 'Syncing...') : 'Sync Delta'}
                </span>
              </button>
              <button
                onClick={() => setIsSyncMenuOpen((prev) => !prev)}
                disabled={isSyncing}
                className="px-1.5 py-1.5 rounded-r-lg bg-sky-600 hover:bg-sky-500 text-white transition-all disabled:opacity-50 cursor-pointer shrink-0"
                title="Choose Qualys Sync Mode"
              >
                <ChevronDown className="w-3.5 h-3.5 shrink-0" />
              </button>

              {isSyncMenuOpen && (
                <>
                  {/* Invisible backdrop for outside click dismiss */}
                  <div
                    className="fixed inset-0 z-40"
                    onClick={() => setIsSyncMenuOpen(false)}
                  />
                  <div className="absolute right-0 top-full mt-1.5 w-80 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl py-1.5 z-50 whitespace-normal animate-in fade-in zoom-in-95 duration-150 overflow-hidden">
                    <button
                      onClick={() => handleSyncNow('delta')}
                      className="group w-full text-left px-3.5 py-2.5 hover:bg-slate-800/80 transition-all flex flex-col gap-1 border-b border-slate-800 cursor-pointer whitespace-normal"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-sky-300 flex items-center gap-1.5">
                          <Zap className="w-3.5 h-3.5 text-sky-400 group-hover:scale-110 transition-transform shrink-0" />
                          <span>Smart Delta Sync</span>
                        </span>
                        <span className="text-[10px] font-semibold tracking-wide px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30 shrink-0">
                          Fast
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 pl-5 leading-relaxed whitespace-normal">
                        Fetches only detections updated since last watermark
                      </p>
                    </button>
                    <button
                      onClick={() => handleSyncNow('full')}
                      className="group w-full text-left px-3.5 py-2.5 hover:bg-slate-800/80 transition-all flex flex-col gap-1 cursor-pointer whitespace-normal"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                          <Database className="w-3.5 h-3.5 text-amber-400 group-hover:scale-110 transition-transform shrink-0" />
                          <span>Full Reconciliation Sync</span>
                        </span>
                        <span className="text-[10px] font-semibold tracking-wide px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 shrink-0">
                          Deep
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 pl-5 leading-relaxed whitespace-normal">
                        Paginates all hosts & identifies decommissioned assets
                      </p>
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {syncFeedback && (
        <div
          className={`p-3 rounded-lg border text-xs flex flex-col gap-2 animate-in fade-in duration-200 ${
            isSyncError
              ? 'bg-red-950/60 text-red-300 border-red-800/80'
              : 'bg-sky-950/60 text-sky-300 border-sky-800/80'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {isSyncError ? (
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
              )}
              <span className="font-medium">{syncFeedback}</span>
            </div>
            <button
              onClick={() => setSyncFeedback(null)}
              className="text-slate-400 hover:text-slate-200 p-0.5 rounded"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          {isSyncing && syncProgress !== null && (
            <div className="w-full bg-sky-950/80 rounded-full h-1.5 overflow-hidden border border-sky-800/50">
              <div
                className="bg-sky-400 h-1.5 rounded-full transition-all duration-300"
                style={{ width: `${Math.max(syncProgress, 3)}%` }}
              />
            </div>
          )}
        </div>
      )}

      {deleteSuccessMsg && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800 text-emerald-400 text-xs font-semibold flex items-center gap-2 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{deleteSuccessMsg}</span>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by Server Name, IP, FQDN, OS, or Owner..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-surfaceBorder rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-primary-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={riskFilter}
              onChange={(e) => {
                setRiskFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-primary-500"
            >
              <option value="">All Risk Tiers</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <select
              value={osFilter}
              onChange={(e) => {
                setOsFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-primary-500"
            >
              <option value="">All OS Families</option>
              <option value="Linux">Linux</option>
              <option value="Windows">Windows</option>
              <option value="macOS">macOS</option>
              <option value="Network">Network</option>
            </select>

            {canAssignOwner && availableOwners.length > 0 && (
              <select
                value={ownerFilter}
                onChange={(e) => {
                  setOwnerFilter(e.target.value);
                  setPage(1);
                }}
                className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-primary-500"
              >
                <option value="">All Owners</option>
                {availableOwners
                  .filter((o) => !o.role || o.role === 'owner')
                  .map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.username} {o.full_name ? `(${o.full_name})` : ''}
                    </option>
                  ))}
              </select>
            )}

            <label className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-950 border border-surfaceBorder cursor-pointer text-xs text-slate-300">
              <input
                type="checkbox"
                checked={riskyOnly}
                onChange={(e) => {
                  setRiskyOnly(e.target.checked);
                  setPage(1);
                }}
                className="rounded border-slate-700 text-primary-600 focus:ring-0 bg-slate-900"
              />
              <span>Risky Only</span>
            </label>

            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold"
            >
              Apply Filter
            </button>

            {isFiltered && (
              <button
                type="button"
                onClick={handleResetFilters}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 text-xs font-semibold border border-surfaceBorder transition-colors"
                title="Reset all filters"
              >
                <RotateCcw className="w-3.5 h-3.5 text-slate-400" />
                Reset
              </button>
            )}
          </div>
        </form>
      </div>

      {/* Sorting & Item Count Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-400 py-1">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-300">
            {total} {total === 1 ? 'Asset' : 'Assets'} Found
          </span>
          {isFiltered && (
            <span className="text-[11px] text-sky-400 font-medium">
              (Filtered results)
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] text-slate-400">Sort By:</span>
          <select
            value={sortBy}
            onChange={(e) => {
              setSortBy(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-surfaceBorder rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 cursor-pointer"
          >
            <option value="vulns">Severity 5 (Critical)</option>
            <option value="high_vulns">Severity 4 (High)</option>
            <option value="total_vulns">Total Vulnerabilities</option>
            <option value="server_name">Server Name</option>
            <option value="host_ip">Host IP</option>
            <option value="scanned">Last Scanned Date</option>
          </select>

          <button
            type="button"
            onClick={() => {
              setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
              setPage(1);
            }}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-950 border border-surfaceBorder hover:border-slate-700 text-xs text-slate-200 transition-colors"
            title={sortOrder === 'asc' ? 'Ascending (Click to sort Descending)' : 'Descending (Click to sort Ascending)'}
          >
            {sortOrder === 'asc' ? (
              <>
                <ArrowUp className="w-3.5 h-3.5 text-sky-400" />
                <span>Ascending</span>
              </>
            ) : (
              <>
                <ArrowDown className="w-3.5 h-3.5 text-sky-400" />
                <span>Descending</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Asset Cards Feed */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="p-12 text-center text-slate-400 bg-surface rounded-xl border border-surfaceBorder">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto text-sky-400 mb-2" />
            Loading asset inventory...
          </div>
        ) : assets.length === 0 ? (
          <div className="p-12 text-center text-slate-400 bg-surface rounded-xl border border-surfaceBorder">
            <Server className="w-8 h-8 text-slate-500 mx-auto mb-2 opacity-80" />
            <p className="text-sm font-semibold text-slate-200">No assets found</p>
            <p className="text-xs text-slate-500 mt-1">
              No assets match your current filter and search criteria.
            </p>
          </div>
        ) : (
          assets.map((asset) => {
            const isCrit = (asset.critical_vulns ?? 0) > 0 || asset.risk_level === 'Critical';
            const isHigh = !isCrit && ((asset.high_vulns ?? 0) > 0 || asset.risk_level === 'High');
            const isMed = !isCrit && !isHigh && ((asset.medium_vulns ?? 0) > 0 || asset.risk_level === 'Medium');
            const isLow = !isCrit && !isHigh && !isMed && ((asset.low_vulns ?? 0) > 0);

            return (
              <div
                key={asset.id}
                className={`p-5 sm:p-6 rounded-2xl bg-surface border transition-all space-y-4 shadow-lg ${
                  isCrit
                    ? 'border-red-500/50 hover:border-red-400 ring-1 ring-red-500/20 shadow-red-950/30 asset-card-crit'
                    : isHigh
                    ? 'border-orange-500/50 hover:border-orange-400 ring-1 ring-orange-500/20 shadow-orange-950/30 asset-card-high'
                    : isMed
                    ? 'border-yellow-400/50 hover:border-yellow-300 ring-1 ring-yellow-400/20 shadow-yellow-950/20 asset-card-med'
                    : isLow
                    ? 'border-sky-500/40 hover:border-sky-400 ring-1 ring-sky-500/20 shadow-sky-950/20 asset-card-low'
                    : 'border-surfaceBorder hover:border-slate-700 asset-card-neutral'
                }`}
              >
                {/* Top Row: Server Name, IP/FQDN, Risk Badge, Last Scanned */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-surfaceBorder pb-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <Server className="w-4 h-4 text-sky-400 shrink-0" />
                      <h3 className="text-sm sm:text-base font-bold text-slate-100 font-mono">
                        {asset.server_name || asset.ip_address}
                      </h3>
                    </div>
                    <span className="font-mono text-xs text-sky-300 bg-sky-950/60 border border-sky-500/30 px-2 py-0.5 rounded">
                      {asset.ip_address}
                    </span>
                    {asset.is_risky && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-950 text-red-400 border border-red-800">
                        Flagged Risky
                      </span>
                    )}
                    {!asset.is_active && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-800/80 text-amber-400 border border-amber-800/50">
                        Inactive / Not Reporting
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                      <Calendar className="w-3.5 h-3.5 text-slate-500" />
                      <span>Last Scanned:</span>
                      <span className="text-slate-200 font-semibold">
                        {formatDateTimeYMD(asset.last_scan_date, true, 'N/A')}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Middle Grid: OS & Family, Owner Assignment, Vulnerability Breakdown */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {/* Operating System Box */}
                  <div className="p-3 rounded-xl bg-slate-950/70 border border-surfaceBorder space-y-1">
                    <div className="text-[11px] font-semibold text-slate-400 flex items-center gap-1.5">
                      <Activity className="w-3.5 h-3.5 text-sky-400" /> Operating System
                    </div>
                    <div className="text-xs text-slate-200 font-medium truncate" title={asset.os_name || 'Unknown'}>
                      {asset.os_name || 'Unknown'}
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono">
                      Family: <span className="text-slate-300 font-semibold">{asset.os_family || 'Other'}</span>
                    </div>
                  </div>

                  {/* Host Ownership & Point of Contact (PoC) Box */}
                  <div className="p-3 rounded-xl bg-slate-950/70 border border-surfaceBorder space-y-2 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <div className="text-[11px] font-semibold text-slate-400 flex items-center gap-1.5">
                          <Users className="w-3.5 h-3.5 text-indigo-400" /> Host Ownership & PoC
                        </div>
                        {canAssignOwner && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setEditingAsset(asset);
                            }}
                            className="inline-flex items-center gap-1 text-[11px] font-semibold text-sky-400 hover:text-sky-300 transition-colors cursor-pointer"
                            title="Edit Server Name, Owner Group, and PoC Contact"
                          >
                            <Pencil className="w-3 h-3" />
                            <span>Edit</span>
                          </button>
                        )}
                      </div>

                      {/* Owner Group Badge */}
                      <div className="pt-1 flex items-center gap-1.5 flex-wrap">
                        {asset.owner_username ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-slate-900 text-sky-300 border border-slate-700 font-medium">
                            <Users className="w-3 h-3 text-sky-400" /> {asset.owner_username}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-500 italic">No Group Assigned</span>
                        )}
                      </div>
                    </div>

                    {/* PoC Details */}
                    <div className="pt-1.5 border-t border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mb-0.5">
                        Point of Contact (PoC)
                      </div>
                      {asset.poc_name ? (
                        <div className="text-xs text-slate-200 flex items-center gap-1.5 truncate">
                          <UserCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          <span className="font-semibold text-slate-100 truncate">{asset.poc_name}</span>
                          {asset.poc_email && (
                            <a
                              href={`mailto:${asset.poc_email}`}
                              onClick={(e) => e.stopPropagation()}
                              className="text-[11px] text-sky-400 hover:text-sky-300 hover:underline truncate"
                              title={`Email ${asset.poc_name} (${asset.poc_email})`}
                            >
                              &lt;{asset.poc_email}&gt;
                            </a>
                          )}
                        </div>
                      ) : (
                        <div className="text-xs text-slate-500 italic flex items-center gap-1">
                          <Mail className="w-3 h-3 text-slate-600" />
                          <span>PoC Not Assigned</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Vulnerabilities Breakdown Box */}
                  <div className="p-3 rounded-xl bg-slate-950/70 border border-surfaceBorder space-y-2 flex flex-col justify-between">
                    <div>
                      <div className="text-[11px] font-semibold text-slate-400 flex items-center justify-between mb-2">
                        <span className="flex items-center gap-1.5">
                          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" /> Qualys Severities
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">Total: {asset.total_vulns}</span>
                      </div>

                      {/* Top Critical & High Summary */}
                      <div className="text-xs font-mono flex items-center gap-1.5">
                        <span className="text-red-400 font-bold">{asset.critical_vulns}</span>
                        <span className="text-slate-400 text-[11px]">Critical</span>
                        <span className="text-slate-600 px-0.5">&bull;</span>
                        <span className="text-amber-400 font-bold">{asset.high_vulns}</span>
                        <span className="text-slate-400 text-[11px]">High</span>
                      </div>
                    </div>

                    {/* Compact 5-Severity Breakdown Pills */}
                    <div className="pt-1.5 border-t border-slate-800/80">
                      <SeverityPills
                        sev5={asset.critical_vulns}
                        sev4={asset.high_vulns}
                        sev3={asset.medium_vulns}
                        sev2={asset.low_vulns}
                        sev1={asset.info_vulns}
                        total={asset.total_vulns}
                        showTotal={false}
                        compact
                      />
                    </div>
                  </div>
                </div>

                {/* Footer / Action Row */}
                <div className="flex items-center justify-between pt-2 border-t border-surfaceBorder">
                  <div className="font-mono text-[11px] text-slate-500">
                    Qualys Host ID: <span className="text-slate-400 font-semibold">{asset.qualys_id}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    {isAdmin && (
                      <button
                        type="button"
                        onClick={() => {
                          setDeletingAsset(asset);
                          setDeleteReason('');
                        }}
                        className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-red-950/40 hover:bg-red-900/60 text-red-400 hover:text-red-300 border border-red-800/40 hover:border-red-700 text-xs font-medium transition-colors"
                        title="Remove Asset from Alert System (Admin Only)"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>Remove</span>
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => handleSelectAsset(asset.id)}
                      className="px-3 py-1.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 hover:text-sky-300 border border-sky-500/30 text-xs font-semibold transition-colors cursor-pointer"
                      title="Inspect asset risk dossier"
                    >
                      Details &rarr;
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Server-Side Pagination Bar */}
      <TablePagination
        currentPage={page}
        totalPages={totalPages}
        totalItems={total}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        pageSizeOptions={[10, 25, 50, 100]}
        label="assets"
      />

      {/* Delete Confirmation Modal (Admin Only) */}
      {deletingAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className="bg-surface border border-surfaceBorder rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-surfaceBorder">
              <div className="flex items-center gap-2 text-red-400">
                <AlertTriangle className="w-5 h-5 shrink-0" />
                <h3 className="text-sm font-bold text-slate-100">Remove Asset from Alert System</h3>
              </div>
              <button
                type="button"
                onClick={() => setDeletingAsset(null)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300">
              <p>
                Are you sure you want to permanently remove this asset from monitoring and alert tracking?
              </p>

              <div className="p-3 rounded-xl bg-slate-950 border border-surfaceBorder space-y-1 font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Server Name:</span>
                  <span className="text-sky-300 font-bold">{deletingAsset.server_name || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Host IP:</span>
                  <span className="text-slate-200">{deletingAsset.ip_address}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Qualys Severities:</span>
                  <span className="text-orange-400 font-semibold">{deletingAsset.critical_vulns} Sev 5, {deletingAsset.high_vulns} Sev 4</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Active Vulns:</span>
                  <span className="text-red-400 font-semibold">{deletingAsset.total_vulns} ({deletingAsset.critical_vulns} Crit)</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-red-950/30 border border-red-900/50 text-red-300 text-[11px] leading-relaxed">
                <strong>Administrative Audit Notice:</strong> Removing this asset permanently deletes its active detections, risk calculations, software inventory, and generated alerts. A permanent audit record will be logged with your administrator identity.
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Reason for Decommissioning / Removal (Recorded in Audit Log):
                </label>
                <input
                  type="text"
                  placeholder="e.g., Host decommissioned, IP retired, server rebuilt..."
                  value={deleteReason}
                  onChange={(e) => setDeleteReason(e.target.value)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-surfaceBorder">
              <button
                type="button"
                onClick={() => setDeletingAsset(null)}
                disabled={isDeleting}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                disabled={isDeleting}
                className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-xs font-bold text-white shadow-lg shadow-red-600/20 transition-all flex items-center gap-1.5 disabled:opacity-50"
              >
                {isDeleting ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Removing Asset...
                  </>
                ) : (
                  <>
                    <Trash2 className="w-3.5 h-3.5" />
                    Confirm Removal
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Asset Metadata & PoC Modal */}
      <EditAssetModal
        asset={editingAsset}
        isOpen={!!editingAsset}
        onClose={() => setEditingAsset(null)}
        availableOwners={availableOwners}
        onSaved={handleAssetSaved}
      />
    </div>
  );
};
