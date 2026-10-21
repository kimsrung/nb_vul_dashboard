import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Bell, CheckCircle2, Send, RefreshCw, ShieldAlert, 
  Search, Server, Zap, Calendar, Terminal, 
  Check, Copy, AlertTriangle, Wrench, CheckCircle
} from 'lucide-react';
import { AlertItem, PaginatedAlertsResponse, apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { TablePagination } from '../components/common/TablePagination';

interface AlertsPageProps {
  onSelectAsset?: (assetId: number) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ onSelectAsset }) => {
  const navigate = useNavigate();
  const handleSelectAsset = onSelectAsset ?? ((assetId: number) => navigate(`/assets/${assetId}`));
  const { isAdmin, isAnalyst, isOwner } = useAuth();
  const canManage = isAdmin || isAnalyst;

  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);
  const [search, setSearch] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('active');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [sortBy, setSortBy] = useState<string>('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Metrics
  const [critCount, setCritCount] = useState<number>(0);
  const [highCount, setHighCount] = useState<number>(0);
  const [activeCount, setActiveCount] = useState<number>(0);
  const [exposedServersCount, setExposedServersCount] = useState<number>(0);

  // Sync state
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);

  // Status updating state
  const [updatingAlertId, setUpdatingAlertId] = useState<number | null>(null);
  const [copiedCmdId, setCopiedCmdId] = useState<number | null>(null);

  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
      };
      if (statusFilter === 'active') params.is_resolved = false;
      if (statusFilter === 'resolved') params.is_resolved = true;
      if (statusFilter !== 'active' && statusFilter !== 'resolved' && statusFilter !== 'all') {
        params.status = statusFilter;
      }
      if (severityFilter) params.severity = severityFilter;
      if (search.trim()) params.search = search.trim();

      const res = await apiClient.get<PaginatedAlertsResponse>('/alerts', { params });
      setAlerts(res.data.items);
      setTotal(res.data.total);
      setTotalPages(res.data.total_pages);
      setCritCount(res.data.critical_count);
      setHighCount(res.data.high_count);
      setActiveCount(res.data.active_count);
      setExposedServersCount(res.data.total_exposed_servers);
    } catch (err) {
      console.error('Failed to load proactive alerts', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, pageSize, statusFilter, severityFilter, sortBy, sortOrder]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAlerts();
  };

  const handleSyncMisp = async () => {
    setIsSyncing(true);
    setSyncFeedback('Querying MISP for new FS-ISAC CVE advisories...');
    try {
      const res = await apiClient.post('/alerts/sync');
      setSyncFeedback(res.data.message || 'Sync completed.');
      fetchAlerts();
      setTimeout(() => setSyncFeedback(null), 6000);
    } catch (err: any) {
      setSyncFeedback(err.response?.data?.detail || 'Failed to sync with MISP');
      setTimeout(() => setSyncFeedback(null), 6000);
    } finally {
      setIsSyncing(false);
    }
  };

  const handleStatusChange = async (alertId: number, newStatus: string) => {
    setUpdatingAlertId(alertId);
    try {
      await apiClient.patch(`/alerts/${alertId}/status`, { status: newStatus });
      fetchAlerts();
    } catch (err) {
      console.error('Failed to update alert status', err);
    } finally {
      setUpdatingAlertId(null);
    }
  };

  const handleCopyCommand = (alertId: number, cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmdId(alertId);
    setTimeout(() => setCopiedCmdId(null), 2500);
  };

  return (
    <div className="p-6 max-w-8xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Bell className="w-5 h-5 text-red-400" /> Alert Center — Proactive FS-ISAC CVE Advisories
            </h2>
            {isOwner && (
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-sky-950 text-sky-400 border border-sky-800">
                Owner View (Scoped to your servers)
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Proactively alerts when newly published FS-ISAC emergency CVEs affect installed software on your servers before Qualys detects them.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start">
          {canManage && (
            <button
              onClick={handleSyncMisp}
              disabled={isSyncing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white transition-colors disabled:opacity-50 shadow-xs"
              title="Poll MISP for newly published FS-ISAC CVE advisories"
            >
              <Zap className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
              <span>{isSyncing ? 'Syncing...' : 'Sync FS-ISAC & Assess'}</span>
            </button>
          )}

          <button
            onClick={() => fetchAlerts()}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Sync Feedback Banner */}
      {syncFeedback && (
        <div className="p-3 rounded-lg bg-indigo-950/60 border border-indigo-800 text-xs text-indigo-300 flex items-center gap-2 animate-in fade-in">
          <Zap className="w-4 h-4 text-indigo-400 shrink-0" />
          <span>{syncFeedback}</span>
        </div>
      )}

      {/* KPI Metric Summary Widgets */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-1">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Bell className="w-3.5 h-3.5 text-red-400" /> Active Threat Alerts
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{activeCount}</div>
          <p className="text-[10px] text-slate-500">Unresolved proactive CVEs</p>
        </div>

        <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-1">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-red-500" /> Critical Threats
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">{critCount}</div>
          <p className="text-[10px] text-slate-500">Require immediate patching</p>
        </div>

        <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-1">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500" /> High Threats
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{highCount}</div>
          <p className="text-[10px] text-slate-500">Elevated risk posture</p>
        </div>

        <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-1">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-sky-400" /> Servers Exposed
          </div>
          <div className="text-2xl font-bold font-mono text-sky-400">{exposedServersCount}</div>
          <p className="text-[10px] text-slate-500">Target host inventory affected</p>
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by CVE ID (e.g. CVE-2024-6387), target product, title, or server name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-surfaceBorder rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Status Tabs */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-surfaceBorder text-xs select-none">
              <button
                type="button"
                onClick={() => {
                  setStatusFilter('active');
                  setPage(1);
                }}
                className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                  statusFilter === 'active'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Active ({activeCount})
              </button>
              <button
                type="button"
                onClick={() => {
                  setStatusFilter('resolved');
                  setPage(1);
                }}
                className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                  statusFilter === 'resolved'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Remediated
              </button>
              <button
                type="button"
                onClick={() => {
                  setStatusFilter('all');
                  setPage(1);
                }}
                className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                  statusFilter === 'all'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                All
              </button>
            </div>

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 cursor-pointer"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
            </select>

            {/* Sort Filter */}
            <select
              value={`${sortBy}:${sortOrder}`}
              onChange={(e) => {
                const [f, o] = e.target.value.split(':');
                setSortBy(f);
                setSortOrder(o as 'asc' | 'desc');
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 cursor-pointer"
            >
              <option value="created_at:desc">Date Detected (Newest)</option>
              <option value="created_at:asc">Date Detected (Oldest)</option>
              <option value="severity:desc">Criticality (Highest)</option>
              <option value="affected_assets_count:desc">Servers Exposed (Most)</option>
              <option value="cve_id:asc">CVE ID (A-Z)</option>
            </select>

            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition-colors"
            >
              Filter
            </button>
          </div>
        </form>
      </div>

      {/* Alerts Feed */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="p-12 text-center text-slate-400 bg-surface rounded-xl border border-surfaceBorder">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto text-indigo-400 mb-2" />
            Evaluating proactive FS-ISAC threat alerts against server inventory...
          </div>
        ) : alerts.length === 0 ? (
          <div className="p-12 text-center text-slate-400 bg-surface rounded-xl border border-surfaceBorder">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
            <p className="text-sm font-semibold text-slate-200">No active proactive alerts found</p>
            <p className="text-xs text-slate-500 mt-1">
              Either no new FS-ISAC CVEs match installed software on your servers, or all existing findings are already scanned by Qualys.
            </p>
          </div>
        ) : (
          alerts.map((al) => {
            const isCrit = al.severity === 'Critical';
            const isRemediated = al.status === 'Remediated' || al.status === 'Resolved';

            return (
              <div
                key={al.id}
                className={`p-6 rounded-2xl bg-surface border transition-all space-y-4 shadow-lg ${
                  isRemediated
                    ? 'border-surfaceBorder opacity-75'
                    : isCrit
                    ? 'border-red-900/40 hover:border-red-800/60 ring-1 ring-red-950'
                    : 'border-amber-900/40 hover:border-amber-800/60 ring-1 ring-amber-950'
                }`}
              >
                {/* Top Row: Date Detected, Criticality, Status, Telegram */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-surfaceBorder pb-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Criticality Badge */}
                    <span
                      className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider ${
                        isCrit
                          ? 'bg-red-950 text-red-400 border border-red-800'
                          : 'bg-amber-950 text-amber-400 border border-amber-800'
                      }`}
                    >
                      <ShieldAlert className="w-3.5 h-3.5" /> {al.severity}
                      {al.cvss_score && <span className="font-mono text-[10px] ml-1">CVSS {al.cvss_score}</span>}
                    </span>

                    {/* Proactive Pre-scan indicator */}
                    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-indigo-950/80 text-indigo-300 border border-indigo-800">
                      <Zap className="w-3 h-3 text-indigo-400" /> Proactive Pre-Scan Alert
                    </span>

                    {/* Status Badge */}
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${
                        isRemediated
                          ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                          : al.status === 'Acknowledged'
                          ? 'bg-sky-950 text-sky-400 border-sky-800'
                          : al.status === 'False_Positive'
                          ? 'bg-slate-900 text-slate-400 border-slate-700'
                          : 'bg-amber-950 text-amber-300 border-amber-800'
                      }`}
                    >
                      {al.status}
                    </span>

                    {al.dispatched_telegram && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-sky-950 text-sky-400 border border-sky-800">
                        <Send className="w-3 h-3" /> Telegram Dispatched
                      </span>
                    )}
                  </div>

                  {/* Date Detected */}
                  <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                    <Calendar className="w-3.5 h-3.5 text-slate-500" />
                    <span>Date Detected:</span>
                    <span className="text-slate-200 font-semibold">
                      {new Date(al.date_detected).toLocaleDateString(undefined, {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                      })}{' '}
                      {new Date(al.date_detected).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>

                {/* Threat Title & Target Criteria */}
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      type="button"
                      onClick={() => navigate(`/assets?search=${encodeURIComponent(al.cve_id)}`)}
                      className="font-mono text-sm font-bold text-sky-400 bg-sky-950/60 hover:bg-sky-900/60 border border-sky-800/70 px-2.5 py-0.5 rounded-lg transition-all flex items-center gap-1.5 group cursor-pointer shadow-xs"
                      title={`Find assets affected by ${al.cve_id} in Inventory`}
                    >
                      <span>{al.cve_id}</span>
                      <span className="text-[11px] text-sky-300 font-sans font-medium group-hover:underline">
                        Find in Inventory &rarr;
                      </span>
                    </button>
                    <h3 className="text-sm font-bold text-slate-100">{al.title}</h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{al.description}</p>
                  <div className="mt-2 text-xs font-mono text-slate-300 bg-slate-950/70 p-2 rounded-lg border border-surfaceBorder flex items-center gap-3">
                    <div>
                      Target Product: <span className="text-indigo-400 font-bold">{al.affected_product}</span>
                    </div>
                    <div className="text-slate-600">|</div>
                    <div>
                      Vulnerable Versions: <span className="text-amber-400 font-bold">{al.vulnerable_versions}</span>
                    </div>
                  </div>
                </div>

                {/* Affected Servers List */}
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-sky-400" />
                    <span>Affected Servers in Inventory ({al.affected_assets.length}):</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {al.affected_assets.map((srv) => (
                      <div
                        key={srv.asset_id}
                        className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                      >
                        <div className="space-y-0.5 min-w-0">
                          <div className="font-semibold text-slate-200 flex items-center gap-1.5 truncate">
                            <span className="truncate">{srv.server_name || srv.ip_address}</span>
                            <span className="text-[10px] text-slate-500 font-mono">({srv.ip_address})</span>
                          </div>
                          <div className="text-[11px] text-slate-400 font-mono truncate" title={srv.evidence}>
                            {srv.evidence}
                          </div>
                        </div>

                        <button
                          type="button"
                          onClick={() => handleSelectAsset(srv.asset_id)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 hover:text-sky-300 font-medium text-[11px] border border-slate-700 shrink-0 transition-colors"
                        >
                          Inspect Host &rarr;
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Suggested Solution & Remediation Guidance */}
                <div className="p-3.5 rounded-xl bg-indigo-950/30 border border-indigo-900/60 space-y-1.5">
                  <div className="text-xs font-bold text-indigo-300 flex items-center gap-1.5">
                    <Wrench className="w-4 h-4 text-indigo-400" /> Suggested Solution & Remediation Guidance:
                  </div>
                  <p className="text-xs text-slate-200 leading-relaxed font-sans">{al.suggested_solution}</p>
                </div>

                {/* Verification Command Snippet (if available) */}
                {al.verification_command && (
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-surfaceBorder flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 font-mono text-xs text-emerald-400 overflow-x-auto">
                      <Terminal className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                      <span className="truncate">{al.verification_command}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopyCommand(al.id, al.verification_command!)}
                      className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 shrink-0 transition-colors"
                      title="Copy verification command"
                    >
                      {copiedCmdId === al.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                )}

                {/* Status Action Toolbar */}
                {canManage && (
                  <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-surfaceBorder text-xs">
                    <div className="text-slate-400 flex items-center gap-2">
                      <span>Update Alert Status:</span>
                      <select
                        value={al.status}
                        onChange={(e) => handleStatusChange(al.id, e.target.value)}
                        disabled={updatingAlertId === al.id}
                        className="bg-slate-950 border border-surfaceBorder rounded px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 cursor-pointer"
                      >
                        <option value="Pending">Pending (Under Review)</option>
                        <option value="Acknowledged">Acknowledged (In Progress)</option>
                        <option value="Remediated">Remediated (Resolved)</option>
                        <option value="False_Positive">False Positive</option>
                      </select>
                    </div>

                    <div className="flex items-center gap-2">
                      {al.status !== 'Remediated' && (
                        <button
                          type="button"
                          onClick={() => handleStatusChange(al.id, 'Remediated')}
                          disabled={updatingAlertId === al.id}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 text-xs font-semibold transition-colors disabled:opacity-50"
                        >
                          <CheckCircle className="w-3.5 h-3.5" />
                          <span>Mark Remediated</span>
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Pagination Bar */}
      <TablePagination
        currentPage={page}
        totalPages={totalPages}
        totalItems={total}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        pageSizeOptions={[5, 10, 20]}
        label="threat alerts"
      />
    </div>
  );
};
