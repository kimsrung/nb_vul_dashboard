import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bell, CheckCircle2, Send, RefreshCw, RotateCw, ShieldAlert,
  Search, Server, Zap, Calendar, Terminal,
  Check, Copy, AlertTriangle, ExternalLink,
  ArrowUpDown, ArrowUp, ArrowDown, X, CheckCircle, Radio
} from 'lucide-react';
import { AlertItem, PaginatedAlertsResponse, apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { TablePagination } from '../components/common/TablePagination';
import { formatDateTimeYMD } from '../utils/date';
import { formatAndSanitizeHtml } from '../utils/sanitize';

interface AlertsPageProps {
  onSelectAsset?: (assetId: number) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ onSelectAsset }) => {
  const navigate = useNavigate();
  const handleSelectAsset = onSelectAsset ?? ((assetId: number) => navigate(`/assets/${assetId}`));
  const { isAdmin, isAnalyst, isOwner } = useAuth();
  const canManage = isAdmin || isAnalyst;

  // Alerts data & pagination
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);
  const [search, setSearch] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Filters & Sorting
  const [statusFilter, setStatusFilter] = useState<string>('active');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [matchTypeFilter, setMatchTypeFilter] = useState<string>('');
  const [sortBy, setSortBy] = useState<string>('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Metrics
  const [critCount, setCritCount] = useState<number>(0);
  const [highCount, setHighCount] = useState<number>(0);
  const [activeCount, setActiveCount] = useState<number>(0);
  const [exposedServersCount, setExposedServersCount] = useState<number>(0);


  // Slide-over detail drawer state
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<AlertItem | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState<boolean>(false);
  const [telegramSending, setTelegramSending] = useState<boolean>(false);
  const [telegramFeedback, setTelegramFeedback] = useState<string | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);

  // Status updating state in table or drawer
  const [updatingAlertId, setUpdatingAlertId] = useState<number | null>(null);

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
      if (matchTypeFilter) params.match_type = matchTypeFilter;
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
      console.error('Failed to load threat alerts', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, pageSize, statusFilter, severityFilter, matchTypeFilter, sortBy, sortOrder]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAlerts();
  };

  const handleSort = (field: string) => {
    if (sortBy === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortOrder(field === 'created_at' || field === 'id' || field === 'severity' || field === 'affected_assets_count' ? 'desc' : 'asc');
    }
    setPage(1);
  };


  const handleOpenDetail = async (alertItem: AlertItem) => {
    setSelectedAlertId(alertItem.id);
    setSelectedDetail(alertItem);
    setTelegramFeedback(null);
    setIsLoadingDetail(true);
    try {
      const res = await apiClient.get<AlertItem>(`/alerts/${alertItem.id}`);
      setSelectedDetail(res.data);
    } catch (err) {
      console.error('Failed to load alert detail', err);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  const handleStatusChange = async (alertId: number, newStatus: string) => {
    setUpdatingAlertId(alertId);
    try {
      const res = await apiClient.patch<AlertItem>(`/alerts/${alertId}/status`, { status: newStatus });
      if (selectedDetail && selectedDetail.id === alertId) {
        setSelectedDetail(res.data);
      }
      fetchAlerts();
    } catch (err) {
      console.error('Failed to update alert status', err);
    } finally {
      setUpdatingAlertId(null);
    }
  };

  const handleDispatchTelegram = async () => {
    if (!selectedDetail) return;
    setTelegramSending(true);
    setTelegramFeedback(null);
    try {
      const res = await apiClient.post(`/alerts/${selectedDetail.id}/telegram`);
      if (res.data?.success) {
        setTelegramFeedback('Alert card successfully dispatched to Telegram channel!');
        setSelectedDetail({ ...selectedDetail, dispatched_telegram: true });
        fetchAlerts();
      } else {
        setTelegramFeedback(res.data?.message || 'Telegram dispatch not sent (check settings).');
      }
    } catch (err: any) {
      setTelegramFeedback(err.response?.data?.detail || 'Telegram dispatch failed');
    } finally {
      setTelegramSending(false);
    }
  };

  const handleCopyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2500);
  };

  return (
    <div className="p-6 max-w-8xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Bell className="w-5 h-5 text-red-400" /> Threat Alert Center
            </h2>
            {isOwner && (
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-sky-950 text-sky-400 border border-sky-800">
                Owner View (Scoped to your servers)
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time advisories from FS-ISAC correlated against your server inventory — displaying both Qualys-confirmed detections and proactive pre-scan software matches.
          </p>
          {isAdmin && (
            <div className="flex items-center gap-2 mt-2 text-xs">
              <span className="text-slate-400">
                Alerts strictly display threats affecting your servers.
              </span>
              <button
                type="button"
                onClick={() => navigate('/misp')}
                className="text-indigo-400 hover:text-indigo-300 font-semibold inline-flex items-center gap-1 cursor-pointer transition-colors"
              >
                <Radio className="w-3.5 h-3.5" />
                View all cataloged advisories in MISP Feed &rarr;
              </button>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 self-start sm:self-center shrink-0 relative flex-nowrap">
          <button
            onClick={() => fetchAlerts()}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            <RotateCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''} shrink-0`} />
            <span className="whitespace-nowrap">Refresh</span>
          </button>
        </div>
      </div>

      {/* KPI Metric Summary Widgets */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4">
        <div className="p-4 rounded-xl bg-surface/60 border border-surfaceBorder">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Active Threat Alerts
            </span>
            <Bell className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-1">{activeCount}</div>
          <span className="text-[10px] text-slate-500 mt-0.5 block">Unresolved CVE advisories</span>
        </div>

        <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/40">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-red-400 uppercase tracking-wider">
              Critical Threats
            </span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-300 mt-1">{critCount}</div>
          <span className="text-[10px] text-red-500/80 mt-0.5 block">Require immediate patching</span>
        </div>

        <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/40">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider">
              High Threats
            </span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-300 mt-1">{highCount}</div>
          <span className="text-[10px] text-amber-500/80 mt-0.5 block">Elevated risk posture</span>
        </div>

        <div className="p-4 rounded-xl bg-sky-950/20 border border-sky-900/40">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-sky-400 uppercase tracking-wider">
              Servers Exposed
            </span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-sky-300 mt-1">{exposedServersCount}</div>
          <span className="text-[10px] text-sky-500/80 mt-0.5 block">Target host inventory affected</span>
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by CVE ID (e.g. CVE-2023-44487), target product, title, or server name..."
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
                className={`px-3 py-1 rounded text-xs font-semibold transition-colors cursor-pointer ${
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
                className={`px-3 py-1 rounded text-xs font-semibold transition-colors cursor-pointer ${
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
                className={`px-3 py-1 rounded text-xs font-semibold transition-colors cursor-pointer ${
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
              <option value="Low">Low</option>
            </select>

            {/* Detection Type Filter */}
            <select
              value={matchTypeFilter}
              onChange={(e) => {
                setMatchTypeFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 cursor-pointer"
            >
              <option value="">All Detection Types</option>
              <option value="QUALYS_CONFIRMED">Qualys Confirmed</option>
              <option value="INVENTORY_PROACTIVE">Proactive Pre-Scan</option>
            </select>

            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition-colors cursor-pointer"
            >
              Filter
            </button>
          </div>
        </form>
      </div>

      {/* Advisory Feed Table */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder overflow-hidden space-y-3">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder select-none">
              <tr>
                {/* Advisory & CVE Column */}
                <th
                  onClick={() => handleSort('cve_id')}
                  className="py-3 px-3 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Advisory & CVE</span>
                    {sortBy === 'cve_id' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-indigo-400" /> : <ArrowDown className="w-3 h-3 text-indigo-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Date Column (includes Detection Type) */}
                <th
                  onClick={() => handleSort('created_at')}
                  className="py-3 px-3 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <Calendar className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Date Detected</span>
                    {sortBy === 'created_at' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-indigo-400" /> : <ArrowDown className="w-3 h-3 text-indigo-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Threat Name & Product */}
                <th
                  onClick={() => handleSort('title')}
                  className="py-3 px-3 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Threat & Product</span>
                    {sortBy === 'title' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-indigo-400" /> : <ArrowDown className="w-3 h-3 text-indigo-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Affected Servers Column */}
                <th
                  onClick={() => handleSort('affected_assets_count')}
                  className="py-3 px-3 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <Server className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Affected Servers</span>
                    {sortBy === 'affected_assets_count' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-indigo-400" /> : <ArrowDown className="w-3 h-3 text-indigo-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Remediation Status */}
                <th
                  onClick={() => handleSort('status')}
                  className="py-3 px-2 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Status</span>
                    {sortBy === 'status' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-indigo-400" /> : <ArrowDown className="w-3 h-3 text-indigo-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Action */}
                <th className="py-3 px-3 text-center font-semibold">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                      Evaluating FS-ISAC threat intelligence against server inventory...
                    </div>
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    {search.trim() ? (
                      <div className="max-w-md mx-auto space-y-2">
                        <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto opacity-80" />
                        <p className="text-sm font-semibold text-slate-200">
                          No active servers are affected by &ldquo;<span className="text-sky-300 font-mono">{search.trim()}</span>&rdquo;
                        </p>
                        <p className="text-xs text-slate-400 leading-relaxed">
                          Your server inventory has 0 exposures for this threat. Newly published CVE advisories that do not match any installed packages on your monitored servers are cataloged in the MISP Feed as clean.
                        </p>
                        {isAdmin && (
                          <div className="pt-2">
                            <button
                              type="button"
                              onClick={() => navigate(`/misp?search=${encodeURIComponent(search.trim())}`)}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 text-xs font-semibold cursor-pointer transition-colors"
                            >
                              <Radio className="w-3.5 h-3.5 text-indigo-400" />
                              Search &ldquo;{search.trim()}&rdquo; in MISP Threat Feed &rarr;
                            </button>
                          </div>
                        )}
                      </div>
                    ) : (
                      <>
                        <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                        <p className="text-sm font-semibold text-slate-200">No matching threat alerts found</p>
                        <p className="text-xs text-slate-500 mt-1">
                          Either no FS-ISAC CVEs match installed software or detections on your servers, or current filters excluded all records.
                        </p>
                        {isAdmin && (
                          <div className="mt-3">
                            <button
                              type="button"
                              onClick={() => navigate('/misp')}
                              className="inline-flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 font-medium cursor-pointer"
                            >
                              <Radio className="w-3 h-3" />
                              Browse all advisories in MISP Threat Feed &rarr;
                            </button>
                          </div>
                        )}
                      </>
                    )}
                  </td>
                </tr>
              ) : (
                alerts.map((al) => {
                  const isCrit = al.severity === 'Critical';
                  const isConfirmed = al.match_type === 'QUALYS_CONFIRMED';
                  const isRemediated = al.status === 'Remediated' || al.status === 'Resolved';

                  return (
                    <tr
                      key={al.id}
                      onClick={() => handleOpenDetail(al)}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                    >
                      {/* Advisory & CVE Column (CVE + Gray MISP ID below + Plain CVSS & Severity) */}
                      <td className="py-3 px-3">
                        <div>
                          <span className="font-mono font-bold text-white text-xs">
                            {al.cve_id}
                          </span>
                          <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                            MISP ID: #{al.misp_event_id || al.id}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                              isCrit
                                ? 'bg-red-950 text-red-400 border border-red-800'
                                : al.severity === 'High'
                                ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                : 'bg-slate-900 text-slate-400 border border-slate-700'
                            }`}
                          >
                            {al.severity}
                          </span>
                          {al.cvss_score && (
                            <span className="text-[9px] font-mono text-slate-400">
                              CVSS {al.cvss_score}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Date Detected (Consistent yyyy-mm-dd HH:mm format + Detection Type Badge) */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="font-mono text-slate-200 text-xs font-semibold">
                          {formatDateTimeYMD(al.date_detected)}
                        </div>
                        <div className="mt-1.5">
                          {isConfirmed ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-950/80 text-blue-300 border border-blue-800 shadow-xs">
                              <ShieldAlert className="w-3 h-3 text-blue-400" /> Qualys Confirmed
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-950/80 text-indigo-300 border border-indigo-800">
                              <Zap className="w-3 h-3 text-indigo-400" /> Pre-Scan Proactive
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Threat Name & Product */}
                      <td className="py-3 px-3 max-w-sm">
                        <div className="font-medium text-slate-200 line-clamp-1">{al.title}</div>
                        <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                          Target: <span className="text-sky-300 font-semibold">{al.affected_product}</span>
                          {al.vulnerable_versions && ` (${al.vulnerable_versions})`}
                        </div>
                      </td>

                      {/* Affected Servers Column (Showing Server Names) */}
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold bg-red-950/60 text-red-400 border border-red-800/60 font-mono">
                            <Server className="w-3 h-3" /> {al.affected_assets_count} server{al.affected_assets_count > 1 ? 's' : ''}
                          </span>

                          {al.dispatched_telegram && (
                            <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-medium bg-sky-950 text-sky-400 border border-sky-800" title="Alert dispatched to Telegram">
                              <Send className="w-2.5 h-2.5" /> Telegram
                            </span>
                          )}
                        </div>

                        {al.affected_assets && al.affected_assets.length > 0 && (
                          <div className="mt-1.5 space-y-0.5">
                            {al.affected_assets.slice(0, 3).map((a) => (
                              <div
                                key={a.asset_id}
                                className="text-[11px] font-medium text-slate-200 truncate max-w-[220px]"
                                title={a.server_name || a.ip_address || 'Server'}
                              >
                                • {a.server_name || a.ip_address}
                              </div>
                            ))}
                            {al.affected_assets.length > 3 && (
                              <div className="text-[10px] text-slate-400 font-mono">
                                +{al.affected_assets.length - 3} more servers
                              </div>
                            )}
                          </div>
                        )}
                      </td>

                      {/* Remediation Status */}
                      <td className="py-3 px-2 whitespace-nowrap">
                        <span
                          className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${
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
                      </td>

                      {/* Action */}
                      <td className="py-3 px-3 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenDetail(al);
                          }}
                          className="px-3 py-1.5 rounded-lg bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 text-xs font-semibold transition-colors cursor-pointer"
                        >
                          Assessment <br/>Report &rarr;
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
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

      {/* Slide-over Drawer for Assessment Report Detail (Previous FS-ISAC Threat Intel Design) */}
      {selectedAlertId && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity animate-in fade-in duration-200">
          <div className="w-full max-w-2xl bg-surface border-l border-surfaceBorder h-full flex flex-col shadow-2xl overflow-hidden animate-in slide-in-from-right duration-200">
            {/* Drawer Header */}
            <div className="p-6 border-b border-surfaceBorder flex items-start justify-between bg-slate-900/60">
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-slate-900 text-slate-400 border border-slate-800">
                    MISP ID: #{selectedDetail?.misp_event_id || selectedDetail?.id}
                  </span>
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
                    {selectedDetail?.cve_id}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${
                      selectedDetail?.severity === 'Critical'
                        ? 'bg-red-950 text-red-400 border border-red-800'
                        : selectedDetail?.severity === 'High'
                        ? 'bg-amber-950 text-amber-400 border border-amber-800'
                        : 'bg-slate-900 text-slate-400 border border-slate-700'
                    }`}
                  >
                    {selectedDetail?.severity}
                  </span>
                  {selectedDetail?.cvss_score && (
                    <span className="text-xs text-slate-400 font-mono">CVSS {selectedDetail.cvss_score}</span>
                  )}
                  <span className="text-[11px] text-slate-500 font-mono">Source: {selectedDetail?.source || 'FS-ISAC'}</span>
                  {selectedDetail?.date_detected && (
                    <span className="text-[11px] text-slate-400 font-mono">
                      Detected: {formatDateTimeYMD(selectedDetail.date_detected)}
                    </span>
                  )}
                </div>
                <h2 className="text-base font-bold text-slate-100 mt-1">{selectedDetail?.title}</h2>
              </div>
              <button
                type="button"
                onClick={() => setSelectedAlertId(null)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-100 transition-colors cursor-pointer shrink-0"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drawer Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs text-slate-300">
              {isLoadingDetail ? (
                <div className="py-24 text-center text-slate-400">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto text-indigo-400 mb-2" />
                  Compiling assessment report...
                </div>
              ) : selectedDetail ? (
                <>
                  {/* Match Banner (Qualys Confirmed in BLUE) */}
                  {selectedDetail.match_type === 'QUALYS_CONFIRMED' ? (
                    <div className="p-4 rounded-xl bg-blue-950/40 border border-blue-800 space-y-1">
                      <div className="flex items-center gap-2 font-bold text-blue-300 text-sm">
                        <ShieldAlert className="w-4 h-4 text-blue-400" /> Qualys Scanner Confirmed Finding
                      </div>
                      <p className="text-blue-200/80 leading-relaxed text-[11px]">
                        Qualys scanner has verified active vulnerability detections for this CVE across your scanned infrastructure with scanner diagnostic proof.
                      </p>
                    </div>
                  ) : (
                    <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-800 space-y-1">
                      <div className="flex items-center gap-2 font-bold text-amber-300 text-sm">
                        <Zap className="w-4 h-4 text-amber-400" /> Pre-Scan Proactive Finding (Inventory Match)
                      </div>
                      <p className="text-amber-200/80 leading-relaxed text-[11px]">
                        Qualys scanner has <b>not</b> detected this vulnerability yet. Our proactive engine identified exposure by comparing installed package versions and OS platform on your servers against FS-ISAC criteria.
                      </p>
                    </div>
                  )}

                  {/* Threat Description */}
                  <div className="space-y-1.5">
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                      Threat Intelligence Analysis
                    </span>
                    <p className="p-3.5 rounded-xl bg-slate-950 border border-surfaceBorder text-slate-300 leading-relaxed font-sans">
                      {selectedDetail.description}
                    </p>
                  </div>

                  {/* Affected Criteria Box */}
                  <div className="grid grid-cols-2 gap-3 p-3.5 rounded-xl bg-slate-950 border border-surfaceBorder font-mono">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Target Product</span>
                      <span className="text-sky-300 font-bold">{selectedDetail.affected_product}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Vulnerable Criteria</span>
                      <span className="text-red-400 font-bold">{selectedDetail.vulnerable_versions || 'All versions'}</span>
                    </div>
                    {selectedDetail.fixed_versions && (
                      <div>
                        <span className="text-[10px] text-slate-500 uppercase block">Fixed Release</span>
                        <span className="text-emerald-400 font-bold">{selectedDetail.fixed_versions}</span>
                      </div>
                    )}
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Confidence Rating</span>
                      <span className="text-indigo-400 font-bold">{selectedDetail.confidence}</span>
                    </div>
                  </div>

                  {/* Affected Servers List */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-indigo-400" /> Affected Servers in Inventory ({selectedDetail.affected_assets_count})
                      </span>
                    </div>

                    {selectedDetail.affected_assets.length === 0 ? (
                      <div className="p-4 rounded-xl bg-slate-950 border border-surfaceBorder text-center text-slate-500 italic">
                        No servers currently affected in inventory.
                      </div>
                    ) : (
                      <div className="space-y-2.5">
                        {selectedDetail.affected_assets.map((srv) => (
                          <div
                            key={srv.asset_id}
                            className="p-3.5 rounded-xl bg-slate-950 border border-surfaceBorder space-y-2 hover:border-slate-700 transition-colors"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-slate-100 font-mono text-xs">
                                  {srv.server_name || srv.ip_address}
                                </span>
                                <span className="text-slate-400 font-mono text-[11px]">
                                  ({srv.ip_address})
                                </span>
                              </div>
                              <button
                                type="button"
                                onClick={() => handleSelectAsset(srv.asset_id)}
                                className="text-sky-400 hover:text-sky-300 text-[11px] font-semibold flex items-center gap-1 cursor-pointer"
                              >
                                Host Dossier <ExternalLink className="w-3 h-3" />
                              </button>
                            </div>

                            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] space-y-1">
                              <div>
                                <span className="text-slate-500">Evidence: </span>
                                <span className="font-mono text-slate-200">{srv.evidence}</span>
                              </div>
                              <div className="flex items-center gap-4 text-[10px] flex-wrap">
                                <span>OS: <span className="text-slate-300">{srv.os_name || 'Unknown OS'}</span></span>
                                <span>Confidence: <span className="text-emerald-400 font-semibold">{srv.confidence}</span></span>
                                {srv.owner_username && (
                                  <span>Owner: <span className="text-sky-300 font-mono font-medium">{srv.owner_username}</span></span>
                                )}
                                {srv.poc_name && (
                                  <span>PoC: <span className="text-emerald-300 font-semibold">{srv.poc_name}</span>{srv.poc_email && <span className="text-slate-400 font-mono"> &lt;{srv.poc_email}&gt;</span>}</span>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Recommended Verification Command */}
                  {selectedDetail.verification_command && (
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-sky-400" /> Recommended Verification Command
                        </span>
                        <button
                          type="button"
                          onClick={() => handleCopyCommand(selectedDetail.verification_command!)}
                          className="flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 font-mono cursor-pointer"
                        >
                          {copiedCmd ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" /> Copied!
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" /> Copy Command
                            </>
                          )}
                        </button>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950 border border-surfaceBorder font-mono text-[11px] text-emerald-400 overflow-x-auto">
                        <code>{selectedDetail.verification_command}</code>
                      </div>
                    </div>
                  )}

                  {/* Suggested Solution & Remediation Guidance */}
                  {selectedDetail.suggested_solution && (
                    <div className="space-y-1.5">
                      <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                        Remediation & Patching Guidance
                      </span>
                      <div
                        className="html-solution p-3.5 rounded-xl bg-slate-950 border border-surfaceBorder text-slate-300 leading-relaxed font-sans"
                        dangerouslySetInnerHTML={{ __html: formatAndSanitizeHtml(selectedDetail.suggested_solution) }}
                      />
                    </div>
                  )}

                  {/* Actions & Status Updates */}
                  <div className="pt-4 border-t border-surfaceBorder space-y-3">
                    <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
                      <div className="flex items-center gap-2 w-full sm:w-auto">
                        <label className="text-[11px] text-slate-400 font-medium">Status:</label>
                        <select
                          value={selectedDetail.status}
                          disabled={!canManage || updatingAlertId === selectedDetail.id}
                          onChange={(e) => handleStatusChange(selectedDetail.id, e.target.value)}
                          className="bg-slate-950 border border-surfaceBorder rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 disabled:opacity-50 cursor-pointer"
                        >
                          <option value="Pending">Pending Review</option>
                          <option value="Acknowledged">Acknowledged / Scheduled</option>
                          <option value="Remediated">Remediated / Verified</option>
                          <option value="False_Positive">False Positive / Exempt</option>
                        </select>
                      </div>

                      <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
                        {canManage && selectedDetail.status !== 'Remediated' && (
                          <button
                            type="button"
                            onClick={() => handleStatusChange(selectedDetail.id, 'Remediated')}
                            disabled={updatingAlertId === selectedDetail.id}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 text-xs font-semibold transition-colors disabled:opacity-50 cursor-pointer"
                          >
                            <CheckCircle className="w-3.5 h-3.5" />
                            <span>Mark Remediated</span>
                          </button>
                        )}

                        {canManage && (
                          <button
                            type="button"
                            onClick={handleDispatchTelegram}
                            disabled={telegramSending}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-950/80 hover:bg-sky-900 text-sky-400 border border-sky-800 text-xs font-semibold transition-colors disabled:opacity-50 cursor-pointer"
                          >
                            <Send className={`w-3.5 h-3.5 ${telegramSending ? 'animate-spin' : ''}`} />
                            <span>{telegramSending ? 'Sending...' : 'Dispatch Telegram'}</span>
                          </button>
                        )}
                      </div>
                    </div>

                    {telegramFeedback && (
                      <div className="p-2.5 rounded-lg bg-sky-950/40 border border-sky-800 text-sky-300 text-xs text-center font-medium animate-in fade-in">
                        {telegramFeedback}
                      </div>
                    )}
                  </div>
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
