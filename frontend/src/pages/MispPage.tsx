import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Radio,
  RefreshCw,
  RotateCw,
  Search,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Calendar,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  Check,
  X,
  Server,
  AlertCircle
} from 'lucide-react';
import { apiClient, MispAssessmentListItem, MispAssessmentDetail, PaginatedMispFeedResponse } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { formatAndSanitizeHtml } from '../utils/sanitize';
import { TablePagination } from '../components/common/TablePagination';
import { formatDateYMD, formatDateTimeYMD } from '../utils/date';

export const MispPage: React.FC = () => {
  const { isAdmin } = useAuth();
  const [searchParams] = useSearchParams();
  const initialSearch = searchParams.get('search') || '';

  // Data states
  const [items, setItems] = useState<MispAssessmentListItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [totalEvents, setTotalEvents] = useState<number>(240);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(25);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [preScanCount, setPreScanCount] = useState<number>(0);
  const [confirmedCount, setConfirmedCount] = useState<number>(0);
  const [cleanCount, setCleanCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Filters & Sorting (defaults to CVE ID descending)
  const [search, setSearch] = useState<string>(initialSearch);
  const [matchType, setMatchType] = useState<string>('');
  const [severity, setSeverity] = useState<string>('');
  const [sourceFilter, setSourceFilter] = useState<string>('');
  const [sortBy, setSortBy] = useState<string>('cve_id');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const handleSort = (field: string) => {
    if (sortBy === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortOrder(
        field === 'cve_id' || field === 'misp_event_date' || field === 'created_at' || field === 'affected_assets_count' || field === 'severity'
          ? 'desc'
          : 'asc'
      );
    }
    setPage(1);
  };

  // Sync search state if URL search param changes
  useEffect(() => {
    const q = searchParams.get('search');
    if (q !== null && q !== search) {
      setSearch(q);
      setPage(1);
    }
  }, [searchParams]);

  // Sync states
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);
  const [isSyncError, setIsSyncError] = useState<boolean>(false);

  // Drawer Detail
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<number | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<MispAssessmentDetail | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState<boolean>(false);
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);

  // Fetch feed items
  const fetchFeed = useCallback(async () => {
    setIsLoading(true);
    try {
      const params: Record<string, any> = {
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
      };
      if (search.trim()) params.search = search.trim();
      if (matchType) params.match_type = matchType;
      if (severity) params.severity = severity;
      if (sourceFilter) params.source = sourceFilter;

      const res = await apiClient.get<PaginatedMispFeedResponse>('/misp/feed', { params });
      setItems(res.data.items);
      setTotal(res.data.total);
      if (res.data.total_events) {
        setTotalEvents(res.data.total_events);
      }
      setTotalPages(res.data.total_pages);
      setPreScanCount(res.data.pre_scan_count);
      setConfirmedCount(res.data.confirmed_count);
      setCleanCount(res.data.clean_count);
    } catch (err: any) {
      console.error('Failed to fetch MISP feed', err);
    } finally {
      setIsLoading(false);
    }
  }, [page, pageSize, sortBy, sortOrder, search, matchType, severity, sourceFilter]);

  useEffect(() => {
    fetchFeed();
  }, [fetchFeed]);

  // Sync MISP Feed
  const handleSyncMisp = async () => {
    if (isSyncing) return;
    setIsSyncing(true);
    setSyncFeedback('Querying MISP for new CVE advisories & evaluating against server software inventory...');
    setIsSyncError(false);

    try {
      const res = await apiClient.post('/misp/sync');
      setSyncFeedback(res.data.message || 'MISP threat intelligence synchronized successfully.');
      setIsSyncError(false);
      await fetchFeed();
    } catch (err: any) {
      setIsSyncError(true);
      setSyncFeedback(err.response?.data?.detail || 'Failed to synchronize with MISP server.');
    } finally {
      setIsSyncing(false);
      setTimeout(() => {
        setSyncFeedback(null);
      }, 9000);
    }
  };

  // Open Drawer Detail
  const openDetail = async (id: number) => {
    setSelectedAssessmentId(id);
    setIsLoadingDetail(true);
    try {
      const res = await apiClient.get<MispAssessmentDetail>(`/misp/assessments/${id}`);
      setSelectedDetail(res.data);
    } catch (err) {
      console.error('Failed to load assessment details', err);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-[1600px] mx-auto min-h-screen">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-surfaceBorder">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Radio className="w-5 h-5 text-purple-400" />
              MISP Threat Intelligence Feed
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-950 text-purple-400 border border-purple-800">
              Admin Only
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Raw CVE threat advisories ingested from MISP (FS-ISAC / CIRCL) and proactively correlated against your server software inventory.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-center shrink-0">
          <button
            onClick={() => fetchFeed()}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition-colors cursor-pointer shrink-0"
          >
            <RotateCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          {isAdmin && (
            <button
              onClick={handleSyncMisp}
              disabled={isSyncing}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-bold text-white transition-all disabled:opacity-50 shadow-md shadow-purple-600/20 cursor-pointer shrink-0"
              title="Query MISP for new CVE advisories & evaluate against host software"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
              <span>{isSyncing ? 'Syncing...' : 'Sync MISP Feed'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Sync Feedback Banner */}
      {syncFeedback && (
        <div
          className={`p-3 rounded-lg border text-xs flex items-center justify-between animate-in fade-in duration-200 ${
            isSyncError
              ? 'bg-red-950/60 text-red-300 border-red-800/80'
              : 'bg-purple-950/60 text-purple-300 border-purple-800/80'
          }`}
        >
          <div className="flex items-center gap-2">
            {isSyncError ? (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            ) : (
              <Radio className="w-4 h-4 text-purple-400 shrink-0 animate-pulse" />
            )}
            <span>{syncFeedback}</span>
          </div>
          <button onClick={() => setSyncFeedback(null)} className="text-slate-400 hover:text-slate-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* KPI Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
        <div className="p-4 rounded-xl bg-surface/60 border border-surfaceBorder">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
            Evaluated CVE Advisories
          </span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-bold text-slate-100">{total}</span>
            <span className="text-xs text-slate-400 font-medium">unique CVEs</span>
          </div>
          <span className="text-[10px] text-purple-300/80 mt-1 block">
            Consolidated from {totalEvents} FS-ISAC Events
          </span>
        </div>

        <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/40">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider">
              Proactive Pre-Scan Matches
            </span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-300 mt-1">{preScanCount}</div>
          <span className="text-[10px] text-amber-500/80 mt-0.5 block">Matched via AssetSoftware before Qualys</span>
        </div>

        <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/40">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-red-400 uppercase tracking-wider">
              Qualys Confirmed
            </span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-300 mt-1">{confirmedCount}</div>
          <span className="text-[10px] text-red-500/80 mt-0.5 block">Verified by Qualys scanner QID</span>
        </div>

        <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/40">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider">
              Clean / No Exposure
            </span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-300 mt-1">{cleanCount}</div>
          <span className="text-[10px] text-emerald-500/80 mt-0.5 block">0 servers running vulnerable versions</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-surface/60 border border-surfaceBorder space-y-3">
        <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
          {/* Search Box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search by CVE ID, title, product (e.g. OpenSSH, Nginx)..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              className="w-full bg-slate-950 border border-surfaceBorder rounded-lg pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-purple-500"
            />
          </div>

          {/* Quick Filters */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Match Type */}
            <select
              value={matchType}
              onChange={(e) => {
                setMatchType(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-purple-500 cursor-pointer"
            >
              <option value="">All Match Types</option>
              <option value="INVENTORY_PROACTIVE">Proactive Pre-Scan Matches</option>
              <option value="QUALYS_CONFIRMED">Qualys Confirmed</option>
              <option value="NO_ASSETS_AFFECTED">Clean (No Exposure)</option>
            </select>

            {/* Severity */}
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-purple-500 cursor-pointer"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            {/* Source */}
            <select
              value={sourceFilter}
              onChange={(e) => {
                setSourceFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-purple-500 cursor-pointer"
            >
              <option value="">All Sources</option>
              <option value="FS-ISAC">FS-ISAC</option>
              <option value="CIRCL">CIRCL</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main MISP CVE Table */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder overflow-hidden space-y-3 shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 border-collapse">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder select-none">
              <tr>
                {/* CVE ID & Source */}
                <th
                  onClick={() => handleSort('cve_id')}
                  className="py-3 px-4 w-44 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>CVE ID & Source</span>
                    {sortBy === 'cve_id' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-purple-400" /> : <ArrowDown className="w-3 h-3 text-purple-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Advisory Title & Product */}
                <th
                  onClick={() => handleSort('title')}
                  className="py-3 px-4 min-w-[280px] cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Advisory Title & Product</span>
                    {sortBy === 'title' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-purple-400" /> : <ArrowDown className="w-3 h-3 text-purple-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Severity */}
                <th
                  onClick={() => handleSort('severity')}
                  className="py-3 px-4 w-28 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Severity</span>
                    {sortBy === 'severity' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-purple-400" /> : <ArrowDown className="w-3 h-3 text-purple-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Match Classification */}
                <th
                  onClick={() => handleSort('match_type')}
                  className="py-3 px-4 w-44 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Classification</span>
                    {sortBy === 'match_type' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-purple-400" /> : <ArrowDown className="w-3 h-3 text-purple-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Affected Infrastructure */}
                <th
                  onClick={() => handleSort('affected_assets_count')}
                  className="py-3 px-4 w-36 text-center cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <Server className="w-3.5 h-3.5 text-purple-400" />
                    <span>Affected Servers</span>
                    {sortBy === 'affected_assets_count' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-purple-400" /> : <ArrowDown className="w-3 h-3 text-purple-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* MISP Event Date */}
                <th
                  onClick={() => handleSort('misp_event_date')}
                  className="py-3 px-4 w-36 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <Calendar className="w-3.5 h-3.5 text-purple-400" />
                    <span>MISP Date</span>
                    {sortBy === 'misp_event_date' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-purple-400" /> : <ArrowDown className="w-3 h-3 text-purple-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Ingested */}
                <th
                  onClick={() => handleSort('created_at')}
                  className="py-3 px-4 w-36 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <Calendar className="w-3.5 h-3.5 text-purple-400" />
                    <span>Ingested</span>
                    {sortBy === 'created_at' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-purple-400" /> : <ArrowDown className="w-3 h-3 text-purple-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>

                {/* Actions */}
                <th className="py-3 px-4 w-24 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500">
                    <RotateCw className="w-6 h-6 mx-auto animate-spin mb-2 text-purple-400" />
                    Loading MISP threat intelligence advisories...
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500">
                    <Radio className="w-8 h-8 mx-auto text-slate-600 mb-2" />
                    No MISP CVE advisories matched the current filters.
                  </td>
                </tr>
              ) : (
                items.map((adv) => {
                  const isProactive = adv.match_type === 'INVENTORY_PROACTIVE';
                  const isConfirmed = adv.match_type === 'QUALYS_CONFIRMED';

                  return (
                    <tr
                      key={adv.id}
                      className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                      onClick={() => openDetail(adv.id)}
                    >
                      {/* CVE ID & Source */}
                      <td className="py-3.5 px-4">
                        <div className="flex flex-col gap-1 items-start">
                          <span className="font-mono font-bold text-slate-100 group-hover:text-purple-400 transition-colors">
                            {adv.cve_id}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                            {adv.source || 'MISP'}
                          </span>
                        </div>
                      </td>

                      {/* Advisory Title & Product */}
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-200 line-clamp-1">{adv.title}</div>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 font-mono text-[10px] text-purple-300">
                            {adv.affected_product} {adv.vulnerable_versions ? `(${adv.vulnerable_versions})` : ''}
                          </span>
                          {adv.description && adv.description !== adv.title && (
                            <span className="text-[11px] text-slate-500 truncate max-w-xs">
                              {adv.description}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Severity & CVSS */}
                      <td className="py-3.5 px-4">
                        <div className="flex flex-col gap-1 items-start">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                              adv.severity === 'Critical'
                                ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                                : adv.severity === 'High'
                                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                                : 'bg-slate-800 text-slate-400 border border-slate-700'
                            }`}
                          >
                            {adv.severity}
                          </span>
                          {adv.cvss_score && (
                            <span className="text-[10px] font-mono text-slate-400">
                              CVSS: {adv.cvss_score}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Match Classification */}
                      <td className="py-3.5 px-4">
                        {isConfirmed ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-bold bg-red-950/80 text-red-300 border border-red-800">
                            <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                            Qualys Confirmed
                          </span>
                        ) : isProactive ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800">
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                            Proactive Pre-Scan
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800">
                            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            Clean / No Exposure
                          </span>
                        )}
                      </td>

                      {/* Affected Infrastructure Count */}
                      <td className="py-3.5 px-4 text-center">
                        {adv.affected_assets_count > 0 ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-500/10 text-amber-300 border border-amber-500/30">
                            <Server className="w-3.5 h-3.5 text-amber-400" />
                            {adv.affected_assets_count} server{adv.affected_assets_count !== 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span className="text-[11px] font-mono text-slate-500">
                            0 servers
                          </span>
                        )}
                      </td>

                      {/* MISP Event Date */}
                      <td className="py-3.5 px-4 font-mono text-xs whitespace-nowrap">
                        {adv.misp_event_date ? (
                          <span className="text-purple-300 font-semibold">{formatDateYMD(adv.misp_event_date)}</span>
                        ) : adv.misp_event_id ? (
                          <span className="text-slate-400 text-[11px]">Event #{adv.misp_event_id}</span>
                        ) : (
                          <span className="text-slate-500">—</span>
                        )}
                      </td>

                      {/* Date Ingested */}
                      <td className="py-3.5 px-4 text-slate-300 text-xs font-mono whitespace-nowrap">
                        {formatDateTimeYMD(adv.created_at)}
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => openDetail(adv.id)}
                          className="px-3 py-1.5 rounded-lg bg-purple-600/10 hover:bg-purple-600/20 text-purple-400 border border-purple-500/30 text-xs font-semibold transition-colors cursor-pointer"
                        >
                          Details &rarr;
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
          pageSizeOptions={[10, 25, 50, 100]}
          label="threat advisories"
        />
      </div>

      {/* Slide-over Threat Advisory Dossier Drawer */}
      {selectedAssessmentId !== null && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end animate-in fade-in duration-200">
          <div className="w-full max-w-2xl bg-surface border-l border-surfaceBorder h-full flex flex-col shadow-2xl overflow-y-auto">
            {isLoadingDetail ? (
              <div className="p-12 text-center text-slate-500 my-auto">
                <RotateCw className="w-8 h-8 mx-auto animate-spin mb-3 text-purple-400" />
                Loading threat advisory dossier...
              </div>
            ) : selectedDetail ? (
              <div className="p-6 space-y-6">
                {/* Header */}
                <div className="flex items-start justify-between pb-4 border-b border-surfaceBorder">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-base font-bold text-purple-400">
                        {selectedDetail.cve_id}
                      </span>
                      {selectedDetail.misp_event_id && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 text-slate-400 border border-slate-800">
                          MISP Event #{selectedDetail.misp_event_id}
                        </span>
                      )}
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300 border border-slate-700">
                        {selectedDetail.source || 'MISP'}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          selectedDetail.severity === 'Critical'
                            ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                            : selectedDetail.severity === 'High'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                            : 'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}
                      >
                        {selectedDetail.severity}
                      </span>
                      {selectedDetail.cvss_score && (
                        <span className="text-xs text-slate-400 font-mono">
                          CVSS: {selectedDetail.cvss_score}
                        </span>
                      )}
                    </div>
                    <h2 className="text-base font-bold text-slate-100 mt-2">{selectedDetail.title}</h2>
                    <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-400 font-mono flex-wrap">
                      {selectedDetail.misp_event_date && (
                        <span>MISP Published: <span className="text-purple-300 font-semibold">{formatDateYMD(selectedDetail.misp_event_date)}</span></span>
                      )}
                      <span>Ingested: <span className="text-slate-200">{formatDateTimeYMD(selectedDetail.created_at)}</span></span>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setSelectedAssessmentId(null);
                      setSelectedDetail(null);
                    }}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-100 transition-colors"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>

                {/* Match Status Box */}
                <div
                  className={`p-3.5 rounded-xl border ${
                    selectedDetail.match_type === 'QUALYS_CONFIRMED'
                      ? 'bg-red-950/40 border-red-800/80 text-red-300'
                      : selectedDetail.match_type === 'INVENTORY_PROACTIVE'
                      ? 'bg-amber-950/40 border-amber-800/80 text-amber-300'
                      : 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                  }`}
                >
                  <div className="flex items-center gap-2 font-bold text-xs uppercase tracking-wider">
                    {selectedDetail.match_type === 'QUALYS_CONFIRMED' ? (
                      <>
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                        <span>Qualys Scanner Confirmed</span>
                      </>
                    ) : selectedDetail.match_type === 'INVENTORY_PROACTIVE' ? (
                      <>
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        <span>Proactive Pre-Scan Match</span>
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                        <span>Clean / No Infrastructure Exposure</span>
                      </>
                    )}
                  </div>
                  <p className="text-xs mt-1.5 opacity-90 leading-relaxed">
                    {selectedDetail.assessment_report?.summary || selectedDetail.description}
                  </p>
                </div>

                {/* Target Criteria */}
                <div className="p-4 rounded-xl bg-slate-900/60 border border-surfaceBorder space-y-2 text-xs">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                    Target Criteria
                  </span>
                  <div className="grid grid-cols-2 gap-3 text-slate-300">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Product / Package:</span>
                      <span className="font-mono font-bold text-slate-100">{selectedDetail.affected_product}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Vulnerable Range:</span>
                      <span className="font-mono font-bold text-slate-100">{selectedDetail.vulnerable_versions || 'All versions'}</span>
                    </div>
                  </div>
                </div>

                {/* Verification Command */}
                {selectedDetail.assessment_report?.verification_command && (
                  <div className="space-y-1.5">
                    <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                      <span>Verification Shell Command</span>
                    </span>
                    <div className="relative flex items-center bg-slate-950 border border-surfaceBorder rounded-lg p-2.5 font-mono text-xs text-purple-300">
                      <code className="flex-1 overflow-x-auto">
                        {selectedDetail.assessment_report.verification_command}
                      </code>
                      <button
                        onClick={() => copyCommand(selectedDetail.assessment_report.verification_command!)}
                        className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100 transition-colors ml-2"
                        title="Copy Command"
                      >
                        {copiedCmd ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                )}

                {/* Recommended Actions */}
                {selectedDetail.assessment_report?.recommended_actions && (
                  <div className="space-y-1.5">
                    <span className="text-xs font-bold text-slate-300">Remediation Guidance</span>
                    <div
                      className="html-solution p-3 bg-slate-900/60 border border-surfaceBorder rounded-lg text-xs text-slate-300 leading-relaxed"
                      dangerouslySetInnerHTML={{
                        __html: formatAndSanitizeHtml(selectedDetail.assessment_report.recommended_actions),
                      }}
                    />
                  </div>
                )}

                {/* Affected Servers List */}
                <div className="space-y-3 pt-2 border-t border-surfaceBorder">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200">
                      Affected Infrastructure ({selectedDetail.affected_assets_count} Host{selectedDetail.affected_assets_count !== 1 ? 's' : ''})
                    </span>
                  </div>

                  {(!selectedDetail.assessment_report?.affected_assets || selectedDetail.assessment_report.affected_assets.length === 0) ? (
                    <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-900/30 text-xs text-emerald-400 flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 shrink-0" />
                      <span>Zero servers in your inventory are affected by this CVE.</span>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {selectedDetail.assessment_report.affected_assets.map((asset, idx) => (
                        <div
                          key={idx}
                          className="p-3 bg-slate-900/80 border border-surfaceBorder rounded-lg text-xs space-y-1.5"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-slate-100 flex items-center gap-1.5">
                              <Server className="w-3.5 h-3.5 text-purple-400" />
                              {asset.server_name || asset.ip_address}
                            </span>
                            <span className="font-mono text-slate-400 text-[11px]">{asset.ip_address}</span>
                          </div>

                          <div className="text-[11px] text-slate-400 leading-relaxed font-mono bg-slate-950/60 p-2 rounded border border-surfaceBorder/60">
                            {asset.evidence}
                          </div>

                          {(asset.owner_username || asset.poc_name) && (
                            <div className="flex flex-wrap items-center gap-2 text-[10px] text-slate-400 pt-1">
                              {asset.owner_username && (
                                <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                                  Owner: {asset.owner_username}
                                </span>
                              )}
                              {asset.poc_name && (
                                <span className="px-1.5 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700">
                                  PoC: {asset.poc_name} {asset.poc_email ? `<${asset.poc_email}>` : ''}
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
