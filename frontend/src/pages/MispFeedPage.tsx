import React, { useState, useEffect } from 'react';
import { 
  Radio, Zap, CheckCircle2, 
  RefreshCw, Search, Send, ExternalLink, X, Copy, Check, 
  Terminal, Server, Shield
} from 'lucide-react';
import { 
  MispAssessmentItem, 
  MispAssessmentDetail, 
  MispSummary, 
  MispSyncResponse, 
  apiClient 
} from '../api/client';
import { useAuth } from '../context/AuthContext';

interface MispFeedPageProps {
  onSelectAsset?: (assetId: number) => void;
}

export const MispFeedPage: React.FC<MispFeedPageProps> = ({ onSelectAsset }) => {
  const { isAnalyst, isAdmin } = useAuth();
  const canManage = isAnalyst || isAdmin;

  const [assessments, setAssessments] = useState<MispAssessmentItem[]>([]);
  const [summary, setSummary] = useState<MispSummary | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<number | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<MispAssessmentDetail | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState<boolean>(false);

  // Filters
  const [matchTypeFilter, setMatchTypeFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [search, setSearch] = useState<string>('');
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);
  const [telegramSending, setTelegramSending] = useState<boolean>(false);
  const [telegramFeedback, setTelegramFeedback] = useState<string | null>(null);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [feedRes, sumRes] = await Promise.all([
        apiClient.get<MispAssessmentItem[]>('/misp/feed', {
          params: {
            match_type: matchTypeFilter || undefined,
            severity: severityFilter || undefined,
            search: search.trim() || undefined,
          },
        }),
        apiClient.get<MispSummary>('/misp/summary'),
      ]);
      setAssessments(feedRes.data);
      setSummary(sumRes.data);
    } catch (err) {
      console.error('Failed to load MISP FS-ISAC data', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [matchTypeFilter, severityFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchData();
  };

  const handleSyncNow = async () => {
    setIsSyncing(true);
    setSyncFeedback('Querying MISP FS-ISAC feed & running proactive assessment...');
    try {
      const res = await apiClient.post<MispSyncResponse>('/misp/sync');
      setSyncFeedback(res.data.message);
      fetchData();
      setTimeout(() => setSyncFeedback(null), 7000);
    } catch (err: any) {
      setSyncFeedback(err.response?.data?.detail || 'Failed to sync MISP feed');
      setTimeout(() => setSyncFeedback(null), 5000);
    } finally {
      setIsSyncing(false);
    }
  };

  const handleOpenDetail = async (id: number) => {
    setSelectedAssessmentId(id);
    setIsLoadingDetail(true);
    setTelegramFeedback(null);
    try {
      const res = await apiClient.get<MispAssessmentDetail>(`/misp/assessments/${id}`);
      setSelectedDetail(res.data);
    } catch (err) {
      console.error('Failed to load assessment report', err);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  const handleCopyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const handleDispatchTelegram = async () => {
    if (!selectedAssessmentId) return;
    setTelegramSending(true);
    setTelegramFeedback(null);
    try {
      const res = await apiClient.post(`/misp/assessments/${selectedAssessmentId}/test-telegram`);
      setTelegramFeedback(res.data.message || 'Telegram alert dispatched successfully');
      // Refresh assessment detail
      handleOpenDetail(selectedAssessmentId);
      fetchData();
    } catch (err: any) {
      setTelegramFeedback(err.response?.data?.detail || 'Failed to dispatch Telegram message');
    } finally {
      setTelegramSending(false);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedAssessmentId || !selectedDetail) return;
    try {
      await apiClient.patch(`/misp/assessments/${selectedAssessmentId}/status`, { status: newStatus });
      setSelectedDetail({ ...selectedDetail, status: newStatus as any });
      fetchData();
    } catch (err) {
      console.error('Failed to update status', err);
    }
  };

  return (
    <div className="p-6 max-w-8xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Radio className="w-5 h-5 text-indigo-400 animate-pulse" /> FS-ISAC Threat Intelligence & Proactive Assessment
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-indigo-950 text-indigo-300 border border-indigo-800">
              MISP Feed • FS-ISAC Only
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Proactively evaluates emergency CVEs against server software inventory before Qualys scanner detection plugins are published.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start">
          <button
            onClick={fetchData}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          {canManage && (
            <button
              onClick={handleSyncNow}
              disabled={isSyncing}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white shadow-md shadow-indigo-600/20 disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 ${isSyncing ? 'animate-bounce' : ''}`} />
              {isSyncing ? 'Evaluating...' : 'Sync FS-ISAC & Assess'}
            </button>
          )}
        </div>
      </div>

      {/* Sync Feedback Alert */}
      {syncFeedback && (
        <div className="p-3 rounded-lg bg-indigo-950/60 border border-indigo-800/80 text-indigo-300 text-xs flex items-center justify-between animate-in fade-in duration-200">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-indigo-400 shrink-0" />
            <span>{syncFeedback}</span>
          </div>
          <button onClick={() => setSyncFeedback(null)} className="text-indigo-400 hover:text-indigo-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* KPI Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total FS-ISAC Advisories */}
        <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>FS-ISAC Advisories</span>
            <Radio className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">
            {summary?.total_advisories ?? 0}
          </div>
          <div className="text-[11px] text-slate-500">Filtered financial sector feed</div>
        </div>

        {/* Card 2: Proactive Pre-Scan Matches */}
        <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/40 space-y-1">
          <div className="flex items-center justify-between text-xs text-amber-300 font-medium">
            <span>⚡ Pre-Scan Proactive Matches</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {summary?.pre_scan_matches ?? 0}
          </div>
          <div className="text-[11px] text-amber-300/70 font-medium">Caught before Qualys detection!</div>
        </div>

        {/* Card 3: Qualys Scanner Confirmed */}
        <div className="p-4 rounded-xl bg-sky-950/20 border border-sky-900/40 space-y-1">
          <div className="flex items-center justify-between text-xs text-sky-300 font-medium">
            <span>🛡️ Scanner Confirmed</span>
            <Shield className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-sky-400">
            {summary?.qualys_confirmed ?? 0}
          </div>
          <div className="text-[11px] text-sky-300/70">Verified active in Qualys scans</div>
        </div>

        {/* Card 4: Affected Infrastructure */}
        <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Exposed Servers</span>
            <Server className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">
            {summary?.at_risk_assets ?? 0}
          </div>
          <div className="text-[11px] text-slate-500">Require patching or verification</div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder flex flex-col md:flex-row items-center justify-between gap-3">
        {/* Match Type Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setMatchTypeFilter('')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              matchTypeFilter === ''
                ? 'bg-indigo-600 text-white'
                : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
            }`}
          >
            All Advisories
          </button>
          <button
            onClick={() => setMatchTypeFilter('INVENTORY_PROACTIVE')}
            className={`flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              matchTypeFilter === 'INVENTORY_PROACTIVE'
                ? 'bg-amber-600 text-white'
                : 'bg-slate-900 text-amber-400 hover:bg-slate-800 border border-amber-900/40'
            }`}
          >
            <Zap className="w-3.5 h-3.5" /> Pre-Scan Proactive
          </button>
          <button
            onClick={() => setMatchTypeFilter('QUALYS_CONFIRMED')}
            className={`flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              matchTypeFilter === 'QUALYS_CONFIRMED'
                ? 'bg-sky-600 text-white'
                : 'bg-slate-900 text-sky-400 hover:bg-slate-800 border border-sky-900/40'
            }`}
          >
            <Shield className="w-3.5 h-3.5" /> Qualys Confirmed
          </button>
          <button
            onClick={() => setMatchTypeFilter('NO_ASSETS_AFFECTED')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              matchTypeFilter === 'NO_ASSETS_AFFECTED'
                ? 'bg-slate-700 text-white'
                : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
            }`}
          >
            Clean / No Assets
          </button>
        </div>

        {/* Search & Severity dropdown */}
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search CVE, product, title..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-surfaceBorder rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
          </select>
        </form>
      </div>

      {/* Advisory Feed Table */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder">
              <tr>
                <th className="py-3 px-4">Advisory & CVE</th>
                <th className="py-3 px-4">Threat Name & Target Product</th>
                <th className="py-3 px-4">Assessment Status</th>
                <th className="py-3 px-4">Affected Servers</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Telegram</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                      Evaluating MISP FS-ISAC intelligence against server inventory...
                    </div>
                  </td>
                </tr>
              ) : assessments.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    No FS-ISAC advisories matching the selected filters.
                  </td>
                </tr>
              ) : (
                assessments.map((a) => {
                  const isCrit = a.severity === 'Critical';
                  const isProactive = a.match_type === 'INVENTORY_PROACTIVE';
                  const isConfirmed = a.match_type === 'QUALYS_CONFIRMED';
                  return (
                    <tr key={a.id} className="hover:bg-slate-800/40 transition-colors">
                      {/* CVE ID & Severity */}
                      <td className="py-3 px-4">
                        <div className="font-mono font-bold text-slate-100 flex items-center gap-1.5">
                          <span>{a.cve_id}</span>
                        </div>
                        <div className="flex items-center gap-1.5 mt-1">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                              isCrit
                                ? 'bg-red-950 text-red-400 border border-red-800'
                                : 'bg-amber-950 text-amber-400 border border-amber-800'
                            }`}
                          >
                            {a.severity}
                          </span>
                          {a.cvss_score && (
                            <span className="text-[10px] text-slate-400 font-mono">CVSS {a.cvss_score}</span>
                          )}
                        </div>
                      </td>

                      {/* Threat Name & Product */}
                      <td className="py-3 px-4 max-w-xs">
                        <div className="font-medium text-slate-200 line-clamp-1">{a.title}</div>
                        <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                          Target: <span className="text-sky-300 font-semibold">{a.affected_product}</span> ({a.vulnerable_versions})
                        </div>
                      </td>

                      {/* Assessment Match Status */}
                      <td className="py-3 px-4">
                        {isProactive ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800 animate-pulse">
                            <Zap className="w-3 h-3 text-amber-400" /> Pre-Scan Proactive
                          </span>
                        ) : isConfirmed ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-sky-950/80 text-sky-300 border border-sky-800">
                            <Shield className="w-3 h-3 text-sky-400" /> Qualys Confirmed
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-medium bg-slate-800 text-slate-400 border border-slate-700">
                            <CheckCircle2 className="w-3 h-3 text-slate-400" /> Clean / No Assets
                          </span>
                        )}
                      </td>

                      {/* Affected Servers Count */}
                      <td className="py-3 px-4 font-mono">
                        {a.affected_assets_count > 0 ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold bg-red-950/60 text-red-400 border border-red-800/60">
                            <Server className="w-3 h-3" /> {a.affected_assets_count} server{a.affected_assets_count > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span className="text-slate-500 font-normal">0 servers</span>
                        )}
                      </td>

                      {/* Confidence */}
                      <td className="py-3 px-4">
                        <span
                          className={`text-[11px] font-semibold ${
                            a.confidence.startsWith('High')
                              ? 'text-emerald-400'
                              : a.confidence === 'Medium'
                              ? 'text-amber-400'
                              : 'text-slate-500'
                          }`}
                        >
                          {a.confidence}
                        </span>
                      </td>

                      {/* Telegram Dispatched */}
                      <td className="py-3 px-4">
                        {a.dispatched_telegram ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-sky-950 text-sky-400 border border-sky-800">
                            <Send className="w-3 h-3" /> Sent
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-500 font-mono">—</span>
                        )}
                      </td>

                      {/* Action */}
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleOpenDetail(a.id)}
                          className="px-3 py-1.5 rounded-lg bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 text-xs font-semibold transition-colors"
                        >
                          Assessment Report &rarr;
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-over Drawer for Assessment Report */}
      {selectedAssessmentId && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity animate-in fade-in duration-200">
          <div className="w-full max-w-2xl bg-surface border-l border-surfaceBorder h-full flex flex-col shadow-2xl overflow-hidden animate-in slide-in-from-right duration-200">
            {/* Drawer Header */}
            <div className="p-6 border-b border-surfaceBorder flex items-start justify-between bg-slate-900/60">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
                    {selectedDetail?.cve_id}
                  </span>
                  <span className="px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-red-950 text-red-400 border border-red-800">
                    {selectedDetail?.severity}
                  </span>
                  {selectedDetail?.cvss_score && (
                    <span className="text-xs text-slate-400 font-mono">CVSS {selectedDetail.cvss_score}</span>
                  )}
                  <span className="text-[11px] text-slate-500 font-mono">Source: FS-ISAC</span>
                </div>
                <h2 className="text-base font-bold text-slate-100">{selectedDetail?.title}</h2>
              </div>
              <button
                onClick={() => setSelectedAssessmentId(null)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-100 transition-colors"
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
                  {/* Match Banner */}
                  {selectedDetail.match_type === 'INVENTORY_PROACTIVE' ? (
                    <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-800 space-y-1">
                      <div className="flex items-center gap-2 font-bold text-amber-300 text-sm">
                        <Zap className="w-4 h-4 text-amber-400" /> Pre-Scan Proactive Finding (Inventory Match)
                      </div>
                      <p className="text-amber-200/80 leading-relaxed text-[11px]">
                        Qualys scanner has <b>not</b> detected this vulnerability yet. Our proactive engine identified exposure by comparing installed package versions on your servers against FS-ISAC criteria.
                      </p>
                    </div>
                  ) : selectedDetail.match_type === 'QUALYS_CONFIRMED' ? (
                    <div className="p-4 rounded-xl bg-sky-950/40 border border-sky-800 space-y-1">
                      <div className="flex items-center gap-2 font-bold text-sky-300 text-sm">
                        <Shield className="w-4 h-4 text-sky-400" /> Qualys Scanner Confirmed Finding
                      </div>
                      <p className="text-sky-200/80 leading-relaxed text-[11px]">
                        Qualys VM has verified active vulnerability detections for this CVE across your scanned infrastructure.
                      </p>
                    </div>
                  ) : (
                    <div className="p-4 rounded-xl bg-slate-900 border border-surfaceBorder space-y-1">
                      <div className="flex items-center gap-2 font-bold text-slate-300 text-sm">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Clean / No Servers Affected
                      </div>
                      <p className="text-slate-400 leading-relaxed text-[11px]">
                        Evaluated against all server inventory. No infrastructure is currently running vulnerable versions of {selectedDetail.affected_product}.
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
                      <span className="text-red-400 font-bold">{selectedDetail.vulnerable_versions}</span>
                    </div>
                  </div>

                  {/* Affected Servers List */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-indigo-400" /> Affected Servers ({selectedDetail.affected_assets_count})
                      </span>
                    </div>

                    {selectedDetail.assessment_report.affected_assets.length === 0 ? (
                      <div className="p-4 rounded-xl bg-slate-950 border border-surfaceBorder text-center text-slate-500 italic">
                        No servers currently affected.
                      </div>
                    ) : (
                      <div className="space-y-2.5">
                        {selectedDetail.assessment_report.affected_assets.map((asset) => (
                          <div
                            key={asset.asset_id}
                            className="p-3.5 rounded-xl bg-slate-950 border border-surfaceBorder space-y-2 hover:border-slate-700 transition-colors"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-slate-100 font-mono text-xs">
                                  {asset.server_name || 'Server'}
                                </span>
                                <span className="text-slate-400 font-mono text-[11px]">
                                  ({asset.ip_address})
                                </span>
                              </div>
                              {onSelectAsset && (
                                <button
                                  onClick={() => onSelectAsset(asset.asset_id)}
                                  className="text-sky-400 hover:text-sky-300 text-[11px] font-semibold flex items-center gap-1"
                                >
                                  Host Dossier <ExternalLink className="w-3 h-3" />
                                </button>
                              )}
                            </div>

                            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] space-y-1">
                              <div>
                                <span className="text-slate-500">Evidence: </span>
                                <span className="font-mono text-slate-200">{asset.evidence}</span>
                              </div>
                              <div className="flex items-center gap-4 text-[10px]">
                                <span>OS: <span className="text-slate-300">{asset.os_name}</span></span>
                                <span>Confidence: <span className="text-emerald-400 font-semibold">{asset.confidence}</span></span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Recommended Verification Command */}
                  {selectedDetail.assessment_report.verification_command && (
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-sky-400" /> Recommended Verification Command
                        </span>
                        <button
                          onClick={() => handleCopyCommand(selectedDetail.assessment_report.verification_command!)}
                          className="flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 font-mono"
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
                        <code>{selectedDetail.assessment_report.verification_command}</code>
                      </div>
                    </div>
                  )}

                  {/* Remediation Guidance */}
                  {selectedDetail.assessment_report.recommended_actions && (
                    <div className="space-y-1.5">
                      <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                        Remediation & Patching Guidance
                      </span>
                      <p className="p-3.5 rounded-xl bg-slate-950 border border-surfaceBorder text-slate-300 leading-relaxed">
                        {selectedDetail.assessment_report.recommended_actions}
                      </p>
                    </div>
                  )}

                  {/* Actions & Telegram Trigger */}
                  <div className="pt-4 border-t border-surfaceBorder space-y-3">
                    <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
                      <div className="flex items-center gap-2 w-full sm:w-auto">
                        <label className="text-[11px] text-slate-400 font-medium">Status:</label>
                        <select
                          value={selectedDetail.status}
                          disabled={!canManage}
                          onChange={(e) => handleStatusChange(e.target.value)}
                          className="bg-slate-950 border border-surfaceBorder rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 disabled:opacity-50"
                        >
                          <option value="Pending">Pending Review</option>
                          <option value="Acknowledged">Acknowledged / Scheduled</option>
                          <option value="Remediated">Remediated / Verified</option>
                          <option value="False_Positive">False Positive / Exempt</option>
                        </select>
                      </div>

                      {canManage && (
                        <button
                          onClick={handleDispatchTelegram}
                          disabled={telegramSending}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-950/80 hover:bg-sky-900 text-sky-400 border border-sky-800 text-xs font-semibold transition-colors disabled:opacity-50 w-full sm:w-auto justify-center"
                        >
                          <Send className={`w-3.5 h-3.5 ${telegramSending ? 'animate-spin' : ''}`} />
                          {telegramSending ? 'Sending...' : 'Dispatch Telegram Alert'}
                        </button>
                      )}
                    </div>

                    {telegramFeedback && (
                      <div className="p-2.5 rounded-lg bg-sky-950/40 border border-sky-800 text-sky-300 text-xs text-center font-medium">
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
