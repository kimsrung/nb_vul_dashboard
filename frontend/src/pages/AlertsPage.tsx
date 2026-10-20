import React, { useState, useEffect } from 'react';
import { 
  Bell, CheckCircle2, Send, RefreshCw, ShieldAlert, 
  Search, ChevronLeft, ChevronRight 
} from 'lucide-react';
import { AlertItem, PaginatedAlertsResponse, apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';

interface AlertsPageProps {
  onSelectAsset?: (assetId: number) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ onSelectAsset }) => {
  const { isAdmin, isAnalyst, isOwner } = useAuth();
  const canResolve = isAdmin || isAnalyst;

  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);
  const [search, setSearch] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('unresolved');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [resolvingId, setResolvingId] = useState<number | null>(null);

  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        page,
        page_size: pageSize,
      };
      if (statusFilter === 'unresolved') params.is_resolved = false;
      if (statusFilter === 'resolved') params.is_resolved = true;
      if (severityFilter) params.severity = severityFilter;
      if (search.trim()) params.search = search.trim();

      const res = await apiClient.get<PaginatedAlertsResponse>('/alerts', { params });
      setAlerts(res.data.items);
      setTotal(res.data.total);
      setTotalPages(res.data.total_pages);
    } catch (err) {
      console.error('Failed to load alerts', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, pageSize, statusFilter, severityFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAlerts();
  };

  const handleResolveAlert = async (alertId: number) => {
    setResolvingId(alertId);
    try {
      await apiClient.post(`/alerts/${alertId}/resolve`);
      fetchAlerts();
    } catch (err) {
      console.error('Failed to resolve alert', err);
    } finally {
      setResolvingId(null);
    }
  };

  // Helper to ensure alert title follows `<Server Name>: <IP>` format
  const formatCardTitle = (title: string, message: string) => {
    if (title.includes('Risk Flagged:')) {
      const ip = title.split('Risk Flagged:')[1]?.trim();
      const match = message.match(/Asset\s+[\d\.]+\s+\(([^)]+)\)/);
      const serverName = match && match[1] && match[1] !== 'None' ? match[1] : null;
      if (serverName && ip) {
        return `${serverName}: ${ip}`;
      } else if (ip) {
        return ip;
      }
    }
    return title;
  };

  // Helper to shorten card description: e.g. "scored 361.0 with 4 Critical and 4 High vulnerabilities"
  const formatCardMessage = (msg: string) => {
    const idx = msg.indexOf('scored ');
    if (idx !== -1) {
      return msg.substring(idx);
    }
    return msg;
  };

  return (
    <div className="p-6 max-w-8xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Bell className="w-5 h-5 text-red-400" /> Security Alert Center & Notification Dispatch
            </h2>
            {isOwner && (
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-sky-950 text-sky-400 border border-sky-800">
                Owner View (Scoped to your hosts)
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Tracking assets flagged as high-risk, SLA breaches, and automated Telegram alerts.
          </p>
        </div>
        <button
          onClick={() => {
            fetchAlerts();
          }}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 self-start"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh Feed
        </button>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search alerts by title, description, server name, or IP..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-surfaceBorder rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-primary-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-surfaceBorder">
              <button
                type="button"
                onClick={() => {
                  setStatusFilter('unresolved');
                  setPage(1);
                }}
                className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                  statusFilter === 'unresolved'
                    ? 'bg-primary-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Active
              </button>
              <button
                type="button"
                onClick={() => {
                  setStatusFilter('resolved');
                  setPage(1);
                }}
                className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                  statusFilter === 'resolved'
                    ? 'bg-primary-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Resolved
              </button>
              <button
                type="button"
                onClick={() => {
                  setStatusFilter('all');
                  setPage(1);
                }}
                className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                  statusFilter === 'all'
                    ? 'bg-primary-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                All
              </button>
            </div>

            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-primary-500"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
            </select>

            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold"
            >
              Filter
            </button>
          </div>
        </form>
      </div>

      {/* Alerts Feed */}
      <div className="space-y-3">
        {isLoading ? (
          <div className="p-12 text-center text-slate-400 bg-surface rounded-xl border border-surfaceBorder">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto text-primary-400 mb-2" />
            Loading security alerts...
          </div>
        ) : alerts.length === 0 ? (
          <div className="p-12 text-center text-slate-400 bg-surface rounded-xl border border-surfaceBorder">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
            <p className="text-sm font-semibold text-slate-200">No alerts found</p>
            <p className="text-xs text-slate-500 mt-1">No alerts match the selected filters.</p>
          </div>
        ) : (
          alerts.map((al) => {
            const isCrit = al.severity === 'Critical';
            const cardTitle = formatCardTitle(al.title, al.message);
            return (
              <div
                key={al.id}
                className={`p-5 rounded-xl bg-surface border transition-all ${
                  isCrit ? 'border-red-900/30 hover:border-red-800/50' : 'border-surfaceBorder hover:border-slate-700'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${
                          isCrit ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-amber-950 text-amber-400 border border-amber-800'
                        }`}
                      >
                        <ShieldAlert className="w-3 h-3" /> {al.severity}
                      </span>
                      <h3 className="text-sm font-bold text-slate-100 font-mono">{cardTitle}</h3>
                      {al.is_resolved && (
                        <span className="px-2 py-0.5 rounded text-[11px] bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold">
                          Resolved
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed font-mono">{formatCardMessage(al.message)}</p>
                    <div className="flex items-center gap-4 text-[11px] text-slate-500 font-mono pt-1">
                      <span>Triggered: {new Date(al.created_at).toLocaleString()}</span>
                      {al.resolved_at && <span>Resolved: {new Date(al.resolved_at).toLocaleString()}</span>}
                    </div>
                  </div>

                  <div className="flex flex-row sm:flex-col items-end gap-2 shrink-0">
                    {/* Telegram Dispatch Indicator */}
                    {al.dispatched_to_telegram ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-sky-950/60 text-sky-400 border border-sky-800/50">
                        <Send className="w-3 h-3" /> Telegram Dispatched
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
                        In-Dashboard Alert
                      </span>
                    )}

                    <div className="flex items-center gap-2 mt-1">
                      {onSelectAsset && (
                        <button
                          onClick={() => onSelectAsset(al.asset_id)}
                          className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 text-xs font-semibold border border-slate-700 transition-colors"
                        >
                          View Host
                        </button>
                      )}

                      {!al.is_resolved && canResolve && (
                        <button
                          onClick={() => handleResolveAlert(al.id)}
                          disabled={resolvingId === al.id}
                          className="px-3 py-1 rounded bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 text-xs font-semibold border border-emerald-500/30 transition-colors disabled:opacity-50"
                        >
                          {resolvingId === al.id ? 'Resolving...' : 'Mark Resolved'}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Pagination Bar */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
        <div className="flex items-center gap-4">
          <span>
            Showing <span className="font-semibold text-slate-200">{total === 0 ? 0 : (page - 1) * pageSize + 1}</span> to{' '}
            <span className="font-semibold text-slate-200">{Math.min(page * pageSize, total)}</span> of{' '}
            <span className="font-semibold text-slate-200">{total}</span> alerts
          </span>
          <div className="flex items-center gap-1.5">
            <span>Per page:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-primary-500"
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage(1)}
            disabled={page <= 1 || isLoading}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 disabled:opacity-40 border border-surfaceBorder text-slate-300 font-medium transition-colors"
          >
            First
          </button>
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1 || isLoading}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 disabled:opacity-40 border border-surfaceBorder text-slate-300 transition-colors"
            title="Previous Page"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="px-3 py-1 font-mono text-slate-200 font-medium">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages || isLoading}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 disabled:opacity-40 border border-surfaceBorder text-slate-300 transition-colors"
            title="Next Page"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
          <button
            onClick={() => setPage(totalPages)}
            disabled={page >= totalPages || isLoading}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 disabled:opacity-40 border border-surfaceBorder text-slate-300 font-medium transition-colors"
          >
            Last
          </button>
        </div>
      </div>
    </div>
  );
};
