import React, { useState, useEffect } from 'react';
import { 
  History, Search, RefreshCw, Trash2, CheckCircle2, Wrench, User, 
  ChevronLeft, ChevronRight, Eye, X, FileText 
} from 'lucide-react';
import { AuditLogItem, PaginatedAuditLogsResponse, apiClient } from '../api/client';

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(15);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Filters
  const [search, setSearch] = useState<string>('');
  const [actionFilter, setActionFilter] = useState<string>('');
  const [targetTypeFilter, setTargetTypeFilter] = useState<string>('');

  // Details Modal
  const [inspectedLog, setInspectedLog] = useState<AuditLogItem | null>(null);

  const fetchLogs = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        page,
        page_size: pageSize,
      };
      if (search.trim()) params.search = search.trim();
      if (actionFilter) params.action = actionFilter;
      if (targetTypeFilter) params.target_type = targetTypeFilter;

      const res = await apiClient.get<PaginatedAuditLogsResponse>('/audit-logs', { params });
      setLogs(res.data.items);
      setTotal(res.data.total);
      setTotalPages(res.data.total_pages);
    } catch (err) {
      console.error('Failed to load audit logs', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, pageSize, actionFilter, targetTypeFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchLogs();
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'DELETE_ASSET':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-950/60 text-red-400 border border-red-800/60">
            <Trash2 className="w-3 h-3" /> DELETE ASSET
          </span>
        );
      case 'RESOLVE_ALERT':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
            <CheckCircle2 className="w-3 h-3" /> RESOLVE ALERT
          </span>
        );
      case 'UPDATE_REMEDIATION':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-950/60 text-amber-400 border border-amber-800/60">
            <Wrench className="w-3 h-3" /> REMEDIATION
          </span>
        );
      case 'ASSIGN_OWNER':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-sky-950/60 text-sky-400 border border-sky-800/60">
            <User className="w-3 h-3" /> ASSIGN OWNER
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-slate-800 text-slate-300 border border-slate-700">
            <FileText className="w-3 h-3" /> {action}
          </span>
        );
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <History className="w-5 h-5 text-sky-400" /> Audit & History Records
            </h2>
            <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
              System Audit Trail
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Immutable administrative logs capturing asset deletions, alert resolutions, owner reassignments, and remediation workflows.
          </p>
        </div>
        <button
          onClick={() => fetchLogs()}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 self-start"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh Log
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by Target, Administrator, Action, or IP..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-surfaceBorder rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-primary-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-primary-500"
            >
              <option value="">All Actions</option>
              <option value="DELETE_ASSET">Delete Asset</option>
              <option value="RESOLVE_ALERT">Resolve Alert</option>
              <option value="UPDATE_REMEDIATION">Update Remediation</option>
              <option value="ASSIGN_OWNER">Assign Owner</option>
            </select>

            <select
              value={targetTypeFilter}
              onChange={(e) => {
                setTargetTypeFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-primary-500"
            >
              <option value="">All Target Types</option>
              <option value="Asset">Asset</option>
              <option value="Alert">Alert</option>
              <option value="Detection">Detection</option>
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

      {/* Logs Table */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder">
              <tr>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target Resource</th>
                <th className="py-3 px-4">Performed By</th>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4 text-right">Snapshot</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400 font-sans">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-primary-400" />
                      Loading audit logs...
                    </div>
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400 font-sans">
                    No audit records found matching the criteria.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition-colors">
                    {/* Timestamp */}
                    <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString()}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 font-sans whitespace-nowrap">
                      {getActionBadge(log.action)}
                    </td>

                    {/* Target Resource */}
                    <td className="py-3 px-4">
                      <div className="text-slate-200 font-semibold truncate max-w-xs" title={log.target_name || ''}>
                        {log.target_name || `Target ID: ${log.target_id}`}
                      </div>
                      <div className="text-[10px] text-slate-500 font-sans">
                        {log.target_type} &bull; ID: {log.target_id}
                      </div>
                    </td>

                    {/* Performed By */}
                    <td className="py-3 px-4 font-sans whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="font-semibold text-sky-400">{log.actor_username}</span>
                        <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-400 uppercase font-mono">
                          {log.actor_role}
                        </span>
                      </div>
                    </td>

                    {/* IP Address */}
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {log.ip_address || '—'}
                    </td>

                    {/* Snapshot inspect button */}
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => setInspectedLog(log)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-sky-400 text-xs font-semibold border border-slate-700 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" /> Details
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="mt-4 pt-4 border-t border-surfaceBorder flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400 font-sans">
          <div className="flex items-center gap-4">
            <span>
              Showing <span className="font-semibold text-slate-200">{total === 0 ? 0 : (page - 1) * pageSize + 1}</span> to{' '}
              <span className="font-semibold text-slate-200">{Math.min(page * pageSize, total)}</span> of{' '}
              <span className="font-semibold text-slate-200">{total}</span> audit records
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
                <option value={15}>15</option>
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

      {/* Details Snapshot Modal */}
      {inspectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className="bg-surface border border-surfaceBorder rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-surfaceBorder">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-sky-400" />
                <h3 className="text-sm font-bold text-slate-100">Audit Record #{inspectedLog.id} Details</h3>
              </div>
              <button
                type="button"
                onClick={() => setInspectedLog(null)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2 p-3 bg-slate-950 rounded-xl border border-surfaceBorder font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px]">Action:</span>
                  <span className="text-slate-200 font-bold">{inspectedLog.action}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Target Type:</span>
                  <span className="text-slate-200 font-bold">{inspectedLog.target_type}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Target Identifier:</span>
                  <span className="text-sky-300 truncate block">{inspectedLog.target_name || inspectedLog.target_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Actor:</span>
                  <span className="text-purple-300 font-bold">{inspectedLog.actor_username} ({inspectedLog.actor_role})</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">IP Address:</span>
                  <span className="text-slate-300">{inspectedLog.ip_address || '—'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Timestamp:</span>
                  <span className="text-slate-300">{new Date(inspectedLog.created_at).toLocaleString()}</span>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Recorded Event Snapshot & Metadata (JSON):
                </label>
                <pre className="p-3 rounded-xl bg-slate-950 border border-surfaceBorder text-slate-200 font-mono text-[11px] overflow-x-auto max-h-60 leading-relaxed">
                  {JSON.stringify(inspectedLog.details, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-surfaceBorder">
              <button
                type="button"
                onClick={() => setInspectedLog(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
