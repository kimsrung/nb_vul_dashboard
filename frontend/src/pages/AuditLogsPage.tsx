import React, { useState, useEffect } from 'react';
import {
  History, Search, RefreshCw, Trash2, CheckCircle2, Wrench, User,
  X, FileText, ArrowUpDown, ArrowUp, ArrowDown, Radio, Zap,
  RotateCw, UserPlus, AlertTriangle, Sliders, ChevronDown, ChevronRight
} from 'lucide-react';
import { AuditLogItem, PaginatedAuditLogsResponse, apiClient } from '../api/client';
import { TablePagination } from '../components/common/TablePagination';
import { formatDateTimeYMD } from '../utils/date';

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
  const [showRawJson, setShowRawJson] = useState<boolean>(false);

  // Sorting
  const [sortBy, setSortBy] = useState<string>('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const handleSort = (field: string) => {
    if (sortBy === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortOrder(field === 'created_at' ? 'desc' : 'asc');
    }
    setPage(1);
  };

  const fetchLogs = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
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
  }, [page, pageSize, actionFilter, targetTypeFilter, sortBy, sortOrder]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchLogs();
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'UPDATE_SETTINGS':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-950/60 text-amber-400 border border-amber-800/60">
            <Sliders className="w-3 h-3" /> UPDATE SETTINGS
          </span>
        );
      case 'UPDATE_USER':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-sky-950/60 text-sky-400 border border-sky-800/60">
            <User className="w-3 h-3" /> UPDATE USER
          </span>
        );
      case 'CREATE_USER':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
            <UserPlus className="w-3 h-3" /> CREATE USER
          </span>
        );
      case 'DELETE_USER':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-950/60 text-rose-400 border border-rose-800/60">
            <Trash2 className="w-3 h-3" /> DELETE USER
          </span>
        );
      case 'MISP_DELTA_SYNC':
      case 'MISP_FULL_SYNC':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-950/60 text-purple-400 border border-purple-800/60">
            <Radio className="w-3 h-3" /> {action === 'MISP_FULL_SYNC' ? 'MISP FULL SYNC' : 'MISP DELTA SYNC'}
          </span>
        );
      case 'MISP_SYNC_FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-950/60 text-rose-400 border border-rose-800/60">
            <AlertTriangle className="w-3 h-3" /> MISP SYNC FAILED
          </span>
        );
      case 'QUALYS_DELTA_SYNC':
      case 'QUALYS_FULL_SYNC':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-cyan-950/60 text-cyan-400 border border-cyan-800/60">
            <RefreshCw className="w-3 h-3" /> {action === 'QUALYS_FULL_SYNC' ? 'QUALYS FULL SYNC' : 'QUALYS DELTA SYNC'}
          </span>
        );
      case 'QUALYS_SYNC_FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-950/60 text-rose-400 border border-rose-800/60">
            <AlertTriangle className="w-3 h-3" /> QUALYS SYNC FAILED
          </span>
        );
      case 'MISP_EVENT_TRIGGERED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-950/60 text-purple-400 border border-purple-800/60">
            <Radio className="w-3 h-3" /> MISP EVENT TRIGGERED
          </span>
        );
      case 'MISP_ZMQ_FEED_RECEIVED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-indigo-950/60 text-indigo-400 border border-indigo-800/60">
            <Zap className="w-3 h-3" /> MISP ZMQ FEED
          </span>
        );
      case 'MISP_FEED_PUSH_RECEIVED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-indigo-950/60 text-indigo-400 border border-indigo-800/60">
            <Zap className="w-3 h-3" /> MISP PUSH
          </span>
        );
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
    <div className="p-6 max-w-8xl mx-auto space-y-6">
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
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 self-start sm:self-center shrink-0 whitespace-nowrap cursor-pointer"
        >
          <RotateCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''} shrink-0`} />
          <span className="whitespace-nowrap">Refresh Log</span>
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
              <optgroup label="System & Configuration">
                <option value="UPDATE_SETTINGS">Update Settings</option>
              </optgroup>
              <optgroup label="User Administration">
                <option value="UPDATE_USER">Update User</option>
                <option value="CREATE_USER">Create User</option>
                <option value="DELETE_USER">Delete User</option>
              </optgroup>
              <optgroup label="Threat Intelligence (MISP)">
                <option value="MISP_DELTA_SYNC">MISP Delta Sync</option>
                <option value="MISP_FULL_SYNC">MISP Full Sync</option>
                <option value="MISP_SYNC_FAILED">MISP Sync Failed</option>
                <option value="MISP_EVENT_TRIGGERED">MISP Event Triggered</option>
                <option value="MISP_ZMQ_FEED_RECEIVED">MISP ZMQ Feed</option>
                <option value="MISP_FEED_PUSH_RECEIVED">MISP Push</option>
              </optgroup>
              <optgroup label="Vulnerability Sync (Qualys)">
                <option value="QUALYS_DELTA_SYNC">Qualys Delta Sync</option>
                <option value="QUALYS_FULL_SYNC">Qualys Full Sync</option>
                <option value="QUALYS_SYNC_FAILED">Qualys Sync Failed</option>
              </optgroup>
              <optgroup label="Asset & Alerts Operations">
                <option value="ASSIGN_OWNER">Assign Owner</option>
                <option value="DELETE_ASSET">Delete Asset</option>
                <option value="RESOLVE_ALERT">Resolve Alert</option>
                <option value="UPDATE_REMEDIATION">Update Remediation</option>
              </optgroup>
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
              <option value="Settings">Settings</option>
              <option value="User">User</option>
              <option value="SYNC">Sync Operation</option>
              <option value="MISP_Advisory">MISP Advisory</option>
              <option value="MISP_Feed">MISP Feed</option>
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
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder overflow-hidden space-y-3">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder select-none">
              <tr>
                <th
                  onClick={() => handleSort('created_at')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Timestamp</span>
                    {sortBy === 'created_at' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('action')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Action</span>
                    {sortBy === 'action' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('target_name')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Target Resource</span>
                    {sortBy === 'target_name' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('actor_username')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Performed By</span>
                    {sortBy === 'actor_username' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('ip_address')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>IP Address</span>
                    {sortBy === 'ip_address' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th className="py-3 px-4 text-right font-semibold">Snapshot</th>
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
                    {/* Timestamp (Full datetime yyyy-mm-dd hh:mm:ss) */}
                    <td className="py-3 px-4 text-slate-300 whitespace-nowrap font-mono">
                      {formatDateTimeYMD(log.created_at, true)}
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
                    <td className="py-3 px-4 text-slate-400">
                      {log.ip_address || '—'}
                    </td>

                    {/* Snapshot inspect button */}
                    <td className="py-3 px-4 text-right font-sans whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => {
                          setInspectedLog(log);
                          setShowRawJson(false);
                        }}
                        className="px-3 py-1.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 text-xs font-semibold transition-colors cursor-pointer"
                        title="View audit event details"
                      >
                        Details &rarr;
                      </button>
                    </td>
                  </tr>
                ))
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
          pageSizeOptions={[15, 25, 50, 100]}
          label="audit records"
        />
      </div>

      {/* Details Snapshot Modal */}
      {inspectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className="bg-surface border border-surfaceBorder rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-150">
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
                  <span className="text-slate-300 font-mono text-[11px]">{formatDateTimeYMD(inspectedLog.created_at, true)}</span>
                </div>
              </div>

              {/* Setting Parameter Changes Comparison Table */}
              {inspectedLog.details?.changes && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-sky-400 flex items-center gap-1.5">
                      <Sliders className="w-3.5 h-3.5 text-sky-400" />
                      Settings Parameter Changes
                    </span>
                    <span className="text-[10px] text-slate-400">
                      {Object.keys(inspectedLog.details.changes).length} {Object.keys(inspectedLog.details.changes).length === 1 ? 'parameter' : 'parameters'} modified
                    </span>
                  </div>
                  <div className="border border-surfaceBorder rounded-xl overflow-hidden bg-slate-950">
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="bg-slate-900 border-b border-surfaceBorder text-[10px] uppercase tracking-wider text-slate-400 font-semibold">
                            <th className="py-2.5 px-3.5">Setting / Parameter</th>
                            <th className="py-2.5 px-3.5">Previous Value</th>
                            <th className="py-2.5 px-3.5">New Value</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-surfaceBorder">
                          {Object.entries(inspectedLog.details.changes).map(([field, diff]: [string, any]) => {
                            const isDiffObj = typeof diff === 'object' && diff !== null && 'old' in diff && 'new' in diff;
                            const oldVal = isDiffObj ? String(diff.old ?? '—') : '—';
                            const newVal = isDiffObj ? String(diff.new ?? '—') : String(diff ?? '—');
                            return (
                              <tr key={field} className="hover:bg-slate-900/50 font-mono">
                                <td className="py-2 px-3.5 text-slate-300 font-semibold text-[11px]">
                                  <span className="px-2 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700/60 inline-block">
                                    {field}
                                  </span>
                                </td>
                                <td className="py-2 px-3.5 text-[11px]">
                                  <span className="inline-block px-2.5 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/25 line-through">
                                    {oldVal}
                                  </span>
                                </td>
                                <td className="py-2 px-3.5 text-[11px]">
                                  <span className="inline-block px-2.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/25 font-semibold">
                                    {newVal}
                                  </span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* Status Transition (Alerts / Tasks) */}
              {inspectedLog.details?.old_status && inspectedLog.details?.new_status && (
                <div className="p-3 rounded-xl bg-slate-950 border border-surfaceBorder flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300">Status Transition:</span>
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="px-2.5 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20 line-through">
                      {inspectedLog.details.old_status}
                    </span>
                    <span className="text-slate-500">&rarr;</span>
                    <span className="px-2.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 font-semibold">
                      {inspectedLog.details.new_status}
                    </span>
                  </div>
                </div>
              )}

              {/* Collapsible Raw Snapshot / JSON */}
              <div className="pt-1">
                <button
                  type="button"
                  onClick={() => setShowRawJson(!showRawJson)}
                  className="flex items-center justify-between w-full p-2.5 rounded-xl bg-slate-900/60 hover:bg-slate-900 border border-surfaceBorder text-slate-300 text-xs transition-colors cursor-pointer"
                >
                  <span className="flex items-center gap-2 font-medium">
                    {showRawJson ? <ChevronDown className="w-4 h-4 text-sky-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                    Recorded Event Snapshot & Metadata (JSON)
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    {showRawJson ? 'Click to collapse' : 'Click to inspect raw JSON'}
                  </span>
                </button>
                {showRawJson && (
                  <pre className="mt-2 p-3 rounded-xl bg-slate-950 border border-surfaceBorder text-slate-200 font-mono text-[11px] overflow-x-auto max-h-60 leading-relaxed animate-in fade-in duration-150">
                    {JSON.stringify(inspectedLog.details, null, 2)}
                  </pre>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-surfaceBorder">
              <button
                type="button"
                onClick={() => setInspectedLog(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors cursor-pointer"
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
