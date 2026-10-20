import React, { useState, useEffect, useRef } from 'react';
import { Search, RefreshCw, Server, User, ChevronLeft, ChevronRight, RotateCcw } from 'lucide-react';
import { AssetListItem, PaginatedAssetsResponse, OwnerOption, apiClient } from '../api/client';
import { RiskBadge } from '../components/common/RiskBadge';
import { useAuth } from '../context/AuthContext';

interface AssetsPageProps {
  onSelectAsset: (assetId: number) => void;
}

interface ColumnDef {
  id: string;
  label: string;
  minWidth: number;
  align?: 'left' | 'right';
}

const COLUMN_DEFS: ColumnDef[] = [
  { id: 'host_ip', label: 'Host IP & FQDN', minWidth: 130 },
  { id: 'server_name', label: 'Server Name', minWidth: 110 },
  { id: 'os', label: 'Operating System', minWidth: 110 },
  { id: 'owner', label: 'Owner', minWidth: 95 },
  { id: 'vulns', label: 'Active Vulns', minWidth: 100 },
  { id: 'risk', label: 'Risk Level & Score', minWidth: 120 },
  { id: 'scanned', label: 'Last Scanned', minWidth: 85 },
  { id: 'action', label: 'Action', minWidth: 110, align: 'right' },
];

const DEFAULT_COLUMN_WIDTHS: Record<string, number> = {
  host_ip: 180,
  server_name: 160,
  os: 150,
  owner: 115, // Made smaller
  vulns: 130,
  risk: 150,
  scanned: 105,
  action: 145,
};

const getInitialColumnWidths = (): Record<string, number> => {
  try {
    const saved = localStorage.getItem('nbc_asset_column_widths');
    if (saved) {
      const parsed = JSON.parse(saved);
      return { ...DEFAULT_COLUMN_WIDTHS, ...parsed };
    }
  } catch (err) {}
  return DEFAULT_COLUMN_WIDTHS;
};

export const AssetsPage: React.FC<AssetsPageProps> = ({ onSelectAsset }) => {
  const { isOwner, canAssignOwner } = useAuth();
  const [assets, setAssets] = useState<AssetListItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Column width state for drag-and-drop resizing
  const [columnWidths, setColumnWidths] = useState<Record<string, number>>(getInitialColumnWidths);
  const [resizingCol, setResizingCol] = useState<string | null>(null);
  const resizeRef = useRef<{
    colId: string;
    startX: number;
    startWidth: number;
    minWidth: number;
  } | null>(null);

  // Filters
  const [search, setSearch] = useState<string>('');
  const [riskFilter, setRiskFilter] = useState<string>('');
  const [osFilter, setOsFilter] = useState<string>('');
  const [riskyOnly, setRiskyOnly] = useState<boolean>(false);
  const [ownerFilter, setOwnerFilter] = useState<string>('');

  // Available owners for assignment
  const [availableOwners, setAvailableOwners] = useState<OwnerOption[]>([]);
  const [updatingOwnerAssetId, setUpdatingOwnerAssetId] = useState<number | null>(null);

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
  }, [page, pageSize, riskFilter, osFilter, riskyOnly, ownerFilter]);

  useEffect(() => {
    return () => {
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, []);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAssets();
  };

  const handleOwnerChange = async (assetId: number, newOwnerId: number) => {
    setUpdatingOwnerAssetId(assetId);
    try {
      const res = await apiClient.patch(`/assets/${assetId}/owner`, {
        owner_id: newOwnerId === 0 ? 0 : newOwnerId,
      });
      // Update local asset row
      setAssets((prev) =>
        prev.map((a) =>
          a.id === assetId
            ? {
                ...a,
                owner_id: res.data.owner_id,
                owner_username: res.data.owner_username,
              }
            : a
        )
      );
    } catch (err) {
      console.error('Failed to update asset owner', err);
    } finally {
      setUpdatingOwnerAssetId(null);
    }
  };

  const handleResizeStart = (e: React.MouseEvent, colId: string) => {
    e.preventDefault();
    e.stopPropagation();

    const colDef = COLUMN_DEFS.find((c) => c.id === colId);
    const minWidth = colDef?.minWidth || 80;
    const currentWidth = columnWidths[colId] || 120;

    resizeRef.current = {
      colId,
      startX: e.clientX,
      startWidth: currentWidth,
      minWidth,
    };
    setResizingCol(colId);

    const handleMouseMove = (moveEvent: MouseEvent) => {
      if (!resizeRef.current) return;
      const { colId: activeColId, startX, startWidth: initialWidth, minWidth: min } = resizeRef.current;
      const deltaX = moveEvent.clientX - startX;
      const newWidth = Math.max(min, Math.round(initialWidth + deltaX));

      setColumnWidths((prev) => {
        if (prev[activeColId] === newWidth) return prev;
        return { ...prev, [activeColId]: newWidth };
      });
    };

    const handleMouseUp = () => {
      if (resizeRef.current) {
        setColumnWidths((latest) => {
          try {
            localStorage.setItem('nbc_asset_column_widths', JSON.stringify(latest));
          } catch (err) {}
          return latest;
        });
      }
      resizeRef.current = null;
      setResizingCol(null);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const resetColumnWidths = () => {
    setColumnWidths(DEFAULT_COLUMN_WIDTHS);
    try {
      localStorage.removeItem('nbc_asset_column_widths');
    } catch (err) {}
  };

  const totalTableWidth = Object.values(columnWidths).reduce((a, b) => a + b, 0);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
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
            Qualys scanned assets with automated risk scoring, ownership auditing, and step-by-step KB remediation.
          </p>
        </div>
        <div className="flex items-center gap-2 self-start">
          <button
            onClick={() => {
              fetchAssets();
              fetchOwners();
            }}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

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
                {availableOwners.map((o) => (
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
          </div>
        </form>
      </div>

      {/* Asset Table with User Draggable Column Resizing */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder overflow-hidden space-y-2">
        {/* <div className="flex items-center justify-between text-xs text-slate-400 pb-1">
          <span className="text-[11px] text-slate-500">
            Tip: Drag column header dividers to resize column widths
          </span>
          <button
            onClick={resetColumnWidths}
            className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-sky-400 px-2 py-0.5 rounded bg-slate-900 border border-surfaceBorder hover:border-slate-700 transition-colors"
            title="Reset all column widths to default"
          >
            <RotateCcw className="w-3 h-3" />
            Reset Widths
          </button>
        </div> */}

        <div className="overflow-x-auto">
          <table
            className="text-left text-xs text-slate-300 table-fixed border-collapse"
            style={{ width: `${totalTableWidth}px`, minWidth: '100%' }}
          >
            <colgroup>
              {COLUMN_DEFS.map((col) => (
                <col key={col.id} style={{ width: `${columnWidths[col.id] || 120}px` }} />
              ))}
            </colgroup>
            <thead className="bg-slate-900/90 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder select-none">
              <tr>
                {COLUMN_DEFS.map((col) => (
                  <th
                    key={col.id}
                    className={`relative py-3 px-3 font-semibold text-slate-300 group ${
                      col.align === 'right' ? 'text-right' : 'text-left'
                    }`}
                  >
                    <div className="truncate pr-2">{col.label}</div>
                    {/* Drag resize handle on column border */}
                    <div
                      onMouseDown={(e) => handleResizeStart(e, col.id)}
                      className={`absolute right-0 top-0 bottom-0 w-3 cursor-col-resize flex items-center justify-center transition-colors z-10 ${
                        resizingCol === col.id ? 'bg-sky-500/30' : 'hover:bg-sky-500/20'
                      }`}
                      title={`Drag to resize ${col.label}`}
                    >
                      <div
                        className={`w-[2px] transition-all rounded-full ${
                          resizingCol === col.id
                            ? 'bg-sky-400 h-6'
                            : 'bg-slate-700 h-4 group-hover:bg-sky-400/80 group-hover:h-5'
                        }`}
                      />
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {isLoading ? (
                <tr>
                  <td colSpan={COLUMN_DEFS.length} className="py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-primary-400" />
                      Loading asset inventory...
                    </div>
                  </td>
                </tr>
              ) : assets.length === 0 ? (
                <tr>
                  <td colSpan={COLUMN_DEFS.length} className="py-12 text-center text-slate-400">
                    No assets found matching the selected filters.
                  </td>
                </tr>
              ) : (
                assets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-slate-800/40 transition-colors">
                    {/* Host IP & FQDN */}
                    <td className="py-3 px-3 overflow-hidden">
                      <div className="font-mono font-bold text-slate-100 truncate">{asset.ip_address}</div>
                      <div className="text-[11px] text-slate-400 font-mono truncate" title={asset.fqdn || 'No FQDN'}>
                        {asset.fqdn || 'No FQDN'}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono">Qualys ID: {asset.qualys_id}</div>
                    </td>

                    {/* Server Name (clean environment / cluster name without secondary duplicate text) */}
                    <td className="py-3 px-3 overflow-hidden">
                      <div className="font-semibold text-sky-300 font-mono text-xs truncate" title={asset.server_name || '—'}>
                        {asset.server_name || '—'}
                      </div>
                    </td>

                    {/* Operating System */}
                    <td className="py-3 px-3 overflow-hidden">
                      <div className="text-slate-200 font-medium truncate" title={asset.os_name || ''}>
                        {asset.os_name}
                      </div>
                      {/* <div className="text-[10px] text-slate-400 font-mono truncate">{asset.os_family}</div> */}
                    </td>

                    {/* Owner column (compact) */}
                    <td className="py-3 px-3 overflow-hidden">
                      {canAssignOwner ? (
                        <div className="flex items-center gap-1.5">
                          <User className="w-3 h-3 text-slate-500 shrink-0" />
                          <select
                            value={asset.owner_id || 0}
                            disabled={updatingOwnerAssetId === asset.id}
                            onChange={(e) => handleOwnerChange(asset.id, Number(e.target.value))}
                            className="w-full max-w-[105px] bg-slate-950 border border-slate-700 hover:border-slate-500 rounded px-1.5 py-0.5 text-[11px] text-slate-200 focus:outline-none focus:border-primary-500 disabled:opacity-50 cursor-pointer truncate"
                            title={asset.owner_username || 'Unassigned'}
                          >
                            <option value={0}>Unassigned</option>
                            {availableOwners.map((o) => (
                              <option key={o.id} value={o.id}>
                                {o.username}
                              </option>
                            ))}
                          </select>
                        </div>
                      ) : (
                        <div className="truncate">
                          {asset.owner_username ? (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] bg-slate-800 text-sky-300 border border-slate-700 font-medium truncate max-w-full">
                              <User className="w-2.5 h-2.5 text-sky-400 shrink-0" />
                              <span className="truncate">{asset.owner_username}</span>
                            </span>
                          ) : (
                            <span className="text-[11px] text-slate-500 italic">Unassigned</span>
                          )}
                        </div>
                      )}
                    </td>

                    {/* Active Vulns */}
                    <td className="py-3 px-3 font-mono overflow-hidden">
                      <div className="truncate">
                        <span className="text-red-400 font-bold">{asset.critical_vulns} Crit</span>
                        <span className="text-slate-500"> / </span>
                        <span className="text-amber-400 font-bold">{asset.high_vulns} High</span>
                      </div>
                      <div className="text-[10px] text-slate-400 truncate">Total: {asset.total_vulns}</div>
                    </td>

                    {/* Risk Level & Score */}
                    <td className="py-3 px-3 overflow-hidden">
                      <RiskBadge level={asset.risk_level} score={asset.risk_score} />
                    </td>

                    {/* Last Scanned */}
                    <td className="py-3 px-3 text-slate-400 font-mono text-[11px] truncate">
                      {asset.last_scan_date ? new Date(asset.last_scan_date).toLocaleDateString() : 'Unknown'}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-3 text-right overflow-hidden">
                      <button
                        onClick={() => onSelectAsset(asset.id)}
                        className="px-2.5 py-1.5 rounded-lg bg-primary-600/10 hover:bg-primary-600/20 text-primary-400 border border-primary-500/30 text-xs font-semibold transition-colors whitespace-nowrap"
                      >
                        Inspect &rarr;
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Server-Side Pagination Bar */}
        <div className="mt-4 pt-4 border-t border-surfaceBorder flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
          <div className="flex items-center gap-4">
            <span>
              Showing <span className="font-semibold text-slate-200">{total === 0 ? 0 : (page - 1) * pageSize + 1}</span> to{' '}
              <span className="font-semibold text-slate-200">{Math.min(page * pageSize, total)}</span> of{' '}
              <span className="font-semibold text-slate-200">{total}</span> assets
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
    </div>
  );
};
