import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert, Server, Bug, Flame, ArrowUpRight,
  Activity, ArrowUpDown, ArrowUp, ArrowDown
} from 'lucide-react';
import { DashboardSummary, AssetListItem } from '../api/client';
import { SeverityPills } from '../components/common/SeverityPills';
import { TablePagination } from '../components/common/TablePagination';
import { formatDateYMD } from '../utils/date';
import { useAuth } from '../context/AuthContext';

interface DashboardPageProps {
  summary: DashboardSummary | null;
  isLoading: boolean;
  onSelectAsset?: (assetId: number) => void;
  onNavigateTab?: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  summary,
  isLoading,
  onSelectAsset,
  onNavigateTab,
}) => {
  const { isAdmin } = useAuth();
  const navigate = useNavigate();

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

  const [sortField, setSortField] = useState<string>('critical_vulns');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(5);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder(field === 'critical_vulns' || field === 'total_vulns' ? 'desc' : 'asc');
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
        </div>
      </div>

      {/* Themed 3-KPI Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Total Assets */}
        <div className="p-5 rounded-2xl bg-sky-950/20 border border-sky-900/40 hover:border-sky-700/60 transition-all shadow-lg hover:shadow-sky-500/5 group flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-sky-400 uppercase tracking-wider">
                Assets Monitored
              </span>
              <div className="p-2.5 rounded-xl bg-sky-500/10 border border-sky-500/30 text-sky-400 shadow-sm shadow-sky-500/10 group-hover:scale-105 transition-transform">
                <Server className="w-5 h-5" />
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <div className="text-3xl sm:text-4xl font-black text-sky-400 font-mono tracking-tight">
                {summary.total_assets}
              </div>
              <span className="text-xs text-slate-400 font-medium">hosts enrolled</span>
            </div>
          </div>
          <div className="text-xs text-slate-400 mt-4 flex items-center justify-between border-t border-sky-900/40 pt-3">
            <span className="text-slate-300 font-medium">Scoped in Qualys VMDR</span>
            <button
              onClick={() => handleNavigateTab('assets')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 text-xs font-semibold border border-sky-500/20 hover:border-sky-500/40 transition-colors cursor-pointer"
            >
              <span>View Inventory</span>
              <span className="group-hover:translate-x-0.5 transition-transform">&rarr;</span>
            </button>
          </div>
        </div>

        {/* Total Vulnerabilities (only Critical & High highlights) */}
        <div className="p-5 rounded-2xl bg-amber-950/20 border border-amber-900/40 hover:border-amber-700/60 transition-all shadow-lg hover:shadow-amber-500/5 group flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-amber-400 uppercase tracking-wider">
                Total Vulnerabilities
              </span>
              <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 shadow-sm shadow-amber-500/10 group-hover:scale-105 transition-transform">
                <Bug className="w-5 h-5" />
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <div className="text-3xl sm:text-4xl font-black text-amber-400 font-mono tracking-tight">
                {summary.total_vulns}
              </div>
              <span className="text-xs text-slate-400 font-medium">active detections</span>
            </div>
          </div>
          <div className="text-xs text-slate-400 mt-4 flex items-center justify-between border-t border-amber-900/40 pt-3">
            <span className="text-slate-300 font-mono text-xs">
              <strong className="text-red-400 font-bold">{summary.critical_vulns}</strong> Crit &bull; <strong className="text-amber-400 font-bold">{summary.high_vulns}</strong> High
            </span>
            <button
              onClick={() => handleNavigateTab('assets')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 text-xs font-semibold border border-amber-500/20 hover:border-amber-500/40 transition-colors cursor-pointer"
            >
              <span>View All</span>
              <span className="group-hover:translate-x-0.5 transition-transform">&rarr;</span>
            </button>
          </div>
        </div>

        {/* MISP Threat Intelligence Advisories */}
        <div className="p-5 rounded-2xl bg-rose-950/20 border border-rose-900/40 hover:border-rose-700/60 transition-all shadow-lg hover:shadow-rose-500/5 group flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-rose-400 uppercase tracking-wider">
                MISP Threat Intelligence
              </span>
              <div className="flex items-center gap-2">
                {isAdmin && (
                  <button
                    onClick={() => handleNavigateTab('misp')}
                    className="text-[11px] font-semibold text-rose-400/80 hover:text-rose-300 transition-colors cursor-pointer underline decoration-rose-500/40"
                    title="View all ingested CVEs including clean / 0-exposure records"
                  >
                    All Feed &rarr;
                  </button>
                )}
                <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 shadow-sm shadow-rose-500/10 group-hover:scale-105 transition-transform">
                  <ShieldAlert className="w-5 h-5" />
                </div>
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <div className="text-3xl sm:text-4xl font-black text-rose-400 font-mono tracking-tight">
                {summary.misp_advisories_count ?? summary.active_alerts}
              </div>
              <span className="text-xs text-slate-400 font-medium">advisories cataloged</span>
            </div>
          </div>
          <div className="text-xs text-slate-400 mt-4 flex items-center justify-between border-t border-rose-900/40 pt-3">
            <span className="text-slate-300 font-mono text-xs">
              <strong className="text-rose-400 font-bold">{summary.misp_matched_assets_count ?? summary.active_alerts}</strong> exposed servers
            </span>
            <button
              onClick={() => handleNavigateTab('alerts')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 text-xs font-semibold border border-rose-500/20 hover:border-rose-500/40 transition-colors cursor-pointer"
            >
              <span>Alert Center</span>
              <span className="group-hover:translate-x-0.5 transition-transform">&rarr;</span>
            </button>
          </div>
        </div>
      </div>

      {/* Middle Row: Severity Breakdown + Threat Intel RTIs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Qualys Vulnerability Severity Distribution */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Flame className="w-4 h-4 text-rose-400" /> Qualys Severity Distribution
          </h3>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-rose-400 font-medium">Severity 5 &bull; Critical</span>
                <span className="text-slate-200 font-mono font-bold">{summary.severity_breakdown?.sev5 ?? summary.critical_vulns}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-rose-500 rounded-full"
                  style={{
                    width: `${summary.total_vulns ? ((summary.severity_breakdown?.sev5 ?? summary.critical_vulns) / summary.total_vulns) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-orange-400 font-medium">Severity 4 &bull; High</span>
                <span className="text-slate-200 font-mono font-bold">{summary.severity_breakdown?.sev4 ?? summary.high_vulns}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-orange-500 rounded-full"
                  style={{
                    width: `${summary.total_vulns ? ((summary.severity_breakdown?.sev4 ?? summary.high_vulns) / summary.total_vulns) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-amber-400 font-medium">Severity 3 &bull; Medium</span>
                <span className="text-slate-200 font-mono font-bold">{summary.severity_breakdown?.sev3 ?? 0}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-amber-400 rounded-full"
                  style={{
                    width: `${summary.total_vulns ? ((summary.severity_breakdown?.sev3 ?? 0) / summary.total_vulns) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-sky-400 font-medium">Severity 2 &bull; Low</span>
                <span className="text-slate-200 font-mono font-bold">{summary.severity_breakdown?.sev2 ?? 0}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-sky-400 rounded-full"
                  style={{
                    width: `${summary.total_vulns ? ((summary.severity_breakdown?.sev2 ?? 0) / summary.total_vulns) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-400 font-medium">Severity 1 &bull; Info</span>
                <span className="text-slate-200 font-mono font-bold">{summary.severity_breakdown?.sev1 ?? 0}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-slate-500 rounded-full"
                  style={{
                    width: `${summary.total_vulns ? ((summary.severity_breakdown?.sev1 ?? 0) / summary.total_vulns) * 100 : 0}%`,
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

      {/* Most Affected Assets Table */}
      <div className="p-5 rounded-xl bg-surface border border-surfaceBorder space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" /> Most Affected Infrastructure Requiring Remediation
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Ranked by active Critical (Severity 5) and High (Severity 4) vulnerability detections
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
                <th className="py-3 px-4">
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Qualys Severities (5 | 4 | 3 | 2 | 1)</span>
                  </div>
                </th>
                <th className="py-3 px-4 text-right font-semibold">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {paginatedAssets.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-400">
                    No active detections on monitored assets at this time.
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
                      <SeverityPills
                        sev5={asset.critical_vulns}
                        sev4={asset.high_vulns}
                        sev3={asset.medium_vulns}
                        sev2={asset.low_vulns}
                        sev1={asset.info_vulns}
                        total={asset.total_vulns}
                        compact
                      />
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => handleSelectAsset(asset.id)}
                        className="px-3 py-1.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 text-xs font-semibold transition-colors cursor-pointer"
                        title="View host dossier"
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
