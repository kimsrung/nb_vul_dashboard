import React, { useState, useEffect } from 'react';
import { Search, RefreshCw, Server } from 'lucide-react';
import { AssetListItem, apiClient } from '../api/client';
import { RiskBadge } from '../components/common/RiskBadge';

interface AssetsPageProps {
  onSelectAsset: (assetId: number) => void;
}

export const AssetsPage: React.FC<AssetsPageProps> = ({ onSelectAsset }) => {
  const [assets, setAssets] = useState<AssetListItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');
  const [riskFilter, setRiskFilter] = useState<string>('');
  const [osFilter, setOsFilter] = useState<string>('');
  const [riskyOnly, setRiskyOnly] = useState<boolean>(false);
  const [tagFilter, setTagFilter] = useState<string>('');

  const fetchAssets = async () => {
    setIsLoading(true);
    try {
      const params: any = {};
      if (search) params.search = search;
      if (riskFilter) params.risk_level = riskFilter;
      if (osFilter) params.os_family = osFilter;
      if (riskyOnly) params.is_risky = true;
      if (tagFilter) params.tag = tagFilter;

      const res = await apiClient.get('/assets', { params });
      setAssets(res.data);
    } catch (err) {
      console.error('Failed to load assets', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, [riskFilter, osFilter, riskyOnly]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchAssets();
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Server className="w-5 h-5 text-sky-400" /> Asset Inventory & Risk Scoring
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Qualys scanned assets with automated risk scoring and direct KB fix remediation.
          </p>
        </div>
        <button
          onClick={fetchAssets}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 self-start"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          <div className="flex-1 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by IP, hostname, OS, or NetBIOS..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-surfaceBorder rounded-lg pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-primary-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
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
              onChange={(e) => setOsFilter(e.target.value)}
              className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-primary-500"
            >
              <option value="">All OS Families</option>
              <option value="Linux">Linux</option>
              <option value="Windows">Windows</option>
              <option value="macOS">macOS</option>
              <option value="Network">Network</option>
            </select>

            <input
              type="text"
              placeholder="Filter Tag (e.g. PCI)"
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
              onBlur={fetchAssets}
              className="w-32 bg-slate-950 border border-surfaceBorder rounded-lg px-2.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-primary-500"
            />

            <label className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-950 border border-surfaceBorder cursor-pointer text-xs text-slate-300">
              <input
                type="checkbox"
                checked={riskyOnly}
                onChange={(e) => setRiskyOnly(e.target.checked)}
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

      {/* Asset Table */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder">
              <tr>
                <th className="py-3 px-4">Host IP & FQDN</th>
                <th className="py-3 px-4">Operating System</th>
                <th className="py-3 px-4">Tags</th>
                <th className="py-3 px-4">Active Vulns</th>
                <th className="py-3 px-4">Risk Level & Score</th>
                <th className="py-3 px-4">Last Scanned</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-primary-400" />
                      Loading asset inventory...
                    </div>
                  </td>
                </tr>
              ) : assets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    No assets found matching the selected filters.
                  </td>
                </tr>
              ) : (
                assets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-mono font-bold text-slate-100">{asset.ip_address}</div>
                      <div className="text-[11px] text-slate-400 font-mono">{asset.fqdn || 'No FQDN'}</div>
                      <div className="text-[10px] text-slate-500 font-mono">Qualys ID: {asset.qualys_id}</div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-slate-200 font-medium">{asset.os_name}</div>
                      <div className="text-[10px] text-slate-400 font-mono">{asset.os_family}</div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {asset.tags.map((t) => (
                          <span
                            key={t}
                            className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 border border-slate-700"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono">
                      <span className="text-red-400 font-bold">{asset.critical_vulns} Crit</span> /{' '}
                      <span className="text-amber-400 font-bold">{asset.high_vulns} High</span>
                      <div className="text-[10px] text-slate-400">Total: {asset.total_vulns}</div>
                    </td>
                    <td className="py-3 px-4">
                      <RiskBadge level={asset.risk_level} score={asset.risk_score} />
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {asset.last_scan_date ? new Date(asset.last_scan_date).toLocaleDateString() : 'Unknown'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onSelectAsset(asset.id)}
                        className="px-3 py-1.5 rounded-lg bg-primary-600/10 hover:bg-primary-600/20 text-primary-400 border border-primary-500/30 text-xs font-semibold transition-colors"
                      >
                        Inspect & Fix Guidance &rarr;
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
