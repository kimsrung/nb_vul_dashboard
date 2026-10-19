import React from 'react';
import { ShieldAlert, Server, AlertTriangle, Bug, Flame, ArrowUpRight, Activity } from 'lucide-react';
import { DashboardSummary } from '../api/client';
import { RiskBadge } from '../components/common/RiskBadge';

interface DashboardPageProps {
  summary: DashboardSummary | null;
  isLoading: boolean;
  onSelectAsset: (assetId: number) => void;
  onNavigateTab: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  summary,
  isLoading,
  onSelectAsset,
  onNavigateTab,
}) => {
  if (isLoading || !summary) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-slate-400">Loading Qualys Risk Telemetry...</p>
        </div>
      </div>
    );
  }

  const riskyPercent = summary.total_assets > 0 ? Math.round((summary.risky_assets / summary.total_assets) * 100) : 0;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
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
        <div className="flex items-center gap-4 bg-slate-950/60 p-3 rounded-xl border border-slate-800">
          <div className="text-right">
            <div className="text-[11px] text-slate-400">Last Qualys Sync</div>
            <div className="text-xs font-mono font-semibold text-slate-200">
              {summary.last_sync_time ? new Date(summary.last_sync_time).toLocaleString() : 'Never'}
            </div>
          </div>
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Assets */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Assets Monitored</span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">{summary.total_assets}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
            <span>Scoped in Qualys</span>
            <span className="text-emerald-400 font-semibold">100% active</span>
          </div>
        </div>

        {/* Risky Assets Flagged */}
        <div className="p-5 rounded-xl bg-surface border border-red-900/30 hover:border-red-700/50 transition-all relative overflow-hidden">
          <div className="absolute -right-4 -bottom-4 w-20 h-20 bg-red-500/5 rounded-full blur-xl pointer-events-none" />
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Flagged Risky Assets</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400 font-mono flex items-baseline gap-2">
            {summary.risky_assets}
            <span className="text-xs text-red-400/80 font-normal">({riskyPercent}% fleet)</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Breaching risk score or SLA rules
          </div>
        </div>

        {/* Critical & High Vulns */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Critical & High Vulns</span>
            <Bug className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono flex items-baseline gap-2">
            {summary.critical_vulns + summary.high_vulns}
            <span className="text-xs text-slate-400 font-normal font-sans">
              ({summary.critical_vulns} Crit / {summary.high_vulns} High)
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Total active findings: {summary.total_vulns}
          </div>
        </div>

        {/* Active Alerts */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Active Security Alerts</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">{summary.active_alerts}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
            <span>Pending remediation</span>
            <button
              onClick={() => onNavigateTab('alerts')}
              className="text-primary-400 hover:text-primary-300 font-semibold"
            >
              View Feed &rarr;
            </button>
          </div>
        </div>
      </div>

      {/* Middle Row: Risk Breakdown + Threat Intel RTIs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution */}
        <div className="p-5 rounded-xl bg-surface border border-surfaceBorder space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Flame className="w-4 h-4 text-orange-400" /> Asset Risk Tier Breakdown
          </h3>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-red-400 font-medium">Critical Risk (Score &ge; 80)</span>
                <span className="text-slate-300 font-mono font-bold">{summary.risk_distribution.critical}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-red-500 rounded-full"
                  style={{
                    width: `${summary.total_assets ? (summary.risk_distribution.critical / summary.total_assets) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-amber-400 font-medium">High Risk (Score 40-79)</span>
                <span className="text-slate-300 font-mono font-bold">{summary.risk_distribution.high}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full"
                  style={{
                    width: `${summary.total_assets ? (summary.risk_distribution.high / summary.total_assets) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-yellow-300 font-medium">Medium Risk (Score 15-39)</span>
                <span className="text-slate-300 font-mono font-bold">{summary.risk_distribution.medium}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-yellow-400 rounded-full"
                  style={{
                    width: `${summary.total_assets ? (summary.risk_distribution.medium / summary.total_assets) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-emerald-400 font-medium">Low Risk (Score &lt; 15)</span>
                <span className="text-slate-300 font-mono font-bold">{summary.risk_distribution.low}</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full"
                  style={{
                    width: `${summary.total_assets ? (summary.risk_distribution.low / summary.total_assets) * 100 : 0}%`,
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

      {/* Flagged Risky Assets Table */}
      <div className="p-5 rounded-xl bg-surface border border-surfaceBorder space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" /> Flagged Risky Assets Requiring Immediate Remediation
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Ranked by composite threat score (Qualys Severity + RTI Exploits + SLA Breaches)
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('assets')}
            className="text-xs font-semibold text-primary-400 hover:text-primary-300 flex items-center gap-1"
          >
            View All Assets <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto rounded-xl border border-surfaceBorder">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder">
              <tr>
                <th className="py-3 px-4">Host IP & Name</th>
                <th className="py-3 px-4">Operating System</th>
                <th className="py-3 px-4">Tags</th>
                <th className="py-3 px-4">Critical / High</th>
                <th className="py-3 px-4">Risk Tier & Score</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {summary.recent_risky_assets.map((asset) => (
                <tr key={asset.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-mono font-bold text-slate-100">{asset.ip_address}</div>
                    <div className="text-[11px] text-slate-400 font-mono">{asset.fqdn || 'No FQDN'}</div>
                  </td>
                  <td className="py-3 px-4 text-slate-300">{asset.os_name}</td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {asset.tags.map((t) => (
                        <span key={t} className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 border border-slate-700">
                          {t}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono">
                    <span className="text-red-400 font-bold">{asset.critical_vulns} Crit</span> /{' '}
                    <span className="text-amber-400 font-bold">{asset.high_vulns} High</span>
                  </td>
                  <td className="py-3 px-4">
                    <RiskBadge level={asset.risk_level} score={asset.risk_score} />
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => onSelectAsset(asset.id)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 hover:text-sky-300 font-semibold border border-slate-700 transition-colors text-[11px]"
                    >
                      Inspect Findings
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
