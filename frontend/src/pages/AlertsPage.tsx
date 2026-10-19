import React, { useState, useEffect } from 'react';
import { Bell, CheckCircle2, Send, RefreshCw, ShieldAlert } from 'lucide-react';
import { AlertItem, apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';

interface AlertsPageProps {
  onSelectAsset?: (assetId: number) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ onSelectAsset }) => {
  const { isAdmin } = useAuth();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('unresolved');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [resolvingId, setResolvingId] = useState<number | null>(null);

  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const params: any = {};
      if (statusFilter === 'unresolved') params.is_resolved = false;
      if (statusFilter === 'resolved') params.is_resolved = true;
      if (severityFilter) params.severity = severityFilter;

      const res = await apiClient.get('/alerts', { params });
      setAlerts(res.data);
    } catch (err) {
      console.error('Failed to load alerts', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [statusFilter, severityFilter]);

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

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Bell className="w-5 h-5 text-red-400" /> Security Alert Center & Notification Dispatch
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Tracking assets flagged as high-risk, SLA breaches, and automated Telegram alerts.
          </p>
        </div>
        <button
          onClick={fetchAlerts}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 self-start"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh Feed
        </button>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setStatusFilter('unresolved')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              statusFilter === 'unresolved'
                ? 'bg-primary-600 text-white'
                : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
            }`}
          >
            Active Alerts
          </button>
          <button
            onClick={() => setStatusFilter('resolved')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              statusFilter === 'resolved'
                ? 'bg-primary-600 text-white'
                : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
            }`}
          >
            Resolved History
          </button>
          <button
            onClick={() => setStatusFilter('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              statusFilter === 'all'
                ? 'bg-primary-600 text-white'
                : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
            }`}
          >
            All
          </button>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary-500"
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
          </select>
        </div>
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
            <p className="text-sm font-semibold text-slate-200">No active alerts</p>
            <p className="text-xs text-slate-500 mt-1">All scanned assets are currently operating within safe thresholds.</p>
          </div>
        ) : (
          alerts.map((al) => {
            const isCrit = al.severity === 'Critical';
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
                      <h3 className="text-sm font-bold text-slate-100">{al.title}</h3>
                      {al.is_resolved && (
                        <span className="px-2 py-0.5 rounded text-[11px] bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold">
                          Resolved
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">{al.message}</p>
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

                      {!al.is_resolved && isAdmin && (
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
    </div>
  );
};
