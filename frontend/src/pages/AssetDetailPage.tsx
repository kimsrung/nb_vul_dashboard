import React, { useState, useEffect } from 'react';
import { ArrowLeft, Server, Bug, RefreshCw, Wrench } from 'lucide-react';
import { AssetDetail, DetectionItem, apiClient } from '../api/client';
import { RiskBadge } from '../components/common/RiskBadge';
import { SeverityTag } from '../components/common/SeverityTag';
import { RemediationStatusBadge } from '../components/common/RemediationStatusBadge';
import { RemediationDrawer } from '../components/remediation/RemediationDrawer';

interface AssetDetailPageProps {
  assetId: number;
  onBack: () => void;
}

export const AssetDetailPage: React.FC<AssetDetailPageProps> = ({ assetId, onBack }) => {
  const [asset, setAsset] = useState<AssetDetail | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [selectedDetection, setSelectedDetection] = useState<DetectionItem | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(false);

  const fetchAssetDetail = async () => {
    setIsLoading(true);
    try {
      const res = await apiClient.get(`/assets/${assetId}`);
      setAsset(res.data);
    } catch (err) {
      console.error('Failed to load asset details', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAssetDetail();
  }, [assetId]);

  const handleOpenRemediation = (detection: DetectionItem) => {
    setSelectedDetection(detection);
    setIsDrawerOpen(true);
  };

  if (isLoading || !asset) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="w-6 h-6 animate-spin text-primary-400" />
          <p className="text-xs text-slate-400">Loading asset risk dossier...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-slate-100 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Assets
        </button>
        <button
          onClick={fetchAssetDetail}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700"
        >
          <RefreshCw className="w-3.5 h-3.5 text-sky-400" /> Refresh Dossier
        </button>
      </div>

      {/* Asset Header Dossier Card */}
      <div className="p-6 rounded-2xl bg-surface border border-surfaceBorder space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surfaceBorder pb-4">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-sky-400 shrink-0">
              <Server className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold text-slate-100 font-mono">{asset.ip_address}</h2>
                <RiskBadge level={asset.risk_level} score={asset.risk_score} />
              </div>
              <p className="text-xs font-mono text-slate-400 mt-0.5">
                {asset.fqdn || 'No FQDN'} &bull; NetBIOS: {asset.netbios_name || 'N/A'} &bull; Qualys Host ID: {asset.qualys_id}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6 bg-slate-950/60 px-5 py-3 rounded-xl border border-slate-800">
            <div className="text-center">
              <div className="text-[10px] uppercase font-semibold text-slate-400">Risk Score</div>
              <div className="text-xl font-bold font-mono text-red-400">{asset.risk_score}</div>
            </div>
            <div className="w-px h-8 bg-slate-800" />
            <div className="text-center">
              <div className="text-[10px] uppercase font-semibold text-slate-400">Critical</div>
              <div className="text-xl font-bold font-mono text-red-400">{asset.critical_vulns}</div>
            </div>
            <div className="w-px h-8 bg-slate-800" />
            <div className="text-center">
              <div className="text-[10px] uppercase font-semibold text-slate-400">High</div>
              <div className="text-xl font-bold font-mono text-amber-400">{asset.high_vulns}</div>
            </div>
            <div className="w-px h-8 bg-slate-800" />
            <div className="text-center">
              <div className="text-[10px] uppercase font-semibold text-slate-400">Total Detections</div>
              <div className="text-xl font-bold font-mono text-slate-200">{asset.detections.length}</div>
            </div>
          </div>
        </div>

        {/* Host Metadata Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs pt-1">
          <div>
            <span className="text-slate-400 block mb-0.5">Operating System</span>
            <span className="text-slate-200 font-medium">{asset.os_name}</span>
          </div>
          <div>
            <span className="text-slate-400 block mb-0.5">OS Family</span>
            <span className="text-slate-200 font-mono font-medium">{asset.os_family}</span>
          </div>
          <div>
            <span className="text-slate-400 block mb-0.5">Last Qualys VM Scan</span>
            <span className="text-slate-200 font-mono">
              {asset.last_scan_date ? new Date(asset.last_scan_date).toLocaleString() : 'N/A'}
            </span>
          </div>
          <div>
            <span className="text-slate-400 block mb-0.5">Asset Tags</span>
            <div className="flex flex-wrap gap-1 mt-0.5">
              {asset.tags.map((t) => (
                <span
                  key={t}
                  className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 border border-slate-700"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Detections & Remediation Section */}
      <div className="p-6 rounded-2xl bg-surface border border-surfaceBorder space-y-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Bug className="w-4 h-4 text-red-400" /> Detected Vulnerabilities & KnowledgeBase Remediation Guidance
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Select any finding to inspect Qualys KB solutions, vendor patch links, CVE references, and scanner proof.
          </p>
        </div>

        <div className="overflow-x-auto rounded-xl border border-surfaceBorder">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder">
              <tr>
                <th className="py-3 px-4">Severity & QID</th>
                <th className="py-3 px-4">Vulnerability Title</th>
                <th className="py-3 px-4">Category & Port</th>
                <th className="py-3 px-4">Threat Intel Flags (RTI)</th>
                <th className="py-3 px-4">Remediation Status</th>
                <th className="py-3 px-4 text-right">Fix Guidance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {asset.detections.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    No active detections on this asset.
                  </td>
                </tr>
              ) : (
                asset.detections.map((det) => {
                  const kb = det.knowledge_base;
                  const ti = kb?.threat_intel_flags || {};

                  return (
                    <tr key={det.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <SeverityTag severity={det.severity} />
                          <span className="font-mono text-slate-400 text-xs">QID {det.qid}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 max-w-md">
                        <div className="font-semibold text-slate-100 line-clamp-2">
                          {kb?.title || `Qualys Finding QID ${det.qid}`}
                        </div>
                        {kb?.cve_list && kb.cve_list.length > 0 && (
                          <div className="text-[10px] text-sky-400 font-mono mt-0.5">
                            {kb.cve_list.join(', ')}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="text-slate-300">{kb?.category || 'Security'}</div>
                        <div className="text-[10px] text-slate-400 font-mono">
                          {det.port ? `Port ${det.port}/${det.protocol || 'tcp'}` : 'General / OS'}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {ti.ransomware && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-950 text-red-300 border border-red-800">
                              Ransomware
                            </span>
                          )}
                          {ti.active_in_wild && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-orange-950 text-orange-300 border border-orange-800">
                              In Wild
                            </span>
                          )}
                          {ti.exploit_public && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-950 text-blue-300 border border-blue-800">
                              Exploit Public
                            </span>
                          )}
                          {!ti.ransomware && !ti.active_in_wild && !ti.exploit_public && (
                            <span className="text-[11px] text-slate-500">None</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <RemediationStatusBadge status={det.remediation_status} />
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleOpenRemediation(det)}
                          className="px-3 py-1.5 rounded-lg bg-sky-600/10 hover:bg-sky-600/20 text-sky-400 border border-sky-500/30 text-xs font-semibold transition-colors flex items-center gap-1 ml-auto"
                        >
                          <Wrench className="w-3.5 h-3.5" /> View Fix Guidance & Proof
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

      {/* Slide-over Remediation Drawer */}
      <RemediationDrawer
        detection={selectedDetection}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        onStatusUpdated={fetchAssetDetail}
      />
    </div>
  );
};
