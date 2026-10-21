import React, { useState, useEffect } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { ArrowLeft, Server, Bug, RefreshCw, Wrench, Package, Trash2, AlertTriangle, X, ArrowUpDown, ArrowUp, ArrowDown, Search } from 'lucide-react';
import { AssetDetail, DetectionItem, SoftwareItem, apiClient } from '../api/client';
import { RiskBadge } from '../components/common/RiskBadge';
import { SeverityTag } from '../components/common/SeverityTag';
import { RemediationStatusBadge } from '../components/common/RemediationStatusBadge';
import { RemediationDrawer } from '../components/remediation/RemediationDrawer';
import { useAuth } from '../context/AuthContext';
import { TablePagination } from '../components/common/TablePagination';

interface AssetDetailPageProps {
  assetId?: number;
  onBack?: () => void;
}

export const AssetDetailPage: React.FC<AssetDetailPageProps> = ({ assetId: propAssetId, onBack: propOnBack }) => {
  const navigate = useNavigate();
  const params = useParams<{ id: string }>();
  const assetId = propAssetId ?? (params.id ? parseInt(params.id, 10) : 0);
  const onBack = propOnBack ?? (() => navigate('/assets'));
  const [searchParams, setSearchParams] = useSearchParams();
  const urlCve = searchParams.get('cve') || '';

  const { isAdmin } = useAuth();
  const [asset, setAsset] = useState<AssetDetail | null>(null);
  const [softwareList, setSoftwareList] = useState<SoftwareItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [selectedDetection, setSelectedDetection] = useState<DetectionItem | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(false);

  // Deletion modal state
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState<boolean>(false);
  const [deleteReason, setDeleteReason] = useState<string>('');
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  // Detections Search & Filter
  const [detSearch, setDetSearch] = useState<string>(urlCve);

  useEffect(() => {
    const qCve = searchParams.get('cve');
    if (qCve !== null && qCve !== detSearch) {
      setDetSearch(qCve);
      setDetPage(1);
    }
  }, [searchParams]);

  // Detections Sorting & Pagination
  const [detSortField, setDetSortField] = useState<string>('severity');
  const [detSortOrder, setDetSortOrder] = useState<'asc' | 'desc'>('desc');
  const [detPage, setDetPage] = useState<number>(1);
  const [detPageSize, setDetPageSize] = useState<number>(10);

  const handleDetSort = (field: string) => {
    if (detSortField === field) {
      setDetSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setDetSortField(field);
      setDetSortOrder(field === 'severity' || field === 'qid' ? 'desc' : 'asc');
    }
    setDetPage(1);
  };

  const filteredDetections = (asset?.detections || []).filter((d) => {
    if (!detSearch.trim()) return true;
    const q = detSearch.trim().toLowerCase();
    const cveMatch = d.knowledge_base?.cve_list?.some((c: string) => c.toLowerCase().includes(q));
    const titleMatch = (d.knowledge_base?.title || '').toLowerCase().includes(q);
    const qidMatch = String(d.qid).includes(q);
    const diagMatch = (d.scanner_results || '').toLowerCase().includes(q);
    return cveMatch || titleMatch || qidMatch || diagMatch;
  });

  const sortedDetections = [...filteredDetections].sort((a, b) => {
    let aVal: any = a[detSortField as keyof DetectionItem];
    let bVal: any = b[detSortField as keyof DetectionItem];

    if (detSortField === 'title') {
      aVal = a.knowledge_base?.title || '';
      bVal = b.knowledge_base?.title || '';
    } else if (detSortField === 'category') {
      aVal = a.knowledge_base?.category || '';
      bVal = b.knowledge_base?.category || '';
    } else if (detSortField === 'status') {
      aVal = a.remediation_status || '';
      bVal = b.remediation_status || '';
    }

    if (typeof aVal === 'string') {
      aVal = aVal.toLowerCase();
      bVal = (bVal || '').toLowerCase();
    }

    if (aVal < bVal) return detSortOrder === 'asc' ? -1 : 1;
    if (aVal > bVal) return detSortOrder === 'asc' ? 1 : -1;
    return 0;
  });

  const totalDetPages = Math.max(1, Math.ceil(sortedDetections.length / detPageSize));
  const paginatedDetections = sortedDetections.slice((detPage - 1) * detPageSize, detPage * detPageSize);

  // Software Sorting & Pagination
  const [swSortField, setSwSortField] = useState<string>('product_name');
  const [swSortOrder, setSwSortOrder] = useState<'asc' | 'desc'>('asc');
  const [swPage, setSwPage] = useState<number>(1);
  const [swPageSize, setSwPageSize] = useState<number>(10);

  const handleSwSort = (field: string) => {
    if (swSortField === field) {
      setSwSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSwSortField(field);
      setSwSortOrder('asc');
    }
    setSwPage(1);
  };

  const sortedSoftware = [...softwareList].sort((a, b) => {
    let aVal: any = a[swSortField as keyof SoftwareItem];
    let bVal: any = b[swSortField as keyof SoftwareItem];

    if (typeof aVal === 'string') {
      aVal = aVal.toLowerCase();
      bVal = (bVal || '').toLowerCase();
    }

    if (aVal < bVal) return swSortOrder === 'asc' ? -1 : 1;
    if (aVal > bVal) return swSortOrder === 'asc' ? 1 : -1;
    return 0;
  });

  const totalSwPages = Math.max(1, Math.ceil(sortedSoftware.length / swPageSize));
  const paginatedSoftware = sortedSoftware.slice((swPage - 1) * swPageSize, swPage * swPageSize);

  const fetchAssetDetail = async () => {
    setIsLoading(true);
    try {
      const [assetRes, swRes] = await Promise.all([
        apiClient.get(`/assets/${assetId}`),
        apiClient.get(`/assets/${assetId}/software`).catch(() => ({ data: [] })),
      ]);
      setAsset(assetRes.data);
      setSoftwareList(swRes.data);
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

  const handleConfirmDelete = async () => {
    if (!asset) return;
    setIsDeleting(true);
    try {
      await apiClient.delete(`/assets/${asset.id}`, {
        data: { reason: deleteReason.trim() || undefined },
      });
      setIsDeleteModalOpen(false);
      onBack();
    } catch (err: any) {
      console.error('Failed to remove asset', err);
      alert(err.response?.data?.detail || 'Failed to remove asset.');
    } finally {
      setIsDeleting(false);
    }
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
    <div className="p-6 max-w-8xl mx-auto space-y-6">
      {/* Top Navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-slate-100 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Assets
        </button>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <button
              onClick={() => {
                setDeleteReason('');
                setIsDeleteModalOpen(true);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-950/40 hover:bg-red-900/60 text-xs font-semibold text-red-400 border border-red-800/40 hover:border-red-700 transition-colors"
              title="Permanently remove asset from system (Admin Only)"
            >
              <Trash2 className="w-3.5 h-3.5" /> Remove Host
            </button>
          )}
          <button
            onClick={fetchAssetDetail}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700"
          >
            <RefreshCw className="w-3.5 h-3.5 text-sky-400" /> Refresh Dossier
          </button>
        </div>
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
            <div className="text-center" title="Scale: Low (<15), Medium (15-39), High (40-79), Critical (≥80)">
              <div className="text-[10px] uppercase font-semibold text-slate-400">Risk Score</div>
              <div className="text-xl font-bold font-mono text-rose-400">{asset.risk_score}</div>
              <div className="text-[10px] text-slate-500 font-mono">
                {asset.risk_score >= 80 ? '≥80 Crit' : asset.risk_score >= 40 ? '≥40 High' : asset.risk_score >= 15 ? '≥15 Med' : '<15 Low'}
              </div>
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
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Bug className="w-4 h-4 text-red-400" /> Detected Vulnerabilities & KnowledgeBase Remediation Guidance
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Select any finding to inspect Qualys KB solutions, vendor patch links, CVE references, and scanner proof.
            </p>
          </div>

          {/* Detections Search / CVE Filter Input */}
          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Filter findings by CVE, QID, or title..."
              value={detSearch}
              onChange={(e) => {
                const val = e.target.value;
                setDetSearch(val);
                setDetPage(1);
                setSearchParams((prev) => {
                  if (val.trim()) {
                    prev.set('cve', val.trim());
                  } else {
                    prev.delete('cve');
                  }
                  return prev;
                });
              }}
              className="w-full bg-slate-950 border border-surfaceBorder rounded-lg pl-9 pr-7 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
            />
            {detSearch && (
              <button
                type="button"
                onClick={() => {
                  setDetSearch('');
                  setSearchParams((prev) => {
                    prev.delete('cve');
                    return prev;
                  });
                  setDetPage(1);
                }}
                className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-200"
                title="Clear finding filter"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {detSearch && (
          <div className="flex items-center justify-between p-2.5 rounded-lg bg-sky-950/40 border border-sky-800/60 text-sky-300 text-xs font-medium">
            <div className="flex items-center gap-2">
              <Bug className="w-4 h-4 text-sky-400 shrink-0" />
              <span>
                Filtering findings matching <strong className="font-mono text-white underline decoration-sky-500">{detSearch}</strong> ({filteredDetections.length} of {asset.detections.length} findings)
              </span>
            </div>
            <button
              type="button"
              onClick={() => {
                setDetSearch('');
                setSearchParams((prev) => {
                  prev.delete('cve');
                  return prev;
                });
                setDetPage(1);
              }}
              className="text-xs text-slate-300 hover:text-white px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors"
            >
              Show All Findings
            </button>
          </div>
        )}

        <div className="overflow-x-auto rounded-xl border border-surfaceBorder">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder select-none">
              <tr>
                <th
                  onClick={() => handleDetSort('severity')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Severity & QID</span>
                    {detSortField === 'severity' ? (
                      detSortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleDetSort('title')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Vulnerability Title</span>
                    {detSortField === 'title' ? (
                      detSortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleDetSort('category')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Category & Port</span>
                    {detSortField === 'category' ? (
                      detSortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th className="py-3 px-4 font-semibold">Threat Intel Flags (RTI)</th>
                <th
                  onClick={() => handleDetSort('status')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Remediation Status</span>
                    {detSortField === 'status' ? (
                      detSortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th className="py-3 px-4 text-right font-semibold">Fix Guidance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {paginatedDetections.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    No active detections on this asset.
                  </td>
                </tr>
              ) : (
                paginatedDetections.map((det) => {
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

        {/* Detections Pagination */}
        <TablePagination
          currentPage={detPage}
          totalPages={totalDetPages}
          totalItems={sortedDetections.length}
          pageSize={detPageSize}
          onPageChange={setDetPage}
          onPageSizeChange={setDetPageSize}
          pageSizeOptions={[10, 25, 50]}
          label="detections"
        />
      </div>

      {/* Installed Software Inventory (Proactive MISP Match Target) */}
      <div className="p-6 rounded-2xl bg-surface border border-surfaceBorder space-y-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Package className="w-4 h-4 text-sky-400" /> Installed Software & Packages Inventory
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Software packages discovered on this host, used for proactive MISP (FS-ISAC) pre-scan vulnerability assessments.
          </p>
        </div>

        {softwareList.length === 0 ? (
          <div className="p-6 text-center text-slate-500 rounded-xl bg-slate-900/40 border border-slate-800 text-xs italic">
            No software packages cataloged for this host yet.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-surfaceBorder">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder select-none">
                <tr>
                  <th
                    onClick={() => handleSwSort('product_name')}
                    className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                  >
                    <div className="inline-flex items-center gap-1 font-semibold">
                      <span>Product Name</span>
                      {swSortField === 'product_name' ? (
                        swSortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                      )}
                    </div>
                  </th>
                  <th
                    onClick={() => handleSwSort('version')}
                    className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                  >
                    <div className="inline-flex items-center gap-1 font-semibold">
                      <span>Installed Version</span>
                      {swSortField === 'version' ? (
                        swSortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                      )}
                    </div>
                  </th>
                  <th
                    onClick={() => handleSwSort('package_name')}
                    className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                  >
                    <div className="inline-flex items-center gap-1 font-semibold">
                      <span>Package Name</span>
                      {swSortField === 'package_name' ? (
                        swSortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                      )}
                    </div>
                  </th>
                  <th
                    onClick={() => handleSwSort('install_path')}
                    className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                  >
                    <div className="inline-flex items-center gap-1 font-semibold">
                      <span>Binary / Path</span>
                      {swSortField === 'install_path' ? (
                        swSortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                      )}
                    </div>
                  </th>
                  <th
                    onClick={() => handleSwSort('port')}
                    className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                  >
                    <div className="inline-flex items-center gap-1 font-semibold">
                      <span>Port</span>
                      {swSortField === 'port' ? (
                        swSortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                      ) : (
                        <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                      )}
                    </div>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surfaceBorder">
                {paginatedSoftware.map((sw) => (
                  <tr key={sw.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-sky-300 font-mono">
                      {sw.product_name}
                      {sw.vendor && <span className="text-[10px] text-slate-500 font-normal block">{sw.vendor}</span>}
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-slate-100">
                      v{sw.version}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {sw.package_name || '—'}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {sw.install_path || 'system default'}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {sw.port ? `TCP/${sw.port}` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Software Pagination */}
        {softwareList.length > 0 && (
          <TablePagination
            currentPage={swPage}
            totalPages={totalSwPages}
            totalItems={sortedSoftware.length}
            pageSize={swPageSize}
            onPageChange={setSwPage}
            onPageSizeChange={setSwPageSize}
            pageSizeOptions={[10, 25, 50]}
            label="packages"
          />
        )}
      </div>

      {/* Slide-over Remediation Drawer */}
      <RemediationDrawer
        detection={selectedDetection}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        onStatusUpdated={fetchAssetDetail}
      />

      {/* Delete Confirmation Modal (Admin Only) */}
      {isDeleteModalOpen && asset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className="bg-surface border border-surfaceBorder rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-surfaceBorder">
              <div className="flex items-center gap-2 text-red-400">
                <AlertTriangle className="w-5 h-5 shrink-0" />
                <h3 className="text-sm font-bold text-slate-100">Remove Asset from Alert System</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsDeleteModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300">
              <p>
                Are you sure you want to permanently remove this host from the alert dashboard?
              </p>

              <div className="p-3 rounded-xl bg-slate-950 border border-surfaceBorder space-y-1 font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Server Name:</span>
                  <span className="text-sky-300 font-bold">{asset.server_name || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Host IP:</span>
                  <span className="text-slate-200">{asset.ip_address}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Risk Score:</span>
                  <span className="text-orange-400 font-semibold">{asset.risk_score} ({asset.risk_level})</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Active Vulns:</span>
                  <span className="text-red-400 font-semibold">{asset.total_vulns} ({asset.critical_vulns} Crit)</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-red-950/30 border border-red-900/50 text-red-300 text-[11px] leading-relaxed">
                <strong>Administrative Audit Notice:</strong> Removing this asset permanently deletes its detections, risk scoring, software inventory, and generated alerts. A permanent audit record will be logged with your administrator identity.
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Reason for Decommissioning / Removal (Recorded in Audit Log):
                </label>
                <input
                  type="text"
                  placeholder="e.g., Host decommissioned, IP retired, server rebuilt..."
                  value={deleteReason}
                  onChange={(e) => setDeleteReason(e.target.value)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-surfaceBorder">
              <button
                type="button"
                onClick={() => setIsDeleteModalOpen(false)}
                disabled={isDeleting}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDelete}
                disabled={isDeleting}
                className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-xs font-bold text-white shadow-lg shadow-red-600/20 transition-all flex items-center gap-1.5 disabled:opacity-50"
              >
                {isDeleting ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Removing Asset...
                  </>
                ) : (
                  <>
                    <Trash2 className="w-3.5 h-3.5" />
                    Confirm Removal
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
