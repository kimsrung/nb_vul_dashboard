import React, { useState } from 'react';
import { X, ExternalLink, ShieldAlert, Wrench, Bug, FileCode, CheckCircle2, Clock, ShieldCheck, Target, Terminal, Copy, Check } from 'lucide-react';
import { DetectionItem, apiClient } from '../../api/client';
import { SeverityTag } from '../common/SeverityTag';
import { RemediationStatusBadge } from '../common/RemediationStatusBadge';
import { useAuth } from '../../context/AuthContext';
import { formatAndSanitizeHtml } from '../../utils/sanitize';

interface RemediationDrawerProps {
  detection: DetectionItem | null;
  isOpen: boolean;
  onClose: () => void;
  onStatusUpdated?: () => void;
}

export const RemediationDrawer: React.FC<RemediationDrawerProps> = ({
  detection,
  isOpen,
  onClose,
  onStatusUpdated,
}) => {
  const { canRemediate } = useAuth();
  const [activeTab, setActiveTab] = useState<'solution' | 'controls' | 'mitre' | 'detection'>('solution');
  const [status, setStatus] = useState<string>(detection?.remediation_status || 'Open');
  const [notes, setNotes] = useState<string>(detection?.remediation_notes || '');
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedQuery, setCopiedQuery] = useState<string | null>(null);

  // Sync state when detection changes
  React.useEffect(() => {
    if (detection) {
      setStatus(detection.remediation_status);
      setNotes(detection.remediation_notes || '');
      setSaveSuccess(false);
      setErrorMsg(null);
      setActiveTab('solution');
    }
  }, [detection]);

  if (!isOpen || !detection) return null;

  const kb = detection.knowledge_base;
  const ti = kb?.threat_intel_flags || {};
  const mitreTechniques = kb?.mitre_techniques || [];
  const allControls = mitreTechniques.flatMap((t) => t.compensating_controls || []);

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedQuery(id);
    setTimeout(() => setCopiedQuery(null), 2000);
  };

  const handleSave = async () => {
    setIsSaving(true);
    setErrorMsg(null);
    setSaveSuccess(false);
    try {
      await apiClient.patch(`/detections/${detection.id}/remediation`, {
        remediation_status: status,
        remediation_notes: notes,
      });
      setSaveSuccess(true);
      if (onStatusUpdated) onStatusUpdated();
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Failed to update remediation status');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity">
      <div className="w-full max-w-2xl bg-surface border-l border-surfaceBorder h-full flex flex-col shadow-2xl overflow-hidden animate-in slide-in-from-right duration-200">
        {/* Drawer Header */}
        <div className="p-6 border-b border-surfaceBorder flex items-start justify-between bg-slate-900/50">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <SeverityTag severity={detection.severity} />
              <span className="text-xs font-mono text-slate-400">QID: {detection.qid}</span>
              {kb?.cvss_v3 && (
                <span className="px-2 py-0.5 rounded text-xs bg-red-950/40 text-red-300 border border-red-800/40 font-mono">
                  CVSS v3: {kb.cvss_v3}
                </span>
              )}
              <RemediationStatusBadge status={status} />
            </div>
            <h2 className="text-lg font-bold text-slate-100 leading-tight">
              {kb?.title || `Qualys Finding QID ${detection.qid}`}
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Category: <span className="text-slate-300">{kb?.category || 'General'}</span> | Detection: <span className="text-slate-300">{detection.detection_type}</span> | Times Found: <span className="text-slate-300">{detection.times_found}</span>
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Threat Intel / RTI Pills */}
        {(ti.ransomware || ti.active_in_wild || ti.exploit_public || ti.remote_code_execution || ti.zero_day) && (
          <div className="px-6 py-2.5 bg-red-950/20 border-b border-red-900/20 flex flex-wrap gap-2 items-center">
            <span className="text-xs font-semibold text-red-400 flex items-center gap-1">
              <ShieldAlert className="w-3.5 h-3.5" /> Threat Intel Flags:
            </span>
            {ti.ransomware && (
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-600/30 text-red-300 border border-red-500/40">
                Known Ransomware Associated
              </span>
            )}
            {ti.active_in_wild && (
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-orange-600/30 text-orange-300 border border-orange-500/40">
                Active Exploit in Wild
              </span>
            )}
            {ti.zero_day && (
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-purple-600/30 text-purple-300 border border-purple-500/40">
                Zero-Day
              </span>
            )}
            {ti.remote_code_execution && (
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-600/30 text-amber-300 border border-amber-500/40">
                Remote Code Execution
              </span>
            )}
            {ti.exploit_public && (
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-600/30 text-blue-300 border border-blue-500/40">
                Public Exploit Available
              </span>
            )}
          </div>
        )}

        {/* Tab Navigation */}
        <div className="flex border-b border-surfaceBorder bg-slate-900/60 px-6 pt-2 gap-2 text-xs font-semibold overflow-x-auto shrink-0">
          <button
            onClick={() => setActiveTab('solution')}
            className={`pb-2.5 px-3 border-b-2 flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeTab === 'solution'
                ? 'border-primary-500 text-primary-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Wrench className="w-3.5 h-3.5" /> Fix & Patches
          </button>
          <button
            onClick={() => setActiveTab('controls')}
            className={`pb-2.5 px-3 border-b-2 flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeTab === 'controls'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            Compensating Controls
            {allControls.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 remediation-emerald-pill">
                {allControls.length} Safe
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('mitre')}
            className={`pb-2.5 px-3 border-b-2 flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeTab === 'mitre'
                ? 'border-amber-500 text-amber-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Target className="w-3.5 h-3.5 text-amber-400" />
            MITRE ATT&CK
            {mitreTechniques.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-amber-950 text-amber-300 border border-amber-800 remediation-amber-pill">
                {mitreTechniques.map((t) => t.id).join(', ')}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('detection')}
            className={`pb-2.5 px-3 border-b-2 flex items-center gap-1.5 transition-colors cursor-pointer ${
              activeTab === 'detection'
                ? 'border-sky-500 text-sky-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-sky-400" /> Detection Guidance
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'solution' && (
            <>
              {/* Solution & Remediation */}
              <section className="bg-sky-950/20 border border-sky-900/40 rounded-xl p-4">
                <h3 className="text-sm font-semibold text-sky-400 flex items-center gap-2 mb-2">
                  <Wrench className="w-4 h-4" /> Qualys KnowledgeBase Solution & Fix Steps
                </h3>
                <div
                  className="html-solution text-sm text-slate-200 leading-relaxed"
                  dangerouslySetInnerHTML={{
                    __html: formatAndSanitizeHtml(
                      kb?.solution,
                      'No specific solution provided by Qualys KnowledgeBase for this QID. Review vendor documentation.'
                    ),
                  }}
                />
              </section>

              {/* Patches */}
              {kb?.patches && kb.patches.length > 0 && (
                <section className="bg-slate-900/50 border border-surfaceBorder rounded-xl p-4">
                  <h3 className="text-sm font-semibold text-slate-300 mb-2">Vendor Patches & Advisories</h3>
                  <ul className="space-y-1.5">
                    {kb.patches.map((p, idx) => (
                      <li key={idx} className="text-xs flex items-center justify-between">
                        <span className="text-slate-300">{p.description || 'Vendor Patch'}</span>
                        {p.url && (
                          <a
                            href={p.url}
                            target="_blank"
                            rel="noreferrer"
                            className="text-primary-500 hover:text-primary-400 flex items-center gap-1 font-mono"
                          >
                            Link <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
              )}

              {/* Workaround */}
              {kb?.workaround && (
                <section className="bg-slate-900/50 border border-surfaceBorder rounded-xl p-4">
                  <h3 className="text-sm font-semibold text-slate-300 mb-2">Temporary Workaround</h3>
                  <div
                    className="html-solution text-xs text-slate-300 leading-relaxed"
                    dangerouslySetInnerHTML={{ __html: formatAndSanitizeHtml(kb.workaround) }}
                  />
                </section>
              )}

              {/* CVE References */}
              {kb?.cve_list && kb.cve_list.length > 0 && (
                <section className="bg-slate-900/50 border border-surfaceBorder rounded-xl p-4">
                  <h3 className="text-sm font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                    <Bug className="w-4 h-4" /> Associated CVE References
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {kb.cve_list.map((cve) => (
                      <a
                        key={cve}
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 text-sky-400 hover:bg-slate-700 text-xs font-mono border border-slate-700 transition-colors"
                      >
                        {cve} <ExternalLink className="w-3 h-3" />
                      </a>
                    ))}
                  </div>
                </section>
              )}

              {/* Scanner Proof / Results */}
              {detection.scanner_results && (
                <section className="bg-slate-900/50 border border-surfaceBorder rounded-xl p-4">
                  <h3 className="text-sm font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                    <FileCode className="w-4 h-4" /> Qualys Scanner Diagnostic Proof
                  </h3>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto whitespace-pre-wrap">
                    {detection.scanner_results}
                  </div>
                </section>
              )}

              {/* Diagnosis & Consequence */}
              {kb?.diagnosis && (
                <section className="bg-slate-900/50 border border-surfaceBorder rounded-xl p-4">
                  <h3 className="text-sm font-semibold text-slate-300 mb-2">Vulnerability Diagnosis</h3>
                  <div
                    className="html-solution text-xs text-slate-300 leading-relaxed"
                    dangerouslySetInnerHTML={{ __html: formatAndSanitizeHtml(kb.diagnosis) }}
                  />
                </section>
              )}

              {kb?.consequence && (
                <section className="bg-slate-900/50 border border-surfaceBorder rounded-xl p-4">
                  <h3 className="text-sm font-semibold text-slate-300 mb-2">Consequence / Impact</h3>
                  <div
                    className="html-solution text-xs text-slate-300 leading-relaxed"
                    dangerouslySetInnerHTML={{ __html: formatAndSanitizeHtml(kb.consequence) }}
                  />
                </section>
              )}
            </>
          )}

          {activeTab === 'controls' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/60 space-y-1.5 remediation-compensating-banner">
                <div className="flex items-center gap-2 font-bold text-emerald-300 text-xs banner-title">
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 banner-icon" />
                  Safe Compensating Controls (Zero Production Downtime)
                </div>
                <p className="text-emerald-200/80 text-[11px] leading-relaxed banner-text">
                  Cannot patch immediately due to banking change freezes or maintenance windows? These defensive controls shield your system against exploit attempts without restarting packages or interrupting banking transactions.
                </p>
              </div>

              {allControls.length === 0 ? (
                <div className="p-6 rounded-xl bg-slate-900/50 border border-surfaceBorder text-center text-slate-400 text-xs remediation-empty-box">
                  No specific compensating controls identified for this finding. Apply standard network boundary restrictions and vendor patch when feasible.
                </div>
              ) : (
                <div className="space-y-3">
                  {allControls.map((ctrl) => (
                    <div
                      key={ctrl.id}
                      className="p-4 rounded-xl bg-slate-900/80 border border-surfaceBorder space-y-2.5 hover:border-slate-700 transition-colors remediation-control-card"
                    >
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 remediation-emerald-pill">
                            {ctrl.id}
                          </span>
                          <span className="font-bold text-slate-100 text-xs ctrl-card-title">{ctrl.name}</span>
                        </div>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 ctrl-category-tag">
                          {ctrl.category}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed ctrl-card-desc">{ctrl.description}</p>

                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5 remediation-steps-box">
                        <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider steps-heading">
                          Recommended Implementation Steps:
                        </span>
                        <ul className="space-y-1 text-xs text-slate-300 steps-list">
                          {ctrl.implementation_steps.map((step, idx) => (
                            <li key={idx} className="flex items-start gap-1.5">
                              <span className="text-emerald-400 font-bold shrink-0 step-bullet">•</span>
                              <span className="step-text">{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 ctrl-footer">
                        <span>
                          Downtime: <span className="text-emerald-400 font-semibold downtime-tag">{ctrl.downtime_required ? 'Required' : 'Zero Downtime'}</span>
                        </span>
                        <span>
                          Platforms: <span className="text-slate-300 font-mono platform-text">{ctrl.applicable_platforms.join(', ')}</span>
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'mitre' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/60 space-y-1.5 remediation-mitre-banner">
                <div className="flex items-center gap-2 font-bold text-amber-300 text-xs banner-title">
                  <Target className="w-4 h-4 text-amber-400 shrink-0 banner-icon" />
                  Adversary Perspective & MITRE ATT&CK Mapping
                </div>
                <p className="text-amber-200/80 text-[11px] leading-relaxed banner-text">
                  Understand how threat actors, ransomware operators, or APT campaigns weaponize this weakness against banking perimeters and internal networks.
                </p>
              </div>

              {mitreTechniques.length === 0 ? (
                <div className="p-6 rounded-xl bg-slate-900/50 border border-surfaceBorder text-center text-slate-400 text-xs remediation-empty-box">
                  No MITRE ATT&CK technique directly linked. Treat as general software maintenance finding.
                </div>
              ) : (
                <div className="space-y-3">
                  {mitreTechniques.map((tech) => (
                    <div
                      key={tech.id}
                      className="p-4 rounded-xl bg-slate-900/80 border border-surfaceBorder space-y-3 remediation-tech-card"
                    >
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800 remediation-amber-pill">
                            {tech.id}
                          </span>
                          <span className="font-bold text-slate-100 text-xs tech-card-title">{tech.name}</span>
                        </div>
                        <a
                          href={tech.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1 font-mono mitre-link"
                        >
                          MITRE Matrix <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>

                      <div className="flex items-center gap-4 text-[11px] text-slate-400 font-mono tech-card-meta">
                        <span>Tactic: <span className="text-amber-400 font-bold">{tech.tactic_name} ({tech.tactic_id})</span></span>
                        <span>Severity Impact: <span className="text-red-400 font-bold">{tech.severity_impact}</span></span>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed tech-card-desc">{tech.description}</p>

                      <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1 remediation-adversary-box">
                        <span className="text-[10px] uppercase font-bold text-amber-400 block tracking-wider box-heading">
                          How Threat Actors Leverage This (Banking Kill-Chain):
                        </span>
                        <p className="text-xs text-slate-300 leading-relaxed font-sans box-text">
                          {tech.adversary_perspective}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'detection' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-sky-950/30 border border-sky-800/60 space-y-1.5 remediation-detection-banner">
                <div className="flex items-center gap-2 font-bold text-sky-300 text-xs banner-title">
                  <Terminal className="w-4 h-4 text-sky-400 shrink-0 banner-icon" />
                  Security Analyst Detection & Monitoring Guidance
                </div>
                <p className="text-sky-200/80 text-[11px] leading-relaxed banner-text">
                  How to detect if this technique is being probed or exploited on your servers before an intrusion occurs.
                </p>
              </div>

              {mitreTechniques.map((tech) => {
                const det = tech.detection_guidance;
                if (!det) return null;
                return (
                  <div
                    key={tech.id}
                    className="p-4 rounded-xl bg-slate-900/80 border border-surfaceBorder space-y-3 remediation-det-card"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-100 text-xs flex items-center gap-2 det-card-title">
                        <span className="font-mono text-sky-400 det-tech-id">{tech.id}</span> — {tech.name}
                      </span>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider det-log-heading">
                        Monitored Telemetry & Log Sources:
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {det.log_sources.map((src, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px] border border-slate-700 det-src-badge"
                          >
                            {src}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1 remediation-det-indicators">
                      <span className="text-[10px] uppercase font-bold text-sky-400 block tracking-wider det-ind-heading">
                        Detection Indicator:
                      </span>
                      <p className="text-xs text-slate-300 leading-relaxed font-sans det-ind-text">
                        {det.indicator_summary}
                      </p>
                    </div>

                    {det.sample_query && (
                      <div className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider det-query-heading">
                            Sample Log Query:
                          </span>
                          <button
                            type="button"
                            onClick={() => handleCopyText(det.sample_query!, tech.id)}
                            className="flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 font-mono cursor-pointer"
                          >
                            {copiedQuery === tech.id ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" /> Copied!
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" /> Copy Query
                              </>
                            )}
                          </button>
                        </div>
                        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-emerald-400 overflow-x-auto remediation-terminal-box">
                          <code className="remediation-terminal-code">{det.sample_query}</code>
                        </div>
                      </div>
                    )}

                    {det.event_ids && det.event_ids.length > 0 && (
                      <div className="flex items-center gap-2 text-[11px] text-slate-400 det-events">
                        <span>Event IDs / Signatures:</span>
                        <div className="flex flex-wrap gap-1">
                          {det.event_ids.map((eid, idx) => (
                            <span key={idx} className="font-mono text-slate-300 bg-slate-800 px-1.5 py-0.5 rounded det-eid-tag">
                              {eid}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Remediation Action Workflow Tracker (Always available across all tabs) */}
          <section className="bg-slate-900 border border-surfaceBorder rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Clock className="w-4 h-4 text-sky-400" /> Remediation Action Status
              </h3>
              {detection.updated_by && (
                <span className="text-[11px] text-slate-400">
                  Last updated by: <span className="text-slate-300">{detection.updated_by}</span>
                </span>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Status</label>
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  disabled={!canRemediate}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-primary-500 disabled:opacity-60"
                >
                  <option value="Open">Open (Pending)</option>
                  <option value="In_Progress">In Progress</option>
                  <option value="Acknowledged">Acknowledged (Muted 50% Risk)</option>
                  <option value="False_Positive">False Positive (Ignored 0% Risk)</option>
                  <option value="Resolved">Resolved (Fixed 0% Risk)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Remediation Notes & Audit Log</label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                disabled={!canRemediate}
                rows={3}
                placeholder={canRemediate ? "Add patch schedule, ticket link (e.g. JIRA-1234), or reason for acknowledgment..." : "No notes added."}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-primary-500 disabled:opacity-60"
              />
            </div>

            {errorMsg && (
              <p className="text-xs text-red-400">{errorMsg}</p>
            )}

            {saveSuccess && (
              <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                <CheckCircle2 className="w-4 h-4" /> Remediation status updated & asset risk score recalculated!
              </div>
            )}

            {canRemediate && (
              <div className="flex justify-end pt-2">
                <button
                  onClick={handleSave}
                  disabled={isSaving}
                  className="px-4 py-2 rounded-lg bg-primary-600 hover:bg-primary-500 text-white text-xs font-semibold shadow-md transition-colors disabled:opacity-50"
                >
                  {isSaving ? 'Updating...' : 'Save Remediation Status'}
                </button>
              </div>
            )}
            {!canRemediate && (
              <p className="text-[11px] text-slate-500 italic">
                * Read-only mode. Only assigned Owners, Analysts, or Admins can update remediation statuses.
              </p>
            )}
          </section>
        </div>
      </div>
    </div>
  );
};
