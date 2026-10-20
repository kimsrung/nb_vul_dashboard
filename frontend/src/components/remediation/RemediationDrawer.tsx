import React, { useState } from 'react';
import { X, ExternalLink, ShieldAlert, Wrench, Bug, FileCode, CheckCircle2, Clock } from 'lucide-react';
import { DetectionItem, apiClient } from '../../api/client';
import { SeverityTag } from '../common/SeverityTag';
import { RemediationStatusBadge } from '../common/RemediationStatusBadge';
import { useAuth } from '../../context/AuthContext';

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
  const [status, setStatus] = useState<string>(detection?.remediation_status || 'Open');
  const [notes, setNotes] = useState<string>(detection?.remediation_notes || '');
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Sync state when detection changes
  React.useEffect(() => {
    if (detection) {
      setStatus(detection.remediation_status);
      setNotes(detection.remediation_notes || '');
      setSaveSuccess(false);
      setErrorMsg(null);
    }
  }, [detection]);

  if (!isOpen || !detection) return null;

  const kb = detection.knowledge_base;
  const ti = kb?.threat_intel_flags || {};

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

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Solution & Remediation */}
          <section className="bg-sky-950/20 border border-sky-900/40 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-sky-400 flex items-center gap-2 mb-2">
              <Wrench className="w-4 h-4" /> Qualys KnowledgeBase Solution & Fix Steps
            </h3>
            <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-line">
              {kb?.solution || 'No specific solution provided by Qualys KnowledgeBase for this QID. Review vendor documentation.'}
            </p>
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
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line">
                {kb.workaround}
              </p>
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
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line">
                {kb.diagnosis}
              </p>
            </section>
          )}

          {kb?.consequence && (
            <section className="bg-slate-900/50 border border-surfaceBorder rounded-xl p-4">
              <h3 className="text-sm font-semibold text-slate-300 mb-2">Consequence / Impact</h3>
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line">
                {kb.consequence}
              </p>
            </section>
          )}

          {/* Remediation Action Workflow Tracker */}
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
