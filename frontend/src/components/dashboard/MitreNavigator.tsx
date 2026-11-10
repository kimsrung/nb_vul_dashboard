import React, { useState, useEffect } from 'react';
import {
  ShieldCheck, Target, Terminal, ExternalLink,
  ArrowRight, CheckCircle2, Layers,
  RefreshCw, Check, Copy, Flame
} from 'lucide-react';
import {
  MitreMatrixResponse,
  MitreTacticSummary,
  MitreTechnique,
  ThreatReadinessResponse,
  apiClient,
} from '../../api/client';

export const MitreNavigator: React.FC = () => {
  const [matrix, setMatrix] = useState<MitreMatrixResponse | null>(null);
  const [readiness, setReadiness] = useState<ThreatReadinessResponse | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<MitreTacticSummary | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [copiedQuery, setCopiedQuery] = useState<string | null>(null);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [matrixRes, readinessRes] = await Promise.all([
        apiClient.get<MitreMatrixResponse>('/mitre/matrix'),
        apiClient.get<ThreatReadinessResponse>('/dashboard/threat-readiness'),
      ]);
      setMatrix(matrixRes.data);
      setReadiness(readinessRes.data);

      // Default select the first tactic with active threats, or TA0001 (Initial Access)
      const activeTactic =
        matrixRes.data.tactics.find((t) => t.active_threats_count > 0) ||
        matrixRes.data.tactics.find((t) => t.id === 'TA0001') ||
        matrixRes.data.tactics[0];

      if (activeTactic) {
        setSelectedTactic(activeTactic);
        if (activeTactic.techniques.length > 0) {
          setSelectedTechnique(activeTactic.techniques[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load MITRE ATT&CK telemetry', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSelectTactic = (tactic: MitreTacticSummary) => {
    setSelectedTactic(tactic);
    if (tactic.techniques.length > 0) {
      setSelectedTechnique(tactic.techniques[0]);
    } else {
      setSelectedTechnique(null);
    }
  };

  const handleCopyQuery = (query: string, id: string) => {
    navigator.clipboard.writeText(query);
    setCopiedQuery(id);
    setTimeout(() => setCopiedQuery(null), 2000);
  };

  if (isLoading) {
    return (
      <div className="p-12 flex flex-col items-center justify-center gap-3">
        <RefreshCw className="w-8 h-8 text-primary-500 animate-spin" />
        <p className="text-xs text-slate-400 font-mono">Analyzing MITRE ATT&CK Kill-Chain & Threat Readiness...</p>
      </div>
    );
  }

  if (!matrix || !readiness) {
    return null;
  }

  return (
    <div className="space-y-6">
      {/* Executive Threat Readiness Header */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Readiness Index Score Card */}
        <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-indigo-950/40 border border-surfaceBorder shadow-xl flex flex-col justify-between mitre-score-card">
          <div>
            <div className="flex items-center justify-between text-xs font-semibold text-slate-400 mb-2">
              <span className="flex items-center gap-1.5 uppercase tracking-wider text-[10px] text-primary-400 font-bold">
                <ShieldCheck className="w-3.5 h-3.5" /> Threat Readiness Index
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-primary-950 text-primary-300 border border-primary-800 mitre-pill-badge">
                Live Posture
              </span>
            </div>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-4xl font-black text-slate-100 font-mono score-val">
                {readiness.overall_readiness_score}%
              </span>
              <span className="text-xs font-semibold text-emerald-400 score-grade">
                {readiness.readiness_grade}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed score-summary">
              {readiness.status_summary}
            </p>
          </div>

          <div className="pt-3 border-t border-surfaceBorder mt-4 flex items-center justify-between text-[11px] text-slate-400 font-mono score-footer">
            <span>Shield Rate: <b className="text-emerald-400">{readiness.proactive_shield_rate}%</b></span>
            <span>MITRE Coverage: <b className="text-sky-400">{readiness.mitre_coverage_percentage}%</b></span>
          </div>
        </div>

        {/* Banking Critical Infrastructure Tiers */}
        {readiness.tier_breakdown.map((tier) => {
          const isT1 = tier.tier_level === 1;
          const hasCritCVEs = tier.critical_cves_count > 0;
          const hasThreats = tier.active_threats_count > 0;

          // Only highlight if there is actual risk / active exposure
          const cardExposureClass = hasCritCVEs
            ? 'bg-gradient-to-br from-slate-900 via-slate-900 to-rose-950/30 border-rose-800/50 mitre-tier-danger-card'
            : hasThreats
            ? 'bg-gradient-to-br from-slate-900 via-slate-900 to-amber-950/30 border-amber-800/40 mitre-tier-warning-card'
            : 'bg-slate-900/80 border-surfaceBorder';

          return (
            <div
              key={tier.tier_level}
              className={`p-5 rounded-2xl border shadow-xl flex flex-col justify-between mitre-tier-card ${cardExposureClass}`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1 tier-badge">
                    <Layers className={`w-3.5 h-3.5 ${isT1 ? 'text-amber-400' : 'text-slate-400'}`} />
                    Tier {tier.tier_level}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold mitre-pill-badge ${
                      tier.status === 'Optimal'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : tier.status === 'Good'
                        ? 'bg-sky-950 text-sky-300 border border-sky-800'
                        : tier.status === 'Critical_Exposure'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : 'bg-amber-950 text-amber-300 border border-amber-800'
                    }`}
                  >
                    {tier.status.replace('_', ' ')}
                  </span>
                </div>

                <h4 className="text-xs font-bold text-slate-100 line-clamp-1 tier-title">{tier.tier_name}</h4>

                <div className="flex items-baseline gap-2 mt-2">
                  <span className="text-2xl font-bold font-mono text-slate-100 tier-pct">
                    {tier.readiness_percentage}%
                  </span>
                  <span className="text-[11px] text-slate-400 font-mono tier-sub">
                    ({tier.clean_assets}/{tier.total_assets} hosts safe)
                  </span>
                </div>
              </div>

              <div className="pt-3 border-t border-surfaceBorder mt-3 flex items-center justify-between text-[11px] text-slate-400 font-mono tier-footer">
                <span>Critical CVEs: <b className={tier.critical_cves_count > 0 ? 'text-red-400' : 'text-slate-300'}>{tier.critical_cves_count}</b></span>
                <span>Active Threats: <b className="text-amber-400">{tier.active_threats_count}</b></span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Recommended Defensive Actions Banner */}
      {readiness.top_recommended_actions && readiness.top_recommended_actions.length > 0 && (
        <div className="p-4 rounded-xl bg-slate-900 border border-surfaceBorder space-y-3 mitre-priority-actions-banner">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5 banner-heading">
              <ShieldCheck className="w-4 h-4 text-emerald-400" /> Priority Compensating Controls (Recommended Next Actions)
            </span>
            <span className="text-[11px] text-slate-400 banner-sub">Zero-downtime defensive measures</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {readiness.top_recommended_actions.map((act, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1 hover:border-slate-700 transition-colors mitre-action-card"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 mitre-action-badge">
                    {act.action_type}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">{act.target_scope}</span>
                </div>
                <h5 className="text-xs font-bold text-slate-200 act-title">{act.title}</h5>
                <p className="text-[11px] text-slate-400 leading-relaxed act-desc">{act.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Matrix: 14 Enterprise Tactics */}
      <div className="p-5 rounded-2xl bg-surface border border-surfaceBorder space-y-4 shadow-xl mitre-matrix-container">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2 matrix-title">
              <Target className="w-4 h-4 text-amber-400" />
              MITRE ATT&CK Enterprise Matrix Navigation
            </h3>
            <p className="text-xs text-slate-400 mt-0.5 matrix-desc">
              Select an adversary tactic across the cyber kill-chain to inspect techniques, affected banking assets, and safe compensating controls.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span className="px-2 py-1 rounded bg-slate-900 border border-slate-800 matrix-tech-count">
              Total Techniques: <b className="text-amber-400">{matrix.total_techniques_mapped}</b>
            </span>
          </div>
        </div>

        {/* 14 Tactics Horizontal Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2">
          {matrix.tactics.map((tactic) => {
            const isSelected = selectedTactic?.id === tactic.id;
            const hasThreats = tactic.active_threats_count > 0;
            const hasCritTier = tactic.critical_tier_exposure_count > 0;

            return (
              <button
                key={tactic.id}
                onClick={() => handleSelectTactic(tactic)}
                className={`p-2.5 rounded-xl border text-left flex flex-col justify-between transition-all cursor-pointer mitre-tactic-btn ${
                  isSelected
                    ? 'bg-amber-950/40 border-amber-500 text-slate-100 shadow-md ring-1 ring-amber-500/50 is-selected'
                    : hasThreats
                    ? 'bg-slate-900/90 border-surfaceBorder hover:border-slate-700 text-slate-300 has-threats'
                    : 'bg-slate-950/40 border-slate-900 text-slate-500 opacity-60 hover:opacity-100 is-clean'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                    <span className="font-semibold text-slate-400 tactic-id">{tactic.id}</span>
                    <span className="text-slate-500 tactic-order">#{tactic.kill_chain_order}</span>
                  </div>
                  <div className="text-xs font-bold leading-tight line-clamp-1 tactic-title">{tactic.short_name}</div>
                </div>

                <div className="mt-2.5 pt-2 border-t border-slate-800 flex items-center justify-between text-[10px] font-mono tactic-footer">
                  <span className={hasThreats ? 'text-amber-400 font-bold' : 'text-slate-500'}>
                    {tactic.active_threats_count} threat{tactic.active_threats_count !== 1 ? 's' : ''}
                  </span>
                  {hasCritTier && (
                    <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" title="Bakong/SWIFT Critical Tier Exposed" />
                  )}
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected Tactic Drill-down Panel */}
        {selectedTactic && (
          <div className="mt-4 pt-4 border-t border-surfaceBorder space-y-4 mitre-drilldown-panel">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-slate-900/60 p-3 rounded-xl border border-slate-800 mitre-drilldown-header">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800 mitre-pill-badge">
                  {selectedTactic.id}
                </span>
                <h4 className="text-sm font-bold text-slate-100 drilldown-title">{selectedTactic.name}</h4>
                <span className="text-xs text-slate-400 hidden md:inline drilldown-desc">— {selectedTactic.description}</span>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono drilldown-stats">
                <span className="text-slate-300">
                  Affected Assets: <b className="text-sky-400">{selectedTactic.affected_assets_count}</b>
                </span>
                <span className="text-slate-300">
                  Critical Tier: <b className={selectedTactic.critical_tier_exposure_count > 0 ? 'text-red-400' : 'text-slate-400'}>{selectedTactic.critical_tier_exposure_count}</b>
                </span>
              </div>
            </div>

            {/* Techniques under this Tactic */}
            {selectedTactic.techniques.length === 0 ? (
              <div className="p-8 rounded-xl bg-slate-950/60 border border-surfaceBorder text-center text-slate-400 text-xs mitre-empty-box">
                <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-1.5 opacity-80" />
                No active vulnerabilities or threats in your inventory currently map to {selectedTactic.name}.
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Technique Selection List */}
                <div className="space-y-2">
                  <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block tech-list-heading">
                    Detected Techniques ({selectedTactic.techniques.length}):
                  </span>
                  <div className="space-y-1.5">
                    {selectedTactic.techniques.map((tech) => {
                      const isTechSelected = selectedTechnique?.id === tech.id;
                      return (
                        <button
                          key={tech.id}
                          onClick={() => setSelectedTechnique(tech)}
                          className={`w-full p-3 rounded-xl border text-left transition-colors cursor-pointer flex items-center justify-between mitre-technique-btn ${
                            isTechSelected
                              ? 'bg-primary-950/40 border-primary-500 text-slate-100 shadow-sm is-active'
                              : 'bg-slate-900/60 border-surfaceBorder hover:border-slate-700 text-slate-300'
                          }`}
                        >
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono font-bold text-xs text-sky-400 tech-id">{tech.id}</span>
                              <span className="text-xs font-semibold tech-name">{tech.name}</span>
                            </div>
                            <div className="text-[10px] text-slate-400 font-mono mt-0.5 tech-impact">
                              Impact: <b className="text-red-400">{tech.severity_impact}</b>
                            </div>
                          </div>
                          <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Technique Dossier: Adversary Context + Compensating Controls */}
                {selectedTechnique && (
                  <div className="lg:col-span-2 space-y-4 p-4 rounded-xl bg-slate-950 border border-surfaceBorder mitre-dossier-panel">
                    <div className="flex items-center justify-between border-b border-surfaceBorder pb-3 dossier-header">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800 mitre-pill-badge">
                            {selectedTechnique.id}
                          </span>
                          <h4 className="text-sm font-bold text-slate-100 dossier-tech-name">{selectedTechnique.name}</h4>
                        </div>
                        <p className="text-xs text-slate-400 mt-1 dossier-tech-desc">{selectedTechnique.description}</p>
                      </div>
                      <a
                        href={selectedTechnique.url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1 shrink-0 mitre-link"
                      >
                        MITRE Link <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>

                    {/* Adversary Perspective */}
                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1 mitre-adversary-box">
                      <span className="text-[10px] uppercase font-bold text-amber-400 block tracking-wider flex items-center gap-1">
                        <Flame className="w-3.5 h-3.5" /> Adversary Weaponization (Banking Sector Impact):
                      </span>
                      <p className="text-xs text-slate-300 leading-relaxed font-sans adversary-text">
                        {selectedTechnique.adversary_perspective}
                      </p>
                    </div>

                    {/* Safe Compensating Controls */}
                    {selectedTechnique.compensating_controls && selectedTechnique.compensating_controls.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-[10px] uppercase font-bold text-emerald-400 block tracking-wider flex items-center gap-1 mitre-controls-heading">
                          <ShieldCheck className="w-3.5 h-3.5" /> Safe Compensating Controls (Zero Production Downtime):
                        </span>
                        <div className="space-y-2">
                          {selectedTechnique.compensating_controls.map((ctrl) => (
                            <div
                              key={ctrl.id}
                              className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5 mitre-control-card"
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-bold text-slate-200 text-xs flex items-center gap-1.5">
                                  <span className="font-mono text-emerald-400 ctrl-id">{ctrl.id}</span> — <span className="ctrl-name">{ctrl.name}</span>
                                </span>
                                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono ctrl-cat">
                                  {ctrl.category}
                                </span>
                              </div>
                              <p className="text-xs text-slate-400 ctrl-desc">{ctrl.description}</p>
                              <ul className="text-xs text-slate-300 space-y-0.5 pt-1">
                                {ctrl.implementation_steps.map((step, idx) => (
                                  <li key={idx} className="flex items-start gap-1">
                                    <span className="text-emerald-400 font-bold ctrl-bullet">•</span>
                                    <span>{step}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Detection Guidance */}
                    {selectedTechnique.detection_guidance && (
                      <div className="space-y-2">
                        <span className="text-[10px] uppercase font-bold text-sky-400 block tracking-wider flex items-center gap-1">
                          <Terminal className="w-3.5 h-3.5" /> Detection Telemetry & Sample Query:
                        </span>
                        <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2 mitre-detection-box">
                          <div className="text-[11px] text-slate-300 detection-indicators">
                            <b>Indicators:</b> {selectedTechnique.detection_guidance.indicator_summary}
                          </div>
                          {selectedTechnique.detection_guidance.sample_query && (
                            <div className="space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] text-slate-400 font-mono">Sample Detection Command:</span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyQuery(selectedTechnique.detection_guidance!.sample_query!, selectedTechnique.id)}
                                  className="text-[10px] font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1 cursor-pointer"
                                >
                                  {copiedQuery === selectedTechnique.id ? (
                                    <>
                                      <Check className="w-3 h-3 text-emerald-400" /> Copied!
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-3 h-3" /> Copy
                                    </>
                                  )}
                                </button>
                              </div>
                              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-400 overflow-x-auto mitre-terminal-box">
                                <code className="mitre-terminal-code">{selectedTechnique.detection_guidance.sample_query}</code>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
