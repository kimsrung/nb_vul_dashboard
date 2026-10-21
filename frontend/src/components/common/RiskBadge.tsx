import React from 'react';

interface RiskBadgeProps {
  level: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  score?: number;
  className?: string;
  showTooltip?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ 
  level, 
  score, 
  className = '',
  showTooltip = true 
}) => {
  const norm = level.toLowerCase();
  
  let colorStyles = 'bg-slate-800 text-slate-300 border-slate-700';
  let dotColor = 'bg-slate-400';
  let thresholdDesc = 'Scale: Low (<15), Med (15-39), High (40-79), Crit (≥80)';

  if (norm === 'critical') {
    colorStyles = 'bg-red-500/10 text-red-400 border-red-500/30';
    dotColor = 'bg-red-500 animate-pulse';
    thresholdDesc = 'Critical Tier (Score ≥80 or Active Critical RTI like Ransomware/Zero-Day)';
  } else if (norm === 'high') {
    colorStyles = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    dotColor = 'bg-amber-500';
    thresholdDesc = 'High Tier (Score 40-79, or SLA breach >30/60d, or Sev 5 vuln present)';
  } else if (norm === 'medium') {
    colorStyles = 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30';
    dotColor = 'bg-yellow-400';
    thresholdDesc = 'Medium Tier (Score 15-39 or Sev 4 vuln present)';
  } else if (norm === 'low') {
    colorStyles = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    dotColor = 'bg-emerald-500';
    thresholdDesc = 'Low Tier (Score <15, minor or informational findings)';
  }

  const tooltipText = showTooltip 
    ? `Risk Level: ${level}${score !== undefined ? ` • Score: ${score}` : ''} | ${thresholdDesc}`
    : undefined;

  return (
    <span
      title={tooltipText}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${colorStyles} ${className} cursor-help`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      <span>{level}</span>
      {score !== undefined && <span className="opacity-80 font-mono text-[11px]">({score})</span>}
    </span>
  );
};
