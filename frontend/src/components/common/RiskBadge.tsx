import React from 'react';

interface RiskBadgeProps {
  level: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  score?: number;
  className?: string;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, score, className = '' }) => {
  const norm = level.toLowerCase();
  
  let colorStyles = 'bg-slate-800 text-slate-300 border-slate-700';
  let dotColor = 'bg-slate-400';

  if (norm === 'critical') {
    colorStyles = 'bg-red-500/10 text-red-400 border-red-500/30';
    dotColor = 'bg-red-500 animate-pulse';
  } else if (norm === 'high') {
    colorStyles = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    dotColor = 'bg-amber-500';
  } else if (norm === 'medium') {
    colorStyles = 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30';
    dotColor = 'bg-yellow-400';
  } else if (norm === 'low') {
    colorStyles = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    dotColor = 'bg-emerald-500';
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${colorStyles} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      <span>{level}</span>
      {score !== undefined && <span className="opacity-75 font-mono text-[11px]">({score})</span>}
    </span>
  );
};
