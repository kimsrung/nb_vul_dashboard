import React from 'react';

interface SeverityTagProps {
  severity: number;
  className?: string;
}

export const SeverityTag: React.FC<SeverityTagProps> = ({ severity, className = '' }) => {
  let bg = 'bg-slate-700 text-slate-300';
  let label = `Sev ${severity}`;

  switch (severity) {
    case 5:
      bg = 'bg-red-600/20 text-red-400 border border-red-500/30';
      label = 'Sev 5 (Critical)';
      break;
    case 4:
      bg = 'bg-orange-600/20 text-orange-400 border border-orange-500/30';
      label = 'Sev 4 (High)';
      break;
    case 3:
      bg = 'bg-yellow-600/20 text-yellow-400 border border-yellow-500/30';
      label = 'Sev 3 (Medium)';
      break;
    case 2:
      bg = 'bg-blue-600/20 text-blue-400 border border-blue-500/30';
      label = 'Sev 2 (Low)';
      break;
    default:
      bg = 'bg-slate-600/20 text-slate-400 border border-slate-500/30';
      label = 'Sev 1 (Info)';
      break;
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${bg} ${className}`}>
      {label}
    </span>
  );
};
