import React from 'react';

interface RemediationStatusBadgeProps {
  status: 'Open' | 'In_Progress' | 'Acknowledged' | 'False_Positive' | 'Resolved' | string;
  className?: string;
}

export const RemediationStatusBadge: React.FC<RemediationStatusBadgeProps> = ({ status, className = '' }) => {
  let style = 'bg-slate-800 text-slate-300 border-slate-700';
  let display = status.replace('_', ' ');

  switch (status) {
    case 'Open':
      style = 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      break;
    case 'In_Progress':
      style = 'bg-sky-500/10 text-sky-400 border-sky-500/20';
      break;
    case 'Acknowledged':
      style = 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      break;
    case 'False_Positive':
      style = 'bg-purple-500/10 text-purple-400 border-purple-500/20';
      break;
    case 'Resolved':
      style = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      break;
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${style} ${className}`}>
      {display}
    </span>
  );
};
