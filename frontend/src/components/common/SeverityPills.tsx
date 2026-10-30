import React from 'react';

interface SeverityPillsProps {
  sev5?: number;
  sev4?: number;
  sev3?: number;
  sev2?: number;
  sev1?: number;
  total?: number;
  compact?: boolean;
  showTotal?: boolean;
}

export const SeverityPills: React.FC<SeverityPillsProps> = ({
  sev5 = 0,
  sev4 = 0,
  sev3 = 0,
  sev2 = 0,
  sev1 = 0,
  total,
  compact = false,
  showTotal = true,
}) => {
  const calculatedTotal = total ?? (sev5 + sev4 + sev3 + sev2 + sev1);

  const pills = [
    {
      level: 5,
      label: 'Sev 5',
      count: sev5,
      bg: sev5 > 0 ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 font-bold' : 'bg-slate-800/40 text-slate-600 border-slate-800',
      dot: 'bg-rose-400',
    },
    {
      level: 4,
      label: 'Sev 4',
      count: sev4,
      bg: sev4 > 0 ? 'bg-orange-500/20 text-orange-300 border-orange-500/40 font-semibold' : 'bg-slate-800/40 text-slate-600 border-slate-800',
      dot: 'bg-orange-400',
    },
    {
      level: 3,
      label: 'Sev 3',
      count: sev3,
      bg: sev3 > 0 ? 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40 font-medium' : 'bg-slate-800/40 text-slate-600 border-slate-800',
      dot: 'bg-yellow-400',
    },
    {
      level: 2,
      label: 'Sev 2',
      count: sev2,
      bg: sev2 > 0 ? 'bg-sky-500/20 text-sky-300 border-sky-500/40 font-medium' : 'bg-slate-800/40 text-slate-600 border-slate-800',
      dot: 'bg-sky-400',
    },
    {
      level: 1,
      label: 'Sev 1',
      count: sev1,
      bg: sev1 > 0 ? 'bg-slate-700/40 text-slate-300 border-slate-600/40' : 'bg-slate-800/40 text-slate-600 border-slate-800',
      dot: 'bg-slate-500',
    },
  ];

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {pills.map((p) => (
        <span
          key={p.level}
          title={`Qualys Severity ${p.level}: ${p.count} detections`}
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border font-mono transition-colors ${
            compact ? 'text-[11px]' : 'text-xs'
          } ${p.bg}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${p.count > 0 ? p.dot : 'bg-slate-700'}`} />
          <span className="text-[10px] text-slate-400 font-sans">{p.level}:</span>
          <span>{p.count}</span>
        </span>
      ))}

      {showTotal && (
        <span
          title="Total open vulnerabilities"
          className={`inline-flex items-center px-2 py-0.5 rounded font-mono font-bold bg-slate-800 border border-slate-700 text-slate-300 ${
            compact ? 'text-[11px]' : 'text-xs'
          }`}
        >
          Σ {calculatedTotal}
        </span>
      )}
    </div>
  );
};
