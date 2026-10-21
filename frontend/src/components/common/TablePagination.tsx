import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

interface TablePaginationProps {
  currentPage: number;
  totalPages: number;
  totalItems: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
  pageSizeOptions?: number[];
  label?: string;
}

export const TablePagination: React.FC<TablePaginationProps> = ({
  currentPage,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [10, 25, 50],
  label = 'items',
}) => {
  if (totalItems === 0) return null;

  const startItem = Math.min((currentPage - 1) * pageSize + 1, totalItems);
  const endItem = Math.min(currentPage * pageSize, totalItems);

  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-4 border-t border-surfaceBorder text-xs text-slate-400 select-none">
      <div className="flex items-center gap-2">
        <span>
          Showing <span className="text-slate-200 font-semibold">{startItem}</span> to{' '}
          <span className="text-slate-200 font-semibold">{endItem}</span> of{' '}
          <span className="text-slate-200 font-semibold">{totalItems}</span> {label}
        </span>
        {onPageSizeChange && (
          <div className="flex items-center gap-1.5 ml-4">
            <span className="text-[11px] text-slate-500">Per page:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                onPageSizeChange(Number(e.target.value));
                onPageChange(1);
              }}
              className="bg-slate-950 border border-surfaceBorder rounded px-2 py-0.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 cursor-pointer"
            >
              {pageSizeOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div className="flex items-center gap-1.5">
        <span className="text-slate-400 mr-2">
          Page <span className="font-semibold text-slate-200">{currentPage}</span> of{' '}
          <span className="font-semibold text-slate-200">{Math.max(1, totalPages)}</span>
        </span>
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage <= 1}
          className="p-1.5 rounded-lg border border-surfaceBorder bg-slate-900/80 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition-colors"
          title="Previous page"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages}
          className="p-1.5 rounded-lg border border-surfaceBorder bg-slate-900/80 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition-colors"
          title="Next page"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
