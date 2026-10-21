/**
 * Formats a date string, timestamp, or Date object as YYYY-MM-DD.
 * Returns fallback (e.g. '—' or 'Never' or 'N/A') if null, undefined, or invalid.
 */
export const formatDateYMD = (
  val: string | number | Date | null | undefined,
  fallback: string = '—'
): string => {
  if (!val) return fallback;
  if (typeof val === 'string') {
    const trimmed = val.trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
      return trimmed;
    }
  }
  const d = new Date(val);
  if (isNaN(d.getTime())) return String(val);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
};

/**
 * Formats a date string, timestamp, or Date object as YYYY-MM-DD HH:mm (or with seconds if requested).
 * Returns fallback (e.g. '—' or 'Never' or 'N/A') if null, undefined, or invalid.
 */
export const formatDateTimeYMD = (
  val: string | number | Date | null | undefined,
  includeSeconds: boolean = false,
  fallback: string = '—'
): string => {
  if (!val) return fallback;
  if (typeof val === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(val.trim())) {
    return val.trim();
  }
  const d = new Date(val);
  if (isNaN(d.getTime())) return String(val);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const hh = String(d.getHours()).padStart(2, '0');
  const min = String(d.getMinutes()).padStart(2, '0');
  if (includeSeconds) {
    const ss = String(d.getSeconds()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
  }
  return `${yyyy}-${mm}-${dd} ${hh}:${min}`;
};

