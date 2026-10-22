export const TIMEZONE_PHNOM_PENH = 'Asia/Phnom_Penh';

/**
 * Safely parses any date string, timestamp, or Date into a Date object.
 * Strings without explicit timezone offset are treated as UTC datetimes from the backend.
 */
const parseToDate = (val: string | number | Date): Date => {
  if (val instanceof Date) return val;
  if (typeof val === 'number') return new Date(val);
  
  let str = String(val).trim();
  // If ISO string with T but no timezone offset (neither Z nor +/- offset)
  if (str.includes('T') && !str.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(str)) {
    str += 'Z';
  } else if (!str.includes('T') && str.includes(' ') && !str.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(str)) {
    str = str.replace(' ', 'T') + 'Z';
  }
  return new Date(str);
};

const dtfPhnomPenh = new Intl.DateTimeFormat('en-US', {
  timeZone: TIMEZONE_PHNOM_PENH,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

/**
 * Formats a date string, timestamp, or Date object as YYYY-MM-DD in Phnom Penh time (Asia/Phnom_Penh / UTC+7).
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
  const d = parseToDate(val);
  if (isNaN(d.getTime())) return String(val);
  
  const parts = dtfPhnomPenh.formatToParts(d);
  const getPart = (type: string) => parts.find((p) => p.type === type)?.value || '';
  return `${getPart('year')}-${getPart('month')}-${getPart('day')}`;
};

/**
 * Formats a date string, timestamp, or Date object as YYYY-MM-DD HH:mm in Phnom Penh time (Asia/Phnom_Penh / UTC+7).
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
  const d = parseToDate(val);
  if (isNaN(d.getTime())) return String(val);

  const parts = dtfPhnomPenh.formatToParts(d);
  const getPart = (type: string) => parts.find((p) => p.type === type)?.value || '';
  const ymd = `${getPart('year')}-${getPart('month')}-${getPart('day')}`;
  const hh = getPart('hour');
  const min = getPart('minute');
  
  if (includeSeconds) {
    const ss = getPart('second');
    return `${ymd} ${hh}:${min}:${ss}`;
  }
  return `${ymd} ${hh}:${min}`;
};
