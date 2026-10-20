import axios from 'axios';

export const API_BASE_URL = '/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to attach JWT token
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor to handle 401s
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('access_token');
      localStorage.removeItem('user_role');
      localStorage.removeItem('username');
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// Types
export type UserRole = 'admin' | 'analyst' | 'owner' | 'viewer';

export interface UserItem {
  id: number;
  username: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  assigned_assets_count?: number;
}

export interface OwnerOption {
  id: number;
  username: string;
  full_name: string | null;
  email: string;
}

export interface AssetListItem {
  id: number;
  qualys_id: string;
  ip_address: string | null;
  ipv6_address: string | null;
  fqdn: string | null;
  netbios_name: string | null;
  server_name: string | null;
  owner_id: number | null;
  owner_username: string | null;
  os_name: string | null;
  os_family: string | null;
  tags: string[];
  last_scan_date: string | null;
  risk_score: number;
  risk_level: 'Critical' | 'High' | 'Medium' | 'Low';
  is_risky: boolean;
  total_vulns: number;
  critical_vulns: number;
  high_vulns: number;
}

export interface PaginatedAssetsResponse {
  items: AssetListItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface KnowledgeBaseItem {
  qid: number;
  title: string;
  category: string | null;
  vuln_type: string | null;
  severity: number;
  cvss_v2: number | null;
  cvss_v3: number | null;
  diagnosis: string | null;
  consequence: string | null;
  solution: string | null;
  patches: { url?: string; description?: string }[] | null;
  workaround: string | null;
  cve_list: string[] | null;
  threat_intel_flags: Record<string, boolean> | null;
}

export interface DetectionItem {
  id: number;
  asset_id: number;
  qid: number;
  detection_type: string;
  severity: number;
  status: string;
  first_found_date: string | null;
  last_found_date: string | null;
  times_found: number;
  port: number | null;
  protocol: string | null;
  scanner_results: string | null;
  remediation_status: 'Open' | 'In_Progress' | 'Acknowledged' | 'False_Positive' | 'Resolved';
  remediation_notes: string | null;
  updated_by: string | null;
  knowledge_base?: KnowledgeBaseItem;
}

export interface AssetDetail extends AssetListItem {
  detections: DetectionItem[];
}

export interface AlertItem {
  id: number;
  asset_id: number;
  alert_type: string;
  title: string;
  message: string;
  severity: string;
  is_resolved: boolean;
  dispatched_to_telegram: boolean;
  telegram_sent_at: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface DashboardSummary {
  total_assets: number;
  risky_assets: number;
  total_vulns: number;
  critical_vulns: number;
  high_vulns: number;
  active_alerts: number;
  sla_breaches: number;
  risk_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  top_os_families: { name: string; count: number }[];
  threat_intel_summary: {
    ransomware: number;
    active_exploit: number;
    public_exploit: number;
    zero_day: number;
  };
  recent_risky_assets: AssetListItem[];
  recent_alerts: AlertItem[];
  last_sync_time: string | null;
  sync_status: string;
}

export interface SystemSettings {
  qualys_api_url: string;
  qualys_username: string;
  qualys_mock_mode: boolean;
  qualys_sync_interval_hours: number;
  qualys_tag_filter: string;
  telegram_enabled: boolean;
  telegram_bot_token_masked: string;
  telegram_chat_id: string;
  telegram_cooldown_hours: number;
  risk_threshold_critical: number;
  risk_threshold_high: number;
  sla_critical_days: number;
  sla_high_days: number;
}
