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

export interface PaginatedAlertsResponse {
  items: AlertItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
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
  misp_url: string;
  misp_api_key_masked: string;
  misp_feed_tag: string;
  misp_enabled: boolean;
  misp_mock_mode: boolean;
  misp_sync_interval_hours: number;
  telegram_enabled: boolean;
  telegram_bot_token_masked: string;
  telegram_chat_id: string;
  telegram_cooldown_hours: number;
  risk_threshold_critical: number;
  risk_threshold_high: number;
  sla_critical_days: number;
  sla_high_days: number;
}

export interface SoftwareItem {
  id: number;
  asset_id: number;
  product_name: string;
  vendor: string | null;
  version: string;
  package_name: string | null;
  install_path: string | null;
  port: number | null;
  cpe: string | null;
  created_at: string;
}

export interface AffectedAssetDetail {
  asset_id: number;
  server_name: string | null;
  ip_address: string | null;
  os_name: string | null;
  evidence: string;
  installed_version: string | null;
  confidence: string;
  recommended_verification: string | null;
}

export interface MispAssessmentItem {
  id: number;
  cve_id: string;
  source: string;
  title: string;
  description: string;
  severity: string;
  cvss_score: number | null;
  affected_product: string;
  vulnerable_versions: string;
  fixed_versions: string | null;
  match_type: 'QUALYS_CONFIRMED' | 'INVENTORY_PROACTIVE' | 'NO_ASSETS_AFFECTED';
  confidence: string;
  affected_assets_count: number;
  dispatched_telegram: boolean;
  telegram_sent_at: string | null;
  status: 'Pending' | 'Acknowledged' | 'Remediated' | 'False_Positive';
  created_at: string;
  updated_at: string;
}

export interface MispAssessmentDetail extends MispAssessmentItem {
  assessment_report: {
    summary: string;
    affected_assets: AffectedAssetDetail[];
    recommended_actions?: string;
    verification_command?: string;
    matched_qid?: number | null;
    vulnerable_versions?: string;
    affected_product?: string;
  };
}

export interface MispSummary {
  total_advisories: number;
  pre_scan_matches: number;
  qualys_confirmed: number;
  at_risk_assets: number;
  last_sync_time: string | null;
}

export interface MispSyncResponse {
  success: boolean;
  message: string;
  assessments_run: number;
  pre_scan_matches: number;
  qualys_confirmed: number;
  clean_cves: number;
}

export interface AssetDeleteResponse {
  success: boolean;
  message: string;
  deleted_asset_id: number;
  server_name: string | null;
  ip_address: string | null;
}

export interface AuditLogItem {
  id: number;
  action: string;
  target_type: string;
  target_id: string;
  target_name: string | null;
  actor_id: number | null;
  actor_username: string;
  actor_role: string;
  ip_address: string | null;
  details: Record<string, any>;
  created_at: string;
}

export interface PaginatedAuditLogsResponse {
  items: AuditLogItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}
