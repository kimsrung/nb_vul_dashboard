import React, { useState, useEffect } from 'react';
import { Settings, Shield, Send, CheckCircle2, AlertCircle, RefreshCw, ToggleLeft, ToggleRight, Radio, Terminal, Eye, EyeOff } from 'lucide-react';
import { SystemSettings, apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';

export const SettingsPage: React.FC = () => {
  const { isAdmin } = useAuth();
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);

  // Form states - Qualys
  const [qualysUrl, setQualysUrl] = useState<string>('');
  const [qualysUsername, setQualysUsername] = useState<string>('');
  const [qualysPassword, setQualysPassword] = useState<string>('');
  const [qualysMockMode, setQualysMockMode] = useState<boolean>(true);
  const [syncInterval, setSyncInterval] = useState<number>(6);
  const [tagFilter, setTagFilter] = useState<string>('');

  // Form states - MISP (FS-ISAC)
  const [mispUrl, setMispUrl] = useState<string>('');
  const [mispApiKey, setMispApiKey] = useState<string>('');
  const [mispCreatorOrg, setMispCreatorOrg] = useState<string>('FS-ISAC');
  const [mispTagFilter, setMispTagFilter] = useState<string>('vulnerability:CVE%');
  const [mispFeedTag, setMispFeedTag] = useState<string>('FS-ISAC');
  const [mispEnabled, setMispEnabled] = useState<boolean>(true);
  const [mispMockMode, setMispMockMode] = useState<boolean>(true);
  const [mispSyncInterval, setMispSyncInterval] = useState<number>(2);
  const [mispZmqEnabled, setMispZmqEnabled] = useState<boolean>(true);
  const [mispZmqHost, setMispZmqHost] = useState<string>('10.20.40.19');
  const [mispZmqPort, setMispZmqPort] = useState<number>(50000);
  const [mispZmqUsername, setMispZmqUsername] = useState<string>('');
  const [mispZmqPassword, setMispZmqPassword] = useState<string>('');
  const [showZmqPassword, setShowZmqPassword] = useState<boolean>(false);
  const [isSimulatingPush, setIsSimulatingPush] = useState<boolean>(false);
  const [simulateResult, setSimulateResult] = useState<{ success: boolean; message: string } | null>(null);

  // Form states - Telegram
  const [telegramEnabled, setTelegramEnabled] = useState<boolean>(false);
  const [telegramToken, setTelegramToken] = useState<string>('');
  const [telegramChatId, setTelegramChatId] = useState<string>('');
  const [telegramCooldown, setTelegramCooldown] = useState<number>(6);

  // Form states - Risk & SLA
  const [riskCritThreshold, setRiskCritThreshold] = useState<number>(80);
  const [riskHighThreshold, setRiskHighThreshold] = useState<number>(40);
  const [slaCritDays, setSlaCritDays] = useState<number>(14);
  const [slaHighDays, setSlaHighDays] = useState<number>(30);

  // Test states
  const [testingQualys, setTestingQualys] = useState<boolean>(false);
  const [qualysTestResult, setQualysTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const [testingMisp, setTestingMisp] = useState<boolean>(false);
  const [mispTestResult, setMispTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const [testingTelegram, setTestingTelegram] = useState<boolean>(false);
  const [telegramTestResult, setTelegramTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const fetchSettings = async () => {
    setIsLoading(true);
    try {
      const res = await apiClient.get('/settings');
      const data: SystemSettings = res.data;
      setSettings(data);

      setQualysUrl(data.qualys_api_url);
      setQualysUsername(data.qualys_username);
      setQualysMockMode(data.qualys_mock_mode);
      setSyncInterval(data.qualys_sync_interval_hours);
      setTagFilter(data.qualys_tag_filter || '');

      setMispUrl(data.misp_url || '');
      setMispCreatorOrg(data.misp_creator_org || 'FS-ISAC');
      setMispTagFilter(data.misp_tag_filter || 'vulnerability:CVE%');
      setMispFeedTag(data.misp_feed_tag || 'FS-ISAC');
      setMispEnabled(data.misp_enabled ?? true);
      setMispMockMode(data.misp_mock_mode ?? true);
      setMispSyncInterval(data.misp_sync_interval_hours ?? 2);
      setMispZmqEnabled(data.misp_zmq_enabled ?? true);
      setMispZmqHost(data.misp_zmq_host || '10.20.40.19');
      setMispZmqPort(data.misp_zmq_port ?? 50000);
      setMispZmqUsername(data.misp_zmq_username || '');

      setTelegramEnabled(data.telegram_enabled);
      setTelegramChatId(data.telegram_chat_id || '');
      setTelegramCooldown(data.telegram_cooldown_hours);

      setRiskCritThreshold(data.risk_threshold_critical);
      setRiskHighThreshold(data.risk_threshold_high);
      setSlaCritDays(data.sla_critical_days);
      setSlaHighDays(data.sla_high_days);
    } catch (err) {
      console.error('Failed to load settings', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setSaveSuccess(false);

    try {
      const payload: any = {
        qualys_api_url: qualysUrl,
        qualys_username: qualysUsername,
        qualys_mock_mode: qualysMockMode,
        qualys_sync_interval_hours: Number(syncInterval),
        qualys_tag_filter: tagFilter,
        misp_url: mispUrl,
        misp_creator_org: mispCreatorOrg,
        misp_tag_filter: mispTagFilter,
        misp_feed_tag: mispFeedTag,
        misp_enabled: mispEnabled,
        misp_mock_mode: mispMockMode,
        misp_sync_interval_hours: Number(mispSyncInterval),
        misp_zmq_enabled: mispZmqEnabled,
        misp_zmq_host: mispZmqHost,
        misp_zmq_port: Number(mispZmqPort),
        misp_zmq_username: mispZmqUsername,
        telegram_enabled: telegramEnabled,
        telegram_chat_id: telegramChatId,
        telegram_cooldown_hours: Number(telegramCooldown),
        risk_threshold_critical: Number(riskCritThreshold),
        risk_threshold_high: Number(riskHighThreshold),
        sla_critical_days: Number(slaCritDays),
        sla_high_days: Number(slaHighDays),
      };

      if (qualysPassword.trim()) {
        payload.qualys_password = qualysPassword;
      }
      if (mispApiKey.trim()) {
        payload.misp_api_key = mispApiKey;
      }
      if (mispZmqPassword.trim()) {
        payload.misp_zmq_password = mispZmqPassword;
      }
      if (telegramToken.trim()) {
        payload.telegram_bot_token = telegramToken;
      }

      await apiClient.post('/settings', payload);
      setSaveSuccess(true);
      fetchSettings();
      setTimeout(() => setSaveSuccess(false), 4000);
    } catch (err) {
      console.error('Failed to save settings', err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleTestQualys = async () => {
    setTestingQualys(true);
    setQualysTestResult(null);
    try {
      const res = await apiClient.post('/settings/test-qualys', {
        qualys_api_url: qualysUrl,
        qualys_username: qualysUsername,
        qualys_password: qualysPassword,
        qualys_mock_mode: qualysMockMode,
      });
      setQualysTestResult(res.data);
    } catch (err: any) {
      setQualysTestResult({
        success: false,
        message: err.response?.data?.detail || 'Connection test failed',
      });
    } finally {
      setTestingQualys(false);
    }
  };

  const handleTestMisp = async () => {
    setTestingMisp(true);
    setMispTestResult(null);
    try {
      const res = await apiClient.post('/settings/test-misp', {
        misp_url: mispUrl,
        misp_api_key: mispApiKey || undefined,
        misp_creator_org: mispCreatorOrg,
        misp_tag_filter: mispTagFilter,
        misp_feed_tag: mispFeedTag,
        misp_mock_mode: mispMockMode,
        misp_zmq_enabled: mispZmqEnabled,
        misp_zmq_host: mispZmqHost,
        misp_zmq_port: Number(mispZmqPort),
        misp_zmq_username: mispZmqUsername || undefined,
        misp_zmq_password: mispZmqPassword || undefined,
      });
      setMispTestResult(res.data);
    } catch (err: any) {
      setMispTestResult({
        success: false,
        message: err.response?.data?.detail || 'MISP connection test failed',
      });
    } finally {
      setTestingMisp(false);
    }
  };

  const handleTestTelegram = async () => {
    setTestingTelegram(true);
    setTelegramTestResult(null);
    try {
      const res = await apiClient.post('/settings/test-telegram', {
        bot_token: telegramToken || undefined,
        chat_id: telegramChatId || undefined,
      });
      setTelegramTestResult(res.data);
    } catch (err: any) {
      setTelegramTestResult({
        success: false,
        message: err.response?.data?.detail || 'Telegram test failed',
      });
    } finally {
      setTestingTelegram(false);
    }
  };

  const handleSimulatePush = async () => {
    setIsSimulatingPush(true);
    setSimulateResult(null);
    try {
      const samplePayload = {
        Event: {
          id: String(Math.floor(10000 + Math.random() * 90000)),
          info: "FS-ISAC Advisory: Critical OpenSSH Remote Code Execution (regreSSHion)",
          orgc_id: "1",
          Orgc: { name: mispCreatorOrg || "FS-ISAC" },
          affected_product: "openssh",
          vulnerable_versions: "< 9.8p1",
          fixed_versions: ">= 9.8p1",
          severity: "Critical",
          cvss_score: 8.1,
          Tag: [
            { name: mispCreatorOrg || "FS-ISAC" },
            { name: "vulnerability:CVE-2024-6387" }
          ],
          Attribute: [
            { type: "vulnerability", value: "CVE-2024-6387" }
          ]
        }
      };

      const res = await apiClient.post('/alerts/simulate-event', samplePayload);
      setSimulateResult({
        success: true,
        message: res.data.message || 'Threat event processed and verified against asset inventory!',
      });
    } catch (err: any) {
      setSimulateResult({
        success: false,
        message: err.response?.data?.detail || 'Failed to simulate ZeroMQ threat event',
      });
    } finally {
      setIsSimulatingPush(false);
    }
  };

  if (isLoading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <RefreshCw className="w-6 h-6 animate-spin text-primary-400" />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Settings className="w-5 h-5 text-sky-400" /> System Configuration & Integrations
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Manage Qualys API credentials, MISP (FS-ISAC) threat intelligence, Telegram alert bot, and risk calculation thresholds.
        </p>
      </div>

      {saveSuccess && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800 text-emerald-400 text-xs font-semibold flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" /> System settings updated successfully!
        </div>
      )}

      <form onSubmit={handleSaveSettings} className="space-y-6">
        {/* Section 1: Qualys Cloud API */}
        <div className="p-6 rounded-2xl bg-surface border border-surfaceBorder space-y-4">
          <div className="flex items-center justify-between border-b border-surfaceBorder pb-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Shield className="w-4 h-4 text-sky-400" /> Qualys Cloud Platform API Configuration
            </h3>
            <span className="text-xs font-mono text-slate-400">Host Detection & KnowledgeBase APIs</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Qualys API Endpoint (POD)</label>
              <input
                type="text"
                value={qualysUrl}
                onChange={(e) => setQualysUrl(e.target.value)}
                disabled={!isAdmin}
                placeholder="https://qualysapi.qualys.com"
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Examples: qualysapi.qualys.com (US1), qualysapi.qg2.apps.qualys.com (US2), qualysapi.qualys.eu (EU1)
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Qualys API Username</label>
              <input
                type="text"
                value={qualysUsername}
                onChange={(e) => setQualysUsername(e.target.value)}
                disabled={!isAdmin}
                placeholder="qualys_api_user"
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Qualys API Password</label>
              <input
                type="password"
                value={qualysPassword}
                onChange={(e) => setQualysPassword(e.target.value)}
                disabled={!isAdmin}
                placeholder="•••••••••••• (Leave blank to keep existing)"
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Scope Filter by Asset Tag (Optional)</label>
              <input
                type="text"
                value={tagFilter}
                onChange={(e) => setTagFilter(e.target.value)}
                disabled={!isAdmin}
                placeholder="e.g. PCI, Production, DMZ"
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
            </div>

            <div className="flex items-center gap-3 md:col-span-2 pt-2">
              <label className="flex items-center gap-2 cursor-pointer text-xs font-semibold text-slate-200">
                <input
                  type="checkbox"
                  checked={qualysMockMode}
                  onChange={(e) => setQualysMockMode(e.target.checked)}
                  disabled={!isAdmin}
                  className="rounded border-slate-700 text-primary-600 focus:ring-0 bg-slate-900 w-4 h-4"
                />
                <span>Enable Mock / Offline Demo Mode (Simulates Qualys Host Detection & KB XML responses)</span>
              </label>
            </div>
          </div>

          <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-t border-surfaceBorder">
            <button
              type="button"
              onClick={handleTestQualys}
              disabled={testingQualys || !isAdmin}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sky-400 text-xs font-semibold border border-slate-700 transition-colors disabled:opacity-50 self-start"
            >
              {testingQualys ? 'Connecting to Qualys...' : 'Test Qualys Connection'}
            </button>

            {qualysTestResult && (
              <div
                className={`text-xs px-3 py-1.5 rounded-lg border flex items-center gap-1.5 ${
                  qualysTestResult.success
                    ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800'
                    : 'bg-red-950/40 text-red-400 border-red-800'
                }`}
              >
                {qualysTestResult.success ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertCircle className="w-3.5 h-3.5" />}
                {qualysTestResult.message}
              </div>
            )}
          </div>
        </div>

        {/* Section 2: MISP Threat Intelligence (FS-ISAC Feed) */}
        <div className="p-6 rounded-2xl bg-surface border border-surfaceBorder space-y-4">
          <div className="flex items-center justify-between border-b border-surfaceBorder pb-3">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-purple-400" />
              <div>
                <h3 className="text-sm font-bold text-slate-100">MISP Threat Intelligence (FS-ISAC Feed)</h3>
              </div>
            </div>
            <label className="flex items-center gap-2 cursor-pointer text-xs font-bold text-purple-400">
              <input
                type="checkbox"
                checked={mispEnabled}
                onChange={(e) => setMispEnabled(e.target.checked)}
                disabled={!isAdmin}
                className="sr-only"
              />
              {mispEnabled ? (
                <ToggleRight className="w-6 h-6 text-purple-400" />
              ) : (
                <ToggleLeft className="w-6 h-6 text-slate-600" />
              )}
              <span>{mispEnabled ? 'Feed Enabled' : 'Disabled'}</span>
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">MISP API Endpoint (Base URL)</label>
              <input
                type="text"
                value={mispUrl}
                onChange={(e) => setMispUrl(e.target.value)}
                disabled={!isAdmin || !mispEnabled}
                placeholder="https://misp.internal.corp"
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Internal MISP instance URL hosting FS-ISAC threat events
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">MISP Auth Key / API Key</label>
              <input
                type="password"
                value={mispApiKey}
                onChange={(e) => setMispApiKey(e.target.value)}
                disabled={!isAdmin || !mispEnabled}
                placeholder={settings?.misp_api_key_masked || "•••••••••••• (Leave blank to keep existing)"}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">API user authentication key for REST queries</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Creator Org Filter (Orgc)</label>
              <input
                type="text"
                value={mispCreatorOrg}
                onChange={(e) => setMispCreatorOrg(e.target.value)}
                disabled={!isAdmin || !mispEnabled}
                placeholder="FS-ISAC"
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-primary-500 disabled:opacity-50 font-mono"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Strictly queries and validates events created by this organization (Default: FS-ISAC)
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Vulnerability Tag Filter</label>
              <input
                type="text"
                value={mispTagFilter}
                onChange={(e) => setMispTagFilter(e.target.value)}
                disabled={!isAdmin || !mispEnabled}
                placeholder="vulnerability:CVE%"
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-primary-500 disabled:opacity-50 font-mono"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Filters events with vulnerability tags matching this pattern (Default: vulnerability:CVE%)
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Assessment Sync Interval (Hours)</label>
              <input
                type="number"
                min={1}
                max={48}
                value={mispSyncInterval}
                onChange={(e) => setMispSyncInterval(Number(e.target.value))}
                disabled={!isAdmin || !mispEnabled}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Frequency of proactive inventory matching background job</span>
            </div>

            <div className="flex items-center gap-3 md:col-span-2 pt-2">
              <label className="flex items-center gap-2 cursor-pointer text-xs font-semibold text-slate-200">
                <input
                  type="checkbox"
                  checked={mispMockMode}
                  onChange={(e) => setMispMockMode(e.target.checked)}
                  disabled={!isAdmin || !mispEnabled}
                  className="rounded border-slate-700 text-purple-600 focus:ring-0 bg-slate-900 w-4 h-4"
                />
                <span>Enable Mock / Offline Demo Feed (Simulates FS-ISAC emergency CVE advisories and pre-scan matches)</span>
              </label>
            </div>
          </div>

          {/* Real-Time Live Feed Stream Box (ZeroMQ) */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-purple-900/40 space-y-4 mt-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-purple-400" />
                <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
                  Real-Time MISP Threat Stream (ZeroMQ)
                </h4>
              </div>
              <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${
                mispZmqEnabled
                  ? 'bg-purple-950 text-purple-300 border-purple-800'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}>
                {mispZmqEnabled ? 'Active ZeroMQ Subscriber' : 'ZeroMQ Disabled'}
              </span>
            </div>

            <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
              Connects directly to MISP's native ZeroMQ TCP publisher (<code className="text-purple-300">tcp://host:port</code>). When new FS-ISAC CVE advisories are published in MISP, the engine immediately evaluates them against installed server software inventory and generates alerts in the Alert Center.
            </p>

            {/* ZeroMQ Stream Configuration & Authentication */}
            <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-200">Connection & PLAIN Authentication</span>
                <button
                  type="button"
                  onClick={() => isAdmin && setMispZmqEnabled(!mispZmqEnabled)}
                  disabled={!isAdmin || !mispEnabled}
                  className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[10px] font-bold border transition-colors ${
                    mispZmqEnabled
                      ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  {mispZmqEnabled ? <CheckCircle2 className="w-3 h-3" /> : null}
                  {mispZmqEnabled ? 'Auto-Subscriber Enabled' : 'Auto-Subscriber Disabled'}
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                <div>
                  <label className="block text-[11px] font-medium text-slate-300 mb-1">
                    ZeroMQ Host / IP
                  </label>
                  <input
                    type="text"
                    value={mispZmqHost}
                    onChange={(e) => setMispZmqHost(e.target.value)}
                    disabled={!isAdmin || !mispEnabled || !mispZmqEnabled}
                    placeholder="10.20.40.19"
                    className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-slate-300 mb-1">
                    ZeroMQ Port
                  </label>
                  <input
                    type="number"
                    value={mispZmqPort}
                    onChange={(e) => setMispZmqPort(parseInt(e.target.value) || 50000)}
                    disabled={!isAdmin || !mispEnabled || !mispZmqEnabled}
                    placeholder="50000"
                    className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-slate-300 mb-1">
                    ZeroMQ Username (PLAIN Auth)
                  </label>
                  <input
                    type="text"
                    value={mispZmqUsername}
                    onChange={(e) => setMispZmqUsername(e.target.value)}
                    disabled={!isAdmin || !mispEnabled || !mispZmqEnabled}
                    placeholder="Matches Plugin.ZeroMQ_username in MISP"
                    className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50"
                  />
                  <span className="text-[10px] text-slate-500 mt-0.5 block">
                    Optional: leave blank if unauthenticated
                  </span>
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-slate-300 mb-1">
                    ZeroMQ Password
                  </label>
                  <div className="relative">
                    <input
                      type={showZmqPassword ? "text" : "password"}
                      value={mispZmqPassword}
                      onChange={(e) => setMispZmqPassword(e.target.value)}
                      disabled={!isAdmin || !mispEnabled || !mispZmqEnabled}
                      placeholder={settings?.misp_zmq_password_masked || "Matches Plugin.ZeroMQ_password in MISP"}
                      className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-1.5 pr-9 text-xs text-slate-100 font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50"
                    />
                    <button
                      type="button"
                      onClick={() => setShowZmqPassword(!showZmqPassword)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                    >
                      {showZmqPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-0.5 block">
                    Optional: leave blank to keep existing password
                  </span>
                </div>
              </div>

              <div className="pt-1">
                <span className="text-[10px] text-slate-500 block mb-1 font-mono">CLI Subscriber Command:</span>
                <div className="bg-slate-950 p-2 rounded text-emerald-400 text-[11px] font-mono overflow-x-auto select-all">
                  python -m app.services.misp_zmq_subscriber --host {mispZmqHost || '10.20.40.19'} --port {mispZmqPort || 50000} {mispZmqUsername ? `--username "${mispZmqUsername}"` : ''}
                </div>
              </div>
            </div>

            {/* Simulate ZeroMQ Threat Event Button */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={handleSimulatePush}
                disabled={isSimulatingPush || !isAdmin || !mispEnabled}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-purple-950/80 hover:bg-purple-900 text-purple-300 text-xs font-semibold border border-purple-800 transition-colors disabled:opacity-50 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isSimulatingPush ? 'animate-spin' : ''}`} />
                <span>{isSimulatingPush ? 'Simulating Event...' : 'Simulate ZeroMQ Threat Event'}</span>
              </button>

              {simulateResult && (
                <div
                  className={`text-xs px-3 py-1.5 rounded-lg border flex items-center gap-1.5 max-w-md ${
                    simulateResult.success
                      ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800'
                      : 'bg-red-950/40 text-red-400 border-red-800'
                  }`}
                >
                  {simulateResult.success ? <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> : <AlertCircle className="w-3.5 h-3.5 shrink-0" />}
                  <span className="truncate">{simulateResult.message}</span>
                </div>
              )}
            </div>
          </div>

          <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-t border-surfaceBorder">
            <button
              type="button"
              onClick={handleTestMisp}
              disabled={testingMisp || !isAdmin || !mispEnabled}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-purple-400 text-xs font-semibold border border-slate-700 transition-colors disabled:opacity-50 self-start"
            >
              {testingMisp ? 'Connecting to MISP...' : 'Test MISP Connection'}
            </button>

            {mispTestResult && (
              <div
                className={`text-xs px-3 py-1.5 rounded-lg border flex items-center gap-1.5 ${
                  mispTestResult.success
                    ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800'
                    : 'bg-red-950/40 text-red-400 border-red-800'
                }`}
              >
                {mispTestResult.success ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertCircle className="w-3.5 h-3.5" />}
                {mispTestResult.message}
              </div>
            )}
          </div>
        </div>

        {/* Section 3: Telegram Bot Integration */}
        <div className="p-6 rounded-2xl bg-surface border border-surfaceBorder space-y-4">
          <div className="flex items-center justify-between border-b border-surfaceBorder pb-3">
            <div className="flex items-center gap-2">
              <Send className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-bold text-slate-100">Telegram Alert Integration</h3>
            </div>
            <label className="flex items-center gap-2 cursor-pointer text-xs font-bold text-sky-400">
              <input
                type="checkbox"
                checked={telegramEnabled}
                onChange={(e) => setTelegramEnabled(e.target.checked)}
                disabled={!isAdmin}
                className="sr-only"
              />
              {telegramEnabled ? (
                <ToggleRight className="w-6 h-6 text-sky-400" />
              ) : (
                <ToggleLeft className="w-6 h-6 text-slate-600" />
              )}
              <span>{telegramEnabled ? 'Alerts Enabled' : 'Disabled'}</span>
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Telegram Bot Token</label>
              <input
                type="password"
                value={telegramToken}
                onChange={(e) => setTelegramToken(e.target.value)}
                disabled={!isAdmin || !telegramEnabled}
                placeholder={settings?.telegram_bot_token_masked || "123456789:ABCdefGHIjklMNOpqrsTUVwxyz"}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Created via @BotFather in Telegram</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Telegram Chat ID / Channel ID</label>
              <input
                type="text"
                value={telegramChatId}
                onChange={(e) => setTelegramChatId(e.target.value)}
                disabled={!isAdmin || !telegramEnabled}
                placeholder="e.g. -1001234567890 or @sec_alerts_channel"
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Destination channel or security group chat ID</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Alert Anti-Spam Cooldown (Hours)</label>
              <input
                type="number"
                min={1}
                max={48}
                value={telegramCooldown}
                onChange={(e) => setTelegramCooldown(Number(e.target.value))}
                disabled={!isAdmin || !telegramEnabled}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Prevents re-alerting the same asset within this window</span>
            </div>
          </div>

          <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-t border-surfaceBorder">
            <button
              type="button"
              onClick={handleTestTelegram}
              disabled={testingTelegram || !isAdmin || !telegramEnabled}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sky-400 text-xs font-semibold border border-slate-700 transition-colors disabled:opacity-50 self-start"
            >
              {testingTelegram ? 'Sending Test Message...' : 'Send Test Alert to Telegram'}
            </button>

            {telegramTestResult && (
              <div
                className={`text-xs px-3 py-1.5 rounded-lg border flex items-center gap-1.5 ${
                  telegramTestResult.success
                    ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800'
                    : 'bg-red-950/40 text-red-400 border-red-800'
                }`}
              >
                {telegramTestResult.success ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertCircle className="w-3.5 h-3.5" />}
                {telegramTestResult.message}
              </div>
            )}
          </div>
        </div>

        {/* Section 3: Risk Scoring & SLA Thresholds */}
        <div className="p-6 rounded-2xl bg-surface border border-surfaceBorder space-y-4">
          <div className="flex items-center justify-between border-b border-surfaceBorder pb-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Shield className="w-4 h-4 text-orange-400" /> Risk Calculation Engine & SLA Thresholds
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Critical Risk Threshold</label>
              <input
                type="number"
                value={riskCritThreshold}
                onChange={(e) => setRiskCritThreshold(Number(e.target.value))}
                disabled={!isAdmin}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Default: 80 points</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">High Risk Threshold</label>
              <input
                type="number"
                value={riskHighThreshold}
                onChange={(e) => setRiskHighThreshold(Number(e.target.value))}
                disabled={!isAdmin}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Default: 40 points</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Critical SLA Window (Days)</label>
              <input
                type="number"
                value={slaCritDays}
                onChange={(e) => setSlaCritDays(Number(e.target.value))}
                disabled={!isAdmin}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Breaches trigger 1.5x score</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">High SLA Window (Days)</label>
              <input
                type="number"
                value={slaHighDays}
                onChange={(e) => setSlaHighDays(Number(e.target.value))}
                disabled={!isAdmin}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Breaches trigger 1.3x score</span>
            </div>
          </div>
        </div>

        {/* Submit */}
        {isAdmin && (
          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={isSaving}
              className="px-6 py-2.5 rounded-xl bg-primary-600 hover:bg-primary-500 text-white text-xs font-bold shadow-lg shadow-primary-600/20 transition-all disabled:opacity-50"
            >
              {isSaving ? 'Saving Changes...' : 'Save All Settings'}
            </button>
          </div>
        )}
      </form>
    </div>
  );
};
