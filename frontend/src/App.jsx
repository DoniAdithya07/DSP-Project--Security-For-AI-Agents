import React, { useState, useEffect, useMemo, useCallback } from 'react';
import axios from 'axios';
import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  Terminal,
  RefreshCw,
  Database,
  Cpu,
  FileText
} from 'lucide-react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import DashboardView from './components/DashboardView';
import AgentInspector from './components/AgentInspector';
import SettingsPanel from './components/SettingsPanel';
import LogsPanel from './components/LogsPanel';
import OpsPanel from './components/OpsPanel';
import { usePersistentState } from './hooks/usePersistentState';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const App = () => {
  const createSessionId = () => `sess-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  const [activeTab, setActiveTab] = useState('dashboard');
  const [prompt, setPrompt] = useState('');
  const [logs, setLogs] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);
  const [executionError, setExecutionError] = useState('');
  const [apiKey, setApiKey] = usePersistentState('aegis_api_key', '');
  const [dryRun, setDryRun] = usePersistentState('aegis_dry_run_mode', false);
  const [agentId, setAgentId] = usePersistentState('aegis_agent_id', 'admin-agent');
  const [refreshIntervalMs, setRefreshIntervalMs] = usePersistentState('aegis_refresh_interval_ms', 5000);
  const [lastPrompt, setLastPrompt] = useState('');
  const [connectionState, setConnectionState] = useState({
    status: 'idle',
    message: 'Connection not tested yet.'
  });
  const [settingsOllamaUrl, setSettingsOllamaUrl] = usePersistentState('aegis_ollama_url', '');
  const [settingsOllamaModel, setSettingsOllamaModel] = usePersistentState('aegis_ollama_model', 'llama3');
  const [settingsBackendUrl, setSettingsBackendUrl] = usePersistentState('aegis_backend_url', import.meta.env.VITE_API_BASE_URL || '/api');
  const [sessionId, setSessionId] = usePersistentState('aegismind_session_id', createSessionId);
  const [stats, setStats] = useState({
    blocked: 0,
    safe: 0,
    threats: 0,
    risk: 0
  });
  const [timelineWindow, setTimelineWindow] = useState('1h');
  const [logSearch, setLogSearch] = useState('');
  const [logStatusFilter, setLogStatusFilter] = useState('all');
  const [logFetchError, setLogFetchError] = useState('');
  const [dashboardToken, setDashboardToken] = usePersistentState('aegis_dashboard_token', '');
  const [dashboardUser, setDashboardUser] = usePersistentState('aegis_dashboard_user', null);
  const [opsStatus, setOpsStatus] = useState({ kind: 'info', message: '' });
  const [opsData, setOpsData] = useState({
    currentPolicy: {},
    policyVersions: [],
    pendingApprovals: [],
    threatIntel: [],
    threatStatus: {},
    toolProfiles: [],
    scorecard: null,
    replay: null,
    liveEvents: [],
    users: [],
    calibration: null,
    backups: [],
    archives: [],
    slo: null
  });

  const refreshIntervalValue = Number(refreshIntervalMs);
  const effectiveRefreshIntervalMs = Number.isFinite(refreshIntervalValue) && refreshIntervalValue >= 2000
    ? refreshIntervalValue
    : 5000;

  const apiBaseUrl = useMemo(() => {
    const raw = String(settingsBackendUrl || import.meta.env.VITE_API_BASE_URL || '/api').trim();
    if (!raw || raw === '/api') return '/api';
    if (raw.startsWith('/')) return raw.replace(/\/+$/, '');
    return raw.replace(/\/+$/, '').replace(/\/api$/i, '');
  }, [settingsBackendUrl]);

  const getHeaders = useCallback(() => {
    const headers = {};
    if (apiKey) {
      headers['X-API-Key'] = apiKey;
      headers['X-Agent-Id'] = agentId || 'admin-agent';
    }
    if (dashboardToken) {
      headers.Authorization = `Bearer ${dashboardToken}`;
    }
    return headers;
  }, [apiKey, agentId, dashboardToken]);

  const getDashboardHeaders = useCallback(() => (
    dashboardToken ? { Authorization: `Bearer ${dashboardToken}` } : {}
  ), [dashboardToken]);

  useEffect(() => {
    const interceptorId = axios.interceptors.request.use((config) => {
      if (typeof config.url !== 'string') return config;
      if (!config.url.startsWith('/api/')) return config;
      if (apiBaseUrl === '/api') return config;
      const suffix = config.url.substring(4);
      return { ...config, url: `${apiBaseUrl}${suffix}` };
    });

    return () => {
      axios.interceptors.request.eject(interceptorId);
    };
  }, [apiBaseUrl]);

  const formatAxiosError = useCallback((err, fallback = 'Request failed.') => {
    const detail = err?.response?.data?.detail;
    if (Array.isArray(detail)) return detail.map((d) => d?.msg).join(', ');
    if (typeof detail === 'string' && detail.trim()) return detail;
    if (String(err?.message || '').toLowerCase() === 'network error') {
      return `Network Error: backend unreachable at ${apiBaseUrl}. Update Backend URL in Settings and click Test Connection.`;
    }
    return err?.message || fallback;
  }, [apiBaseUrl]);

  const parseTimestampMs = (value) => {
    if (!value) return Number.NaN;
    if (typeof value === 'number') return value;
    if (value instanceof Date) return value.getTime();

    const raw = String(value).trim();
    if (!raw) return Number.NaN;

    const hasTimezone = /([zZ]|[+-]\d{2}:\d{2})$/.test(raw);
    const normalized = hasTimezone ? raw : `${raw}Z`;
    const parsed = Date.parse(normalized);
    if (!Number.isNaN(parsed)) return parsed;

    if (raw.includes(' ')) {
      const asIso = raw.replace(' ', 'T');
      const isoHasTimezone = /([zZ]|[+-]\d{2}:\d{2})$/.test(asIso);
      return Date.parse(isoHasTimezone ? asIso : `${asIso}Z`);
    }

    return Number.NaN;
  };

  const formatTimestamp = (value) => {
    const timestampMs = parseTimestampMs(value);
    if (!Number.isFinite(timestampMs)) return 'Unknown time';
    return new Date(timestampMs).toLocaleString();
  };

  const fetchLogs = useCallback(async () => {
    if (!apiKey && !dashboardToken) {
      setLogFetchError('Add API key or sign in to load protected logs.');
      return;
    }

    try {
      const requestConfig = { headers: getHeaders() };
      const windowMs = timelineWindow === '24h' ? 24 * 60 * 60 * 1000 : 60 * 60 * 1000;
      const fromTs = new Date(Date.now() - windowMs).toISOString();
      const queryParams = {
        limit: 200,
        from_ts: fromTs
      };
      const securityRes = await axios.get('/api/logs/security', { ...requestConfig, params: queryParams });
      const auditRes = await axios.get('/api/logs/audit', { ...requestConfig, params: queryParams });

      setLogFetchError('');
      setSecurityEvents(securityRes.data);
      setLogs(auditRes.data);

      const blockedStatuses = new Set(['blocked', 'denied']);
      const safeStatuses = new Set(['executed', 'modified', 'safe']);
      const blockedCount = auditRes.data.filter((item) => blockedStatuses.has((item.status || '').toLowerCase())).length;
      const safeCount = auditRes.data.filter((item) => safeStatuses.has((item.status || '').toLowerCase())).length;
      const averageRisk = securityRes.data.length > 0
        ? Math.round(
          (securityRes.data.reduce((acc, event) => acc + Number(event.risk_score || 0), 0) / securityRes.data.length) * 100
        )
        : 0;

      setStats({
        blocked: blockedCount,
        safe: safeCount,
        threats: securityRes.data.length,
        risk: averageRisk
      });
    } catch (err) {
      setLogFetchError(formatAxiosError(err, 'Failed to fetch logs.'));
      console.error('Error fetching logs', err);
    }
  }, [apiKey, dashboardToken, getHeaders, formatAxiosError, timelineWindow]);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, effectiveRefreshIntervalMs);
    return () => clearInterval(interval);
  }, [fetchLogs, effectiveRefreshIntervalMs]);

  const executePrompt = async () => {
    const trimmedPrompt = prompt.trim();
    if (!trimmedPrompt) return;
    if (!apiKey && !dashboardToken) {
      setExecutionError('Missing credentials. Add API key or sign in to continue.');
      return;
    }

    setLastPrompt(trimmedPrompt);
    setLoading(true);
    setExecutionError('');
    setExecutionResult(null);

    try {
      const response = await axios.post('/api/agent/execute', {
        session_id: sessionId,
        prompt: trimmedPrompt,
        role: 'researcher',
        dry_run: Boolean(dryRun)
      }, { headers: getHeaders() });
      const responseData = response?.data;

      if (responseData?.session_id) {
        setSessionId(responseData.session_id);
      }

      if (responseData?.firewall) {
        const localEvent = {
          timestamp: new Date().toISOString(),
          event_type: responseData.gateway?.simulation
            ? 'PROMPT_SIMULATION'
            : (responseData.firewall.status === 'blocked' ? 'FIREWALL_BLOCK' : 'PROMPT_EVAL'),
          risk_score: Number(responseData.firewall.risk_score || 0),
          details: {
            reason: responseData.gateway?.reason || responseData.firewall.decision || 'Prompt evaluated'
          }
        };
        setSecurityEvents((previous) => [localEvent, ...previous].slice(0, 50));
      }

      setExecutionResult(responseData);
      setPrompt('');
      await fetchLogs();
    } catch (err) {
      setExecutionError(formatAxiosError(err, 'Execution failed.'));
      console.error('Execution failed', err);
    } finally {
      setLoading(false);
    }
  };

  const getWindowDurationMs = (windowKey) => (
    windowKey === '24h' ? 24 * 60 * 60 * 1000 : 60 * 60 * 1000
  );

  const filteredSecurityEvents = useMemo(() => {
    const cutoff = Date.now() - getWindowDurationMs(timelineWindow);
    return securityEvents.filter((event) => {
      const timestamp = parseTimestampMs(event.timestamp);
      return Number.isFinite(timestamp) && timestamp >= cutoff;
    });
  }, [securityEvents, timelineWindow]);

  const timeFilteredLogs = useMemo(() => {
    const cutoff = Date.now() - getWindowDurationMs(timelineWindow);
    return logs.filter((log) => {
      const timestamp = parseTimestampMs(log.timestamp);
      return Number.isFinite(timestamp) && timestamp >= cutoff;
    });
  }, [logs, timelineWindow]);

  const visibleLogs = useMemo(() => {
    const normalizedQuery = logSearch.trim().toLowerCase();
    return timeFilteredLogs.filter((log) => {
      const normalizedStatus = String(log.status || '').toLowerCase();
      const statusMatch = logStatusFilter === 'all' || normalizedStatus === logStatusFilter;
      if (!statusMatch) return false;
      if (!normalizedQuery) return true;

      const searchable = [
        log.action,
        log.input_text,
        log.output_text,
        log.session_id,
        log.agent_id,
        log.status
      ].join(' ').toLowerCase();

      return searchable.includes(normalizedQuery);
    });
  }, [timeFilteredLogs, logSearch, logStatusFilter]);

  const chartData = useMemo(() => {
    const isDailyWindow = timelineWindow === '24h';
    const bucketCount = isDailyWindow ? 25 : 7;
    const bucketSizeMinutes = isDailyWindow ? 60 : 10;
    const nowMs = Date.now();
    const bucketValues = Array.from({ length: bucketCount }, () => 0);

    filteredSecurityEvents.forEach((event) => {
      const eventTime = parseTimestampMs(event.timestamp);
      if (Number.isNaN(eventTime)) return;

      const ageMinutes = (nowMs - eventTime) / (1000 * 60);
      if (ageMinutes < 0 || ageMinutes > (bucketCount - 1) * bucketSizeMinutes) return;

      const bucketFromNow = Math.floor(ageMinutes / bucketSizeMinutes);
      const index = bucketCount - 1 - bucketFromNow;
      if (index < 0 || index >= bucketCount) return;

      const riskPercent = Math.round(Number(event.risk_score || 0) * 100);
      bucketValues[index] = Math.max(bucketValues[index], riskPercent);
    });

    const labels = Array.from({ length: bucketCount }, (_, idx) => {
      const minutesAgo = (bucketCount - 1 - idx) * bucketSizeMinutes;
      if (minutesAgo === 0) return 'Now';
      if (isDailyWindow) return `${Math.round(minutesAgo / 60)}h ago`;
      return `${minutesAgo}m ago`;
    });

    return {
      labels,
      datasets: [
        {
          label: 'Risk Score',
          data: bucketValues,
          borderColor: '#0ea5e9',
          backgroundColor: 'rgba(14, 165, 233, 0.1)',
          fill: true,
          tension: 0.4
        }
      ]
    };
  }, [filteredSecurityEvents, timelineWindow]);

  const hasRiskTimelineData = useMemo(() => (
    chartData.datasets?.[0]?.data?.some((value) => Number(value) > 0) || false
  ), [chartData]);

  const chartOptions = useMemo(() => ({
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: '#94a3b8'
        }
      },
      tooltip: {
        callbacks: {
          label: (context) => `Risk Score: ${context.parsed.y}%`
        }
      }
    },
    scales: {
      x: {
        ticks: { color: '#64748b' },
        grid: { color: 'rgba(30, 41, 59, 0.35)' }
      },
      y: {
        min: 0,
        max: 100,
        ticks: {
          stepSize: 20,
          color: '#64748b',
          callback: (value) => `${value}%`
        },
        grid: { color: 'rgba(30, 41, 59, 0.35)' }
      }
    }
  }), []);

  const getAlertMessage = (event) => {
    if (!event?.details) return 'Security policy violation detected';
    return (
      event.details.reason ||
      event.details.threats?.[0] ||
      event.details.prompt ||
      event.details.tool ||
      'Security policy violation detected'
    );
  };

  const getDisplayReasoning = (thought) => {
    const normalizedThought = String(thought || '').trim();
    if (!normalizedThought) return 'Secure reasoning completed.';
    if (normalizedThought.toLowerCase().includes('ollama unavailable')) {
      return 'Secure fallback reasoning mode is active.';
    }
    return normalizedThought;
  };

  const testConnection = async () => {
    if (!apiKey && !dashboardToken) {
      setConnectionState({ status: 'error', message: 'Missing credentials. Add API key or dashboard sign-in.' });
      return;
    }

    setConnectionState({ status: 'checking', message: 'Testing backend connection...' });
    try {
      const response = await axios.get('/api/logs/security', { headers: getHeaders() });
      setConnectionState({
        status: 'ok',
        message: `Connected. Retrieved ${response.data?.length || 0} security records.`
      });
    } catch (err) {
      setConnectionState({
        status: 'error',
        message: formatAxiosError(err, 'Connection failed.')
      });
    }
  };

  const regenerateSessionId = () => {
    setSessionId(createSessionId());
    setExecutionResult(null);
    setExecutionError('');
  };

  const setOpsSuccess = useCallback((message) => {
    setOpsStatus({ kind: 'success', message });
  }, []);

  const setOpsError = useCallback((err, fallback = 'Operation failed') => {
    setOpsStatus({
      kind: 'error',
      message: formatAxiosError(err, fallback)
    });
  }, [formatAxiosError]);

  const refreshOpsData = useCallback(async () => {
    if (!dashboardToken) return;
    try {
      const headers = getDashboardHeaders();
      const [
        currentPolicy,
        policyVersions,
        pendingApprovals,
        threatIntel,
        threatStatus,
        toolProfiles,
        scorecard,
        users,
        calibration,
        backups,
        archives,
        slo
      ] = await Promise.all([
        axios.get('/api/policy/current', { headers }),
        axios.get('/api/policy/versions?limit=20', { headers }),
        axios.get('/api/approvals/pending', { headers }),
        axios.get('/api/threat-intel/list', { headers }),
        axios.get('/api/threat-intel/status', { headers }),
        axios.get('/api/tool-profiles', { headers }),
        axios.get('/api/analytics/scorecard?window_days=7', { headers }),
        axios.get('/api/auth/users', { headers }),
        axios.get('/api/analytics/calibration/summary?limit=200', { headers }),
        axios.get('/api/ops/backups', { headers }),
        axios.get('/api/ops/logs/archives', { headers }),
        axios.get('/api/observability/slo', { headers })
      ]);

      setOpsData((previous) => ({
        ...previous,
        currentPolicy: currentPolicy.data?.policy || {},
        policyVersions: policyVersions.data || [],
        pendingApprovals: pendingApprovals.data || [],
        threatIntel: threatIntel.data || [],
        threatStatus: threatStatus.data || {},
        toolProfiles: toolProfiles.data || [],
        scorecard: scorecard.data || null,
        users: users.data || [],
        calibration: calibration.data || null,
        backups: backups.data || [],
        archives: archives.data || [],
        slo: slo.data || null
      }));
    } catch (err) {
      setOpsError(err, 'Failed to refresh operations data.');
    }
  }, [dashboardToken, getDashboardHeaders, setOpsError]);

  const loginDashboard = async (username, password) => {
    try {
      const response = await axios.post('/api/auth/login', { username, password });
      const token = response?.data?.access_token || '';
      setDashboardToken(token);
      setDashboardUser(response?.data?.user || null);
      setOpsSuccess(`Signed in as ${response?.data?.user?.username || 'user'}.`);
    } catch (err) {
      setOpsError(err, 'Sign in failed.');
    }
  };

  const logoutDashboard = async () => {
    try {
      if (dashboardToken) {
        await axios.post('/api/auth/logout', {}, { headers: getDashboardHeaders() });
      }
    } catch (err) {
      setOpsError(err, 'Sign out request failed.');
    } finally {
      setDashboardToken('');
      setDashboardUser(null);
      setOpsSuccess('Signed out.');
    }
  };

  const publishPolicy = async (policyText, changeNote) => {
    try {
      const parsed = JSON.parse(policyText);
      await axios.post('/api/policy/publish', { policy: parsed, change_note: changeNote || '' }, { headers: getDashboardHeaders() });
      setOpsSuccess('Policy published.');
      await refreshOpsData();
    } catch (err) {
      if (err instanceof SyntaxError) {
        setOpsStatus({ kind: 'error', message: 'Policy JSON is invalid.' });
      } else {
        setOpsError(err, 'Policy publish failed.');
      }
    }
  };

  const decideApproval = async (approvalId, decision) => {
    try {
      await axios.post(`/api/approvals/${approvalId}/decision`, { decision }, { headers: getDashboardHeaders() });
      setOpsSuccess(`Approval #${approvalId} ${decision}d.`);
      await refreshOpsData();
    } catch (err) {
      setOpsError(err, 'Approval decision failed.');
    }
  };

  const importThreatIntel = async (rulesJsonText) => {
    try {
      const items = JSON.parse(rulesJsonText);
      const normalizedItems = Array.isArray(items) ? items : items.items;
      await axios.post('/api/threat-intel/import', { source: 'manual-ui', items: normalizedItems || [] }, { headers: getDashboardHeaders() });
      setOpsSuccess('Threat intel imported.');
      await refreshOpsData();
    } catch (err) {
      if (err instanceof SyntaxError) {
        setOpsStatus({ kind: 'error', message: 'Threat intel JSON is invalid.' });
      } else {
        setOpsError(err, 'Threat intel import failed.');
      }
    }
  };

  const syncThreatFeed = async (url) => {
    try {
      await axios.post('/api/threat-intel/sync', { url: url || null, source: 'remote-ui' }, { headers: getDashboardHeaders() });
      setOpsSuccess('Threat feed synchronized.');
      await refreshOpsData();
    } catch (err) {
      setOpsError(err, 'Threat feed sync failed.');
    }
  };

  const saveToolProfile = async (toolName, maxRisk, approvalRisk) => {
    try {
      await axios.post('/api/tool-profiles', {
        tool_name: toolName,
        max_risk_score: Number(maxRisk),
        require_approval_above: Number(approvalRisk)
      }, { headers: getDashboardHeaders() });
      setOpsSuccess(`Tool profile saved for ${toolName}.`);
      await refreshOpsData();
    } catch (err) {
      setOpsError(err, 'Saving tool profile failed.');
    }
  };

  const loadReplay = async (targetSessionId) => {
    if (!targetSessionId) return;
    try {
      const response = await axios.get(`/api/sessions/${encodeURIComponent(targetSessionId)}/replay`, { headers: getHeaders() });
      setOpsData((previous) => ({ ...previous, replay: response.data }));
      setOpsSuccess(`Loaded replay for session ${targetSessionId}.`);
    } catch (err) {
      setOpsError(err, 'Session replay fetch failed.');
    }
  };

  const rotateKey = async (label) => {
    try {
      await axios.post('/api/ops/api-keys/rotate', { label: label || 'ops-rotated-key', deactivate_old_keys: true }, { headers: getDashboardHeaders() });
      setOpsSuccess('API key rotated. Copy the new key from API response logs if needed.');
    } catch (err) {
      setOpsError(err, 'API key rotation failed.');
    }
  };

  const archiveLogs = async (days) => {
    try {
      await axios.post(`/api/ops/logs/archive?days=${Number(days) || 30}`, {}, { headers: getDashboardHeaders() });
      setOpsSuccess('Logs archived.');
      await refreshOpsData();
    } catch (err) {
      setOpsError(err, 'Log archive failed.');
    }
  };

  const createBackup = async () => {
    try {
      await axios.post('/api/ops/backup/create', {}, { headers: getDashboardHeaders() });
      setOpsSuccess('Backup created.');
      await refreshOpsData();
    } catch (err) {
      setOpsError(err, 'Backup create failed.');
    }
  };

  const restoreBackup = async (backupFile, dryRun = true) => {
    try {
      await axios.post('/api/ops/backup/restore', { backup_file: backupFile, dry_run: dryRun }, { headers: getDashboardHeaders() });
      setOpsSuccess(dryRun ? 'Restore dry-run completed.' : 'Backup restored.');
    } catch (err) {
      setOpsError(err, 'Backup restore failed.');
    }
  };

  const submitCalibration = async (sessionIdValue, expectedDecision, actualDecision, riskScoreValue, notesValue) => {
    try {
      await axios.post('/api/analytics/calibration/feedback', {
        session_id: sessionIdValue || '',
        expected_decision: expectedDecision,
        actual_decision: actualDecision,
        risk_score: Number(riskScoreValue),
        notes: notesValue || ''
      }, { headers: getDashboardHeaders() });
      setOpsSuccess('Calibration feedback submitted.');
      await refreshOpsData();
    } catch (err) {
      setOpsError(err, 'Calibration feedback failed.');
    }
  };

  const saveUser = async (userPayload) => {
    try {
      await axios.post('/api/auth/users', userPayload, { headers: getDashboardHeaders() });
      setOpsSuccess(`User ${userPayload.username} saved.`);
      await refreshOpsData();
    } catch (err) {
      setOpsError(err, 'Saving dashboard user failed.');
    }
  };

  useEffect(() => {
    if (!dashboardToken) return;
    if (activeTab !== 'ops') return;
    refreshOpsData();
  }, [dashboardToken, activeTab, refreshOpsData]);

  useEffect(() => {
    if (!dashboardToken) return undefined;
    if (activeTab !== 'ops') return undefined;

    const wsUrl = (() => {
      if (apiBaseUrl === '/api') {
        const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
        return `${scheme}://${window.location.host}/api/ws/security-stream`;
      }
      try {
        const parsed = new URL(apiBaseUrl);
        const wsScheme = parsed.protocol === 'https:' ? 'wss' : 'ws';
        return `${wsScheme}://${parsed.host}/ws/security-stream`;
      } catch {
        const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
        return `${scheme}://${window.location.host}/api/ws/security-stream`;
      }
    })();

    const ws = new WebSocket(wsUrl);
    let pingInterval = null;

    ws.onopen = () => {
      pingInterval = window.setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send('ping');
      }, 15000);
    };
    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        setOpsData((previous) => ({
          ...previous,
          liveEvents: [parsed, ...(previous.liveEvents || [])].slice(0, 100)
        }));
      } catch (err) {
        console.error('Invalid websocket payload', err);
      }
    };
    ws.onerror = () => {
      setOpsStatus((previous) => (
        previous.kind === 'error'
          ? previous
          : { kind: 'error', message: 'Live stream disconnected. Check backend websocket route.' }
      ));
    };

    return () => {
      if (pingInterval) window.clearInterval(pingInterval);
      ws.close();
    };
  }, [dashboardToken, activeTab, apiBaseUrl]);

  const remediationGuidance = useMemo(() => {
    if (!executionResult?.firewall) return [];

    const status = String(executionResult.firewall.status || '').toLowerCase();
    const matchedRules = executionResult.firewall.matched_rules || [];
    const threats = executionResult.firewall.threats || [];
    const systemActions = executionResult.gateway?.remediation?.actions || [];
    const normalizedSignals = [...matchedRules, ...threats].join(' ').toLowerCase();
    const items = [];

    if (status === 'blocked') {
      items.push('Rewrite the prompt with one safe objective and avoid instruction override language.');
      items.push('Split risky tasks into smaller approved actions, then retry each step.');
    } else {
      items.push('Prompt passed checks; continue with least-privilege tools and monitor outcomes.');
    }

    if (normalizedSignals.includes('prompt_injection') || normalizedSignals.includes('ignore')) {
      items.push('Avoid phrases like "ignore previous instructions" and use explicit task boundaries.');
    }
    if (normalizedSignals.includes('data_exfiltration') || normalizedSignals.includes('secret')) {
      items.push('Never request secrets, tokens, database dumps, or internal credentials in prompts.');
    }
    if (normalizedSignals.includes('sql')) {
      items.push('Prefer read-only, parameterized queries and require human approval for write operations.');
    }
    if (matchedRules.length > 0) {
      items.push(`Triggered rules: ${matchedRules.join(', ')}.`);
    }
    if (systemActions.length > 0) {
      items.push(`System remediation applied: ${systemActions.join('; ')}.`);
    }

    return [...new Set(items)].slice(0, 6);
  }, [executionResult]);

  const downloadFile = (filename, content, mimeType) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const csvSafe = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;

  const exportAuditLogs = () => {
    const headers = ['timestamp', 'session_id', 'agent_id', 'action', 'status', 'input_text', 'output_text'];
    const rows = visibleLogs.map((log) => [
      csvSafe(log.timestamp),
      csvSafe(log.session_id),
      csvSafe(log.agent_id),
      csvSafe(log.action),
      csvSafe(log.status),
      csvSafe(log.input_text),
      csvSafe(log.output_text)
    ].join(','));

    const csv = [headers.join(','), ...rows].join('\n');
    downloadFile(`aegismind-audit-${timelineWindow}-${Date.now()}.csv`, csv, 'text/csv;charset=utf-8;');
  };

  const exportSecurityEvents = () => {
    const payload = {
      exported_at: new Date().toISOString(),
      window: timelineWindow === '24h' ? 'Last 24 Hours' : 'Last 1 Hour',
      event_count: filteredSecurityEvents.length,
      events: filteredSecurityEvents
    };

    downloadFile(
      `aegismind-security-events-${timelineWindow}-${Date.now()}.json`,
      JSON.stringify(payload, null, 2),
      'application/json;charset=utf-8;'
    );
  };

  const exportIncidentReport = () => {
    const now = new Date().toLocaleString();
    const recentEvents = filteredSecurityEvents.slice(0, 5);
    const report = [
      '# AegisMind Security Snapshot',
      '',
      `Generated: ${now}`,
      `Window: ${timelineWindow === '24h' ? 'Last 24 Hours' : 'Last 1 Hour'}`,
      `Safe Actions: ${stats.safe}`,
      `Blocked Calls: ${stats.blocked}`,
      `Total Alerts: ${stats.threats}`,
      `Average Risk: ${stats.risk}%`,
      '',
      '## Remediation Guidance',
      ...(remediationGuidance.length > 0 ? remediationGuidance.map((item) => `- ${item}`) : ['- No active remediation required.']),
      '',
      '## Recent Security Events',
      ...(recentEvents.length > 0
        ? recentEvents.map(
          (event) => `- ${new Date(event.timestamp).toLocaleString()} | ${event.event_type} | ${Math.round(Number(event.risk_score || 0) * 100)}%`
        )
        : ['- No security events in selected window.']),
      '',
      '## Last Agent Response',
      executionResult?.gateway?.agent_response || 'No execution response captured in this session.',
      ''
    ].join('\n');

    downloadFile(`aegismind-incident-report-${timelineWindow}-${Date.now()}.md`, report, 'text/markdown;charset=utf-8;');
  };

  const buildDecisionSnapshot = () => {
    if (!executionResult) return null;

    const riskScore = Number(executionResult.firewall?.risk_score || 0);
    const zone = riskScore >= 0.60 ? 'BLOCK_ZONE' : 'SAFE_ZONE';
    const snapshotSimulationMode = Boolean(executionResult.gateway?.simulation);
    const snapshotDecisionStatus = String(executionResult.firewall?.status || '').toLowerCase();
    const snapshotDecisionSummary = snapshotDecisionStatus === 'blocked'
      ? (snapshotSimulationMode ? 'Blocked in simulation' : 'Blocked and quarantined')
      : snapshotDecisionStatus === 'safe'
        ? (snapshotSimulationMode ? 'Safe in simulation' : 'Allowed and executed')
        : 'No execution yet';
    const explainability = executionResult.explainability || {
      risk_score: Number(riskScore.toFixed(4)),
      risk_percent: Number((riskScore * 100).toFixed(1)),
      zone: zone === 'BLOCK_ZONE' ? 'block' : 'safe',
      safe_zone_max_percent: 60,
      block_zone_min_percent: 60,
      matched_rules: executionResult.firewall?.matched_rules || [],
      threats: executionResult.firewall?.threats || []
    };

    return {
      generated_at: new Date().toISOString(),
      session_id: executionResult.session_id || sessionId,
      mode: snapshotSimulationMode ? 'simulation' : 'execution',
      decision: snapshotDecisionSummary,
      prompt: lastPrompt || '(prompt unavailable)',
      firewall: executionResult.firewall || {},
      explainability,
      gateway: executionResult.gateway || {}
    };
  };

  const exportSimulatorJson = () => {
    const snapshot = buildDecisionSnapshot();
    if (!snapshot) return;
    downloadFile(
      `aegismind-simulator-${snapshot.mode}-${Date.now()}.json`,
      JSON.stringify(snapshot, null, 2),
      'application/json;charset=utf-8;'
    );
  };

  const exportSimulatorReport = () => {
    const snapshot = buildDecisionSnapshot();
    if (!snapshot) return;
    const report = [
      '# AegisMind Simulator Report',
      '',
      `Generated: ${new Date(snapshot.generated_at).toLocaleString()}`,
      `Mode: ${snapshot.mode}`,
      `Session: ${snapshot.session_id}`,
      `Decision: ${snapshot.decision}`,
      `Risk: ${snapshot.explainability.risk_percent}%`,
      `Zone: ${snapshot.explainability.zone === 'block' ? 'Block Zone (60-100%)' : 'Safe Zone (0-60%)'}`,
      '',
      '## Prompt',
      snapshot.prompt,
      '',
      '## Matched Rules',
      ...((snapshot.explainability.matched_rules || []).length > 0
        ? snapshot.explainability.matched_rules.map((rule) => `- ${rule}`)
        : ['- None']),
      '',
      '## Threat Signals',
      ...((snapshot.explainability.threats || []).length > 0
        ? snapshot.explainability.threats.map((signal) => `- ${signal}`)
        : ['- None']),
      '',
      '## Gateway Summary',
      `- Status: ${snapshot.gateway.status || 'unknown'}`,
      `- Reason: ${snapshot.gateway.reason || 'n/a'}`,
      `- Allowed: ${snapshot.gateway.allowed ? 'yes' : 'no'}`,
      ''
    ].join('\n');

    downloadFile(
      `aegismind-simulator-${snapshot.mode}-${Date.now()}.md`,
      report,
      'text/markdown;charset=utf-8;'
    );
  };

  const timelineLabel = timelineWindow === '24h' ? 'Last 24 Hours' : 'Last 1 Hour';
  const hasApiKey = Boolean(apiKey.trim());
  const hasDashboardToken = Boolean(dashboardToken);
  const hasAccessCredentials = hasApiKey || hasDashboardToken;
  const latestReasoning = getDisplayReasoning(executionResult?.gateway?.agent_thought);
  const fallbackModeActive = latestReasoning.toLowerCase().includes('fallback');
  const simulationMode = Boolean(executionResult?.gateway?.simulation);
  const totalLogsLoaded = logs.length;

  const readinessChecks = [
    {
      label: 'Access credentials configured',
      done: hasAccessCredentials,
      hint: hasAccessCredentials
        ? (hasDashboardToken ? 'Dashboard login is active in this browser.' : 'API key is loaded in this browser.')
        : 'Paste `SECURITY_API_KEY` or sign in with dashboard account.'
    },
    {
      label: 'Backend connection',
      done: connectionState.status === 'ok',
      hint: connectionState.status === 'ok'
        ? connectionState.message
        : `Run "Test Connection" in Settings. Target: ${apiBaseUrl}.`
    },
    {
      label: 'Session tracking active',
      done: Boolean(sessionId),
      hint: `Session: ${sessionId}`
    },
    {
      label: 'LLM reasoning mode',
      done: Boolean(executionResult) && !fallbackModeActive && !simulationMode,
      hint: !executionResult
        ? 'Run one prompt to verify live reasoning mode.'
        : simulationMode
          ? 'Simulation ran successfully. Disable dry run and execute once to verify live reasoning.'
        : fallbackModeActive
          ? 'Fallback mode active (check Ollama connectivity).'
          : 'Primary reasoning engine active.'
    }
  ];

  const decisionStatus = String(executionResult?.firewall?.status || '').toLowerCase();
  const decisionSummary = decisionStatus === 'blocked'
    ? (simulationMode ? 'Blocked in simulation' : 'Blocked and quarantined')
    : decisionStatus === 'safe'
      ? (simulationMode ? 'Safe in simulation' : 'Allowed and executed')
      : 'No execution yet';

  return (
    <div className="min-h-screen flex bg-black text-white font-sans">
      <aside className="w-64 border-r border-blue-500/10 bg-black flex flex-col">
        <div className="p-6 flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-lg flex items-center justify-center shadow-lg shadow-blue-500/20">
            <ShieldCheck className="text-white w-6 h-6" />
          </div>
          <div>
            <h1 className="font-bold text-xl tracking-tight">AegisMind</h1>
            <p className="text-xs text-blue-400 font-medium tracking-widest uppercase">Security Guard</p>
          </div>
        </div>

        <nav className="flex-1 px-4 py-6 space-y-2">
          {['dashboard', 'agent', 'logs', 'settings', 'ops'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                activeTab === tab
                  ? 'bg-blue-500/10 text-blue-200 border border-blue-500/20'
                  : 'text-white/60 hover:bg-white/5 hover:text-white'
              }`}
            >
              {tab === 'dashboard' && <Activity size={20} />}
              {tab === 'agent' && <Terminal size={20} />}
              {tab === 'logs' && <Database size={20} />}
              {tab === 'settings' && <RefreshCw size={20} />}
              {tab === 'ops' && <Cpu size={20} />}
              <span className="capitalize">{tab}</span>
            </button>
          ))}
        </nav>

        <div className="p-4 mt-auto">
          <div className="glass-card p-4">
            <div className="flex items-center gap-2 mb-2">
              <Cpu size={16} className="text-blue-400" />
              <span className="text-xs font-semibold text-white/70">CORE STATUS</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></div>
              <span className="text-sm font-medium">{fallbackModeActive ? 'Secure Fallback Mode' : 'Primary LLM Mode'}</span>
            </div>
            <div className="mt-2 text-[10px] text-white/50 font-mono">{timelineLabel} | SESSION AWARE</div>
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto bg-black">
        <header className="h-20 border-b border-blue-500/10 px-8 flex items-center justify-between sticky top-0 z-10 bg-black/80">
          <div>
            <h2 className="text-lg font-semibold text-white capitalize">{activeTab} View</h2>
            <p className="text-xs text-white/50 mt-1">Secure agent operations dashboard | {timelineLabel}</p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={fetchLogs}
              className="text-xs px-3 py-2 rounded-lg bg-black hover:bg-white/5 border border-blue-500/20 text-white flex items-center gap-1"
            >
              <RefreshCw size={12} /> Refresh
            </button>
            <button
              onClick={exportIncidentReport}
              className="text-xs px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white flex items-center gap-1"
            >
              <FileText size={12} /> Report
            </button>
            <div className="flex items-center gap-2 px-3 py-1 bg-blue-500/10 border border-blue-500/20 rounded-full">
              <ShieldAlert size={14} className="text-blue-300" />
              <span className="text-xs font-bold text-blue-200 uppercase tracking-wider">{stats.threats} Alerts</span>
            </div>
          </div>
        </header>

        <div className="p-8 max-w-7xl mx-auto">
          {activeTab === 'dashboard' && (
            <DashboardView
              decisionSummary={decisionSummary}
              readinessChecks={readinessChecks}
              stats={stats}
              timelineWindow={timelineWindow}
              setTimelineWindow={setTimelineWindow}
              chartData={chartData}
              chartOptions={chartOptions}
              hasRiskTimelineData={hasRiskTimelineData}
              filteredSecurityEvents={filteredSecurityEvents}
              getAlertMessage={getAlertMessage}
              apiKey={apiKey}
              onApiKeyChange={setApiKey}
              prompt={prompt}
              setPrompt={setPrompt}
              executePrompt={executePrompt}
              dryRun={Boolean(dryRun)}
              setDryRun={setDryRun}
              loading={loading}
              executionError={executionError}
              executionResult={executionResult}
              sessionId={sessionId}
              remediationGuidance={remediationGuidance}
              getDisplayReasoning={getDisplayReasoning}
              exportSimulatorJson={exportSimulatorJson}
              exportSimulatorReport={exportSimulatorReport}
            />
          )}

          {activeTab === 'agent' && (
            <AgentInspector
              executionResult={executionResult}
              lastPrompt={lastPrompt}
              sessionId={sessionId}
              remediationGuidance={remediationGuidance}
              getDisplayReasoning={getDisplayReasoning}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsPanel
              readinessChecks={readinessChecks}
              apiKey={apiKey}
              setApiKey={setApiKey}
              agentId={agentId}
              setAgentId={setAgentId}
              sessionId={sessionId}
              setSessionId={setSessionId}
              createSessionId={createSessionId}
              refreshIntervalMs={refreshIntervalMs}
              setRefreshIntervalMs={setRefreshIntervalMs}
              testConnection={testConnection}
              regenerateSessionId={regenerateSessionId}
              fetchLogs={fetchLogs}
              connectionState={connectionState}
              settingsBackendUrl={settingsBackendUrl}
              setSettingsBackendUrl={setSettingsBackendUrl}
              settingsOllamaUrl={settingsOllamaUrl}
              setSettingsOllamaUrl={setSettingsOllamaUrl}
              settingsOllamaModel={settingsOllamaModel}
              setSettingsOllamaModel={setSettingsOllamaModel}
            />
          )}

          {activeTab === 'logs' && (
            <LogsPanel
              visibleLogs={visibleLogs}
              timeFilteredLogs={timeFilteredLogs}
              timelineLabel={timelineLabel}
              totalLogsLoaded={totalLogsLoaded}
              logFetchError={logFetchError}
              timelineWindow={timelineWindow}
              setTimelineWindow={setTimelineWindow}
              exportAuditLogs={exportAuditLogs}
              exportSecurityEvents={exportSecurityEvents}
              exportIncidentReport={exportIncidentReport}
              logSearch={logSearch}
              setLogSearch={setLogSearch}
              logStatusFilter={logStatusFilter}
              setLogStatusFilter={setLogStatusFilter}
              formatTimestamp={formatTimestamp}
            />
          )}

          {activeTab === 'ops' && (
            <OpsPanel
              dashboardUser={dashboardUser}
              dashboardToken={dashboardToken}
              onLogin={loginDashboard}
              onLogout={logoutDashboard}
              opsData={opsData}
              opsStatus={opsStatus}
              handlers={{
                refreshAll: refreshOpsData,
                publishPolicy,
                decideApproval,
                importThreatIntel,
                syncThreatFeed,
                saveToolProfile,
                loadReplay,
                rotateKey,
                archiveLogs,
                createBackup,
                restoreBackup,
                submitCalibration,
                saveUser
              }}
            />
          )}
        </div>
      </main>
    </div>
  );
};

export default App;
