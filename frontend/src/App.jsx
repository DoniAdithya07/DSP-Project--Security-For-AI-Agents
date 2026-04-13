import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  Terminal, 
  Lock, 
  RefreshCw, 
  AlertTriangle,
  ChevronRight,
  Database,
  Cpu,
  Download,
  FileText,
  CheckCircle2,
  XCircle,
  Search,
  SlidersHorizontal,
  Sparkles
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
import { Line } from 'react-chartjs-2';

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
  const [apiKey, setApiKey] = useState(localStorage.getItem('aegis_api_key') || '');
  const [agentId, setAgentId] = useState(localStorage.getItem('aegis_agent_id') || 'admin-agent');
  const [refreshIntervalMs, setRefreshIntervalMs] = useState(() => {
    const stored = Number(localStorage.getItem('aegis_refresh_interval_ms') || 5000);
    return Number.isFinite(stored) && stored >= 2000 ? stored : 5000;
  });
  const [lastPrompt, setLastPrompt] = useState('');
  const [connectionState, setConnectionState] = useState({
    status: 'idle',
    message: 'Connection not tested yet.'
  });
  const [settingsOllamaUrl, setSettingsOllamaUrl] = useState(localStorage.getItem('aegis_ollama_url') || '');
  const [settingsOllamaModel, setSettingsOllamaModel] = useState(localStorage.getItem('aegis_ollama_model') || 'llama3');
  const [sessionId, setSessionId] = useState(() => {
    const existing = localStorage.getItem('aegismind_session_id');
    return existing || createSessionId();
  });
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

  const getHeaders = () => {
      return {
          'X-API-Key': apiKey,
          'X-Agent-Id': agentId || 'admin-agent'
      };
  };

  const parseTimestampMs = (value) => {
    if (!value) return Number.NaN;
    if (typeof value === 'number') return value;
    if (value instanceof Date) return value.getTime();

    const raw = String(value).trim();
    if (!raw) return Number.NaN;

    const hasTimezone = /([zZ]|[+\-]\d{2}:\d{2})$/.test(raw);
    const normalized = hasTimezone ? raw : `${raw}Z`;
    const parsed = Date.parse(normalized);
    if (!Number.isNaN(parsed)) return parsed;

    if (raw.includes(' ')) {
      const asIso = raw.replace(' ', 'T');
      const isoHasTimezone = /([zZ]|[+\-]\d{2}:\d{2})$/.test(asIso);
      return Date.parse(isoHasTimezone ? asIso : `${asIso}Z`);
    }

    return Number.NaN;
  };

  const formatTimestamp = (value) => {
    const timestampMs = parseTimestampMs(value);
    if (!Number.isFinite(timestampMs)) return 'Unknown time';
    return new Date(timestampMs).toLocaleString();
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, refreshIntervalMs);
    return () => clearInterval(interval);
  }, [apiKey, agentId, refreshIntervalMs]);

  useEffect(() => {
    localStorage.setItem('aegismind_session_id', sessionId);
  }, [sessionId]);

  useEffect(() => {
    localStorage.setItem('aegis_agent_id', agentId);
  }, [agentId]);

  useEffect(() => {
    localStorage.setItem('aegis_refresh_interval_ms', String(refreshIntervalMs));
  }, [refreshIntervalMs]);

  useEffect(() => {
    localStorage.setItem('aegis_ollama_url', settingsOllamaUrl);
  }, [settingsOllamaUrl]);

  useEffect(() => {
    localStorage.setItem('aegis_ollama_model', settingsOllamaModel);
  }, [settingsOllamaModel]);

  const fetchLogs = async () => {
    try {
      const requestConfig = apiKey ? { headers: getHeaders() } : {};
      const securityRes = await axios.get('/api/logs/security', requestConfig);
      const auditRes = await axios.get('/api/logs/audit', requestConfig);
      setLogFetchError(apiKey ? '' : 'Viewing log stream without API key. Add key for protected operations.');
      setSecurityEvents(securityRes.data);
      setLogs(auditRes.data);
      
      const blockedStatuses = new Set(['blocked', 'denied', 'review']);
      const safeStatuses = new Set(['executed', 'modified', 'safe']);
      const blockedCount = auditRes.data.filter(l => blockedStatuses.has((l.status || '').toLowerCase())).length;
      const safeCount = auditRes.data.filter(l => safeStatuses.has((l.status || '').toLowerCase())).length;
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
      const detail = err?.response?.data?.detail;
      setLogFetchError(Array.isArray(detail) ? detail.map((d) => d?.msg).join(', ') : (detail || err.message || 'Failed to fetch logs.'));
      console.error("Error fetching logs", err);
    }
  };

  const executePrompt = async () => {
    const trimmedPrompt = prompt.trim();
    if (!trimmedPrompt) return;
    if (!apiKey) {
        setExecutionError("Missing Master API Key. Please paste it to continue.");
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
        role: 'researcher'
      }, { headers: getHeaders() });
      const responseData = response?.data;
      if (response?.data?.session_id) {
        setSessionId(response.data.session_id);
      }

      if (responseData?.firewall) {
        const localEvent = {
          timestamp: new Date().toISOString(),
          event_type:
            responseData.firewall.status === 'blocked'
              ? 'FIREWALL_BLOCK'
              : responseData.firewall.status === 'review'
                ? 'FIREWALL_REVIEW'
                : 'PROMPT_EVAL',
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
      const detail = err?.response?.data?.detail;
      setExecutionError(Array.isArray(detail) ? detail.map((d) => d?.msg).join(', ') : (detail || err.message || 'Execution failed'));
      console.error("Execution failed", err);
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
          tension: 0.4,
        },
      ],
    };
  }, [filteredSecurityEvents, timelineWindow]);

  const hasRiskTimelineData = useMemo(() => {
    return chartData.datasets?.[0]?.data?.some((value) => Number(value) > 0) || false;
  }, [chartData]);

  const chartOptions = useMemo(() => {
    return {
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
    };
  }, []);

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
    if (!apiKey) {
      setConnectionState({ status: 'error', message: 'Missing API key. Add it in settings.' });
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
      const detail = err?.response?.data?.detail;
      setConnectionState({
        status: 'error',
        message: Array.isArray(detail) ? detail.map((item) => item?.msg).join(', ') : (detail || err.message || 'Connection failed')
      });
    }
  };

  const regenerateSessionId = () => {
    setSessionId(createSessionId());
    setExecutionResult(null);
    setExecutionError('');
  };

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
    } else if (status === 'review') {
      items.push('Clarify intent by adding business context and expected output in the prompt.');
      items.push('Remove sensitive verbs (drop, bypass, dump, disable) unless explicitly required.');
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
      csvSafe(log.output_text),
    ].join(','));

    const csv = [headers.join(','), ...rows].join('\n');
    downloadFile(
      `aegismind-audit-${timelineWindow}-${Date.now()}.csv`,
      csv,
      'text/csv;charset=utf-8;'
    );
  };

  const exportSecurityEvents = () => {
    const payload = {
      exported_at: new Date().toISOString(),
      window: timelineWindow === '24h' ? 'Last 24 Hours' : 'Last 1 Hour',
      event_count: filteredSecurityEvents.length,
      events: filteredSecurityEvents,
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
            (event) =>
              `- ${new Date(event.timestamp).toLocaleString()} | ${event.event_type} | ${Math.round(Number(event.risk_score || 0) * 100)}%`
          )
        : ['- No security events in selected window.']),
      '',
      '## Last Agent Response',
      executionResult?.gateway?.agent_response || 'No execution response captured in this session.',
      '',
    ].join('\n');

    downloadFile(
      `aegismind-incident-report-${timelineWindow}-${Date.now()}.md`,
      report,
      'text/markdown;charset=utf-8;'
    );
  };

  const timelineLabel = timelineWindow === '24h' ? 'Last 24 Hours' : 'Last 1 Hour';
  const hasApiKey = Boolean(apiKey.trim());
  const latestReasoning = getDisplayReasoning(executionResult?.gateway?.agent_thought);
  const fallbackModeActive = latestReasoning.toLowerCase().includes('fallback');
  const totalLogsLoaded = logs.length;

  const readinessChecks = [
    {
      label: 'Master key configured',
      done: hasApiKey,
      hint: hasApiKey ? 'API key is loaded in this browser.' : 'Paste `SECURITY_API_KEY` from `.env`.'
    },
    {
      label: 'Backend connection',
      done: connectionState.status === 'ok',
      hint: connectionState.status === 'ok' ? connectionState.message : 'Run "Test Connection" in Settings.'
    },
    {
      label: 'Session tracking active',
      done: Boolean(sessionId),
      hint: `Session: ${sessionId}`
    },
    {
      label: 'LLM reasoning mode',
      done: Boolean(executionResult) && !fallbackModeActive,
      hint: !executionResult
        ? 'Run one prompt to verify live reasoning mode.'
        : fallbackModeActive
          ? 'Fallback mode active (check Ollama connectivity).'
          : 'Primary reasoning engine active.'
    }
  ];

  const decisionStatus = String(executionResult?.firewall?.status || '').toLowerCase();
  const decisionSummary = decisionStatus === 'blocked'
    ? 'Blocked and quarantined'
    : decisionStatus === 'review'
      ? 'Queued for manual review'
      : decisionStatus === 'safe'
        ? 'Allowed and executed'
        : 'No execution yet';

  return (
    <div className="min-h-screen flex bg-black text-white font-sans">
      {/* Sidebar */}
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
          {['dashboard', 'agent', 'logs', 'settings'].map((tab) => (
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
            <div className="mt-2 text-[10px] text-white/50 font-mono">{timelineLabel} • SESSION AWARE</div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto bg-black">
        <header className="h-20 border-b border-blue-500/10 px-8 flex items-center justify-between sticky top-0 z-10 bg-black/80">
          <div>
            <h2 className="text-lg font-semibold text-white capitalize">{activeTab} View</h2>
            <p className="text-xs text-white/50 mt-1">Secure agent operations dashboard • {timelineLabel}</p>
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
            <div className="space-y-8 animate-in fade-in duration-500">
              <div className="glass-card p-6">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <h3 className="font-semibold text-lg flex items-center gap-2">
                      <Sparkles className="text-blue-400" size={18} />
                      Operational Readiness
                    </h3>
                    <p className="text-sm text-gray-400 mt-1">Everything needed to run agent prompts safely and clearly.</p>
                  </div>
                  <div className="text-xs px-3 py-2 rounded-lg border border-gray-700 bg-gray-900/60 text-gray-300">
                    Latest decision: <span className="font-semibold text-blue-300">{decisionSummary}</span>
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
                  {readinessChecks.map((check) => (
                    <div key={check.label} className="rounded-lg border border-gray-800 bg-gray-900/40 px-4 py-3">
                      <div className="flex items-center gap-2">
                        {check.done ? (
                          <CheckCircle2 size={16} className="text-blue-300" />
                        ) : (
                          <XCircle size={16} className="text-white/60" />
                        )}
                        <p className="text-sm font-medium text-gray-200">{check.label}</p>
                      </div>
                      <p className="text-xs text-gray-500 mt-1">{check.hint}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {[
                  { label: "Safe Actions", value: stats.safe, icon: ShieldCheck, color: "text-blue-300", bg: "bg-blue-500/10 border border-blue-500/20" },
                  { label: "Blocked Calls", value: stats.blocked, icon: Lock, color: "text-blue-200", bg: "bg-white/5 border border-blue-500/20" },
                  { label: "Total Alerts", value: stats.threats, icon: AlertTriangle, color: "text-blue-300", bg: "bg-blue-500/10 border border-blue-500/20" },
                  { label: "Avg Risk Level", value: `${stats.risk}%`, icon: Activity, color: "text-blue-300", bg: "bg-blue-500/10 border border-blue-500/20" },
                ].map((s, i) => (
                  <div key={i} className="glass-card p-6 flex items-center gap-4 hover:border-blue-500/30 transition-all group">
                    <div className={`${s.bg} w-12 h-12 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform`}>
                      <s.icon className={`${s.color} w-6 h-6`} />
                    </div>
                    <div>
                      <p className="text-xs font-medium text-gray-500 uppercase tracking-widest">{s.label}</p>
                      <h3 className="text-2xl font-bold">{s.value}</h3>
                    </div>
                  </div>
                ))}
              </div>

              {/* Chart & Live Logs */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 glass-card p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="font-semibold text-lg flex items-center gap-2">
                       <Activity className="text-blue-500" size={18} />
                       Agent Anomaly Timeline
                    </h3>
                    <select
                      value={timelineWindow}
                      onChange={(event) => setTimelineWindow(event.target.value)}
                      className="bg-black border border-blue-500/20 text-xs rounded-md px-2 py-1 text-white/80"
                    >
                       <option value="1h">Last 1 Hour</option>
                       <option value="24h">Last 24 Hours</option>
                    </select>
                  </div>
                  <div className="h-64 relative">
                    <Line data={chartData} options={chartOptions} />
                    {!hasRiskTimelineData && (
                      <div className="absolute inset-0 rounded-lg border border-dashed border-blue-500/10 bg-black/30 flex items-center justify-center pointer-events-none">
                        <p className="text-sm text-white/50 italic">No anomaly signals in the selected {timelineWindow === '24h' ? '24 hours' : '1 hour'}.</p>
                      </div>
                    )}
                  </div>
                </div>

                <div className="glass-card p-6 flex flex-col">
                  <h3 className="font-semibold text-lg flex items-center gap-2 mb-4">
                     <AlertTriangle className="text-blue-300" size={18} />
                     Live Security Alerts
                  </h3>
                  <div className="space-y-4 flex-1 overflow-y-auto max-h-[300px] pr-2 custom-scrollbar">
                     {filteredSecurityEvents.length === 0 && <p className="text-gray-500 text-sm text-center py-10 italic">No threats detected in this window.</p>}
                     {filteredSecurityEvents.map((event, i) => (
                       <div key={i} className="p-3 bg-blue-500/5 border-l-2 border-blue-500/60 rounded-r-lg animate-in slide-in-from-right duration-300">
                          <div className="flex justify-between items-start mb-1">
                             <span className="text-xs font-bold text-blue-200">{event.event_type}</span>
                             <span className="text-[10px] text-gray-500">{new Date(event.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <p className="text-xs text-gray-300 truncate">{getAlertMessage(event)}</p>
                       </div>
                     ))}
                  </div>
                </div>
              </div>

              {/* Interaction Terminal */}
              <div className="glass-card p-8 border-t-2 border-t-blue-500/30 glow-blue">
                 <div className="flex justify-between items-start mb-6">
                     <div>
                       <h3 className="text-xl font-bold mb-1 flex items-center gap-2">
                          <Terminal className="text-blue-400" />
                          Agent Security Playground
                       </h3>
                       <p className="text-sm text-gray-400">1) Add key  2) Submit prompt  3) Review firewall decision and remediation.</p>
                     </div>
                     <input 
                        type="password" 
                        value={apiKey} 
                        onChange={(e) => { setApiKey(e.target.value); localStorage.setItem('aegis_api_key', e.target.value); }} 
                        placeholder="Paste Master API Key..." 
                        className="bg-gray-900 border border-gray-700 px-4 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none w-64"
                     />
                 </div>
                 <div className="flex gap-3">
                    <input 
                      type="text" 
                      value={prompt}
                      onChange={(e) => setPrompt(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && executePrompt()}
                      placeholder="Enter a prompt (e.g., 'Search for latest AI news' or 'IGNORE PREVIOUS INSTRUCTIONS')..."
                      className="flex-1 bg-gray-950/50 border border-gray-700 rounded-xl px-4 py-3 focus:ring-2 focus:ring-blue-500 outline-none transition-all placeholder:text-gray-600"
                    />
                    <button 
                      onClick={executePrompt}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 text-white px-8 py-3 rounded-xl font-bold transition-all shadow-lg shadow-blue-600/20 active:scale-95 flex items-center gap-2"
                    >
                      {loading ? <RefreshCw className="animate-spin" /> : <ChevronRight />}
                      {loading ? 'Analyzing...' : 'Execute'}
                    </button>
                    <button
                      onClick={() => setPrompt('')}
                      disabled={!prompt.trim() || loading}
                      className="bg-black hover:bg-white/5 disabled:bg-black/40 disabled:text-white/30 text-white px-5 py-3 rounded-xl font-semibold border border-blue-500/20 transition-all"
                    >
                      Clear
                    </button>
                 </div>
                 <div className="mt-4 flex flex-wrap gap-2">
                    <span className="text-[10px] text-gray-500 uppercase font-bold tracking-tighter">Quick Examples:</span>
                    {['Summarize a PDF', 'Access root system', 'Drop database tables', 'Decode Base64 instructions'].map(ex => (
                      <button key={ex} onClick={() => setPrompt(ex)} className="text-[10px] bg-black hover:bg-white/5 text-white/60 border border-blue-500/10 px-2 py-1 rounded transition-colors uppercase font-medium">{ex}</button>
                    ))}
                 </div>
                 {executionError && (
                   <div className="mt-4 rounded-xl border border-blue-500/30 bg-blue-500/5 p-3 text-sm text-blue-200">
                     {executionError}
                   </div>
                 )}
                {executionResult && (
                   <div className={`mt-6 rounded-xl border p-5 ${
                     executionResult.firewall?.status === 'blocked' 
                       ? 'border-blue-500/40 bg-blue-500/5' 
                       : executionResult.firewall?.status === 'review'
                         ? 'border-blue-500/30 bg-blue-500/5'
                         : 'border-blue-500/20 bg-blue-500/5'
                   }`}>
                     <div className="flex items-center gap-3 mb-3">
                       {executionResult.firewall?.status === 'blocked' ? (
                         <div className="bg-blue-500/10 p-3 rounded-full text-blue-300"><ShieldAlert size={28} /></div>
                       ) : executionResult.firewall?.status === 'review' ? (
                         <div className="bg-blue-500/10 p-3 rounded-full text-blue-300"><AlertTriangle size={28} /></div>
                       ) : (
                         <div className="bg-blue-500/10 p-3 rounded-full text-blue-300"><ShieldCheck size={28} /></div>
                       )}
                       <div>
                           <h4 className={`text-xl font-bold ${
                             executionResult.firewall?.status === 'blocked' 
                               ? 'text-blue-200' 
                               : executionResult.firewall?.status === 'review'
                                 ? 'text-blue-200' 
                                 : 'text-blue-200'
                           }`}>
                             {executionResult.firewall?.status === 'blocked' 
                               ? 'THREAT BLOCKED' 
                               : executionResult.firewall?.status === 'review'
                                 ? 'REVIEW REQUIRED'
                                 : 'PROMPT SAFE'}
                           </h4>
                           <span className="text-xs text-white/50 uppercase tracking-widest font-mono">
                               Risk Score: {(executionResult.firewall?.risk_score * 100).toFixed(1)}%
                           </span>
                       </div>
                     </div>
                     <div className="mb-3 flex flex-wrap gap-2">
                       <span className="text-xs px-2 py-1 rounded-full border border-blue-500/20 bg-black/40 text-white/80">
                         Decision: {decisionSummary}
                       </span>
                       <span className="text-xs px-2 py-1 rounded-full border border-blue-500/20 bg-black/40 text-white/80">
                         Session: {executionResult.session_id || sessionId}
                       </span>
                     </div>
                      <p className="text-sm text-white/80 p-4 bg-black/40 rounded-lg border border-blue-500/10">
                         {executionResult.firewall?.status === 'blocked' 
                             ? `Security triggered: [${executionResult.firewall.matched_rules?.join(', ')}] ${executionResult.firewall.threats?.join(', ')}` 
                             : executionResult.firewall?.status === 'review'
                               ? `Caution: This prompt contains suspicious patterns and has been flagged for manual review.`
                               : 'No adversarial intent detected. Execution allowed.'}
                      </p>
                      {((executionResult.firewall?.matched_rules || []).length > 0 || (executionResult.firewall?.threats || []).length > 0) && (
                        <div className="mt-3 text-xs text-white/80 bg-black/40 rounded-lg border border-blue-500/10 p-3">
                          <p className="uppercase tracking-wider text-white/50 mb-2">Detection Details</p>
                          {(executionResult.firewall?.matched_rules || []).length > 0 && (
                            <p>Rules: {(executionResult.firewall.matched_rules || []).join(', ')}</p>
                          )}
                          {(executionResult.firewall?.threats || []).length > 0 && (
                            <p className="mt-1">Signals: {(executionResult.firewall.threats || []).join(', ')}</p>
                          )}
                        </div>
                      )}
                      <div className="mt-4 rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
                        <p className="text-xs text-blue-300 uppercase tracking-wider mb-2 font-semibold">Remediation Guidance</p>
                        <div className="space-y-1 text-sm text-blue-100">
                          {remediationGuidance.map((step, idx) => (
                            <p key={idx}>• {step}</p>
                          ))}
                        </div>
                      </div>
                      
                      {executionResult.gateway?.agent_thought && (
                        <div className="mt-4 space-y-3">
                           <div className="flex items-start gap-2 text-xs text-blue-400 bg-blue-400/5 p-3 rounded-lg border border-blue-400/20">
                             <Activity size={14} className="mt-0.5" />
                             <div>
                               <span className="font-bold uppercase tracking-wider block mb-1">Agent Reasoning:</span>
                               {getDisplayReasoning(executionResult.gateway.agent_thought)}
                             </div>
                           </div>

                           {executionResult.gateway?.agent_response && (
                             <div className="flex items-start gap-3 text-sm text-gray-200 bg-gray-900 p-4 rounded-xl border border-gray-700 shadow-inner">
                               <div className="w-8 h-8 rounded-full bg-blue-600 flex-shrink-0 flex items-center justify-center text-white">
                                  <ShieldCheck size={18} />
                               </div>
                               <div>
                                 <span className="text-[10px] font-bold text-blue-500 uppercase tracking-widest block mb-1">AegisMind Response</span>
                                 {executionResult.gateway.agent_response}
                               </div>
                             </div>
                           )}
                        </div>
                      )}
                    </div>
                 )}
              </div>
            </div>
          )}

          {activeTab === 'agent' && (
            <div className="space-y-6 animate-in fade-in duration-500">
              <div className="glass-card p-6">
                <h3 className="font-bold text-xl mb-4">Agent Execution Inspector</h3>
                {!executionResult ? (
                  <p className="text-sm text-gray-400">No execution yet. Run a prompt from Dashboard to inspect agent decisions here.</p>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
                      <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Last Prompt</p>
                      <p className="text-sm text-gray-200">{lastPrompt || 'N/A'}</p>
                    </div>
                    <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
                      <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Session ID</p>
                      <p className="text-sm text-gray-200 font-mono">{executionResult.session_id || sessionId}</p>
                    </div>
                    <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
                      <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Firewall Decision</p>
                      <p className="text-sm text-gray-200">
                        {(executionResult.firewall?.status || 'unknown').toUpperCase()} ({Math.round(Number(executionResult.firewall?.risk_score || 0) * 100)}%)
                      </p>
                    </div>
                    <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
                      <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Gateway Status</p>
                      <p className="text-sm text-gray-200">{executionResult.gateway?.status || 'unknown'}</p>
                    </div>
                  </div>
                )}
              </div>

              <div className="glass-card p-6">
                <h3 className="font-semibold text-lg mb-3">Decision Pipeline</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
                  <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-4">
                    <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Step 1</p>
                    <p className="font-medium text-gray-200">Prompt Firewall</p>
                    <p className="text-xs text-gray-400 mt-1">{executionResult ? 'Prompt scanned for threats and policy violations.' : 'Waiting for first prompt.'}</p>
                  </div>
                  <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-4">
                    <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Step 2</p>
                    <p className="font-medium text-gray-200">Secure Gateway</p>
                    <p className="text-xs text-gray-400 mt-1">{executionResult ? `Gateway outcome: ${executionResult.gateway?.status || 'unknown'}.` : 'Gateway decision appears after execution.'}</p>
                  </div>
                  <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-4">
                    <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Step 3</p>
                    <p className="font-medium text-gray-200">Remediation + Response</p>
                    <p className="text-xs text-gray-400 mt-1">{executionResult ? `${remediationGuidance.length} guidance item(s) available.` : 'Guidance and response appear after execution.'}</p>
                  </div>
                </div>
              </div>

              <div className="glass-card p-6">
                <h3 className="font-semibold text-lg mb-3">Reasoning Trace</h3>
                <div className="space-y-3">
                  <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4">
                    <p className="text-xs text-blue-300 uppercase tracking-wider mb-2">Agent Reasoning</p>
                    <p className="text-sm text-gray-200">{getDisplayReasoning(executionResult?.gateway?.agent_thought)}</p>
                  </div>
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                    <p className="text-xs text-blue-300 uppercase tracking-wider mb-2">Agent Response</p>
                    <p className="text-sm text-gray-200 whitespace-pre-wrap">{executionResult?.gateway?.agent_response || 'No response yet.'}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="space-y-6 animate-in fade-in duration-500">
              <div className="glass-card p-6">
                <h3 className="font-semibold text-lg mb-2">Setup Checklist</h3>
                <p className="text-sm text-gray-400 mb-4">Use this order for reliable startup: set key → test connection → verify LLM host → run prompt.</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {readinessChecks.map((check) => (
                    <div key={`settings-${check.label}`} className="rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-3">
                      <p className={`text-sm font-medium ${check.done ? 'text-blue-200' : 'text-white/70'}`}>{check.label}</p>
                      <p className="text-xs text-gray-500 mt-1">{check.hint}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="glass-card p-6">
                <h3 className="font-bold text-xl mb-4">Runtime Settings</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-widest block mb-2">Master API Key</label>
                    <input
                      type="password"
                      value={apiKey}
                      onChange={(event) => {
                        setApiKey(event.target.value);
                        localStorage.setItem('aegis_api_key', event.target.value);
                      }}
                      className="w-full bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none"
                    />
                    <p className="text-[11px] text-gray-500 mt-2">This must match `SECURITY_API_KEY` from backend `.env`.</p>
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-widest block mb-2">Agent ID Header</label>
                    <input
                      type="text"
                      value={agentId}
                      onChange={(event) => setAgentId(event.target.value)}
                      className="w-full bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-widest block mb-2">Session ID</label>
                    <input
                      type="text"
                      value={sessionId}
                      onChange={(event) => setSessionId(event.target.value || createSessionId())}
                      className="w-full bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-widest block mb-2">Auto-Refresh (ms)</label>
                    <input
                      type="number"
                      min="2000"
                      step="500"
                      value={refreshIntervalMs}
                      onChange={(event) => {
                        const value = Number(event.target.value);
                        if (!Number.isFinite(value)) return;
                        setRefreshIntervalMs(Math.max(2000, value));
                      }}
                      className="w-full bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none"
                    />
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap gap-3">
                  <button
                    onClick={testConnection}
                    className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-semibold"
                  >
                    Test Connection
                  </button>
                  <button
                    onClick={regenerateSessionId}
                    className="bg-black hover:bg-white/5 text-white px-4 py-2 rounded-lg text-sm font-semibold border border-blue-500/20"
                  >
                    Regenerate Session
                  </button>
                  <button
                    onClick={fetchLogs}
                    className="bg-black hover:bg-white/5 text-white px-4 py-2 rounded-lg text-sm font-semibold border border-blue-500/20"
                  >
                    Refresh Logs
                  </button>
                </div>

                <div className={`mt-4 rounded-lg px-3 py-2 text-sm border ${
                  connectionState.status === 'ok'
                    ? 'bg-blue-500/10 border-blue-500/30 text-blue-200'
                    : connectionState.status === 'error'
                      ? 'bg-white/5 border-white/10 text-white/80'
                      : 'bg-black/40 border-blue-500/10 text-white/70'
                }`}>
                  {connectionState.message}
                </div>
              </div>

              <div className="glass-card p-6">
                <h3 className="font-semibold text-lg mb-3">LLM Host Notes</h3>
                <div className="space-y-3">
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-widest block mb-2">Ollama Base URL (reference)</label>
                    <input
                      type="text"
                      value={settingsOllamaUrl}
                      onChange={(event) => setSettingsOllamaUrl(event.target.value)}
                      placeholder="http://host.docker.internal:11434"
                      className="w-full bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-widest block mb-2">Ollama Model (reference)</label>
                    <input
                      type="text"
                      value={settingsOllamaModel}
                      onChange={(event) => setSettingsOllamaModel(event.target.value)}
                      className="w-full bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none"
                    />
                  </div>
                  <p className="text-xs text-gray-500">
                    Update backend values in `.env` and recreate backend container for server-side changes to take effect.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="glass-card animate-in fade-in duration-500">
               <div className="p-6 border-b border-gray-800 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="font-bold text-xl">Audit Log Stream</h3>
                    <p className="text-xs text-gray-500 mt-1">
                      {visibleLogs.length} shown - {timeFilteredLogs.length} in {timelineLabel} - {totalLogsLoaded} loaded
                    </p>
                    {logFetchError && (
                      <p className="text-xs text-red-300 mt-2">{logFetchError}</p>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <select
                      value={timelineWindow}
                      onChange={(event) => setTimelineWindow(event.target.value)}
                      className="bg-black border border-blue-500/20 text-xs rounded-md px-2 py-2 text-white/80"
                    >
                      <option value="1h">Last 1 Hour</option>
                      <option value="24h">Last 24 Hours</option>
                    </select>
                    <button
                      onClick={exportAuditLogs}
                      className="bg-black hover:bg-white/5 text-white border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1"
                    >
                      <Download size={14} /> Export Logs
                    </button>
                    <button
                      onClick={exportSecurityEvents}
                      className="bg-black hover:bg-white/5 text-white border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1"
                    >
                      <Database size={14} /> Export Events
                    </button>
                    <button
                      onClick={exportIncidentReport}
                      className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1"
                    >
                      <FileText size={14} /> Export Report
                    </button>
                  </div>
               </div>
               <div className="px-6 py-4 border-b border-blue-500/10 bg-black/40">
                 <div className="flex flex-wrap gap-3">
                   <div className="relative min-w-[260px] flex-1">
                     <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40" />
                     <input
                       type="text"
                       value={logSearch}
                       onChange={(event) => setLogSearch(event.target.value)}
                       placeholder="Search action, prompt, response, session, agent..."
                       className="w-full bg-black border border-blue-500/20 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:ring-2 focus:ring-blue-500 outline-none"
                     />
                   </div>
                   <div className="flex items-center gap-2">
                     <SlidersHorizontal size={14} className="text-white/40" />
                     <select
                       value={logStatusFilter}
                       onChange={(event) => setLogStatusFilter(event.target.value)}
                       className="bg-black border border-blue-500/20 text-sm rounded-lg px-3 py-2 text-white"
                     >
                       <option value="all">All statuses</option>
                       <option value="executed">Executed</option>
                       <option value="modified">Modified</option>
                       <option value="safe">Safe</option>
                       <option value="review">Review</option>
                       <option value="blocked">Blocked</option>
                       <option value="denied">Denied</option>
                     </select>
                   </div>
                 </div>
               </div>
               <div className="overflow-x-auto">
                 <table className="w-full text-left">
                    <thead className="bg-black/40 text-xs text-white/50 uppercase tracking-widest border-b border-blue-500/10">
                       <tr>
                          <th className="px-6 py-4">Timestamp</th>
                          <th className="px-6 py-4">Action</th>
                          <th className="px-6 py-4">Status</th>
                          <th className="px-6 py-4">Input</th>
                          <th className="px-6 py-4">Output</th>
                       </tr>
                    </thead>
                    <tbody className="text-sm divide-y divide-gray-800">
                       {visibleLogs.length === 0 && (
                         <tr>
                           <td colSpan={5} className="px-6 py-10 text-center text-gray-500 italic">
                             {timeFilteredLogs.length === 0 && totalLogsLoaded > 0
                               ? `No audit records found in ${timelineLabel}. Try widening the time window.`
                               : 'No audit records match the current filters.'}
                           </td>
                         </tr>
                       )}
                       {visibleLogs.map((log, i) => (
                       <tr key={i} className="hover:bg-gray-900/30 transition-colors">
                            <td className="px-6 py-4 text-xs text-gray-500 whitespace-nowrap">{formatTimestamp(log.timestamp)}</td>
                            <td className="px-6 py-4"><span className="font-mono text-blue-400 bg-blue-400/5 px-2 py-0.5 rounded capitalize">{log.action}</span></td>
                            <td className="px-6 py-4">
                              {(() => {
                                const normalizedStatus = (log.status || '').toLowerCase();
                                const isSafe = ['executed', 'modified', 'safe'].includes(normalizedStatus);
                                return (
                               <span className={`px-2 py-1 rounded-full text-[10px] font-bold uppercase ${
                                  isSafe ? 'bg-blue-500/10 text-blue-200 border border-blue-500/20' : 'bg-white/5 text-white/80 border border-white/10'
                               }`}>
                                  {log.status}
                               </span>
                                );
                              })()}
                            </td>
                            <td className="px-6 py-4 max-w-xs truncate text-gray-400">{log.input_text}</td>
                            <td className="px-6 py-4 max-w-xs truncate italic text-gray-500">{log.output_text}</td>
                         </tr>
                       ))}
                    </tbody>
                 </table>
               </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default App;

