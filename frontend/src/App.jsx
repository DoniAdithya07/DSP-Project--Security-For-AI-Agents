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
  Cpu
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

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    localStorage.setItem('aegismind_session_id', sessionId);
  }, [sessionId]);

  const fetchLogs = async () => {
    try {
      const securityRes = await axios.get('/api/logs/security');
      const auditRes = await axios.get('/api/logs/audit');
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
      console.error("Error fetching logs", err);
    }
  };

  const executePrompt = async () => {
    const trimmedPrompt = prompt.trim();
    if (!trimmedPrompt) return;
    setLoading(true);
    setExecutionError('');
    try {
      const response = await axios.post('/api/agent/execute', {
        session_id: sessionId,
        prompt: trimmedPrompt,
        role: 'researcher'
      });
      if (response?.data?.session_id) {
        setSessionId(response.data.session_id);
      }
      setExecutionResult(response.data);
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

  const chartData = useMemo(() => {
    const bucketCount = 7;
    const bucketSizeMinutes = 10;
    const nowMs = Date.now();
    const bucketValues = Array.from({ length: bucketCount }, () => 0);

    securityEvents.forEach((event) => {
      const eventTime = new Date(event.timestamp).getTime();
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
      return minutesAgo === 0 ? 'Now' : `${minutesAgo}m ago`;
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
  }, [securityEvents]);

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

  return (
    <div className="min-h-screen flex bg-gray-950 text-gray-100 font-sans">
      {/* Sidebar */}
      <aside className="w-64 border-r border-gray-800 bg-gray-900/50 flex flex-col">
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
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-600/20' 
                  : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
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
          <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-4 border border-gray-700">
            <div className="flex items-center gap-2 mb-2">
              <Cpu size={16} className="text-blue-400" />
              <span className="text-xs font-semibold text-gray-400">CORE STATUS</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
              <span className="text-sm font-medium">Heuristics Active</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-gray-900 via-gray-950 to-gray-950">
        <header className="h-16 border-b border-gray-800 px-8 flex items-center justify-between backdrop-blur-md sticky top-0 z-10">
          <h2 className="text-lg font-medium text-gray-300 capitalize">{activeTab} View</h2>
          <div className="flex items-center gap-4">
             <div className="flex items-center gap-2 px-3 py-1 bg-red-500/10 border border-red-500/20 rounded-full">
                <ShieldAlert size={14} className="text-red-500" />
                <span className="text-xs font-bold text-red-500 uppercase tracking-wider">{stats.threats} Threats Blocked</span>
             </div>
             <div className="w-8 h-8 rounded-full bg-gray-800 border border-gray-700"></div>
          </div>
        </header>

        <div className="p-8 max-w-7xl mx-auto">
          {activeTab === 'dashboard' && (
            <div className="space-y-8 animate-in fade-in duration-500">
              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {[
                  { label: "Safe Actions", value: stats.safe, icon: ShieldCheck, color: "text-green-500", bg: "bg-green-500/10" },
                  { label: "Blocked Calls", value: stats.blocked, icon: Lock, color: "text-red-500", bg: "bg-red-500/10" },
                  { label: "Total Alerts", value: stats.threats, icon: AlertTriangle, color: "text-amber-500", bg: "bg-amber-500/10" },
                  { label: "Avg Risk Level", value: `${stats.risk}%`, icon: Activity, color: "text-blue-500", bg: "bg-blue-500/10" },
                ].map((s, i) => (
                  <div key={i} className="glass-card p-6 flex items-center gap-4 hover:border-gray-700 transition-all group">
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
                    <select className="bg-gray-800 border-none text-xs rounded-md px-2 py-1">
                       <option>Last 1 Hour</option>
                       <option>Last 24 Hours</option>
                    </select>
                  </div>
                  <div className="h-64">
                    <Line data={chartData} options={{ maintainAspectRatio: false }} />
                  </div>
                </div>

                <div className="glass-card p-6 flex flex-col">
                  <h3 className="font-semibold text-lg flex items-center gap-2 mb-4">
                     <AlertTriangle className="text-red-500" size={18} />
                     Live Security Alerts
                  </h3>
                  <div className="space-y-4 flex-1 overflow-y-auto max-h-[300px] pr-2 custom-scrollbar">
                     {securityEvents.length === 0 && <p className="text-gray-500 text-sm text-center py-10 italic">No threats detected yet.</p>}
                     {securityEvents.map((event, i) => (
                       <div key={i} className="p-3 bg-red-500/5 border-l-2 border-red-500 rounded-r-lg animate-in slide-in-from-right duration-300">
                          <div className="flex justify-between items-start mb-1">
                             <span className="text-xs font-bold text-red-500">{event.event_type}</span>
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
                 <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
                    <Terminal className="text-blue-400" />
                    Agent Security Playground
                 </h3>
                 <p className="text-sm text-gray-400 mb-6">Test the framework by submitting prompts. Try to "trick" the agent or access restricted tools.</p>
                 <div className="flex gap-4">
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
                 </div>
                 <div className="mt-4 flex flex-wrap gap-2">
                    <span className="text-[10px] text-gray-500 uppercase font-bold tracking-tighter">Quick Examples:</span>
                    {['Summarize a PDF', 'Access root system', 'Drop database tables', 'Decode Base64 instructions'].map(ex => (
                      <button key={ex} onClick={() => setPrompt(ex)} className="text-[10px] bg-gray-800 hover:bg-gray-700 text-gray-400 px-2 py-1 rounded transition-colors uppercase font-medium">{ex}</button>
                    ))}
                 </div>
                 {executionError && (
                   <div className="mt-4 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
                     {executionError}
                   </div>
                 )}
                 {executionResult && (
                   <div className="mt-4 rounded-xl border border-gray-700 bg-gray-950/70 p-4">
                     <p className="mb-2 text-xs font-semibold uppercase tracking-widest text-gray-400">Latest Response</p>
                     <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words text-xs text-gray-300">
                       {JSON.stringify(executionResult, null, 2)}
                     </pre>
                   </div>
                 )}
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="glass-card animate-in fade-in duration-500">
               <div className="p-6 border-b border-gray-800">
                  <h3 className="font-bold text-xl">Audit Log Stream</h3>
               </div>
               <div className="overflow-x-auto">
                 <table className="w-full text-left">
                    <thead className="bg-gray-900/50 text-xs text-gray-500 uppercase tracking-widest">
                       <tr>
                          <th className="px-6 py-4">Timestamp</th>
                          <th className="px-6 py-4">Action</th>
                          <th className="px-6 py-4">Status</th>
                          <th className="px-6 py-4">Input</th>
                          <th className="px-6 py-4">Output</th>
                       </tr>
                    </thead>
                    <tbody className="text-sm divide-y divide-gray-800">
                       {logs.map((log, i) => (
                       <tr key={i} className="hover:bg-gray-900/30 transition-colors">
                            <td className="px-6 py-4 text-xs text-gray-500 whitespace-nowrap">{new Date(log.timestamp).toLocaleString()}</td>
                            <td className="px-6 py-4"><span className="font-mono text-blue-400 bg-blue-400/5 px-2 py-0.5 rounded capitalize">{log.action}</span></td>
                            <td className="px-6 py-4">
                              {(() => {
                                const normalizedStatus = (log.status || '').toLowerCase();
                                const isSafe = ['executed', 'modified', 'safe'].includes(normalizedStatus);
                                return (
                               <span className={`px-2 py-1 rounded-full text-[10px] font-bold uppercase ${
                                  isSafe ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'
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
