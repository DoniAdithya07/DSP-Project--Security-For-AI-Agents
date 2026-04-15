import React from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Cpu,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  XCircle,
} from "lucide-react";
import { Line } from "react-chartjs-2";

const QUICK_EXAMPLES = [
  "Summarize a PDF",
  "Access root system",
  "Drop database tables",
  "Decode Base64 instructions",
];

const DashboardView = ({
  decisionSummary,
  readinessChecks,
  stats,
  timelineWindow,
  setTimelineWindow,
  chartData,
  chartOptions,
  hasRiskTimelineData,
  filteredSecurityEvents,
  getAlertMessage,
  apiKey,
  onApiKeyChange,
  prompt,
  setPrompt,
  executePrompt,
  dryRun,
  setDryRun,
  loading,
  executionError,
  executionResult,
  sessionId,
  remediationGuidance,
  getDisplayReasoning,
  exportSimulatorJson,
  exportSimulatorReport,
}) => {
  const riskScore = Number(executionResult?.firewall?.risk_score || 0);
  const riskPercent = (riskScore * 100).toFixed(1);
  const blocked = executionResult?.firewall?.status === "blocked";
  const simulationMode = Boolean(executionResult?.gateway?.simulation);
  const zoneLabel = riskScore >= 0.60 ? "Block Zone (60-100%)" : "Safe Zone (0-60%)";
  const matchedRules = executionResult?.firewall?.matched_rules || [];
  const threatSignals = executionResult?.firewall?.threats || [];
  const multiModel = executionResult?.explainability?.multi_model_guard || executionResult?.firewall?.multi_model_guard || {};
  const calibration = executionResult?.explainability?.calibration || executionResult?.firewall?.calibration || {};

  return (
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
              <p className="text-sm text-white/50 italic">
                No anomaly signals in the selected {timelineWindow === "24h" ? "24 hours" : "1 hour"}.
              </p>
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
          {filteredSecurityEvents.length === 0 && (
            <p className="text-gray-500 text-sm text-center py-10 italic">No threats detected in this window.</p>
          )}
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
          onChange={(e) => onApiKeyChange(e.target.value)}
          placeholder="Paste Master API Key..."
          className="bg-gray-900 border border-gray-700 px-4 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none w-64"
        />
      </div>
      <div className="flex gap-3">
        <input
          type="text"
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && executePrompt()}
          placeholder="Enter a prompt (e.g., 'Search for latest AI news' or 'IGNORE PREVIOUS INSTRUCTIONS')..."
          className="flex-1 bg-gray-950/50 border border-gray-700 rounded-xl px-4 py-3 focus:ring-2 focus:ring-blue-500 outline-none transition-all placeholder:text-gray-600"
        />
        <button
          onClick={executePrompt}
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 text-white px-8 py-3 rounded-xl font-bold transition-all shadow-lg shadow-blue-600/20 active:scale-95 flex items-center gap-2"
        >
          {loading ? <RefreshCw className="animate-spin" /> : <ChevronRight />}
          {loading ? (dryRun ? "Simulating..." : "Analyzing...") : (dryRun ? "Simulate" : "Execute")}
        </button>
        <button
          onClick={() => setPrompt("")}
          disabled={!prompt.trim() || loading}
          className="bg-black hover:bg-white/5 disabled:bg-black/40 disabled:text-white/30 text-white px-5 py-3 rounded-xl font-semibold border border-blue-500/20 transition-all"
        >
          Clear
        </button>
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-blue-500/20 bg-black/40 px-3 py-2">
        <label className="inline-flex items-center gap-2 text-sm text-blue-100">
          <input
            type="checkbox"
            checked={dryRun}
            onChange={(event) => setDryRun(event.target.checked)}
            className="accent-blue-500"
          />
          Dry Run Simulator (no tool execution)
        </label>
        <span className="text-xs text-white/60">Safe zone: 0-60% | Block zone: 60-100%</span>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <span className="text-[10px] text-gray-500 uppercase font-bold tracking-tighter">Quick Examples:</span>
        {QUICK_EXAMPLES.map((ex) => (
          <button
            key={ex}
            onClick={() => setPrompt(ex)}
            className="text-[10px] bg-black hover:bg-white/5 text-white/60 border border-blue-500/10 px-2 py-1 rounded transition-colors uppercase font-medium"
          >
            {ex}
          </button>
        ))}
      </div>
      {executionError && <div className="mt-4 rounded-xl border border-blue-500/30 bg-blue-500/5 p-3 text-sm text-blue-200">{executionError}</div>}
      {executionResult && (
        <div
          className={`mt-6 rounded-xl border p-5 ${
            blocked ? "border-blue-500/40 bg-blue-500/5" : "border-blue-500/20 bg-blue-500/5"
          }`}
        >
          <div className="flex items-center gap-3 mb-3">
            {blocked ? (
              <div className="bg-blue-500/10 p-3 rounded-full text-blue-300">
                <ShieldAlert size={28} />
              </div>
            ) : (
              <div className="bg-blue-500/10 p-3 rounded-full text-blue-300">
                <ShieldCheck size={28} />
              </div>
            )}
            <div>
              <h4 className="text-xl font-bold text-blue-200">
                {blocked ? "THREAT BLOCKED" : "PROMPT SAFE"}
              </h4>
              <span className="text-xs text-white/50 uppercase tracking-widest font-mono">
                Risk Score: {riskPercent}%
              </span>
            </div>
          </div>
          <div className="mb-3 flex flex-wrap gap-2">
            <span className="text-xs px-2 py-1 rounded-full border border-blue-500/20 bg-black/40 text-white/80">Decision: {decisionSummary}</span>
            <span className="text-xs px-2 py-1 rounded-full border border-blue-500/20 bg-black/40 text-white/80">
              Mode: {simulationMode ? "Simulation" : "Execution"}
            </span>
            <span className="text-xs px-2 py-1 rounded-full border border-blue-500/20 bg-black/40 text-white/80">
              Zone: {zoneLabel}
            </span>
            <span className="text-xs px-2 py-1 rounded-full border border-blue-500/20 bg-black/40 text-white/80">
              Session: {executionResult.session_id || sessionId}
            </span>
          </div>
          <p className="text-sm text-white/80 p-4 bg-black/40 rounded-lg border border-blue-500/10">
            {blocked
              ? `Security triggered: [${matchedRules.join(", ")}] ${threatSignals.join(", ")}`
              : simulationMode
                ? "Simulation indicates no adversarial intent. Prompt is safe to execute."
                : "No adversarial intent detected. Execution allowed."}
          </p>
          {(matchedRules.length > 0 || threatSignals.length > 0) && (
            <div className="mt-3 text-xs text-white/80 bg-black/40 rounded-lg border border-blue-500/10 p-3">
              <p className="uppercase tracking-wider text-white/50 mb-2">Detection Details</p>
              {matchedRules.length > 0 && <p>Rules: {matchedRules.join(", ")}</p>}
              {threatSignals.length > 0 && <p className="mt-1">Signals: {threatSignals.join(", ")}</p>}
            </div>
          )}
          <div className="mt-3 text-xs text-blue-100 bg-blue-500/5 rounded-lg border border-blue-500/20 p-3">
            <p className="uppercase tracking-wider text-blue-300 mb-2">Explainability</p>
            <p>Mode: {simulationMode ? "Dry run simulation (no tool execution)" : "Live execution"}</p>
            <p className="mt-1">Risk zone decision: {zoneLabel}</p>
            <p className="mt-1">Matched rules: {matchedRules.length}</p>
            <p className="mt-1">Threat signals: {threatSignals.length}</p>
            {multiModel?.models && (
              <p className="mt-1">
                Model votes: regex {Math.round(Number(multiModel.models.regex?.score || 0) * 100)}% |
                ml {Math.round(Number(multiModel.models.ml?.score || 0) * 100)}% |
                llm {Math.round(Number(multiModel.models.llm?.score || 0) * 100)}%
              </p>
            )}
            {typeof calibration?.bias === "number" && (
              <p className="mt-1">Calibration bias: {calibration.bias >= 0 ? "+" : ""}{(calibration.bias * 100).toFixed(1)}%</p>
            )}
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              onClick={exportSimulatorJson}
              className="bg-black hover:bg-white/5 text-white border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold"
            >
              Export Simulator JSON
            </button>
            <button
              onClick={exportSimulatorReport}
              className="bg-black hover:bg-white/5 text-white border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold"
            >
              Export Simulator Report
            </button>
          </div>
          <div className="mt-4 rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
            <p className="text-xs text-blue-300 uppercase tracking-wider mb-2 font-semibold">Remediation Guidance</p>
            <div className="space-y-1 text-sm text-blue-100">
              {remediationGuidance.map((step, idx) => (
                <p key={idx}>- {step}</p>
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
  );
};

export default DashboardView;
