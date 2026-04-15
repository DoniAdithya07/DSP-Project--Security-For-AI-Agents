import React from "react";

const SettingsPanel = ({
  readinessChecks,
  apiKey,
  setApiKey,
  agentId,
  setAgentId,
  sessionId,
  setSessionId,
  createSessionId,
  refreshIntervalMs,
  setRefreshIntervalMs,
  testConnection,
  regenerateSessionId,
  fetchLogs,
  connectionState,
  settingsBackendUrl,
  setSettingsBackendUrl,
  settingsOllamaUrl,
  setSettingsOllamaUrl,
  settingsOllamaModel,
  setSettingsOllamaModel,
}) => (
  <div className="space-y-6 animate-in fade-in duration-500">
    <div className="glass-card p-6">
      <h3 className="font-semibold text-lg mb-2">Setup Checklist</h3>
      <p className="text-sm text-gray-400 mb-4">Use this order for reliable startup: set key, test connection, verify LLM host, then run prompt.</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {readinessChecks.map((check) => (
          <div key={`settings-${check.label}`} className="rounded-lg border border-gray-800 bg-gray-900/50 px-4 py-3">
            <p className={`text-sm font-medium ${check.done ? "text-blue-200" : "text-white/70"}`}>{check.label}</p>
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
            onChange={(event) => setApiKey(event.target.value)}
            className="w-full bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none"
          />
          <p className="text-[11px] text-gray-500 mt-2">This should match SECURITY_API_KEY unless you use dashboard login in Ops.</p>
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
          <label className="text-xs text-gray-500 uppercase tracking-widest block mb-2">Backend URL</label>
          <input
            type="text"
            value={settingsBackendUrl}
            onChange={(event) => setSettingsBackendUrl(event.target.value)}
            placeholder="/api or http://localhost:8000"
            className="w-full bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm text-gray-300 focus:ring-2 focus:ring-blue-500 outline-none"
          />
          <p className="text-[11px] text-gray-500 mt-2">Use `/api` for Vite proxy, or a full backend URL for direct calls.</p>
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
        <button onClick={testConnection} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-semibold">
          Test Connection
        </button>
        <button
          onClick={regenerateSessionId}
          className="bg-black hover:bg-white/5 text-white px-4 py-2 rounded-lg text-sm font-semibold border border-blue-500/20"
        >
          Regenerate Session
        </button>
        <button onClick={fetchLogs} className="bg-black hover:bg-white/5 text-white px-4 py-2 rounded-lg text-sm font-semibold border border-blue-500/20">
          Refresh Logs
        </button>
      </div>

      <div
        className={`mt-4 rounded-lg px-3 py-2 text-sm border ${
          connectionState.status === "ok"
            ? "bg-blue-500/10 border-blue-500/30 text-blue-200"
            : connectionState.status === "error"
              ? "bg-white/5 border-white/10 text-white/80"
              : "bg-black/40 border-blue-500/10 text-white/70"
        }`}
      >
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
        <p className="text-xs text-gray-500">Update backend values in .env and recreate backend container for server-side changes to take effect.</p>
      </div>
    </div>
  </div>
);

export default SettingsPanel;
