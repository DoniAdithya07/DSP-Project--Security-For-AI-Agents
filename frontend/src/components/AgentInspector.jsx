import React from "react";

const AgentInspector = ({ executionResult, lastPrompt, sessionId, remediationGuidance, getDisplayReasoning }) => (
  <div className="space-y-6 animate-in fade-in duration-500">
    <div className="glass-card p-6">
      <h3 className="font-bold text-xl mb-4">Agent Execution Inspector</h3>
      {!executionResult ? (
        <p className="text-sm text-gray-400">No execution yet. Run a prompt from Dashboard to inspect agent decisions here.</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Last Prompt</p>
            <p className="text-sm text-gray-200">{lastPrompt || "N/A"}</p>
          </div>
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Session ID</p>
            <p className="text-sm text-gray-200 font-mono">{executionResult.session_id || sessionId}</p>
          </div>
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Firewall Decision</p>
            <p className="text-sm text-gray-200">
              {(executionResult.firewall?.status || "unknown").toUpperCase()} ({Math.round(Number(executionResult.firewall?.risk_score || 0) * 100)}%)
            </p>
          </div>
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Gateway Status</p>
            <p className="text-sm text-gray-200">{executionResult.gateway?.status || "unknown"}</p>
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
          <p className="text-xs text-gray-400 mt-1">{executionResult ? "Prompt scanned for threats and policy violations." : "Waiting for first prompt."}</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-4">
          <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Step 2</p>
          <p className="font-medium text-gray-200">Secure Gateway</p>
          <p className="text-xs text-gray-400 mt-1">
            {executionResult ? `Gateway outcome: ${executionResult.gateway?.status || "unknown"}.` : "Gateway decision appears after execution."}
          </p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-4">
          <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Step 3</p>
          <p className="font-medium text-gray-200">Remediation + Response</p>
          <p className="text-xs text-gray-400 mt-1">
            {executionResult ? `${remediationGuidance.length} guidance item(s) available.` : "Guidance and response appear after execution."}
          </p>
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
          <p className="text-sm text-gray-200 whitespace-pre-wrap">{executionResult?.gateway?.agent_response || "No response yet."}</p>
        </div>
      </div>
    </div>
  </div>
);

export default AgentInspector;
