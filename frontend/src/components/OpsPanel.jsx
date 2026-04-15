import React, { useEffect, useMemo, useState } from "react";

const OpsPanel = ({
  dashboardUser,
  dashboardToken,
  onLogin,
  onLogout,
  opsData,
  opsStatus,
  handlers,
}) => {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [policyText, setPolicyText] = useState(JSON.stringify(opsData.currentPolicy || {}, null, 2));
  const [policyNote, setPolicyNote] = useState("");
  const [threatJson, setThreatJson] = useState(
    JSON.stringify([{ rule_id: "jailbreak_custom", pattern: "ignore all previous", reason: "Custom jailbreak", weight: 0.8 }], null, 2)
  );
  const [threatUrl, setThreatUrl] = useState("");
  const [toolName, setToolName] = useState("db_read");
  const [toolMaxRisk, setToolMaxRisk] = useState("0.8");
  const [toolApprovalRisk, setToolApprovalRisk] = useState("0.6");
  const [replaySessionId, setReplaySessionId] = useState("");
  const [rotationLabel, setRotationLabel] = useState("ops-rotated-key");
  const [archiveDays, setArchiveDays] = useState("30");
  const [restoreBackupName, setRestoreBackupName] = useState("");
  const [feedbackExpected, setFeedbackExpected] = useState("blocked");
  const [feedbackActual, setFeedbackActual] = useState("safe");
  const [feedbackRisk, setFeedbackRisk] = useState("0.7");
  const [feedbackSession, setFeedbackSession] = useState("");
  const [feedbackNotes, setFeedbackNotes] = useState("");
  const [newUser, setNewUser] = useState({
    username: "",
    password: "",
    role: "analyst",
    team: "default",
    is_active: true,
  });

  const isAuthenticated = Boolean(dashboardToken);
  const topThreat = opsData.scorecard?.top_threats?.[0];
  const trendRows = opsData.scorecard?.daily_trend || [];
  const replayAuditCount = opsData.replay?.timeline?.audit_logs?.length || 0;
  const replayEventCount = opsData.replay?.timeline?.security_events?.length || 0;

  const policyVersionsText = useMemo(
    () => (opsData.policyVersions || []).slice(0, 5).map((item) => `v${item.version} by ${item.changed_by}`).join(" | ") || "No versions yet",
    [opsData.policyVersions]
  );

  useEffect(() => {
    setPolicyText(JSON.stringify(opsData.currentPolicy || {}, null, 2));
  }, [opsData.currentPolicy]);

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="glass-card p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-xl font-bold">Operations & Governance</h3>
            <p className="text-sm text-gray-400 mt-1">Policy studio, approvals, threat feed, replay, scorecard, backups and live stream.</p>
          </div>
          <div className="text-xs border border-blue-500/20 bg-black/40 rounded-lg px-3 py-2">
            {isAuthenticated
              ? `Signed in as ${dashboardUser?.username || "user"} (${dashboardUser?.role || "unknown"} | ${dashboardUser?.team || "default"})`
              : "Not signed in"}
          </div>
        </div>
        {!isAuthenticated ? (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mt-4">
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
            <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
            <button onClick={() => onLogin(username, password)} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-semibold">Sign In</button>
            <div className="text-xs text-white/70 flex items-center">Use dashboard auth for admin features.</div>
          </div>
        ) : (
          <div className="mt-4 flex flex-wrap gap-2">
            <button onClick={handlers.refreshAll} className="bg-black hover:bg-white/5 text-white border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold">Refresh Ops Data</button>
            <button onClick={onLogout} className="bg-black hover:bg-white/5 text-white border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold">Sign Out</button>
          </div>
        )}
        {opsStatus.message && (
          <div className={`mt-4 rounded-lg px-3 py-2 text-sm border ${opsStatus.kind === "error" ? "bg-white/5 border-white/10 text-white/80" : "bg-blue-500/10 border-blue-500/30 text-blue-200"}`}>
            {opsStatus.message}
          </div>
        )}
      </div>

      {isAuthenticated && (
        <>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Policy Studio</h4>
              <p className="text-xs text-gray-500 mb-2">Recent versions: {policyVersionsText}</p>
              <textarea
                value={policyText}
                onChange={(e) => setPolicyText(e.target.value)}
                className="w-full h-56 bg-gray-950/50 border border-gray-700 rounded-lg p-3 text-xs font-mono"
              />
              <div className="mt-3 flex flex-wrap gap-2">
                <input value={policyNote} onChange={(e) => setPolicyNote(e.target.value)} placeholder="Change note" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm flex-1 min-w-[180px]" />
                <button onClick={() => handlers.publishPolicy(policyText, policyNote)} className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded-lg text-xs font-semibold">Publish Policy</button>
              </div>
            </div>

            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Human Approvals</h4>
              <div className="space-y-2 max-h-72 overflow-y-auto pr-2">
                {(opsData.pendingApprovals || []).length === 0 && <p className="text-xs text-white/60">No pending approvals.</p>}
                {(opsData.pendingApprovals || []).map((item) => (
                  <div key={item.id} className="border border-blue-500/20 rounded-lg p-3 bg-black/30">
                    <p className="text-xs text-white/80">#{item.id} | Tool: {item.tool_name} | Risk: {(Number(item.risk_score || 0) * 100).toFixed(1)}%</p>
                    <p className="text-xs text-white/50 mt-1 line-clamp-2">{item.prompt}</p>
                    <div className="mt-2 flex gap-2">
                      <button onClick={() => handlers.decideApproval(item.id, "approve")} className="bg-blue-600 hover:bg-blue-500 text-white px-2 py-1 rounded text-xs">Approve</button>
                      <button onClick={() => handlers.decideApproval(item.id, "reject")} className="bg-black hover:bg-white/5 border border-blue-500/20 px-2 py-1 rounded text-xs">Reject</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Threat Intelligence Feed</h4>
              <textarea
                value={threatJson}
                onChange={(e) => setThreatJson(e.target.value)}
                className="w-full h-40 bg-gray-950/50 border border-gray-700 rounded-lg p-3 text-xs font-mono"
              />
              <div className="mt-3 flex flex-wrap gap-2">
                <button onClick={() => handlers.importThreatIntel(threatJson)} className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded-lg text-xs font-semibold">Import JSON Rules</button>
                <input value={threatUrl} onChange={(e) => setThreatUrl(e.target.value)} placeholder="Remote feed URL (optional)" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm flex-1 min-w-[180px]" />
                <button onClick={() => handlers.syncThreatFeed(threatUrl)} className="bg-black hover:bg-white/5 border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold">Sync Remote Feed</button>
              </div>
              <p className="text-xs text-gray-500 mt-2">Loaded rules: {(opsData.threatIntel || []).length} | Last sync: {opsData.threatStatus?.last_sync_at || "n/a"}</p>
            </div>

            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Tool Risk Profiles</h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                <input value={toolName} onChange={(e) => setToolName(e.target.value)} placeholder="tool_name" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
                <input value={toolMaxRisk} onChange={(e) => setToolMaxRisk(e.target.value)} placeholder="max_risk_score" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
                <input value={toolApprovalRisk} onChange={(e) => setToolApprovalRisk(e.target.value)} placeholder="require_approval_above" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
              </div>
              <button onClick={() => handlers.saveToolProfile(toolName, toolMaxRisk, toolApprovalRisk)} className="mt-3 bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded-lg text-xs font-semibold">Save Tool Profile</button>
              <div className="mt-3 max-h-36 overflow-y-auto space-y-1 pr-2">
                {(opsData.toolProfiles || []).map((item) => (
                  <p key={item.tool_name} className="text-xs text-white/80">{item.tool_name}: max {item.max_risk_score}, approval {item.require_approval_above}</p>
                ))}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Session Replay</h4>
              <div className="flex flex-wrap gap-2">
                <input value={replaySessionId} onChange={(e) => setReplaySessionId(e.target.value)} placeholder="session_id" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm flex-1 min-w-[180px]" />
                <button onClick={() => handlers.loadReplay(replaySessionId)} className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded-lg text-xs font-semibold">Load Replay</button>
              </div>
              <p className="text-xs text-gray-400 mt-2">Audit rows: {replayAuditCount} | Security events: {replayEventCount}</p>
              <div className="mt-2 max-h-40 overflow-y-auto text-xs text-white/70 space-y-1 pr-2">
                {(opsData.replay?.timeline?.audit_logs || []).slice(0, 8).map((row) => (
                  <p key={row.id || `${row.timestamp}-${row.action}`}>{row.timestamp} | {row.action} | {row.status}</p>
                ))}
              </div>
            </div>

            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Realtime Security Stream</h4>
              <p className="text-xs text-gray-500">Live events received: {(opsData.liveEvents || []).length}</p>
              <div className="mt-2 max-h-44 overflow-y-auto space-y-2 pr-2">
                {(opsData.liveEvents || []).slice(0, 20).map((event, idx) => (
                  <div key={`${event.timestamp || idx}-${idx}`} className="border border-blue-500/20 rounded-lg p-2 bg-black/30">
                    <p className="text-xs text-blue-200">{event.type || "event"}</p>
                    <p className="text-[11px] text-white/70">{JSON.stringify(event)}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Scorecard & SLO</h4>
              <p className="text-sm">Safe ratio: <span className="text-blue-300 font-semibold">{opsData.scorecard?.safe_ratio_percent ?? 0}%</span></p>
              <p className="text-sm mt-1">Top threat: <span className="text-blue-200">{topThreat ? `${topThreat.event_type} (${topThreat.count})` : "n/a"}</span></p>
              <p className="text-sm mt-1">Availability: <span className="text-blue-200">{opsData.slo?.availability_percent ?? 0}%</span></p>
              <p className="text-sm mt-1">P95 latency: <span className="text-blue-200">{opsData.slo?.p95_latency_ms ?? 0} ms</span></p>
              <div className="mt-3 max-h-36 overflow-y-auto text-xs text-white/70 space-y-1 pr-2">
                {trendRows.slice(-10).map((row) => (
                  <p key={row.date}>{row.date}: safe {row.safe}, blocked {row.blocked}</p>
                ))}
              </div>
            </div>

            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Calibration Feedback</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <input value={feedbackSession} onChange={(e) => setFeedbackSession(e.target.value)} placeholder="session_id" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
                <input value={feedbackRisk} onChange={(e) => setFeedbackRisk(e.target.value)} placeholder="risk_score (0-1)" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
                <select value={feedbackExpected} onChange={(e) => setFeedbackExpected(e.target.value)} className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm">
                  <option value="blocked">Expected blocked</option>
                  <option value="safe">Expected safe</option>
                </select>
                <select value={feedbackActual} onChange={(e) => setFeedbackActual(e.target.value)} className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm">
                  <option value="safe">Actual safe</option>
                  <option value="blocked">Actual blocked</option>
                </select>
              </div>
              <input value={feedbackNotes} onChange={(e) => setFeedbackNotes(e.target.value)} placeholder="notes" className="mt-2 bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm w-full" />
              <button onClick={() => handlers.submitCalibration(feedbackSession, feedbackExpected, feedbackActual, feedbackRisk, feedbackNotes)} className="mt-3 bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded-lg text-xs font-semibold">Submit Feedback</button>
              <p className="text-xs text-gray-500 mt-2">Current bias: {opsData.calibration?.bias ?? 0}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Key Rotation, Archives, Backups</h4>
              <div className="flex flex-wrap gap-2">
                <input value={rotationLabel} onChange={(e) => setRotationLabel(e.target.value)} placeholder="rotation label" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm flex-1 min-w-[180px]" />
                <button onClick={() => handlers.rotateKey(rotationLabel)} className="bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded-lg text-xs font-semibold">Rotate API Key</button>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <input value={archiveDays} onChange={(e) => setArchiveDays(e.target.value)} placeholder="archive days" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm w-28" />
                <button onClick={() => handlers.archiveLogs(archiveDays)} className="bg-black hover:bg-white/5 border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold">Archive Old Logs</button>
                <button onClick={handlers.createBackup} className="bg-black hover:bg-white/5 border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold">Create Backup</button>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <input value={restoreBackupName} onChange={(e) => setRestoreBackupName(e.target.value)} placeholder="backup filename" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm flex-1 min-w-[180px]" />
                <button onClick={() => handlers.restoreBackup(restoreBackupName, true)} className="bg-black hover:bg-white/5 border border-blue-500/20 px-3 py-2 rounded-lg text-xs font-semibold">Dry Run Restore</button>
              </div>
              <div className="mt-2 max-h-36 overflow-y-auto text-xs text-white/70 space-y-1 pr-2">
                {(opsData.backups || []).slice(0, 8).map((item) => <p key={item.name}>{item.name}</p>)}
              </div>
            </div>

            <div className="glass-card p-6">
              <h4 className="font-semibold mb-3">Dashboard Users (Role/Team Access)</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <input value={newUser.username} onChange={(e) => setNewUser((s) => ({ ...s, username: e.target.value }))} placeholder="username" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
                <input value={newUser.password} onChange={(e) => setNewUser((s) => ({ ...s, password: e.target.value }))} placeholder="password" type="password" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
                <input value={newUser.team} onChange={(e) => setNewUser((s) => ({ ...s, team: e.target.value }))} placeholder="team" className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm" />
                <select value={newUser.role} onChange={(e) => setNewUser((s) => ({ ...s, role: e.target.value }))} className="bg-gray-900 border border-gray-700 px-3 py-2 rounded-lg text-sm">
                  <option value="viewer">viewer</option>
                  <option value="analyst">analyst</option>
                  <option value="admin">admin</option>
                </select>
              </div>
              <button onClick={() => handlers.saveUser(newUser)} className="mt-3 bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded-lg text-xs font-semibold">Create/Update User</button>
              <div className="mt-3 max-h-36 overflow-y-auto text-xs text-white/70 space-y-1 pr-2">
                {(opsData.users || []).map((item) => (
                  <p key={item.username}>{item.username} | {item.role} | {item.team} | {item.is_active ? "active" : "inactive"}</p>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default OpsPanel;
