import React from "react";
import { Database, Download, FileText, Search, SlidersHorizontal } from "lucide-react";

const LogsPanel = ({
  visibleLogs,
  timeFilteredLogs,
  timelineLabel,
  totalLogsLoaded,
  logFetchError,
  timelineWindow,
  setTimelineWindow,
  exportAuditLogs,
  exportSecurityEvents,
  exportIncidentReport,
  logSearch,
  setLogSearch,
  logStatusFilter,
  setLogStatusFilter,
  formatTimestamp,
}) => (
  <div className="glass-card animate-in fade-in duration-500">
    <div className="p-6 border-b border-gray-800 flex flex-wrap items-center justify-between gap-3">
      <div>
        <h3 className="font-bold text-xl">Audit Log Stream</h3>
        <p className="text-xs text-gray-500 mt-1">
          {visibleLogs.length} shown - {timeFilteredLogs.length} in {timelineLabel} - {totalLogsLoaded} loaded
        </p>
        {logFetchError && <p className="text-xs text-red-300 mt-2">{logFetchError}</p>}
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
                  : "No audit records match the current filters."}
              </td>
            </tr>
          )}
          {visibleLogs.map((log, i) => (
            <tr key={i} className="hover:bg-gray-900/30 transition-colors">
              <td className="px-6 py-4 text-xs text-gray-500 whitespace-nowrap">{formatTimestamp(log.timestamp)}</td>
              <td className="px-6 py-4">
                <span className="font-mono text-blue-400 bg-blue-400/5 px-2 py-0.5 rounded capitalize">{log.action}</span>
              </td>
              <td className="px-6 py-4">
                {(() => {
                  const normalizedStatus = (log.status || "").toLowerCase();
                  const isSafe = ["executed", "modified", "safe"].includes(normalizedStatus);
                  return (
                    <span
                      className={`px-2 py-1 rounded-full text-[10px] font-bold uppercase ${
                        isSafe ? "bg-blue-500/10 text-blue-200 border border-blue-500/20" : "bg-white/5 text-white/80 border border-white/10"
                      }`}
                    >
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
);

export default LogsPanel;
