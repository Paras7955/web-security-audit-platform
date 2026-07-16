"use client";

import { useMemo, useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import type { AuditLogEntry } from "@/lib/securityAuditApi";

const activityPageSize = 8;

export function AuditLogPanel({ entries, onRefresh }: { entries: AuditLogEntry[]; onRefresh: () => void }) {
  const [query, setQuery] = useState("");
  const [visibleCount, setVisibleCount] = useState(activityPageSize);
  const filteredEntries = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return entries;
    return entries.filter((entry) => [entry.event_type, entry.resource_type, entry.resource_id, metadataSummary(entry.metadata_json)]
      .some((value) => value?.toLowerCase().includes(normalizedQuery)));
  }, [entries, query]);
  const visibleEntries = filteredEntries.slice(0, visibleCount);
  const remainingCount = Math.max(0, filteredEntries.length - visibleEntries.length);

  function handleQueryChange(value: string) {
    setQuery(value);
    setVisibleCount(activityPageSize);
  }

  return (
    <section className="auditLogPanel">
      <div className="panelHeader">
        <div><h3>Workspace activity</h3><p>Safe audit metadata for actions in this workspace.</p></div>
        <span className="contextBadge">{filteredEntries.length}</span>
      </div>
      <div className="auditLogToolbar">
        <label className="searchField compactSearch">
          <AppIcon name="search" size={16} />
          <span className="srOnly">Search workspace activity</span>
          <input value={query} onChange={(event) => handleQueryChange(event.target.value)} placeholder="Search event or resource" />
        </label>
        <button type="button" className="secondaryButton" onClick={onRefresh}><AppIcon name="refresh" size={15} />Refresh history</button>
      </div>
      {visibleEntries.length ? (
        <div className="auditLogTableWrap">
          <table className="auditLogTable">
            <thead><tr><th>Event</th><th>Resource</th><th>Safe details</th><th>Time</th></tr></thead>
            <tbody>
              {visibleEntries.map((entry) => (
                <tr key={entry.id}>
                  <td><span className="auditEvent"><AppIcon name="activity" size={14} />{formatEvent(entry.event_type)}</span></td>
                  <td>{entry.resource_type ? `${formatEvent(entry.resource_type)}${entry.resource_id ? ` · ${entry.resource_id.slice(0, 8)}` : ""}` : "Workspace"}</td>
                  <td>{metadataSummary(entry.metadata_json) || "No additional metadata"}</td>
                  <td><time dateTime={entry.created_at}>{formatDate(entry.created_at)}</time></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <div className="emptyState richEmptyState"><AppIcon name="activity" size={22} /><strong>{entries.length ? "No activity matches this search" : "No workspace activity yet"}</strong><span>Target, scan, report, and management events will appear here.</span></div>}
      {filteredEntries.length > activityPageSize ? (
        <nav className="resultsPagination auditLogDisclosure" aria-label="Workspace activity visibility">
          {visibleEntries.length > activityPageSize ? (
            <button type="button" className="secondaryButton" onClick={() => setVisibleCount(activityPageSize)}>
              Show fewer
            </button>
          ) : null}
          <span>Showing <strong>{visibleEntries.length}</strong> of <strong>{filteredEntries.length}</strong></span>
          {remainingCount > 0 ? (
            <button
              type="button"
              className="secondaryButton"
              onClick={() => setVisibleCount((currentCount) => Math.min(currentCount + activityPageSize, filteredEntries.length))}
            >
              Show {Math.min(activityPageSize, remainingCount)} more
            </button>
          ) : null}
        </nav>
      ) : null}
    </section>
  );
}

function metadataSummary(metadata: Record<string, unknown>) {
  return Object.entries(metadata)
    .filter(([key]) => !forbiddenMetadataKeys.has(key.toLowerCase()) && !sensitiveKeyPattern.test(key))
    .slice(0, 4)
    .map(([key, value]) => `${formatEvent(key)}: ${safeValue(value)}`)
    .join(" · ");
}

function safeValue(value: unknown) {
  if (value === null || value === undefined) return "none";
  if (typeof value === "string") return redactFreeText(value).slice(0, 120);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? "" : "s"}`;
  return "recorded";
}

const forbiddenMetadataKeys = new Set([
  "mode",
  "cancelled_by_user_id",
  "cancellation_requested_by_user_id",
  "error_detail",
  "failure_detail",
  "raw_error",
  "repo_path",
  "artifact_path",
  "traceback"
]);

const sensitiveKeyPattern = /(secret|token|password|authorization|cookie|credential|header|body|evidence|exception|trace|path|query|fragment)/i;

function redactFreeText(value: string) {
  return value
    .replace(/Bearer\s+[^\s]+/gi, "[redacted credential]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted token]")
    .replace(/(https?:\/\/[^\s?#]+)[?#][^\s]*/gi, "$1")
    .replace(/(?:^|\s)\/(?:[^\s/]+\/){2,}[^\s]*/g, " [redacted path]");
}

function formatEvent(value: string) {
  return value.replaceAll("_", " ").replaceAll(".", " · ");
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value));
}
