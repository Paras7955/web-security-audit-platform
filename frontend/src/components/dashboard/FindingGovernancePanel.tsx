import { AppIcon } from "@/components/AppIcon";
import type { SuppressionRule, Tag, TagAssignment } from "@/lib/securityAuditApi";

export function FindingGovernancePanel({
  suppressions,
  tags,
  assignments,
  busyActionId,
  onRevokeSuppression,
  onArchiveTag,
  onUnassignTag
}: {
  suppressions: SuppressionRule[];
  tags: Tag[];
  assignments: TagAssignment[];
  busyActionId: string;
  onRevokeSuppression: (rule: SuppressionRule) => void;
  onArchiveTag: (tag: Tag) => void;
  onUnassignTag: (assignment: TagAssignment) => void;
}) {
  const activeSuppressions = suppressions.filter((rule) => !rule.revoked_at);
  const tagById = new Map(tags.map((tag) => [tag.id, tag]));

  return (
    <details className="findingGovernancePanel">
      <summary>
        <span><AppIcon name="shield" size={17} />Suppression and tag history</span>
        <span>{activeSuppressions.length} active suppressions · {assignments.length} assignments</span>
      </summary>
      <div className="findingGovernanceGrid">
        <section aria-labelledby="active-suppressions-title">
          <div className="authSectionHeader"><span><AppIcon name="finding" size={18} /></span><div><h4 id="active-suppressions-title">Active suppressions</h4><p>Revoke a rule without erasing its decision history.</p></div></div>
          {activeSuppressions.length ? (
            <ul className="governanceList">
              {activeSuppressions.map((rule) => (
                <li key={rule.id}>
                  <div><strong>{rule.reason}</strong><small>{rule.severity ?? "Any severity"} · {rule.source_tool ?? "Any scanner"}</small></div>
                  <button type="button" className="secondaryButton" onClick={() => onRevokeSuppression(rule)} disabled={busyActionId === rule.id}>{busyActionId === rule.id ? "Revoking…" : "Revoke"}</button>
                </li>
              ))}
            </ul>
          ) : <p className="emptyState">No active suppression rules.</p>}
        </section>

        <section aria-labelledby="tag-governance-title">
          <div className="authSectionHeader"><span><AppIcon name="intelligence" size={18} /></span><div><h4 id="tag-governance-title">Tags and assignments</h4><p>Archive unused tags or remove one audited assignment at a time.</p></div></div>
          {tags.length ? (
            <ul className="governanceList governanceTagList">
              {tags.map((tag) => {
                const tagAssignments = assignments.filter((assignment) => assignment.tag_id === tag.id);
                return (
                  <li key={tag.id}>
                    <div><strong>{tag.label}</strong><small>{tag.archived_at ? "Archived · " : ""}{tagAssignments.length} active assignment{tagAssignments.length === 1 ? "" : "s"}</small></div>
                    {tag.archived_at ? <span className="contextBadge">History</span> : <button type="button" className="secondaryButton" onClick={() => onArchiveTag(tag)} disabled={busyActionId === tag.id}>{busyActionId === tag.id ? "Archiving…" : "Archive"}</button>}
                    {tagAssignments.length ? (
                      <ul className="tagAssignmentList">
                        {tagAssignments.map((assignment) => (
                          <li key={assignment.id}>
                            <span>{assignment.resource_type.replaceAll("_", " ")} · {shortId(assignment.resource_id)}</span>
                            <button type="button" className="textButton" onClick={() => onUnassignTag(assignment)} disabled={busyActionId === assignment.id}>{busyActionId === assignment.id ? "Removing…" : `Remove ${tagById.get(assignment.tag_id)?.label ?? "tag"}`}</button>
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          ) : <p className="emptyState">No active tags.</p>}
        </section>
      </div>
    </details>
  );
}

function shortId(value: string) {
  return value.length > 12 ? `${value.slice(0, 8)}…` : value;
}
