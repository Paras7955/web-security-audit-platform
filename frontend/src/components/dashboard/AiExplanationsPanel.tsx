import type { AiExplanation } from "@/lib/securityAuditApi";

export function AiExplanationsPanel({ explanation, message }: { explanation: AiExplanation | null; message: string }) {
  return (
    <div className="aiPanel">
      <div className="panelHeader">
        <h3>AI Explanations</h3>
        <span className="contextBadge">{explanation?.provider ?? "Template default"}</span>
      </div>

      {explanation ? (
        <>
          <dl className="aiMeta">
            <div>
              <dt>Provider</dt>
              <dd>{explanation.provider}</dd>
            </div>
            <div>
              <dt>Fallback</dt>
              <dd>{explanation.fallback_used ? "used" : "not used"}</dd>
            </div>
            <div>
              <dt>Cache</dt>
              <dd>{explanation.cache_hit ? "hit" : "generated"}</dd>
            </div>
            <div>
              <dt>Risk model</dt>
              <dd>{explanation.scoring_model_version}</dd>
            </div>
            <div>
              <dt>Groups</dt>
              <dd>{explanation.groups.length}</dd>
            </div>
          </dl>
          <p>{explanation.executive_summary}</p>
          <p>{explanation.risk_score_explanation}</p>
          <p>{explanation.summary}</p>
          {explanation.provider_error_code ? (
            <p className="errorText">Provider fallback code: {explanation.provider_error_code}</p>
          ) : null}

          {explanation.groups.length > 0 ? (
            <ul className="aiGroupList">
              {explanation.groups.map((group) => (
                <li key={group.label}>
                  <strong>{group.label}</strong>
                  <span>{group.count} finding(s)</span>
                </li>
              ))}
            </ul>
          ) : null}

          {explanation.explanations.length > 0 ? (
            <div className="aiFindingGrid">
              {explanation.explanations.map((item) => (
                <div className="aiFinding" key={item.finding_id}>
                  <div className="aiFindingHeader">
                    <strong>Priority {item.priority}</strong>
                    <small>{item.owasp_mapping}</small>
                  </div>
                  <p>{item.summary}</p>
                  <h4>Why it matters</h4>
                  <p>{item.why_it_matters}</p>
                  <h4>Recommended action</h4>
                  <p>{item.recommended_action}</p>
                  <h4>Limitations</h4>
                  <p>{item.limitations}</p>
                </div>
              ))}
            </div>
          ) : null}
        </>
      ) : (
        <p className="emptyState">{message}</p>
      )}
    </div>
  );
}
