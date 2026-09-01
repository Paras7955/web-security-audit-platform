import type { AiExplanation, FindingExplanation } from "@/lib/securityAuditApi";

const visibleExplanationCount = 5;

export function FindingGuidancePanel({
  explanation,
  message,
  canGenerate,
  isGenerating,
  onGenerate
}: {
  explanation: AiExplanation | null;
  message: string;
  canGenerate: boolean;
  isGenerating: boolean;
  onGenerate: () => void;
}) {
  const visibleExplanations = explanation?.explanations.slice(0, visibleExplanationCount) ?? [];
  const remainingExplanations = explanation?.explanations.slice(visibleExplanationCount) ?? [];
  const externalProviderConfigured = explanation?.configured_provider === "openai";
  const providerLabel = externalProviderConfigured
    ? explanation?.provider === "openai" ? "AI-assisted" : explanation?.fallback_used ? "Local fallback" : "External AI available"
    : "Local guidance";
  const generateLabel = externalProviderConfigured ? "Generate AI-assisted guidance" : "Refresh local guidance";

  return (
    <div className="aiPanel">
      <div className="panelHeader">
        <div><h3>Finding guidance</h3><p>Turn prioritized normalized findings into impact, recommended action, and stated limitations.</p></div>
        <div className="aiPanelActions">
          <span className="contextBadge">{providerLabel}</span>
          <button type="button" className="secondaryButton" onClick={onGenerate} disabled={!canGenerate || isGenerating}>
            {isGenerating ? "Generating…" : generateLabel}
          </button>
        </div>
      </div>

      {externalProviderConfigured ? (
        <p className="aiConsentNotice">
          Generating AI-assisted guidance sends only bounded, normalized, independently redacted web-finding fields to the operator-configured provider. Raw artifacts, response bodies, credentials, cookies, queries, repository findings, and provider errors stay local.
        </p>
      ) : null}

      {explanation ? (
        <>
          <p className="aiExecutiveSummary">{explanation.executive_summary}</p>
          <details className="aiContextDetails">
            <summary>Scoring and generation details</summary>
            <div className="aiContextBody">
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
              <p>{explanation.risk_score_explanation}</p>
              <p>{explanation.summary}</p>
              {explanation.provider_error_code ? (
                <p className="errorText">Provider fallback code: {explanation.provider_error_code}</p>
              ) : null}
            </div>
          </details>

          {explanation.groups.length > 0 ? (
            <ul className="aiGroupList" aria-label="Finding groups">
              {explanation.groups.map((group) => (
                <li key={group.label}>
                  <strong>{group.label}</strong>
                  <span>{group.count} finding(s)</span>
                </li>
              ))}
            </ul>
          ) : null}

          {explanation.explanations.length > 0 ? (
            <section className="aiExplanationSection" aria-labelledby="prioritized-explanations-heading">
              <div className="aiExplanationHeading">
                <h4 id="prioritized-explanations-heading">Prioritized actions</h4>
                <span>{explanation.explanations.length} total</span>
              </div>
              <div className="aiFindingGrid">
                {visibleExplanations.map((item) => <FindingExplanationRow item={item} key={item.finding_id} />)}
                {remainingExplanations.length > 0 ? (
                  <details className="aiOverflowDetails">
                    <summary>Show {remainingExplanations.length} more actions</summary>
                    <div className="aiOverflowList">
                      {remainingExplanations.map((item) => <FindingExplanationRow item={item} key={item.finding_id} />)}
                    </div>
                  </details>
                ) : null}
              </div>
            </section>
          ) : null}
        </>
      ) : (
        <div className="emptyState aiEmptyState" role="status" aria-live="polite">
          <strong>{canGenerate ? "Finding guidance is ready" : "Finding guidance is unavailable for this audit"}</strong>
          <span>{message}</span>
        </div>
      )}
    </div>
  );
}

function FindingExplanationRow({ item }: { item: FindingExplanation }) {
  return (
    <details className="aiFinding">
      <summary className="aiFindingSummary">
        <span className="aiFindingRank"><strong>Priority {item.priority}</strong><small>{item.owasp_mapping}</small></span>
        <span>{item.summary}</span>
      </summary>
      <div className="aiFindingBody">
        <section>
          <h5>Why it matters</h5>
          <p>{item.why_it_matters}</p>
        </section>
        <section>
          <h5>Recommended action</h5>
          <p>{item.recommended_action}</p>
        </section>
        <section className="aiFindingLimitations">
          <h5>Limitations</h5>
          <p>{item.limitations}</p>
        </section>
      </div>
    </details>
  );
}
