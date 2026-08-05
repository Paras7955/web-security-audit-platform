"use client";

import { FormEvent, useState } from "react";

import { AppIcon } from "@/components/AppIcon";
import { authSessionSource, clearSessionAuthToken, setSessionAuthToken, type AuthSessionSource } from "@/lib/securityAuditApi";

export function OperatorSessionPanel({ onSessionChange }: { onSessionChange: () => Promise<boolean> }) {
  const [token, setToken] = useState("");
  const [source, setSource] = useState<AuthSessionSource>(() => authSessionSource());
  const [message, setMessage] = useState(sessionMessage(source));
  const [isBusy, setIsBusy] = useState(false);

  async function useToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token.trim()) return;
    setIsBusy(true);
    setMessage("Verifying the operator session against this local workspace…");
    setSessionAuthToken(token);
    setToken("");
    try {
      const accepted = await onSessionChange();
      if (!accepted) throw new Error("Authentication failed.");
      setSource("oidc");
      setMessage("Operator bearer session active in memory for this browser tab.");
    } catch {
      clearSessionAuthToken();
      const fallbackSource = authSessionSource();
      setSource(fallbackSource);
      if (fallbackSource === "development") {
        await onSessionChange();
        setMessage("The bearer token was not accepted. It was cleared, and the local development session was restored.");
      } else {
        setMessage("The bearer token was not accepted. It and the previous protected workspace state were cleared from memory.");
      }
    } finally {
      setIsBusy(false);
    }
  }

  async function clearToken() {
    clearSessionAuthToken();
    setSource(authSessionSource());
    setMessage(sessionMessage(authSessionSource()));
    setIsBusy(true);
    try {
      await onSessionChange();
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <section className="operatorSessionPanel" aria-labelledby="operator-session-title">
      <div className="sectionHeading">
        <div>
          <p className="panelKicker">Operator access</p>
          <h3 id="operator-session-title">OIDC and local development session</h3>
          <p>Use an identity-provider-issued platform bearer token when OIDC is enabled. The token stays in memory and is never written to browser storage.</p>
        </div>
        <span className={`sessionStatus sessionStatus-${source}`}><AppIcon name={source === "none" ? "finding" : "check"} size={14} />{sourceLabel(source)}</span>
      </div>
      <form className="operatorSessionForm" onSubmit={useToken}>
        <label>
          <span>Platform bearer token</span>
          <input
            type="password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder="Paste an OIDC access token"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <div className="actions">
          <button type="submit" disabled={isBusy || !token.trim()}>{isBusy ? "Checking…" : "Use token for this tab"}</button>
          <button type="button" className="secondaryButton" onClick={clearToken} disabled={isBusy || source !== "oidc"}>Clear session token</button>
        </div>
      </form>
      <p className="formMessage" role="status" aria-live="polite">{message}</p>
    </section>
  );
}

function sourceLabel(source: AuthSessionSource) {
  if (source === "oidc") return "OIDC bearer active";
  if (source === "development") return "Development token active";
  return "Authentication required";
}

function sessionMessage(source: AuthSessionSource) {
  if (source === "oidc") return "An operator bearer token is active for this browser tab.";
  if (source === "development") return "The build-provided local development token is active.";
  return "Provide a platform bearer token to load protected workspace data.";
}
