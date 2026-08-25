import { AppIcon } from "@/components/AppIcon";
import { formatScanProfileLabel } from "@/components/dashboard/ScanControls";
import type { TargetPolicy } from "@/lib/securityAuditApi";

export function TargetPolicyCatalog({ policies }: { policies: TargetPolicy[] }) {
  return (
    <details className="targetPolicyCatalog">
      <summary>
        <span><AppIcon name="shield" size={17} />Configured target policies</span>
        <span>{policies.length} exact {policies.length === 1 ? "policy" : "policies"}</span>
      </summary>
      <div className="targetPolicyTableWrap">
        {policies.length ? (
          <table className="targetPolicyTable">
            <thead><tr><th>Policy</th><th>Connection</th><th>Scope</th><th>TLS</th><th>Eligible profiles</th></tr></thead>
            <tbody>
              {policies.map((policy) => (
                <tr key={policy.allowlist_id}>
                  <td><strong>{policy.name}</strong><small>{policy.base_url}</small></td>
                  <td>{formatConnectionClass(policy.connection_class)}</td>
                  <td><span className="policyLiteral">{policy.scope_path}</span><small>{policy.max_redirects} redirect{policy.max_redirects === 1 ? "" : "s"} max</small></td>
                  <td>{formatTlsTrust(policy.tls_trust)}</td>
                  <td>{policy.available_scan_profile_ids.map(formatScanProfileLabel).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="emptyState">No launchable target policies are configured.</p>}
      </div>
    </details>
  );
}

function formatConnectionClass(value: string) {
  if (value === "compose_service") return "Docker service";
  if (value === "host_gateway") return "Host gateway";
  return value.replaceAll("_", " ");
}

function formatTlsTrust(value: string) {
  if (value === "system") return "System trust";
  if (value === "custom_ca") return "Confined custom CA";
  if (value === "not_applicable") return "HTTP policy";
  return value.replaceAll("_", " ");
}
