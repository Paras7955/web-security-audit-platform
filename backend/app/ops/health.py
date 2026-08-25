from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class ComponentProbe:
    status: str
    detail: str


def probe_zap(*, base_url: str, api_key: str, timeout_seconds: float) -> ComponentProbe:
    try:
        normalized_base_url = base_url.rstrip("/")
        with httpx.Client(trust_env=False, follow_redirects=False) as client:
            response = client.get(
                f"{normalized_base_url}/JSON/core/view/version/",
                headers={"X-ZAP-API-Key": api_key},
                timeout=timeout_seconds,
            )
            response.raise_for_status()
        return ComponentProbe(status="ok", detail="zap reachable from worker")
    except Exception:
        return ComponentProbe(status="degraded", detail="zap unavailable to worker")
