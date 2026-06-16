ZAP_FIXTURE = {
    "title": "Missing Content Security Policy",
    "severity": "medium",
    "confidence": "high",
    "affected_url": "http://juice-shop:3000/",
    "evidence": "set-cookie: session=abc123\ncontent-type: text/html",
    "source_tool": "zap",
    "scanner_rule_id": "10038",
    "cwe": "CWE-693",
    "owasp_category": "A05:2021",
}

GITLEAKS_FIXTURE = {
    "title": "Hardcoded API key",
    "severity": "high",
    "confidence": "confirmed",
    "affected_file": "/workspace/app/.env",
    "evidence": "api_key=super-secret-key",
    "source_tool": "gitleaks",
    "scanner_rule_id": "generic-api-key",
    "cwe": "CWE-798",
    "owasp_category": "A02:2021",
}

