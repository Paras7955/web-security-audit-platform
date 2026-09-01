import json
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from app.ai.service import (
    AiExplanationError,
    AiExplanationResult,
    AiRateLimitExceeded,
    OpenAiProvider,
    TemplateAiProvider,
    generate_ai_explanations,
    lock_ai_rate_limit_scope,
)
from app.db.session import SessionLocal
from app.main import app
from app.models import AiExplanationCache, AiRequestLog, Finding, FindingState, Scan, SuppressionRule, Target
from fastapi.testclient import TestClient
from sqlalchemy import delete

from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class AiExplanationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.target_id = str(uuid4())
        self.scan_id = str(uuid4())
        self.finding_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(
                Target(
                    id=self.target_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    allowlist_id="juice-shop",
                    name="OWASP Juice Shop",
                    base_url="http://juice-shop:3000/",
                    permission_confirmed=True,
                )
            )
            db.add(
                Scan(
                    id=self.scan_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    created_by_user_id=DEV_USER_ID,
                    target_id=self.target_id,
                    mode="passive",
                    status="completed",
                    current_step="normalizing_findings",
                    status_message="Completed.",
                    progress_percent=100,
                )
            )
            db.commit()
            db.add(
                Finding(
                    id=self.finding_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    scan_id=self.scan_id,
                    title="Missing Content Security Policy",
                    severity="high",
                    confidence="high",
                    affected_url="http://juice-shop:3000/",
                    evidence="authorization: bearer [REDACTED]",
                    source_tool="custom-passive",
                    scanner_rule_id="header:content-security-policy",
                    dedupe_key="custom-passive|http://juice-shop:3000/|missing content security policy|cwe-693",
                    owasp_category="A05:2021",
                    cwe="CWE-693",
                    remediation="Set a Content-Security-Policy header.",
                    redaction_applied=True,
                )
            )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(AiRequestLog).where(AiRequestLog.workspace_id == DEV_WORKSPACE_ID))
            db.execute(delete(AiExplanationCache).where(AiExplanationCache.workspace_id == DEV_WORKSPACE_ID))
            db.execute(delete(FindingState).where(FindingState.target_id == self.target_id))
            db.execute(delete(SuppressionRule).where(SuppressionRule.target_id == self.target_id))
            db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
            db.execute(delete(Scan).where(Scan.id == self.scan_id))
            db.execute(delete(Target).where(Target.id == self.target_id))
            db.commit()

    def test_template_provider_returns_deterministic_explanation(self) -> None:
        with SessionLocal() as db:
            first = generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                provider_name="template",
                openai_api_key=None,
                openai_model=None,
                cache_enabled=False,
            )
            second = generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                provider_name="template",
                openai_api_key=None,
                openai_model=None,
                cache_enabled=False,
            )

        self.assertEqual(first, second)
        self.assertEqual(first.provider, "template")
        self.assertFalse(first.fallback_used)
        self.assertEqual(first.explanations[0].finding_id, self.finding_id)
        self.assertIn("Content-Security-Policy", first.explanations[0].recommended_action)

    def test_ai_api_returns_explanations(self) -> None:
        response = self.client.get(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["provider"], "template")
        self.assertEqual(body["configured_provider"], "template")
        self.assertEqual(body["scan_id"], self.scan_id)
        self.assertEqual(body["explanations"][0]["finding_id"], self.finding_id)
        self.assertFalse(body["cache_hit"])
        self.assertEqual(body["scoring_model_version"], "risk-v1")
        self.assertIn("Risk is", body["executive_summary"])

    def test_ai_get_never_calls_external_provider_or_persists_generation(self) -> None:
        with (
            patch("app.api.ai.settings.ai_provider", "openai"),
            patch("app.api.ai.settings.openai_model", "test-model"),
            patch("app.ai.service.OpenAiProvider.explain") as explain,
        ):
            response = self.client.get(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["provider"], "template")
        self.assertEqual(response.json()["configured_provider"], "openai")
        explain.assert_not_called()
        with SessionLocal() as db:
            self.assertEqual(db.query(AiExplanationCache).filter(AiExplanationCache.scan_id == self.scan_id).count(), 0)
            self.assertEqual(db.query(AiRequestLog).filter(AiRequestLog.workspace_id == DEV_WORKSPACE_ID).count(), 0)

    def test_ai_api_reuses_cached_explanation_and_logs_requests(self) -> None:
        first = self.client.post(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)
        second = self.client.post(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)
        read = self.client.get(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(read.status_code, 200)
        self.assertFalse(first.json()["cache_hit"])
        self.assertTrue(second.json()["cache_hit"])
        self.assertTrue(read.json()["cache_hit"])
        self.assertEqual(first.json()["input_fingerprint"], second.json()["input_fingerprint"])
        with SessionLocal() as db:
            cache_rows = db.query(AiExplanationCache).filter(AiExplanationCache.scan_id == self.scan_id).all()
            logs = (
                db.query(AiRequestLog)
                .filter(AiRequestLog.input_fingerprint == first.json()["input_fingerprint"])
                .order_by(AiRequestLog.created_at.asc(), AiRequestLog.id.asc())
                .all()
            )
        self.assertEqual(len(cache_rows), 1)
        self.assertEqual(len(logs), 2)
        self.assertEqual([log.cache_hit for log in logs], [False, True])

    def test_lifecycle_change_invalidates_cached_explanation(self) -> None:
        with SessionLocal() as db:
            first = generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                user_id=DEV_USER_ID,
                provider_name="template",
                openai_api_key=None,
                openai_model=None,
            )
            db.add(
                FindingState(
                    id=str(uuid4()),
                    workspace_id=DEV_WORKSPACE_ID,
                    target_id=self.target_id,
                    dedupe_key="custom-passive|http://juice-shop:3000/|missing content security policy|cwe-693",
                    lifecycle_status="accepted_risk",
                    updated_by_user_id=DEV_USER_ID,
                )
            )
            db.commit()
            second = generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                user_id=DEV_USER_ID,
                provider_name="template",
                openai_api_key=None,
                openai_model=None,
            )

        self.assertNotEqual(first.input_fingerprint, second.input_fingerprint)
        self.assertFalse(second.cache_hit)

    def test_suppression_expiration_invalidates_cached_explanation(self) -> None:
        with SessionLocal() as db:
            db.add(
                SuppressionRule(
                    id=str(uuid4()),
                    workspace_id=DEV_WORKSPACE_ID,
                    target_id=self.target_id,
                    dedupe_key="custom-passive|http://juice-shop:3000/|missing content security policy|cwe-693",
                    reason="Temporary demo suppression.",
                    created_by_user_id=DEV_USER_ID,
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                )
            )
            db.commit()
            first = generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                user_id=DEV_USER_ID,
                provider_name="template",
                openai_api_key=None,
                openai_model=None,
            )
            rule = db.query(SuppressionRule).filter(SuppressionRule.target_id == self.target_id).one()
            rule.expires_at = datetime.now(UTC) - timedelta(days=1)
            db.add(rule)
            db.commit()
            second = generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                user_id=DEV_USER_ID,
                provider_name="template",
                openai_api_key=None,
                openai_model=None,
            )

        self.assertNotEqual(first.input_fingerprint, second.input_fingerprint)

    def test_rate_limit_blocks_uncached_generation(self) -> None:
        with SessionLocal() as db:
            generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                user_id=DEV_USER_ID,
                provider_name="template",
                openai_api_key=None,
                openai_model=None,
                cache_enabled=False,
                rate_limit_max_requests=1,
                rate_limit_window_seconds=3600,
            )
            with self.assertRaises(AiRateLimitExceeded):
                generate_ai_explanations(
                    db,
                    workspace_id=DEV_WORKSPACE_ID,
                    scan_id=self.scan_id,
                    user_id=DEV_USER_ID,
                    provider_name="template",
                    openai_api_key=None,
                    openai_model=None,
                    cache_enabled=False,
                    rate_limit_max_requests=1,
                    rate_limit_window_seconds=3600,
                )

        with SessionLocal() as db:
            blocked_log = db.query(AiRequestLog).filter(AiRequestLog.allowed.is_(False)).one()
        self.assertFalse(blocked_log.cache_hit)

    def test_ai_api_returns_429_when_rate_limited(self) -> None:
        with patch("app.ai.service.settings.ai_rate_limit_max_requests", 0):
            response = self.client.post(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 429)
        self.assertIn("rate limit", response.json()["detail"].lower())

    def test_cache_payload_contains_only_safe_result_data(self) -> None:
        response = self.client.post(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)
        self.assertEqual(response.status_code, 200)

        with SessionLocal() as db:
            cache = db.query(AiExplanationCache).filter(AiExplanationCache.scan_id == self.scan_id).one()

        payload_text = str(cache.payload)
        self.assertNotIn("raw-artifact-id", payload_text)
        self.assertNotIn("raw_artifact_ref", payload_text)
        self.assertNotIn("bearer raw-secret", payload_text)

    def test_missing_scan_returns_404(self) -> None:
        response = self.client.get(f"/api/v1/scans/{uuid4()}/ai-explanations", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 404)

    def test_running_scan_is_not_eligible_for_ai_explanations(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.status = "running"
            db.add(scan)
            db.commit()

        response = self.client.get(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 400)
        self.assertIn("completed scans", response.json()["detail"])

    def test_active_demo_scan_is_eligible_for_ai_explanations(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "active_demo"
            scan.scan_profile_id = "active-demo"
            db.add(scan)
            db.commit()

        response = self.client.get(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["provider"], "template")

    def test_ajax_short_scan_is_not_eligible_for_ai_explanations(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "ajax_short"
            scan.scan_profile_id = "ajax-short"
            db.add(scan)
            db.commit()

        response = self.client.get(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Finding guidance is available only for Passive Web and Active Demo scans", response.json()["detail"])

    def test_repo_scan_is_not_eligible_for_ai_explanations(self) -> None:
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "repo"
            scan.scan_profile_id = "repository"
            db.add(scan)
            db.commit()

        response = self.client.get(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Finding guidance is available only for Passive Web and Active Demo scans", response.json()["detail"])

    def test_openai_without_configuration_falls_back_to_template(self) -> None:
        with SessionLocal() as db:
            result = generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                provider_name="openai",
                openai_api_key=None,
                openai_model=None,
            )

        self.assertEqual(result.provider, "template")
        self.assertTrue(result.fallback_used)
        self.assertEqual(result.provider_error, "provider_unavailable")

    def test_provider_fallback_results_are_not_cached(self) -> None:
        provider = FailingProvider()
        with SessionLocal() as db, patch("app.ai.service.build_provider", return_value=provider):
            first = generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                provider_name="openai",
                openai_api_key="test-key",
                openai_model="test-model",
            )
            second = generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                provider_name="openai",
                openai_api_key="test-key",
                openai_model="test-model",
            )

        self.assertTrue(first.fallback_used)
        self.assertTrue(second.fallback_used)
        self.assertEqual(provider.calls, 2)
        with SessionLocal() as db:
            cache_rows = db.query(AiExplanationCache).filter(AiExplanationCache.scan_id == self.scan_id).all()
        self.assertEqual(cache_rows, [])

    def test_unknown_provider_is_rejected(self) -> None:
        with patch("app.api.ai.settings.ai_provider", "unexpected"):
            response = self.client.get(f"/api/v1/scans/{self.scan_id}/ai-explanations", headers=DEV_AUTH_HEADERS)
            generation_response = self.client.post(
                f"/api/v1/scans/{self.scan_id}/ai-explanations",
                headers=DEV_AUTH_HEADERS,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["provider"], "template")
        self.assertEqual(generation_response.status_code, 400)
        self.assertIn("AI_PROVIDER", generation_response.json()["detail"])

    def test_provider_receives_only_safe_finding_projection(self) -> None:
        provider = CapturingProvider()
        with SessionLocal() as db:
            scan = db.get(Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.mode = "active_demo"
            scan.scan_profile_id = "active-demo"
            finding = db.get(Finding, self.finding_id)
            self.assertIsNotNone(finding)
            finding.source_tool = "zap-active"
            finding.evidence = "set-cookie: session=[REDACTED]"
            db.add(scan)
            db.add(finding)
            db.commit()

        with SessionLocal() as db, patch("app.ai.service.build_provider", return_value=provider):
            generate_ai_explanations(
                db,
                workspace_id=DEV_WORKSPACE_ID,
                scan_id=self.scan_id,
                provider_name="openai",
                openai_api_key="test-key",
                openai_model="test-model",
            )

        self.assertIsNotNone(provider.payload)
        payload = provider.payload[0].to_provider_dict()
        self.assertNotIn("raw_artifact_ref", payload)
        self.assertNotIn("dedupe_key", payload)
        self.assertIn("[REDACTED]", str(payload["evidence"]))
        self.assertEqual(payload["source_tool"], "zap-active")
        self.assertNotIn("raw-artifact-id", str(payload))

    def test_provider_payload_strips_query_strings_and_unredacted_text(self) -> None:
        unsafe_id = str(uuid4())
        provider = CapturingProvider()
        with SessionLocal() as db:
            db.add(
                Finding(
                    id=unsafe_id,
                    workspace_id=DEV_WORKSPACE_ID,
                    scan_id=self.scan_id,
                    title="Sensitive callback URL",
                    severity="medium",
                    confidence="medium",
                    affected_url="http://user:pass@juice-shop:3000/callback?code=secret-code&token=secret-token#fragment",
                    evidence="authorization: bearer raw-secret",
                    source_tool="custom-passive",
                    scanner_rule_id="url:callback",
                    dedupe_key="custom-passive|http://juice-shop:3000/callback|sensitive callback url",
                    reproduction_steps="Visit /callback?code=secret-code",
                    remediation="Remove secret token secret-token.",
                    redaction_applied=False,
                )
            )
            db.commit()

        try:
            with SessionLocal() as db, patch("app.ai.service.build_provider", return_value=provider):
                generate_ai_explanations(
                    db,
                    workspace_id=DEV_WORKSPACE_ID,
                    scan_id=self.scan_id,
                    provider_name="openai",
                    openai_api_key="test-key",
                    openai_model="test-model",
                )

            self.assertIsNotNone(provider.payload)
            unsafe_payload = next(item.to_provider_dict() for item in provider.payload if item.id == unsafe_id)
            self.assertEqual(unsafe_payload["location"], "http://juice-shop:3000/callback")
            self.assertEqual(unsafe_payload["evidence"], "authorization: bearer [REDACTED]")
            self.assertEqual(unsafe_payload["reproduction_steps"], "Visit /callback")
            self.assertIn("[REDACTED]", str(unsafe_payload["remediation"]))
            self.assertNotIn("secret-code", str(unsafe_payload))
            self.assertNotIn("secret-token", str(unsafe_payload))
            self.assertNotIn("raw-secret", str(unsafe_payload))
            self.assertNotIn("user:pass", str(unsafe_payload))
        finally:
            with SessionLocal() as db:
                db.execute(delete(Finding).where(Finding.id == unsafe_id))
                db.commit()

    def test_openai_response_is_parsed_without_network_when_mocked(self) -> None:
        output_text = (
            '{"summary":"Mocked summary","explanations":[{"finding_id":"'
            + self.finding_id
            + '","summary":"Mocked finding","why_it_matters":"Because configured controls are missing",'
            '"recommended_action":"Add CSP","owasp_mapping":"A05:2021","limitations":"Provided data only"}]}'
        )
        completed_event = {
            "type": "response.completed",
            "response": {"output_text": output_text},
        }
        with patch("app.ai.service.httpx.Client") as client_class:
            client = client_class.return_value.__enter__.return_value
            response = client.stream.return_value.__enter__.return_value
            response.raise_for_status.return_value = None
            response.iter_bytes.return_value = [f"data: {json.dumps(completed_event)}\n\n".encode()]
            with SessionLocal() as db:
                result = generate_ai_explanations(
                    db,
                    workspace_id=DEV_WORKSPACE_ID,
                    scan_id=self.scan_id,
                    provider_name="openai",
                    openai_api_key="test-key",
                    openai_model="test-model",
                )

        self.assertEqual(result.provider, "openai")
        self.assertFalse(result.fallback_used)
        self.assertEqual(result.summary, "Mocked summary")
        self.assertEqual(result.explanations[0].summary, "Mocked finding")
        client_class.assert_called_once_with(timeout=20.0, follow_redirects=False, trust_env=False)
        request_json = client.stream.call_args.kwargs["json"]
        self.assertTrue(request_json["stream"])
        self.assertNotIn("raw_artifact_ref", str(request_json))
        self.assertNotIn("raw-artifact-id", str(request_json))

    def test_openai_stream_rejects_oversized_response_without_echoing_content(self) -> None:
        provider = OpenAiProvider(api_key="test-key", model="test-model")
        with (
            patch("app.ai.service.OPENAI_RESPONSE_MAX_BYTES", 8),
            patch("app.ai.service.httpx.Client") as client_class,
        ):
            response = client_class.return_value.__enter__.return_value.stream.return_value.__enter__.return_value
            response.raise_for_status.return_value = None
            response.iter_bytes.return_value = [b"sensitive-provider-content"]
            with self.assertRaises(AiExplanationError) as raised:
                provider.explain(scan_id=self.scan_id, findings=())

        self.assertIn("size limit", str(raised.exception))
        self.assertNotIn("sensitive-provider-content", str(raised.exception))

    def test_openai_stream_rejects_malformed_and_non_json_output_safely(self) -> None:
        provider = OpenAiProvider(api_key="test-key", model="test-model")
        malformed_cases = (
            b"data: provider-secret-not-json\n\n",
            b'data: {"type":"response.completed","response":{"output_text":"not-json-provider-secret"}}\n\n',
        )
        for payload in malformed_cases:
            with self.subTest(payload=payload), patch("app.ai.service.httpx.Client") as client_class:
                response = client_class.return_value.__enter__.return_value.stream.return_value.__enter__.return_value
                response.raise_for_status.return_value = None
                response.iter_bytes.return_value = [payload]
                with self.assertRaises(AiExplanationError) as raised:
                    provider.explain(scan_id=self.scan_id, findings=())
                self.assertNotIn("provider-secret", str(raised.exception))

    def test_ai_rate_limit_scope_uses_transaction_advisory_lock_on_postgres(self) -> None:
        class FakeDialect:
            name = "postgresql"

        class FakeBind:
            dialect = FakeDialect()

        class FakeSession:
            def __init__(self) -> None:
                self.statements: list[str] = []
                self.params: list[dict[str, int]] = []

            def get_bind(self) -> FakeBind:
                return FakeBind()

            def execute(self, statement, params):  # type: ignore[no-untyped-def]
                self.statements.append(str(statement))
                self.params.append(params)

        fake_session = FakeSession()
        lock_ai_rate_limit_scope(
            fake_session,  # type: ignore[arg-type]
            workspace_id=DEV_WORKSPACE_ID,
            user_id=DEV_USER_ID,
            action="interactive_ai_explanations",
            provider="openai",
            model="test-model",
            config_hash="config-hash",
        )

        self.assertEqual(fake_session.statements, ["SELECT pg_advisory_xact_lock(:lock_key)"])
        self.assertIsInstance(fake_session.params[0]["lock_key"], int)


class CapturingProvider:
    provider_name = "capturing"

    def __init__(self) -> None:
        self.payload = None

    def explain(self, *, scan_id: str, findings: tuple) -> AiExplanationResult:
        self.payload = findings
        return TemplateAiProvider().explain(scan_id=scan_id, findings=findings)


class FailingProvider:
    provider_name = "openai"

    def __init__(self) -> None:
        self.calls = 0

    def explain(self, *, scan_id: str, findings: tuple) -> AiExplanationResult:
        self.calls += 1
        raise RuntimeError("temporary provider failure")


if __name__ == "__main__":
    unittest.main()
