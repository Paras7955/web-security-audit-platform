import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app.api.deps import get_scan_allowlist
from app.db.session import SessionLocal
from app.main import app
from app.models import AuthProfile, Scan, Target
from app.security.allowlist import ScanAllowlist
from fastapi.testclient import TestClient
from sqlalchemy import delete

from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class ScanApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.target_destination_guard = patch("app.api.targets.validate_destination")
        self.scan_destination_guard = patch("app.api.scans.validate_destination")
        self.target_destination_guard.start()
        self.scan_destination_guard.start()
        self.addCleanup(self.target_destination_guard.stop)
        self.addCleanup(self.scan_destination_guard.stop)
        self.created_scan_ids: list[str] = []
        self.created_target_ids: list[str] = []
        self.created_auth_profile_ids: list[str] = []

    def tearDown(self) -> None:
        with SessionLocal() as db:
            if self.created_scan_ids:
                db.execute(delete(Scan).where(Scan.id.in_(self.created_scan_ids)))
            if self.created_target_ids:
                db.execute(delete(Target).where(Target.id.in_(self.created_target_ids)))
            if self.created_auth_profile_ids:
                db.execute(delete(AuthProfile).where(AuthProfile.id.in_(self.created_auth_profile_ids)))
            db.commit()

    def create_target(self, *, repo_path: str | None = None) -> dict[str, object]:
        if repo_path is None:
            response = self.client.post(
                "/api/v1/targets",
                json={"target_url": "http://juice-shop:3000", "permission_confirmed": True},
                headers=DEV_AUTH_HEADERS,
            )
        else:
            with patch("app.api.targets.settings.repo_scan_root", str(Path(repo_path).parent)):
                response = self.client.post(
                    "/api/v1/targets",
                    json={"target_url": "http://juice-shop:3000", "permission_confirmed": True, "repo_path": repo_path},
                    headers=DEV_AUTH_HEADERS,
                )
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_target_ids.append(body["id"])
        return body

    def test_create_passive_scan_queues_job(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target["id"], "scan_profile_id": "passive-web", "acknowledgements": ["authorized_target"]},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_scan_ids.append(body["id"])
        self.assertEqual(body["target_id"], target["id"])
        self.assertNotIn("mode", body)
        self.assertEqual(body["scan_profile_id"], "passive-web")
        self.assertEqual(body["status"], "queued")
        self.assertEqual(body["current_step"], "target_validation")
        self.assertEqual(body["progress_percent"], 0)
        self.assertIn("Passive Web profile", body["status_message"])

    def test_create_scan_accepts_scan_profile_id(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target["id"], "scan_profile_id": "passive-web", "acknowledgements": ["authorized_target"]},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_scan_ids.append(body["id"])
        self.assertEqual(body["scan_profile_id"], "passive-web")
        self.assertNotIn("mode", body)

    def test_create_scan_rejects_profile_mode_mismatch(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target["id"], "scan_profile_id": "passive-web", "mode": "active_demo"},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 422)

    def test_create_scan_rejects_unknown_profile(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target["id"], "scan_profile_id": "future-profile", "acknowledgements": []},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("Unsupported scan profile", response.json()["detail"])

    def test_create_scan_rejects_missing_target(self) -> None:
        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": str(uuid4()), "scan_profile_id": "passive-web", "acknowledgements": ["authorized_target"]},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 404)

    def test_create_active_demo_scan_requires_acknowledgement(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target["id"], "scan_profile_id": "active-demo", "acknowledgements": []},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("acknowledgement", response.json()["detail"])

    def test_create_active_demo_scan_rejects_non_local_demo_target(self) -> None:
        allowlist = build_scan_allowlist(local_demo=False, allowed_modes=("passive", "active_demo"))
        target = self.create_db_target(allowlist_id="remote-demo", base_url="https://owned.example.test/")

        app.dependency_overrides[get_scan_allowlist] = lambda: allowlist
        try:
            response = self.client.post(
                "/api/v1/scans",
                json={"target_id": target.id, "scan_profile_id": "active-demo", "acknowledgements": ["authorized_target", "active_testing_local_demo"]},
                headers=DEV_AUTH_HEADERS,
            )
        finally:
            app.dependency_overrides.pop(get_scan_allowlist, None)

        self.assertEqual(response.status_code, 400)
        self.assertIn("local/demo", response.json()["detail"])

    def test_create_active_demo_scan_queues_for_local_demo_target(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target["id"], "scan_profile_id": "active-demo", "acknowledgements": ["authorized_target", "active_testing_local_demo"]},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_scan_ids.append(body["id"])
        self.assertEqual(body["scan_profile_id"], "active-demo")
        self.assertNotIn("mode", body)
        self.assertEqual(body["status"], "queued")

    def test_create_non_passive_scan_rejects_target_auth_profile(self) -> None:
        profile = self.client.post(
            "/api/v1/auth-profiles",
            json={"label": "Bearer", "profile_type": "bearer_token", "secret": "demo-token"},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(profile.status_code, 201)
        profile_id = profile.json()["id"]
        self.created_auth_profile_ids.append(profile_id)
        target = self.client.post(
            "/api/v1/targets",
            json={
                "target_url": "http://juice-shop:3000",
                "permission_confirmed": True,
                "auth_profile_id": profile_id,
            },
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(target.status_code, 201)
        target_id = target.json()["id"]
        self.created_target_ids.append(target_id)

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target_id, "scan_profile_id": "active-demo", "acknowledgements": ["authorized_target", "active_testing_local_demo"]},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("supported only for passive-web", response.json()["detail"])

    def test_create_modern_web_crawl_requires_acknowledgement(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target["id"], "scan_profile_id": "modern-web-crawl", "acknowledgements": []},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("acknowledgement", response.json()["detail"])

    def test_create_modern_web_crawl_rejects_non_local_demo_target(self) -> None:
        allowlist = build_scan_allowlist(local_demo=False, allowed_modes=("passive", "modern_web_crawl"))
        target = self.create_db_target(allowlist_id="remote-demo", base_url="http://owned-demo:8080/")

        app.dependency_overrides[get_scan_allowlist] = lambda: allowlist
        try:
            response = self.client.post(
                "/api/v1/scans",
                json={"target_id": target.id, "scan_profile_id": "modern-web-crawl", "acknowledgements": ["authorized_target", "browser_crawl_local_demo"]},
                headers=DEV_AUTH_HEADERS,
            )
        finally:
            app.dependency_overrides.pop(get_scan_allowlist, None)

        self.assertEqual(response.status_code, 400)
        self.assertIn("local/demo", response.json()["detail"])

    def test_create_modern_web_crawl_queues_for_local_demo_target(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target["id"], "scan_profile_id": "modern-web-crawl", "acknowledgements": ["authorized_target", "browser_crawl_local_demo"]},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_scan_ids.append(body["id"])
        self.assertEqual(body["scan_profile_id"], "modern-web-crawl")
        self.assertNotIn("mode", body)
        self.assertEqual(body["status"], "queued")

    def test_create_repo_scan_requires_configured_repo_path(self) -> None:
        target = self.create_target()

        response = self.client.post("/api/v1/scans", json={"target_id": target["id"], "scan_profile_id": "repository", "acknowledgements": ["authorized_repository"]}, headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Repo scans require", response.json()["detail"])

    def test_create_repo_scan_queues_for_valid_repo_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "security-project"
            repo_path.mkdir()
            with patch("app.api.scans.settings.repo_scan_root", temp_dir):
                target = self.create_target(repo_path=str(repo_path))
                response = self.client.post("/api/v1/scans", json={"target_id": target["id"], "scan_profile_id": "repository", "acknowledgements": ["authorized_repository"]}, headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_scan_ids.append(body["id"])
        self.assertEqual(body["scan_profile_id"], "repository")
        self.assertNotIn("mode", body)
        self.assertEqual(body["status"], "queued")

    def test_create_modern_web_crawl_revalidates_target_base_url(self) -> None:
        target = self.create_db_target(allowlist_id="juice-shop", base_url="https://owned.example.test/")

        response = self.client.post(
            "/api/v1/scans",
            json={"target_id": target.id, "scan_profile_id": "modern-web-crawl", "acknowledgements": ["authorized_target", "browser_crawl_local_demo"]},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("allowlist", response.json()["detail"])

    def test_list_and_get_scan(self) -> None:
        target = self.create_target()
        created = self.client.post(
            "/api/v1/scans",
            json={"target_id": target["id"], "scan_profile_id": "passive-web", "acknowledgements": ["authorized_target"]},
            headers=DEV_AUTH_HEADERS,
        ).json()
        self.created_scan_ids.append(created["id"])

        detail = self.client.get(f"/api/v1/scans/{created['id']}", headers=DEV_AUTH_HEADERS)
        scan_list = self.client.get("/api/v1/scans", headers=DEV_AUTH_HEADERS)

        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["id"], created["id"])
        self.assertEqual(scan_list.status_code, 200)
        self.assertTrue(any(scan["id"] == created["id"] for scan in scan_list.json()["items"]))

    def create_db_target(self, *, allowlist_id: str, base_url: str) -> Target:
        target = Target(
            id=str(uuid4()),
            workspace_id=DEV_WORKSPACE_ID,
            created_by_user_id=DEV_USER_ID,
            allowlist_id=allowlist_id,
            name="Remote demo",
            base_url=base_url,
            permission_confirmed=True,
        )
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(target)
            db.commit()
            db.refresh(target)
            self.created_target_ids.append(target.id)
            return target


def build_scan_allowlist(*, local_demo: bool, allowed_modes: tuple[str, ...]) -> ScanAllowlist:
    return ScanAllowlist.model_validate(
        {
            "targets": [
                {
                    "id": "remote-demo",
                    "name": "Remote Demo",
                    "base_url": "http://owned-demo:8080",
                    "schemes": ["http"],
                    "hosts": ["owned-demo"],
                    "ports": [8080],
                    "allowed_modes": list(allowed_modes),
                    "max_redirects": 2,
                    "local_demo": local_demo,
                }
            ]
        }
    )


if __name__ == "__main__":
    unittest.main()
