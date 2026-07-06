import unittest
import tempfile
from pathlib import Path
from urllib.parse import urlencode
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.main import app
from app.core.config import settings
from app.db.session import SessionLocal
from app.models import AuthProfile, Target
from tests.helpers import DEV_AUTH_HEADERS


class TargetApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.created_target_ids: list[str] = []
        self.created_auth_profile_ids: list[str] = []

    def tearDown(self) -> None:
        with SessionLocal() as db:
            if self.created_target_ids:
                db.execute(delete(Target).where(Target.id.in_(self.created_target_ids)))
            if self.created_auth_profile_ids:
                db.execute(delete(AuthProfile).where(AuthProfile.id.in_(self.created_auth_profile_ids)))
            db.commit()

    def test_validate_allowed_target(self) -> None:
        response = self.client.get(
            f"/targets/validate?{urlencode({'target_url': 'http://juice-shop:3000'})}",
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["allowlist_id"], "juice-shop")
        self.assertIn("passive", response.json()["allowed_modes"])

    def test_create_allowed_target_requires_permission(self) -> None:
        response = self.client.post(
            "/targets",
            json={"target_url": "http://juice-shop:3000", "permission_confirmed": False},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)

    def test_create_allowed_target_persists_repo_path_placeholder(self) -> None:
        response = self.client.post(
            "/targets",
            json={
                "target_url": "http://juice-shop:3000",
                "permission_confirmed": True,
                "repo_path": "/repos/example",
            },
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_target_ids.append(body["id"])
        self.assertEqual(body["allowlist_id"], "juice-shop")
        self.assertEqual(body["repo_path"], "/repos/example")
        self.assertIsNone(body["auth_profile_id"])

        detail = self.client.get(f"/targets/{body['id']}", headers=DEV_AUTH_HEADERS)
        self.assertEqual(detail.status_code, 200)

    def test_update_target_repo_path_validates_and_persists_path(self) -> None:
        response = self.client.post(
            "/targets",
            json={"target_url": "http://juice-shop:3000", "permission_confirmed": True},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_target_ids.append(body["id"])
        self.assertIsNone(body["repo_path"])

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "security-project"
            repo_path.mkdir()
            original_root = settings.repo_scan_root
            settings.repo_scan_root = temp_dir
            try:
                update = self.client.patch(
                    f"/targets/{body['id']}/repo-path",
                    json={"repo_path": f"  {repo_path}  "},
                    headers=DEV_AUTH_HEADERS,
                )
            finally:
                settings.repo_scan_root = original_root

        self.assertEqual(update.status_code, 200)
        self.assertEqual(update.json()["repo_path"], str(repo_path))

    def test_update_target_repo_path_rejects_invalid_path(self) -> None:
        response = self.client.post(
            "/targets",
            json={"target_url": "http://juice-shop:3000", "permission_confirmed": True},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_target_ids.append(body["id"])

        update = self.client.patch(
            f"/targets/{body['id']}/repo-path",
            json={"repo_path": "relative/repo"},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(update.status_code, 400)
        self.assertIn("absolute", update.json()["detail"])

    def test_update_target_repo_path_allows_browser_preflight(self) -> None:
        response = self.client.options(
            f"/targets/{uuid4()}/repo-path",
            headers={
                "Origin": "http://localhost:3001",
                "Access-Control-Request-Method": "PATCH",
                "Access-Control-Request-Headers": "content-type",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["access-control-allow-origin"], "http://localhost:3001")
        self.assertIn("PATCH", response.headers["access-control-allow-methods"])

    def test_update_target_auth_profile_persists_workspace_profile(self) -> None:
        target = self.client.post(
            "/targets",
            json={"target_url": "http://juice-shop:3000", "permission_confirmed": True},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(target.status_code, 201)
        target_body = target.json()
        self.created_target_ids.append(target_body["id"])

        profile = self.client.post(
            "/auth-profiles",
            json={"label": "API Key", "profile_type": "custom_header", "header_name": "X-API-Key", "secret": "secret-key"},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(profile.status_code, 201)
        profile_body = profile.json()
        self.created_auth_profile_ids.append(profile_body["id"])

        update = self.client.patch(
            f"/targets/{target_body['id']}/auth-profile",
            json={"auth_profile_id": profile_body["id"]},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(update.status_code, 200)
        self.assertEqual(update.json()["auth_profile_id"], profile_body["id"])

    def test_public_target_is_rejected(self) -> None:
        response = self.client.post(
            "/targets",
            json={"target_url": "https://example.com", "permission_confirmed": True},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)

    def test_missing_target_returns_404(self) -> None:
        response = self.client.get(f"/targets/{uuid4()}", headers=DEV_AUTH_HEADERS)

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
