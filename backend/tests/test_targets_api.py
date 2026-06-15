import unittest
from urllib.parse import urlencode
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.main import app
from app.models import Target
from app.db.session import SessionLocal


class TargetApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def tearDown(self) -> None:
        with SessionLocal() as db:
            db.execute(delete(Target).where(Target.name == "OWASP Juice Shop"))
            db.commit()

    def test_validate_allowed_target(self) -> None:
        response = self.client.get(f"/targets/validate?{urlencode({'target_url': 'http://juice-shop:3000'})}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["allowlist_id"], "juice-shop")
        self.assertIn("passive", response.json()["allowed_modes"])

    def test_create_allowed_target_requires_permission(self) -> None:
        response = self.client.post(
            "/targets",
            json={"target_url": "http://juice-shop:3000", "permission_confirmed": False},
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
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["allowlist_id"], "juice-shop")
        self.assertEqual(body["repo_path"], "/repos/example")
        self.assertIsNone(body["auth_profile_id"])

        detail = self.client.get(f"/targets/{body['id']}")
        self.assertEqual(detail.status_code, 200)

    def test_auth_profile_placeholder_is_not_enabled(self) -> None:
        response = self.client.post(
            "/targets",
            json={
                "target_url": "http://juice-shop:3000",
                "permission_confirmed": True,
                "auth_profile_id": str(uuid4()),
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_public_target_is_rejected(self) -> None:
        response = self.client.post(
            "/targets",
            json={"target_url": "https://example.com", "permission_confirmed": True},
        )

        self.assertEqual(response.status_code, 400)

    def test_missing_target_returns_404(self) -> None:
        response = self.client.get(f"/targets/{uuid4()}")

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
