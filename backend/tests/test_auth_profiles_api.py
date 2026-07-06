import unittest
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.auth_profiles import decrypt_secret
from app.db.session import SessionLocal
from app.main import app
from app.models import AuthProfile, Scan, Target, Workspace
from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class AuthProfileApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.created_auth_profile_ids: list[str] = []
        self.created_target_ids: list[str] = []
        self.created_scan_ids: list[str] = []

    def tearDown(self) -> None:
        with SessionLocal() as db:
            if self.created_scan_ids:
                db.execute(delete(Scan).where(Scan.id.in_(self.created_scan_ids)))
            if self.created_target_ids:
                db.execute(delete(Target).where(Target.id.in_(self.created_target_ids)))
            if self.created_auth_profile_ids:
                db.execute(delete(AuthProfile).where(AuthProfile.id.in_(self.created_auth_profile_ids)))
            db.commit()

    def test_create_bearer_profile_encrypts_and_redacts_secret(self) -> None:
        response = self.client.post(
            "/auth-profiles",
            json={"label": "Demo bearer", "profile_type": "bearer_token", "secret": "demo-secret-token"},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_auth_profile_ids.append(body["id"])
        self.assertEqual(body["profile_type"], "bearer_token")
        self.assertIsNone(body["header_name"])
        self.assertEqual(body["secret_hint"], "****oken")
        self.assertNotIn("secret", body)

        with SessionLocal() as db:
            profile = db.get(AuthProfile, body["id"])
            self.assertIsNotNone(profile)
            assert profile is not None
            self.assertNotEqual(profile.encrypted_secret, "demo-secret-token")
            self.assertEqual(decrypt_secret(profile.encrypted_secret), "demo-secret-token")

    def test_create_custom_header_profile_validates_header(self) -> None:
        response = self.client.post(
            "/auth-profiles",
            json={"label": "API key", "profile_type": "custom_header", "header_name": "X-API-Key", "secret": "key-1234"},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_auth_profile_ids.append(body["id"])
        self.assertEqual(body["profile_type"], "custom_header")
        self.assertEqual(body["header_name"], "X-API-Key")
        self.assertEqual(body["secret_hint"], "****1234")

    def test_create_custom_header_profile_rejects_disallowed_header(self) -> None:
        response = self.client.post(
            "/auth-profiles",
            json={"label": "Bad", "profile_type": "custom_header", "header_name": "Cookie", "secret": "cookie-value"},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)

    def test_list_and_get_profiles_are_workspace_scoped(self) -> None:
        own = self.client.post(
            "/auth-profiles",
            json={"label": "Own", "profile_type": "bearer_token", "secret": "own-token"},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(own.status_code, 201)
        own_id = own.json()["id"]
        self.created_auth_profile_ids.append(own_id)
        other_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(Workspace(id="other-workspace", owner_user_id=DEV_USER_ID, name="Other Workspace"))
            db.flush()
            db.add(
                AuthProfile(
                    id=other_id,
                    workspace_id="other-workspace",
                    created_by_user_id=DEV_USER_ID,
                    label="Other",
                    profile_type="bearer_token",
                    encrypted_secret="ciphertext",
                    secret_hint="****text",
                )
            )
            db.commit()

        profile_list = self.client.get("/auth-profiles", headers=DEV_AUTH_HEADERS)
        own_detail = self.client.get(f"/auth-profiles/{own_id}", headers=DEV_AUTH_HEADERS)
        other_detail = self.client.get(f"/auth-profiles/{other_id}", headers=DEV_AUTH_HEADERS)

        self.assertEqual(profile_list.status_code, 200)
        self.assertTrue(any(profile["id"] == own_id for profile in profile_list.json()))
        self.assertFalse(any(profile["id"] == other_id for profile in profile_list.json()))
        self.assertEqual(own_detail.status_code, 200)
        self.assertEqual(other_detail.status_code, 404)

        with SessionLocal() as db:
            db.execute(delete(AuthProfile).where(AuthProfile.id == other_id))
            db.execute(delete(Workspace).where(Workspace.id == "other-workspace"))
            db.commit()

    def test_target_can_reference_workspace_profile_and_scan_snapshots_it(self) -> None:
        profile = self.client.post(
            "/auth-profiles",
            json={"label": "Bearer", "profile_type": "bearer_token", "secret": "scan-token"},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(profile.status_code, 201)
        profile_id = profile.json()["id"]
        self.created_auth_profile_ids.append(profile_id)

        target = self.client.post(
            "/targets",
            json={
                "target_url": "http://juice-shop:3000",
                "permission_confirmed": True,
                "auth_profile_id": profile_id,
            },
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(target.status_code, 201)
        target_body = target.json()
        self.created_target_ids.append(target_body["id"])
        self.assertEqual(target_body["auth_profile_id"], profile_id)

        scan = self.client.post(
            "/scans",
            json={"target_id": target_body["id"], "scan_profile_id": "passive-web"},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(scan.status_code, 201)
        scan_body = scan.json()
        self.created_scan_ids.append(scan_body["id"])
        self.assertEqual(scan_body["auth_profile_id"], profile_id)

    def test_target_rejects_cross_workspace_profile(self) -> None:
        other_profile_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(Workspace(id="other-workspace", owner_user_id=DEV_USER_ID, name="Other Workspace"))
            db.flush()
            db.add(
                AuthProfile(
                    id=other_profile_id,
                    workspace_id="other-workspace",
                    created_by_user_id=DEV_USER_ID,
                    label="Other",
                    profile_type="bearer_token",
                    encrypted_secret="ciphertext",
                    secret_hint="****text",
                )
            )
            db.commit()

        response = self.client.post(
            "/targets",
            json={
                "target_url": "http://juice-shop:3000",
                "permission_confirmed": True,
                "auth_profile_id": other_profile_id,
            },
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 404)
        with SessionLocal() as db:
            db.execute(delete(AuthProfile).where(AuthProfile.id == other_profile_id))
            db.execute(delete(Workspace).where(Workspace.id == "other-workspace"))
            db.commit()


if __name__ == "__main__":
    unittest.main()
