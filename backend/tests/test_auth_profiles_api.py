import unittest
from unittest.mock import patch
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
        self.target_destination_guard = patch("app.api.targets.validate_destination")
        self.scan_destination_guard = patch("app.api.scans.validate_destination")
        self.target_destination_guard.start()
        self.scan_destination_guard.start()
        self.addCleanup(self.target_destination_guard.stop)
        self.addCleanup(self.scan_destination_guard.stop)
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
            "/api/v1/auth-profiles",
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
        for header_name in ("X-API-Key", "Api-Key", "X-Auth-Token", "X-Access-Token"):
            response = self.client.post(
                "/api/v1/auth-profiles",
                json={"label": header_name, "profile_type": "custom_header", "header_name": header_name, "secret": "key-1234"},
                headers=DEV_AUTH_HEADERS,
            )

            self.assertEqual(response.status_code, 201)
            body = response.json()
            self.created_auth_profile_ids.append(body["id"])
            self.assertEqual(body["profile_type"], "custom_header")
            self.assertEqual(body["header_name"], header_name)
            self.assertEqual(body["secret_hint"], "****1234")

    def test_create_custom_header_profile_rejects_disallowed_header(self) -> None:
        response = self.client.post(
            "/api/v1/auth-profiles",
            json={"label": "Bad", "profile_type": "custom_header", "header_name": "Cookie", "secret": "cookie-value"},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)

    def test_create_custom_header_profile_rejects_routing_headers(self) -> None:
        for header_name in ("Forwarded", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL"):
            response = self.client.post(
                "/api/v1/auth-profiles",
                json={"label": "Bad", "profile_type": "custom_header", "header_name": header_name, "secret": "header-value"},
                headers=DEV_AUTH_HEADERS,
            )

            self.assertEqual(response.status_code, 400)

    def test_create_profile_rejects_blank_label(self) -> None:
        response = self.client.post(
            "/api/v1/auth-profiles",
            json={"label": "   ", "profile_type": "bearer_token", "secret": "demo-token"},
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("label", response.json()["detail"].lower())

    def test_list_and_get_profiles_are_workspace_scoped(self) -> None:
        own = self.client.post(
            "/api/v1/auth-profiles",
            json={"label": "Own", "profile_type": "bearer_token", "secret": "own-token"},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(own.status_code, 201)
        own_id = own.json()["id"]
        self.created_auth_profile_ids.append(own_id)
        other_id = str(uuid4())
        other_workspace_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(Workspace(id=other_workspace_id, owner_user_id=DEV_USER_ID, name="Other Workspace"))
            db.flush()
            db.add(
                AuthProfile(
                    id=other_id,
                    workspace_id=other_workspace_id,
                    created_by_user_id=DEV_USER_ID,
                    label="Other",
                    profile_type="bearer_token",
                    encrypted_secret="ciphertext",
                    secret_hint="****text",
                )
            )
            db.commit()

        profile_list = self.client.get("/api/v1/auth-profiles", headers=DEV_AUTH_HEADERS)
        own_detail = self.client.get(f"/api/v1/auth-profiles/{own_id}", headers=DEV_AUTH_HEADERS)
        other_detail = self.client.get(f"/api/v1/auth-profiles/{other_id}", headers=DEV_AUTH_HEADERS)

        self.assertEqual(profile_list.status_code, 200)
        self.assertTrue(any(profile["id"] == own_id for profile in profile_list.json()["items"]))
        self.assertFalse(any(profile["id"] == other_id for profile in profile_list.json()["items"]))
        self.assertEqual(own_detail.status_code, 200)
        self.assertEqual(other_detail.status_code, 404)

        with SessionLocal() as db:
            db.execute(delete(AuthProfile).where(AuthProfile.id == other_id))
            db.execute(delete(Workspace).where(Workspace.id == other_workspace_id))
            db.commit()

    def test_target_can_reference_workspace_profile_and_scan_snapshots_it(self) -> None:
        profile = self.client.post(
            "/api/v1/auth-profiles",
            json={"label": "Bearer", "profile_type": "bearer_token", "secret": "scan-token"},
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
        target_body = target.json()
        self.created_target_ids.append(target_body["id"])
        self.assertEqual(target_body["auth_profile_id"], profile_id)

        scan = self.client.post(
            "/api/v1/scans",
            json={"target_id": target_body["id"], "scan_profile_id": "passive-web", "acknowledgements": ["authorized_target"]},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(scan.status_code, 201)
        scan_body = scan.json()
        self.created_scan_ids.append(scan_body["id"])
        self.assertNotIn("auth_profile_id", scan_body)
        with SessionLocal() as db:
            stored_scan = db.get(Scan, scan_body["id"])
            self.assertIsNotNone(stored_scan)
            self.assertEqual(stored_scan.auth_profile_id, profile_id)

    def test_target_rejects_cross_workspace_profile(self) -> None:
        other_profile_id = str(uuid4())
        other_workspace_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(Workspace(id=other_workspace_id, owner_user_id=DEV_USER_ID, name="Other Workspace"))
            db.flush()
            db.add(
                AuthProfile(
                    id=other_profile_id,
                    workspace_id=other_workspace_id,
                    created_by_user_id=DEV_USER_ID,
                    label="Other",
                    profile_type="bearer_token",
                    encrypted_secret="ciphertext",
                    secret_hint="****text",
                )
            )
            db.commit()

        response = self.client.post(
            "/api/v1/targets",
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
            db.execute(delete(Workspace).where(Workspace.id == other_workspace_id))
            db.commit()

    def test_rotation_and_revocation_enforce_scan_lifecycle(self) -> None:
        profile = self.client.post(
            "/api/v1/auth-profiles",
            json={"label": "Rotating", "profile_type": "bearer_token", "secret": "first-secret"},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(profile.status_code, 201)
        profile_id = profile.json()["id"]
        self.created_auth_profile_ids.append(profile_id)

        rotated = self.client.post(
            f"/api/v1/auth-profiles/{profile_id}/rotate",
            json={"secret": "second-secret"},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(rotated.status_code, 200)
        self.assertEqual(rotated.json()["rotation_count"], 1)
        self.assertEqual(rotated.json()["secret_hint"], "****cret")
        self.assertNotIn("secret", rotated.json())

        target = self.client.post(
            "/api/v1/targets",
            json={"target_url": "http://juice-shop:3000", "permission_confirmed": True, "auth_profile_id": profile_id},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(target.status_code, 201)
        target_id = target.json()["id"]
        self.created_target_ids.append(target_id)
        scan = self.client.post(
            "/api/v1/scans",
            json={"target_id": target_id, "scan_profile_id": "passive-web", "acknowledgements": ["authorized_target"]},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(scan.status_code, 201)
        scan_id = scan.json()["id"]
        self.created_scan_ids.append(scan_id)

        blocked_rotation = self.client.post(
            f"/api/v1/auth-profiles/{profile_id}/rotate",
            json={"secret": "third-secret"},
            headers=DEV_AUTH_HEADERS,
        )
        blocked_revocation = self.client.post(
            f"/api/v1/auth-profiles/{profile_id}/revoke",
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(blocked_rotation.status_code, 409)
        self.assertEqual(blocked_revocation.status_code, 409)

        cancelled = self.client.post(f"/api/v1/scans/{scan_id}/cancel", headers=DEV_AUTH_HEADERS)
        self.assertEqual(cancelled.status_code, 200)
        revoked = self.client.post(f"/api/v1/auth-profiles/{profile_id}/revoke", headers=DEV_AUTH_HEADERS)
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(revoked.json()["status"], "revoked")
        self.assertEqual(revoked.json()["secret_hint"], "revoked")

        with SessionLocal() as db:
            stored_profile = db.get(AuthProfile, profile_id)
            stored_target = db.get(Target, target_id)
            self.assertIsNone(stored_profile.encrypted_secret)
            self.assertIsNone(stored_target.auth_profile_id)

        rotate_revoked = self.client.post(
            f"/api/v1/auth-profiles/{profile_id}/rotate",
            json={"secret": "fourth-secret"},
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(rotate_revoked.status_code, 409)


if __name__ == "__main__":
    unittest.main()
