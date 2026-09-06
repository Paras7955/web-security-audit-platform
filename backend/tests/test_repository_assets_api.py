import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app.db.session import SessionLocal
from app.main import app
from app.models import AuditLog, RepositoryAsset, Scan, Workspace
from fastapi.testclient import TestClient
from sqlalchemy import delete

from tests.helpers import DEV_AUTH_HEADERS, DEV_USER_ID, DEV_WORKSPACE_ID, ensure_dev_principal


class RepositoryAssetApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.temp_dir.name)
        self.repo_path = self.repo_root / "example-repository"
        self.repo_path.mkdir()
        self.asset_ids: list[str] = []
        self.scan_ids: list[str] = []
        self.other_workspace_id = str(uuid4())
        with SessionLocal() as db:
            ensure_dev_principal(db)
            db.add(
                Workspace(
                    id=self.other_workspace_id,
                    owner_user_id=DEV_USER_ID,
                    name="Other Workspace",
                )
            )
            db.commit()

    def tearDown(self) -> None:
        with SessionLocal() as db:
            if self.scan_ids:
                db.execute(delete(Scan).where(Scan.id.in_(self.scan_ids)))
            if self.asset_ids:
                db.execute(delete(RepositoryAsset).where(RepositoryAsset.id.in_(self.asset_ids)))
            db.execute(
                delete(AuditLog).where(
                    AuditLog.workspace_id.in_([DEV_WORKSPACE_ID, self.other_workspace_id]),
                    AuditLog.resource_type == "repository_asset",
                )
            )
            db.execute(delete(Workspace).where(Workspace.id == self.other_workspace_id))
            db.commit()
        self.temp_dir.cleanup()

    def create_asset(self) -> dict[str, object]:
        with patch("app.api.repository_assets.settings.repo_scan_root", str(self.repo_root)):
            response = self.client.post(
                "/api/v1/repository-assets",
                headers=DEV_AUTH_HEADERS,
                json={
                    "name": "Example repository",
                    "repo_path": str(self.repo_path),
                    "permission_confirmed": True,
                },
            )
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.asset_ids.append(body["id"])
        return body

    def test_create_list_read_and_archive_repository_asset(self) -> None:
        created = self.create_asset()

        listing = self.client.get("/api/v1/repository-assets", headers=DEV_AUTH_HEADERS)
        detail = self.client.get(
            f"/api/v1/repository-assets/{created['id']}",
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(created["relative_path"], "example-repository")
        self.assertTrue(created["permission_confirmed"])
        self.assertTrue(any(item["id"] == created["id"] for item in listing.json()["items"]))
        self.assertEqual(detail.status_code, 200)

        archived = self.client.delete(
            f"/api/v1/repository-assets/{created['id']}",
            headers=DEV_AUTH_HEADERS,
        )
        hidden = self.client.get(
            f"/api/v1/repository-assets/{created['id']}",
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(archived.status_code, 204)
        self.assertEqual(hidden.status_code, 404)

    def test_creation_rejects_missing_permission_and_paths_outside_root(self) -> None:
        with patch("app.api.repository_assets.settings.repo_scan_root", str(self.repo_root)):
            missing_permission = self.client.post(
                "/api/v1/repository-assets",
                headers=DEV_AUTH_HEADERS,
                json={
                    "name": "Unconfirmed",
                    "repo_path": str(self.repo_path),
                    "permission_confirmed": False,
                },
            )
            outside = self.client.post(
                "/api/v1/repository-assets",
                headers=DEV_AUTH_HEADERS,
                json={
                    "name": "Outside",
                    "repo_path": str(self.repo_root.parent),
                    "permission_confirmed": True,
                },
            )

        self.assertEqual(missing_permission.status_code, 400)
        self.assertEqual(outside.status_code, 400)

    def test_repository_scan_uses_immutable_asset_snapshot_and_blocks_archive(self) -> None:
        created = self.create_asset()
        with patch("app.api.scans.settings.repo_scan_root", str(self.repo_root)):
            response = self.client.post(
                "/api/v1/scans",
                headers=DEV_AUTH_HEADERS,
                json={
                    "repository_asset_id": created["id"],
                    "scan_profile_id": "repository",
                    "acknowledgements": ["authorized_repository"],
                },
            )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.scan_ids.append(body["id"])
        self.assertIsNone(body["target_id"])
        self.assertEqual(body["repository_asset_id"], created["id"])
        self.assertEqual(body["subject_type"], "repository_asset")

        with SessionLocal() as db:
            scan = db.get(Scan, body["id"])
            self.assertIsNotNone(scan)
            self.assertEqual(scan.repo_path_snapshot, "example-repository")
            self.assertEqual(
                scan.authorization_snapshot,
                {
                    "subject_type": "repository_asset",
                    "subject_id": created["id"],
                    "relative_path": "example-repository",
                    "authorized_at": scan.authorization_snapshot["authorized_at"],
                },
            )

        blocked = self.client.delete(
            f"/api/v1/repository-assets/{created['id']}",
            headers=DEV_AUTH_HEADERS,
        )
        self.assertEqual(blocked.status_code, 409)

    def test_repository_asset_ids_are_workspace_scoped(self) -> None:
        other_asset_id = str(uuid4())
        self.asset_ids.append(other_asset_id)
        with SessionLocal() as db:
            db.add(
                RepositoryAsset(
                    id=other_asset_id,
                    workspace_id=self.other_workspace_id,
                    created_by_user_id=DEV_USER_ID,
                    name="Other repository",
                    relative_path="other",
                    permission_confirmed=True,
                )
            )
            db.commit()

        detail = self.client.get(
            f"/api/v1/repository-assets/{other_asset_id}",
            headers=DEV_AUTH_HEADERS,
        )
        with patch("app.api.scans.settings.repo_scan_root", str(self.repo_root)):
            launch = self.client.post(
                "/api/v1/scans",
                headers=DEV_AUTH_HEADERS,
                json={
                    "repository_asset_id": other_asset_id,
                    "scan_profile_id": "repository",
                    "acknowledgements": ["authorized_repository"],
                },
            )

        self.assertEqual(detail.status_code, 404)
        self.assertEqual(launch.status_code, 404)

    def test_repository_dashboard_and_comparison_use_repository_subject(self) -> None:
        created = self.create_asset()
        baseline_id = str(uuid4())
        comparison_id = str(uuid4())
        self.scan_ids.extend((baseline_id, comparison_id))
        with SessionLocal() as db:
            for offset, scan_id in enumerate((baseline_id, comparison_id)):
                completed_at = datetime(2026, 7, 29, tzinfo=UTC) + timedelta(minutes=offset)
                db.add(
                    Scan(
                        id=scan_id,
                        workspace_id=DEV_WORKSPACE_ID,
                        created_by_user_id=DEV_USER_ID,
                        repository_asset_id=created["id"],
                        repo_path_snapshot="example-repository",
                        mode="repository",
                        scan_profile_id="repository",
                        status="completed",
                        current_step="normalizing_findings",
                        status_message="Completed.",
                        progress_percent=100,
                        started_at=completed_at - timedelta(seconds=1),
                        completed_at=completed_at,
                        created_at=completed_at - timedelta(seconds=2),
                    )
                )
            db.commit()

        dashboard = self.client.get(
            f"/api/v1/repository-assets/{created['id']}/dashboard",
            headers=DEV_AUTH_HEADERS,
        )
        comparison = self.client.get(
            f"/api/v1/repository-assets/{created['id']}/latest-comparison",
            headers=DEV_AUTH_HEADERS,
        )

        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(dashboard.json()["repository_asset_id"], created["id"])
        self.assertEqual(dashboard.json()["posture_basis"], "latest completed scan per subject and profile")
        self.assertEqual(dashboard.json()["current_posture_score"]["scoring_model_version"], "posture-v2")
        self.assertEqual(comparison.status_code, 200)
        self.assertEqual(comparison.json()["subject_type"], "repository_asset")
        self.assertEqual(comparison.json()["repository_asset_id"], created["id"])
        self.assertEqual(comparison.json()["baseline_scan_id"], baseline_id)
        self.assertEqual(comparison.json()["comparison_scan_id"], comparison_id)


if __name__ == "__main__":
    unittest.main()
