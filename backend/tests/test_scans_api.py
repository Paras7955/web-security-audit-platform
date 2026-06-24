import unittest
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.api.deps import get_scan_allowlist
from app.db.session import SessionLocal
from app.main import app
from app.models import Scan, Target
from app.security.allowlist import ScanAllowlist


class ScanApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.created_scan_ids: list[str] = []
        self.created_target_ids: list[str] = []

    def tearDown(self) -> None:
        with SessionLocal() as db:
            if self.created_scan_ids:
                db.execute(delete(Scan).where(Scan.id.in_(self.created_scan_ids)))
            if self.created_target_ids:
                db.execute(delete(Target).where(Target.id.in_(self.created_target_ids)))
            db.commit()

    def create_target(self) -> dict[str, object]:
        response = self.client.post(
            "/targets",
            json={"target_url": "http://juice-shop:3000", "permission_confirmed": True},
        )
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_target_ids.append(body["id"])
        return body

    def test_create_passive_scan_queues_job(self) -> None:
        target = self.create_target()

        response = self.client.post("/scans", json={"target_id": target["id"], "mode": "passive"})

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_scan_ids.append(body["id"])
        self.assertEqual(body["target_id"], target["id"])
        self.assertEqual(body["mode"], "passive")
        self.assertEqual(body["status"], "queued")
        self.assertEqual(body["current_step"], "target_validation")
        self.assertEqual(body["progress_percent"], 0)
        self.assertIn("passive scanner worker", body["status_message"])

    def test_create_scan_rejects_missing_target(self) -> None:
        response = self.client.post("/scans", json={"target_id": str(uuid4()), "mode": "passive"})

        self.assertEqual(response.status_code, 404)

    def test_create_active_demo_scan_requires_acknowledgement(self) -> None:
        target = self.create_target()

        response = self.client.post("/scans", json={"target_id": target["id"], "mode": "active_demo"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("acknowledgement", response.json()["detail"])

    def test_create_active_demo_scan_rejects_non_local_demo_target(self) -> None:
        allowlist = build_scan_allowlist(local_demo=False, allowed_modes=("passive", "active_demo"))
        target = self.create_db_target(allowlist_id="remote-demo", base_url="https://owned.example.test/")

        app.dependency_overrides[get_scan_allowlist] = lambda: allowlist
        try:
            response = self.client.post(
                "/scans",
                json={"target_id": target.id, "mode": "active_demo", "active_demo_acknowledged": True},
            )
        finally:
            app.dependency_overrides.pop(get_scan_allowlist, None)

        self.assertEqual(response.status_code, 400)
        self.assertIn("local/demo", response.json()["detail"])

    def test_create_active_demo_scan_queues_for_local_demo_target(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/scans",
            json={"target_id": target["id"], "mode": "active_demo", "active_demo_acknowledged": True},
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_scan_ids.append(body["id"])
        self.assertEqual(body["mode"], "active_demo")
        self.assertEqual(body["status"], "queued")

    def test_create_ajax_short_scan_requires_acknowledgement(self) -> None:
        target = self.create_target()

        response = self.client.post("/scans", json={"target_id": target["id"], "mode": "ajax_short"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("acknowledgement", response.json()["detail"])

    def test_create_ajax_short_scan_rejects_non_local_demo_target(self) -> None:
        allowlist = build_scan_allowlist(local_demo=False, allowed_modes=("passive", "ajax_short"))
        target = self.create_db_target(allowlist_id="remote-demo", base_url="https://owned.example.test/")

        app.dependency_overrides[get_scan_allowlist] = lambda: allowlist
        try:
            response = self.client.post(
                "/scans",
                json={"target_id": target.id, "mode": "ajax_short", "ajax_short_acknowledged": True},
            )
        finally:
            app.dependency_overrides.pop(get_scan_allowlist, None)

        self.assertEqual(response.status_code, 400)
        self.assertIn("local/demo", response.json()["detail"])

    def test_create_ajax_short_scan_queues_for_local_demo_target(self) -> None:
        target = self.create_target()

        response = self.client.post(
            "/scans",
            json={"target_id": target["id"], "mode": "ajax_short", "ajax_short_acknowledged": True},
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.created_scan_ids.append(body["id"])
        self.assertEqual(body["mode"], "ajax_short")
        self.assertEqual(body["status"], "queued")

    def test_list_and_get_scan(self) -> None:
        target = self.create_target()
        created = self.client.post("/scans", json={"target_id": target["id"], "mode": "passive"}).json()
        self.created_scan_ids.append(created["id"])

        detail = self.client.get(f"/scans/{created['id']}")
        scan_list = self.client.get("/scans")

        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["id"], created["id"])
        self.assertEqual(scan_list.status_code, 200)
        self.assertTrue(any(scan["id"] == created["id"] for scan in scan_list.json()))

    def create_db_target(self, *, allowlist_id: str, base_url: str) -> Target:
        target = Target(
            id=str(uuid4()),
            allowlist_id=allowlist_id,
            name="Remote demo",
            base_url=base_url,
            permission_confirmed=True,
        )
        with SessionLocal() as db:
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
                    "base_url": "https://owned.example.test",
                    "schemes": ["https"],
                    "hosts": ["owned.example.test"],
                    "ports": [443],
                    "allowed_modes": list(allowed_modes),
                    "max_redirects": 2,
                    "local_demo": local_demo,
                }
            ]
        }
    )


if __name__ == "__main__":
    unittest.main()
