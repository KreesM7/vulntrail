from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from vulntrail.models import Finding, Run
from vulntrail.response import plan_response
from vulntrail import response
from vulntrail.store import Store


class ResponsePlanTests(unittest.TestCase):
    def test_plans_human_review_upgrade_and_verification_without_commands(self):
        run = Run(
            "demo",
            "trivy",
            [
                Finding("CVE-2025-1001", "demo; rm -rf /", "1", "pypi", "HIGH", fixed_version="2"),
                Finding("CVE-2025-1002", "other", "1", "pypi", "LOW", kev=True),
            ],
            status="partial",
            warnings=["Coverage incomplete"],
        )
        plan = plan_response(run)
        self.assertEqual(plan["run_id"], run.id)
        self.assertEqual(plan["actions"][0]["priority"], "P1")
        self.assertNotIn("command", str(plan).lower())
        self.assertTrue(any("2" in action["advice"] for action in plan["actions"]))
        self.assertTrue(
            all("verify" in action["verification"].lower() for action in plan["actions"])
        )
        self.assertIn("partial", plan["limitations"])

    def test_empty_plan_is_not_a_security_assurance(self):
        plan = plan_response(Run("demo", "trivy"))
        self.assertEqual(plan["actions"], [])
        self.assertIn("does not establish", plan["limitations"])


class ArtifactResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir(mode=0o700)
        self.artifact = self.root / "dependency.zip"
        self.artifact.write_bytes(b"project artifact")
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.store = Store(Path(self.temp.name) / "evidence.sqlite3")

    def hold(self):
        return response.hold_artifact(self.root, self.artifact, self.digest, self.store)

    def test_hold_restore_preserves_bytes_and_audits_both_operations(self):
        held = self.hold()
        self.assertFalse(self.artifact.exists())
        self.assertEqual(held["status"], "held")
        self.assertEqual(held["relative_path"], "dependency.zip")
        restored = response.restore_artifact(self.root, held["hold_id"], self.digest, self.store)
        self.assertEqual(restored["status"], "restored")
        self.assertEqual(self.artifact.read_bytes(), b"project artifact")
        with closing(sqlite3.connect(self.store.path)) as connection:
            events = [row[0] for row in connection.execute("SELECT event FROM audit")]
        self.assertIn("artifact_held", events)
        self.assertIn("artifact_restored", events)

    def test_wrong_digest_cannot_move_file(self):
        with self.assertRaises(ValueError):
            response.hold_artifact(self.root, self.artifact, "0" * 64, self.store)
        self.assertTrue(self.artifact.exists())
        with self.assertRaises(ValueError):
            response.hold_artifact(self.root, self.artifact, "not-a-digest", self.store)

    def test_root_outside_directory_and_metadata_targets_are_rejected(self):
        outside = Path(self.temp.name) / "outside.zip"
        outside.write_bytes(b"project artifact")
        for target in (self.root, outside, self.root / "../outside.zip"):
            with self.assertRaises(ValueError):
                response.hold_artifact(self.root, target, self.digest, self.store)
        self.hold()
        with self.assertRaises(ValueError):
            response.hold_artifact(
                self.root, self.root / ".vulntrail-hold/owner.json", self.digest, self.store
            )

    def test_foreign_owner_and_reparse_ancestors_fail_closed(self):
        with patch("vulntrail.response._owner", return_value="other-owner"):
            with self.assertRaises(ValueError):
                self.hold()
        nested = self.root / "nested"
        nested.mkdir()
        target = nested / "artifact"
        target.write_bytes(b"project artifact")
        original = response._reparse
        with patch(
            "vulntrail.response._reparse",
            side_effect=lambda path: Path(path) == nested or original(path),
        ):
            with self.assertRaises(ValueError):
                response.hold_artifact(self.root, target, self.digest, self.store)
        self.assertTrue(target.exists())

    def test_real_symlink_is_rejected_on_posix_and_reparse_file_on_windows(self):
        if os.name == "nt":
            original = response._reparse
            with patch(
                "vulntrail.response._reparse",
                side_effect=lambda path: Path(path) == self.artifact or original(path),
            ):
                with self.assertRaises(ValueError):
                    self.hold()
        else:
            link = self.root / "link"
            link.symlink_to(self.artifact)
            with self.assertRaises(ValueError):
                response.hold_artifact(self.root, link, self.digest, self.store)
        self.assertTrue(self.artifact.exists())

    def test_restore_collision_never_overwrites(self):
        held = self.hold()
        self.artifact.write_bytes(b"new project file")
        with self.assertRaises(ValueError):
            response.restore_artifact(self.root, held["hold_id"], self.digest, self.store)
        self.assertEqual(self.artifact.read_bytes(), b"new project file")

    def test_tampered_blob_or_manifest_cannot_restore(self):
        held = self.hold()
        directory = self.root / ".vulntrail-hold" / held["hold_id"]
        (directory / "artifact").write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            response.restore_artifact(self.root, held["hold_id"], self.digest, self.store)
        self.assertFalse(self.artifact.exists())
        manifest_path = directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["relative_path"] = "../../outside.zip"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(ValueError):
            response.restore_artifact(self.root, held["hold_id"], self.digest, self.store)

    def test_unowned_hold_directory_and_invalid_hold_identifier_are_rejected(self):
        directory = self.root / ".vulntrail-hold"
        directory.mkdir()
        (directory / "unrelated").write_bytes(b"keep")
        with self.assertRaises(ValueError):
            self.hold()
        self.assertEqual((directory / "unrelated").read_bytes(), b"keep")
        with self.assertRaises(ValueError):
            response.restore_artifact(self.root, "../escape", self.digest, self.store)

    def test_audit_failure_before_action_prevents_move(self):
        with patch.object(self.store, "audit", side_effect=RuntimeError("audit unavailable")):
            with self.assertRaises(RuntimeError):
                self.hold()
        self.assertTrue(self.artifact.exists())

    def test_prepared_manifest_recovers_after_post_move_metadata_failure(self):
        original = response._write_json

        def interrupted(path, value, descriptors, initial=False):
            if path.name == "manifest.json" and not initial:
                raise OSError("simulated metadata write failure")
            return original(path, value, descriptors, initial)

        with patch("vulntrail.response._write_json", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.hold()
        self.assertFalse(self.artifact.exists())
        manifests = list((self.root / ".vulntrail-hold").glob("*/manifest.json"))
        self.assertEqual(len(manifests), 1)
        record = json.loads(manifests[0].read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "prepared")
        response.restore_artifact(self.root, record["hold_id"], self.digest, self.store)
        self.assertEqual(self.artifact.read_bytes(), b"project artifact")

    def test_additional_hardlinks_and_oversize_files_cannot_be_held(self):
        with patch("vulntrail.response.MAX_ARTIFACT_BYTES", 1):
            with self.assertRaises(ValueError):
                self.hold()
        second = self.root / "second-link"
        os.link(self.artifact, second)
        with self.assertRaises(ValueError):
            self.hold()
        self.assertTrue(self.artifact.exists())

    def test_existing_operation_lock_prevents_a_second_response(self):
        first = self.hold()
        self.artifact.write_bytes(b"project artifact")
        lock = self.root / ".vulntrail-hold/.operation.lock"
        lock.write_text("another operation", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.hold()
        self.assertTrue(self.artifact.exists())
        self.assertEqual(lock.read_text(encoding="utf-8"), "another operation")
        self.assertEqual(first["status"], "held")
