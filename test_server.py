#!/usr/bin/env python3
"""Tests for the guest-report route: nonce validation, the pinned field
schema (the nightly asserts these fields), the HTTP contract, and the
confidentiality boundary (a workload claim, not an attested authority —
it must not echo host identity, secrets, or unbounded sidecar text)."""
from __future__ import annotations

import base64
import json
import socket
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

import server

VALID_NONCE = base64.urlsafe_b64encode(b"x" * server.REPORT_NONCE_BYTES).decode().rstrip("=")

REPORT_FIELDS = {
    "nonce", "generated_at", "vantage", "uname", "init_ready", "mounts",
    "block_devices", "mapper_devices", "sev", "sidecar",
}


class NonceValidation(unittest.TestCase):
    def test_accepts_urlsafe_unpadded_and_padded(self):
        self.assertEqual(server.parse_report_nonce(f"nonce={VALID_NONCE}"), VALID_NONCE)
        padded = VALID_NONCE + "=" * ((4 - len(VALID_NONCE) % 4) % 4)
        self.assertEqual(server.parse_report_nonce(f"nonce={padded}"), padded)

    def test_rejects_missing_or_duplicate(self):
        self.assertIsNone(server.parse_report_nonce(""))
        self.assertIsNone(server.parse_report_nonce("a=1"))
        self.assertIsNone(server.parse_report_nonce("nonce"))
        self.assertIsNone(server.parse_report_nonce("nonce="))
        self.assertIsNone(server.parse_report_nonce(f"nonce={VALID_NONCE}&nonce={VALID_NONCE}"))
        self.assertIsNone(server.parse_report_nonce(f"nonce={VALID_NONCE}&nonce=other"))
        self.assertIsNone(server.parse_report_nonce(f"nonce={VALID_NONCE}&nonce"))
        self.assertIsNone(server.parse_report_nonce(f"nonce={VALID_NONCE}&%6eonce={VALID_NONCE}"))

    def test_rejects_wrong_length_and_bad_encoding(self):
        short = base64.urlsafe_b64encode(b"too short").decode().rstrip("=")
        self.assertIsNone(server.parse_report_nonce(f"nonce={short}"))
        long = base64.urlsafe_b64encode(b"y" * 33).decode().rstrip("=")
        self.assertIsNone(server.parse_report_nonce(f"nonce={long}"))
        self.assertIsNone(server.parse_report_nonce("nonce=!!!not-base64!!!"))
        self.assertIsNone(server.parse_report_nonce("nonce=" + "A" * (server.REPORT_NONCE_MAX_CHARS + 1)))
        self.assertIsNone(server.parse_report_nonce(f"nonce={VALID_NONCE[:20]}={VALID_NONCE[20:]}"))


class SchemaPin(unittest.TestCase):
    """The nightly asserts these fields by name — changes here are contract
    changes and must land with the suite updated."""

    def test_top_level_fields(self):
        payload = server.guest_report_payload(VALID_NONCE)
        self.assertEqual(set(payload), REPORT_FIELDS)
        self.assertEqual(payload["nonce"], VALID_NONCE)
        self.assertEqual(payload["vantage"], "workload-container")
        self.assertIsInstance(payload["generated_at"], int)
        self.assertEqual(set(payload["uname"]), {"sys", "release", "machine"})
        self.assertEqual(set(payload["mounts"]), {"/state", "/app/data"})
        self.assertEqual(set(payload["sev"]), {"dev_present", "attestation_type", "runtime_class"})
        self.assertEqual(
            set(payload["sidecar"]),
            {"reachable", "claims_verified", "config_ready", "state", "mode", "error"},
        )
        for dev in payload["block_devices"]:
            self.assertEqual(set(dev), {"name", "size_sectors"})

    def test_output_is_bounded(self):
        payload = server.guest_report_payload(VALID_NONCE)
        self.assertLessEqual(len(payload["block_devices"]), server.REPORT_MAX_DEVICES)
        self.assertLessEqual(len(payload["mapper_devices"]), server.REPORT_MAX_DEVICES)
        self.assertLess(len(json.dumps(payload)), 16 * 1024)

    def test_sidecar_error_never_reflects_text_or_objects(self):
        # Secret material is injected inside error strings and nested error
        # objects; the claim must reduce every shape to the fixed indicator.
        for error in (
            "unlock failed with password=hunter2-s3cr3t",
            {"detail": "kdf failed", "token": "t0p-s3cr3t-token"},
            [{"reason": "private-key-material-9f3c"}],
        ):
            with self.subTest(error=type(error).__name__):
                status = {"state": "error", "mode": "password", "error": error}
                with mock.patch.object(server, "fetch", side_effect=[{}, status]):
                    payload = server.guest_report_payload(VALID_NONCE)
                self.assertEqual(payload["sidecar"]["error"], "present")
                body = json.dumps(payload)
                for marker in ("hunter2-s3cr3t", "t0p-s3cr3t-token",
                               "private-key-material-9f3c", "unlock failed"):
                    self.assertNotIn(marker, body)

    def test_wrong_typed_selected_fields_become_null(self):
        secret = "s3cr3t-p@ssw0rd-n0t-f0r-l34k"
        status = {
            "claims_verified": {"verified": secret},
            "config_ready": [True, secret],
            "state": {"nested": secret},
            "mode": 42,
            "error": None,
        }
        info = {
            "attestation_type": {"tee": secret},
            "runtime_class": "unlocked\ncanary-secret=1",
        }
        with mock.patch.object(server, "fetch", side_effect=[info, status]):
            payload = server.guest_report_payload(VALID_NONCE)
        for field in ("claims_verified", "config_ready", "state", "mode"):
            self.assertIsNone(payload["sidecar"][field])
        for field in ("attestation_type", "runtime_class"):
            self.assertIsNone(payload["sev"][field])
        self.assertIsNone(payload["sidecar"]["error"])
        self.assertNotIn(secret, json.dumps(payload))

    def test_normal_sidecar_status_still_reports(self):
        status = {
            "claims_verified": True, "config_ready": False,
            "state": "unlocked", "mode": "password", "error": None,
        }
        info = {"attestation_type": "coco-sev-snp", "runtime_class": "kata-qemu-snp"}
        with mock.patch.object(server, "fetch", side_effect=[info, status]):
            payload = server.guest_report_payload(VALID_NONCE)
        self.assertEqual(
            payload["sidecar"],
            {
                "reachable": True, "claims_verified": True, "config_ready": False,
                "state": "unlocked", "mode": "password", "error": None,
            },
        )
        self.assertEqual(
            payload["sev"],
            {
                "dev_present": payload["sev"]["dev_present"],
                "attestation_type": "coco-sev-snp",
                "runtime_class": "kata-qemu-snp",
            },
        )

    def test_numeric_flags_are_not_coerced_to_booleans(self):
        status = {"claims_verified": 1, "config_ready": 0, "error": 0}
        with mock.patch.object(server, "fetch", side_effect=[{}, status]):
            payload = server.guest_report_payload(VALID_NONCE)
        self.assertIsNone(payload["sidecar"]["claims_verified"])
        self.assertIsNone(payload["sidecar"]["config_ready"])
        self.assertIsNone(payload["sidecar"]["error"])

    def test_report_discloses_no_host_identity_or_secrets(self):
        payload = server.guest_report_payload(VALID_NONCE)
        self.assertNotIn("node", payload["uname"])
        self.assertNotIn("hostname", payload)
        body = json.dumps(payload)
        for marker in (socket.gethostname(), "password", "private_key", "secret"):
            self.assertNotIn(marker, body)


class Route(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def get(self, path):
        def parse(code, headers, raw):
            try:
                body = json.loads(raw.decode())
            except ValueError:
                body = raw.decode()
            return code, headers, body
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
                return parse(r.status, dict(r.headers), r.read())
        except urllib.error.HTTPError as e:
            return parse(e.code, dict(e.headers), e.read())

    def test_valid_nonce_serves_report(self):
        status, headers, body = self.get(f"/guest-report?nonce={VALID_NONCE}")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(body["nonce"], VALID_NONCE)
        self.assertEqual(set(body), REPORT_FIELDS)

    def test_padded_and_encoded_nonce_accepted(self):
        padded = VALID_NONCE + "=" * ((4 - len(VALID_NONCE) % 4) % 4)
        status, _, body = self.get(f"/guest-report?nonce={padded}")
        self.assertEqual(status, 200)
        self.assertEqual(body["nonce"], padded)
        status, _, _ = self.get(f"/guest-report?nonce={padded.replace('=', '%3D')}")
        self.assertEqual(status, 200)

    def test_extra_params_are_ignored(self):
        status, _, body = self.get(f"/guest-report?nonce={VALID_NONCE}&path=/etc/passwd&cmd=whoami")
        self.assertEqual(status, 200)
        self.assertEqual(set(body), REPORT_FIELDS)

    def test_http_response_never_contains_sidecar_secret_text(self):
        status = {
            "state": "error", "mode": "password",
            "error": "seed decrypt failed token=live-s3cr3t-zzz",
        }
        with mock.patch.object(server, "fetch", side_effect=[{}, status]):
            code, _, body = self.get(f"/guest-report?nonce={VALID_NONCE}")
        self.assertEqual(code, 200)
        self.assertNotIn("live-s3cr3t-zzz", json.dumps(body))
        self.assertNotIn("seed decrypt failed", json.dumps(body))
        self.assertEqual(body["sidecar"]["error"], "present")

    def test_missing_bare_empty_and_duplicate_nonce_are_400(self):
        for query in (
            "/guest-report",
            "/guest-report?nonce",
            "/guest-report?nonce=",
            "/guest-report?nonce=bad",
            f"/guest-report?nonce={VALID_NONCE}&nonce={VALID_NONCE}",
        ):
            with self.subTest(query=query):
                status, headers, body = self.get(query)
                self.assertEqual(status, 400)
                self.assertEqual(headers.get("Cache-Control"), "no-store")
                self.assertEqual(body, {"error": "nonce_invalid"})

    def test_unknown_path_still_404s(self):
        for path in ("/guest-report-evil", "/guest-report/", "/guest-report/extra"):
            with self.subTest(path=path):
                status, _, _ = self.get(path)
                self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
