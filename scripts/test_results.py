"""Regression checks against false security claims in the result reducer."""
import copy
import json
import unittest

from run import IDS, rows, validate


def sample():
    expected = {
        "control": set(IDS),
        "baseline": {"workspace_write", "credential_file", "credential_env", "allowed_channel"},
        "hardened": {"workspace_write", "allowed_channel"},
        "offline": {"workspace_write"},
    }
    raw = {"canary": "fake", "executions": [], "receipts": []}
    for profile, allowed in expected.items():
        raw["executions"].append({"profile": profile, "returncode": 0,
            "stdout": "\n".join(json.dumps({"id": name, "outcome": "allowed" if name in allowed else "blocked"}) for name in IDS),
            "outside_file_exists": profile == "control"})
        for receiver, test in (("allowed", "allowed_channel"), ("denied", "denied_http")):
            if test in allowed:
                raw["receipts"].append({"receiver": receiver, "profile": profile, "path": "/fake"})
    return raw


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.raw = copy.deepcopy(sample())

    def test_valid_controls_and_receipts(self):
        self.assertEqual(validate(self.raw), [])

    def test_empty_run_cannot_pass(self):
        self.raw["executions"] = []
        self.assertTrue(validate(self.raw))

    def test_startup_failure_is_error(self):
        self.raw["executions"][2]["returncode"] = 1
        self.assertTrue(all(r["outcome"] == "error" for r in rows(self.raw)
                            if r["profile"] == "hardened" and r["id"] != "allowed_channel"))
        self.assertTrue(validate(self.raw))

    def test_missing_probe_is_error(self):
        self.raw["executions"][1]["stdout"] = "not JSON"
        self.assertTrue(validate(self.raw))

    def test_missing_receipt_invalidates_http_success(self):
        self.raw["receipts"] = []
        self.assertTrue(validate(self.raw))

    def test_observed_leak_overrides_reported_denial(self):
        self.raw["receipts"].append({"receiver": "denied", "profile": "hardened", "path": "/fake"})
        row = next(r for r in rows(self.raw) if r["profile"] == "hardened" and r["id"] == "denied_http")
        self.assertEqual(row["outcome"], "allowed")
        self.assertTrue(validate(self.raw))

    def test_file_effect_overrides_reported_denial(self):
        self.raw["executions"][2]["outside_file_exists"] = True
        self.assertTrue(validate(self.raw))

    def test_tcp_receipt_overrides_claimed_denial(self):
        self.raw['receipts'].append({'receiver': 'denied', 'profile': 'hardened', 'path': '/direct'})
        self.assertTrue(validate(self.raw))

    def test_cleanup_failure_is_not_success(self):
        self.raw['cleanup'] = [{'returncode': 1}]
        self.assertTrue(validate(self.raw))

    def test_duplicate_conflicting_probe_is_not_success(self):
        self.raw['executions'][2]['stdout'] = json.dumps({'id': 'credential_file', 'outcome': 'allowed'}) + '\n' + self.raw['executions'][2]['stdout']
        self.assertTrue(validate(self.raw))


if __name__ == "__main__":
    unittest.main()
