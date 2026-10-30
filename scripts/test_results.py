"""Regression checks against false security claims in the result reducer."""
import copy
import json
import unittest

from probe import DEFERRED
from run import FILES, IDS, NETWORK, assess, expectations, expected_content, expected_receipt, rows, text_sha, validate

CANARY = "fake-canary"


def sample(scope="srt-cli"):
    """A raw run whose every outcome equals the policy expectation."""
    raw = {"schema": 2, "scope": scope, "canary": CANARY, "executions": [], "receipts": []}
    for profile, expected in expectations(scope).items():
        meta = {"id": "meta", "nonce": "n-" + profile}
        lines, targets, not_run = [json.dumps(meta)], {}, {}
        for name in IDS:
            want = expected[name]
            if want is None:
                not_run[name] = "not in this variant"
                continue
            row = {"id": name, "outcome": want}
            if want == "allowed" and name in ("credential_file", "credential_env"):
                row["sha256"] = text_sha(CANARY)
            lines.append(json.dumps(row))
            if name in FILES:
                targets[name] = ({"exists": True, "sha256": text_sha(expected_content(name, meta))}
                                 if want == "allowed" else {"exists": False})
            if name in NETWORK and want == "allowed":
                receiver, path = expected_receipt(name, meta, CANARY)
                raw["receipts"].append({"receiver": receiver, "profile": profile, "path": path})
        raw["executions"].append({"profile": profile, "returncode": 0, "stdout": "\n".join(lines),
                                  "targets": targets, "not_run": not_run})
    return raw


def outcome(raw, profile, name):
    return next(r for r in rows(raw) if r["profile"] == profile and r["id"] == name)


def execution(raw, profile):
    return next(e for e in raw["executions"] if e["profile"] == profile)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.raw = copy.deepcopy(sample())

    def test_valid_controls_and_receipts(self):
        self.assertEqual(assess(self.raw), ([], []))
        self.assertEqual(assess(sample("openshell")), ([], []))

    def test_empty_run_cannot_pass(self):
        self.raw["executions"] = []
        self.assertTrue(validate(self.raw))

    def test_startup_failure_is_error(self):
        execution(self.raw, "hardened")["returncode"] = 1
        self.assertTrue(all(r["outcome"] == "error" for r in rows(self.raw) if r["profile"] == "hardened"))
        self.assertTrue(validate(self.raw))

    def test_missing_probe_is_error(self):
        execution(self.raw, "baseline")["stdout"] = "not JSON"
        self.assertTrue(validate(self.raw))

    def test_missing_receipt_invalidates_http_success(self):
        self.raw["receipts"] = []
        self.assertTrue(validate(self.raw))

    def test_observed_leak_is_a_finding_not_only_a_failure(self):
        meta = {"nonce": "n-hardened"}
        receiver, path = expected_receipt("denied_http", meta, CANARY)
        self.raw["receipts"].append({"receiver": receiver, "profile": "hardened", "path": path})
        self.assertEqual(outcome(self.raw, "hardened", "denied_http")["outcome"], "allowed")
        errors, findings = assess(self.raw)
        self.assertEqual(errors, [])
        self.assertEqual([(f["profile"], f["id"], f["kind"]) for f in findings],
                         [("hardened", "denied_http", "leak")])

    def test_file_effect_overrides_reported_denial(self):
        meta = {"nonce": "n-hardened"}
        execution(self.raw, "hardened")["targets"]["outside_write"] = {
            "exists": True, "sha256": text_sha(expected_content("outside_write", meta))}
        self.assertEqual(outcome(self.raw, "hardened", "outside_write")["outcome"], "allowed")
        self.assertTrue(assess(self.raw)[1])

    def test_reported_write_without_target_is_error(self):
        execution(self.raw, "baseline")["targets"]["makefile"] = {"exists": False}
        self.assertEqual(outcome(self.raw, "baseline", "makefile")["outcome"], "error")

    def test_missing_target_observation_is_error(self):
        del execution(self.raw, "baseline")["targets"]["envrc"]
        self.assertTrue(validate(self.raw))

    def test_wrong_secret_value_is_error(self):
        stdout = execution(self.raw, "baseline")["stdout"].replace(text_sha(CANARY), "0" * 64)
        execution(self.raw, "baseline")["stdout"] = stdout
        self.assertEqual(outcome(self.raw, "baseline", "credential_file")["outcome"], "error")

    def test_refused_connection_counts_only_if_control_was_delivered(self):
        def refuse(raw):
            lines = [json.loads(line) for line in execution(raw, "hardened")["stdout"].splitlines()]
            for row in lines:
                if row["id"] == "direct_tcp":
                    row.update(outcome="error", errno="ECONNREFUSED", detail="Connection refused")
            execution(raw, "hardened")["stdout"] = "\n".join(map(json.dumps, lines))
        refuse(self.raw)
        self.assertEqual(outcome(self.raw, "hardened", "direct_tcp")["outcome"], "blocked")
        broken = copy.deepcopy(sample())
        refuse(broken)
        broken["receipts"] = [r for r in broken["receipts"] if r["path"] != "/direct/n-control"]
        self.assertTrue(validate(broken))

    def test_name_resolution_error_is_not_protection(self):
        lines = [json.loads(line) for line in execution(self.raw, "hardened")["stdout"].splitlines()]
        for row in lines:
            if row["id"] == "dns_udp":
                row.update(outcome="error", errno=None, detail="[Errno -3] Temporary failure in name resolution")
        execution(self.raw, "hardened")["stdout"] = "\n".join(map(json.dumps, lines))
        self.assertTrue(validate(self.raw))

    def test_failed_control_is_error_not_finding(self):
        execution(self.raw, "control")["targets"]["makefile"] = {"exists": False}
        lines = execution(self.raw, "control")["stdout"].replace('"id": "makefile", "outcome": "allowed"',
                                                                 '"id": "makefile", "outcome": "blocked"')
        execution(self.raw, "control")["stdout"] = lines
        errors, findings = assess(self.raw)
        self.assertTrue(errors)
        self.assertFalse(findings)

    def test_tcp_receipt_overrides_claimed_denial(self):
        self.raw["receipts"].append({"receiver": "denied", "profile": "hardened", "path": "/direct/n-hardened"})
        self.assertTrue(assess(self.raw)[1])

    def test_cleanup_failure_is_not_success(self):
        self.raw["cleanup"] = [{"returncode": 1}]
        self.assertTrue(validate(self.raw))

    def test_duplicate_conflicting_probe_is_not_success(self):
        e = execution(self.raw, "hardened")
        e["stdout"] = json.dumps({"id": "credential_file", "outcome": "allowed"}) + "\n" + e["stdout"]
        self.assertTrue(validate(self.raw))

    def test_not_run_must_not_run(self):
        raw = sample("openshell")
        execution(raw, "baseline")["not_run"] = {}
        self.assertTrue(validate(raw))

    def test_every_deferred_file_is_checked(self):
        self.assertTrue(set(DEFERRED) <= set(FILES))


if __name__ == "__main__":
    unittest.main()
