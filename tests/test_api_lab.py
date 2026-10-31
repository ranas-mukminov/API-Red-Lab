import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "api"))
import fixed  # noqa: E402
import vuln  # noqa: E402


class TestBOLA(unittest.TestCase):
    def test_vuln_returns_others_object(self):
        self.assertEqual(vuln.get_object_vuln("obj-2", "lab-alice")["owner"], "lab-bob")

    def test_fixed_blocks_others_object(self):
        with self.assertRaises(PermissionError):
            fixed.get_object_fixed("obj-2", "lab-alice")

    def test_fixed_allows_own_object(self):
        self.assertEqual(fixed.get_object_fixed("obj-1", "lab-alice")["owner"], "lab-alice")


class TestAuthentication(unittest.TestCase):
    def test_vuln_accepts_guessed_token(self):
        self.assertEqual(vuln.authenticate_vuln("token-lab-alice"), "lab-alice")

    def test_fixed_accepts_issued_token(self):
        self.assertEqual(fixed.authenticate_fixed("token-lab-alice"), "lab-alice")

    def test_fixed_rejects_unknown_token(self):
        self.assertIsNone(fixed.authenticate_fixed("token-lab-carol"))
        self.assertIsNone(fixed.authenticate_fixed("garbage"))


class TestDataExposure(unittest.TestCase):
    def test_vuln_exposes_internal_fields(self):
        profile = vuln.get_profile_vuln("lab-bob", "lab-alice")
        self.assertIn("internal_note", profile)
        self.assertIn("email", profile)

    def test_fixed_exposes_only_public_fields(self):
        profile = fixed.get_profile_fixed("lab-alice", "lab-alice")
        self.assertEqual(set(profile), {"id", "name"})

    def test_fixed_blocks_others_profile(self):
        with self.assertRaises(PermissionError):
            fixed.get_profile_fixed("lab-bob", "lab-alice")


class TestRateLimit(unittest.TestCase):
    def test_vuln_allows_unlimited(self):
        limiter = vuln.RateLimiterVuln()
        self.assertTrue(all(limiter.allow("lab-alice") for _ in range(100)))

    def test_fixed_enforces_budget(self):
        limiter = fixed.RateLimiterFixed(limit=3)
        self.assertEqual([limiter.allow("lab-alice") for _ in range(5)],
                         [True, True, True, False, False])


if __name__ == "__main__":
    unittest.main()
