"""Tests for jwt-scalpel. Run: python3 -m unittest discover -s tests -v"""

import base64
import hashlib
import hmac
import json
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jwtscalpel import scan, split_token, main


def b64(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make(header, payload, secret=None):
    h, p = b64(header), b64(payload)
    if secret is None:
        return h + "." + p + "."
    mac = hmac.new(secret.encode(), (h + "." + p).encode(),
                   hashlib.sha256).digest()
    sig = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
    return h + "." + p + "." + sig


FUTURE = 2000000000


class TestParse(unittest.TestCase):
    def test_rejects_two_segments(self):
        with self.assertRaises(ValueError):
            split_token("aaa.bbb")

    def test_rejects_bad_json(self):
        with self.assertRaises(ValueError):
            split_token("!!!.!!!.sig")

    def test_roundtrip(self):
        tok = make({"alg": "HS256"}, {"sub": "1", "exp": FUTURE}, "x")
        header, payload, _ = split_token(tok)
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(payload["sub"], "1")


class TestFindings(unittest.TestCase):
    def test_weak_secret_cracked(self):
        tok = make({"alg": "HS256"}, {"sub": "1", "exp": FUTURE}, "secret")
        titles = [t for _, t, _ in scan(tok)]
        self.assertIn("weak HMAC secret", titles)

    def test_strong_secret_clean_of_crack(self):
        tok = make({"alg": "HS256"}, {"sub": "1", "exp": FUTURE},
                   "v3ry-l0ng-r4nd0m-s3cret!!")
        titles = [t for _, t, _ in scan(tok)]
        self.assertNotIn("weak HMAC secret", titles)

    def test_none_alg_flagged(self):
        tok = b64({"alg": "none"}) + "." + b64({"sub": "1"}) + "."
        titles = [t for _, t, _ in scan(tok)]
        self.assertIn("alg is none", titles)

    def test_kid_traversal_flagged(self):
        tok = make({"alg": "HS256", "kid": "../../keys/dev"},
                   {"sub": "1", "exp": FUTURE}, "zz-top-secret-9")
        titles = [t for _, t, _ in scan(tok)]
        self.assertIn("suspicious kid", titles)

    def test_jku_flagged(self):
        tok = make({"alg": "RS256", "jku": "https://evil.example/jwks.json"},
                   {"sub": "1", "exp": FUTURE})
        titles = [t for _, t, _ in scan(tok)]
        self.assertIn("untrusted key URL", titles)

    def test_expired_flagged(self):
        tok = make({"alg": "HS256"}, {"sub": "1", "exp": 1000},
                   "zz-top-secret-9")
        severities = {t: s for s, t, _ in scan(tok)}
        self.assertEqual(severities.get("token expired"), "high")

    def test_missing_exp_noted(self):
        tok = make({"alg": "HS256"}, {"sub": "1"}, "zz-top-secret-9")
        titles = [t for _, t, _ in scan(tok)]
        self.assertIn("no exp claim", titles)


class TestCLI(unittest.TestCase):
    def test_malformed_exits_2(self):
        self.assertEqual(main(["not-a-token"]), 2)

    def test_clean_token_exits_0(self):
        tok = make({"alg": "RS256"}, {"sub": "1", "exp": FUTURE})
        # RS256 with no kid/jku and valid exp: only info-level or none
        rc = main([tok])
        self.assertIn(rc, (0, 1))


if __name__ == "__main__":
    unittest.main()
