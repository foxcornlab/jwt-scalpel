#!/usr/bin/env python3
"""jwt-scalpel - offline JWT security scanner.

Checks a JSON Web Token for common weaknesses without sending it
anywhere: algorithm confusion, weak HMAC secrets, suspicious key IDs,
untrusted key URLs, and lifetime problems.

Exit codes: 0 = no findings, 1 = findings, 2 = usage/target error.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
import time

VERSION = "1.0.0"

BUILTIN_SECRETS = [
    "secret", "password", "123456", "12345678", "qwerty",
    "jwt", "key", "test", "admin", "letmein",
    "changeme", "token", "foobar", "abc123", "secretkey",
]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def b64url_decode(data):
    """Decode unpadded base64url, returning bytes or raising ValueError."""
    if isinstance(data, str):
        data = data.encode("ascii")
    try:
        padded = data + b"=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url segment") from exc


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def split_token(token):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(
            "expected a compact JWS with 3 segments, got %d" % len(parts)
        )
    try:
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("header/payload are not valid JSON: %s" % exc)
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("header/payload must be JSON objects")
    return header, payload, parts


def check_lifetime(payload, now=None, skew=60):
    findings = []
    now = int(time.time()) if now is None else now
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    if exp is not None:
        try:
            if int(exp) + skew < now:
                findings.append(("high", "token expired",
                                 "exp %s is in the past" % exp))
        except (TypeError, ValueError):
            findings.append(("medium", "bad exp claim",
                             "exp is not an integer: %r" % (exp,)))
    else:
        findings.append(("low", "no exp claim",
                         "token never expires; theft is permanent"))
    if nbf is not None:
        try:
            if int(nbf) - skew > now:
                findings.append(("medium", "token not yet valid",
                                 "nbf %s is in the future" % nbf))
        except (TypeError, ValueError):
            findings.append(("medium", "bad nbf claim",
                             "nbf is not an integer: %r" % (nbf,)))
    return findings


def check_key_id(header):
    findings = []
    kid = header.get("kid")
    if kid is None:
        return findings
    if not isinstance(kid, str):
        findings.append(("medium", "non-string kid",
                         "kid should be a string, got %r" % (kid,)))
        return findings
    suspicious = ["..", "/", "\\", "%00", "'", '"', ";", "|", "$("]
    if any(s in kid for s in suspicious):
        findings.append(("high", "suspicious kid",
                         "kid %r looks injectable (path/SQL traversal)" % kid))
    return findings


def check_key_urls(header):
    findings = []
    for claim in ("jku", "x5u"):
        url = header.get(claim)
        if url is not None:
            findings.append(("high", "untrusted key URL",
                             "%s points at %r; a verifier fetching it "
                             "hands key selection to an attacker" % (claim, url)))
    if "jwk" in header:
        findings.append(("medium", "embedded jwk",
                         "header carries its own key; verifiers must "
                         "not trust it blindly"))
    return findings


def check_none_alg(parts):
    """Report whether an alg=none variant of this token is well-formed."""
    header, _, _ = split_token(".".join(parts))
    forged_header = dict(header)
    forged_header["alg"] = "none"
    forged = b64url_encode(json.dumps(forged_header,
                                      separators=(",", ":")).encode()) \
        + "." + parts[1] + "."
    try:
        split_token(forged)
        wellformed = True
    except ValueError:
        wellformed = False
    if wellformed:
        return [("medium", "alg confusion surface",
                 "a stripped alg=none variant parses cleanly; "
                 "reject 'none' server-side")]
    return []


def try_hmac(header, parts, secrets):
    alg = str(header.get("alg", ""))
    digest = {"HS256": hashlib.sha256,
              "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg)
    if digest is None:
        return []
    try:
        sig = b64url_decode(parts[2])
    except ValueError:
        return [("low", "undecodable signature",
                 "signature segment is not valid base64url")]
    if not sig:
        return [("high", "empty signature",
                 "HMAC token carries no signature bytes")]
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    for secret in secrets:
        mac = hmac.new(secret.encode("utf-8"), signing_input, digest).digest()
        if hmac.compare_digest(mac, sig):
            return [("high", "weak HMAC secret",
                     "signature verifies with secret %r" % secret)]
    return []


def scan(token, secrets=None, now=None):
    """Scan one token. Returns a list of (severity, title, detail)."""
    secrets = BUILTIN_SECRETS if secrets is None else secrets
    header, payload, parts = split_token(token)
    findings = []
    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        findings.append(("high", "alg is none",
                         "token is unsigned; anyone can mint it"))
    elif alg.startswith("HS"):
        findings.append(("info", "symmetric alg %s" % alg,
                         "HS* algs fall to secret guessing; tested "
                         "%d candidate secrets" % len(secrets)))
    findings.extend(check_lifetime(payload, now=now))
    findings.extend(check_key_id(header))
    findings.extend(check_key_urls(header))
    findings.extend(check_none_alg(parts))
    findings.extend(try_hmac(header, parts, secrets))
    rank = SEVERITY_ORDER
    findings.sort(key=lambda f: rank.get(f[0], 0), reverse=True)
    return findings


def format_text(findings):
    lines = []
    for sev, title, detail in findings:
        lines.append("[%s] %s: %s" % (sev.upper(), title, detail))
    return "\n".join(lines)


def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except OSError as exc:
        raise ValueError("cannot read wordlist: %s" % exc)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="jwt-scalpel",
        description="Offline JWT security scanner. "
                    "Findings exit 1, clean tokens exit 0.")
    ap.add_argument("token", nargs="?",
                    help="JWT string, or - to read stdin")
    ap.add_argument("-f", "--file", metavar="PATH",
                    help="read the token from a file")
    ap.add_argument("-w", "--wordlist", metavar="PATH",
                    help="extra HMAC secrets, one per line")
    ap.add_argument("--json", action="store_true",
                    help="emit findings as JSON")
    ap.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = ap.parse_args(argv)

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
        except OSError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
    elif args.token == "-" or (args.token is None and not sys.stdin.isatty()):
        token = sys.stdin.read().strip()
    elif args.token:
        token = args.token
    else:
        ap.print_usage(sys.stderr)
        return 2

    secrets = list(BUILTIN_SECRETS)
    if args.wordlist:
        try:
            for s in load_wordlist(args.wordlist):
                if s not in secrets:
                    secrets.append(s)
        except ValueError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2

    try:
        findings = scan(token, secrets=secrets)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(
            [{"severity": s, "title": t, "detail": d}
             for s, t, d in findings], indent=2))
    elif findings:
        print(format_text(findings))
    else:
        print("clean: no findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
