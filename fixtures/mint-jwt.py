#!/usr/bin/env python3
"""Mint a fixture JWT signed with the stack's PGRST_JWT_SECRET.

ONE script for every fixture. There were previously three copies and they
drifted: the matrix fixture held a version predating the --role flag, which did
not reject the unknown argument but silently emitted an `anon` token into a
file named authenticated.jwt.

That token was about to become the negative control for the privilege
escalation soundness test, where it would have "proved" the probe finds no
escalation — a correct-looking result produced by a broken input. Same class of
failure this project keeps finding in probes, arriving this time through a
fixture.

So the token is decoded after minting and the role claim checked against what
was asked for. Verifying the output rather than trusting the code path is the
only thing that would have caught the drift.

  python3 fixtures/mint-jwt.py                                   # anon
  python3 fixtures/mint-jwt.py --role authenticated              # authenticated
  python3 fixtures/mint-jwt.py --role authenticated --sub <uuid> # a specific user
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
import json

SECRET = b"super-secret-jwt-token-with-at-least-32-characters-long"


def b64(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def claims_of(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def mint(role: str, sub: str, secret: bytes = None) -> str:
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    # Claims are fixed rather than time-based: a token whose contents change
    # between runs would make scans non-reproducible for no benefit.
    claims = {"role": role, "iss": "supabase-fixture", "iat": 1700000000, "exp": 4102444800}
    # sub is carried for EVERY role, including anon.
    #
    # It used to be dropped for anon, so `--sub X` was accepted and silently
    # did nothing: two anon tokens minted with different subs came out byte
    # identical. That is the same shape as the --role drift this script's
    # header describes, and it had the same consequence -- a preview-deployment
    # fixture meant to serve a DIFFERENT key from production served the same
    # one, so the finding took its "already public" branch and the fixture
    # would have documented the wrong expectation.
    claims["sub"] = sub
    payload = b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = b64(hmac.new(secret or SECRET, header + b"." + payload, hashlib.sha256).digest())
    return (header + b"." + payload + b"." + sig).decode()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", default="anon", choices=["anon", "authenticated", "service_role"])
    ap.add_argument("--sub", default="11111111-1111-1111-1111-111111111111")
    # A key signed with a DIFFERENT secret is what rotation actually produces,
    # and without one the fixture cannot tell a rotated credential from a live
    # one: every token minted here works, so a test that an archived key still
    # authenticates passes whatever it is pointed at. That is a test passing
    # for the wrong reason, which is worse than no test.
    ap.add_argument("--secret", default=None,
                    help="sign with a different secret: a key the project would refuse")
    args = ap.parse_args()

    token = mint(args.role, args.sub,
                 args.secret.encode() if args.secret else None)

    got = claims_of(token)
    if got.get("role") != args.role:
        raise SystemExit(f"minted token claims role {got.get('role')!r}, expected {args.role!r}")
    # Verified for the same reason the role is: a flag that parses and does
    # nothing produces a fixture that looks right.
    if got.get("sub") != args.sub:
        raise SystemExit(f"minted token claims sub {got.get('sub')!r}, expected {args.sub!r}")

    print(token)
