"""Proof-of-Work captcha using PBKDF2-SHA512.

Challenges are 9 bytes — work byte w, difficulty byte (high nibble:
zero bits z; low nibble: PBKDF2 iteration exponent n), 7 random
bytes — as 12-char base64url. Solutions are `w` dot-separated 4-byte
nonces, each base64url (6 chars max) with trailing 'A' zero-bit chars
stripped.
"""

import hashlib
import secrets

import base64url

# (max work units, zero bits z, 1<<n iterations, work shift); 1 unit = 0.1s
TIERS = [
    (31, 11, 7, 0),
    (127, 12, 7, 1),
    (511, 13, 7, 2),
    (2047, 14, 7, 3),
    (4095, 15, 7, 4),
]


def generate(seconds: float = 1.0) -> str:
    """Generate a challenge taking about `seconds` to solve (0.1 to 410)."""
    units = max(0, round(seconds * 10))
    _, z, n, shift = next((t for t in TIERS if units <= t[0]), TIERS[-1])
    w = min(units >> shift, 255)
    return base64url.enc(bytes([w, z << 4 | n]) + secrets.token_bytes(7))


def solve(challenge: str) -> str:
    """Solve a challenge, takes some time."""
    c, w, mask, iterations = _decode(challenge)
    fragments = []
    n = 0
    for _ in range(w):
        while True:
            n += 1
            nonce = n.to_bytes(4, "little")
            digest = hashlib.pbkdf2_hmac("sha512", c, nonce, iterations, 2)
            if not int.from_bytes(digest[:4], "little") & mask:
                fragments.append(base64url.enc(nonce).rstrip("A"))
                break
    return ".".join(fragments)


def validate(challenge: str, solution: str) -> None:
    """Validate a solution; raise ValueError if invalid."""
    c, w, mask, iterations = _decode(challenge)
    fragments = solution.split(".") if solution else []
    if len(fragments) != w or any(len(f) > 6 for f in fragments):
        msg = "Malformed easypow solution"
        raise ValueError(msg)
    for fragment in fragments:
        nonce = base64url.dec(fragment.ljust(6, "A"))
        digest = hashlib.pbkdf2_hmac("sha512", c, nonce, iterations, 2)
        if int.from_bytes(digest[:4], "little") & mask:
            msg = "Invalid easypow solution"
            raise ValueError(msg)


def _decode(challenge: str) -> tuple[bytes, int, int, int]:
    c = base64url.dec(challenge)
    w, diff = c[0], c[1]
    return c, w, (1 << (diff >> 4)) - 1, 1 << (diff & 0xF)
