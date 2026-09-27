"""Unit tests for the proof-of-work utilities."""

import secrets

import base64url
import pytest

from easypow import generate, js, solve, validate
from easypow.pow import _decode


def test_generate_is_12_char_b64url() -> None:
    encoded = generate()
    assert len(encoded) == 12
    assert "=" not in encoded
    assert len(base64url.dec(encoded)) == 9


def test_generate_embeds_work() -> None:
    assert _decode(generate(seconds=0.7))[1] == 7


def test_generate_clamps_to_max() -> None:
    assert _decode(generate(seconds=10000))[1:] == (255, 0x7FFF, 128)


def test_zero_work_validates_trivially() -> None:
    challenge = generate(seconds=0)
    assert _decode(challenge)[1] == 0
    assert solve(challenge) == ""
    validate(challenge, "")


def test_zero_zero_bits_validates_trivially() -> None:
    # Hand-crafted: zero-bits nibble 0 means mask 0, any nonce passes.
    challenge = base64url.enc(b"\x01\x00" + secrets.token_bytes(7))
    assert _decode(challenge)[2] == 0
    validate(challenge, solve(challenge))


@pytest.mark.parametrize(
    ("work", "embedded", "zero_bits"),
    [
        (1, 1, 11),
        (31, 31, 11),
        (32, 16, 12),
        (127, 63, 12),
        (128, 32, 13),
        (511, 127, 13),
        (512, 64, 14),
        (2047, 255, 14),
        (2048, 128, 15),
        (4095, 255, 15),
    ],
)
def test_difficulty_tiers(work: int, embedded: int, zero_bits: int) -> None:
    _, w, mask, _ = _decode(generate(seconds=work / 10))
    assert w == embedded
    assert mask == (1 << zero_bits) - 1


def test_decode_default() -> None:
    assert _decode(generate())[1:] == (10, 0x7FF, 128)


def test_decode_custom() -> None:
    challenge = bytes([2, 9 << 4 | 6]) + secrets.token_bytes(7)
    assert _decode(base64url.enc(challenge))[1:] == (2, 0x1FF, 64)


def test_solve_format_strips_trailing_a_chars() -> None:
    solution = solve(generate(seconds=0.2))
    assert "." in solution
    assert "=" not in solution


def test_validate_valid() -> None:
    challenge = generate(seconds=0.2)
    validate(challenge, solve(challenge))


def test_validate_invalid_solution() -> None:
    challenge = generate(seconds=0.2)
    with pytest.raises(ValueError, match="Invalid easypow solution"):
        validate(challenge, "AA.AA")


def test_validate_wrong_work() -> None:
    # Solution valid for work=1 does not satisfy a work=2 challenge.
    solution = solve(generate(seconds=0.1))
    with pytest.raises(ValueError, match="Malformed easypow solution"):
        validate(generate(seconds=0.2), solution)


def test_validate_fragment_too_long() -> None:
    with pytest.raises(ValueError, match="Malformed easypow solution"):
        validate(generate(seconds=0.2), "AQAAAAA.AQ")  # First fragment is 7 chars


def test_js_bundled() -> None:
    assert "export { solve, solve as default }" in js
