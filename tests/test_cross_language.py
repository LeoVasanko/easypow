"""Cross-language tests: the bundled JS solver and the Python validator must agree.

These tests execute the actual bundled easypow.js with Node.js, guarding
against the two implementations drifting apart (e.g. mismatched masks).
Skipped when node is not available.
"""

import json
import secrets
import shutil
import subprocess
from importlib.resources import files

import base64url
import pytest

from easypow import generate, solve, validate
from easypow.pow import _decode

NODE = shutil.which("node")
SOLVER_PATH = files("easypow").joinpath("easypow.js")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not available")


def _run_node(script: str) -> str:
    result = subprocess.run(
        [NODE, "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _js_solves(challenge: str) -> None:
    script = (
        f"import solve from {json.dumps(str(SOLVER_PATH))}\n"
        f"console.log(await solve({json.dumps(challenge)}))"
    )
    validate(challenge, _run_node(script).splitlines()[-1])


def test_js_solution_validates_in_python() -> None:
    _js_solves(generate(seconds=0.2))


def test_js_solution_validates_in_python_custom_params() -> None:
    _js_solves(base64url.enc(bytes([2, 9 << 4 | 6]) + secrets.token_bytes(7)))


def test_python_solution_validates_in_js() -> None:
    challenge = generate(seconds=0.2)
    _, _, mask, iterations = _decode(challenge)
    script = f"""
const B64URL = {{ alphabet: 'base64url', omitPadding: true }}
const challenge = Uint8Array.fromBase64({json.dumps(challenge)}, B64URL)
const key = await crypto.subtle.importKey(
  'raw', challenge, 'PBKDF2', false, ['deriveBits']
)
const args = {{
  name: 'PBKDF2', salt: null, hash: 'SHA-512', iterations: {iterations}
}}
for (const fragment of {json.dumps(solve(challenge))}.split('.')) {{
  const nonce = Uint8Array.fromBase64(fragment.padEnd(6, 'A'), B64URL)
  const result = new Uint32Array(await crypto.subtle.deriveBits(
    {{ ...args, salt: nonce }}, key, 32
  ))
  if (result[0] & {mask}) {{
    console.error('nonce failed mask check')
    process.exit(1)
  }}
}}
"""
    _run_node(script)
