"""Proof-of-Work captcha using PBKDF2-SHA512, with a bundled JavaScript solver."""

from importlib.resources import files

from easypow.pow import generate, solve, validate

__all__ = ["generate", "js", "solve", "validate"]

js: str = files("easypow").joinpath("easypow.js").read_text(encoding="utf-8")
"""Source of the bundled JavaScript PoW solver module."""
