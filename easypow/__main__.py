"""Command-line interface: python -m easypow <command>."""

import sys
from pathlib import Path

from easypow import generate, js, solve, validate

USAGE = """\
usage: python -m easypow <command> [args]

Commands (unambiguous prefixes accepted):
  generate [seconds]            Generate a challenge (default 1.0s of work)
  solve <challenge>             Solve a challenge
  validate <challenge> <sol.>   Validate a solution (exit 1 if invalid)
  js [filename]                 Dump the JS solver module (stdout or file)
"""

_COMMANDS = ("generate", "solve", "validate", "js")


def _match(command: str) -> str:
    """Match a command by unambiguous prefix."""
    if command in _COMMANDS:
        return command
    matches = [c for c in _COMMANDS if c.startswith(command)]
    if len(matches) == 1:
        return matches[0]
    msg = f"Unknown or ambiguous command: {command!r}"
    raise ValueError(msg)


def _cmd_generate(args: list[str]) -> None:
    if len(args) > 1:
        msg = "generate takes at most one argument: [seconds]"
        raise ValueError(msg)
    print(generate(seconds=float(args[0])) if args else generate())


def _cmd_solve(args: list[str]) -> None:
    if len(args) != 1:
        msg = "solve takes exactly one argument: <challenge>"
        raise ValueError(msg)
    print(solve(args[0]))


def _cmd_validate(args: list[str]) -> int:
    if len(args) != 2:
        msg = "validate takes exactly two arguments: <challenge> <solution>"
        raise ValueError(msg)
    try:
        validate(args[0], args[1])
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1
    return 0


def _cmd_js(args: list[str]) -> None:
    if len(args) > 1:
        msg = "js takes at most one argument: [filename]"
        raise ValueError(msg)
    if args:
        Path(args[0]).write_text(js, encoding="utf-8")
    else:
        print(js)


def main(argv: list[str] | None = None) -> int:
    """Run the easypow CLI; return exit code."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(USAGE, file=sys.stderr if not args else sys.stdout)
        return 0 if args else 2
    try:
        handler = {
            "generate": _cmd_generate,
            "solve": _cmd_solve,
            "validate": _cmd_validate,
            "js": _cmd_js,
        }[_match(args.pop(0))]
        result = handler(args)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    return result or 0


if __name__ == "__main__":
    sys.exit(main())
