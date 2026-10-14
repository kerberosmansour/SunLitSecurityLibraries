#!/usr/bin/env python3
"""Delegate Kani's Cargo calls to its verified SDK with locked resolution."""
import hashlib
import json
import os
from pathlib import Path
import sys


def locked_arguments(arguments):
    arguments = list(arguments)
    boundary = arguments.index("--") if "--" in arguments else len(arguments)
    index = 1 if arguments and arguments[0].startswith("+") else 0
    while index < boundary:
        value = arguments[index]
        if value in {"--config", "--color", "-Z", "-C"}:
            if index + 1 >= boundary:
                raise ValueError("Cargo global option is missing its value")
            index += 2
        elif value.startswith("-"):
            index += 1
        else:
            break
    if index < boundary and arguments[index] in {"metadata", "build", "check", "test", "rustc", "run", "doc", "package"}:
        if "--locked" not in arguments[:boundary] and "--frozen" not in arguments[:boundary]:
            arguments.insert(index + 1, "--locked")
    return arguments



if __name__ == "__main__":
    record = json.loads(Path(__file__).with_name("cargo.source.json").read_text(encoding="utf-8"))
    executable = Path(record["path"])
    if hashlib.sha256(executable.read_bytes()).hexdigest() != record["sha256"]:
        raise SystemExit("Kani SDK Cargo differs from the verified setup")
    # Known SDK executable, separate argv, no shell. Do not alter the SDK itself.
    os.execv(str(executable), [str(executable), *locked_arguments(sys.argv[1:])])
