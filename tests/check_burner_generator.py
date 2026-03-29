#!/usr/bin/env python3

import re
import subprocess
import sys
from pathlib import Path


def extract_macro(content: str, name: str) -> str:
    match = re.search(rf"#define\s+{name}\s+0x([0-9A-Fa-f]+)u", content)
    if match is None:
        raise SystemExit(f"missing {name} in generated config")
    return match.group(1).upper()


def extract_enum_values(content: str) -> dict[str, str]:
    pairs = re.findall(r"^\s*([A-Za-z0-9_]+)\s*=\s*0x([0-9A-Fa-f]+)u,\s*$", content, re.MULTILINE)
    if not pairs:
        raise SystemExit("missing ErrorCode enum values in generated config")
    return {name: value.upper() for name, value in pairs}


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    script = repo_root / "tools" / "generate_config.py"
    out_a = repo_root / "tests" / "_generated_a.h"
    out_b = repo_root / "tests" / "_generated_b.h"

    try:
        subprocess.run([sys.executable, str(script), "config:generate", "--output", str(out_a)], check=True, cwd=repo_root)
        subprocess.run([sys.executable, str(script), "config:generate", "--output", str(out_b)], check=True, cwd=repo_root)

        content_a = out_a.read_text(encoding="utf-8")
        content_b = out_b.read_text(encoding="utf-8")

        xor_a = extract_macro(content_a, "BURNERNET_ERROR_XOR")
        xor_b = extract_macro(content_b, "BURNERNET_ERROR_XOR")
        enum_a = extract_enum_values(content_a)
        enum_b = extract_enum_values(content_b)

        if xor_a == xor_b:
            raise SystemExit("generated BURNERNET_ERROR_XOR values should differ across runs")
        if enum_a == enum_b:
            raise SystemExit("generated ErrorCode enum values should differ across runs")
        if len(enum_a) != len(set(enum_a.values())):
            raise SystemExit("generated ErrorCode enum values must be unique within a config")

        return 0
    finally:
        out_a.unlink(missing_ok=True)
        out_b.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
