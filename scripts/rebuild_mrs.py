#!/usr/bin/env python3
"""Rebuild conflicted MRS artifacts from the merged text rule sources."""

import os
from pathlib import Path
import subprocess
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from gfwlist_parser import split_existing_rule_files  # noqa: E402


def has_content(path: Path, file_format: str) -> bool:
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if file_format == "yaml" and line == "payload:":
            continue
        return True
    return False


def source_candidates(base_name: str, rule_family: str):
    return (
        (Path("Clash/Providers") / f"{base_name}_{rule_family}.yaml", "yaml"),
        (Path("Clash/Providers/Ruleset") / f"{base_name}_{rule_family}.yaml", "yaml"),
        (Path("Clash/Ruleset") / f"{base_name}_{rule_family}.list", "text"),
    )


def parse_output_path(value: str):
    relative_path = Path(value)
    if (
        relative_path.is_absolute()
        or ".." in relative_path.parts
        or relative_path.parts[:2] != ("Clash", "mrs")
        or relative_path.suffix != ".mrs"
        or len(relative_path.parts) != 3
    ):
        raise ValueError(f"Not a Clash/mrs artifact path: {value}")

    stem = relative_path.stem
    if stem.endswith("_domain"):
        return relative_path, stem[: -len("_domain")], "domain", "domain"
    if stem.endswith("_ip"):
        return relative_path, stem[: -len("_ip")], "ip", "ipcidr"
    raise ValueError(f"MRS filename must end in _domain.mrs or _ip.mrs: {value}")


def rebuild(relative_path: Path, base_name: str, rule_family: str, rule_type: str):
    source = None
    source_format = None

    # Match update.yml: later Ruleset inputs overwrite same-named Provider outputs.
    for candidate, file_format in source_candidates(base_name, rule_family):
        candidate_path = REPOSITORY_ROOT / candidate
        if candidate_path.is_file() and has_content(candidate_path, file_format):
            source = candidate
            source_format = file_format

    if source is None:
        raise FileNotFoundError(
            f"No non-empty source rules found for {relative_path.as_posix()}"
        )

    output = relative_path.as_posix()
    command = [
        "./mihomo",
        "convert-ruleset",
        rule_type,
        source_format,
        source.as_posix(),
        output,
    ]
    print(f"Rebuilding {output} from {source.as_posix()}")
    subprocess.run(command, cwd=REPOSITORY_ROOT, check=True)

    output_path = REPOSITORY_ROOT / relative_path
    if not output_path.is_file() or output_path.stat().st_size == 0:
        raise RuntimeError(f"mihomo did not produce a non-empty file: {output}")


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "Usage: python scripts/rebuild_mrs.py "
            "Clash/mrs/<name>_domain.mrs ...",
            file=sys.stderr,
        )
        return 2

    try:
        outputs = [parse_output_path(value) for value in sys.argv[1:]]
        # Generate temporary domain/IP inputs from the final merged text sources.
        os.chdir(REPOSITORY_ROOT)
        split_existing_rule_files()
        for relative_path, base_name, rule_family, rule_type in outputs:
            rebuild(relative_path, base_name, rule_family, rule_type)
    except (FileNotFoundError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
