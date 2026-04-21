from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def write_multiline(handle: Any, name: str, value: str) -> None:
    delimiter = f"__FORTIFY_{name.upper().replace('-', '_')}__"
    handle.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: write_action_outputs.py <results_json_path> <github_output_path>", file=sys.stderr)
        return 1

    results_path = Path(sys.argv[1]).resolve()
    github_output_path = sys.argv[2].strip()

    if not results_path.exists():
        raise FileNotFoundError(f"Results file was not created: {results_path}")

    payload = json.loads(results_path.read_text(encoding="utf-8"))
    metrics_summary = json.dumps(payload.get("metrics_summary", {}), separators=(",", ":"))
    results_summary = json.dumps(payload.get("results_summary", {}), separators=(",", ":"))
    results_count = str(payload.get("results_count", 0))
    metrics_published_to = str(payload.get("metrics_published_to") or "")

    if not github_output_path:
        return 0

    with open(github_output_path, "a", encoding="utf-8") as handle:
        handle.write(f"results-file={results_path}\n")
        handle.write(f"results-count={results_count}\n")
        handle.write(f"metrics-published-to={metrics_published_to}\n")
        write_multiline(handle, "metrics-summary", metrics_summary)
        write_multiline(handle, "results-summary", results_summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
