#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generate an HTML performance report from the JSON results file."""

import json
import sys
from pathlib import Path

RESULTS_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("perf-results/results.json")
OUTPUT_FILE = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("perf-results/report.html")


def _fmt(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    return f"{seconds:.2f} s"


def generate_html(data: dict) -> str:
    config = data["config"]
    results = data["results"]
    timestamp = data["timestamp"]

    # Group results by category
    groups: dict[str, list[dict]] = {}
    for r in results:
        name = r["test"]
        if "roundtrip" in name or "local_crypto" in name:
            cat = "Roundtrip: S3EC vs Local Crypto + Plain S3"
        elif "put" in name and "plain" in name:
            cat = "Put: S3EC vs Plain S3"
        elif "get" in name and "plain" in name:
            cat = "Get: S3EC vs Plain S3"
        elif "put" in name:
            cat = "Put by Algorithm Suite"
        elif "get" in name:
            cat = "Get by Algorithm Suite"
        else:
            cat = "Other"
        groups.setdefault(cat, []).append(r)

    sections_html = ""
    for cat, items in groups.items():
        rows = ""
        for r in sorted(items, key=lambda x: (x["size_mb"], x["test"])):
            durations_str = ", ".join(_fmt(d) for d in r["durations_s"])
            rows += f"""
            <tr>
                <td>{r['test']}</td>
                <td>{r['size_mb']} MB</td>
                <td>{r['rounds']}</td>
                <td>{_fmt(r['mean_s'])}</td>
                <td>{_fmt(r['min_s'])}</td>
                <td>{_fmt(r['max_s'])}</td>
                <td class="durations">{durations_str}</td>
            </tr>"""

        sections_html += f"""
    <h2>{cat}</h2>
    <table>
        <thead>
            <tr>
                <th>Test</th><th>Size</th><th>Rounds</th>
                <th>Mean</th><th>Min</th><th>Max</th><th>All Durations</th>
            </tr>
        </thead>
        <tbody>{rows}
        </tbody>
    </table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>S3EC Performance Report</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           margin: 2rem; color: #1a1a1a; background: #fafafa; }}
    h1 {{ color: #232f3e; border-bottom: 3px solid #ff9900; padding-bottom: 0.5rem; }}
    h2 {{ color: #232f3e; margin-top: 2rem; }}
    .meta {{ color: #555; font-size: 0.9rem; margin-bottom: 1.5rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem;
             background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    th {{ background: #232f3e; color: #fff; padding: 0.6rem 0.8rem;
          text-align: left; font-weight: 600; }}
    td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid #e8e8e8; }}
    tr:hover {{ background: #f0f4ff; }}
    .durations {{ font-size: 0.8rem; color: #666; max-width: 300px; word-break: break-all; }}
</style>
</head>
<body>
<h1>S3 Encryption Client &mdash; Performance Report</h1>
<div class="meta">
    Generated: {timestamp}<br>
    Rounds per test: {config['num_rounds']} &middot;
    Object sizes: {', '.join(str(s) + ' MB' for s in config['object_sizes_mb'])} &middot;
    Bucket: {config['bucket']} &middot; Region: {config['region']}
</div>
{sections_html}
</body>
</html>"""


def main():
    if not RESULTS_FILE.exists():
        print(f"Results file not found: {RESULTS_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(RESULTS_FILE) as f:
        data = json.load(f)

    html = generate_html(data)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(html)
    print(f"Report written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
