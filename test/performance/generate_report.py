#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generate an HTML performance report with tables and SVG bar charts."""

import json
import sys
from pathlib import Path

RESULTS_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("perf-results/results.json")
OUTPUT_FILE = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("perf-results/report.html")

# Chart palette
COLORS = {
    "plain": "#36a2eb",
    "aes_gcm": "#ff6384",
    "kc_gcm": "#ff9f40",
    "local": "#4bc0c0",
}


def _fmt(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    return f"{seconds:.2f} s"


def _lookup(results, prefix, size_mb):
    """Find a result entry matching prefix and size."""
    for r in results:
        if r["test"].startswith(prefix) and r["size_mb"] == size_mb:
            return r
    return None


def _bar_chart_svg(chart_id, title, groups, sizes, width=700, bar_h=28, gap=6):
    """Render a grouped horizontal bar chart as an SVG string.

    Args:
        chart_id: unique id for the SVG element
        title: chart title
        groups: list of dicts {label, color, values: {size_mb: mean_s}}
        sizes: list of size_mb values
        width: total SVG width
        bar_h: height of each bar
        gap: vertical gap between bars
    """
    label_col_w = 120  # left column for size labels
    chart_w = width - label_col_w - 80  # room for value labels on right
    n_groups = len(groups)
    block_h = n_groups * (bar_h + gap) + 20  # per size block
    total_h = len(sizes) * block_h + 60  # extra for title + legend

    # Find max value for scaling
    max_val = 0
    for g in groups:
        for v in g["values"].values():
            max_val = max(max_val, v)
    if max_val == 0:
        max_val = 1

    svg_parts = [
        f'<svg id="{chart_id}" width="{width}" height="{total_h}" '
        f'xmlns="http://www.w3.org/2000/svg" style="font-family: sans-serif; margin: 1rem 0;">',
        f'<text x="{width // 2}" y="20" text-anchor="middle" font-size="14" '
        f'font-weight="600" fill="#232f3e">{title}</text>',
    ]

    # Legend
    lx = label_col_w
    for g in groups:
        svg_parts.append(
            f'<rect x="{lx}" y="30" width="12" height="12" fill="{g["color"]}" rx="2"/>'
        )
        svg_parts.append(
            f'<text x="{lx + 16}" y="41" font-size="11" fill="#333">{g["label"]}</text>'
        )
        lx += len(g["label"]) * 7 + 30

    y_offset = 58
    for size in sizes:
        # Size label
        svg_parts.append(
            f'<text x="5" y="{y_offset + (n_groups * (bar_h + gap)) // 2}" '
            f'font-size="13" font-weight="600" fill="#555">{size} MB</text>'
        )
        for i, g in enumerate(groups):
            val = g["values"].get(size, 0)
            bar_w = max(2, (val / max_val) * chart_w)
            by = y_offset + i * (bar_h + gap)
            svg_parts.append(
                f'<rect x="{label_col_w}" y="{by}" width="{bar_w:.1f}" '
                f'height="{bar_h}" fill="{g["color"]}" rx="3" opacity="0.85"/>'
            )
            svg_parts.append(
                f'<text x="{label_col_w + bar_w + 4}" y="{by + bar_h * 0.7}" '
                f'font-size="11" fill="#333">{_fmt(val)}</text>'
            )
        y_offset += block_h

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


def _build_charts(results, sizes):
    """Build all SVG charts from the results data."""
    charts = []

    # --- Chart 1: Put — Plain S3 vs S3EC (AES_GCM) vs S3EC (KC_GCM) ---
    put_groups = [
        {"label": "Plain S3", "color": COLORS["plain"], "values": {}},
        {"label": "S3EC AES_GCM", "color": COLORS["aes_gcm"], "values": {}},
        {"label": "S3EC KC_GCM", "color": COLORS["kc_gcm"], "values": {}},
    ]
    for s in sizes:
        r = _lookup(results, f"plain_s3_put_{s}mb", s)
        if r:
            put_groups[0]["values"][s] = r["mean_s"]
        r = _lookup(results, f"s3ec_put_aes_gcm_{s}mb", s)
        if r:
            put_groups[1]["values"][s] = r["mean_s"]
        r = _lookup(results, f"s3ec_put_kc_gcm_{s}mb", s)
        if r:
            put_groups[2]["values"][s] = r["mean_s"]
    charts.append(_bar_chart_svg("chart-put", "PutObject: Plain S3 vs S3EC", put_groups, sizes))

    # --- Chart 2: Get — Plain S3 vs S3EC (AES_GCM) vs S3EC (KC_GCM) ---
    get_groups = [
        {"label": "Plain S3", "color": COLORS["plain"], "values": {}},
        {"label": "S3EC AES_GCM", "color": COLORS["aes_gcm"], "values": {}},
        {"label": "S3EC KC_GCM", "color": COLORS["kc_gcm"], "values": {}},
    ]
    for s in sizes:
        r = _lookup(results, f"plain_s3_get_{s}mb", s)
        if r:
            get_groups[0]["values"][s] = r["mean_s"]
        r = _lookup(results, f"s3ec_get_aes_gcm_{s}mb", s)
        if r:
            get_groups[1]["values"][s] = r["mean_s"]
        r = _lookup(results, f"s3ec_get_kc_gcm_{s}mb", s)
        if r:
            get_groups[2]["values"][s] = r["mean_s"]
    charts.append(_bar_chart_svg("chart-get", "GetObject: Plain S3 vs S3EC", get_groups, sizes))

    # --- Chart 3: Roundtrip — S3EC (AES_GCM) vs S3EC (KC_GCM) vs Local Crypto + Plain S3 ---
    rt_groups = [
        {"label": "Local Crypto + Plain S3", "color": COLORS["local"], "values": {}},
        {"label": "S3EC AES_GCM", "color": COLORS["aes_gcm"], "values": {}},
        {"label": "S3EC KC_GCM", "color": COLORS["kc_gcm"], "values": {}},
    ]
    for s in sizes:
        r = _lookup(results, f"local_crypto_roundtrip_{s}mb", s)
        if r:
            rt_groups[0]["values"][s] = r["mean_s"]
        r = _lookup(results, f"s3ec_roundtrip_aes_gcm_{s}mb", s)
        if r:
            rt_groups[1]["values"][s] = r["mean_s"]
        r = _lookup(results, f"s3ec_roundtrip_kc_gcm_{s}mb", s)
        if r:
            rt_groups[2]["values"][s] = r["mean_s"]
    charts.append(
        _bar_chart_svg("chart-rt", "Roundtrip: S3EC vs Local Crypto + Plain S3", rt_groups, sizes)
    )

    return "\n".join(charts)


def _build_table(results):
    """Build the full results table HTML."""
    # Group results by category
    groups: dict[str, list[dict]] = {}
    for r in results:
        name = r["test"]
        if "roundtrip" in name or "local_crypto" in name:
            cat = "Roundtrip: S3EC vs Local Crypto + Plain S3"
        elif "put" in name:
            cat = "PutObject: Plain S3 vs S3EC"
        elif "get" in name:
            cat = "GetObject: Plain S3 vs S3EC"
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
    return sections_html


def generate_html(data: dict) -> str:
    config = data["config"]
    results = data["results"]
    timestamp = data["timestamp"]
    sizes = config["object_sizes_mb"]

    charts_html = _build_charts(results, sizes)
    tables_html = _build_table(results)

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
    .charts {{ display: flex; flex-wrap: wrap; gap: 2rem; margin-bottom: 2rem; }}
    .charts svg {{ background: #fff; border-radius: 6px;
                   box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 0.5rem; }}
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
    Object sizes: {', '.join(str(s) + ' MB' for s in sizes)} &middot;
    Bucket: {config['bucket']} &middot; Region: {config['region']}
</div>

<h2>Charts</h2>
<div class="charts">
{charts_html}
</div>

{tables_html}
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
