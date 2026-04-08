#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generate an HTML performance report with tables, bar charts, and histograms."""

import json
import math
import sys
from pathlib import Path

RESULTS_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("perf-results/results.json")
OUTPUT_FILE = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("perf-results/report.html")

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


def _percentile(sorted_vals, p):
    """Compute the p-th percentile from a sorted list."""
    k = (len(sorted_vals) - 1) * (p / 100)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


def _median(vals):
    s = sorted(vals)
    return _percentile(s, 50)


def _p95(vals):
    s = sorted(vals)
    return _percentile(s, 95)


def _lookup(results, prefix, size_mb):
    for r in results:
        if r["test"].startswith(prefix) and r["size_mb"] == size_mb:
            return r
    return None


def _bar_chart_svg(chart_id, title, groups, sizes, width=700, bar_h=28, gap=6):
    """Render a grouped horizontal bar chart (median values) as SVG."""
    label_col_w = 120
    chart_w = width - label_col_w - 80
    n_groups = len(groups)
    block_h = n_groups * (bar_h + gap) + 20
    total_h = len(sizes) * block_h + 60

    max_val = max(
        (v for g in groups for v in g["values"].values()),
        default=1,
    )
    if max_val == 0:
        max_val = 1

    svg = [
        f'<svg id="{chart_id}" width="{width}" height="{total_h}" '
        f'xmlns="http://www.w3.org/2000/svg" style="font-family:sans-serif;margin:1rem 0">',
        f'<text x="{width // 2}" y="20" text-anchor="middle" font-size="14" '
        f'font-weight="600" fill="#232f3e">{title}</text>',
    ]
    lx = label_col_w
    for g in groups:
        svg.append(f'<rect x="{lx}" y="30" width="12" height="12" fill="{g["color"]}" rx="2"/>')
        svg.append(f'<text x="{lx+16}" y="41" font-size="11" fill="#333">{g["label"]}</text>')
        lx += len(g["label"]) * 7 + 30

    y = 58
    for size in sizes:
        svg.append(
            f'<text x="5" y="{y + (n_groups * (bar_h + gap)) // 2}" '
            f'font-size="13" font-weight="600" fill="#555">{size} MB</text>'
        )
        for i, g in enumerate(groups):
            val = g["values"].get(size, 0)
            bw = max(2, (val / max_val) * chart_w)
            by = y + i * (bar_h + gap)
            svg.append(
                f'<rect x="{label_col_w}" y="{by}" width="{bw:.1f}" '
                f'height="{bar_h}" fill="{g["color"]}" rx="3" opacity="0.85"/>'
            )
            svg.append(
                f'<text x="{label_col_w + bw + 4}" y="{by + bar_h * 0.7}" '
                f'font-size="11" fill="#333">{_fmt(val)}</text>'
            )
        y += block_h
    svg.append("</svg>")
    return "\n".join(svg)


def _histogram_svg(chart_id, title, series_list, width=700, height=220, n_bins=15):
    """Render overlaid histograms for multiple series as SVG.

    Args:
        chart_id: unique SVG id
        title: chart title
        series_list: list of {label, color, durations: [float]}
        width, height: SVG dimensions
        n_bins: number of histogram bins
    """
    # Compute global range across all series
    all_vals = [d for s in series_list for d in s["durations"]]
    if not all_vals:
        return ""
    lo = min(all_vals)
    hi = max(all_vals)
    if lo == hi:
        hi = lo + 0.001  # avoid zero-width range

    margin_l, margin_r, margin_t, margin_b = 60, 20, 50, 40
    plot_w = width - margin_l - margin_r
    plot_h = height - margin_t - margin_b
    bin_width = (hi - lo) / n_bins

    # Build histogram counts for each series
    histograms = []
    global_max_count = 0
    for s in series_list:
        counts = [0] * n_bins
        for d in s["durations"]:
            idx = min(int((d - lo) / bin_width), n_bins - 1)
            counts[idx] += 1
        global_max_count = max(global_max_count, max(counts))
        histograms.append(counts)
    if global_max_count == 0:
        global_max_count = 1

    svg = [
        f'<svg id="{chart_id}" width="{width}" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg" style="font-family:sans-serif;margin:0.5rem 0">',
        f'<text x="{width // 2}" y="18" text-anchor="middle" font-size="13" '
        f'font-weight="600" fill="#232f3e">{title}</text>',
    ]

    # Legend
    lx = margin_l
    for s in series_list:
        svg.append(f'<rect x="{lx}" y="26" width="10" height="10" fill="{s["color"]}" rx="2"/>')
        svg.append(f'<text x="{lx+14}" y="35" font-size="10" fill="#333">{s["label"]}</text>')
        lx += len(s["label"]) * 6 + 24

    # Axes
    ax_y = margin_t + plot_h
    svg.append(
        f'<line x1="{margin_l}" y1="{margin_t}" x2="{margin_l}" y2="{ax_y}" '
        f'stroke="#999" stroke-width="1"/>'
    )
    svg.append(
        f'<line x1="{margin_l}" y1="{ax_y}" x2="{margin_l + plot_w}" y2="{ax_y}" '
        f'stroke="#999" stroke-width="1"/>'
    )

    # X-axis labels (5 ticks)
    for i in range(6):
        val = lo + (hi - lo) * i / 5
        x = margin_l + plot_w * i / 5
        svg.append(
            f'<text x="{x:.0f}" y="{ax_y + 14}" text-anchor="middle" '
            f'font-size="9" fill="#666">{_fmt(val)}</text>'
        )

    # Y-axis labels
    for i in range(4):
        cnt = int(global_max_count * i / 3)
        y_pos = ax_y - plot_h * i / 3
        svg.append(
            f'<text x="{margin_l - 5}" y="{y_pos + 3}" text-anchor="end" '
            f'font-size="9" fill="#666">{cnt}</text>'
        )

    # Draw bars for each series (slightly offset for overlap visibility)
    bar_px = plot_w / n_bins
    n_series = len(series_list)
    sub_w = bar_px / n_series if n_series > 1 else bar_px * 0.8

    for si, (s, counts) in enumerate(zip(series_list, histograms)):
        for bi, cnt in enumerate(counts):
            if cnt == 0:
                continue
            bh = (cnt / global_max_count) * plot_h
            bx = margin_l + bi * bar_px + si * sub_w
            by = ax_y - bh
            svg.append(
                f'<rect x="{bx:.1f}" y="{by:.1f}" width="{sub_w:.1f}" '
                f'height="{bh:.1f}" fill="{s["color"]}" opacity="0.7" rx="1"/>'
            )

    svg.append("</svg>")
    return "\n".join(svg)


def _build_charts_and_histograms(results, sizes):
    """Build bar charts (median) and histograms for each category."""
    html_parts = []

    # --- Define chart groups ---
    chart_defs = [
        {
            "id": "put",
            "title": "PutObject: Plain S3 vs S3EC",
            "series": [
                ("Plain S3", "plain", "plain_s3_put"),
                ("S3EC AES_GCM", "aes_gcm", "s3ec_put_aes_gcm"),
                ("S3EC KC_GCM", "kc_gcm", "s3ec_put_kc_gcm"),
            ],
        },
        {
            "id": "get",
            "title": "GetObject: Plain S3 vs S3EC",
            "series": [
                ("Plain S3", "plain", "plain_s3_get"),
                ("S3EC AES_GCM", "aes_gcm", "s3ec_get_aes_gcm"),
                ("S3EC KC_GCM", "kc_gcm", "s3ec_get_kc_gcm"),
            ],
        },
        {
            "id": "rt",
            "title": "Roundtrip: S3EC vs Local Crypto + Plain S3",
            "series": [
                ("Local Crypto + Plain S3", "local", "local_crypto_roundtrip"),
                ("S3EC AES_GCM", "aes_gcm", "s3ec_roundtrip_aes_gcm"),
                ("S3EC KC_GCM", "kc_gcm", "s3ec_roundtrip_kc_gcm"),
            ],
        },
    ]

    for cdef in chart_defs:
        # Bar chart using median
        groups = []
        for label, color_key, prefix in cdef["series"]:
            vals = {}
            for s in sizes:
                r = _lookup(results, f"{prefix}_{s}mb", s)
                if r:
                    vals[s] = _median(r["durations_s"])
            groups.append({"label": label, "color": COLORS[color_key], "values": vals})
        html_parts.append(
            _bar_chart_svg(f"chart-{cdef['id']}", f"{cdef['title']} (Median)", groups, sizes)
        )

        # Histograms — one per payload size, stacked vertically
        for s in sizes:
            series_list = []
            for label, color_key, prefix in cdef["series"]:
                r = _lookup(results, f"{prefix}_{s}mb", s)
                if r:
                    series_list.append(
                        {
                            "label": label,
                            "color": COLORS[color_key],
                            "durations": r["durations_s"],
                        }
                    )
            if series_list:
                html_parts.append(
                    _histogram_svg(
                        f"hist-{cdef['id']}-{s}mb",
                        f"{cdef['title']} — {s} MB Distribution",
                        series_list,
                    )
                )

    return "\n".join(html_parts)


def _build_table(results):
    """Build the full results table with median and p95."""
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
            d = r["durations_s"]
            med = _median(d)
            p95 = _p95(d)
            durations_str = ", ".join(_fmt(v) for v in d)
            rows += f"""
            <tr>
                <td>{r['test']}</td>
                <td>{r['size_mb']} MB</td>
                <td>{r['rounds']}</td>
                <td>{_fmt(med)}</td>
                <td>{_fmt(r['mean_s'])}</td>
                <td>{_fmt(p95)}</td>
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
                <th>Median</th><th>Mean</th><th>p95</th>
                <th>Min</th><th>Max</th><th>All Durations</th>
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

    visuals_html = _build_charts_and_histograms(results, sizes)
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
    .visuals {{ margin-bottom: 2rem; }}
    .visuals svg {{ background: #fff; border-radius: 6px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 0.5rem;
                    display: block; margin-bottom: 0.5rem; }}
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

<div class="visuals">
{visuals_html}
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
