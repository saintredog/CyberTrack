"""Chart geometry for server-rendered inline SVG.

Turns plain numbers into coordinates the Jinja macros in
templates/macros.html draw. No JavaScript chart library, so the portal
stays fully offline. Mark specs follow the dataviz method: columns at most
24px wide with a 4px rounded data-end and a square base, 2px lines, a 10%
area wash, solid hairline gridlines, and a 2px surface gap between stacked
segments.
"""
from __future__ import annotations

import math
from datetime import date, timedelta

# Urgency is a status meaning, so it uses the reserved status steps.
URGENCY_COLORS = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#0ca30c",
}
URGENCY_ORDER = ["critical", "high", "medium", "low"]

# Categorical slots (dark steps), fixed order, validated on the panel surface.
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500"]
TRACK_COLORS = {"cwe": SERIES[0], "cysa": SERIES[1], "pentest": SERIES[2], "wgu": SERIES[3]}

# Sequential blue, dark mode: near-zero recedes toward the surface.
HEAT_STEPS = ["#232a30", "#104281", "#1c5cab", "#2a78d6", "#5598e7", "#86b6ef"]


def nice_max(v: float) -> float:
    """Round an axis max up to a clean number."""
    if v <= 0:
        return 1
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def ticks(vmax: float, n: int = 4) -> list[float]:
    step = vmax / n
    return [round(step * i, 6) for i in range(n + 1)]


def nice_scale(raw_max: float, max_intervals: int = 5, integer: bool = True) -> tuple[float, list[float]]:
    """Clean axis: step is 1, 2 or 5 x 10^k, so count axes never show 1.2 or 3.8.

    integer=True (counts) never steps below 1; integer=False allows fractional steps.
    """
    if raw_max <= 0:
        return 1, [0, 1]
    for exp in range(0 if integer else -2, 8):
        for m in (1, 2, 5):
            step = m * 10 ** exp
            intervals = math.ceil(raw_max / step - 1e-9)
            if intervals <= max_intervals:
                vmax = intervals * step
                return vmax, [round(step * i, 6) for i in range(intervals + 1)]
    return raw_max, ticks(raw_max)


def _label_flags(n: int, every: int) -> list[bool]:
    """Show x labels counting back from the newest point so the last label never collides."""
    show = [False] * n
    for i in range(n - 1, -1, -every):
        show[i] = True
    return show


def column_path(x: float, y_top: float, w: float, base: float, r: float = 4) -> str:
    """Column with a rounded top (data-end) and square base."""
    h = base - y_top
    if h <= 0:
        return ""
    r = min(r, h, w / 2)
    return (
        f"M{x:.1f},{base:.1f} V{y_top + r:.1f} Q{x:.1f},{y_top:.1f} {x + r:.1f},{y_top:.1f} "
        f"H{x + w - r:.1f} Q{x + w:.1f},{y_top:.1f} {x + w:.1f},{y_top + r:.1f} V{base:.1f} Z"
    )


def stacked_columns(rows: list[dict], keys: list[str], colors: dict, width=640, height=180,
                    pad_l=34, pad_r=8, pad_t=10, pad_b=24, gap=2):
    """rows: [{"label": str, "tip": str, key: count, ...}] -> geometry for a stacked column chart."""
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    totals = [sum(r.get(k, 0) for k in keys) for r in rows]
    vmax, tick_vals = nice_scale(max(totals or [0]))
    band = plot_w / max(1, len(rows))
    bar_w = min(24, band * 0.6)
    base = pad_t + plot_h
    cols = []
    for i, r in enumerate(rows):
        x = pad_l + band * i + (band - bar_w) / 2
        y = base
        segs = []
        present = [k for k in keys if r.get(k, 0) > 0]
        for j, k in enumerate(present):
            v = r[k]
            h = v / vmax * plot_h
            top_seg = j == len(present) - 1
            y_top = y - h
            if top_seg:
                path = column_path(x, y_top, bar_w, y)
            else:
                # Square segment; leave a 2px surface gap above it.
                gh = max(0.5, h - gap)
                path = f"M{x:.1f},{y:.1f} V{y - gh:.1f} H{x + bar_w:.1f} V{y:.1f} Z"
            segs.append({"path": path, "color": colors[k], "key": k, "value": v})
            y = y_top
        cols.append({
            "x": x, "w": bar_w, "cx": x + bar_w / 2, "label": r["label"], "tip": r.get("tip", ""),
            "total": totals[i], "segs": segs, "band_x": pad_l + band * i, "band_w": band,
        })
    grid = [{"y": base - t / vmax * plot_h, "label": _fmt(t)} for t in tick_vals]
    return {"w": width, "h": height, "cols": cols, "grid": grid, "base": base,
            "pad_l": pad_l, "plot_w": plot_w, "pad_t": pad_t, "plot_h": plot_h}


def line_chart(points: list[dict], width=640, height=200, vmax: float | None = 100.0, pad_l=38, pad_r=14,
               pad_t=14, pad_b=24, suffix="%", reference: float | None = None):
    """points: [{"label": str, "value": float|None}] -> geometry for a 1-series line with area wash.

    vmax=100 gives a 0/25/50/75/100 percent axis; vmax=None fits a clean axis to the data.
    A reference line gets its label in the right margin so it never sits on the data.
    """
    if vmax == 100.0:
        tick_vals = [0, 25, 50, 75, 100]
    else:
        raw = max([p["value"] for p in points if p["value"] is not None] or [1])
        vmax, tick_vals = nice_scale(raw, max_intervals=4, integer=False)
    if reference is not None:
        pad_r = max(pad_r, 52)
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    base = pad_t + plot_h
    n = len(points)
    step = plot_w / max(1, n - 1) if n > 1 else 0
    pts = []
    for i, p in enumerate(points):
        x = pad_l + (step * i if n > 1 else plot_w / 2)
        if p["value"] is None:
            pts.append({"x": x, "y": None, **p})
        else:
            y = base - min(p["value"], vmax) / vmax * plot_h
            pts.append({"x": x, "y": y, **p})
    # Break the line at gaps (days with no data).
    segments, cur = [], []
    for p in pts:
        if p["y"] is None:
            if cur:
                segments.append(cur)
            cur = []
        else:
            cur.append(p)
    if cur:
        segments.append(cur)
    lines, areas = [], []
    for seg in segments:
        if len(seg) == 1:
            seg[0]["lone"] = True  # no line to draw; the macro gives it a dot
            continue
        d = "M" + " L".join(f"{p['x']:.1f},{p['y']:.1f}" for p in seg)
        lines.append(d)
        if len(seg) > 1:
            areas.append(d + f" L{seg[-1]['x']:.1f},{base:.1f} L{seg[0]['x']:.1f},{base:.1f} Z")
    grid = [{"y": base - t / vmax * plot_h, "label": f"{_fmt(t)}{suffix}"} for t in tick_vals]
    hit_w = step if n > 1 else plot_w
    ref = None
    if reference is not None:
        ref = {"y": base - reference / vmax * plot_h, "label": "target", "x": pad_l + plot_w + 6}
    last = next((p for p in reversed(pts) if p["y"] is not None), None)
    for p, show in zip(pts, _label_flags(n, max(1, math.ceil(n / 7)))):
        p["show_label"] = show
    return {"w": width, "h": height, "pts": pts, "lines": lines, "areas": areas, "grid": grid,
            "base": base, "pad_l": pad_l, "plot_w": plot_w, "pad_t": pad_t, "hit_w": hit_w,
            "ref": ref, "last": last, "suffix": suffix}


def sparkline(values: list[float | None], width=110, height=30, pad=3):
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return None
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1
    n = len(values)
    step = (width - 2 * pad) / (n - 1)
    coords = []
    for i, v in enumerate(values):
        if v is None:
            continue
        x = pad + step * i
        y = height - pad - (v - lo) / span * (height - 2 * pad)
        coords.append((x, y))
    d = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    return {"w": width, "h": height, "d": d, "end": coords[-1]}


def ring(done: int, total: int, r: int = 30, stroke: int = 7):
    c = 2 * math.pi * r
    pct = done / total if total else 0
    return {"r": r, "stroke": stroke, "size": 2 * (r + stroke), "c": c,
            "offset": c * (1 - pct), "pct": round(pct * 100)}


def heatmap(counts: dict[date, int], end: date, weeks: int = 12, cell: int = 13, gap: int = 3):
    """GitHub/Splunk punchcard-style calendar: columns are weeks, rows are weekdays (Mon-Sun)."""
    end_week_start = end - timedelta(days=end.weekday())
    start = end_week_start - timedelta(weeks=weeks - 1)
    vmax = max([v for d, v in counts.items() if start <= d <= end] or [0])
    cells = []
    for w in range(weeks):
        for dow in range(7):
            d = start + timedelta(weeks=w, days=dow)
            if d > end:
                continue
            v = counts.get(d, 0)
            level = 0 if v == 0 else min(5, 1 + int((v / vmax) * 4.999)) if vmax else 0
            cells.append({"x": w * (cell + gap), "y": dow * (cell + gap), "date": d,
                          "count": v, "color": HEAT_STEPS[level]})
    months = []
    seen = set()
    for w in range(weeks):
        d = start + timedelta(weeks=w)
        if d.month not in seen:
            seen.add(d.month)
            months.append({"x": w * (cell + gap), "label": d.strftime("%b")})
    return {"cells": cells, "w": weeks * (cell + gap), "h": 7 * (cell + gap), "cell": cell,
            "months": months, "steps": HEAT_STEPS, "vmax": vmax}


def _fmt(v: float) -> str:
    return f"{int(v)}" if float(v).is_integer() else f"{v:.1f}"
