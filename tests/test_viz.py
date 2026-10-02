from datetime import date

from cybertrack import viz


def test_nice_scale_uses_clean_integer_steps():
    for raw in (1, 3, 5, 7, 12, 37, 99):
        vmax, ticks = viz.nice_scale(raw)
        assert vmax >= raw
        assert all(float(t).is_integer() for t in ticks), (raw, ticks)
        assert len(ticks) <= 6


def test_line_chart_labels_never_collide_at_the_end():
    pts = [{"label": f"d{i}", "value": i * 5} for i in range(14)]
    c = viz.line_chart(pts)
    shown = [i for i, p in enumerate(c["pts"]) if p["show_label"]]
    assert shown[-1] == 13
    gaps = [b - a for a, b in zip(shown, shown[1:])]
    assert min(gaps) >= 2


def test_line_chart_gaps_and_lone_points():
    pts = [{"label": "a", "value": 50}, {"label": "b", "value": None}, {"label": "c", "value": 60},
           {"label": "d", "value": 70}]
    c = viz.line_chart(pts)
    assert len(c["lines"]) == 1  # c-d connected, a is isolated
    assert c["pts"][0].get("lone") is True


def test_stacked_columns_segments_and_heatmap():
    rows = [{"label": "1", "critical": 1, "high": 2, "medium": 0, "low": 1}]
    c = viz.stacked_columns(rows, viz.URGENCY_ORDER, viz.URGENCY_COLORS)
    assert [s["key"] for s in c["cols"][0]["segs"]] == ["critical", "high", "low"]
    h = viz.heatmap({date(2026, 10, 1): 3}, date(2026, 10, 2), weeks=4)
    assert any(cell["count"] == 3 for cell in h["cells"])
    assert all(cell["date"] <= date(2026, 10, 2) for cell in h["cells"])
