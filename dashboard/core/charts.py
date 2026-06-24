"""Plotly chart builders with consistent dark theming, severity color-coding,
and label wrapping so long feature/category names never clip the layout.
"""

from __future__ import annotations

from typing import Dict, Optional

import pandas as pd
import plotly.graph_objects as go

from core.theme import PALETTE, color_for, rgba

GRID_COLOR = PALETTE["border"]
TEXT_COLOR = PALETTE["text"]
MUTED_COLOR = PALETTE["text_muted"]

# Exact severity palette requested for the executive risk-breakdown chart -
# color is only ever used functionally to flag risk; baseline stays steel.
STACK_COLORS = {
    "Critical": "#E5484D",
    "High": "#E5484D",
    "Medium": "#F5D90A",
    "Low": "#374151",
}


def wrap_label(label: str, width: int = 14) -> str:
    """Break a long snake_case/space-separated label into multiple lines
    (Plotly tick labels support <br>) instead of letting it clip or overlap."""
    words = str(label).replace("_", " ").split()
    lines, current = [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return "<br>".join(lines) if lines else str(label)


def _finalize(fig: go.Figure, *, height: int, title: Optional[str], tickangle: int) -> go.Figure:
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT_COLOR, size=12),
        margin=dict(l=8, r=8, t=44 if title else 8, b=72),
        height=height,
        showlegend=False,
        title=dict(text=title or "", font=dict(size=14, color=TEXT_COLOR)),
        hoverlabel=dict(bgcolor=PALETTE["bg_elevated"], font_color=TEXT_COLOR),
    )
    fig.update_xaxes(tickangle=tickangle, gridcolor=GRID_COLOR, automargin=True, color=MUTED_COLOR)
    fig.update_yaxes(gridcolor=GRID_COLOR, zerolinecolor=GRID_COLOR, color=MUTED_COLOR, automargin=True)
    return fig


def severity_bar(
    series: pd.Series,
    *,
    title: Optional[str] = None,
    height: int = 300,
    wrap: bool = False,
    tickangle: int = -30,
) -> go.Figure:
    """Bar chart where each bar's color reflects the security level of its
    own category label (e.g. 'critical' -> crimson, 'low' -> emerald)."""
    categories = list(series.index)
    colors = [color_for(c) for c in categories]
    labels = [wrap_label(c) for c in categories] if wrap else [str(c) for c in categories]
    fig = go.Figure(
        go.Bar(
            x=labels,
            y=list(series.values),
            marker_color=colors,
            marker_line_width=0,
            hovertemplate="%{x}: %{y}<extra></extra>",
        )
    )
    return _finalize(fig, height=height, title=title, tickangle=tickangle)


def accent_bar(
    series: pd.Series,
    *,
    title: Optional[str] = None,
    height: int = 300,
    color: str = PALETTE["steel"],
    wrap: bool = True,
    tickangle: int = -30,
) -> go.Figure:
    """Single-accent-color bar chart for non-severity distributions
    (e.g. syscall type counts, language usage)."""
    labels = [wrap_label(c) for c in series.index] if wrap else [str(c) for c in series.index]
    fig = go.Figure(
        go.Bar(
            x=labels,
            y=list(series.values),
            marker_color=color,
            marker_line_width=0,
            hovertemplate="%{x}: %{y}<extra></extra>",
        )
    )
    return _finalize(fig, height=height, title=title, tickangle=tickangle)


def feature_importance_bar(
    scores: Dict[str, float],
    *,
    title: Optional[str] = None,
    height: int = 340,
    color: str = PALETTE["steel"],
) -> go.Figure:
    """Top-N feature-importance bar chart with wrapped, shortened labels so
    long snake_case feature names never crowd the x-axis."""
    items = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    labels = [wrap_label(name, width=16) for name, _ in items]
    values = [score for _, score in items]
    fig = go.Figure(
        go.Bar(
            x=labels,
            y=values,
            marker_color=color,
            marker_line_width=0,
            hovertemplate="%{x}: %{y:.4f}<extra></extra>",
        )
    )
    return _finalize(fig, height=height, title=title, tickangle=-20)


def trend_spline_area(
    series: pd.Series,
    *,
    title: Optional[str] = None,
    height: int = 320,
    color: str = PALETTE["critical"],
    wrap: bool = False,
) -> go.Figure:
    """Smooth splined line with a neon glow halo and a translucent area fill -
    used for the 'Vulnerability Ingestion Trend' across pipeline stages."""
    labels = [wrap_label(c) for c in series.index] if wrap else [str(c) for c in series.index]
    values = list(series.values)

    fig = go.Figure()
    # Glow halo: same line redrawn wider + fainter underneath the crisp line.
    for width, opacity in ((16, 0.05), (10, 0.09), (6, 0.14)):
        fig.add_trace(
            go.Scatter(
                x=labels, y=values, mode="lines",
                line=dict(color=color, width=width, shape="spline", smoothing=1.0),
                opacity=opacity, hoverinfo="skip", showlegend=False,
            )
        )
    # Crisp foreground line + markers + glowing area fill.
    fig.add_trace(
        go.Scatter(
            x=labels, y=values, mode="lines+markers",
            line=dict(color=color, width=2.5, shape="spline", smoothing=1.0),
            marker=dict(size=7, color=PALETTE["bg"], line=dict(color=color, width=2)),
            fill="tozeroy", fillcolor=rgba(color, 0.18),
            hovertemplate="<b>%{x}</b><br>%{y} findings<extra></extra>",
            showlegend=False,
        )
    )
    return _finalize(fig, height=height, title=title, tickangle=-20)


def stacked_risk_bar(
    df: pd.DataFrame,
    *,
    title: Optional[str] = None,
    height: int = 380,
) -> go.Figure:
    """Horizontal stacked bar of Critical/High/Medium/Low counts per stage,
    using the exact security color mapping for an executive risk breakdown."""
    fig = go.Figure()
    for column in ("Critical", "High", "Medium", "Low"):
        if column not in df.columns:
            continue
        fig.add_trace(
            go.Bar(
                y=[str(i) for i in df.index],
                x=df[column],
                name=column,
                orientation="h",
                marker_color=STACK_COLORS[column],
                marker_line_width=0,
                hovertemplate=f"<b>%{{y}}</b><br>{column}: %{{x}}<extra></extra>",
            )
        )
    fig.update_layout(barmode="stack")
    fig = _finalize(fig, height=height, title=title, tickangle=0)
    fig.update_layout(
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(color=TEXT_COLOR, size=11), bgcolor="rgba(0,0,0,0)"),
    )
    return fig


def style_severity_column(df: pd.DataFrame, column: str):
    """Return a pandas Styler that color-codes one column by security level,
    for use with st.dataframe(styler)."""

    def _style(value):
        c = color_for(value)
        return f"background-color:{c}26;color:{c};font-weight:700;border-radius:4px;"

    return df.style.map(_style, subset=[column])
