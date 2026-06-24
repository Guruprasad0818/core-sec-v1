"""Shared visual language for the CBAD dashboard: palette, CSS injection,
severity classification, and HTML component helpers (badges, KPI blocks,
icons, section headers) used to build a premium security-SaaS presentation
layer on top of Streamlit's primitives.
"""

from __future__ import annotations

from typing import Any, Optional

import streamlit as st

MONO_STACK = "SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace"
SANS_STACK = '-apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif'

PALETTE = {
    "bg": "#000000",
    "bg_secondary": "#0A0A0A",
    "bg_elevated": "#111111",
    "card_bg": "#0A0A0A",
    "border": "rgba(255,255,255,0.05)",
    "border_hover": "rgba(255,255,255,0.12)",
    "text": "#FAFAFA",
    "text_muted": "#888888",
    "text_faint": "#666666",
    # Functional risk colors only - everything else stays grayscale.
    "critical": "#E5484D",
    "high": "#E5484D",
    "medium": "#F5D90A",
    "low": "#374151",
    "neutral": "#1F2937",
    "steel": "#374151",
    "slate": "#1F2937",
}

LEVEL_RANK = {"neutral": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Normalizes the many raw vocabularies used across the 9 stages (severities,
# trust categories, policy actions, Falco classifications, etc.) onto one
# critical/high/medium/low/neutral scale so every chart and badge in the app
# uses the same color for "this needs attention" vs "this is fine".
_VALUE_TO_LEVEL = {
    "critical": "critical", "p0": "critical", "blocked": "critical", "block": "critical",
    "quarantine_and_terminate": "critical", "lockdown": "critical", "fail": "critical", "false": "critical",
    "high": "high", "p1": "high", "quarantine": "high", "quarantined": "high",
    "elevated_alert": "high", "elevated": "high", "risk": "high", "denied": "high",
    "medium": "medium", "moderate": "medium", "p2": "medium", "review": "medium", "caution": "medium",
    "low": "low", "p3": "low", "allow": "low", "allowed": "low", "trusted": "low",
    "log": "low", "pass": "low", "true": "low", "valid": "low", "ok": "low", "operational": "low",
    "skip": "low", "mitigate": "high",
}


def level_for(value: Any) -> str:
    """Classify any raw stage value onto critical/high/medium/low/neutral."""
    if value is None:
        return "neutral"
    if isinstance(value, bool):
        return "low" if value else "critical"
    return _VALUE_TO_LEVEL.get(str(value).strip().lower(), "neutral")


def color_for(value: Any) -> str:
    return PALETTE[level_for(value)]


def deepest_level(values) -> str:
    """Given a list of raw values, return the single highest-risk level."""
    levels = [level_for(v) for v in values if v is not None]
    if not levels:
        return "neutral"
    return max(levels, key=lambda lvl: LEVEL_RANK[lvl])


def rgba(hex_color: str, alpha: float) -> str:
    """Convert '#E5484D' -> 'rgba(229,72,77,0.30)' for glow/border effects."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def _risk_style_vars(level: str) -> str:
    """Inline CSS custom properties for a card: risk levels get a visible
    accent hairline + glow; low/neutral blend into the ambient border so
    color is only ever used to draw the eye to something that needs it."""
    c = PALETTE.get(level, PALETTE["neutral"])
    if level in ("critical", "high", "medium"):
        accent_top = rgba(c, 0.7)
        glow = rgba(c, 0.16)
        chip_bg = rgba(c, 0.12)
    else:
        accent_top = PALETTE["border"]
        glow = "rgba(255,255,255,0.05)"
        chip_bg = "rgba(255,255,255,0.04)"
    return f"--accent:{c};--accent-top:{accent_top};--accent-glow:{glow};--chip-bg:{chip_bg};"


# ---------------------------------------------------------------------------
# Iconography - small inline SVGs (no external icon font / emoji dependency)
# ---------------------------------------------------------------------------

_ICON_PATHS = {
    "shield": '<path d="M12 2 4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3Z"/>',
    "skull": (
        '<path d="M12 3c-4.4 0-8 3.4-8 7.6 0 2.6 1.4 4.9 3.5 6.3V19a1 1 0 0 0 1 1h1v1.5a.5.5 0 0 0 .5.5h2a.5.5 0 0 0 .5-.5V20h1v.5a.5.5 0 0 0 .5.5h2a.5.5 0 0 0 .5-.5V19a1 1 0 0 0 1-1v-2.1c2.1-1.4 3.5-3.7 3.5-6.3C20 6.4 16.4 3 12 3Z"/>'
        '<circle cx="9" cy="11" r="1.3" fill="currentColor" stroke="none"/>'
        '<circle cx="15" cy="11" r="1.3" fill="currentColor" stroke="none"/>'
    ),
    "alert": '<path d="M12 2 1 21h22L12 2Z"/><path d="M12 9v5"/><path d="M12 17h.01"/>',
    "check": '<circle cx="12" cy="12" r="9"/><path d="m8 12.5 2.8 2.8L16 9.8"/>',
    "activity": '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
    "lock": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "pulse": '<path d="M3 12h3l2.5 6L13 4l2 8h6"/>',
    "layers": '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5"/>',
}

_LEVEL_ICON = {"low": "check", "medium": "shield", "high": "alert", "critical": "skull", "neutral": "activity"}


def icon_for_level(level: str) -> str:
    return _LEVEL_ICON.get(level, "activity")


def icon(name: str, color: str, size: int = 18) -> str:
    path = _ICON_PATHS.get(name, _ICON_PATHS["activity"])
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 24 24" '
        f'fill="none" stroke="{color}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">{path}</svg>'
    )


# ---------------------------------------------------------------------------
# HTML component helpers
# ---------------------------------------------------------------------------

def badge(text: str, *, value: Any = None, level: Optional[str] = None) -> str:
    """Small pill-shaped HTML badge, color-coded by security level."""
    lvl = level or level_for(value if value is not None else text)
    c = PALETTE.get(lvl, PALETTE["neutral"])
    if lvl in ("critical", "high", "medium"):
        text_color, bg, border = c, rgba(c, 0.12), rgba(c, 0.4)
    else:
        text_color, bg, border = PALETTE["text_muted"], "rgba(255,255,255,0.03)", PALETTE["border"]
    return (
        f'<span style="display:inline-block;padding:0.2rem 0.65rem;border-radius:999px;'
        f'font-size:0.72rem;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;'
        f'background:{bg};color:{text_color};border:1px solid {border};white-space:nowrap;">{text}</span>'
    )


def kpi_block(label: str, value: str, *, level: str = "neutral", icon_name: Optional[str] = None, sublabel: Optional[str] = None) -> str:
    """Premium glass-card KPI block: icon chip + status badge + mono value + label."""
    c = PALETTE.get(level, PALETTE["neutral"])
    ic = icon(icon_name or icon_for_level(level), c if level in ("critical", "high", "medium") else PALETTE["text_muted"], size=18)
    sub_html = f'<div class="cbad-kpi-sub">{sublabel}</div>' if sublabel else ""
    return (
        f'<div class="cbad-card cbad-kpi" style="{_risk_style_vars(level)}">'
        f'<div class="cbad-kpi-row">'
        f'<span class="cbad-kpi-icon">{ic}</span>'
        f"{badge(level.upper(), level=level)}"
        f"</div>"
        f'<div class="cbad-kpi-value">{value}</div>'
        f'<div class="cbad-kpi-label">{label}</div>'
        f"{sub_html}"
        f"</div>"
    )


def stage_health_card(stage_num: int, name: str, status_label: str, sub_metric: str, level: str) -> str:
    """One cell of the stage-health visual matrix."""
    c = PALETTE.get(level, PALETTE["neutral"])
    sub_color = c if level in ("critical", "high", "medium") else PALETTE["text_muted"]
    return (
        f'<div class="cbad-card cbad-stage-card" style="{_risk_style_vars(level)}">'
        f'<div class="cbad-stage-top">'
        f'<span class="cbad-stage-num">STAGE {stage_num}</span>'
        f"{badge(status_label, level=level)}"
        f"</div>"
        f'<div class="cbad-stage-name">{name}</div>'
        f'<div class="cbad-stage-sub" style="color:{sub_color};">{sub_metric}</div>'
        f"</div>"
    )


def pulse_dot(level: str = "low") -> str:
    c = PALETTE.get(level, PALETTE["neutral"]) if level in ("critical", "high", "medium") else "#3FB950"
    return f'<span class="cbad-pulse-dot" style="--dot-color:{c};"></span>'


def section_header(title: str, subtitle: Optional[str] = None) -> None:
    sub_html = f'<div class="cbad-section-sub">{subtitle}</div>' if subtitle else ""
    st.markdown(
        f'<div class="cbad-section-header"><h3>{title}</h3>{sub_html}</div>',
        unsafe_allow_html=True,
    )


def divider() -> None:
    st.markdown('<div class="cbad-divider"></div>', unsafe_allow_html=True)


def inject_theme() -> None:
    p = PALETTE
    st.markdown(
        f"""
        <style>
        :root {{
            --font-mono: {MONO_STACK};
            --font-sans: {SANS_STACK};
        }}
        html, body, .stApp, [class*="css"] {{
            font-family: var(--font-sans);
        }}
        .stApp {{
            background-color: {p['bg']};
        }}
        header[data-testid="stHeader"] {{
            background: rgba(0,0,0,0);
        }}
        #MainMenu {{ visibility: hidden; }}
        footer {{ visibility: hidden; }}
        div[data-testid="stToolbar"] {{ visibility: hidden; }}
        div[data-testid="stDecoration"] {{ display: none; }}
        .block-container {{
            padding-top: 1.1rem;
            padding-bottom: 2.5rem;
            max-width: 1480px;
        }}
        div[data-testid="stVerticalBlock"] {{
            gap: 0.6rem;
        }}
        section[data-testid="stSidebar"] {{
            background-color: {p['bg_secondary']};
            border-right: 1px solid {p['border']};
        }}
        section[data-testid="stSidebar"] .block-container {{
            padding-top: 1.1rem;
        }}
        h1, h2, h3, h4 {{
            color: {p['text']} !important;
            font-weight: 700 !important;
            letter-spacing: -0.01em;
        }}
        p, span, label, .stMarkdown {{
            color: {p['text']};
        }}
        [data-testid="stCaptionContainer"], .stCaption, small {{
            color: {p['text_muted']} !important;
        }}
        code, pre, kbd {{
            font-family: var(--font-mono) !important;
        }}

        /* ---------------- Hero header ---------------- */
        .cbad-hero {{
            margin-bottom: 0.3rem;
        }}
        .cbad-hero-title {{
            font-size: 1.85rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: {p['text']};
        }}
        .cbad-hero-sub {{
            color: {p['text_faint']};
            font-size: 0.88rem;
            margin-top: 0.15rem;
        }}

        /* ---------------- Glass card primitive ---------------- */
        .cbad-card {{
            background: {p['card_bg']};
            border: 1px solid {p['border']};
            border-top: 2px solid var(--accent-top, {p['border']});
            border-radius: 8px;
            padding: 1rem 1.15rem;
            transition: border-color 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
            height: 100%;
        }}
        .cbad-card:hover {{
            border-color: {p['border_hover']};
            box-shadow: 0 10px 24px -14px var(--accent-glow, rgba(255,255,255,0.05));
            transform: translateY(-1px);
        }}

        /* ---------------- KPI blocks ---------------- */
        .cbad-kpi-row {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.6rem;
        }}
        .cbad-kpi-icon {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 30px;
            height: 30px;
            border-radius: 7px;
            background: var(--chip-bg, rgba(255,255,255,0.04));
        }}
        .cbad-kpi-value {{
            font-family: var(--font-mono);
            font-size: 1.75rem;
            font-weight: 600;
            color: {p['text']};
            line-height: 1.1;
        }}
        .cbad-kpi-label {{
            color: {p['text_muted']};
            font-size: 0.74rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-top: 0.3rem;
        }}
        .cbad-kpi-sub {{
            color: {p['text_faint']};
            font-size: 0.76rem;
            margin-top: 0.3rem;
        }}

        /* ---------------- Stage health matrix ---------------- */
        .cbad-stage-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 0.6rem;
        }}
        .cbad-stage-card {{
            padding: 0.8rem 0.95rem;
        }}
        .cbad-stage-top {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.5rem;
        }}
        .cbad-stage-num {{
            font-family: var(--font-mono);
            font-size: 0.68rem;
            font-weight: 700;
            color: {p['text_faint']};
            letter-spacing: 0.05em;
        }}
        .cbad-stage-name {{
            font-size: 0.85rem;
            font-weight: 600;
            color: {p['text']};
            margin-bottom: 0.25rem;
            min-height: 2.2em;
        }}
        .cbad-stage-sub {{
            font-family: var(--font-mono);
            font-size: 0.74rem;
            font-weight: 600;
        }}

        /* ---------------- KPI grid (secondary metrics) ---------------- */
        .cbad-metric-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(165px, 1fr));
            gap: 0.6rem;
        }}

        /* ---------------- Section headers / dividers ---------------- */
        .cbad-section-header {{
            margin: 0.3rem 0 0.9rem 0;
            padding-bottom: 0.45rem;
            border-bottom: 1px solid {p['border']};
        }}
        .cbad-section-header h3 {{
            margin: 0;
            font-size: 1rem;
        }}
        .cbad-section-sub {{
            color: {p['text_faint']};
            font-size: 0.8rem;
            margin-top: 0.15rem;
        }}
        .cbad-divider {{
            height: 1px;
            margin: 1.5rem 0;
            background: {p['border']};
        }}

        /* ---------------- Misc components ---------------- */
        .cbad-panel-label {{
            color: {p['text_faint']};
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 0.5rem;
        }}
        .cbad-pulse-dot {{
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--dot-color, #3FB950);
            display: inline-block;
            margin-right: 6px;
        }}

        /* ---------------- Native widget polish ---------------- */
        div[data-testid="stMetric"] {{
            background: {p['card_bg']};
            border: 1px solid {p['border']};
            border-radius: 8px;
            padding: 1rem 1.15rem;
        }}
        div[data-testid="stMetricLabel"] {{
            color: {p['text_muted']} !important;
            font-size: 0.74rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}
        div[data-testid="stMetricValue"] {{
            color: {p['text']} !important;
            font-weight: 600;
            font-family: var(--font-mono);
        }}
        details[data-testid="stExpander"], div[data-testid="stExpander"] {{
            background-color: {p['card_bg']};
            border: 1px solid {p['border']};
            border-radius: 8px;
        }}
        div[data-testid="stDataFrame"] {{
            border: 1px solid {p['border']};
            border-radius: 8px;
            overflow: hidden;
        }}
        button[data-testid="stTab"] {{
            color: {p['text_muted']};
        }}

        /* Generic buttons */
        .stButton > button {{
            border-radius: 6px;
            border: 1px solid {p['border']};
            font-weight: 600;
            transition: all 0.2s ease;
        }}
        /* Monochrome sidebar action button (e.g. "Refresh all stage data") */
        section[data-testid="stSidebar"] .stButton > button {{
            background: #1A1A1A;
            color: #FFFFFF;
            border: 1px solid {p['border']};
            font-weight: 600;
            letter-spacing: 0.01em;
            padding: 0.6rem 0;
        }}
        section[data-testid="stSidebar"] .stButton > button:hover {{
            border-color: rgba(255,255,255,0.35);
            color: #FFFFFF;
            background: #1A1A1A;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )