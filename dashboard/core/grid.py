"""High-density, dark-themed AgGrid table helper used in place of raw
st.dataframe for event/finding/log views (Syscall Monitor, SAST findings,
SBOM exposures, etc.), matching the rest of the dashboard's glass/mono theme.
"""

from __future__ import annotations

import json
from typing import Optional

import pandas as pd
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, JsCode

from core.theme import MONO_STACK, PALETTE, color_for

ROW_HEIGHT = 34
HEADER_HEIGHT = 36

# AgGrid renders inside an isolated iframe, so the app's global CSS never
# reaches it - custom_css is the only way to pull the grid into the same
# pitch-black glass theme as the rest of the dashboard.
AGGRID_CUSTOM_CSS = {
    ".ag-theme-alpine-dark": {
        "--ag-background-color": "#000000",
        "--ag-header-background-color": PALETTE["bg_secondary"],
        "--ag-odd-row-background-color": PALETTE["bg_secondary"],
        "--ag-modal-overlay-background-color": "#000000",
        "--ag-header-foreground-color": PALETTE["text_muted"],
        "--ag-foreground-color": PALETTE["text"],
        "--ag-border-color": PALETTE["border"],
        "--ag-row-border-color": PALETTE["border"],
        "--ag-secondary-border-color": PALETTE["border"],
        "--ag-font-family": MONO_STACK,
        "--ag-font-size": "12.5px",
        "--ag-row-height": f"{ROW_HEIGHT}px",
        "--ag-header-height": f"{HEADER_HEIGHT}px",
        "--ag-cell-horizontal-padding": "12px",
        "--ag-range-selection-border-color": "rgba(255,255,255,0.12)",
    },
    ".ag-theme-alpine-dark .ag-root-wrapper": {
        "border": f"1px solid {PALETTE['border']} !important",
        "border-radius": "8px !important",
        "overflow": "hidden !important",
    },
    ".ag-theme-alpine-dark .ag-header": {
        "border-bottom": f"1px solid {PALETTE['border']} !important",
        "text-transform": "uppercase",
        "letter-spacing": "0.04em",
        "font-size": "10.5px !important",
        "font-weight": "700 !important",
    },
    ".ag-theme-alpine-dark .ag-row": {
        "border-bottom": f"1px solid {PALETTE['border']} !important",
    },
    ".ag-theme-alpine-dark .ag-cell": {
        "white-space": "nowrap",
        "text-overflow": "ellipsis",
        "overflow": "hidden",
        "display": "flex",
        "align-items": "center",
    },
}


def _severity_cell_style(df: pd.DataFrame, column: str) -> JsCode:
    """Map each distinct raw value in `column` to its risk color and bake
    that lookup into a small JS function (AgGrid cellStyle runs client-side
    inside the grid's iframe, so it can't call back into Python per-cell)."""
    mapping = {str(v).lower(): color_for(v) for v in df[column].dropna().unique()}
    mapping_json = json.dumps(mapping)
    return JsCode(
        f"""
        function(params) {{
            const colors = {mapping_json};
            const c = colors[String(params.value).toLowerCase()];
            if (!c) return {{}};
            return {{color: c, fontWeight: '700'}};
        }}
        """
    )


def render_grid(
    df: pd.DataFrame,
    *,
    severity_col: Optional[str] = None,
    height: int = 340,
    key: Optional[str] = None,
):
    """Compact alpine-dark AgGrid for tabular event/finding data."""
    if df.empty:
        return None

    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_default_column(resizable=True, sortable=True, filter=True)
    if severity_col and severity_col in df.columns:
        gb.configure_column(severity_col, cellStyle=_severity_cell_style(df, severity_col))
    gb.configure_grid_options(domLayout="normal", suppressMovableColumns=True)
    grid_options = gb.build()
    grid_options["rowHeight"] = ROW_HEIGHT
    grid_options["headerHeight"] = HEADER_HEIGHT

    fitted_height = min(height, HEADER_HEIGHT + ROW_HEIGHT * len(df) + 14)
    fitted_height = max(fitted_height, HEADER_HEIGHT + ROW_HEIGHT + 14)

    return AgGrid(
        df,
        gridOptions=grid_options,
        height=fitted_height,
        theme="alpine-dark",
        update_mode=GridUpdateMode.NO_UPDATE,
        allow_unsafe_jscode=True,
        custom_css=AGGRID_CUSTOM_CSS,
        fit_columns_on_grid_load=False,
        key=key,
    )
