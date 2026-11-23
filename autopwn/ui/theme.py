"""Brand palette and Rich theme."""
from __future__ import annotations

from rich.theme import Theme

BG = "#0B0D0C"            # terminal background
SURFACE = "#131715"      # panels / input well
SELECT = "#1B201D"       # hovered / selected row
GREEN = "#4ADE80"        # primary accent
WHITE = "#E6EAE7"        # primary text
GRAY = "#8A938D"         # secondary text
FAINT = "#3A423D"        # guides / tree lines
FAINT2 = "#2A312D"       # progress-bar "off"

BLUE = "#6CB6FF"
PURPLE = "#B49CFF"
ORANGE = "#FFA552"
RED = "#FF6B7A"

# Logo pixel colors (dark-adapted, from the design)
LOGO_GRAY = "#8A938D"
LOGO_GREEN = "#4ADE80"
LOGO_WHITE = "#E6EAE7"

THEME = Theme(
    {
        "brand": f"bold {GREEN}",
        "accent": GREEN,
        "text": WHITE,
        "muted": GRAY,
        "faint": FAINT,
        "label": GRAY,
        "rule": FAINT,
        "ok": GREEN,
        "warn": ORANGE,
        "err": RED,
        "key": WHITE,            # keybinding keys
        "blue": BLUE,
        "purple": PURPLE,
        "orange": ORANGE,
        "red": RED,
        "phase.done": GREEN,
        "phase.active": f"bold {GREEN}",
        "phase.pending": FAINT,
        "sev.critical": f"bold {RED}",
        "sev.high": f"bold {ORANGE}",
        "sev.medium": "bold #E0C64F",
        "sev.low": f"bold {BLUE}",
        "sev.info": GRAY,
        "role.user": f"bold {WHITE}",
        "role.agent": f"bold {GREEN}",
        "role.tool": BLUE,
        "role.system": GRAY,
    }
)

SEVERITY_STYLE = {
    "critical": "sev.critical",
    "high": "sev.high",
    "medium": "sev.medium",
    "low": "sev.low",
    "info": "sev.info",
}
