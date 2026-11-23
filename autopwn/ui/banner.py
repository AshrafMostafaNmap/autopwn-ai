"""The pixel-exact logo rendered with half-block characters."""
from __future__ import annotations

import re

from rich.align import Align
from rich.console import Group, RenderableType
from rich.text import Text

from .. import __version__
from .theme import GRAY, GREEN, LOGO_GRAY, LOGO_GREEN, LOGO_WHITE, WHITE

# Path data copied from the official logo SVG (dark-adapted fills).
_LOGO_PATHS = [
    (LOGO_GRAY, "M3 3h2v1h-2zM16 3h2v1h-2zM3 4h1v11h-1zM17 4h1v11h-1zM3 15h2v1h-2zM16 15h2v1h-2z"),
    (LOGO_GREEN, "M7 5h1v1h-1zM13 5h1v1h-1zM8 6h1v1h-1zM12 6h1v1h-1zM9 7h3v1h-3zM6 8h1v1h-1zM8 8h5v1h-5zM14 8h1v1h-1zM7 9h3v1h-3zM11 9h3v1h-3zM6 10h4v1h-4zM11 10h4v1h-4zM7 11h3v1h-3zM11 11h3v1h-3zM6 12h1v1h-1zM8 12h2v1h-2zM11 12h2v1h-2zM14 12h1v1h-1zM8 13h5v1h-5z"),
    (LOGO_GRAY, "M35 5h1v1h-1zM35 6h1v1h-1zM23 7h3v1h-3zM28 7h1v1h-1zM32 7h1v1h-1zM34 7h4v1h-4zM41 7h3v1h-3zM26 8h1v1h-1zM28 8h1v1h-1zM32 8h1v1h-1zM35 8h1v1h-1zM40 8h1v1h-1zM44 8h1v1h-1zM23 9h4v1h-4zM28 9h1v1h-1zM32 9h1v1h-1zM35 9h1v1h-1zM40 9h1v1h-1zM44 9h1v1h-1zM22 10h1v1h-1zM26 10h1v1h-1zM28 10h1v1h-1zM31 10h2v1h-2zM35 10h1v1h-1zM38 10h1v1h-1zM40 10h1v1h-1zM44 10h1v1h-1zM23 11h4v1h-4zM29 11h2v1h-2zM32 11h1v1h-1zM36 11h2v1h-2zM41 11h3v1h-3z"),
    (LOGO_WHITE, "M46 7h4v1h-4zM52 7h1v1h-1zM56 7h1v1h-1zM58 7h4v1h-4zM46 8h1v1h-1zM50 8h1v1h-1zM52 8h1v1h-1zM56 8h1v1h-1zM58 8h1v1h-1zM62 8h1v1h-1zM46 9h1v1h-1zM50 9h1v1h-1zM52 9h1v1h-1zM54 9h1v1h-1zM56 9h1v1h-1zM58 9h1v1h-1zM62 9h1v1h-1zM46 10h4v1h-4zM52 10h1v1h-1zM54 10h1v1h-1zM56 10h1v1h-1zM58 10h1v1h-1zM62 10h1v1h-1zM46 11h1v1h-1zM53 11h1v1h-1zM55 11h1v1h-1zM58 11h1v1h-1zM62 11h1v1h-1zM46 12h1v1h-1z"),
]


def _grid() -> dict[tuple[int, int], str]:
    cells: dict[tuple[int, int], str] = {}
    for color, d in _LOGO_PATHS:
        for m in re.finditer(r"M(\d+) (\d+)h(-?\d+)v(-?\d+)", d):
            x, y, w, h = map(int, m.groups())
            for yy in range(y, y + h):
                for xx in range(x, x + w):
                    cells[(xx, yy)] = color
    return cells


def logo_mark(pad_left: int = 0) -> Text:
    """Pixel-exact logo via half-blocks (2 pixel-rows per char row)."""
    cells = _grid()
    xs = [x for x, _ in cells]
    ys = [y for _, y in cells]
    x0, x1 = min(xs), max(xs)
    y0, y1 = min(ys), max(ys)
    if (y1 - y0 + 1) % 2:
        y1 += 1
    out = Text()
    for y in range(y0, y1 + 1, 2):
        out.append(" " * pad_left)
        for x in range(x0, x1 + 1):
            top = cells.get((x, y))
            bot = cells.get((x, y + 1))
            if top and bot:
                out.append("█" if top == bot else "▀", style=top if top == bot else f"{top} on {bot}")
            elif top:
                out.append("▀", style=top)
            elif bot:
                out.append("▄", style=bot)
            else:
                out.append(" ")
        out.append("\n")
    return out


def compact_logo() -> Text:
    t = Text()
    t.append("▌ ", style=GREEN)
    t.append("auto", style=f"bold {GRAY}")
    t.append("pwn", style=f"bold {WHITE}")
    return t


TAGLINE = "Purple-Team Vulnerability Discovery Agent"
VERSION = f"v{__version__}  ·  single-agent  ·  safe-verification"


def splash(subtitle: str | None = None) -> RenderableType:
    parts = [
        Align.center(logo_mark()),
        Align.center(Text(TAGLINE, style=f"italic {GRAY}")),
        Align.center(Text(VERSION, style="#3A423D")),
    ]
    if subtitle:
        parts.append(Align.center(Text(subtitle, style=GREEN)))
    return Group(*parts)
