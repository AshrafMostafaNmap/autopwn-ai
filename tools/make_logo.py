"""Build the animated README banner from the logo's own pixel data.

    python tools/make_logo.py        → assets/brand/logo-animated.svg

CSS animations only (GitHub renders SVG images without scripts): the bug's
pixels assemble, its antennae twitch, "autopwn" types itself out behind a
blinking cursor, a scan line sweeps the card and the bug glows.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from autopwn.ui.banner import _LOGO_PATHS  # noqa: E402
from autopwn.ui.theme import BG, FAINT2, GRAY, GREEN, LOGO_GREEN  # noqa: E402

OUT = ROOT / "assets" / "brand" / "logo-animated.svg"
SCALE = 10
W, H = 900, 300
OX, OY = (W - 66 * SCALE) // 2, 40
RECT = re.compile(r"M(\d+) (\d+)h(\d+)v(\d+)h-\d+z")


def pixels():
    for color, d in _LOGO_PATHS:
        for x, y, w, h in RECT.findall(d):
            yield color, int(x), int(y), int(w), int(h)


def build() -> str:
    bug, frame, word = [], [], []
    for color, x, y, w, h in pixels():
        (bug if color == LOGO_GREEN and x < 20 else frame if x < 20 else word).append((color, x, y, w, h))

    def rect(color, x, y, w, h, cls="", style=""):
        return (f'<rect x="{OX + x * SCALE}" y="{OY + y * SCALE}" width="{w * SCALE}" height="{h * SCALE}" '
                f'fill="{color}"{f" class={chr(34)}{cls}{chr(34)}" if cls else ""}'
                f'{f" style={chr(34)}{style}{chr(34)}" if style else ""}/>')

    bug_rects = []
    for i, (color, x, y, w, h) in enumerate(sorted(bug, key=lambda p: (p[2], p[1]))):
        cls = "px antenna" if y <= 6 else "px"
        bug_rects.append(rect(color, x, y, w, h, cls, f"animation-delay:{0.15 + i * 0.035:.3f}s"))
    frame_rects = [rect(c, x, y, w, h, "frame") for c, x, y, w, h in frame]
    word_rects = [rect(c, x, y, w, h) for c, x, y, w, h in word]
    word_x0 = OX + min(p[1] for p in word) * SCALE
    word_x1 = OX + max(p[1] + p[3] for p in word) * SCALE
    word_y0 = OY + min(p[2] for p in word) * SCALE
    word_y1 = OY + max(p[2] + p[4] for p in word) * SCALE
    type_w = word_x1 - word_x0

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="AutoPwn AI">
<title>AutoPwn AI</title>
<defs>
  <linearGradient id="scan" x1="0" x2="0" y1="0" y2="1">
    <stop offset="0" stop-color="{GREEN}" stop-opacity="0"/>
    <stop offset="0.5" stop-color="{GREEN}" stop-opacity="0.18"/>
    <stop offset="1" stop-color="{GREEN}" stop-opacity="0"/>
  </linearGradient>
  <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
    <path d="M20 0H0V20" fill="none" stroke="{GREEN}" stroke-opacity="0.05" stroke-width="1"/>
  </pattern>
  <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
    <feGaussianBlur stdDeviation="6" result="b"/>
    <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <clipPath id="card"><rect width="{W}" height="{H}" rx="18"/></clipPath>
  <clipPath id="typing"><rect class="typer" x="{word_x0}" y="{word_y0 - 4}" width="{type_w}" height="{word_y1 - word_y0 + 8}"/></clipPath>
</defs>
<style>
  .px {{ opacity: 0; transform-box: fill-box; transform-origin: center; animation: pop .45s cubic-bezier(.2,1.6,.4,1) forwards; }}
  .antenna {{ animation: pop .45s cubic-bezier(.2,1.6,.4,1) forwards, twitch 2.4s ease-in-out 2.2s infinite; }}
  .frame {{ opacity: 0; animation: fade .6s ease-out .05s forwards; }}
  .bug {{ animation: glow 3s ease-in-out 2s infinite; }}
  .typer {{ transform-box: fill-box; transform-origin: left; transform: scaleX(0); animation: type 1.4s steps(7) 1.1s forwards; }}
  .cursor {{ opacity: 0; animation: blink 1s steps(1) 1.1s infinite; }}
  .cursor-move {{ animation: slide 1.4s steps(7) 1.1s forwards; }}
  .sweep {{ animation: sweep 4.5s linear 1s infinite; }}
  .tag {{ opacity: 0; animation: fade .8s ease-out 2.5s forwards; }}
  .sub {{ opacity: 0; animation: fade .8s ease-out 2.9s forwards; }}
  @keyframes pop {{ 0% {{ opacity: 0; transform: scale(0.2); }} 100% {{ opacity: 1; transform: scale(1); }} }}
  @keyframes fade {{ to {{ opacity: 1; }} }}
  @keyframes type {{ to {{ transform: scaleX(1); }} }}
  @keyframes slide {{ to {{ transform: translateX({type_w}px); }} }}
  @keyframes blink {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0; }} }}
  @keyframes twitch {{ 0%, 70%, 100% {{ transform: rotate(0); }} 78% {{ transform: rotate(-14deg); }} 86% {{ transform: rotate(12deg); }} }}
  @keyframes glow {{ 0%, 100% {{ filter: drop-shadow(0 0 0 {GREEN}00); }} 50% {{ filter: drop-shadow(0 0 10px {GREEN}aa); }} }}
  @keyframes sweep {{ 0% {{ transform: translateY(-120px); }} 100% {{ transform: translateY({H + 40}px); }} }}
  @media (prefers-reduced-motion: reduce) {{
    .px, .frame, .tag, .sub {{ animation: none; opacity: 1; }}
    .typer {{ animation: none; transform: none; }}
    .cursor, .sweep, .bug, .antenna {{ animation: none; }}
  }}
</style>
<g clip-path="url(#card)">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  <rect width="{W}" height="{H}" fill="url(#grid)"/>
  <rect class="sweep" x="0" y="0" width="{W}" height="90" fill="url(#scan)"/>
  <g>{''.join(frame_rects)}</g>
  <g class="bug">{''.join(bug_rects)}</g>
  <g clip-path="url(#typing)">{''.join(word_rects)}</g>
  <g class="cursor-move"><rect class="cursor" x="{word_x0 + 4}" y="{word_y0 - 2}" width="{SCALE}" height="{word_y1 - word_y0 + 4}" fill="{GREEN}"/></g>
  <text class="tag" x="{W / 2}" y="{OY + 19 * SCALE + 24}" text-anchor="middle" fill="{GREEN}"
        font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="20" letter-spacing="6">PURPLE-TEAM AI AGENT</text>
  <text class="sub" x="{W / 2}" y="{OY + 19 * SCALE + 54}" text-anchor="middle" fill="{GRAY}"
        font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="15">find · verify safely · report · for the blue team</text>
  <rect width="{W}" height="{H}" rx="18" fill="none" stroke="{FAINT2}" stroke-width="2"/>
</g>
</svg>
"""


if __name__ == "__main__":
    OUT.write_text(build(), encoding="utf-8")
    print("wrote", OUT.relative_to(ROOT))
