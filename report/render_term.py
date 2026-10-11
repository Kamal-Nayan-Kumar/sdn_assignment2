#!/usr/bin/env python3
"""
render_term.py - Render captured terminal output (with ANSI colours) to PNG.

Reads an ANSI-coloured text file and writes a styled "terminal window"
PNG: rounded dark background, a title bar with traffic-light dots, the
command line in a prompt colour, and monospaced body text.

Usage:
    render_term.py <input.ansi> <output.png> [--title "some title"]
                  [--cols N] [--max-lines N]

Requires: pillow.
"""

import argparse
import os
import re
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    sys.exit("ERROR: pillow is required -- pip install pillow")

# ------------------------------------------------------------------ #
# Theme                                                               #
# ------------------------------------------------------------------ #
BG = (23, 25, 33)
TITLEBAR = (32, 35, 45)
FG = (208, 214, 224)
CHROME = (90, 97, 112)
RED = (255, 95, 86)
YELLOW = (255, 189, 46)
GREEN = (39, 201, 63)
PROMPT = (94, 214, 255)

# xterm 16-colour palette, normalised to 0-255.
PALETTE = {
    30: (86, 95, 110),   31: (255, 95, 86),   32: (39, 201, 63),
    33: (255, 189, 46),  34: (93, 168, 255),  35: (198, 120, 221),
    36: (86, 182, 194),  37: (208, 214, 224),
    90: (120, 130, 148), 91: (255, 130, 120), 92: (110, 220, 130),
    93: (255, 210, 120), 94: (140, 195, 255), 95: (220, 160, 235),
    96: (140, 210, 220), 97: (240, 244, 250),
}

# Bright 256-colour cube + greyscale ramp, so `script` colour output and
# pytest/mininet 256-colour output both render sensibly.
def xterm256(n):
    if n < 16:
        base = [30, 31, 32, 33, 34, 35, 36, 37,
                90, 91, 92, 93, 94, 95, 96, 97]
        return PALETTE[base[n]]
    if n < 232:
        n -= 16
        levels = [0, 95, 135, 175, 215, 255]
        return (levels[n // 36], levels[(n // 6) % 6], levels[n % 6])
    v = 8 + (n - 232) * 10
    return (v, v, v)


FONT_CANDIDATES = [
    "/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Regular.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/LiberationMono-Regular.ttf",
    "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
]

BOLD_CANDIDATES = [
    "/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/liberation/LiberationMono-Bold.ttf",
]

ANSI_RE = re.compile(r'\x1b\[([0-9;]*)m|\x1b\][^\x07]*\x07|\x1b[\(\)][A-Z0-9]|\r')


def load_font(candidates, size):
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def parse_ansi(text):
    """Turn ANSI-coloured text into a list of lines of (char, colour, bold)."""
    lines = []
    cur = []                      # spans of the current line
    colour, bold, dim = FG, False, False
    i = 0
    while i < len(text):
        m = ANSI_RE.match(text, i)
        if m:
            if m.group(1) is not None:
                for code in (m.group(1) or "0").split(";"):
                    c = int(code or 0)
                    if c == 0:
                        colour, bold, dim = FG, False, False
                    elif c == 1:
                        bold = True
                    elif c == 2:
                        dim = True
                    elif c == 22:
                        bold = dim = False
                    elif c == 39:
                        colour = FG
                    elif c in PALETTE:
                        colour = PALETTE[c]
                    elif c == 38 and i < len(text):
                        pass
                    elif 30 <= c <= 37 or 90 <= c <= 97:
                        colour = PALETTE[c]
                # 256-colour / truecolour: handled by the extended regex below
                i = m.end()
                continue
            i = m.end()
            continue

        # 38;5;N and 38;2;R;G;B
        ext = re.match(r'\x1b\[38;5;(\d+)m', text[i:])
        if ext:
            colour = xterm256(int(ext.group(1)))
            i += ext.end()
            continue
        ext = re.match(r'\x1b\[38;2;(\d+);(\d+);(\d+)m', text[i:])
        if ext:
            colour = (int(ext.group(1)), int(ext.group(2)), int(ext.group(3)))
            i += ext.end()
            continue

        ch = text[i]
        if ch == '\n':
            lines.append(cur)
            cur = []
        elif ch == '\t':
            cur.extend((' ', colour, bold) for _ in range(4))
        elif ch >= ' ':
            cur.append((ch, colour, bold))
        i += 1
    lines.append(cur)
    return lines


def render(src, dst, title="terminal", cols=None, max_lines=None,
           font_size=15):
    with open(src, "r", errors="replace") as f:
        raw = f.read()

    lines = parse_ansi(raw)

    # Strip trailing blank lines.
    while lines and not lines[-1]:
        lines.pop()
    if max_lines:
        lines = lines[:max_lines]
    if not lines:
        lines = [[]]

    font = load_font(FONT_CANDIDATES, font_size)
    bold_font = load_font(BOLD_CANDIDATES, font_size)
    ui_font = load_font(FONT_CANDIDATES, 13)

    # Character cell metrics from a wide glyph ("W").
    try:
        cw = font.getlength("W")
        ascent, descent = font.getmetrics()
        ch = ascent + descent
    except AttributeError:
        cw, ch = 8, 18

    width_chars = cols or max((len(l) for l in lines), default=40)
    width_chars = max(width_chars, len(title) + 12, 40)

    pad = 22
    bar = 34
    W = int(cw * width_chars) + pad * 2
    H = int(ch * len(lines)) + pad * 2 + bar

    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # Title bar.
    d.rectangle([0, 0, W, bar], fill=TITLEBAR)
    for idx, col in enumerate((RED, YELLOW, GREEN)):
        cx = pad + idx * 18
        d.ellipse([cx - 5, bar // 2 - 5, cx + 5, bar // 2 + 5], fill=col)
    try:
        tw = ui_font.getlength(title)
    except AttributeError:
        tw = len(title) * 7
    d.text(((W - tw) / 2, bar / 2 - 8), title, font=ui_font, fill=CHROME)

    y = bar + pad
    for line in lines:
        x = pad
        for chr_, colour, bold in line:
            d.text((x, y), chr_, font=bold_font if bold else font,
                   fill=colour)
            x += cw
        y += ch

    # Border.
    d.rectangle([0, 0, W - 1, H - 1], outline=(54, 58, 70))

    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    img.save(dst)
    return dst


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--title", default=None,
                    help="title-bar text (default: input filename)")
    ap.add_argument("--cols", type=int, default=None,
                    help="force a fixed width in characters")
    ap.add_argument("--max-lines", type=int, default=None)
    ap.add_argument("--font-size", type=int, default=15)
    args = ap.parse_args()

    title = args.title or os.path.basename(args.input)
    path = render(args.input, args.output, title=title, cols=args.cols,
                  max_lines=args.max_lines, font_size=args.font_size)
    print("[render] %s" % path)


if __name__ == "__main__":
    main()
