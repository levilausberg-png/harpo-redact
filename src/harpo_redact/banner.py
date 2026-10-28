"""The boot banner: a harp, the name, and what this gateway is about to do.

Shown on interactive terminals only, so a log file, a pipe or a container gets none of it. ``HARPO_NO_BANNER=1``
turns it off, ``NO_COLOR`` keeps it plain, and a terminal that cannot show the rose or the rule gets ASCII.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

from . import __version__

# The harp, eight rows: the pillar on the left, the neck along the top, the soundboard falling back to the right,
# strings in between. The rose sits at the crown. Roles per character: F frame, S string, R rose, space nothing.
_HARP = (
    ("   *          ", "   R          "),
    ("   |\\_.-~~-._ ", "   FFFFFFFFFF "),
    ("   | | | | | `.", "   F S S S S FF"),
    ("   | | | | | / ", "   F S S S S F "),
    ("   | | | | /   ", "   F S S S F   "),
    ("   | | | /     ", "   F S S F     "),
    ("   | | /       ", "   F S F       "),
    ("   |_|/        ", "   FFSF        "),
)
_WIDTH = 17
_RGB = {"F": (226, 232, 240), "S": (46, 230, 168), "R": (247, 96, 138), "dim": (148, 163, 184), "tag": (46, 230, 168)}
_ROSE, _HUSH, _RULE = "✿", "\U0001f92b", "─"


def _paint(text: str, role: str, color: bool) -> str:
    if not color or not text.strip():
        return text
    r, g, b = _RGB[role]
    return f"\x1b[38;2;{r};{g};{b}m{text}\x1b[0m"


def render(lines: list[tuple[str, str]], *, color: bool = False, fancy: bool = True) -> str:
    """The harp beside a title, a rule, the (tag, text) lines and a closing rule."""
    rose = _ROSE if fancy else "@"
    rule = (_RULE if fancy else "-") * 52
    title = f"{_HUSH + ' ' if fancy else ''}HARPO-REDACT {__version__}"
    right = [
        "\x1b[1m" + title + "\x1b[0m" if color else title,
        _paint(rule, "dim", color),
        *(f"{_paint(f'[{tag}]', 'tag', color)}{' ' * (7 - len(tag))}{text}" for tag, text in lines),
        _paint(rule, "dim", color),
    ]
    out = []
    for i in range(max(len(_HARP), len(right))):
        art = ""
        if i < len(_HARP):
            chars, roles = _HARP[i]
            for ch, role in zip(chars, roles, strict=True):
                ch = rose if role == "R" else ch
                art += _paint(ch, role, color) if role != " " else ch
            art += " " * (_WIDTH - len(chars))
        else:
            art = " " * _WIDTH
        out.append((art + (right[i] if i < len(right) else "")).rstrip())
    return "\n" + "\n".join(out) + "\n"


def wanted(stream: TextIO) -> tuple[bool, bool, bool]:
    """(show it at all, in colour, with the rose and rule characters) for this stream."""
    if os.environ.get("HARPO_NO_BANNER") or not getattr(stream, "isatty", lambda: False)():
        return False, False, False
    color = not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
    if sys.platform == "win32" and not (os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM")):
        color = False  # the classic console shows escape codes as text
    try:
        (_ROSE + _HUSH + _RULE).encode(getattr(stream, "encoding", None) or "ascii")
        fancy = True
    except (UnicodeEncodeError, LookupError):
        fancy = False
    return True, color, fancy


def show(lines: list[tuple[str, str]], stream: TextIO | None = None) -> None:
    stream = stream or sys.stderr
    ok, color, fancy = wanted(stream)
    if ok:
        stream.write(render(lines, color=color, fancy=fancy))
        stream.flush()


def standard_lines(port: int, upstreams: list[str], key_rules: int, ner: bool, slm: bool) -> list[tuple[str, str]]:
    """The lines every start shows: what Harpo listens on, what it hides, and what never leaves."""
    names = ", ".join(upstreams[:4]) + (f" and {len(upstreams) - 4} more" if len(upstreams) > 4 else "")
    plural = "s" if len(upstreams) != 1 else ""
    return [
        ("INFO", "Sub-rosa gateway initiated."),
        ("INFO", f"Intercepting LLM traffic on port :{port}"),
        ("INFO", "Enforcing silence on personal data and secrets."),
        ("SHIELD", f"{len(upstreams)} upstream{plural}: {names}" if upstreams else "no upstreams configured"),
        ("MASK", f"{key_rules} key rules, NER {'on' if ner else 'off'}, local model {'on' if slm else 'off'}"),
        ("VAULT", "provider keys stay here; placeholders end with the request"),
    ]
