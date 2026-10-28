"""Harpo's marks, from one geometry: a harp whose strings are the gate, a heraldic rose at its crown.

Usage: python tools/make_marks.py docs/assets/brand   (then copy harpo-logo.svg to docs/assets/logo.svg and src/harpo_redact/console/logo.svg)

Writes into the directory given as the first argument:
  harpo-logo.svg           the primary mark: the harp on a Midnight Slate tile (app icon, favicon, README)
  harpo-mark-silver.svg    the harp alone, for dark backgrounds
  harpo-mark-slate.svg     the harp alone, for light backgrounds
  harpo-avatar.svg         the harp on a full-bleed square, for profile pictures (GitHub wants a raster: render it at
                           512 px as harpo-avatar.png)
  harpo-shield.svg         the cyber-shield crest
  harpo-monolith.svg       the high-contrast monolith: one solid silhouette, strings cut out
  harpo-blueprint.svg      the blueprint: fine lines on a grid, construction marks, the rose hidden at the crown
  harpo-palette.svg        the colours, named
"""

import math
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)

SLATE = "#0F172A"
SILVER = "#E2E8F0"
JADE = "#2EE6A8"
ROSE = "#E11D48"
GOLD = "#FDE68A"

# The harp in a 32-unit box: the neck (an S from the crown to the back), the pillar, the soundboard back to the neck.
NECK = "M9.2 9.6C13.2 5.2 17.4 11.6 23.6 8.6"
FRAME = "M9.2 9.6V25.2H10L23.6 8.6"
STRINGS = "M12.5 9.4V20.6M15 9.8V17.6M17.5 10.5V14.6M20 10.8V11.7"
CROWN = (9.2, 6.15)


def rose(cx: float, cy: float, scale: float = 1.0, petal: str = ROSE, barb: str = JADE, seed: str = GOLD) -> str:
    """A heraldic five-petal rose, the rose of sub rosa: petals, barbs between them, a golden centre."""
    petals = "".join(
        f'<circle cx="{cx + 1.05 * scale * math.cos(math.radians(-90 + k * 72)):.3f}" '
        f'cy="{cy + 1.05 * scale * math.sin(math.radians(-90 + k * 72)):.3f}" r="{1.08 * scale:.3f}"/>'
        for k in range(5)
    )
    barbs = []
    for k in range(5):
        a = math.radians(-54 + k * 72)
        tip = (cx + 2.15 * scale * math.cos(a), cy + 2.15 * scale * math.sin(a))
        left = (cx + 1.35 * scale * math.cos(a - 0.32), cy + 1.35 * scale * math.sin(a - 0.32))
        right = (cx + 1.35 * scale * math.cos(a + 0.32), cy + 1.35 * scale * math.sin(a + 0.32))
        barbs.append(f"M{left[0]:.3f} {left[1]:.3f}L{tip[0]:.3f} {tip[1]:.3f}L{right[0]:.3f} {right[1]:.3f}Z")
    return (
        f'<path d="{" ".join(barbs)}" fill="{barb}"/><g fill="{petal}">{petals}</g>'
        f'<circle cx="{cx}" cy="{cy}" r="{0.62 * scale:.3f}" fill="{seed}"/>'
    )


def harp(frame: str, strings: str, width: float = 2.3) -> str:
    return (
        f'<path d="{STRINGS}" stroke="{strings}" stroke-width="1.15" stroke-linecap="round"/>'
        f'<g stroke="{frame}" stroke-width="{width}" stroke-linecap="round" stroke-linejoin="round">'
        f'<path d="{NECK}"/><path d="{FRAME}"/></g>'
    )


def svg(view: str, body: str, title: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}" fill="none" role="img" aria-label="{title}">'
        f"<title>{title}</title>{body}</svg>\n"
    )


# A nudge so the harp and its rose sit in the optical centre of the tile.
CENTRE = 'transform="translate(.4 1)"'

tile = (
    f'<rect x="1" y="1" width="30" height="30" rx="8.5" fill="{SLATE}"/>'
    f'<rect x="1.3" y="1.3" width="29.4" height="29.4" rx="8.2" stroke="{SILVER}" stroke-opacity=".14" stroke-width=".6"/>'
    f"<g {CENTRE}>{harp(SILVER, JADE)}{rose(*CROWN)}</g>"
)
(OUT / "harpo-logo.svg").write_text(svg("0 0 32 32", tile, "Harpo"))
(OUT / "harpo-mark-silver.svg").write_text(svg("5 2.4 22 25", harp(SILVER, JADE) + rose(*CROWN), "Harpo"))
(OUT / "harpo-mark-slate.svg").write_text(
    svg("5 2.4 22 25", harp(SLATE, "#059669") + rose(*CROWN, barb="#059669", seed="#F59E0B"), "Harpo")
)

# The avatar: the tile's harp on a full-bleed square, small enough to survive the circle profile pictures are cut to.
avatar = (
    f'<rect width="32" height="32" fill="{SLATE}"/>'
    f'<g transform="translate(16 16) scale(.82) translate(-16 -16)"><g {CENTRE}>{harp(SILVER, JADE)}{rose(*CROWN)}</g></g>'
)
(OUT / "harpo-avatar.svg").write_text(svg("0 0 32 32", avatar, "Harpo"))

# The cyber-shield: the harp set in a crest, the crest edged in jade.
shield_path = "M16 1.8L28 6.2V15.4C28 22.6 22.9 27.8 16 30.2C9.1 27.8 4 22.6 4 15.4V6.2Z"
shield = (
    f'<path d="{shield_path}" fill="{SLATE}"/>'
    f'<path d="{shield_path}" stroke="{JADE}" stroke-opacity=".9" stroke-width=".8" stroke-linejoin="round"/>'
    f'<path d="M16 3.4L26.5 7.3V15.4C26.5 21.7 22.2 26.3 16 28.6C9.8 26.3 5.5 21.7 5.5 15.4V7.3Z" '
    f'stroke="{SILVER}" stroke-opacity=".18" stroke-width=".4"/>'
    f'<g transform="translate(16 16.4) scale(.74) translate(-16.4 -15.4)">{harp(SILVER, JADE)}{rose(*CROWN)}</g>'
)
(OUT / "harpo-shield.svg").write_text(svg("0 0 32 32", shield, "Harpo shield"))

# The monolith: one heavy silver silhouette, the strings cut out of it, the rose the only colour.
monolith = (
    f'<rect x="1" y="1" width="30" height="30" rx="2" fill="{SLATE}"/>'
    f"<g {CENTRE}>"
    f'<path d="M9.2 9.6C13.2 5.2 17.4 11.6 23.6 8.6L10 25.2H9.2Z" fill="{SILVER}" stroke="{SILVER}" '
    f'stroke-width="2.6" stroke-linejoin="round"/>'
    f'<path d="M12.5 9.6V21.4M15 10V18.4M17.5 10.7V15.4M20 11V12.4" stroke="{SLATE}" stroke-width="1.1"/>'
    f"{rose(*CROWN, petal=ROSE, barb=SLATE, seed=GOLD)}</g>"
)
(OUT / "harpo-monolith.svg").write_text(svg("0 0 32 32", monolith, "Harpo monolith"))

# The blueprint: hairlines on a grid, the construction of the neck curve, the rose drawn small at the crown.
grid = "".join(f'<path d="M{x} 1V31" />' for x in range(2, 31, 2)) + "".join(
    f'<path d="M1 {y}H31" />' for y in range(2, 31, 2)
)
blueprint = (
    f'<rect x="1" y="1" width="30" height="30" rx="3" fill="#0B1A33"/>'
    f'<g stroke="#5EA8F5" stroke-opacity=".16" stroke-width=".08">{grid}</g>'
    f"<g {CENTRE}>"
    f'<g stroke="#5EA8F5" stroke-opacity=".55" stroke-width=".12" stroke-dasharray=".5 .4">'
    f'<path d="M9.2 9.6L13.2 5.2M17.4 11.6L23.6 8.6"/><circle cx="13.2" cy="5.2" r=".35"/><circle cx="17.4" cy="11.6" r=".35"/>'
    f'<path d="M7 25.2H26M23.6 6V27"/></g>'
    f'<path d="{STRINGS}" stroke="{JADE}" stroke-width=".32" stroke-linecap="round"/>'
    f'<g stroke="#DCE9FF" stroke-width=".42" stroke-linecap="round" stroke-linejoin="round">'
    f'<path d="{NECK}"/><path d="{FRAME}"/></g>'
    f"{rose(*CROWN, scale=0.62, petal='none', barb='none', seed=ROSE)}"
    f'<g stroke="{ROSE}" stroke-width=".18">'
    + "".join(
        f'<circle cx="{CROWN[0] + 0.65 * math.cos(math.radians(-90 + k * 72)):.3f}" '
        f'cy="{CROWN[1] + 0.65 * math.sin(math.radians(-90 + k * 72)):.3f}" r=".67"/>'
        for k in range(5)
    )
    + "</g></g>"
)
(OUT / "harpo-blueprint.svg").write_text(svg("0 0 32 32", blueprint, "Harpo blueprint"))


# The palette, as swatches with names and values (docs/BRAND.md shows it).
SWATCHES = [
    ("Midnight Slate", "#0F172A", "canvas, the tile"),
    ("Silver", "#E2E8F0", "text, the harp"),
    ("Cyber Jade", "#2EE6A8", "silenced, verified, on"),
    ("Crimson Rose", "#E11D48", "the rose; held back"),
    ("Rose (text)", "#F7608A", "blocked, on dark"),
    ("Lamp Amber", "#F4B54C", "needs attention"),
]
cells = []
for i, (name, value, role) in enumerate(SWATCHES):
    x = 16 + i * 148
    ink = "#0F172A" if value in ("#E2E8F0", "#2EE6A8", "#F4B54C") else "#E2E8F0"
    edge = ' stroke="#334155" stroke-width="1"' if value == "#0F172A" else ""
    cells.append(
        f'<rect x="{x}" y="16" width="136" height="96" rx="10" fill="{value}"{edge}/>'
        f'<text x="{x + 12}" y="88" fill="{ink}" font-size="13" font-weight="600">{name}</text>'
        f'<text x="{x + 12}" y="104" fill="{ink}" font-size="11" opacity=".8" font-family="ui-monospace, Menlo, monospace">'
        f"{value}</text>"
        f'<text x="{x}" y="134" fill="#94A3B8" font-size="11">{role}</text>'
    )
palette = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 920 150" font-family="ui-sans-serif, system-ui, sans-serif" '
    'role="img" aria-label="Harpo palette"><title>Harpo palette</title>'
    f'<rect width="920" height="150" rx="14" fill="#0B1222"/>{"".join(cells)}</svg>\n'
)
(OUT / "harpo-palette.svg").write_text(palette)
print("wrote", sorted(p.name for p in OUT.iterdir() if p.suffix == ".svg"))
