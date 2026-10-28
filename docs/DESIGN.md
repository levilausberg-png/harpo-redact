# Console design system

The console is a control plane, not a marketing page. Every visual decision answers "why is this here?".

**Surfaces.** Mostly flat tonal panels (`--s1`..`--s3`); soft elevation for overview summaries; glass only for transient
layers (command palette, inspector, menus), and never when `prefers-reduced-transparency` asks; recessed `--inset`
surfaces for instrumentation (code, raw egress, waterfalls).

**Colour carries meaning.** The canvas is Midnight Slate (`#0F172A`; Slate 50 in the light theme), and the brand's two
colours each have one job: jade (`--ver`, `--jade`) is what Harpo silenced or verified, rose (`--bad`, `--rose`) what it
held back, a blocked request. Sky `--det`: deterministic processing. Lavender `--prob`: probabilistic layers (NER, the
local SLM). Amber `--warn`: degraded or needs review. Named gradients (`--g-brand`, `--g-assure`, `--g-danger`,
`--g-flow`) are the only gradients: posture, assurance and flow, never decoration; a healthy posture uses the jade one.
Text tokens meet WCAG AA (4.5:1) on every surface they sit on, in both themes. The brand itself (the mark, the palette,
the voice) is in [BRAND.md](BRAND.md).

**Navigation follows Harpo's parts.** Overview, then four rooms: Shield (traffic in and out), Mask (what is
redacted, and how), Vault (what never leaves) and Proof (what you can check). Each page's eyebrow and breadcrumb name
its room.

**Motion explains state.** Tokens: `--motion-instant` 80 ms, `--motion-fast` 120 ms, `--motion-normal` 180 ms,
`--motion-slow` 260 ms, `--motion-emphasis` 360 ms; easings `--ease-standard`, `--ease-enter`, `--ease-exit`,
`--ease-data`, `--ease-layout`. Things move to show data arriving, a state changing, where something came from, or
that work is in progress. Nothing loops while the system is idle: the live indicator lights only when new requests
arrive. Page changes use View Transitions on the page area only (the shell never moves), with a CSS fallback, and
`prefers-reduced-motion` removes them.

**Privacy in the browser.** The gateway key lives in `sessionStorage` for one tab. `core/prefs.js` is the only module
that touches `localStorage`: one versioned key (`harpo.ui.v1`) with a whitelist (theme, density, layout, views,
favourites, columns, recents of page names). Prompts, findings, keys and documents are never stored;
`tests/test_console_browser.py` checks this after real use.

**Accessibility.** Keyboard first (⌘K, `?`, `G` + letter, `J`/`K`, `/`, `[`/`]`, Esc); dialogs trap and return focus;
inputs inside a labelled field are named automatically; scrollable regions are focusable. axe-core reports no serious
or critical issues on all 16 pages in dark, light and mobile layouts (run it with `bypass_csp` in a test browser: the
console's own CSP rightly refuses injected scripts).

**Local only.** Fonts, icons, scripts and styles ship with the gateway; the CSP allows nothing else.

**Ambient and light.** The ambient field is two faint radial washes drifting over 140 s, behind all content
(`z-index: -1`); a degraded posture warms its secondary tint, never the whole screen. Pointer light exists on the
posture card and the exact-egress pane only, as a layer beneath their content, and only for a fine pointer without
reduced motion. Test: if doubling an effect's opacity would distract, it is already too strong.

**Menus, dialogs, tour.** One menu component (`ui/menu.js`) serves context menus and popovers: arrow keys, Home/End,
Esc, focus returns to the anchor. Dialogs trap focus. The tour has five steps, never starts by itself, and is
remembered once finished or dismissed. Preferences add `dismissed` (attention items hidden until their condition
changes) to the whitelist; saved views store filters only.

**Live data.** `core/stream.js` reads `/v1/events` with `fetch` (EventSource cannot send the gateway key), reconnects
with backoff, and reports its state in the top bar. Views register their subscriptions in `ctx.cleanups`, which the
router runs on every navigation, so a page never keeps listening after you leave it.
