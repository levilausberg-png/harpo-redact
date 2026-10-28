// One menu component for context menus and popovers: keyboard first, kept inside the viewport.
import { esc, icon } from "../core/dom.js";

let current = null, anchor = null;
const outside = (e) => { if (current && !current.contains(e.target)) closeMenu(false); };
export function closeMenu(refocus = true) {
  current?.remove(); current = null;
  document.removeEventListener("pointerdown", outside, true);
  if (refocus && anchor instanceof Element) anchor.focus?.();
  anchor = null;
}
/** items: {label, icon, kbd, run, checked, keep, danger, disabled} | "-" | {head} */
export function openMenu(at, items, { label = "Actions" } = {}) {
  closeMenu(false);
  anchor = at;
  const m = document.createElement("div");
  m.className = "ctx-menu glass"; m.setAttribute("role", "menu"); m.setAttribute("aria-label", label);
  const mark = (it) => (it.checked != null ? `<span class="ck">${it.checked ? icon("check", "sm") : ""}</span>` : it.icon ? icon(it.icon, "sm") : '<span class="ck"></span>');
  m.innerHTML = items.map((it, i) => (it === "-" ? '<div class="ctx-sep" role="separator"></div>' : it.head ? `<div class="ctx-h" role="presentation">${esc(it.head)}</div>`
    : `<button role="${it.checked == null ? "menuitem" : "menuitemcheckbox"}"${it.checked != null ? ` aria-checked="${!!it.checked}"` : ""} data-i="${i}" class="${it.danger ? "danger" : ""}"${it.disabled ? " disabled" : ""}>${mark(it)}<span>${esc(it.label)}</span>${it.kbd ? `<kbd>${esc(it.kbd)}</kbd>` : ""}</button>`)).join("");
  document.body.appendChild(m); current = m;
  const r = at instanceof Element ? at.getBoundingClientRect() : { left: at.x, right: at.x, top: at.y, bottom: at.y };
  const w = m.offsetWidth, h = m.offsetHeight;
  let x = at instanceof Element ? Math.min(r.left, r.right - w) : r.left, y = r.bottom + 4;
  x = Math.max(8, Math.min(x, innerWidth - w - 8));
  if (y + h > innerHeight - 8) y = Math.max(8, r.top - h - 4);
  m.style.left = `${x}px`; m.style.top = `${y}px`;
  const live = () => [...m.querySelectorAll("button:not([disabled])")];
  m.onclick = (e) => {
    const b = e.target.closest("button[data-i]"); if (!b) return;
    const it = items[+b.dataset.i];
    if (it.keep) { it.run?.(); if (it.checked != null) { it.checked = !it.checked; b.setAttribute("aria-checked", String(it.checked)); b.querySelector(".ck").innerHTML = it.checked ? icon("check", "sm") : ""; } return; }
    closeMenu(); it.run?.();
  };
  m.onkeydown = (e) => {
    const list = live(), i = list.indexOf(document.activeElement);
    const go = (j) => { list[(j + list.length) % list.length]?.focus(); e.preventDefault(); };
    if (e.key === "ArrowDown") go(i + 1); else if (e.key === "ArrowUp") go(i - 1); else if (e.key === "Home") go(0); else if (e.key === "End") go(list.length - 1);
    else if (e.key === "Escape" || e.key === "Tab") { e.preventDefault(); e.stopPropagation(); closeMenu(); }
  };
  setTimeout(() => document.addEventListener("pointerdown", outside, true));
  live()[0]?.focus();
  return m;
}
export const menuOpen = () => !!current;
