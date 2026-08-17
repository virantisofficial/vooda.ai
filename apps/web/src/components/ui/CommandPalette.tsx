"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/*
 * Cmd+K command palette — global keyboard navigation surface.
 *
 * Mirrors what Linear / Vercel / Stripe Dashboard ship: a full-screen
 * overlay anchored near the top with a single search input that filters
 * a flat list of jump destinations (Navigate) and parameterised views
 * (Quick Actions).  The set is opinionated and intentionally short —
 * a palette with 200 items is just a search index, which defeats the
 * "I know what I want, take me there" muscle memory the pattern is
 * designed around.
 *
 * Items are grouped by section in the rendered list, but the index
 * itself is a single flat array so ↑↓ navigation crosses sections
 * naturally and the keyboard never gets "stuck" inside a section.
 *
 * Filtering is case-insensitive substring match across label +
 * keywords; we don't bother with a proper fuzzy matcher (fuse.js,
 * minisearch) because the corpus is ~30 items — substring is faster
 * to ship, easier to debug, and zero dependencies.
 */

import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";

type PaletteItem = {
  id: string;
  label: string;
  /** Section heading shown above this item in the grouped list. */
  section: "Navigate" | "Quick Actions";
  /** Target path (passed to router.push). */
  href: string;
  /** Extra search terms — aliases, synonyms, abbreviations. */
  keywords?: string[];
  /** Optional one-line description shown to the right of the label. */
  hint?: string;
  /** Icon glyph (24×24 stroke path data). */
  icon: React.ReactNode;
};

// Icon shortcuts so the item table below stays readable. Each is a
// stroke-only SVG path that inherits currentColor from the parent.
const ICON = {
  dash: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />,
  folder: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />,
  database: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />,
  key: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />,
  shield: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />,
  link: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />,
  cog: <><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></>,
  doc: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />,
  warn: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01M5.062 19h13.876c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />,
  bolt: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />,
  check: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />,
  plus: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 4v16m8-8H4" />,
  rotate: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />,
  chart: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />,
  pkg: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />,
  calendar: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />,
  user: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />,
} as const;

// The full palette index. Ordering inside each section is roughly
// "highest-traffic first" — Findings before Sources before Repos,
// because that mirrors what the dashboard surfaces in Quick Actions.
const ITEMS: PaletteItem[] = [
  // ── Navigate ───────────────────────────────────────────────
  { id: "nav:dashboard",    section: "Navigate", label: "Dashboard",         href: "/dashboard",            keywords: ["home", "overview", "kpi", "posture"], icon: ICON.dash },
  { id: "nav:findings",     section: "Navigate", label: "Secrets",           href: "/findings",             keywords: ["findings", "leaks", "credentials"], icon: ICON.key },
  { id: "nav:sources",      section: "Navigate", label: "Sources",           href: "/sources",              keywords: ["integrations", "connectors", "saas", "slack", "github", "notion", "jira", "confluence"], icon: ICON.database },
  { id: "nav:repos",        section: "Navigate", label: "Repositories",      href: "/repositories",         keywords: ["repos", "git", "code"], icon: ICON.folder },
  // Governance entries (nhi, nhi/vault, nhi/federation, supply-chain,
  // supply-chain/sbom, policies) removed 2026-05-16 — the corresponding
  // product surfaces were deleted to refocus on secret-scanner core.
  { id: "nav:integrations", section: "Navigate", label: "Integrations",      href: "/integrations",         keywords: ["scanners", "notifications", "webhooks"], icon: ICON.link },
  { id: "nav:reports",      section: "Navigate", label: "Reports",           href: "/reports",              keywords: ["export", "compliance", "audit"], icon: ICON.chart },
  { id: "nav:schedules",    section: "Navigate", label: "Schedules",         href: "/schedules",            keywords: ["cron", "recurring scans"], icon: ICON.calendar },
  { id: "nav:suppressions", section: "Navigate", label: "Suppressions",      href: "/suppressions",         keywords: ["allow", "ignore", "false positive"], icon: ICON.doc },
  { id: "nav:allowlists",   section: "Navigate", label: "Allowlists",        href: "/allowlists",           keywords: ["whitelist", "permit"], icon: ICON.doc },
  { id: "nav:webhooks",     section: "Navigate", label: "Webhooks",          href: "/webhooks",             keywords: ["http callbacks", "endpoints"], icon: ICON.link },
  { id: "nav:settings",     section: "Navigate", label: "Settings",          href: "/settings/admin",       keywords: ["admin", "config", "team"], icon: ICON.cog },
  { id: "nav:profile",      section: "Navigate", label: "My Profile",        href: "/profile",              keywords: ["account", "password", "tokens"], icon: ICON.user },
  { id: "nav:docs",         section: "Navigate", label: "Documentation",     href: "/docs",                 keywords: ["help", "manual", "guide"], icon: ICON.doc },

  // ── Quick Actions ──────────────────────────────────────────
  { id: "qa:critical",  section: "Quick Actions", label: "View critical findings", href: "/findings?severity=critical",                 hint: "Severity = critical",         keywords: ["urgent", "high priority"], icon: ICON.warn },
  { id: "qa:active",    section: "Quick Actions", label: "View active credentials", href: "/findings?validation_status=active",         hint: "Verified live secrets",       keywords: ["live", "verified", "rotate"], icon: ICON.bolt },
  { id: "qa:triage",    section: "Quick Actions", label: "Triage needs review",     href: "/findings?classification=NEEDS_REVIEW",      hint: "AI flagged for human review", keywords: ["queue", "needs review", "classify"], icon: ICON.warn },
  { id: "qa:patches",   section: "Quick Actions", label: "Pending patches",          href: "/findings?remediation_status=PATCH_GENERATED", hint: "Awaiting approval",         keywords: ["remediation", "fix", "approve"], icon: ICON.check },
  { id: "qa:rotation",  section: "Quick Actions", label: "Rotation queue",           href: "/secrets/rotation",                          hint: "Credentials awaiting rotation", keywords: ["rotate", "sla", "credentials"], icon: ICON.rotate },
  { id: "qa:add-repo",  section: "Quick Actions", label: "Add repository",           href: "/repositories",                              hint: "Connect a new repo",          keywords: ["new repo", "onboard", "github"], icon: ICON.plus },
  { id: "qa:add-src",   section: "Quick Actions", label: "Connect source",           href: "/sources",                                   hint: "Add a SaaS data source",      keywords: ["new source", "connect", "saas"], icon: ICON.plus },
];

/** Hook returning [open, setOpen]; auto-binds Cmd/Ctrl+K globally. */
export function useCommandPalette() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Cmd+K (mac) / Ctrl+K (everything else). Linear, Vercel,
      // GitHub all use the same chord; staying with the convention
      // keeps muscle memory portable.
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return [open, setOpen] as const;
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function CommandPalette({ open, onClose }: Props) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Reset state every time the palette opens. Closing leaves the
  // last query in place briefly while the close animation plays —
  // that's intentional so the user doesn't see content shift during
  // dismiss.
  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIdx(0);
      // Focus the input after the open animation has started so the
      // caret lands in the right place visually.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return ITEMS;
    return ITEMS.filter((item) => {
      if (item.label.toLowerCase().includes(q)) return true;
      if (item.hint?.toLowerCase().includes(q)) return true;
      return (item.keywords || []).some((k) => k.toLowerCase().includes(q));
    });
  }, [query]);

  // Clamp active index when the filtered list shrinks below it.
  useEffect(() => {
    if (activeIdx >= filtered.length) setActiveIdx(Math.max(0, filtered.length - 1));
  }, [filtered, activeIdx]);

  const select = useCallback((item: PaletteItem) => {
    onClose();
    router.push(item.href);
  }, [onClose, router]);

  // ── Keyboard handling inside the palette ──
  // The Cmd+K toggle still works globally (lives in useCommandPalette);
  // here we only handle navigation chords when the palette is mounted.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveIdx((i) => Math.min(filtered.length - 1, i + 1));
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveIdx((i) => Math.max(0, i - 1));
        return;
      }
      if (e.key === "Enter") {
        e.preventDefault();
        const item = filtered[activeIdx];
        if (item) select(item);
        return;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, filtered, activeIdx, select, onClose]);

  // Auto-scroll the active row into view as the user arrow-keys.
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-idx="${activeIdx}"]`) as HTMLElement | null;
    el?.scrollIntoView({ block: "nearest" });
  }, [activeIdx]);

  if (!open) return null;

  // Group the filtered list by section, preserving the original
  // declaration order within each section. We compute groups inline
  // (not memoised) because filtered changes on every keystroke and
  // the list is small enough that the work is negligible.
  const groups: Array<{ section: string; items: PaletteItem[]; firstIdx: number }> = [];
  let cursor = 0;
  for (const item of filtered) {
    const existing = groups.find((g) => g.section === item.section);
    if (existing) existing.items.push(item);
    else groups.push({ section: item.section, items: [item], firstIdx: cursor });
    cursor++;
  }

  return (
    <div
      className="fixed inset-0 z-[200] flex items-start justify-center pt-[12vh] px-4 vooda-fade-in"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      style={{
        background: "rgba(2, 4, 12, 0.65)",
        backdropFilter: "blur(8px)",
        WebkitBackdropFilter: "blur(8px)",
      }}
    >
      <div
        className="w-full max-w-xl rounded-xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "rgba(12, 15, 32, 0.96)",
          border: "1px solid rgba(255,255,255,0.10)",
          boxShadow: "0 24px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(239,68,68,0.06)",
        }}
      >
        {/* ── Search row ── */}
        <div className="flex items-center gap-3 px-4 py-3" style={{ borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: "#94a3b8" }}>
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setActiveIdx(0); }}
            placeholder="Search pages, actions, settings..."
            className="flex-1 bg-transparent outline-none text-sm text-white placeholder:text-slate-600"
            spellCheck={false}
            autoComplete="off"
          />
          <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded border" style={{ color: "#475569", borderColor: "rgba(255,255,255,0.08)" }}>esc</kbd>
        </div>

        {/* ── Results ── */}
        <div ref={listRef} className="max-h-[60vh] overflow-y-auto py-1.5">
          {filtered.length === 0 ? (
            <div className="px-4 py-10 text-center">
              <p className="text-sm text-slate-400">No matches</p>
              <p className="text-[11px] text-slate-600 mt-1">Try a different search term</p>
            </div>
          ) : (
            groups.map((g) => (
              <div key={g.section} className="px-2 py-1">
                <div className="px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-widest" style={{ color: "#475569" }}>
                  {g.section}
                </div>
                {g.items.map((item, localIdx) => {
                  const idx = g.firstIdx + localIdx;
                  const isActive = idx === activeIdx;
                  return (
                    <button
                      key={item.id}
                      data-idx={idx}
                      type="button"
                      onMouseEnter={() => setActiveIdx(idx)}
                      onClick={() => select(item)}
                      className="w-full flex items-center gap-3 px-2.5 py-2 rounded-md text-left transition-colors"
                      style={{
                        background: isActive ? "rgba(239,68,68,0.10)" : "transparent",
                        border: "1px solid",
                        borderColor: isActive ? "rgba(239,68,68,0.18)" : "transparent",
                      }}
                    >
                      <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: isActive ? "#f87171" : "#94a3b8" }}>
                        {item.icon}
                      </svg>
                      <span className="flex-1 min-w-0 truncate text-sm" style={{ color: isActive ? "#ffffff" : "#cbd5e1" }}>
                        {item.label}
                      </span>
                      {item.hint && (
                        <span className="hidden sm:inline text-[11px] truncate ml-2" style={{ color: "#475569" }}>
                          {item.hint}
                        </span>
                      )}
                      {isActive && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded shrink-0" style={{ color: "#f87171", background: "rgba(239,68,68,0.10)", border: "1px solid rgba(239,68,68,0.20)" }}>
                          ↵
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        {/* ── Footer hint row ── */}
        <div className="flex items-center justify-between px-4 py-2 text-[10px]" style={{ borderTop: "1px solid rgba(255,255,255,0.06)", color: "#475569", background: "rgba(255,255,255,0.015)" }}>
          <div className="flex items-center gap-3">
            <span><kbd className="font-mono">↑↓</kbd> navigate</span>
            <span><kbd className="font-mono">↵</kbd> open</span>
            <span><kbd className="font-mono">esc</kbd> close</span>
          </div>
          <span>{filtered.length} of {ITEMS.length}</span>
        </div>
      </div>
    </div>
  );
}
