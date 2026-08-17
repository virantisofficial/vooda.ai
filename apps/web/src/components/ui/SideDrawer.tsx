"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * SideDrawer — right-side slide-in panel used for ALL "look at this
 * source / repo / item closely" surfaces (source detail, source connect
 * wizard, source edit form, etc.).
 *
 * Chrome is unified intentionally: every drawer in the product
 * should feel like the same component family.  The body is what
 * varies — tab strip + detail content, wizard step + form, etc.
 *
 * Visual contract matches the original /sources connect-wizard aside:
 *   - Right-side, slides in from the right via the `vooda-slide-in`
 *     keyframe (defined in app/globals.css)
 *   - Backdrop fades in via `vooda-fade-in`
 *   - Background `bg-[#0a0a0d]`, border `border-white/[0.08]`
 *   - Responsive width: sm/md/lg cap so the drawer doesn't fill a
 *     30-inch monitor edge-to-edge
 *   - Optional brand-glyph circle on the left of the header (icon +
 *     gradient class) — matches the connect-drawer's existing pattern
 *   - Close on Esc, close on backdrop click, body-scroll lock while
 *     open
 *
 * Optional tab strip in the header lets the consumer surface multiple
 * sub-sections (Overview / Scans / Settings / Rule Overrides) without
 * a separate component for each.
 */

import { useEffect } from "react";

export interface DrawerTab {
  key: string;
  label: string;
  /** Optional badge text (counts, "stale", etc.) rendered next to the label. */
  badge?: string;
  /** Optional badge colour class — default subtle slate. */
  badgeClass?: string;
}

interface Props {
  open: boolean;
  onClose: () => void;
  /** Drawer title shown top-left.  Required so screen readers have a label. */
  title: string;
  /** Optional subtitle below the title (source type, repo URL, etc.). */
  subtitle?: string;
  /**
   * Optional brand glyph rendered in a gradient-filled circle to the
   * left of the title.  Matches the visual treatment the original
   * /sources connect-wizard drawer used so that wizard and detail
   * drawers feel like the same surface.
   */
  icon?: React.ReactNode;
  /** Tailwind gradient class for the icon background, e.g.
   *  "from-pink-500 to-orange-500".  Ignored when icon is omitted. */
  iconGradient?: string;
  /**
   * Optional tab list.  When provided, the drawer renders a tab strip
   * under the title and the consumer controls `activeTab` + reacts to
   * `onTabChange`.  Omit both for a single-section drawer (wizard,
   * confirmation panel, etc.).
   */
  tabs?: DrawerTab[];
  activeTab?: string;
  onTabChange?: (key: string) => void;
  /** Right-aligned slot in the header (action buttons, status pill, etc.). */
  headerExtras?: React.ReactNode;
  /**
   * Optional sticky footer.  Used by the connect-wizard for Back /
   * Next / Cancel / Connect actions that need to stay visible while
   * the body scrolls.  Omit for tab-based drawers where actions live
   * inline in each tab.
   */
  footer?: React.ReactNode;
  /** Drawer body. */
  children: React.ReactNode;
  /**
   * Width preset.  Defaults to "lg" (the original aside's responsive
   * cap).  "md" is narrower for simpler dialogs; "xl" is wider for
   * dense edit forms.  All three caps are responsive — the drawer
   * is always full-width below the sm: breakpoint.
   */
  width?: "md" | "lg" | "xl";
}

// Responsive width caps matching the original aside's contract.
// Below sm: every variant goes full-width; above sm: the cap grows.
const WIDTH_CLASS: Record<NonNullable<Props["width"]>, string> = {
  md: "w-full sm:max-w-sm md:max-w-md lg:max-w-lg",
  lg: "w-full sm:max-w-md md:max-w-lg lg:max-w-xl",
  xl: "w-full sm:max-w-lg md:max-w-xl lg:max-w-2xl",
};

export function SideDrawer({
  open,
  onClose,
  title,
  subtitle,
  icon,
  iconGradient,
  tabs,
  activeTab,
  onTabChange,
  headerExtras,
  footer,
  children,
  width = "lg",
}: Props) {
  // Esc to close + body-scroll lock while open.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <>
      {/* Backdrop — fade-in via the small CSS keyframe declared in
          globals.css so we don't need tailwindcss-animate.  Click to
          close.  z-40 sits just under the panel's z-50. */}
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 vooda-fade-in"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel — slides in from the right via vooda-slide-in.  Uses
          the same #0a0a0d background as the original aside so a user
          flipping between drawers sees no visual seam. */}
      <aside
        className={`fixed inset-y-0 right-0 z-50 ${WIDTH_CLASS[width]} bg-[#0a0a0d] border-l border-white/[0.08] shadow-2xl flex flex-col vooda-slide-in`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        {/* Header — brand-glyph circle (optional) + title + subtitle
            on the left, headerExtras + close button on the right.
            Matches the original aside's spacing so the two surfaces
            don't visually jitter when a user moves between them. */}
        <div className="border-b border-white/[0.06] px-6 py-4 shrink-0">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              {icon && (
                <div
                  className={`w-9 h-9 rounded-lg bg-gradient-to-br ${
                    iconGradient || "from-violet-500 to-fuchsia-500"
                  } flex items-center justify-center shrink-0 text-white`}
                >
                  {icon}
                </div>
              )}
              <div className="min-w-0">
                <h2 className="text-sm font-semibold text-white truncate">
                  {title}
                </h2>
                {subtitle && (
                  <p className="text-[10px] text-slate-500 mt-0.5 truncate">
                    {subtitle}
                  </p>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {headerExtras}
              <button
                type="button"
                onClick={onClose}
                aria-label="Close"
                title="Close (Esc)"
                className="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded hover:bg-white/[0.04]"
              >
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>
          </div>

          {/* Tab strip */}
          {tabs && tabs.length > 0 && (
            <div className="mt-4 -mb-4 flex gap-1 overflow-x-auto">
              {tabs.map((tab) => {
                const isActive = tab.key === activeTab;
                return (
                  <button
                    key={tab.key}
                    type="button"
                    onClick={() => onTabChange?.(tab.key)}
                    className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-all whitespace-nowrap ${
                      isActive
                        ? "border-red-400 text-red-400"
                        : "border-transparent text-slate-400 hover:text-slate-200 hover:border-white/[0.1]"
                    }`}
                  >
                    {tab.label}
                    {tab.badge && (
                      <span
                        className={`text-[9px] px-1.5 py-0.5 rounded ${
                          tab.badgeClass || "bg-slate-500/15 text-slate-400"
                        }`}
                      >
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Body — scrolls independently of the optional sticky footer
            so long forms don't push the action buttons off-screen. */}
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>

        {/* Sticky footer (e.g. wizard Back/Next).  Matches the original
            aside's bg + spacing so footers look identical across
            drawers. */}
        {footer && (
          <div className="flex items-center justify-between gap-2 px-6 py-4 border-t border-white/[0.06] bg-[#0a0a0d] shrink-0">
            {footer}
          </div>
        )}
      </aside>
    </>
  );
}
