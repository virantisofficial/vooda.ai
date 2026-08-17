"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect, useMemo, useRef } from "react";
import Link from "next/link";
import { useAuthStore } from "@/lib/store";
import { usePathname, useRouter } from "next/navigation";
import {
  getMetricsOverview,
  getNotifications,
  markNotificationRead,
  markAllNotificationsRead,
} from "@/lib/api";

// Route → human label mapping for the breadcrumb. Built from the
// sidebar nav set plus the sub-pages that exist under each top-level
// route. Anything not in this map renders the URL slug raw (humanised
// — kebab-case → Title Case) so even unmapped pages get a readable
// crumb. Dynamic IDs (UUID-ish segments) are shown truncated to keep
// the bar from wrapping on deep URLs.
// Governance route labels (nhi, vault, federation, connectors,
// recommendations, supply-chain, sbom, policies, dsl, agents) removed
// 2026-05-16 — the corresponding pages were deleted to refocus on the
// secret-scanner core.
const ROUTE_LABELS: Record<string, string> = {
  dashboard: "Dashboard",
  repositories: "Repositories",
  sources: "Sources",
  findings: "Secrets",
  integrations: "Integrations",
  reports: "Reports",
  schedules: "Schedules",
  suppressions: "Suppressions",
  allowlists: "Allowlists",
  webhooks: "Webhooks",
  settings: "Settings",
  admin: "Admin",
  profile: "My Profile",
  docs: "Documentation",
  about: "About",
  "scan-jobs": "Scan Jobs",
  secrets: "Secrets",
  rotation: "Rotation",
  trends: "Trends",
  heatmap: "Heatmap",
};

// Heuristic: anything that looks like a UUID or numeric ID gets
// truncated rather than rendered raw. Keeps crumbs scannable even on
// /findings/3d8f...e91c style URLs.
function crumbLabel(segment: string): string {
  // UUID v4 or hex-ish 16+ char tokens
  if (/^[0-9a-f-]{12,}$/i.test(segment)) return segment.slice(0, 8) + "…";
  // Pure numeric IDs
  if (/^\d{4,}$/.test(segment)) return "#" + segment;
  if (ROUTE_LABELS[segment]) return ROUTE_LABELS[segment];
  // Fall back to humanised slug — "scan-jobs" → "Scan Jobs"
  return segment.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function buildBreadcrumbs(pathname: string): Array<{ label: string; href: string }> {
  if (!pathname || pathname === "/" || pathname === "/dashboard") return [];
  const segments = pathname.split("/").filter(Boolean);
  return segments.map((seg, i) => ({
    label: crumbLabel(seg),
    href: "/" + segments.slice(0, i + 1).join("/"),
  }));
}

/* ── Notification types ── */
interface Notification {
  id: string;
  title: string;
  body: string;
  type: "scan" | "finding" | "remediation" | "system" | "triage_health";
  severity: "info" | "warning" | "critical";
  time: string;
  read: boolean;
  link?: string;
}

// Human-friendly relative time (e.g. "5m", "2h", "3d") from an ISO timestamp.
function relativeTime(isoOrDate: string | Date | undefined): string {
  if (!isoOrDate) return "";
  const d = typeof isoOrDate === "string" ? new Date(isoOrDate) : isoOrDate;
  const diffMs = Date.now() - d.getTime();
  if (isNaN(diffMs)) return "";
  const s = Math.round(diffMs / 1000);
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const dy = Math.round(h / 24);
  return `${dy}d ago`;
}

function TypeIcon({ type }: { type: string }) {
  if (type === "finding")
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: "#fb923c" }}>
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    );
  if (type === "scan")
    return (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: "#22d3ee" }}>
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
      </svg>
    );
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: "#ef4444" }}>
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}

export default function Header({
  pageTitle,
  pageActions,
  pageBreadcrumb,
}: {
  /** Explicit H1 shown in the header when the page is at root (no
      breadcrumb trail). On non-root pages the breadcrumb's terminal
      crumb already serves as the title, so this prop is ignored. */
  pageTitle?: string;
  /** Page-specific hero controls slotted between the page identity
      zone and the notifications bell. Typically a time-range picker,
      an Add button, or an Export menu. */
  pageActions?: React.ReactNode;
  /** Full breadcrumb override.  When set, replaces the auto-derived
      pathname crumbs entirely.  Required for pages that use query
      params rather than path segments for navigation — e.g. the
      Integrations hub uses `/integrations?category=notifications`,
      so the pathname only has one segment ("integrations") and the
      auto-derived breadcrumb can't reflect the active category on
      its own.  Each entry: `{ label, href? }` — last entry is
      rendered as the H1, earlier entries as clickable nav links.
      Takes precedence over both pageTitle and pathname-derived
      crumbs.  Added 2026-05-14. */
  pageBreadcrumb?: Array<{ label: string; href?: string }>;
} = {}) {
  const { user, logout } = useAuthStore();
  const router = useRouter();
  // Single source of truth for the current path — Next.js App Router
  // `usePathname` reflects router pushes/replaces immediately.  All
  // SPA pages that update the URL now go through the router (the
  // Sources catalog used to bypass it with raw `replaceState`; that
  // path was switched to `router.replace`), so this stays in sync
  // with every navigation surface — direct URL, breadcrumb click,
  // browser back/forward, internal SPA state change.
  const pathname = usePathname() || "";

  // Breadcrumb derived from pathname. We strip the trailing crumb
  // for "leaf" pages that already render their own H1 — keeping the
  // crumb as a navigation aid back to the parent rather than a
  // duplicated label. The H1 on the page is the page title; the
  // breadcrumb is the trail to it.
  const crumbs = useMemo(() => buildBreadcrumbs(pathname || ""), [pathname]);

  // Crumb resolution priority (highest → lowest):
  //   1. `pageBreadcrumb` — full override, used by pages with query-
  //      param navigation (e.g. /integrations?category=...)
  //   2. `pageTitle` — replaces the terminal crumb label, used for
  //      detail routes where the URL segment is a UUID
  //   3. auto-derived from pathname (the default for most pages)
  //
  // The pageBreadcrumb entries are normalized to the same shape as
  // auto-derived crumbs ({ label, href }) — when href is omitted
  // we fall back to "" which the render path treats as non-navigable
  // (last crumb is always non-navigable, intermediate crumbs without
  // href render as a non-link span).
  const displayCrumbs = useMemo(() => {
    if (pageBreadcrumb && pageBreadcrumb.length > 0) {
      return pageBreadcrumb.map((c) => ({ label: c.label, href: c.href || "" }));
    }
    if (!pageTitle || crumbs.length === 0) return crumbs;
    return [...crumbs.slice(0, -1), { ...crumbs[crumbs.length - 1], label: pageTitle }];
  }, [crumbs, pageTitle, pageBreadcrumb]);

  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);

  const notifRef = useRef<HTMLDivElement>(null);
  const userRef = useRef<HTMLDivElement>(null);

  // Load real notifications from the backend (emitted by the worker — triage
  // health signals, etc.). Augment with live-metric hints (criticals, needs-
  // review) that are computed on each dashboard load.
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      const items: Notification[] = [];

      // Real persisted notifications from the DB.
      try {
        const r = await getNotifications({ limit: 20 });
        for (const n of r.data || []) {
          items.push({
            id: n.id,
            title: n.title,
            body: n.body || "",
            type: (n.notification_type || "system") as Notification["type"],
            severity: n.notification_type === "triage_health" ? "critical" : "info",
            time: relativeTime(n.created_at),
            read: !!n.is_read,
            link: n.resource_type === "ai_model"
              ? `/integrations?category=ai_models`
              : undefined,
          });
        }
      } catch { /* keep going with metric-hints even if API errors */ }

      // Derived live hints (not persisted — refresh each time bell loads).
      try {
        const r = await getMetricsOverview();
        const data = r.data || {};
        const criticals =
          (data.by_severity?.["Severity.CRITICAL"] ?? 0) + (data.by_severity?.["critical"] ?? 0);
        const needsReview =
          (data.by_classification?.["Classification.NEEDS_REVIEW"] ?? 0) +
          (data.by_classification?.["needs_review"] ?? 0);
        if (criticals > 0)
          items.push({
            id: "live:crit",
            title: `${criticals} critical findings`,
            body: "Immediate attention required.",
            type: "finding",
            severity: "critical",
            time: "Live",
            read: false,
            link: "/findings?severity=critical",
          });
        if (needsReview > 0)
          items.push({
            id: "live:review",
            title: `${needsReview} findings awaiting review`,
            body: "AI triage marked these as needs_review — hand-classify or re-triage.",
            type: "finding",
            severity: "warning",
            time: "Live",
            read: false,
            link: "/findings?classification=needs_review",
          });
      } catch { /* ignore — metric hints are optional */ }

      if (!cancelled) setNotifications(items);
    };
    load();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    const handle = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node))
        setShowNotifications(false);
      if (userRef.current && !userRef.current.contains(e.target as Node))
        setShowUserMenu(false);
    };
    document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, []);

  const handleLogout = () => { logout(); router.push("/login"); };
  const unreadCount = notifications.filter((n) => !n.read).length;
  const markAllRead = async () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    // Persist for DB-backed notifications; live-metric entries (id starts
    // with "live:") are ephemeral and have no backend row.
    try { await markAllNotificationsRead(); } catch { /* non-fatal */ }
  };
  const handleNotificationClick = (n: Notification) => {
    if (!n.read && !n.id.startsWith("live:")) {
      markNotificationRead(n.id).catch(() => {});
      setNotifications((prev) => prev.map((x) => x.id === n.id ? { ...x, read: true } : x));
    }
    setShowNotifications(false);
  };

  return (
    <header
      className="h-16 flex items-center justify-between px-6 sticky top-0 z-20"
      style={{
        // Glass header — translucent canvas + 12px backdrop-blur so the
        // content below softly bleeds through when the user scrolls.
        // Matches what Stripe Dashboard / Linear / Vercel ship. The 75%
        // base opacity keeps text contrast above WCAG AA on the brand
        // canvas, while -webkit-backdrop-filter ensures Safari renders
        // the blur (still required as of late-2025).
        background: "rgba(7, 9, 26, 0.72)",
        backdropFilter: "blur(12px) saturate(140%)",
        WebkitBackdropFilter: "blur(12px) saturate(140%)",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        boxShadow: "0 1px 0 rgba(255,255,255,0.03), 0 4px 16px rgba(0,0,0,0.2)",
      }}
    >
      {/* ── Left: Page identity (title or breadcrumb) + global search trigger ── */}
      <div className="flex items-center gap-3 min-w-0 flex-1">
        {/* The page identity zone. Three states:
            1) crumbs.length > 1 — render breadcrumb trail (terminal
               crumb acts as the H1, intermediate ones are nav links).
            2) crumbs.length === 1 — render just the single crumb as a
               compact H1; no leading home icon, no separator.
            3) crumbs.length === 0 — render the `pageTitle` prop as the
               H1 (root pages like /dashboard that have no trail).
            Either way exactly one element on the page reads as
            "you are here", and a page never duplicates H1+breadcrumb. */}
        {displayCrumbs.length > 1 ? (
          <nav aria-label="Breadcrumb" className="hidden sm:flex items-center gap-1.5 min-w-0">
            {displayCrumbs.map((c, i) => {
              const isLast = i === displayCrumbs.length - 1;
              return (
                <span key={c.href} className="flex items-center gap-1.5 min-w-0">
                  {i > 0 && (
                    <svg className="w-3 h-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{ color: "#2d3a52" }}>
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  )}
                  {isLast ? (
                    <h1 className="text-[16px] font-semibold truncate text-white m-0 tracking-tight" aria-current="page">
                      {c.label}
                    </h1>
                  ) : (
                    <Link
                      href={c.href}
                      className="text-[12px] truncate transition-colors"
                      style={{ color: "#475569" }}
                      onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "#94a3b8")}
                      onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "#475569")}
                    >
                      {c.label}
                    </Link>
                  )}
                </span>
              );
            })}
          </nav>
        ) : displayCrumbs.length === 1 ? (
          <h1 className="hidden sm:block text-[16px] font-semibold truncate text-white m-0 tracking-tight">
            {displayCrumbs[0].label}
          </h1>
        ) : pageTitle ? (
          <h1 className="hidden sm:block text-[16px] font-semibold truncate text-white m-0 tracking-tight">
            {pageTitle}
          </h1>
        ) : null}

        {/* Cmd+K palette is a SILENT feature — no visible trigger.
            Power users discover it through docs / onboarding tooltips
            and invoke it via the keyboard chord (⌘K on macOS, Ctrl+K
            elsewhere).  The global keydown listener lives in the
            `useCommandPalette` hook mounted in AppShell, so it stays
            active across every authenticated route. */}
      </div>

      <div className="flex items-center gap-2">
        {/* ── Page-specific actions ──
            Slot for the host page's hero control(s) — e.g. dashboard's
            time-range picker, or list pages' Export menu. Sits just
            before the notifications bell so the eye reads: identity
            (left) · search · page action · global icons (right). */}
        {pageActions && (
          <div className="flex items-center gap-2 mr-1">
            {pageActions}
          </div>
        )}

        {/* ── Notification Bell ── */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => { setShowNotifications(!showNotifications); setShowUserMenu(false); }}
            className="relative w-9 h-9 rounded-lg flex items-center justify-center transition-all duration-200"
            style={{ color: "#475569" }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.05)";
              (e.currentTarget as HTMLElement).style.color = "#94a3b8";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.background = "transparent";
              (e.currentTarget as HTMLElement).style.color = "#475569";
            }}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
            {unreadCount > 0 && (
              <span
                className="absolute top-1 right-1 min-w-[14px] h-3.5 px-1 flex items-center justify-center rounded-full text-[9px] font-bold text-white"
                style={{ background: "#ef4444", boxShadow: "0 0 8px rgba(239,68,68,0.6)" }}
              >
                {unreadCount}
              </span>
            )}
          </button>

          {showNotifications && (
            <div
              className="absolute right-0 top-11 w-96 z-50"
              style={{
                background: "rgba(8, 11, 28, 0.98)",
                border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: "12px",
                boxShadow: "0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(239,68,68,0.05)",
                overflow: "hidden",
              }}
            >
              <div
                className="flex items-center justify-between px-4 py-3"
                style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}
              >
                <h3 className="text-sm font-semibold text-white">Notifications</h3>
                <div className="flex items-center gap-3">
                  {unreadCount > 0 && (
                    <button
                      onClick={markAllRead}
                      className="text-[10px] transition-colors"
                      style={{ color: "#ef4444" }}
                      onMouseEnter={(e) => ((e.target as HTMLElement).style.color = "#f87171")}
                      onMouseLeave={(e) => ((e.target as HTMLElement).style.color = "#ef4444")}
                    >
                      Mark all read
                    </button>
                  )}
                  <span
                    className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
                    style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444" }}
                  >
                    {notifications.length}
                  </span>
                </div>
              </div>

              <div className="max-h-[340px] overflow-y-auto">
                {notifications.map((n) => {
                  const inner = (
                    <div
                      key={n.id}
                      className="flex gap-3 px-4 py-3 transition-colors"
                      style={{
                        borderBottom: "1px solid rgba(255,255,255,0.03)",
                        background: !n.read ? "rgba(239,68,68,0.03)" : "transparent",
                      }}
                      onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.025)")}
                      onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = !n.read ? "rgba(239,68,68,0.03)" : "transparent")}
                    >
                      <div
                        className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
                        style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.06)" }}
                      >
                        <TypeIcon type={n.type} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start gap-2">
                          <p className={`text-[13px] leading-snug flex-1 ${!n.read ? "text-slate-200 font-medium" : "text-slate-400"}`}>
                            {n.title}
                          </p>
                          <span
                            className="w-1.5 h-1.5 rounded-full shrink-0 mt-1.5"
                            style={{
                              background:
                                n.severity === "critical"
                                  ? "#f87171"
                                  : n.severity === "warning"
                                  ? "#fbbf24"
                                  : "#ef4444",
                            }}
                          />
                        </div>
                        <p className="text-[11px] text-slate-500 mt-0.5 line-clamp-1">{n.body}</p>
                        <p className="text-[10px] mt-1" style={{ color: "#2d3a52" }}>{n.time}</p>
                      </div>
                    </div>
                  );
                  return n.link ? (
                    <Link key={n.id} href={n.link} onClick={() => handleNotificationClick(n)}>
                      {inner}
                    </Link>
                  ) : (
                    <button
                      key={n.id}
                      onClick={() => handleNotificationClick(n)}
                      className="block w-full text-left"
                    >
                      {inner}
                    </button>
                  );
                })}
              </div>

              <div
                className="px-4 py-2.5"
                style={{ borderTop: "1px solid rgba(255,255,255,0.05)", background: "rgba(255,255,255,0.01)" }}
              >
                <Link
                  href="/integrations?category=notifications"
                  onClick={() => setShowNotifications(false)}
                  className="text-[11px] transition-colors"
                  style={{ color: "#475569" }}
                  onMouseEnter={(e) => ((e.target as HTMLElement).style.color = "#94a3b8")}
                  onMouseLeave={(e) => ((e.target as HTMLElement).style.color = "#475569")}
                >
                  Notification settings →
                </Link>
              </div>
            </div>
          )}
        </div>

        {/* ── User Avatar ── */}
        {user && (
          <div className="relative" ref={userRef}>
            <button
              onClick={() => { setShowUserMenu(!showUserMenu); setShowNotifications(false); }}
              className="flex items-center gap-2.5 pl-2.5 ml-1 rounded-lg py-1.5 pr-2 transition-all duration-200"
              style={{ borderLeft: "1px solid rgba(255,255,255,0.06)" }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.03)")}
              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = "transparent")}
            >
              <div
                className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white shrink-0"
                style={{
                  background: "linear-gradient(135deg, #dc2626 0%, #ea580c 100%)",
                  boxShadow: "0 2px 8px rgba(220,38,38,0.4)",
                }}
              >
                {user.full_name?.charAt(0) || "U"}
              </div>
              <div className="hidden md:block text-left">
                <p className="text-[13px] font-medium text-slate-200 leading-tight">{user.full_name}</p>
                <p className="text-[11px] text-slate-500 leading-tight">{user.email}</p>
              </div>
              <svg
                className={`w-3.5 h-3.5 text-slate-600 transition-transform hidden md:block ${showUserMenu ? "rotate-180" : ""}`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            {showUserMenu && (
              <div
                className="absolute right-0 top-full mt-2 w-64 z-50"
                style={{
                  background: "rgba(8, 11, 28, 0.98)",
                  border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: "12px",
                  boxShadow: "0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(239,68,68,0.05)",
                  overflow: "hidden",
                  marginTop: "8px",
                }}
              >
                {/* User header */}
                <div className="px-4 py-3.5" style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                  <div className="flex items-center gap-3">
                    <div
                      className="w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold text-white shrink-0"
                      style={{
                        background: "linear-gradient(135deg, #dc2626 0%, #ea580c 100%)",
                        boxShadow: "0 2px 10px rgba(220,38,38,0.4)",
                      }}
                    >
                      {user.full_name?.charAt(0) || "U"}
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">{user.full_name}</p>
                      <p className="text-xs text-slate-500 truncate">{user.email}</p>
                    </div>
                  </div>
                  {user.roles?.length > 0 && (
                    <div className="mt-2.5 flex gap-1.5 flex-wrap">
                      {user.roles.map((role) => (
                        <span
                          key={role}
                          className="text-[9px] px-2 py-0.5 rounded-full capitalize font-medium"
                          style={{
                            background: "rgba(239,68,68,0.1)",
                            color: "#f87171",
                            border: "1px solid rgba(239,68,68,0.2)",
                          }}
                        >
                          {role}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="py-1">
                  <DropdownLink
                    href="/profile"
                    label="My Profile"
                    onClick={() => setShowUserMenu(false)}
                    icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />}
                  />
                  <DropdownLink
                    href="/settings/admin?tab=organization"
                    label="Organization"
                    onClick={() => setShowUserMenu(false)}
                    icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />}
                  />
                  <DropdownLink
                    href="/docs"
                    label="Documentation"
                    newTab
                    onClick={() => setShowUserMenu(false)}
                    icon={<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />}
                  />
                </div>

                {/* Sign out */}
                <div className="py-1" style={{ borderTop: "1px solid rgba(255,255,255,0.05)" }}>
                  <button
                    onClick={() => { setShowUserMenu(false); handleLogout(); }}
                    className="w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-colors"
                    style={{ color: "#f87171" }}
                    onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = "rgba(248,113,113,0.06)")}
                    onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = "transparent")}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                    </svg>
                    Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  );
}

/* ── Dropdown menu link ── */
function DropdownLink({
  href, icon, label, onClick, newTab,
}: {
  href: string;
  icon: React.ReactNode;
  label: string;
  onClick?: () => void;
  newTab?: boolean;
}) {
  return (
    <Link
      href={href}
      onClick={onClick}
      target={newTab ? "_blank" : undefined}
      rel={newTab ? "noopener" : undefined}
      className="flex items-center gap-3 px-4 py-2.5 text-sm transition-colors"
      style={{ color: "#94a3b8" }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)";
        (e.currentTarget as HTMLElement).style.color = "#e2e8f0";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLElement).style.background = "transparent";
        (e.currentTarget as HTMLElement).style.color = "#94a3b8";
      }}
    >
      <svg className="w-4 h-4 text-slate-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        {icon}
      </svg>
      <span className="flex-1">{label}</span>
      {newTab && (
        <svg className="w-3 h-3 text-slate-700 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
        </svg>
      )}
    </Link>
  );
}
