"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import AuthGuard from "./AuthGuard";
import Sidebar from "./Sidebar";
import Header from "./Header";
import CommandPalette, { useCommandPalette } from "@/components/ui/CommandPalette";

/*
 * AppShell — the chrome around every authenticated page.
 *
 * Pages can promote their primary identity (title) and one or two
 * hero controls (e.g. a time-range picker, an "Add" button) up into
 * the sticky header via the `pageTitle` and `pageActions` props.
 * This collapses the old layout pattern (sticky header row + page
 * H1 row + page controls row) into a single horizontal band, which
 * is what Stripe / Linear / Vercel ship.
 *
 * Pages that don't pass `pageTitle` fall back to the breadcrumb
 * trail derived from the pathname — the last crumb is rendered as
 * the de-facto title, so non-root pages get a header H1 "for free"
 * without any per-page wiring.
 *
 * Pages that don't pass `pageActions` simply leave that header slot
 * empty; the search trigger + notifications + avatar still occupy
 * the rest of the bar.
 */
export default function AppShell({
  children,
  pageTitle,
  pageActions,
  pageBreadcrumb,
}: {
  children: React.ReactNode;
  /** Optional explicit H1 text shown in the header (used by root
      pages like /dashboard where there is no breadcrumb trail). */
  pageTitle?: string;
  /** Optional right-side header controls — e.g. dashboard's
      time-range picker. Rendered between the page identity and the
      notifications bell. */
  pageActions?: React.ReactNode;
  /** Optional full breadcrumb override.  See Header's pageBreadcrumb
      prop for the full contract.  Used by pages with query-param
      navigation (e.g. /integrations?category=...) where the
      auto-derived pathname crumbs can't reflect the active section. */
  pageBreadcrumb?: Array<{ label: string; href?: string }>;
}) {
  // Global Cmd+K palette — SILENT feature. The chord (⌘K / Ctrl+K)
  // is bound by `useCommandPalette` and active across every route;
  // there is no visible trigger in the header chrome. Users discover
  // the chord via docs or onboarding rather than a button.
  const [paletteOpen, setPaletteOpen] = useCommandPalette();
  return (
    <AuthGuard>
      <div className="flex min-h-screen" style={{ background: "var(--bg-base)" }}>
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0 main-content">
          <Header pageTitle={pageTitle} pageActions={pageActions} pageBreadcrumb={pageBreadcrumb} />
          <main className="flex-1 p-6 overflow-auto">{children}</main>
        </div>
      </div>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </AuthGuard>
  );
}
