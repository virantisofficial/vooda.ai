"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import Link from "next/link";
import { usePathname } from "next/navigation";
import { clsx } from "clsx";
import { APP_VERSION } from "@/lib/constants";

const navItems = [
  {
    href: "/dashboard",
    label: "Dashboard",
    icon: (
      <svg className="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
      </svg>
    ),
  },
  {
    href: "/repositories",
    label: "Repositories",
    icon: (
      <svg className="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
      </svg>
    ),
  },
  {
    href: "/sources",
    label: "Sources",
    icon: (
      <svg className="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
      </svg>
    ),
  },
  {
    href: "/findings",
    label: "Secrets",
    icon: (
      <svg className="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
      </svg>
    ),
  },
  // Governance nav item removed 2026-05-15 — the /nhi, /agents,
  // /policies, /supply-chain surfaces were deviating from the
  // secret-scanner core (NHI / Supply Chain / Policy DSL are
  // separate product categories with dedicated specialists like
  // Astrix, Snyk Open Source, Apiiro).  Vooda focuses on
  // best-in-class secret scanning.  Allowlists + Suppressions
  // (the scanner-core governance bits) are surfaced under Settings.
  {
    href: "/integrations",
    label: "Integrations",
    icon: (
      <svg className="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
      </svg>
    ),
  },
  {
    href: "/settings/admin",
    label: "Settings",
    icon: (
      <svg className="w-[18px] h-[18px] shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      </svg>
    ),
  },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      className="sidebar-root fixed left-0 top-0 h-full z-30 flex flex-col"
      style={{
        background: "rgba(6, 8, 22, 0.98)",
        borderRight: "1px solid rgba(255,255,255,0.05)",
        boxShadow: "4px 0 24px rgba(0,0,0,0.4)",
      }}
    >
      {/* ── Logo ── */}
      <div className="h-16 flex items-center px-3.5 shrink-0 overflow-hidden">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 overflow-hidden"
            style={{ background: "#080808", boxShadow: "0 2px 12px rgba(220,38,38,0.35), 0 0 0 1px rgba(239,68,68,0.2)" }}
          >
            <img src="/logo-icon.svg" alt="Vooda AI" className="w-7 h-7" />
          </div>
          <span
            className="sidebar-logo-text text-[13px] font-semibold tracking-tight"
            style={{ color: "#e2e8f0" }}
          >
            Vooda AI
          </span>
        </div>
      </div>

      {/* ── Divider ── */}
      <div className="mx-3 h-px" style={{ background: "rgba(255,255,255,0.04)" }} />

      {/* ── Navigation ── */}
      <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-hidden">
        {navItems.map((item) => {
          const isActive = pathname?.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                "flex items-center gap-2.5 px-2.5 py-2.5 rounded-lg transition-all duration-200 overflow-hidden relative",
                isActive
                  ? "text-white"
                  : "hover:text-slate-200"
              )}
              style={
                isActive
                  ? {
                      background: "rgba(239, 68, 68, 0.15)",
                      border: "1px solid rgba(239, 68, 68, 0.2)",
                      boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)",
                    }
                  : {
                      color: "#475569",
                      border: "1px solid transparent",
                    }
              }
              onMouseEnter={(e) => {
                if (!isActive) {
                  (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.04)";
                  (e.currentTarget as HTMLElement).style.color = "#cbd5e1";
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  (e.currentTarget as HTMLElement).style.background = "transparent";
                  (e.currentTarget as HTMLElement).style.color = "#475569";
                }
              }}
            >
              {/* Active indicator bar */}
              {isActive && (
                <span
                  className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 rounded-r"
                  style={{ background: "linear-gradient(180deg, #f87171 0%, #dc2626 100%)" }}
                />
              )}

              <span
                style={{ color: isActive ? "#f87171" : "inherit" }}
              >
                {item.icon}
              </span>

              <span
                className="sidebar-label text-[13px] font-medium"
              >
                {item.label}
              </span>
            </Link>
          );
        })}
      </nav>

      {/* ── Footer ── */}
      <div className="shrink-0 overflow-hidden">
        <div className="mx-3 h-px mb-2" style={{ background: "rgba(255,255,255,0.04)" }} />
        <div className="px-3.5 pb-4 flex items-center">
          <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: "rgba(239, 68, 68, 0.4)" }} />
          <span className="sidebar-label ml-2 text-[10px] font-mono" style={{ color: "#2d3a52" }}>
            v{APP_VERSION}
          </span>
        </div>
      </div>
    </aside>
  );
}
