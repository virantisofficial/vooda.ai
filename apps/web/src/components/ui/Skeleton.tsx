// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/*
 * Skeleton loaders — replace pop-in spinners with shape-preserving
 * placeholders. The pattern is a load-time scaffold that mirrors the
 * final layout so users see structure immediately and the eventual
 * paint feels like content sliding into place rather than a fresh
 * render.
 *
 * Three layers:
 *   1. <Skeleton /> — primitive grey block (one DOM node).
 *   2. <SkeletonKpiTile /> — opinionated KPI-tile shape used on dash.
 *   3. <SkeletonTableRow /> — opinionated table row used on lists.
 *
 * Pages compose layers 2/3 into a full-page scaffold. Each page owns
 * its own scaffold (the dashboard's 4×2 grid is different from the
 * findings table) but every block reads from the same shimmer token
 * in globals.css so the loading state has a single visual language.
 */

import type { CSSProperties } from "react";

interface SkeletonProps {
  /** Width — number is treated as px, string passes through. */
  w?: number | string;
  /** Height — number is treated as px, string passes through. */
  h?: number | string;
  /** Border-radius override (default: 6px from the .skeleton token). */
  radius?: number | string;
  className?: string;
  style?: CSSProperties;
}

export function Skeleton({ w, h = 12, radius, className = "", style }: SkeletonProps) {
  return (
    <div
      className={`skeleton ${className}`}
      style={{
        width: typeof w === "number" ? `${w}px` : w,
        height: typeof h === "number" ? `${h}px` : h,
        borderRadius: typeof radius === "number" ? `${radius}px` : radius,
        ...style,
      }}
      aria-hidden="true"
    />
  );
}

/** Mirror the dashboard KPI tile (number + label + sub-text). */
export function SkeletonKpiTile() {
  return (
    <div className="card p-5">
      <Skeleton w={90} h={10} />
      <Skeleton w={70} h={28} className="mt-2" />
      <Skeleton w="60%" h={10} className="mt-2" />
    </div>
  );
}

/** Mirror a single table-style list row. */
export function SkeletonTableRow({ cols = 5 }: { cols?: number }) {
  return (
    <div className="flex items-center gap-3 py-3 px-2" style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
      {Array.from({ length: cols }).map((_, i) => (
        <Skeleton key={i} w={i === 0 ? 60 : i === 1 ? "40%" : "15%"} h={12} />
      ))}
    </div>
  );
}

/** Mirror a generic card body (heading + 4 rows). */
export function SkeletonCard({ rows = 4 }: { rows?: number }) {
  return (
    <div className="card">
      <Skeleton w={140} h={12} />
      <div className="mt-4 space-y-3">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center gap-3">
            <Skeleton w={36} h={36} radius={8} />
            <div className="flex-1 space-y-1.5">
              <Skeleton w="70%" h={10} />
              <Skeleton w="40%" h={8} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
