"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import AuthGuard from "@/components/layout/AuthGuard";

/**
 * Docs layout — standalone full-screen, no AppShell sidebar.
 * Still requires authentication via AuthGuard.
 */
export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return <AuthGuard>{children}</AuthGuard>;
}
