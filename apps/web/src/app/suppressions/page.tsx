"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import AppShell from "@/components/layout/AppShell";
import { SuppressionsContent } from "@/components/secrets/SuppressionsContent";

export default function SuppressionsPage() {
  return <AppShell><SuppressionsContent /></AppShell>;
}
