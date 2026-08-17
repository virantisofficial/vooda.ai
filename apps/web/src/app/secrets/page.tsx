// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
import { redirect } from "next/navigation";

// "Secrets" in the sidebar resolves to the Findings list; the analytics
// sub-pages live under /secrets/{trends,rotation,heatmap}. The bare
// /secrets route has no index, so send it to the Findings list.
export default function SecretsIndex() {
  redirect("/findings");
}
