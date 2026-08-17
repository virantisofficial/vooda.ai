// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
import { redirect } from "next/navigation";

// Incidents (deduplicated unique credentials) are listed on the Findings
// page in incidents view. The bare /incidents route has no index of its
// own, so send it to the canonical incidents list.
export default function IncidentsIndex() {
  redirect("/findings?view=incidents");
}
