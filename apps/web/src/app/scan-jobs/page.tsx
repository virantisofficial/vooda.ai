// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
import { redirect } from "next/navigation";

// Scan jobs are viewed per-repository (Repositories → a repo → Scans).
// There is no global scan-jobs index, so send the bare route there
// instead of 404-ing.
export default function ScanJobsIndex() {
  redirect("/repositories");
}
