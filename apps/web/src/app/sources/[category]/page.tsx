"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * Dynamic deep-link route for the Sources catalog.
 *
 * Matches /sources/<category>, e.g. /sources/collaboration,
 * /sources/docs-wikis, /sources/cloud-storage. Renders the same
 * SourcesPage component the catalog uses, but seeds it with the
 * category segment so the user lands directly on that category
 * (drilldown view), bookmarkable and back-button-friendly.
 *
 * Added 2026-05-08 to fix the 404 on direct deep-links to category
 * pages — previously /sources/<category> returned 404 because the
 * Sources page was a single SPA at /sources with no sub-routes and
 * the in-app docs referenced `/sources/<category>` URLs that didn't
 * resolve.
 */

import { use } from "react";

import SourcesPage from "../page";

export default function SourcesCategoryPage({
  params,
}: {
  // Next.js 15: route params are async (a Promise) and must be
  // unwrapped with React.use() in a client component before reading.
  params: Promise<{ category: string }>;
}) {
  const { category } = use(params);
  return <SourcesPage initialCategory={category} />;
}
