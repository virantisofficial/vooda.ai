"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * ExportDropdown — shared between the /findings page (per-finding
 * export, full CSV/JSON/SARIF/SPDX format menu via
 * /reports/export/{format}) and the Incidents view (per-credential
 * CSV via /incidents/export/csv).
 *
 * Extracted from findings/page.tsx so IncidentsView can mount it
 * using its own filter state without prop-drilling through the
 * parent.  Behavior unchanged from the original inline component.
 */

import { useState } from "react";

import api from "@/lib/api";
import { useToast } from "@/components/ui/Toast";

interface Props {
  filters: Record<string, string>;
  /**
   * "findings" (default): full format menu hitting /reports/export.
   * "incidents": CSV only, hits /incidents/export/csv.  Incidents are
   *   a credential-level rollup — SARIF/SPDX don't fit that data
   *   shape so we deliberately don't surface those format options.
   */
  kind?: "findings" | "incidents";
}

export function ExportDropdown({ filters, kind = "findings" }: Props) {
  const [open, setOpen] = useState(false);
  const [exporting, setExporting] = useState("");
  const { toast } = useToast();

  const formats =
    kind === "incidents"
      ? [{ id: "csv", label: "CSV", icon: "📄" }]
      : [
          { id: "csv", label: "CSV", icon: "📄" },
          { id: "json", label: "JSON", icon: "{ }" },
          { id: "sarif", label: "SARIF 2.1", icon: "🔍" },
          { id: "spdx", label: "SPDX 2.3", icon: "📦" },
        ];

  const handleExport = async (format: string) => {
    setExporting(format);
    setOpen(false);
    try {
      let path: string;
      let filename: string;
      if (kind === "incidents") {
        const params = new URLSearchParams(
          Object.fromEntries(Object.entries(filters).filter(([, v]) => v)),
        );
        path = `/incidents/export/csv?${params.toString()}`;
        filename = "vooda-incidents.csv";
      } else {
        const params = new URLSearchParams({
          report_type: "findings",
          ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)),
        });
        path = `/reports/export/${format}?${params.toString()}`;
        const ext: Record<string, string> = {
          csv: "csv",
          json: "json",
          pdf: "pdf",
          sarif: "sarif",
          spdx: "spdx.json",
        };
        filename = `vooda-findings.${ext[format] || format}`;
      }
      const response = await api.get(path, { responseType: "blob" });
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      window.URL.revokeObjectURL(url);
      toast(
        "success",
        "Export Complete",
        `${kind === "incidents" ? "Incidents" : "Findings"} exported as ${format.toUpperCase()}`,
      );
    } catch {
      toast("error", "Export Failed", "Could not generate the export file");
    } finally {
      setExporting("");
    }
  };

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        disabled={!!exporting}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 border border-white/[0.07] hover:bg-white/[0.04] transition-all"
      >
        {exporting ? (
          <div
            className="w-3 h-3 rounded-full animate-spin"
            style={{ borderWidth: 1, borderColor: "rgba(239,68,68,0.2)", borderTopColor: "#ef4444" }}
          />
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
            />
          </svg>
        )}
        Export
        <svg
          className={`w-3 h-3 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div
            className="absolute right-0 top-full mt-1 z-20 w-40 py-1 rounded-lg border border-white/[0.07] shadow-xl"
            style={{ background: "rgba(14,18,40,0.95)" }}
          >
            {formats.map((fmt) => (
              <button
                key={fmt.id}
                onClick={() => handleExport(fmt.id)}
                className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-white/[0.04] flex items-center gap-2"
              >
                <span className="w-4 text-center">{fmt.icon}</span> {fmt.label}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
