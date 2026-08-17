"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useMemo } from "react";

interface Defect {
  defect_id: string;
  name: string;
  short_description: string;
  full_description: string;
  severity: string;
  status: string;
  category: string;
  cwe: string | null;
  file_path: string | null;
  line_number: number | null;
  assignee: string | null;
  detected_date: string | null;
  scanner_url: string | null;
  raw_data: Record<string, any>;
}

interface Props {
  defects: Defect[];
  availableColumns: string[];
  totalCount: number;
}

const DEFAULT_COLUMNS = ["defect_id", "name", "severity", "status", "file_path", "line_number"];

const COLUMN_LABELS: Record<string, string> = {
  defect_id: "Defect ID",
  name: "Name",
  short_description: "Description",
  severity: "Severity",
  status: "Status",
  category: "Category",
  cwe: "CWE",
  file_path: "File",
  line_number: "Line",
  assignee: "Assignee",
  detected_date: "Detected",
  scanner_url: "Link",
};

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-green-500",
    info: "bg-slate-500",
  };
  return (
    <span className="flex items-center gap-2">
      <span className={`w-2 h-2 rounded-full ${colors[severity] || colors.medium}`} />
      <span className="capitalize">{severity}</span>
    </span>
  );
}

export default function DefectTable({ defects, availableColumns, totalCount }: Props) {
  const [activeColumns, setActiveColumns] = useState<string[]>(DEFAULT_COLUMNS);
  const [showColumnPicker, setShowColumnPicker] = useState(false);
  const [hoveredDefect, setHoveredDefect] = useState<string | null>(null);
  const [sortColumn, setSortColumn] = useState<string>("severity");
  const [sortAsc, setSortAsc] = useState(false);
  const [selectedDefects, setSelectedDefects] = useState<Set<string>>(new Set());

  // All possible columns = default + what scanner reports
  const allColumns = useMemo(() => {
    const cols = new Set([...DEFAULT_COLUMNS, ...availableColumns]);
    return Array.from(cols);
  }, [availableColumns]);

  const toggleColumn = (col: string) => {
    setActiveColumns((prev) =>
      prev.includes(col) ? prev.filter((c) => c !== col) : [...prev, col]
    );
  };

  const sortedDefects = useMemo(() => {
    return [...defects].sort((a, b) => {
      const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      if (sortColumn === "severity") {
        const diff = (sevOrder[a.severity] ?? 3) - (sevOrder[b.severity] ?? 3);
        return sortAsc ? diff : -diff;
      }
      const aVal = String((a as any)[sortColumn] || a.raw_data[sortColumn] || "");
      const bVal = String((b as any)[sortColumn] || b.raw_data[sortColumn] || "");
      return sortAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });
  }, [defects, sortColumn, sortAsc]);

  const toggleSort = (col: string) => {
    if (sortColumn === col) setSortAsc(!sortAsc);
    else { setSortColumn(col); setSortAsc(false); }
  };

  const toggleSelectAll = () => {
    if (selectedDefects.size === defects.length) {
      setSelectedDefects(new Set());
    } else {
      setSelectedDefects(new Set(defects.map((d) => d.defect_id)));
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedDefects((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const getCellValue = (defect: Defect, col: string) => {
    // Known fields
    if (col in defect && (defect as any)[col] != null) return (defect as any)[col];
    // Fallback to raw_data
    return defect.raw_data[col] ?? "—";
  };

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-sm text-slate-400">
            {totalCount} defects loaded
          </span>
          {selectedDefects.size > 0 && (
            <span className="text-sm text-red-400 font-medium">
              {selectedDefects.size} selected for scan
            </span>
          )}
        </div>
        <div className="relative">
          <button
            onClick={() => setShowColumnPicker(!showColumnPicker)}
            className="flex items-center gap-2 text-xs text-slate-400 hover:text-slate-200 px-3 py-2 rounded-lg hover:bg-white/[0.04] transition-colors"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
            </svg>
            Customize Columns
          </button>
          {showColumnPicker && (
            <div className="absolute right-0 top-10 z-30 w-64 card border-white/[0.1] p-3 max-h-72 overflow-y-auto">
              <p className="text-xs text-slate-500 mb-2 font-medium uppercase tracking-wider">Toggle Columns</p>
              {allColumns.map((col) => (
                <label key={col} className="flex items-center gap-2 py-1.5 cursor-pointer hover:bg-white/[0.04] rounded px-2 -mx-1">
                  <input
                    type="checkbox"
                    checked={activeColumns.includes(col)}
                    onChange={() => toggleColumn(col)}
                    className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-red-500"
                  />
                  <span className="text-sm text-slate-300">{COLUMN_LABELS[col] || col}</span>
                </label>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="px-4 py-3 w-10">
                  <input
                    type="checkbox"
                    checked={selectedDefects.size === defects.length && defects.length > 0}
                    onChange={toggleSelectAll}
                    className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-red-500"
                  />
                </th>
                {activeColumns.map((col) => (
                  <th
                    key={col}
                    onClick={() => toggleSort(col)}
                    className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider cursor-pointer hover:text-slate-300 transition-colors select-none whitespace-nowrap"
                  >
                    <span className="flex items-center gap-1">
                      {COLUMN_LABELS[col] || col}
                      {sortColumn === col && (
                        <svg className={`w-3 h-3 ${sortAsc ? "" : "rotate-180"}`} fill="currentColor" viewBox="0 0 20 20">
                          <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
                        </svg>
                      )}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {sortedDefects.map((defect) => (
                <tr
                  key={defect.defect_id}
                  className={`hover:bg-white/[0.02] transition-colors relative ${selectedDefects.has(defect.defect_id) ? "bg-red-500/[0.03]" : ""}`}
                  onMouseEnter={() => setHoveredDefect(defect.defect_id)}
                  onMouseLeave={() => setHoveredDefect(null)}
                >
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selectedDefects.has(defect.defect_id)}
                      onChange={() => toggleSelect(defect.defect_id)}
                      className="w-3.5 h-3.5 rounded border-slate-600 bg-dark-950 text-red-500"
                    />
                  </td>
                  {activeColumns.map((col) => (
                    <td key={col} className="px-4 py-3 whitespace-nowrap">
                      {col === "severity" ? (
                        <SeverityDot severity={defect.severity} />
                      ) : col === "name" ? (
                        <div className="relative group max-w-xs">
                          <span className="text-slate-200 font-medium truncate block">{defect.name}</span>
                          {/* Tooltip with full description on hover */}
                          {hoveredDefect === defect.defect_id && defect.full_description && (
                            <div className="absolute left-0 top-full mt-2 z-40 w-80 p-3 rounded-lg border border-white/[0.1] shadow-xl text-xs text-slate-300 leading-relaxed" style={{ background: "rgba(8,11,28,0.95)",  }}>
                              <p className="font-medium text-slate-200 mb-1">{defect.name}</p>
                              <p>{defect.full_description.slice(0, 300)}{defect.full_description.length > 300 ? "..." : ""}</p>
                              {defect.cwe && <p className="mt-2 text-red-400">{defect.cwe}</p>}
                            </div>
                          )}
                        </div>
                      ) : col === "short_description" ? (
                        <span className="text-slate-400 truncate block max-w-xs" title={defect.full_description}>
                          {defect.short_description.slice(0, 80)}{defect.short_description.length > 80 ? "..." : ""}
                        </span>
                      ) : col === "file_path" ? (
                        <span className="text-slate-400 font-mono text-xs truncate block max-w-[200px]">
                          {defect.file_path || "—"}
                        </span>
                      ) : col === "scanner_url" && defect.scanner_url ? (
                        <a href={defect.scanner_url} target="_blank" rel="noopener noreferrer" className="text-red-400 hover:text-red-300 text-xs">
                          Open ↗
                        </a>
                      ) : col === "detected_date" ? (
                        <span className="text-slate-500 text-xs">
                          {defect.detected_date ? new Date(defect.detected_date).toLocaleDateString() : "—"}
                        </span>
                      ) : (
                        <span className="text-slate-400">{String(getCellValue(defect, col))}</span>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
