"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect, useRef, useCallback } from "react";

interface SearchableSelectProps {
  label: string;
  placeholder?: string;
  items: { id: string; name: string; detail?: string }[];
  value: string;
  onChange: (id: string) => void;
  required?: boolean;
  emptyText?: string;
  clearable?: boolean;
  /** Server-side search: called with query string, should update `items` externally */
  onSearch?: (query: string) => void;
  /** Show loading spinner in dropdown */
  searching?: boolean;
}

export default function SearchableSelect({
  label,
  placeholder,
  items,
  value,
  onChange,
  required,
  emptyText,
  clearable = true,
  onSearch,
  searching,
}: SearchableSelectProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  useEffect(() => {
    if (open && inputRef.current) inputRef.current.focus();
  }, [open]);

  // Debounced server-side search
  const handleSearchChange = useCallback((val: string) => {
    setSearch(val);
    if (onSearch) {
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => onSearch(val), 300);
    }
  }, [onSearch]);

  // Trigger initial load when dropdown opens in server-search mode
  useEffect(() => {
    if (open && onSearch && items.length === 0) {
      onSearch("");
    }
  }, [open, onSearch, items.length]);

  // Client-side filtering only when no server search
  const filtered = onSearch ? items : items.filter((i) =>
    i.name.toLowerCase().includes(search.toLowerCase())
  );

  const selectedItem = items.find((i) => i.id === value);

  return (
    <div ref={containerRef}>
      <label className="block text-sm font-medium text-slate-400 mb-1.5">
        {label}
        {required && <span className="text-red-400 ml-1">*</span>}
      </label>

      {/* Collapsed: trigger button */}
      {!open && (
        <button
          type="button"
          onClick={() => { setOpen(true); setSearch(""); if (onSearch) onSearch(""); }}
          className="w-full flex items-center gap-2 px-3 py-2.5 rounded-lg border border-white/[0.08] bg-white/[0.02] hover:border-white/[0.15] text-sm text-left transition-all"
        >
          <svg className="w-4 h-4 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <span className={`flex-1 truncate ${selectedItem ? "text-slate-200" : "text-slate-500"}`}>
            {selectedItem ? selectedItem.name : placeholder || "Search and select..."}
          </span>
          {selectedItem && clearable ? (
            <span
              onClick={(e) => { e.stopPropagation(); onChange(""); }}
              className="text-slate-500 hover:text-red-400 transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </span>
          ) : (
            <svg className="w-3.5 h-3.5 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          )}
        </button>
      )}

      {/* Expanded: search + list */}
      {open && (
        <div className="rounded-lg border border-red-500/20 bg-[rgba(8,11,28,0.95)] backdrop-blur-xl overflow-hidden shadow-lg">
          {/* Search bar */}
          <div className="px-3 py-2 border-b border-white/[0.06]">
            <div className="flex items-center gap-2">
              {searching ? (
                <div className="w-4 h-4 rounded-full border-2 animate-spin shrink-0" style={{ borderColor: "rgba(239,68,68,0.2)", borderTopColor: "#ef4444" }} />
              ) : (
                <svg className="w-4 h-4 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              )}
              <input
                ref={inputRef}
                value={search}
                onChange={(e) => handleSearchChange(e.target.value)}
                placeholder={placeholder || "Type to search..."}
                className="flex-1 bg-transparent text-sm text-slate-200 placeholder-slate-500 outline-none"
              />
              {search && (
                <button type="button" onClick={() => handleSearchChange("")} className="text-slate-500 hover:text-slate-300">
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              )}
            </div>
          </div>

          {/* Options list */}
          <div className="overflow-y-auto max-h-[12rem]">
            {items.length === 0 && !searching ? (
              <div className="px-3 py-4 text-xs text-slate-500 text-center">{emptyText || "No items available"}</div>
            ) : filtered.length === 0 && !searching ? (
              <div className="px-3 py-4 text-xs text-slate-500 text-center">No matches for &ldquo;{search}&rdquo;</div>
            ) : (
              filtered.map((item) => {
                const isSelected = item.id === value;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => { onChange(item.id); setOpen(false); setSearch(""); }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 text-left text-sm transition-colors hover:bg-red-500/10 ${isSelected ? "bg-white/[0.03]" : ""}`}
                  >
                    <span className={`w-4 h-4 rounded-full border flex items-center justify-center shrink-0 transition-colors ${isSelected ? "bg-red-500/20 border-red-500/40" : "border-white/[0.15] bg-white/[0.02]"}`}>
                      {isSelected && (
                        <svg className="w-2.5 h-2.5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                        </svg>
                      )}
                    </span>
                    <span className={`truncate ${isSelected ? "text-red-300 font-medium" : "text-slate-300"}`}>{item.name}</span>
                    {item.detail && <span className="ml-auto text-[10px] text-slate-600 shrink-0">{item.detail}</span>}
                  </button>
                );
              })
            )}
          </div>

          {/* Footer */}
          <div className="px-3 py-1.5 border-t border-white/[0.06] flex items-center justify-between">
            <span className="text-[10px] text-slate-600">
              {searching ? "Searching..." : `${filtered.length} result${filtered.length !== 1 ? "s" : ""}`}
            </span>
            <button type="button" onClick={() => setOpen(false)} className="text-[10px] text-slate-400 hover:text-red-400">Done</button>
          </div>
        </div>
      )}
    </div>
  );
}
