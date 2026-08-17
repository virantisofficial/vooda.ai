"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { clsx } from "clsx";

export interface SubNavTab {
  key: string;
  label: string;
  count?: number;
  icon?: React.ReactNode;
}

interface SubNavProps {
  tabs: SubNavTab[];
  activeTab: string;
  onChange: (key: string) => void;
}

export default function SubNav({ tabs, activeTab, onChange }: SubNavProps) {
  return (
    <div
      className="flex items-center gap-0.5 mb-6 overflow-x-auto"
      style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}
    >
      {tabs.map((tab) => {
        const isActive = activeTab === tab.key;
        return (
          <button
            key={tab.key}
            onClick={() => onChange(tab.key)}
            className="flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-all relative whitespace-nowrap"
            style={{ color: isActive ? "#f87171" : "#475569" }}
            onMouseEnter={(e) => {
              if (!isActive) (e.currentTarget as HTMLElement).style.color = "#94a3b8";
            }}
            onMouseLeave={(e) => {
              if (!isActive) (e.currentTarget as HTMLElement).style.color = "#475569";
            }}
          >
            {tab.icon && (
              <span className="w-4 h-4 shrink-0">{tab.icon}</span>
            )}
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span
                className="text-[10px] px-1.5 py-0.5 rounded-full min-w-[18px] text-center font-medium"
                style={
                  isActive
                    ? { background: "rgba(239,68,68,0.15)", color: "#f87171" }
                    : { background: "rgba(255,255,255,0.04)", color: "#475569" }
                }
              >
                {tab.count}
              </span>
            )}
            {isActive && (
              <span
                className="absolute bottom-0 left-0 right-0 h-[2px] rounded-t"
                style={{ background: "linear-gradient(90deg, #dc2626 0%, #f87171 100%)" }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}
