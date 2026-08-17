"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect } from "react";
import AppShell from "@/components/layout/AppShell";
import { getTrendData } from "@/lib/api";

interface TrendPoint {
  date: string;
  count: number;
  critical: number;
  high: number;
}

export default function TrendsPage() {
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const res = await getTrendData(90);
        const severityTrend = res.data?.severity_trend || [];

        // Group daily data into weeks
        const byWeek: Record<string, TrendPoint> = {};
        for (const day of severityTrend) {
          const date = new Date(day.date);
          const weekStart = new Date(date);
          weekStart.setDate(date.getDate() - date.getDay());
          const key = weekStart.toISOString().split("T")[0];

          if (!byWeek[key]) byWeek[key] = { date: key, count: 0, critical: 0, high: 0 };
          byWeek[key].count += (day.critical || 0) + (day.high || 0) + (day.medium || 0) + (day.low || 0) + (day.info || 0);
          byWeek[key].critical += day.critical || 0;
          byWeek[key].high += day.high || 0;
        }

        const sorted = Object.values(byWeek).sort((a, b) => a.date.localeCompare(b.date));
        setTrends(sorted.slice(-12)); // Last 12 weeks
      } catch { setTrends([]); }
      setLoading(false);
    }
    load();
  }, []);

  const maxCount = Math.max(...trends.map(t => t.count), 1);

  return (
    <AppShell>
      <div className="space-y-6">

        {loading ? (
          <div className="text-center py-20 text-slate-500">Loading trends...</div>
        ) : trends.length === 0 ? (
          <div className="card text-center py-12 text-slate-500">No trend data yet. Run scans to see detection trends over time.</div>
        ) : (
          <div className="card">
            <div className="flex items-end gap-2 h-64 px-4 pb-4">
              {trends.map(t => (
                <div key={t.date} className="flex-1 flex flex-col items-center gap-1">
                  <span className="text-[10px] text-slate-500">{t.count}</span>
                  <div className="w-full flex flex-col-reverse gap-px" style={{ height: `${(t.count / maxCount) * 200}px`, minHeight: "4px" }}>
                    {t.critical > 0 && <div className="bg-red-500 rounded-t" style={{ height: `${(t.critical / t.count) * 100}%`, minHeight: "2px" }} />}
                    {t.high > 0 && <div className="bg-orange-500" style={{ height: `${(t.high / t.count) * 100}%`, minHeight: "2px" }} />}
                    <div className="bg-red-500 flex-1 rounded-b" style={{ minHeight: "2px" }} />
                  </div>
                  <span className="text-[9px] text-slate-600 rotate-[-45deg] origin-top-left whitespace-nowrap">{new Date(t.date).toLocaleDateString("en", { month: "short", day: "numeric" })}</span>
                </div>
              ))}
            </div>
            <div className="flex gap-4 px-4 pt-2 border-t border-white/[0.06]">
              <span className="flex items-center gap-1.5 text-xs text-slate-400"><span className="w-3 h-3 rounded bg-red-500 inline-block" /> Critical</span>
              <span className="flex items-center gap-1.5 text-xs text-slate-400"><span className="w-3 h-3 rounded bg-orange-500 inline-block" /> High</span>
              <span className="flex items-center gap-1.5 text-xs text-slate-400"><span className="w-3 h-3 rounded bg-red-500 inline-block" /> Other</span>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
