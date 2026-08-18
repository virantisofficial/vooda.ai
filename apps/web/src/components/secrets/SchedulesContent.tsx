"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect, useCallback } from "react";
import { getRepositories, updateRepository } from "@/lib/api";

interface Repository {
  id: string;
  name: string;
  scan_mode: string;
  scan_schedule: string | null;
  last_scan_at: string | null;
}

const SCHEDULES = [
  { value: "on_demand", label: "On Demand", desc: "Scan only when manually triggered", icon: "M" },
  { value: "daily", label: "Daily", desc: "Every day at 2:00 AM UTC", icon: "D" },
  { value: "weekly", label: "Weekly", desc: "Every Monday at 2:00 AM UTC", icon: "W" },
  { value: "on_push", label: "On Push", desc: "Scan on every push (requires webhook)", icon: "P" },
  { value: "on_pr", label: "On PR/MR", desc: "Scan when PR opened (requires webhook)", icon: "R" },
];

export function SchedulesContent() {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchRepos = useCallback(async () => {
    try {
      setLoading(true);
      const res = await getRepositories({ page_size: 200 });
      const d = res.data;
      setRepos(d?.items ?? (Array.isArray(d) ? d : d?.repositories || []));
    } catch { setRepos([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchRepos(); }, [fetchRepos]);

  const updateSchedule = async (repoId: string, schedule: string) => {
    try {
      await updateRepository(repoId, { scan_schedule: schedule });
      fetchRepos();
    } catch (e) { console.error(e); }
  };

  const bySchedule: Record<string, Repository[]> = {};
  for (const r of repos) {
    const sched = r.scan_schedule || "on_demand";
    bySchedule[sched] = bySchedule[sched] || [];
    bySchedule[sched].push(r);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Scan Schedules</h1>
        <p className="text-sm text-slate-400 mt-1">Configure automatic scanning schedules for your repositories</p>
      </div>

      {/* Schedule Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {SCHEDULES.map(s => (
          <div key={s.value} className="card p-4 text-center">
            <div className={`w-10 h-10 rounded-lg mx-auto mb-2 flex items-center justify-center text-sm font-bold ${
              s.value === "on_push" ? "bg-red-500/15 text-red-400" :
              s.value === "daily" ? "bg-green-500/15 text-green-400" :
              s.value === "weekly" ? "bg-purple-500/15 text-purple-400" :
              s.value === "on_pr" ? "bg-orange-500/15 text-orange-400" :
              "bg-slate-500/10 text-slate-400"
            }`}>{s.icon}</div>
            <p className="text-sm font-medium text-white">{s.label}</p>
            <p className="text-xs text-slate-500 mt-0.5">{(bySchedule[s.value] || []).length} repos</p>
          </div>
        ))}
      </div>

      {/* Repository Schedule Table */}
      <div className="card">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Repository Schedules</h3>
        {loading ? (
          <div className="text-center py-12 text-slate-500">Loading...</div>
        ) : repos.length === 0 ? (
          <div className="text-center py-12 text-slate-500">No repositories added yet.</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Repository</th>
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Current Schedule</th>
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Last Scan</th>
                <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase">Change Schedule</th>
              </tr>
            </thead>
            <tbody>
              {repos.map(r => (
                <tr key={r.id} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                  <td className="py-2.5 px-3 text-slate-300 font-medium">{r.name}</td>
                  <td className="py-2.5 px-3">
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      r.scan_schedule === "daily" ? "bg-green-500/15 text-green-400" :
                      r.scan_schedule === "weekly" ? "bg-purple-500/15 text-purple-400" :
                      r.scan_schedule === "on_push" ? "bg-red-500/15 text-red-400" :
                      "bg-slate-500/10 text-slate-500"
                    }`}>{r.scan_schedule || "on_demand"}</span>
                  </td>
                  <td className="py-2.5 px-3 text-xs text-slate-500">
                    {r.last_scan_at ? new Date(r.last_scan_at).toLocaleDateString() : "Never"}
                  </td>
                  <td className="py-2.5 px-3">
                    <select
                      value={r.scan_schedule || "on_demand"}
                      onChange={e => updateSchedule(r.id, e.target.value)}
                      className="input-dark text-xs py-1 px-2"
                    >
                      {SCHEDULES.map(s => (
                        <option key={s.value} value={s.value}>{s.label}</option>
                      ))}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
