"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect } from "react";
import AppShell from "@/components/layout/AppShell";
import { getRepositories, getFindings } from "@/lib/api";

interface RepoRisk {
  repo_id: string;
  repo_name: string;
  total_secrets: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  active_secrets: number;
  risk_score: number;
}

function getRiskColor(score: number): string {
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-yellow-500";
  if (score >= 20) return "bg-red-500";
  return "bg-green-500";
}

function getRiskLabel(score: number): string {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  if (score >= 20) return "Low";
  return "Clean";
}

export default function HeatmapPage() {
  const [repos, setRepos] = useState<RepoRisk[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const res = await getRepositories({ page_size: 50 });
        const d = res.data;
        const repoList = d?.items ?? (Array.isArray(d) ? d : d?.repositories || []);

        // Fetch findings per repo and compute risk
        const risks: RepoRisk[] = [];
        for (const repo of repoList.slice(0, 50)) {
          const findingsRes = await getFindings({ repository_id: repo.id, page_size: "500", category: "Hardcoded Secret" });
          const findings = findingsRes.data?.findings || [];
          const critical = findings.filter((f: any) => f.severity === "critical").length;
          const high = findings.filter((f: any) => f.severity === "high").length;
          const medium = findings.filter((f: any) => f.severity === "medium").length;
          const low = findings.filter((f: any) => f.severity === "low").length;
          const active = findings.filter((f: any) => f.source_metadata?.validation_status === "active").length;

          const riskScore = Math.min(100, critical * 25 + high * 10 + medium * 3 + low * 1 + active * 15);

          if (findings.length > 0) {
            risks.push({ repo_id: repo.id, repo_name: repo.name, total_secrets: findings.length, critical, high, medium, low, active_secrets: active, risk_score: riskScore });
          }
        }

        setRepos(risks.sort((a, b) => b.risk_score - a.risk_score));
      } catch { setRepos([]); }
      setLoading(false);
    }
    load();
  }, []);

  return (
    <AppShell>
      <div className="space-y-6">

        {loading ? (
          <div className="text-center py-20 text-slate-500">Analyzing repositories...</div>
        ) : repos.length === 0 ? (
          <div className="card text-center py-12 text-slate-500">No secrets detected across repositories. Run scans to populate the heatmap.</div>
        ) : (
          <div className="space-y-2">
            {repos.map(repo => (
              <div key={repo.repo_id} className="card p-4 flex items-center gap-4">
                <div className={`w-3 h-12 rounded-full ${getRiskColor(repo.risk_score)}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3">
                    <p className="text-sm font-medium text-white truncate">{repo.repo_name}</p>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                      repo.risk_score >= 60 ? "bg-red-500/15 text-red-400" : repo.risk_score >= 30 ? "bg-yellow-500/15 text-yellow-400" : "bg-green-500/15 text-green-400"
                    }`}>{getRiskLabel(repo.risk_score)}</span>
                  </div>
                  <div className="flex gap-4 mt-1 text-xs text-slate-500">
                    <span>{repo.total_secrets} secrets</span>
                    {repo.critical > 0 && <span className="text-red-400">{repo.critical} critical</span>}
                    {repo.high > 0 && <span className="text-orange-400">{repo.high} high</span>}
                    {repo.active_secrets > 0 && <span className="text-red-400">{repo.active_secrets} active</span>}
                  </div>
                </div>
                <div className="text-right">
                  <div className="w-16 h-2 rounded-full bg-white/10 overflow-hidden">
                    <div className={`h-full rounded-full ${getRiskColor(repo.risk_score)}`} style={{ width: `${repo.risk_score}%` }} />
                  </div>
                  <p className="text-xs text-slate-500 mt-1">{repo.risk_score}/100</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}
