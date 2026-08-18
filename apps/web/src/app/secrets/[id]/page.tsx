"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import AppShell from "@/components/layout/AppShell";
import { CodeSnippet } from "@/components/findings/CodeSnippet";
import { getFinding } from "@/lib/api";

interface SecretDetail {
  id: string;
  title: string;
  description: string;
  severity: string;
  file_path: string;
  line_start: number;
  confidence: number;
  scanner_rule_id: string;
  classification: string;
  review_status: string;
  code_snippet: string;
  first_seen_at: string;
  last_seen_at: string;
  scan_count: number;
  assigned_to: string | null;
  source_metadata: Record<string, any>;
  repository?: { name: string; id: string };
  decisions?: Array<{ action: string; comment: string; created_at: string; user?: { email: string } }>;
}

const SEV = { critical: "bg-red-500/15 text-red-400", high: "bg-orange-500/15 text-orange-400", medium: "bg-yellow-500/15 text-yellow-400", low: "bg-slate-500/15 text-slate-400" };
const VAL = { active: "bg-red-500/15 text-red-400", inactive: "bg-green-500/15 text-green-400", revoked: "bg-green-500/15 text-green-400", unknown: "bg-slate-500/15 text-slate-400", not_validated: "bg-slate-500/10 text-slate-500" };

export default function SecretDetailPage() {
  const { id } = useParams();
  const [finding, setFinding] = useState<SecretDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getFinding(id as string).then(res => { setFinding(res.data); setLoading(false); }).catch(() => setLoading(false));
  }, [id]);

  if (loading) return <AppShell><div className="text-center py-20 text-slate-500">Loading...</div></AppShell>;
  if (!finding) return <AppShell><div className="text-center py-20 text-slate-500">Secret not found</div></AppShell>;

  const sm = finding.source_metadata || {};
  const sevClass = SEV[finding.severity as keyof typeof SEV] || SEV.medium;
  const valStatus = sm.validation_status || "not_validated";
  const valClass = VAL[valStatus as keyof typeof VAL] || VAL.unknown;

  return (
    <AppShell>
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <div className="card">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-xl font-bold text-white">{finding.title}</h1>
              <p className="text-sm text-slate-400 mt-1">{finding.description}</p>
            </div>
            <span className={`px-3 py-1 rounded-lg text-sm font-medium ${sevClass}`}>{finding.severity}</span>
          </div>
          <div className="flex gap-4 mt-4 text-xs text-slate-500">
            <span>Rule: <code className="text-red-400">{finding.scanner_rule_id}</code></span>
            <span>Confidence: <strong className="text-white">{(finding.confidence * 100).toFixed(0)}%</strong></span>
            <span>Scans: {finding.scan_count}</span>
          </div>
        </div>

        {/* Secret Metadata */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="card">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Secret Info</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-slate-500">Type</span><span className="text-white capitalize">{sm.secret_type?.replace(/_/g, " ") || "—"}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Provider</span><span className="text-white capitalize">{sm.provider || "—"}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Masked Value</span><span className="font-mono text-red-400">{sm.masked_value || "****"}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Detection Method</span>
                <span className={`px-2 py-0.5 rounded text-xs ${sm.detection_method === "entropy" ? "bg-purple-500/15 text-purple-400" : "bg-red-500/15 text-red-400"}`}>{sm.detection_method || "regex"}</span>
              </div>
              {sm.entropy_score && <div className="flex justify-between"><span className="text-slate-500">Entropy Score</span><span className="text-white">{sm.entropy_score}</span></div>}
              <div className="flex justify-between"><span className="text-slate-500">Secret Hash</span><span className="font-mono text-xs text-slate-400">{sm.secret_hash?.slice(0, 16) || "—"}...</span></div>
            </div>
          </div>

          <div className="card">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Validation & Status</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-slate-500">Validation Status</span>
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${valClass}`}>{valStatus.replace(/_/g, " ")}</span>
              </div>
              <div className="flex justify-between"><span className="text-slate-500">Validated At</span><span className="text-white">{sm.validated_at || "Never"}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Classification</span><span className="text-white">{finding.classification?.replace(/_/g, " ") || "Unreviewed"}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Review Status</span><span className="text-white">{finding.review_status?.replace(/_/g, " ") || "Unreviewed"}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Rotation Status</span><span className="text-white">{sm.rotation_status || "Not tracked"}</span></div>
            </div>
          </div>
        </div>

        {/* Location */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Location</h3>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="text-slate-500">File</span><p className="text-white font-mono text-xs mt-1">{finding.file_path}</p></div>
            <div><span className="text-slate-500">Line</span><p className="text-white mt-1">{finding.line_start}</p></div>
            {sm.commit_sha && <div><span className="text-slate-500">Commit</span><p className="font-mono text-xs text-red-400 mt-1">{sm.commit_sha?.slice(0, 8)}</p></div>}
            {sm.commit_author && <div><span className="text-slate-500">Author</span><p className="text-white mt-1">{sm.commit_author}</p></div>}
            {sm.commit_date && <div><span className="text-slate-500">Committed</span><p className="text-white mt-1">{new Date(sm.commit_date).toLocaleDateString()}</p></div>}
            {sm.branch && <div><span className="text-slate-500">Branch</span><p className="text-white mt-1">{sm.branch}</p></div>}
          </div>
        </div>

        {/* Exposure Timeline */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Exposure Timeline</h3>
          <div className="relative pl-6 space-y-4">
            <div className="absolute left-2 top-0 bottom-0 w-px bg-white/10" />
            <div className="relative">
              <div className="absolute left-[-18px] w-3 h-3 rounded-full bg-red-500 border-2 border-[#1a1f2e]" />
              <p className="text-sm text-white">First Detected</p>
              <p className="text-xs text-slate-500">{finding.first_seen_at ? new Date(finding.first_seen_at).toLocaleString() : "—"}</p>
            </div>
            {sm.commit_date && (
              <div className="relative">
                <div className="absolute left-[-18px] w-3 h-3 rounded-full bg-orange-500 border-2 border-[#1a1f2e]" />
                <p className="text-sm text-white">Committed by {sm.commit_author || "unknown"}</p>
                <p className="text-xs text-slate-500">{new Date(sm.commit_date).toLocaleString()}</p>
              </div>
            )}
            <div className="relative">
              <div className="absolute left-[-18px] w-3 h-3 rounded-full bg-red-500 border-2 border-[#1a1f2e]" />
              <p className="text-sm text-white">Last Seen</p>
              <p className="text-xs text-slate-500">{finding.last_seen_at ? new Date(finding.last_seen_at).toLocaleString() : "—"}</p>
            </div>
            {sm.is_in_history_only && (
              <div className="relative">
                <div className="absolute left-[-18px] w-3 h-3 rounded-full bg-green-500 border-2 border-[#1a1f2e]" />
                <p className="text-sm text-green-400">Deleted from current branch</p>
                <p className="text-xs text-slate-500">Secret still exists in git history</p>
              </div>
            )}
          </div>
        </div>

        {/* Code Snippet */}
        {finding.code_snippet && (
          <div className="card">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Code Context (Masked)</h3>
            <CodeSnippet snippet={finding.code_snippet} lineStart={finding.line_start} />
          </div>
        )}

        {/* Decision History */}
        {finding.decisions && finding.decisions.length > 0 && (
          <div className="card">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Decision History</h3>
            <div className="space-y-2">
              {finding.decisions.map((d, i) => (
                <div key={i} className="flex items-center gap-3 p-2 rounded bg-white/[0.02] text-sm">
                  <span className="text-slate-500 text-xs">{new Date(d.created_at).toLocaleDateString()}</span>
                  <span className="text-white">{d.action?.replace(/_/g, " ")}</span>
                  {d.user && <span className="text-slate-400 text-xs">{d.user.email}</span>}
                  {d.comment && <span className="text-slate-500 text-xs">— {d.comment}</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
