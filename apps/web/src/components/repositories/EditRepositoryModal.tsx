"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

/**
 * EditRepositoryModal — focused modal for editing an existing repository.
 *
 * Why not reuse AddRepositoryModal? That component is 1000+ lines and
 * carries logic that only makes sense at create time (URL probing,
 * archive upload, scanner-import wiring, provider auto-detection).
 * Showing those fields in edit mode would either gray them out (ugly)
 * or hide most of the modal (confusing). A dedicated modal here keeps
 * the visual style of the create modal but shows only the fields a
 * user would realistically change post-creation:
 *
 *   - Name
 *   - Default Branch
 *   - Scan Schedule
 *   - Scan Branch override
 *   - Scan Paths (include patterns)
 *   - Exclude Patterns
 *
 * The Repository URL is intentionally read-only — changing the URL
 * of a saved repo would be sketchy (it would point an existing
 * scan history at a different code base). If a user really needs
 * to change the URL, the right path is delete + re-add.
 *
 * Bug fix 2026-04-27: previously the only entry point to editing
 * was navigating to the detail page (?edit=1). User-reported as
 * heavy — opening a full page just to rename a repo. This modal
 * replaces that flow for the inline edit pencil on the list view.
 */

import { useState, useEffect } from "react";
import api, { updateRepository } from "@/lib/api";
import type { Repository } from "@/types";
import { useToast } from "@/components/ui/Toast";

interface EditRepositoryModalProps {
  repo: Repository;
  onClose: () => void;
  onSaved: () => void;  // called after a successful PUT so the list can refresh
}

// Lightweight shape for the Ticketing destination dropdown — only
// the fields we render. Loaded from /integrations on mount.
interface TicketingChoice {
  id: string;
  name: string;
  provider: string;
  config?: { project_key?: string };
}

export default function EditRepositoryModal({ repo, onClose, onSaved }: EditRepositoryModalProps) {
  const { toast } = useToast();
  const [saving, setSaving] = useState(false);

  // Form state — pre-filled from the existing repo. We deliberately
  // copy each field rather than holding a ref to `repo` so the user
  // can revert changes by closing the modal without affecting the
  // upstream repo object.
  const [name, setName] = useState(repo.name || "");
  const [defaultBranch, setDefaultBranch] = useState(repo.default_branch || "");
  const [scanSchedule, setScanSchedule] = useState((repo as any).scan_schedule || "on_demand");
  const [scanBranch, setScanBranch] = useState((repo as any).scan_branch || "");
  const [scanPaths, setScanPaths] = useState(
    Array.isArray((repo as any).scan_paths) ? (repo as any).scan_paths.join(", ") : ""
  );
  const [excludePatterns, setExcludePatterns] = useState(
    Array.isArray((repo as any).exclude_patterns) ? (repo as any).exclude_patterns.join(", ") : ""
  );
  // Ticketing destination override — empty string = "use default
  // (board-level scope)". Bug fix / feature 2026-04-27: lets dev
  // teams say "this repo's findings file to this Jira board" in
  // one click, no scope-picker gymnastics.
  const [ticketingId, setTicketingId] = useState((repo as any).ticketing_integration_id || "");
  const [ticketingChoices, setTicketingChoices] = useState<TicketingChoice[]>([]);

  // Re-sync form when a different repo gets passed in (e.g. user
  // opens the modal, closes, then opens it on a different row).
  useEffect(() => {
    setName(repo.name || "");
    setDefaultBranch(repo.default_branch || "");
    setScanSchedule((repo as any).scan_schedule || "on_demand");
    setScanBranch((repo as any).scan_branch || "");
    setScanPaths(Array.isArray((repo as any).scan_paths) ? (repo as any).scan_paths.join(", ") : "");
    setExcludePatterns(Array.isArray((repo as any).exclude_patterns) ? (repo as any).exclude_patterns.join(", ") : "");
    setTicketingId((repo as any).ticketing_integration_id || "");
  }, [repo]);

  // Load active ticketing integrations so the picker can show them.
  // We don't filter by type — Jira / ServiceNow / Linear / custom
  // are all valid destinations. The dispatcher routes based on
  // provider regardless.
  useEffect(() => {
    api.get("/integrations").then((r) => {
      const items = (r.data?.items || r.data || []) as any[];
      const ticketing = (Array.isArray(items) ? items : []).filter(
        (i) => i.integration_type === "ticketing" && i.is_active,
      );
      setTicketingChoices(ticketing.map((i) => ({
        id: i.id,
        name: i.name || `${i.provider} integration`,
        provider: i.provider,
        config: i.config || {},
      })));
    }).catch(() => setTicketingChoices([]));
  }, []);

  const handleSave = async () => {
    if (!name.trim()) {
      toast("error", "Name is required", "Please enter a repository name.");
      return;
    }
    setSaving(true);
    try {
      const payload: Record<string, any> = {
        name: name.trim(),
        default_branch: defaultBranch.trim() || null,
        scan_schedule: scanSchedule,
        scan_branch: scanBranch.trim() || null,
        scan_paths: scanPaths.split(",").map((s: string) => s.trim()).filter(Boolean),
        exclude_patterns: excludePatterns.split(",").map((s: string) => s.trim()).filter(Boolean),
        // Empty string from the dropdown means "Default — use scope
        // routing"; we send null so the backend clears the override.
        ticketing_integration_id: ticketingId || null,
      };
      await updateRepository(repo.id, payload);
      toast("success", "Repository updated", "Your changes have been saved.");
      onSaved();
      onClose();
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || "Update failed";
      toast("error", "Could not save", String(detail).slice(0, 200));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-[8px]" onClick={onClose} />

      <div
        className="relative w-full max-w-xl border border-white/[0.08] rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col"
        style={{ background: "rgba(8,11,28,0.95)" }}
      >
        {/* Header — mirrors AddRepositoryModal's style + spacing so
            the two modals feel like one consistent surface. */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.06] shrink-0">
          <div>
            <h3 className="text-lg font-semibold text-white">Edit Repository</h3>
            <p className="text-[11px] text-slate-500 mt-0.5">Rename, reconfigure scanning, or change defaults</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/[0.06] transition-colors">
            <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          {/* URL — read-only. Shown for context so the user knows
              which repo they're editing, but we don't allow changes
              (would re-point existing scan history at a different
              codebase). */}
          <div>
            <label className="text-[11px] text-slate-500 block mb-1.5 uppercase tracking-wider">Repository URL</label>
            <input
              value={repo.url || "(local archive)"}
              disabled
              className="input-dark w-full text-xs opacity-60 cursor-not-allowed"
            />
            <p className="text-[10px] text-slate-600 mt-1">URL cannot be changed. Delete and re-add the repository to point Vooda at a different source.</p>
          </div>

          {/* Name */}
          <div>
            <label className="text-[11px] text-slate-500 block mb-1.5 uppercase tracking-wider">
              Name <span className="text-red-400">*</span>
            </label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="my-service"
              className="input-dark w-full text-xs"
            />
            <p className="text-[10px] text-slate-600 mt-1">Display name shown across the app — defaults to the URL's repo name on create.</p>
          </div>

          {/* Default branch */}
          <div>
            <label className="text-[11px] text-slate-500 block mb-1.5 uppercase tracking-wider">Default Branch</label>
            <input
              value={defaultBranch}
              onChange={(e) => setDefaultBranch(e.target.value)}
              placeholder="main"
              className="input-dark w-full text-xs"
            />
            <p className="text-[10px] text-slate-600 mt-1">The branch Vooda scans when no branch is explicitly chosen.</p>
          </div>

          {/* Scan schedule */}
          <div>
            <label className="text-[11px] text-slate-500 block mb-1.5 uppercase tracking-wider">Scan Schedule</label>
            <select
              value={scanSchedule}
              onChange={(e) => setScanSchedule(e.target.value)}
              className="select-dark w-full text-xs"
            >
              <option value="on_demand">On demand only</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
            <p className="text-[10px] text-slate-600 mt-1">How often Vooda automatically rescans this repository.</p>
          </div>

          {/* Scan branch override */}
          <div>
            <label className="text-[11px] text-slate-500 block mb-1.5 uppercase tracking-wider">Scheduled Scan Branch</label>
            <input
              value={scanBranch}
              onChange={(e) => setScanBranch(e.target.value)}
              placeholder="main"
              className="input-dark w-full text-xs"
            />
            <p className="text-[10px] text-slate-600 mt-1">Branch used by scheduled scans. Leave blank to use the default branch above.</p>
          </div>

          {/* Scan paths */}
          <div>
            <label className="text-[11px] text-slate-500 block mb-1.5 uppercase tracking-wider">Scan Paths</label>
            <input
              value={scanPaths}
              onChange={(e) => setScanPaths(e.target.value)}
              placeholder="src/**, lib/**"
              className="input-dark w-full text-xs"
            />
            <p className="text-[10px] text-slate-600 mt-1">Comma-separated globs. Leave blank to scan everything.</p>
          </div>

          {/* Exclude patterns */}
          <div>
            <label className="text-[11px] text-slate-500 block mb-1.5 uppercase tracking-wider">Exclude Patterns</label>
            <input
              value={excludePatterns}
              onChange={(e) => setExcludePatterns(e.target.value)}
              placeholder="**/node_modules/**, **/dist/**, **/*.min.js"
              className="input-dark w-full text-xs"
            />
            <p className="text-[10px] text-slate-600 mt-1">Comma-separated globs. Files matching any pattern are skipped during scanning.</p>
          </div>

          {/* Ticketing destination — per-repo override.
              When set, every finding from this repo files to this
              specific ticketing integration, ignoring its scope_level.
              "Default" means fall back to the integration's own
              scope routing (organization / business unit / project).
              Multiple repos can point at the same integration —
              that's how "Repo A, C → JIRA A" works in the model.
              Bug fix / feature 2026-04-27. */}
          <div>
            <label className="text-[11px] text-slate-500 block mb-1.5 uppercase tracking-wider">Ticketing Destination</label>
            <select
              value={ticketingId}
              onChange={(e) => setTicketingId(e.target.value)}
              className="select-dark w-full text-xs"
            >
              <option value="">— Default (use board-level scope routing) —</option>
              {ticketingChoices.map((tc) => {
                const projectKey = tc.config?.project_key ? ` → ${tc.config.project_key}` : "";
                return (
                  <option key={tc.id} value={tc.id}>
                    {tc.name} ({tc.provider}{projectKey})
                  </option>
                );
              })}
            </select>
            <p className="text-[10px] text-slate-600 mt-1 leading-snug">
              {ticketingId
                ? "Findings from this repository file to this board only — overrides any organization-wide catch-all."
                : "Findings follow the configured ticketing boards' scope rules (Organization / Business Unit / Single Repository)."}
            </p>
          </div>
        </div>

        {/* Footer — Save / Cancel mirror the create modal */}
        <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-white/[0.06] shrink-0">
          <button onClick={onClose} className="btn-secondary text-sm">Cancel</button>
          <button onClick={handleSave} disabled={saving} className="btn-primary text-sm disabled:opacity-50">
            {saving ? "Saving..." : "Save Changes"}
          </button>
        </div>
      </div>
    </div>
  );
}
