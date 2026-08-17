"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useCallback, useRef, useEffect } from "react";
import { detectProvider, extractRepoName, type RepoProvider, type AuthField } from "@/lib/providers";
import { probeRepository, getIntegrations } from "@/lib/api";
import { validateFile, validateFileContent } from "@/lib/fileValidation";
import { useToast } from "@/components/ui/Toast";

type CodeSource = "url" | "upload";
type ProbeStatus = "idle" | "probing" | "public" | "private" | "auth_required" | "not_found" | "error";

interface ProbeResult {
  status: string;
  message: string;
  provider?: string;
  default_branch?: string;
  branches: { name: string; is_default: boolean }[];
  languages: Record<string, number>;
  frameworks: string[];
  topics: string[];
  description?: string;
  stars?: number;
  is_fork?: boolean;
}

interface AddRepositoryModalProps {
  onClose: () => void;
  onSubmit: (data: {
    name: string;
    url?: string;
    source_type: string;
    default_branch?: string;
    provider?: string;
    auth?: Record<string, string>;
    file?: File;
    [key: string]: any;
  }) => Promise<void>;
}

/* ── Provider Icon ─────────────────────────────────── */
function ProviderIcon({ provider, size = 24 }: { provider: RepoProvider; size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill={provider.color} className="transition-all duration-300">
      <path d={provider.icon} />
    </svg>
  );
}

/* ── Connection Status ─────────────────────────────── */
function ConnectionStatus({ status, message }: { status: ProbeStatus; message: string }) {
  if (status === "idle") return null;
  const config: Record<string, { icon: React.ReactNode; bg: string; text: string; border: string }> = {
    probing: { icon: <div className="w-4 h-4 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />, bg: "bg-red-500/5", text: "text-red-400", border: "border-red-500/20" },
    public: { icon: <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>, bg: "bg-green-500/5", text: "text-green-400", border: "border-green-500/20" },
    private: { icon: <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>, bg: "bg-green-500/5", text: "text-green-400", border: "border-green-500/20" },
    auth_required: { icon: <svg className="w-4 h-4 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>, bg: "bg-yellow-500/5", text: "text-yellow-400", border: "border-yellow-500/20" },
    not_found: { icon: <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>, bg: "bg-red-500/5", text: "text-red-400", border: "border-red-500/20" },
    error: { icon: <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>, bg: "bg-red-500/5", text: "text-red-400", border: "border-red-500/20" },
  };
  const c = config[status] || config.error;
  return (
    <div className={`flex items-center gap-2 px-3 py-2 rounded-lg ${c.bg} border ${c.border} mt-2`}>
      {c.icon}
      <span className={`text-xs font-medium ${c.text}`}>{message}</span>
    </div>
  );
}

/* ── Metadata Panel ────────────────────────────────── */
function MetadataPanel({ probe, selectedBranch, onBranchChange }: { probe: ProbeResult; selectedBranch: string; onBranchChange: (b: string) => void }) {
  const langs = Object.entries(probe.languages).sort((a, b) => b[1] - a[1]);
  return (
    <div className="space-y-3 mt-3 p-4 rounded-xl bg-white/[0.02] border border-white/[0.06]">
      {probe.branches.length > 0 && (
        <div>
          <label className="block text-xs font-medium text-slate-500 mb-1.5">Branch</label>
          <select value={selectedBranch} onChange={(e) => onBranchChange(e.target.value)} className="select-dark w-full">
            {probe.branches.map((b) => <option key={b.name} value={b.name}>{b.name} {b.is_default ? "(default)" : ""}</option>)}
          </select>
        </div>
      )}
      {langs.length > 0 && (
        <div>
          <label className="block text-xs font-medium text-slate-500 mb-2">Languages</label>
          <div className="space-y-1.5">
            {langs.slice(0, 5).map(([lang, pct]) => (
              <div key={lang} className="flex items-center gap-2">
                <span className="text-xs text-slate-300 w-20 truncate">{lang}</span>
                <div className="flex-1 bg-white/[0.04] rounded-full h-1.5"><div className="h-full rounded-full bg-gradient-to-r from-red-500 to-orange-500" style={{ width: `${Math.max(pct, 2)}%` }} /></div>
                <span className="text-xs text-slate-500 w-10 text-right">{pct.toFixed(0)}%</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {probe.frameworks.length > 0 && (
        <div>
          <label className="block text-xs font-medium text-slate-500 mb-1.5">Frameworks</label>
          <div className="flex gap-1.5 flex-wrap">
            {probe.frameworks.map((fw) => <span key={fw} className="text-xs px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-400 border border-purple-500/20">{fw}</span>)}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Drop Zone with Validation ─────────────────────── */
function DropZone({ file, onFile, accept, hint, validationContext }: {
  file: File | null; onFile: (f: File | null) => void; accept?: string; hint?: string;
  validationContext?: "code_archive" | "scan_results";
}) {
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  const handleFile = useCallback(async (f: File | null) => {
    setError(null);
    if (!f) { onFile(null); return; }

    // Validate extension + size
    const ctx = validationContext || (accept?.includes(".json") ? "scan_results" : "code_archive");
    const result = validateFile(f, ctx);

    if (!result.valid) {
      setError(result.error || "Invalid file");
      toast("error", "Invalid File", result.error);
      // Reset the file input
      if (inputRef.current) inputRef.current.value = "";
      return;
    }

    if (result.warning) {
      toast("warning", "File Warning", result.warning);
    }

    // Content validation for scan results
    if (ctx === "scan_results") {
      const contentResult = await validateFileContent(f, "scan_results");
      if (!contentResult.valid) {
        setError(contentResult.error || "Invalid file content");
        toast("error", "Invalid File Content", contentResult.error);
        if (inputRef.current) inputRef.current.value = "";
        return;
      }
    }

    onFile(f);
  }, [onFile, validationContext, accept, toast]);

  return (
    <div>
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files?.[0] || null); }}
        onClick={() => inputRef.current?.click()}
        className={`border border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
          error ? "border-red-400/40 bg-red-400/5" :
          dragging ? "border-red-400/60 bg-red-400/5" :
          file ? "border-green-400/40 bg-green-400/5" :
          "border-white/[0.08] bg-white/[0.02] hover:border-white/[0.15]"
        }`}
      >
        <input ref={inputRef} type="file" accept={accept || ".zip,.tar,.tar.gz,.tgz"} onChange={(e) => handleFile(e.target.files?.[0] || null)} className="hidden" />
        {file ? (
          <div className="flex items-center justify-center gap-3">
            <svg className="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
            <span className="text-sm text-slate-200">{file.name}</span>
            <span className="text-xs text-slate-500">({(file.size / 1024).toFixed(0)} KB)</span>
            <button type="button" onClick={(e) => { e.stopPropagation(); onFile(null); setError(null); }} className="text-xs text-red-400 hover:text-red-300 ml-2">Remove</button>
          </div>
        ) : (
          <div>
            <p className="text-sm text-slate-400"><span className="text-red-400 font-medium">Click to browse</span> or drag and drop</p>
            <p className="text-xs text-slate-600 mt-1">{hint || ".zip, .tar.gz, .tgz"}</p>
          </div>
        )}
      </div>
      {error && (
        <div className="flex items-center gap-2 mt-2 px-3 py-2 rounded-lg bg-red-500/5 border border-red-500/20">
          <svg className="w-4 h-4 text-red-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          <span className="text-xs text-red-400">{error}</span>
        </div>
      )}
    </div>
  );
}

/* ── Searchable Project Select (scanner projects) ──── */
function SearchableProjectSelect({ projects, value, onChange, loading, placeholder }: {
  projects: { key: string; name: string; last_analysis: string }[];
  value: string; onChange: (key: string) => void; loading?: boolean; placeholder?: string;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

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

  const filtered = projects.filter((p) =>
    p.name.toLowerCase().includes(search.toLowerCase()) || p.key.toLowerCase().includes(search.toLowerCase())
  );

  const selected = projects.find((p) => p.key === value);

  return (
    <div ref={containerRef}>
      {/* Collapsed: trigger */}
      {!open && (
        <button type="button" onClick={() => { setOpen(true); setSearch(""); }}
          className="w-full flex items-center gap-2 px-3 py-2.5 rounded-lg border border-white/[0.08] bg-white/[0.02] hover:border-white/[0.15] text-sm text-left transition-all">
          <svg className="w-4 h-4 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <span className={`flex-1 truncate ${selected ? "text-slate-200" : "text-slate-500"}`}>
            {selected ? `${selected.name} (${selected.key})` : placeholder || "Search projects..."}
          </span>
          {selected ? (
            <span onClick={(e) => { e.stopPropagation(); onChange(""); }} className="text-slate-500 hover:text-red-400 transition-colors">
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
          <div className="px-3 py-2 border-b border-white/[0.06]">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input ref={inputRef} value={search} onChange={(e) => setSearch(e.target.value)}
                placeholder="Type to search projects..." className="flex-1 bg-transparent text-sm text-slate-200 placeholder-slate-500 outline-none" />
              {search && (
                <button type="button" onClick={() => setSearch("")} className="text-slate-500 hover:text-slate-300">
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              )}
            </div>
          </div>

          <div className="overflow-y-auto max-h-[14rem]">
            {loading ? (
              <div className="px-3 py-4 text-xs text-slate-500 text-center flex items-center justify-center gap-2">
                <div className="w-3 h-3 border-2 border-slate-500/30 border-t-slate-400 rounded-full animate-spin" />
                Loading projects from scanner...
              </div>
            ) : projects.length === 0 ? (
              <div className="px-3 py-4 text-xs text-slate-500 text-center">No projects found on this scanner</div>
            ) : filtered.length === 0 ? (
              <div className="px-3 py-4 text-xs text-slate-500 text-center">No matches for &ldquo;{search}&rdquo;</div>
            ) : (
              filtered.map((p) => {
                const isSelected = p.key === value;
                return (
                  <button key={p.key} type="button"
                    onClick={() => { onChange(p.key); setOpen(false); setSearch(""); }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2.5 text-left text-sm transition-colors hover:bg-red-500/10 ${isSelected ? "bg-white/[0.03]" : ""}`}>
                    <span className={`w-4 h-4 rounded-full border flex items-center justify-center shrink-0 transition-colors ${isSelected ? "bg-red-500/20 border-red-500/40" : "border-white/[0.15] bg-white/[0.02]"}`}>
                      {isSelected && (
                        <svg className="w-2.5 h-2.5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                        </svg>
                      )}
                    </span>
                    <div className="min-w-0 flex-1">
                      <span className={`block truncate ${isSelected ? "text-red-300 font-medium" : "text-slate-300"}`}>{p.name}</span>
                      <span className="block text-[10px] text-slate-600 truncate">{p.key}</span>
                    </div>
                    {p.last_analysis && (
                      <span className="text-[10px] text-slate-600 shrink-0">{new Date(p.last_analysis).toLocaleDateString()}</span>
                    )}
                  </button>
                );
              })
            )}
          </div>

          <div className="px-3 py-1.5 border-t border-white/[0.06] flex items-center justify-between">
            <span className="text-[10px] text-slate-600">{filtered.length} of {projects.length} projects</span>
            <button type="button" onClick={() => setOpen(false)} className="text-[10px] text-slate-400 hover:text-red-400">Done</button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── URL Input with Provider Detection ─────────────── */
function URLInput({ value, onChange, provider, probeStatus, placeholder }: {
  value: string; onChange: (v: string) => void; provider: RepoProvider; probeStatus?: ProbeStatus; placeholder?: string;
}) {
  const isGeneric = provider.id === "generic";
  return (
    <div className="relative">
      <div className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 flex items-center justify-center">
        {value.length > 5 && !isGeneric ? <ProviderIcon provider={provider} size={18} /> : (
          <svg className="w-4 h-4 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" /></svg>
        )}
      </div>
      <input type="text" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder || "https://github.com/org/repo"} className="input-dark pl-10 pr-10" />
      {probeStatus === "probing" && <div className="absolute right-3 top-1/2 -translate-y-1/2"><div className="w-4 h-4 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" /></div>}
    </div>
  );
}

/* ── Auth Section (collapsible) ────────────────────── */
function AuthSection({ provider, auth, onChange, probeStatus, onRetry, isGeneric }: {
  provider: RepoProvider; auth: Record<string, string>; onChange: (k: string, v: string) => void;
  probeStatus?: ProbeStatus; onRetry?: () => void; isGeneric: boolean;
}) {
  const [show, setShow] = useState(probeStatus === "auth_required");
  useEffect(() => { if (probeStatus === "auth_required") setShow(true); }, [probeStatus]);

  return (
    <div className="mt-2">
      <button type="button" onClick={() => setShow(!show)}
        className={`flex items-center gap-1.5 text-xs transition-colors ${probeStatus === "auth_required" ? "text-yellow-400" : "text-slate-600 hover:text-slate-400"}`}>
        <svg className={`w-3 h-3 transition-transform ${show ? "rotate-90" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
        Authentication {!isGeneric ? `(${provider.name})` : ""} {probeStatus === "auth_required" && <span className="text-yellow-400/70">— required</span>}
      </button>
      {show && (
        <div className="mt-2 space-y-2 pl-4 border-l-2 border-white/[0.06]">
          {provider.authFields.map((field: AuthField) => (
            <div key={field.key}>
              <label className="block text-xs text-slate-500 mb-1">{field.label}</label>
              <input type={field.type} value={auth[field.key] || ""} onChange={(e) => onChange(field.key, e.target.value)} placeholder={field.placeholder} className="input-dark text-xs" />
            </div>
          ))}
          {probeStatus === "auth_required" && onRetry && (
            <button type="button" onClick={onRetry} className="btn-secondary text-xs py-1.5 flex items-center gap-1.5">
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
              Retry connection
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════
   MAIN MODAL
   ══════════════════════════════════════════════════════ */
export default function AddRepositoryModal({ onClose, onSubmit }: AddRepositoryModalProps) {
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Ticketing destination picker — same as the edit modal. Lets the
  // user wire the new repo to a Jira board at create time, no
  // go-back-and-edit. Empty string = "use the integration's own
  // scope routing" (no per-repo override). User feedback 2026-04-27:
  // "we have to keep the Ticketing Destination in Add Repository
  // as well I feel".
  const [ticketingId, setTicketingId] = useState("");
  const [ticketingChoices, setTicketingChoices] = useState<{
    id: string; name: string; provider: string; project_key?: string;
  }[]>([]);

  // ── Vooda AI Engine tab state ──
  const [codeSourceVooda, setCodeSourceVooda] = useState<CodeSource>("url");
  const [url, setUrl] = useState("");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [auth, setAuth] = useState<Record<string, string>>({});

  // Probe state (for URL mode)
  const [probeStatus, setProbeStatus] = useState<ProbeStatus>("idle");
  const [probeMessage, setProbeMessage] = useState("");
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
  const [selectedBranch, setSelectedBranch] = useState("");
  const probeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastProbedUrl = useRef("");

  // Load active ticketing integrations to populate the per-repo
  // Jira-destination dropdown.
  useEffect(() => {
    getIntegrations().then((res) => {
      const items = (res.data || []) as any[];
      const ticketing = items
        .filter((i) => i.integration_type === "ticketing" && i.is_active)
        .map((i) => ({
          id: i.id,
          name: i.name || `${i.provider} integration`,
          provider: i.provider,
          project_key: i.config?.project_key,
        }));
      setTicketingChoices(ticketing);
    }).catch(() => {});
  }, []);

  const provider = detectProvider(url);
  const connected = probeStatus === "public" || probeStatus === "private";

  // ── Debounced auto-probe ──
  useEffect(() => {
    if (codeSourceVooda !== "url") return;
    if (probeTimerRef.current) clearTimeout(probeTimerRef.current);
    const trimmed = url.trim();
    if (trimmed.length < 10 || !trimmed.includes("/")) { setProbeStatus("idle"); setProbeResult(null); return; }
    probeTimerRef.current = setTimeout(() => runProbe(trimmed), 800);
    return () => { if (probeTimerRef.current) clearTimeout(probeTimerRef.current); };
  }, [url, codeSourceVooda]);

  async function runProbe(repoUrl: string) {
    if (repoUrl === lastProbedUrl.current && connected) return;
    lastProbedUrl.current = repoUrl;
    setProbeStatus("probing"); setProbeMessage("Checking repository..."); setProbeResult(null);
    try {
      const res = await probeRepository({ url: repoUrl, token: auth.token, username: auth.username, password: auth.password || auth.app_password });
      const data: ProbeResult = res.data;
      setProbeMessage(data.message); setProbeResult(data);
      if (data.status === "public" || data.status === "private") {
        setProbeStatus(data.status as ProbeStatus);
        if (data.default_branch) setSelectedBranch(data.default_branch);
        if (!name) { const autoName = extractRepoName(repoUrl); if (autoName) setName(autoName); }
      } else if (data.status === "auth_required") { setProbeStatus("auth_required"); }
      else if (data.status === "not_found") { setProbeStatus("not_found"); }
      else { setProbeStatus("error"); }
    } catch (err: any) { setProbeStatus("error"); setProbeMessage(err?.response?.data?.detail || "Failed to probe repository"); }
  }

  const handleRetryWithAuth = () => { const trimmed = url.trim(); if (trimmed.length > 10) { lastProbedUrl.current = ""; runProbe(trimmed); } };

  // ── Submit ──
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    try {
      await onSubmit({
        name: name.trim(),
        url: codeSourceVooda === "url" ? url : undefined,
        source_type: codeSourceVooda === "url" ? "git_url" : "archive",
        default_branch: selectedBranch || undefined,
        provider: codeSourceVooda === "url" ? provider.id : undefined,
        auth: codeSourceVooda === "url" && Object.values(auth).some(Boolean) ? auth : undefined,
        file: codeSourceVooda === "upload" ? uploadFile ?? undefined : undefined,
        ticketing_integration_id: ticketingId || undefined,
      });
    } finally { setSubmitting(false); }
  };

  const canSubmit = (() => {
    if (!name.trim()) return false;
    return codeSourceVooda === "url" ? url.trim().length > 5 : uploadFile !== null;
  })();

  // ── Code source toggle component ──
  function CodeSourceToggle({ value, onChange }: { value: CodeSource; onChange: (v: CodeSource) => void }) {
    return (
      <div className="flex gap-1 p-1 bg-white/[0.03] rounded-lg w-fit">
        <button type="button" onClick={() => onChange("url")}
          className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center gap-1.5 ${value === "url" ? "bg-white/[0.08] text-red-400" : "text-slate-500 hover:text-slate-300"}`}>
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" /></svg>
          Repository URL
        </button>
        <button type="button" onClick={() => onChange("upload")}
          className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center gap-1.5 ${value === "upload" ? "bg-white/[0.08] text-red-400" : "text-slate-500 hover:text-slate-300"}`}>
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" /></svg>
          Upload Archive
        </button>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-[8px]" onClick={onClose} />

      <div className="relative w-full max-w-xl border border-white/[0.08] rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col" style={{ background: "rgba(8,11,28,0.95)",  }}>
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.06] shrink-0">
          <h3 className="text-lg font-semibold text-white">Add Repository</h3>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/[0.06] transition-colors">
            <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4 overflow-y-auto flex-1">

          <div className="space-y-4">
            <p className="text-xs text-slate-500">Vooda AI scans your code using 3,000+ security rules, performs AI false positive analysis, and generates secure code fixes.</p>

              <CodeSourceToggle value={codeSourceVooda} onChange={setCodeSourceVooda} />

              {codeSourceVooda === "url" ? (
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-2">Repository URL</label>
                  <URLInput value={url} onChange={(v) => { setUrl(v); lastProbedUrl.current = ""; if (!name) { const n = extractRepoName(v); if (n) setName(n); } }} provider={provider} probeStatus={probeStatus} />
                  {url.length > 5 && provider.id !== "generic" && (
                    <div className="flex items-center gap-2 mt-2">
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium border"
                        style={{ backgroundColor: `${provider.color}10`, borderColor: `${provider.color}30`, color: provider.color === "#ffffff" ? "#e2e8f0" : provider.color }}>
                        <ProviderIcon provider={provider} size={10} /> {provider.name}
                      </span>
                    </div>
                  )}
                  <ConnectionStatus status={probeStatus} message={probeMessage} />
                  {connected && probeResult && <MetadataPanel probe={probeResult} selectedBranch={selectedBranch} onBranchChange={setSelectedBranch} />}
                  <AuthSection provider={provider} auth={auth} onChange={(k, v) => setAuth((p) => ({ ...p, [k]: v }))} probeStatus={probeStatus} onRetry={handleRetryWithAuth} isGeneric={provider.id === "generic"} />
                </div>
              ) : (
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-2">Source Code Archive</label>
                  <DropZone file={uploadFile} onFile={setUploadFile} validationContext="code_archive" />
                </div>
              )}
          </div>

          {/* ── Name ── */}
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-2">Repository Name</label>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="my-application" className="input-dark" required />
            <p className="text-[10px] text-slate-600 mt-1">Display name in Vooda AI</p>
          </div>

          {/* ── Ticketing Destination (shared) ──
              Same picker as the edit modal, surfaced at create time
              so users can wire the new repo to a Jira board in one
              shot. Hidden when no ticketing integrations exist —
              there's nothing to pick. */}
          {ticketingChoices.length > 0 && (
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-2">Ticketing Destination</label>
              <select
                value={ticketingId}
                onChange={(e) => setTicketingId(e.target.value)}
                className="select-dark w-full text-xs"
              >
                <option value="">— Default (use board-level scope routing) —</option>
                {ticketingChoices.map((tc) => {
                  const projectKey = tc.project_key ? ` → ${tc.project_key}` : "";
                  return (
                    <option key={tc.id} value={tc.id}>
                      {tc.name} ({tc.provider}{projectKey})
                    </option>
                  );
                })}
              </select>
              <p className="text-[10px] text-slate-600 mt-1 leading-snug">
                {ticketingId
                  ? "Findings from this repository file to this board only."
                  : "Findings follow the configured ticketing boards' scope rules. Set a destination to bind this repo to one specific board."}
              </p>
            </div>
          )}

          {/* ── Actions ── */}
          <div className="flex items-center justify-end gap-3 pt-1">
            <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={!canSubmit || submitting} className="btn-primary flex items-center gap-2">
              {submitting ? (
                <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />Saving...</>
              ) : (
                <><svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>Save</>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
