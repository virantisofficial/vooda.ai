"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect } from "react";
import { getProviderSchema, testIntegrationConnection, createIntegration, getBusinessUnits, getRepositories } from "@/lib/api";
import SearchableSelect from "@/components/ui/SearchableSelect";

interface FieldDef {
  key: string;
  label: string;
  type: string;
  placeholder?: string;
  required: boolean;
  options?: string[];
}

interface ProviderSchema {
  label: string;
  type: string;
  category: string;
  description: string;
  fields: FieldDef[];
  auth_type: string;
}

interface BusinessUnit {
  id: string;
  name: string;
}

interface Repository {
  id: string;
  name: string;
  business_unit_id?: string | null;
}

interface Props {
  provider: string;
  color: string;
  icon: React.ReactNode;
  onClose: () => void;
  onConnected: () => void;
}

type ConnectionStatus = "idle" | "testing" | "success" | "auth_failed" | "connection_failed" | "error" | "saving";

export default function NotificationConnectModal({ provider, color, icon, onClose, onConnected }: Props) {
  const [schema, setSchema] = useState<ProviderSchema | null>(null);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [status, setStatus] = useState<ConnectionStatus>("idle");
  const [statusMessage, setStatusMessage] = useState("");
  const [statusDetails, setStatusDetails] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);

  // Scoping state
  const [scopeLevel, setScopeLevel] = useState<string>("organization");
  const [businessUnitId, setBusinessUnitId] = useState<string>("");
  const [repositoryId, setRepositoryId] = useState<string>("");
  const [businessUnits, setBusinessUnits] = useState<BusinessUnit[]>([]);
  const [repositories, setRepositories] = useState<Repository[]>([]);

  useEffect(() => {
    getProviderSchema(provider)
      .then((r) => {
        setSchema(r.data);
        const init: Record<string, string> = {};
        for (const f of r.data.fields) {
          init[f.key] = "";
        }
        setFormData(init);
      })
      .catch(() => setStatusMessage("Failed to load provider configuration"))
      .finally(() => setLoading(false));

    // Load BUs and repos for scope dropdowns
    getBusinessUnits()
      .then((r) => setBusinessUnits(r.data?.business_units || r.data || []))
      .catch(() => {});
    getRepositories({ page_size: 200 })
      .then((r) => {
        const d = r.data;
        setRepositories(d?.items ?? (Array.isArray(d) ? d : d?.repositories || []));
      })
      .catch(() => {});
  }, [provider]);

  // Filter repos by selected BU — repos with null BU are treated as belonging to "Default" BU
  const defaultBU = businessUnits.find((bu) => bu.name === "Default");
  const filteredRepos = businessUnitId
    ? repositories.filter((r) => {
        // If this repo has a BU, match directly
        if (r.business_unit_id) return r.business_unit_id === businessUnitId;
        // If repo has no BU assigned, include it when "Default" BU is selected
        return defaultBU && businessUnitId === defaultBU.id;
      })
    : repositories;

  const handleTestConnection = async () => {
    setStatus("testing");
    setStatusMessage("Testing connection...");
    try {
      const res = await testIntegrationConnection({ provider, config: formData });
      const data = res.data;
      setStatus(data.status as ConnectionStatus);
      setStatusMessage(data.message);
      setStatusDetails(data.details || {});
    } catch {
      setStatus("error");
      setStatusMessage("Failed to test connection");
    }
  };

  const handleSave = async () => {
    // Validate scope requirements
    if (scopeLevel === "business_unit" && !businessUnitId) {
      setStatus("error");
      setStatusMessage("Please select a Business Unit for BU-scoped notifications");
      return;
    }
    if (scopeLevel === "project" && !repositoryId) {
      setStatus("error");
      setStatusMessage("Please select a Repository for project-scoped notifications");
      return;
    }

    setStatus("saving");
    try {
      await createIntegration({
        provider,
        name: schema?.label,
        config: formData,
        scope_level: scopeLevel,
        business_unit_id: scopeLevel === "business_unit" ? businessUnitId : undefined,
        repository_id: scopeLevel === "project" ? repositoryId : undefined,
      });
      setStatus("success");
      setStatusMessage("Notification channel saved successfully!");
      setTimeout(() => onConnected(), 1000);
    } catch (err: any) {
      setStatus("error");
      const detail = err?.response?.data?.detail;
      setStatusMessage(detail || "Failed to save notification channel");
    }
  };

  const statusConfig: Record<string, { icon: string; color: string; bg: string; border: string }> = {
    idle: { icon: "", color: "text-slate-400", bg: "", border: "" },
    testing: { icon: "", color: "text-red-400", bg: "bg-red-500/5", border: "border-red-500/20" },
    success: { icon: "\u2713", color: "text-green-400", bg: "bg-green-500/5", border: "border-green-500/20" },
    auth_failed: { icon: "\u2717", color: "text-red-400", bg: "bg-red-500/5", border: "border-red-500/20" },
    connection_failed: { icon: "\u2717", color: "text-orange-400", bg: "bg-orange-500/5", border: "border-orange-500/20" },
    error: { icon: "!", color: "text-red-400", bg: "bg-red-500/5", border: "border-red-500/20" },
    saving: { icon: "", color: "text-red-400", bg: "bg-red-500/5", border: "border-red-500/20" },
  };

  const sc = statusConfig[status];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-[8px]" onClick={onClose}>
      <div
        className="w-full max-w-lg mx-4 overflow-hidden max-h-[90vh] flex flex-col rounded-2xl border border-white/[0.08]"
        style={{ background: "rgba(8,11,28,0.95)",  }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center gap-4 px-6 pt-6 pb-5 border-b border-white/[0.06]">
          <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${color} flex items-center justify-center text-white`}>
            {icon}
          </div>
          <div className="flex-1">
            <h3 className="text-lg font-bold text-white">
              Connect {schema?.label || provider}
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">{schema?.description}</p>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-white/[0.04] transition-colors text-slate-500 hover:text-slate-300">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Form */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />
            </div>
          ) : schema ? (
            <>
              {/* Provider fields */}
              {schema.fields.map((field) => (
                <div key={field.key}>
                  <label className="block text-sm font-medium text-slate-400 mb-1.5">
                    {field.label}
                    {field.required && <span className="text-red-400 ml-1">*</span>}
                  </label>
                  {field.type === "select" ? (
                    <select
                      value={formData[field.key] || ""}
                      onChange={(e) => setFormData((d) => ({ ...d, [field.key]: e.target.value }))}
                      className="select-dark w-full"
                    >
                      <option value="">Select...</option>
                      {(field.options || []).map((opt) => (
                        <option key={opt} value={opt}>{opt.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}</option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type={field.type === "password" ? "password" : field.type === "url" ? "url" : "text"}
                      value={formData[field.key] || ""}
                      onChange={(e) => setFormData((d) => ({ ...d, [field.key]: e.target.value }))}
                      placeholder={field.placeholder || ""}
                      className="input-dark"
                    />
                  )}
                </div>
              ))}

              {/* ── Notification Scope Section ── */}
              <div className="pt-3 mt-3 border-t border-white/[0.06]">
                <div className="flex items-center gap-2 mb-3">
                  <svg className="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  <span className="text-sm font-semibold text-slate-300">Notification Scope</span>
                </div>
                <p className="text-xs text-slate-500 mb-3">
                  Control who receives alerts from this channel. Org-wide sends to everyone, BU/Project limits to specific teams.
                </p>

                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-1.5">
                    Scope Level <span className="text-red-400 ml-1">*</span>
                  </label>
                  <select
                    value={scopeLevel}
                    onChange={(e) => {
                      setScopeLevel(e.target.value);
                      setBusinessUnitId("");
                      setRepositoryId("");
                    }}
                    className="select-dark w-full"
                  >
                    <option value="organization">Organization (all repos)</option>
                    <option value="business_unit">Business Unit</option>
                    <option value="project">Project (specific repo)</option>
                  </select>
                </div>

                {scopeLevel === "business_unit" && (
                  <div className="mt-3">
                    <SearchableSelect
                      label="Business Unit"
                      placeholder="Search business units..."
                      required
                      items={businessUnits.map((bu) => ({ id: bu.id, name: bu.name }))}
                      value={businessUnitId}
                      onChange={(id) => {
                        setBusinessUnitId(id);
                        setRepositoryId("");
                      }}
                      emptyText="No business units found. Create one in Access Control first."
                    />
                  </div>
                )}

                {scopeLevel === "project" && (
                  <>
                    {businessUnits.length > 0 && (
                      <div className="mt-3">
                        <SearchableSelect
                          label="Business Unit"
                          placeholder="Filter by business unit..."
                          items={businessUnits.map((bu) => ({ id: bu.id, name: bu.name }))}
                          value={businessUnitId}
                          onChange={(id) => {
                            setBusinessUnitId(id);
                            setRepositoryId("");
                          }}
                          emptyText="No business units available"
                        />
                        <p className="text-[10px] text-slate-600 mt-1">Optional — narrows the repository list</p>
                      </div>
                    )}
                    <div className="mt-3">
                      <SearchableSelect
                        label="Repository"
                        placeholder="Search repositories..."
                        required
                        items={filteredRepos.map((repo) => ({ id: repo.id, name: repo.name }))}
                        value={repositoryId}
                        onChange={setRepositoryId}
                        emptyText={businessUnitId ? "No repositories in this business unit" : "No repositories found"}
                      />
                    </div>
                  </>
                )}
              </div>
            </>
          ) : (
            <p className="text-sm text-red-400">Failed to load provider configuration</p>
          )}

          {/* Connection Status */}
          {status !== "idle" && statusMessage && (
            <div className={`flex items-start gap-3 p-4 rounded-lg border ${sc.bg} ${sc.border}`}>
              {status === "testing" || status === "saving" ? (
                <div className="w-5 h-5 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin shrink-0 mt-0.5" />
              ) : (
                <span className={`text-lg ${sc.color} shrink-0`}>{sc.icon}</span>
              )}
              <div className="flex-1 min-w-0">
                <p className={`text-sm font-medium ${sc.color}`}>{statusMessage}</p>
                {Object.keys(statusDetails).length > 0 && status === "success" && (
                  <div className="mt-2 space-y-1">
                    {Object.entries(statusDetails).map(([k, v]) => (
                      <p key={k} className="text-xs text-slate-500">
                        {k.replace(/_/g, " ")}: <span className="text-slate-400">{String(v)}</span>
                      </p>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center gap-3 px-6 pt-5 pb-6 border-t border-white/[0.06]">
          <button onClick={onClose} className="btn-secondary flex-1">
            Cancel
          </button>
          <button
            onClick={handleTestConnection}
            disabled={status === "testing" || status === "saving"}
            className="btn-secondary flex-1 flex items-center justify-center gap-2"
          >
            {status === "testing" ? (
              <div className="w-4 h-4 border-2 border-red-400/30 border-t-violet-400 rounded-full animate-spin" />
            ) : (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            )}
            Test
          </button>
          <button
            onClick={handleSave}
            disabled={status !== "success" && status !== "idle"}
            className="btn-primary flex-1 flex items-center justify-center gap-2"
          >
            {status === "saving" ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            )}
            Save & Connect
          </button>
        </div>
      </div>
    </div>
  );
}
