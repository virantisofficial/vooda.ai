"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect } from "react";
import { getProviderSchema, testIntegrationConnection, createIntegration } from "@/lib/api";
import ScannerIcon from "./ScannerIcons";

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
  description: string;
  fields: FieldDef[];
  auth_type: string;
}

interface Props {
  provider: string;
  color: string;
  onClose: () => void;
  onConnected: () => void;
}

type ConnectionStatus = "idle" | "testing" | "success" | "auth_failed" | "connection_failed" | "error" | "saving";

export default function ScannerConnectModal({ provider, color, onClose, onConnected }: Props) {
  const [schema, setSchema] = useState<ProviderSchema | null>(null);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [status, setStatus] = useState<ConnectionStatus>("idle");
  const [statusMessage, setStatusMessage] = useState("");
  const [statusDetails, setStatusDetails] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getProviderSchema(provider)
      .then((r) => {
        setSchema(r.data);
        // Initialize form with empty values
        const init: Record<string, string> = {};
        for (const f of r.data.fields) {
          init[f.key] = "";
        }
        setFormData(init);
      })
      .catch(() => setStatusMessage("Failed to load provider configuration"))
      .finally(() => setLoading(false));
  }, [provider]);

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
    setStatus("saving");
    try {
      await createIntegration({
        provider,
        name: schema?.label,
        config: formData,
      });
      setStatus("success");
      setStatusMessage("Integration saved successfully!");
      setTimeout(() => onConnected(), 1000);
    } catch {
      setStatus("error");
      setStatusMessage("Failed to save integration");
    }
  };

  const statusConfig: Record<string, { icon: string; color: string; bg: string; border: string }> = {
    idle: { icon: "", color: "text-slate-400", bg: "", border: "" },
    testing: { icon: "⏳", color: "text-red-400", bg: "bg-red-500/5", border: "border-red-500/20" },
    success: { icon: "✓", color: "text-green-400", bg: "bg-green-500/5", border: "border-green-500/20" },
    auth_failed: { icon: "✗", color: "text-red-400", bg: "bg-red-500/5", border: "border-red-500/20" },
    connection_failed: { icon: "✗", color: "text-orange-400", bg: "bg-orange-500/5", border: "border-orange-500/20" },
    error: { icon: "!", color: "text-red-400", bg: "bg-red-500/5", border: "border-red-500/20" },
    saving: { icon: "⏳", color: "text-red-400", bg: "bg-red-500/5", border: "border-red-500/20" },
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
            <ScannerIcon provider={provider} className="w-6 h-6" />
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
            schema.fields.map((field) => (
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
                      <option key={opt} value={opt}>{opt.toUpperCase()}</option>
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
            ))
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
                {/* Show details */}
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
            Test Connection
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
