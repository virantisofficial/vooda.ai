"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState } from "react";
import { useRouter } from "next/navigation";
import { login } from "@/lib/api";
import { useAuthStore } from "@/lib/store";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { setAuth } = useAuthStore();
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await login(email, password);
      const token = res.data.access_token;
      setAuth({ id: "", email, full_name: "", roles: [] }, token);
      router.push("/dashboard");
    } catch {
      setError("Invalid credentials");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen flex"
      style={{
        background: "var(--bg-base)",
        backgroundImage:
          "radial-gradient(ellipse 80% 50% at 50% -20%, rgba(239,68,68,0.1) 0%, transparent 60%), radial-gradient(ellipse 60% 40% at 80% 80%, rgba(59,130,246,0.05) 0%, transparent 50%)",
      }}
    >
      {/* ── Left panel — Brand ── */}
      <div className="hidden lg:flex w-[50%] relative overflow-hidden">
        {/* Ambient glow */}
        <div
          className="absolute"
          style={{
            top: "30%",
            left: "40%",
            width: 600,
            height: 600,
            background: "radial-gradient(circle, rgba(220,38,38,0.08) 0%, transparent 70%)",
            transform: "translate(-50%, -50%)",
          }}
        />
        <div
          className="absolute"
          style={{
            bottom: "20%",
            right: "10%",
            width: 300,
            height: 300,
            background: "radial-gradient(circle, rgba(34,211,238,0.04) 0%, transparent 70%)",
          }}
        />

        {/* Vertical separator */}
        <div
          className="absolute right-0 top-[10%] bottom-[10%] w-px"
          style={{ background: "linear-gradient(to bottom, transparent, rgba(255,255,255,0.05) 30%, rgba(255,255,255,0.05) 70%, transparent)" }}
        />

        {/* Content */}
        <div className="relative z-10 flex flex-col justify-center flex-1 px-14 xl:px-20">
          {/* Logo */}
          <img src="/logo.svg" alt="Vooda AI" className="h-18 self-start mb-12" />

          {/* Tagline */}
          <p className="text-[15px] font-normal leading-relaxed mb-2" style={{ color: "#94a3b8" }}>
            Protect your secrets.{" "}
            <span
              style={{
                background: "linear-gradient(90deg, #f87171 0%, #22d3ee 100%)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }}
            >
              Ship with confidence.
            </span>
          </p>

          <p className="text-[12px] leading-relaxed max-w-[320px] mb-12" style={{ color: "#94a3b8" }}>
            Continuous secret detection for engineering teams — every commit, every branch, every SaaS source.
          </p>

          {/* Capability list */}
          <div className="space-y-3">
            {[
              {
                icon: "M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z",
                label: "Secret Scanning",
                desc: "Detect secrets across all branches",
              },
              {
                icon: "M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z",
                label: "AI-Powered Triage",
                desc: "Automated risk classification",
              },
              {
                icon: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15",
                label: "Remediation Workflows",
                desc: "Rotate credentials and ship fixes fast",
              },
            ].map((item) => (
              <div key={item.label} className="flex items-center gap-3">
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                  style={{
                    background: "rgba(239,68,68,0.08)",
                    border: "1px solid rgba(239,68,68,0.15)",
                  }}
                >
                  <svg
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth={1.5}
                    viewBox="0 0 24 24"
                    style={{ color: "#ef4444" }}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                  </svg>
                </div>
                <div>
                  <p className="text-[12px] font-medium" style={{ color: "#cbd5e1" }}>{item.label}</p>
                  <p className="text-[11px]" style={{ color: "#94a3b8" }}>{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="absolute bottom-0 left-0 right-0 px-14 xl:px-20 py-5 z-10">
          <p className="text-[12px] font-medium" style={{ color: "#cbd5e1" }}>
            &copy; 2026 Vooda AI — a Virantis product
          </p>
        </div>
      </div>

      {/* ── Right panel — Login form ── */}
      <div className="w-full lg:w-[50%] flex items-center justify-center relative">
        <div className="w-full max-w-[340px] px-6">
          {/* Mobile logo */}
          <div className="lg:hidden flex justify-center mb-10">
            <img src="/logo.svg" alt="Vooda AI" className="h-10" />
          </div>

          {/* Card */}
          <div
            className="p-8 rounded-2xl"
            style={{
              background: "rgba(14,18,40,0.7)",
              
              
              border: "1px solid rgba(255,255,255,0.07)",
              boxShadow: "0 8px 40px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.05)",
            }}
          >
            {/* Header */}
            <div className="mb-6">
              <div
                className="w-10 h-10 rounded-xl flex items-center justify-center mb-4"
                style={{
                  background: "linear-gradient(135deg, #dc2626 0%, #ea580c 100%)",
                  boxShadow: "0 4px 16px rgba(220,38,38,0.35)",
                }}
              >
                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h1 className="text-[15px] font-semibold text-white mb-0.5">Welcome back</h1>
              <p className="text-[12px]" style={{ color: "#475569" }}>
                Sign in to your Vooda AI workspace
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              {error && (
                <div
                  className="px-3 py-2.5 rounded-lg text-[12px]"
                  style={{
                    background: "rgba(248,113,113,0.08)",
                    border: "1px solid rgba(248,113,113,0.2)",
                    color: "#fca5a5",
                  }}
                >
                  {error}
                </div>
              )}

              <div>
                <label className="block text-[11px] font-medium mb-1.5" style={{ color: "#64748b" }}>
                  Email address
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-dark"
                  placeholder="you@company.com"
                  required
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-[11px] font-medium" style={{ color: "#64748b" }}>
                    Password
                  </label>
                  <span
                    className="text-[11px] cursor-pointer transition-colors"
                    style={{ color: "#64748b" }}
                    onMouseEnter={(e) => ((e.target as HTMLElement).style.color = "#ef4444")}
                    onMouseLeave={(e) => ((e.target as HTMLElement).style.color = "#64748b")}
                  >
                    Forgot password?
                  </span>
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-dark"
                  placeholder="Enter your password"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-primary w-full mt-2"
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <div
                      className="w-3.5 h-3.5 rounded-full border-2 border-t-transparent animate-spin"
                      style={{ borderColor: "rgba(255,255,255,0.3)", borderTopColor: "white" }}
                    />
                    Signing in...
                  </span>
                ) : (
                  "Sign in"
                )}
              </button>
            </form>

            <p className="text-[11px] text-center mt-5" style={{ color: "#64748b" }}>
              Protected by Vooda AI
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
