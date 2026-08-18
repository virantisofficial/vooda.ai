"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useState, useEffect } from "react";
import AppShell from "@/components/layout/AppShell";
import { useAuthStore } from "@/lib/store";
import { getMe, changeMyPassword } from "@/lib/api";

export default function ProfilePage() {
  const { user } = useAuthStore();
  const [profile, setProfile] = useState<any>(null);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ full_name: "", email: "" });
  const [passwordForm, setPasswordForm] = useState({ current: "", newPw: "", confirm: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [pwSaving, setPwSaving] = useState(false);
  const [pwMsg, setPwMsg] = useState<{ type: "error" | "success"; text: string } | null>(null);

  const submitPassword = async () => {
    setPwMsg(null);
    if (!passwordForm.current) {
      setPwMsg({ type: "error", text: "Enter your current password." });
      return;
    }
    if (passwordForm.newPw.length < 12) {
      setPwMsg({ type: "error", text: "New password must be at least 12 characters." });
      return;
    }
    if (passwordForm.newPw !== passwordForm.confirm) {
      setPwMsg({ type: "error", text: "New password and confirmation do not match." });
      return;
    }
    if (passwordForm.newPw === passwordForm.current) {
      setPwMsg({ type: "error", text: "New password must be different from your current password." });
      return;
    }
    setPwSaving(true);
    try {
      await changeMyPassword({ current_password: passwordForm.current, new_password: passwordForm.newPw });
      setPasswordForm({ current: "", newPw: "", confirm: "" });
      setPwMsg({ type: "success", text: "Password updated." });
      setShowPassword(false);
    } catch (e: any) {
      setPwMsg({ type: "error", text: e?.response?.data?.detail || "Could not update password. Please try again." });
    } finally {
      setPwSaving(false);
    }
  };

  useEffect(() => {
    getMe().then((r) => {
      setProfile(r.data);
      setForm({ full_name: r.data.full_name, email: r.data.email });
    }).catch(() => {});
  }, []);

  const initials = user?.full_name?.split(" ").map((n) => n[0]).join("").toUpperCase() || "U";

  return (
    <AppShell>
      <div className="max-w-3xl mx-auto space-y-6">
        <p className="text-sm text-slate-400">Manage your account settings</p>

        {/* Profile Header */}
        <div className="card flex items-center gap-5">
          <div className="w-16 h-16 rounded-full bg-gradient-to-br from-red-400 to-purple-400 flex items-center justify-center text-xl font-bold text-dark-950 shrink-0">
            {initials}
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-lg font-bold text-white">{user?.full_name || "User"}</h3>
            <p className="text-sm text-slate-400">{user?.email}</p>
            <div className="flex gap-1.5 mt-2">
              {(user?.roles || []).map((role) => (
                <span key={role} className="text-[10px] px-2.5 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20 capitalize font-medium">
                  {role}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Personal Info */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Personal Information</h3>
            <button
              onClick={() => setEditing(!editing)}
              className={editing ? "btn-secondary text-xs px-3 py-1.5" : "text-xs text-red-400 hover:text-red-300 transition-colors"}
            >
              {editing ? "Cancel" : "Edit"}
            </button>
          </div>

          {editing ? (
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">
                  Full Name <span className="text-red-400">*</span>
                </label>
                <input
                  value={form.full_name}
                  onChange={(e) => setForm((f) => ({ ...f, full_name: e.target.value }))}
                  className="input-dark"
                />
                <p className="text-[11px] text-slate-600 mt-1">Shown in audit logs and on findings you assign or comment on.</p>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">
                  Email <span className="text-red-400">*</span>
                </label>
                <input
                  value={form.email}
                  onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
                  className="input-dark"
                  type="email"
                />
                <p className="text-[11px] text-slate-600 mt-1">Used for login and notification routing.</p>
              </div>
              <button className="btn-primary text-sm">Update</button>
            </div>
          ) : (
            <dl className="space-y-3">
              <div className="flex items-center py-2 border-b border-white/[0.04]">
                <dt className="text-sm text-slate-500 w-36">Full Name</dt>
                <dd className="text-sm text-slate-200">{user?.full_name}</dd>
              </div>
              <div className="flex items-center py-2 border-b border-white/[0.04]">
                <dt className="text-sm text-slate-500 w-36">Email</dt>
                <dd className="text-sm text-slate-200">{user?.email}</dd>
              </div>
              <div className="flex items-center py-2 border-b border-white/[0.04]">
                <dt className="text-sm text-slate-500 w-36">Role</dt>
                <dd className="text-sm text-slate-200 capitalize">{(user?.roles || []).join(", ") || "—"}</dd>
              </div>
              <div className="flex items-center py-2">
                <dt className="text-sm text-slate-500 w-36">Account Status</dt>
                <dd>
                  <span className="flex items-center gap-1.5 text-sm">
                    <span className="w-2 h-2 rounded-full bg-green-400" />
                    <span className="text-green-400">Active</span>
                  </span>
                </dd>
              </div>
            </dl>
          )}
        </div>

        {/* Change Password.
            Section header + edit toggle now mirror the Personal
            Information section above. The toggle label reads "Edit"
            vs "Cancel" (was "Update Password" / "Cancel" — confused
            users into thinking the toggle itself was the save action).
            The actual save button at the bottom keeps the verb
            "Update" so the call-to-action is unambiguous. */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Change Password</h3>
            <button
              onClick={() => setShowPassword(!showPassword)}
              className={showPassword ? "btn-secondary text-xs px-3 py-1.5" : "text-xs text-red-400 hover:text-red-300 transition-colors"}
            >
              {showPassword ? "Cancel" : "Edit"}
            </button>
          </div>

          {showPassword ? (
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">
                  Current Password <span className="text-red-400">*</span>
                </label>
                <input
                  type="password"
                  value={passwordForm.current}
                  onChange={(e) => setPasswordForm((f) => ({ ...f, current: e.target.value }))}
                  className="input-dark"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">
                  New Password <span className="text-red-400">*</span>
                </label>
                <input
                  type="password"
                  value={passwordForm.newPw}
                  onChange={(e) => setPasswordForm((f) => ({ ...f, newPw: e.target.value }))}
                  className="input-dark"
                />
                <p className="text-[11px] text-slate-600 mt-1">At least 12 characters. Mix letters, numbers, and symbols.</p>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1.5">
                  Confirm New Password <span className="text-red-400">*</span>
                </label>
                <input
                  type="password"
                  value={passwordForm.confirm}
                  onChange={(e) => setPasswordForm((f) => ({ ...f, confirm: e.target.value }))}
                  className="input-dark"
                />
              </div>
              {pwMsg && (
                <p className={`text-sm ${pwMsg.type === "error" ? "text-red-400" : "text-emerald-400"}`}>
                  {pwMsg.text}
                </p>
              )}
              <button className="btn-primary text-sm" onClick={submitPassword} disabled={pwSaving}>
                {pwSaving ? "Updating…" : "Update"}
              </button>
            </div>
          ) : (
            <p className="text-sm text-slate-500">
              {pwMsg?.type === "success"
                ? <span className="text-emerald-400">{pwMsg.text}</span>
                : <>Password last changed: <span className="text-slate-400">Never</span></>}
            </p>
          )}
        </div>

        {/* Preferences */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Preferences</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between py-2 border-b border-white/[0.04]">
              <div>
                <p className="text-sm text-slate-200">Email Notifications</p>
                <p className="text-xs text-slate-500">Receive email alerts for critical findings and scan completions</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" defaultChecked className="sr-only peer" />
                <div className="w-9 h-5 bg-white/[0.08] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-red-500"></div>
              </label>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-white/[0.04]">
              <div>
                <p className="text-sm text-slate-200">Slack Notifications</p>
                <p className="text-xs text-slate-500">Receive Slack DMs for assigned findings</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" />
                <div className="w-9 h-5 bg-white/[0.08] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-red-500"></div>
              </label>
            </div>
            <div className="flex items-center justify-between py-2">
              <div>
                <p className="text-sm text-slate-200">Default Findings View</p>
                <p className="text-xs text-slate-500">Show findings from all repos or only assigned repos</p>
              </div>
              <select className="select-dark text-xs w-32">
                <option value="all">All Repos</option>
                <option value="assigned">Assigned Only</option>
              </select>
            </div>
          </div>
        </div>

        {/* Sessions */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">Active Sessions</h3>
          <div className="bg-white/[0.02] border border-white/[0.04] rounded-lg p-3 flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-green-500/10 flex items-center justify-center shrink-0">
              <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
            <div className="flex-1">
              <p className="text-sm text-slate-200">Current session</p>
              <p className="text-xs text-slate-500">Browser · Active now</p>
            </div>
            <span className="flex items-center gap-1.5 text-xs text-green-400">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
              Active
            </span>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
