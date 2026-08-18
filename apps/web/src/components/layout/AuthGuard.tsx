"use client";
// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import { getMe } from "@/lib/api";

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const { token, setAuth, logout } = useAuthStore();
  const router = useRouter();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) {
      router.push("/login");
      return;
    }
    getMe()
      .then((res) => {
        setAuth(res.data, token);
        setLoading(false);
      })
      .catch(() => {
        logout();
        router.push("/login");
      });
  }, [token]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen" style={{ background: "var(--bg-base)" }}>
        <div className="w-7 h-7 rounded-full border-2 animate-spin" style={{ borderColor: "rgba(239,68,68,0.2)", borderTopColor: "#ef4444" }} />
      </div>
    );
  }

  return <>{children}</>;
}
