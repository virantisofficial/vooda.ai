// SPDX-FileCopyrightText: 2026 Virantis
// SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

import { create } from "zustand";

interface User {
  id: string;
  email: string;
  full_name: string;
  roles: string[];
}

interface AuthStore {
  user: User | null;
  token: string | null;
  setAuth: (user: User, token: string) => void;
  logout: () => void;
  isAuthenticated: () => boolean;
}

export const useAuthStore = create<AuthStore>((set, get) => ({
  user: null,
  token: typeof window !== "undefined" ? localStorage.getItem("vooda_token") : null,

  setAuth: (user, token) => {
    localStorage.setItem("vooda_token", token);
    set({ user, token });
  },

  logout: () => {
    localStorage.removeItem("vooda_token");
    set({ user: null, token: null });
  },

  isAuthenticated: () => !!get().token,
}));
