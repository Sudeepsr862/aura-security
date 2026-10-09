// ─── AURA Demo Auth Context ───────────────────────────────────────────────────
// Provides active demo role and session state across the app.
// Supports quick role switching to easily demonstrate role-based permissions.

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, type DemoUser } from '../api/client';

interface AuthContextType {
  user: DemoUser | null;
  role: DemoUser['role'];
  isLoading: boolean;
  switchRole: (newRole: DemoUser['role']) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  role: 'administrator',
  isLoading: true,
  switchRole: async () => {},
  signOut: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<DemoUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Load existing session or default to administrator on first load
  useEffect(() => {
    let mounted = true;
    async function initAuth() {
      try {
        const me = await api.me();
        if (mounted && me.user) {
          setUser(me.user);
          setIsLoading(false);
          return;
        }
      } catch {
        // Not signed in yet — auto-signin as administrator for demo convenience
      }

      try {
        const sign = await api.signIn('administrator');
        if (mounted) {
          setUser(sign.user);
        }
      } catch (err) {
        console.error('Failed to auto-sign-in demo administrator:', err);
      } finally {
        if (mounted) setIsLoading(false);
      }
    }

    initAuth();
    return () => {
      mounted = false;
    };
  }, []);

  const switchRole = async (newRole: DemoUser['role']) => {
    setIsLoading(true);
    try {
      const res = await api.signIn(newRole);
      setUser(res.user);
    } catch (err) {
      console.error(`Failed to switch demo role to ${newRole}:`, err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSignOut = async () => {
    try {
      await api.signOut();
      setUser(null);
    } catch (err) {
      console.error('Sign out error:', err);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        role: user?.role ?? 'administrator',
        isLoading,
        switchRole,
        signOut: handleSignOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
