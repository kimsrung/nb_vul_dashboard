import React, { createContext, useContext, useState, useEffect } from 'react';
import { apiClient, UserRole } from '../api/client';

interface AuthContextType {
  token: string | null;
  username: string | null;
  role: UserRole | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  isAnalyst: boolean;
  isOwner: boolean;
  isViewer: boolean;
  canManageUsers: boolean;
  canAssignOwner: boolean;
  canRemediate: boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; message?: string }>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(localStorage.getItem('access_token'));
  const [username, setUsername] = useState<string | null>(localStorage.getItem('username'));
  const [role, setRole] = useState<UserRole | null>(
    (localStorage.getItem('user_role') as UserRole) || null
  );

  useEffect(() => {
    if (token) {
      apiClient
        .get('/auth/me')
        .then((res) => {
          setUsername(res.data.username);
          setRole(res.data.role);
          localStorage.setItem('username', res.data.username);
          localStorage.setItem('user_role', res.data.role);
        })
        .catch(() => {
          logout();
        });
    }
  }, [token]);

  const login = async (user: string, pass: string) => {
    try {
      const res = await apiClient.post('/auth/login', { username: user, password: pass });
      const { access_token, role: userRole, username: uName } = res.data;
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('user_role', userRole);
      localStorage.setItem('username', uName);
      setToken(access_token);
      setRole(userRole);
      setUsername(uName);
      return { success: true };
    } catch (err: any) {
      const msg = err.response?.data?.detail || 'Invalid login credentials';
      return { success: false, message: msg };
    }
  };

  const logout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_role');
    localStorage.removeItem('username');
    setToken(null);
    setUsername(null);
    setRole(null);
  };

  const value = {
    token,
    username,
    role,
    isAuthenticated: !!token,
    isAdmin: role === 'admin',
    isAnalyst: role === 'analyst',
    isOwner: role === 'owner',
    isViewer: role === 'viewer',
    canManageUsers: role === 'admin',
    canAssignOwner: role === 'admin' || role === 'analyst',
    canRemediate: role === 'admin' || role === 'analyst' || role === 'owner',
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
