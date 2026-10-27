import React from 'react';
import { Shield, User, LogOut, PanelLeftClose, PanelLeftOpen, Sun, Moon } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';

interface NavbarProps {
  onSyncTriggered?: () => void;
  syncStatus?: string;
  isSidebarCollapsed?: boolean;
  onToggleSidebar?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  isSidebarCollapsed = false,
  onToggleSidebar,
}) => {
  const { username, role, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="h-16 shrink-0 border-b border-surfaceBorder bg-surface/90 backdrop-blur-md px-4 sm:px-6 flex items-center justify-between sticky top-0 z-40 select-none">
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-slate-800/80 transition-colors border border-slate-800"
            title={isSidebarCollapsed ? "Expand sidebar navigation" : "Collapse sidebar navigation"}
            aria-label="Toggle navigation"
          >
            {isSidebarCollapsed ? (
              <PanelLeftOpen className="w-4 h-4 text-sky-400" />
            ) : (
              <PanelLeftClose className="w-4 h-4 text-slate-400" />
            )}
          </button>
        )}
        <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            Risk Alert
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
              KB Remediation
            </span>
          </h1>
          <p className="text-[11px] text-slate-400">Host Detection & Threat Intelligence Engine</p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Theme Mode Toggle (Night / Day) */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-slate-800/80 transition-colors border border-surfaceBorder"
          title={theme === 'dark' ? "Switch to Day Mode (Light)" : "Switch to Night Mode (Dark)"}
          aria-label="Toggle theme mode"
        >
          {theme === 'dark' ? (
            <Sun className="w-4 h-4 text-amber-400 hover:text-amber-300 transition-colors" />
          ) : (
            <Moon className="w-4 h-4 text-sky-600 hover:text-sky-500 transition-colors" />
          )}
        </button>

        {/* User profile & Role Badge */}
        <div className="flex items-center gap-2 pl-2">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
            <User className="w-4 h-4" />
          </div>
          <div className="text-left hidden sm:block">
            <div className="text-xs font-semibold text-slate-200">{username}</div>
            <div className="flex items-center gap-1">
              <span
                className={`text-[10px] font-mono px-1.5 rounded uppercase font-semibold ${
                  role === 'admin'
                    ? 'bg-purple-950/60 text-purple-300 border border-purple-800/40'
                    : role === 'analyst'
                    ? 'bg-indigo-950/60 text-indigo-300 border border-indigo-800/40'
                    : role === 'owner'
                    ? 'bg-sky-950/60 text-sky-300 border border-sky-800/40'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}
              >
                {role}
              </span>
            </div>
          </div>
          <button
            onClick={logout}
            className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors ml-1"
            title="Log out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
