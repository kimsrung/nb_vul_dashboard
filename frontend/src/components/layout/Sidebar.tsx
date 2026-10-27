import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, Server, Bell, Settings, ShieldCheck, Users, ChevronLeft, ChevronRight, History, Radio, FileCode2, ExternalLink } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface SidebarProps {
  currentTab?: string;
  setCurrentTab?: (tab: string) => void;
  activeAlertCount?: number;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ 
  setCurrentTab, 
  activeAlertCount = 0,
  isCollapsed = false,
  onToggleCollapse,
}) => {
  const { isAdmin, isAnalyst } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const canViewDocs = isAdmin || isAnalyst;

  const navItems = [
    { id: 'dashboard', path: '/dashboard', label: 'Executive Overview', icon: LayoutDashboard },
    { id: 'assets', path: '/assets', label: 'Asset Inventory', icon: Server, matchPrefix: true },
    { id: 'alerts', path: '/alerts', label: 'Alert Center', icon: Bell, badge: activeAlertCount > 0 ? activeAlertCount : undefined },
    ...(isAdmin ? [{ id: 'misp', path: '/misp', label: 'MISP Feed', icon: Radio }] : []),
    ...(isAdmin ? [{ id: 'users', path: '/users', label: 'User Management', icon: Users }] : []),
    { id: 'audit-logs', path: '/audit-logs', label: 'Audit & History Logs', icon: History },
    { id: 'settings', path: '/settings', label: 'Admin Settings', icon: Settings },
    ...(canViewDocs ? [{ id: 'api-docs', path: '/docs', label: 'API Documentation', icon: FileCode2, external: true }] : []),
  ];

  const handleNavClick = (item: (typeof navItems)[0]) => {
    if ('external' in item && item.external) {
      window.open(item.path, '_blank', 'noopener,noreferrer');
      return;
    }
    if (setCurrentTab) {
      setCurrentTab(item.id);
    }
    navigate(item.path);
  };

  return (
    <aside 
      className={`${
        isCollapsed ? 'w-16 p-2' : 'w-64 p-4'
      } border-r border-surfaceBorder bg-surface/50 flex flex-col justify-between hidden md:flex shrink-0 transition-all duration-300 ease-in-out select-none overflow-y-auto`}
    >
      <div className="space-y-6">
        <div>
          {!isCollapsed && (
            <span className="text-[10px] font-semibold tracking-wider uppercase text-slate-500 px-3 transition-opacity duration-200">
              Navigation
            </span>
          )}
          <nav className="mt-2 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = item.matchPrefix
                ? location.pathname.startsWith(item.path)
                : (location.pathname === item.path || (item.id === 'dashboard' && location.pathname === '/'));

              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item)}
                  title={isCollapsed ? item.label : undefined}
                  className={`w-full relative flex items-center ${
                    isCollapsed ? 'justify-center h-10 px-0' : 'justify-between px-3 py-2.5'
                  } rounded-xl text-xs font-semibold border transition-colors duration-150 focus:outline-none ${
                    isActive
                      ? 'bg-primary-600/10 text-primary-400 border-primary-500/30 shadow-xs'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <div className={`flex items-center ${isCollapsed ? 'justify-center' : 'gap-2.5'}`}>
                    <Icon className={`w-4 h-4 shrink-0 transition-colors duration-150 ${isActive ? 'text-primary-400' : 'text-slate-400'}`} />
                    {!isCollapsed && <span className="truncate">{item.label}</span>}
                  </div>
                  {'external' in item && item.external && !isCollapsed && (
                    <ExternalLink className="w-3 h-3 text-slate-500 shrink-0" />
                  )}
                  {item.badge !== undefined && (
                    isCollapsed ? (
                      <span className="absolute top-1.5 right-2 w-2 h-2 rounded-full bg-red-500 animate-pulse ring-2 ring-surface" />
                    ) : (
                      <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-red-500 text-white animate-pulse">
                        {item.badge}
                      </span>
                    )
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Qualys Coverage Box */}
        {!isCollapsed && (
          <div className="pt-4 border-t border-surfaceBorder transition-opacity duration-200">
            <span className="text-[10px] font-semibold tracking-wider uppercase text-slate-500 px-3">
              Qualys Coverage
            </span>
            <div className="mt-2 p-3 rounded-xl bg-slate-900/60 border border-surfaceBorder text-xs space-y-1.5">
              <div className="flex items-center justify-between text-slate-400">
                <span>Host Detection:</span>
                <span className="text-emerald-400 font-mono flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" /> Active
                </span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>KB Remediation:</span>
                <span className="text-emerald-400 font-mono flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" /> Synced
                </span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>Telegram Alert:</span>
                <span className="text-sky-400 font-mono">Ready</span>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="space-y-2 pt-4">
        {/* Role Badge Widget */}
        {!isCollapsed ? (
          <div className="p-3 rounded-xl bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="truncate">Secured via RBAC Scoping</span>
          </div>
        ) : (
          <div className="flex justify-center p-2 text-slate-500" title="Secured via RBAC Scoping">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
        )}

        {/* Collapse / Expand Toggle Button */}
        {onToggleCollapse && (
          <button
            onClick={onToggleCollapse}
            className={`w-full flex items-center ${
              isCollapsed ? 'justify-center p-2' : 'justify-between px-3 py-2'
            } rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 text-xs transition-colors duration-150 border border-transparent hover:border-slate-800 focus:outline-none`}
            title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {!isCollapsed && <span>Collapse Sidebar</span>}
            {isCollapsed ? (
              <ChevronRight className="w-4 h-4 text-sky-400 shrink-0" />
            ) : (
              <ChevronLeft className="w-4 h-4 text-slate-400 shrink-0" />
            )}
          </button>
        )}
      </div>
    </aside>
  );
};
