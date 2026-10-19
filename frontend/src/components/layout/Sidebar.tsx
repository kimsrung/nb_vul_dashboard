import React from 'react';
import { LayoutDashboard, Server, Bell, Settings, ShieldCheck } from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  activeAlertCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, setCurrentTab, activeAlertCount = 0 }) => {
  const navItems = [
    { id: 'dashboard', label: 'Executive Overview', icon: LayoutDashboard },
    { id: 'assets', label: 'Asset Inventory', icon: Server },
    { id: 'alerts', label: 'Alert Center', icon: Bell, badge: activeAlertCount > 0 ? activeAlertCount : undefined },
    { id: 'settings', label: 'Admin Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 border-r border-surfaceBorder bg-surface/50 p-4 flex flex-col justify-between hidden md:flex shrink-0">
      <div className="space-y-6">
        <div>
          <span className="text-[10px] font-semibold tracking-wider uppercase text-slate-500 px-3">
            Navigation
          </span>
          <nav className="mt-2 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setCurrentTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-semibold transition-all ${
                    isActive
                      ? 'bg-primary-600/10 text-primary-400 border border-primary-500/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-primary-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== undefined && (
                    <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-red-500 text-white animate-pulse">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="pt-4 border-t border-surfaceBorder">
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
      </div>

      <div className="p-3 rounded-xl bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
        <span>Secured via Role-Based Access Control</span>
      </div>
    </aside>
  );
};
