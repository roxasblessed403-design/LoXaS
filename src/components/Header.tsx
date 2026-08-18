import React, { useEffect, useState } from 'react';
import {
  Terminal,
  Activity,
  FolderArchive,
  Globe,
  LayoutDashboard,
  Cpu,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import type { SupportedLanguage } from '../types.js';
import { TRANSLATIONS } from '../translations.js';

interface HeaderProps {
  currentView: 'terminal' | 'dashboard' | 'files';
  onViewChange: (view: 'terminal' | 'dashboard' | 'files') => void;
  language: SupportedLanguage;
  onLanguageChange: (lang: SupportedLanguage) => void;
  onOpenAiDoctor?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentView,
  onViewChange,
  language,
  onLanguageChange,
  onOpenAiDoctor,
}) => {
  const [serverHealth, setServerHealth] = useState<{
    status: string;
    uptime: number;
    memoryMb: number;
  } | null>(null);

  const t = TRANSLATIONS[language] || TRANSLATIONS.en;

  const fetchHealth = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        setServerHealth({
          status: data.status,
          uptime: Math.round(data.uptime),
          memoryMb: Math.round((data.memory?.heapUsed || 0) / 1024 / 1024),
        });
      }
    } catch {
      // Server health fallback
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleDownloadZip = () => {
    window.location.href = '/api/storage/download-zip';
  };

  return (
    <header className="bg-zinc-950 border-b border-zinc-800/80 px-4 py-2.5 select-none sticky top-0 z-40 backdrop-blur-md bg-opacity-95">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-3">
        {/* Brand / Logo */}
        <div className="flex items-center gap-3 w-full md:w-auto justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-gradient-to-tr from-emerald-600 via-teal-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-emerald-950/50">
              <Activity className="w-5 h-5 text-zinc-950 stroke-[2.5]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-sm tracking-widest text-emerald-400">
                  LoXaSB PRO
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-300 font-mono">
                  v5.4 SUPREME
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 font-mono hidden sm:block">
                Zero-Credit Tunneling • CDN/WAF Bypass • Route Hop Probe
              </p>
            </div>
          </div>

          {/* Quick status pill on mobile */}
          <div className="flex items-center gap-1.5 md:hidden text-[11px] font-mono text-emerald-400 bg-zinc-900 px-2 py-1 rounded border border-zinc-800">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>ONLINE</span>
          </div>
        </div>

        {/* Center Mode Switcher Tabs */}
        <div className="flex items-center bg-zinc-900/90 p-1 rounded-lg border border-zinc-800/80 gap-1 w-full sm:w-auto justify-center">
          <button
            onClick={() => onViewChange('terminal')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono transition-all ${
              currentView === 'terminal'
                ? 'bg-emerald-600 text-zinc-950 font-bold shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>CLI Terminal</span>
          </button>

          <button
            onClick={() => onViewChange('dashboard')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono transition-all ${
              currentView === 'dashboard'
                ? 'bg-emerald-600 text-zinc-950 font-bold shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'
            }`}
          >
            <LayoutDashboard className="w-3.5 h-3.5" />
            <span>Pro Dashboard</span>
          </button>

          <button
            onClick={() => onViewChange('files')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono transition-all ${
              currentView === 'files'
                ? 'bg-emerald-600 text-zinc-950 font-bold shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'
            }`}
          >
            <FolderArchive className="w-3.5 h-3.5" />
            <span>Directories</span>
          </button>
        </div>

        {/* Right Controls: AI Assistant, ZIP Download, Language & Engine Status */}
        <div className="flex items-center gap-2 w-full md:w-auto justify-end flex-wrap">
          {/* AI Network Assistant Button */}
          {onOpenAiDoctor && (
            <button
              onClick={onOpenAiDoctor}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300 text-xs font-mono hover:bg-purple-900/50 transition-colors"
              title="AI Bughost & Network Route Diagnostics"
            >
              <Sparkles className="w-3.5 h-3.5 text-purple-400 animate-pulse" />
              <span className="hidden sm:inline">AI Doctor</span>
            </button>
          )}

          {/* Download Entire Storage ZIP */}
          <button
            onClick={handleDownloadZip}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-zinc-900 border border-zinc-700/70 text-zinc-300 text-xs font-mono hover:bg-zinc-800 transition-colors"
            title="Download all scanned files in cdn/, sni/, direct-ip/ as ZIP"
          >
            <FolderArchive className="w-3.5 h-3.5 text-amber-400" />
            <span className="hidden sm:inline">ZIP Export</span>
          </button>

          {/* Language Selector */}
          <div className="flex items-center bg-zinc-900 rounded border border-zinc-800 px-2 py-1 gap-1">
            <Globe className="w-3.5 h-3.5 text-zinc-400" />
            <select
              value={language}
              onChange={(e) => onLanguageChange(e.target.value as SupportedLanguage)}
              className="bg-transparent text-xs text-zinc-200 font-mono outline-none cursor-pointer"
            >
              <option value="en" className="bg-zinc-900 text-zinc-200">EN</option>
              <option value="es" className="bg-zinc-900 text-zinc-200">ES</option>
              <option value="pt" className="bg-zinc-900 text-zinc-200">PT</option>
              <option value="id" className="bg-zinc-900 text-zinc-200">ID</option>
              <option value="ru" className="bg-zinc-900 text-zinc-200">RU</option>
              <option value="fr" className="bg-zinc-900 text-zinc-200">FR</option>
            </select>
          </div>

          {/* Server Metric Info (Desktop) */}
          <div className="hidden lg:flex items-center gap-2 text-[11px] font-mono text-zinc-400 bg-zinc-900/80 px-2.5 py-1 rounded border border-zinc-800">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Heap: {serverHealth ? `${serverHealth.memoryMb}MB` : '28MB'}</span>
          </div>
        </div>
      </div>
    </header>
  );
};
