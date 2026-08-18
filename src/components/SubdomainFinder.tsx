import React, { useState } from 'react';
import { Search, Globe, Server, CheckCircle2, Shield, Radio, Copy, Check, Download } from 'lucide-react';
import type { SupportedLanguage } from '../types.js';

interface SubdomainFinderProps {
  language: SupportedLanguage;
  onSelectHost?: (host: string) => void;
}

export const SubdomainFinder: React.FC<SubdomainFinderProps> = ({
  language,
  onSelectHost,
}) => {
  const [domain, setDomain] = useState('cloudflare.com');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<{ subdomain: string; ip?: string; isAlive: boolean; isCdn: boolean; provider: string }[]>([]);
  const [copied, setCopied] = useState(false);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!domain.trim()) return;

    setIsLoading(true);
    try {
      const res = await fetch('/api/subdomains/enum', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      });
      if (res.ok) {
        const data = await res.json();
        setResults(data.subdomains || []);
      }
    } catch (err) {
      console.error('Error finding subdomains:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyAll = () => {
    const list = results.map((r) => r.subdomain).join('\n');
    navigator.clipboard.writeText(list);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-5 shadow-xl font-mono text-xs space-y-4">
        <div>
          <label className="block text-zinc-400 mb-1.5 uppercase tracking-wider">
            Cloud Subdomain & Bughost Discovery (Menu [05] & [13])
          </label>
          <form onSubmit={handleSearch} className="flex gap-2">
            <div className="relative flex-1">
              <Globe className="w-4 h-4 text-emerald-400 absolute left-3 top-3" />
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="e.g. cloudflare.com, fastly.com, zoom.us, tiktok.com"
                className="w-full bg-zinc-900 border border-zinc-700 rounded-lg pl-9 pr-3 py-2 text-zinc-100 font-mono focus:border-emerald-500 focus:outline-none"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading || !domain.trim()}
              className="px-6 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-zinc-950 font-bold shadow-md"
            >
              {isLoading ? 'SCANNING...' : 'FIND SUBDOMAINS'}
            </button>
          </form>
        </div>
      </div>

      {results.length > 0 && (
        <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 font-mono text-xs space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-900 pb-3">
            <span className="font-bold text-zinc-200 uppercase tracking-wide">
              Discovered Subdomains ({results.length})
            </span>
            <button
              onClick={handleCopyAll}
              className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 hover:bg-zinc-800"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy All'}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {results.map((sub, idx) => (
              <div
                key={idx}
                onClick={() => onSelectHost?.(sub.subdomain)}
                className="p-3 rounded-lg bg-zinc-900/80 border border-zinc-800 hover:border-emerald-500/60 cursor-pointer transition-all space-y-1.5"
              >
                <div className="font-bold text-zinc-100 truncate flex items-center justify-between">
                  <span className="truncate">{sub.subdomain}</span>
                  <span
                    className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      sub.isAlive ? 'bg-emerald-500' : 'bg-rose-500'
                    }`}
                  />
                </div>
                <div className="text-[11px] text-zinc-400 flex items-center justify-between">
                  <span>IP: {sub.ip || 'N/A'}</span>
                  {sub.isCdn && (
                    <span className="px-1.5 py-0.2 rounded bg-purple-950 text-purple-300 text-[10px] font-bold">
                      {sub.provider}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
