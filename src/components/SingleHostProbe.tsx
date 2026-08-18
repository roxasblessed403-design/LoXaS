import React, { useState } from 'react';
import {
  Activity,
  Zap,
  Radio,
  ShieldCheck,
  Globe,
  Server,
  Terminal,
  Clock,
  AlertCircle,
  CheckCircle2,
  FolderCheck,
  Sparkles,
  Layers,
  Lock,
  Compass,
  FileCode,
  Share2,
} from 'lucide-react';
import type { ScanItemResult, ScanOptions, SupportedLanguage } from '../types.js';
import { TRANSLATIONS } from '../translations.js';
import { RouteHopVisualizer } from './RouteHopVisualizer.js';

interface SingleHostProbeProps {
  onScanComplete?: (result: ScanItemResult) => void;
  onOpenAiDoctor?: (item: ScanItemResult) => void;
  language: SupportedLanguage;
  onOpenFileInManager?: (filePath: string) => void;
}

export const SingleHostProbe: React.FC<SingleHostProbeProps> = ({
  onScanComplete,
  onOpenAiDoctor,
  language,
  onOpenFileInManager,
}) => {
  const [target, setTarget] = useState('speed.cloudflare.com');
  const [pingCount, setPingCount] = useState(4);
  const [checkTraceroute, setCheckTraceroute] = useState(true);
  const [checkCdn, setCheckCdn] = useState(true);
  const [checkSni, setCheckSni] = useState(true);
  const [checkPayloads, setCheckPayloads] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<ScanItemResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const t = TRANSLATIONS[language] || TRANSLATIONS.en;

  const handleRunProbe = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!target.trim()) return;

    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/scan/single', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target.trim(),
          options: {
            pingCount,
            checkTraceroute,
            checkCdn,
            checkSni,
            checkPayloads,
            autoSave: true,
          } as Partial<ScanOptions>,
        }),
      });

      if (!res.ok) {
        throw new Error(`Probe failed with status ${res.status}`);
      }

      const data: ScanItemResult = await res.json();
      setResult(data);
      if (onScanComplete) {
        onScanComplete(data);
      }
    } catch (err: any) {
      setError(err.message || 'Probe execution failed');
    } finally {
      setIsLoading(false);
    }
  };

  const getLossBadge = (loss: number) => {
    if (loss === 0) return 'text-emerald-400 bg-emerald-950/60 border-emerald-700/60';
    if (loss < 30) return 'text-amber-400 bg-amber-950/60 border-amber-700/60';
    return 'text-rose-400 bg-rose-950/60 border-rose-700/60';
  };

  return (
    <div className="space-y-6">
      {/* Target Input & Configuration Panel */}
      <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-5 shadow-xl">
        <form onSubmit={handleRunProbe} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-zinc-400 mb-1.5 uppercase tracking-wider">
              Target Host / Domain / IP / CIDR
            </label>
            <div className="flex flex-col sm:flex-row gap-2.5">
              <div className="relative flex-1">
                <Globe className="w-4 h-4 text-emerald-400 absolute left-3 top-3" />
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. speed.cloudflare.com, 104.16.240.5, 172.67.0.0/24"
                  className="w-full bg-zinc-900 border border-zinc-700 rounded-lg pl-9 pr-3 py-2 text-sm text-zinc-100 font-mono focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
                />
              </div>

              <button
                type="submit"
                disabled={isLoading || !target.trim()}
                className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-zinc-950 font-mono font-bold text-sm transition-all shadow-md shadow-emerald-950/50"
              >
                {isLoading ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin text-zinc-950" />
                    <span>PROBING...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 text-zinc-950 fill-current" />
                    <span>LAUNCH PROBE</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Feature toggles */}
          <div className="flex flex-wrap items-center gap-4 pt-2 border-t border-zinc-900 text-xs font-mono text-zinc-300">
            <div className="flex items-center gap-2">
              <span className="text-zinc-400">Pings:</span>
              <select
                value={pingCount}
                onChange={(e) => setPingCount(parseInt(e.target.value, 10))}
                className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-200 outline-none cursor-pointer"
              >
                <option value="2">2 Probes</option>
                <option value="4">4 Probes</option>
                <option value="8">8 Probes</option>
                <option value="10">10 Probes</option>
              </select>
            </div>

            <label className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={checkTraceroute}
                onChange={(e) => setCheckTraceroute(e.target.checked)}
                className="rounded bg-zinc-900 border-zinc-700 text-emerald-500 focus:ring-0"
              />
              <span>Route Hops (Traceroute)</span>
            </label>

            <label className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={checkCdn}
                onChange={(e) => setCheckCdn(e.target.checked)}
                className="rounded bg-zinc-900 border-zinc-700 text-emerald-500 focus:ring-0"
              />
              <span>Detect CDN / WAF Edge</span>
            </label>

            <label className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={checkSni}
                onChange={(e) => setCheckSni(e.target.checked)}
                className="rounded bg-zinc-900 border-zinc-700 text-emerald-500 focus:ring-0"
              />
              <span>TLS / SNI Handshake</span>
            </label>

            <label className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={checkPayloads}
                onChange={(e) => setCheckPayloads(e.target.checked)}
                className="rounded bg-zinc-900 border-zinc-700 text-emerald-500 focus:ring-0"
              />
              <span>HTTP/WS Payload Tests</span>
            </label>
          </div>
        </form>
      </div>

      {error && (
        <div className="bg-rose-950/40 border border-rose-800/80 rounded-xl p-4 flex items-center gap-3 text-rose-300 font-mono text-xs">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6 animate-fadeIn">
          {/* Top Banner with Auto-Save Directory Indicator */}
          <div className="bg-gradient-to-r from-zinc-900 via-zinc-950 to-zinc-900 border border-zinc-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 font-mono">
            <div className="flex items-center gap-3">
              <div
                className={`w-3 h-3 rounded-full ${
                  result.ping.isAlive ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'
                }`}
              />
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm text-zinc-100">{result.target}</span>
                  {result.resolvedIp && result.resolvedIp !== result.target && (
                    <span className="text-xs text-zinc-400">({result.resolvedIp})</span>
                  )}
                </div>
                <div className="text-[11px] text-zinc-400 flex items-center gap-2 mt-0.5">
                  <span>Type: <b className="text-emerald-400 uppercase">{result.type}</b></span>
                  <span>•</span>
                  <span>Category: <b className="text-cyan-400 uppercase">{result.category}</b></span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {/* Auto-saved directory link */}
              {result.savedDirectory && (
                <button
                  onClick={() => onOpenFileInManager?.(result.savedDirectory + '/' + result.savedFileName)}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-emerald-950/60 border border-emerald-700/60 text-emerald-300 text-xs hover:bg-emerald-900/50 transition-colors"
                >
                  <FolderCheck className="w-3.5 h-3.5" />
                  <span>Saved: <b className="underline">{result.savedDirectory}</b></span>
                </button>
              )}

              {onOpenAiDoctor && (
                <button
                  onClick={() => onOpenAiDoctor(result)}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-purple-950/60 border border-purple-700/60 text-purple-300 text-xs hover:bg-purple-900/50 transition-colors"
                >
                  <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                  <span>AI Diagnostics</span>
                </button>
              )}
            </div>
          </div>

          {/* 4-Card Diagnostics Grid: Latency, Packet Loss, CDN Edge, TLS SNI */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* 1. Ping Latency Card */}
            <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 font-mono">
              <div className="flex items-center justify-between text-zinc-400 mb-2">
                <span className="text-xs uppercase tracking-wider">Ping Latency</span>
                <Clock className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-zinc-100">
                  {result.ping.isAlive ? `${result.ping.latencyAvg}` : '0'}
                </span>
                <span className="text-xs text-zinc-400">ms avg</span>
              </div>

              <div className="mt-3 pt-3 border-t border-zinc-900 grid grid-cols-3 text-[11px] text-zinc-400">
                <div>
                  Min: <b className="text-emerald-400">{result.ping.latencyMin}ms</b>
                </div>
                <div>
                  Max: <b className="text-amber-400">{result.ping.latencyMax}ms</b>
                </div>
                <div>
                  Jitter: <b className="text-cyan-400">{result.ping.jitter}ms</b>
                </div>
              </div>
            </div>

            {/* 2. Packet Loss Card */}
            <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 font-mono">
              <div className="flex items-center justify-between text-zinc-400 mb-2">
                <span className="text-xs uppercase tracking-wider">Packet Loss</span>
                <Activity className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-zinc-100">
                  {result.ping.packetLoss}%
                </span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded border ${getLossBadge(
                    result.ping.packetLoss
                  )}`}
                >
                  {result.ping.packetLoss === 0
                    ? 'EXCELLENT'
                    : result.ping.packetLoss < 30
                    ? 'FAIR'
                    : 'UNSTABLE'}
                </span>
              </div>

              <div className="mt-3 pt-3 border-t border-zinc-900 flex justify-between text-[11px] text-zinc-400">
                <span>Sent: <b className="text-zinc-200">{result.ping.packetsSent}</b></span>
                <span>Recv: <b className="text-emerald-400">{result.ping.packetsReceived}</b></span>
                <span>Lost: <b className="text-rose-400">{result.ping.packetsSent - result.ping.packetsReceived}</b></span>
              </div>
            </div>

            {/* 3. CDN / Edge Detection */}
            <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 font-mono">
              <div className="flex items-center justify-between text-zinc-400 mb-2">
                <span className="text-xs uppercase tracking-wider">CDN / WAF Edge</span>
                <Server className="w-4 h-4 text-purple-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-lg font-bold text-zinc-100 truncate">
                  {result.cdn.provider}
                </span>
              </div>

              <div className="mt-3 pt-3 border-t border-zinc-900 text-[11px] text-zinc-400 truncate">
                {result.cdn.isCdn ? (
                  <span className="text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Active CDN Edge Node</span>
                  </span>
                ) : (
                  <span className="text-zinc-500">Non-CDN / Direct Origin</span>
                )}
              </div>
            </div>

            {/* 4. SNI & TLS Info */}
            <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 font-mono">
              <div className="flex items-center justify-between text-zinc-400 mb-2">
                <span className="text-xs uppercase tracking-wider">SNI / TLS Status</span>
                <Lock className="w-4 h-4 text-amber-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-lg font-bold text-zinc-100">
                  {result.sni.hasSni ? result.sni.tlsVersion || 'TLS Valid' : 'No TLS'}
                </span>
                {result.sni.isFrontable && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 border border-emerald-600 text-emerald-300">
                    Frontable
                  </span>
                )}
              </div>

              <div className="mt-3 pt-3 border-t border-zinc-900 text-[11px] text-zinc-400 flex items-center justify-between">
                <span>ALPN: <b className="text-zinc-200">{result.sni.alpnProtocols?.join('/') || 'none'}</b></span>
                <span>Wildcard: <b className="text-zinc-200">{result.sni.isWildcard ? 'YES' : 'NO'}</b></span>
              </div>
            </div>
          </div>

          {/* Probe Sequence Timeline (RTT per packet) */}
          <div className="bg-zinc-950 border border-zinc-800/80 rounded-xl p-4 font-mono">
            <div className="flex items-center justify-between mb-3 text-xs text-zinc-400">
              <span className="uppercase tracking-wider">Ping Probes Breakdown (Sequences)</span>
              <span>{result.ping.probes.length} Samples</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
              {result.ping.probes.map((p) => (
                <div
                  key={p.seq}
                  className={`p-2.5 rounded-lg border text-center ${
                    p.status === 'success'
                      ? 'bg-zinc-900/90 border-emerald-800/40 text-emerald-300'
                      : 'bg-rose-950/30 border-rose-800/40 text-rose-300'
                  }`}
                >
                  <div className="text-[10px] text-zinc-400 mb-0.5">Seq #{p.seq}</div>
                  <div className="font-bold text-xs">
                    {p.status === 'success' ? `${p.rtt} ms` : 'TIMEOUT'}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Route Hop Traceroute Section */}
          {result.traceroute && (
            <RouteHopVisualizer traceroute={result.traceroute} />
          )}

          {/* Direct Connection & Open Ports */}
          <div className="bg-zinc-950 border border-zinc-800/80 rounded-xl p-4 font-mono text-xs">
            <div className="flex items-center gap-2 mb-3 border-b border-zinc-900 pb-2">
              <Compass className="w-4 h-4 text-emerald-400" />
              <span className="font-bold text-zinc-200 uppercase tracking-wider">
                Direct Connection & Ports Probe
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-zinc-900/80 p-3 rounded border border-zinc-800">
                <span className="text-zinc-400 block text-[11px] mb-1">Reachable Ports</span>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {result.direct.openPorts.length > 0 ? (
                    result.direct.openPorts.map((port) => (
                      <span
                        key={port}
                        className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-700/60 text-emerald-300 text-xs font-bold"
                      >
                        PORT {port} (OPEN)
                      </span>
                    ))
                  ) : (
                    <span className="text-zinc-500">No standard ports open</span>
                  )}
                </div>
              </div>

              <div className="bg-zinc-900/80 p-3 rounded border border-zinc-800">
                <span className="text-zinc-400 block text-[11px] mb-1">TCP Handshake Time</span>
                <span className="text-base font-bold text-zinc-200">
                  {result.direct.tcpHandshakeMs > 0 ? `${result.direct.tcpHandshakeMs} ms` : 'N/A'}
                </span>
              </div>

              <div className="bg-zinc-900/80 p-3 rounded border border-zinc-800">
                <span className="text-zinc-400 block text-[11px] mb-1">Time To First Byte (TTFB)</span>
                <span className="text-base font-bold text-zinc-200">
                  {result.direct.ttfbMs > 0 ? `${result.direct.ttfbMs} ms` : 'N/A'}
                </span>
              </div>
            </div>
          </div>

          {/* Payload Discovery / Community Tunneling Bugs Table */}
          {result.payloads && result.payloads.length > 0 && (
            <div className="bg-zinc-950 border border-zinc-800/80 rounded-xl p-4 font-mono text-xs">
              <div className="flex items-center justify-between mb-3 border-b border-zinc-900 pb-2">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  <span className="font-bold text-zinc-200 uppercase tracking-wider">
                    Community Bughost Payload Prober Results
                  </span>
                </div>
                <span className="text-zinc-500 text-[11px]">
                  {result.payloads.filter((p) => p.isLoophole).length} Loopholes Found
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-zinc-800 text-[11px] text-zinc-400">
                      <th className="py-2 px-2">Payload Name</th>
                      <th className="py-2 px-2">Method / Request</th>
                      <th className="py-2 px-2">HTTP Status</th>
                      <th className="py-2 px-2">Response Time</th>
                      <th className="py-2 px-2">Viability</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-900 text-xs">
                    {result.payloads.map((p) => (
                      <tr key={p.id} className="hover:bg-zinc-900/50">
                        <td className="py-2.5 px-2 font-semibold text-zinc-200">{p.name}</td>
                        <td className="py-2.5 px-2 text-zinc-400">
                          <code className="bg-zinc-900 px-1 py-0.5 rounded text-zinc-300">
                            {p.payloadPattern}
                          </code>
                        </td>
                        <td className="py-2.5 px-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                              p.statusCode === 101 || p.statusCode === 200 || p.statusCode === 302
                                ? 'bg-emerald-950 border border-emerald-700/60 text-emerald-300'
                                : p.statusCode === 400 || p.statusCode === 403
                                ? 'bg-amber-950/60 border border-amber-800/40 text-amber-300'
                                : 'bg-zinc-900 text-zinc-500'
                            }`}
                          >
                            {p.statusCode ? `${p.statusCode} ${p.statusText || ''}` : 'Refused'}
                          </span>
                        </td>
                        <td className="py-2.5 px-2 text-zinc-300">
                          {p.responseTimeMs > 0 ? `${p.responseTimeMs} ms` : 'N/A'}
                        </td>
                        <td className="py-2.5 px-2">
                          {p.isLoophole ? (
                            <span className="text-emerald-400 font-bold flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Zero-Rating / WS Loophole</span>
                            </span>
                          ) : (
                            <span className="text-zinc-500">Standard</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
