import React from 'react';
import {
  GitCommit,
  ArrowRight,
  ShieldCheck,
  Globe,
  Radio,
  Clock,
  AlertTriangle,
  Server,
  Zap,
} from 'lucide-react';
import type { RouteHop, TracerouteResult } from '../types.js';

interface RouteHopVisualizerProps {
  traceroute?: TracerouteResult;
  isLoading?: boolean;
}

export const RouteHopVisualizer: React.FC<RouteHopVisualizerProps> = ({
  traceroute,
  isLoading,
}) => {
  if (isLoading) {
    return (
      <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-5">
        <div className="flex items-center gap-2 mb-4">
          <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
          <span className="text-xs font-mono text-emerald-400 font-bold uppercase tracking-wider">
            Tracing Route Hops & BGP ASNs...
          </span>
        </div>
        <div className="space-y-3 animate-pulse">
          <div className="h-10 bg-zinc-900 rounded border border-zinc-800" />
          <div className="h-10 bg-zinc-900 rounded border border-zinc-800" />
          <div className="h-10 bg-zinc-900 rounded border border-zinc-800" />
        </div>
      </div>
    );
  }

  if (!traceroute || traceroute.hops.length === 0) {
    return (
      <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-6 text-center text-zinc-500 font-mono text-xs">
        No route hop data available. Enable "Trace Hops" and run a probe.
      </div>
    );
  }

  const getRttColor = (rtt: number, status: string) => {
    if (status === 'timeout') return 'text-rose-400 bg-rose-950/40 border-rose-800/60';
    if (rtt < 30) return 'text-emerald-400 bg-emerald-950/40 border-emerald-800/60';
    if (rtt < 75) return 'text-cyan-400 bg-cyan-950/40 border-cyan-800/60';
    if (rtt < 150) return 'text-amber-400 bg-amber-950/40 border-amber-800/60';
    return 'text-rose-400 bg-rose-950/40 border-rose-800/60';
  };

  return (
    <div className="bg-zinc-950 border border-zinc-800/80 rounded-lg p-4 font-mono text-xs">
      {/* Traceroute Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800/80 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-emerald-400" />
          <span className="font-bold text-zinc-200 uppercase tracking-wide">
            Route Traceroute to {traceroute.target}
          </span>
          <span className="text-zinc-500">({traceroute.resolvedIp})</span>
        </div>

        <div className="flex items-center gap-3 text-[11px] text-zinc-400">
          <div className="flex items-center gap-1">
            <GitCommit className="w-3.5 h-3.5 text-emerald-400" />
            <span>Hops: <b className="text-zinc-200">{traceroute.totalHops}</b></span>
          </div>
          <div className="flex items-center gap-1">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Avg: <b className="text-zinc-200">{traceroute.avgRtt}ms</b></span>
          </div>
          <div className="flex items-center gap-1">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Max: <b className="text-zinc-200">{traceroute.maxRtt}ms</b></span>
          </div>
        </div>
      </div>

      {/* Visual Hop Flow Timeline */}
      <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-zinc-800">
        {traceroute.hops.map((hop, index) => {
          const isLast = index === traceroute.hops.length - 1;
          const isFirst = index === 0;
          const colorClass = getRttColor(hop.rtt, hop.status);

          return (
            <div key={hop.hop} className="relative flex items-start gap-3 group">
              {/* Hop Marker Circle */}
              <div
                className={`absolute -left-6 top-1 w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold border ${
                  hop.status === 'timeout'
                    ? 'bg-rose-950 border-rose-600 text-rose-300'
                    : isLast
                    ? 'bg-emerald-950 border-emerald-400 text-emerald-300 ring-2 ring-emerald-500/20'
                    : isFirst
                    ? 'bg-blue-950 border-blue-400 text-blue-300'
                    : 'bg-zinc-900 border-zinc-700 text-zinc-300'
                }`}
              >
                {hop.hop}
              </div>

              {/* Hop Information Card */}
              <div className="flex-1 bg-zinc-900/80 hover:bg-zinc-900 border border-zinc-800/80 rounded-md p-2.5 transition-colors">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-zinc-200">
                      {hop.ip === '*' ? 'Request Timed Out (*)' : hop.ip}
                    </span>

                    {hop.hostname && (
                      <span className="text-[11px] text-zinc-400 truncate max-w-[200px] sm:max-w-xs">
                        ({hop.hostname})
                      </span>
                    )}

                    {isFirst && (
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-blue-950 border border-blue-700/50 text-blue-300">
                        Local Gateway
                      </span>
                    )}

                    {isLast && (
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 border border-emerald-700/50 text-emerald-300">
                        Destination
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {hop.asn && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                        {hop.asn}
                      </span>
                    )}

                    {hop.country && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">
                        {hop.country}
                      </span>
                    )}

                    {/* Hop Latency Badge */}
                    <span
                      className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${colorClass}`}
                    >
                      {hop.status === 'timeout' ? 'TIMEOUT' : `${hop.rtt} ms`}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
