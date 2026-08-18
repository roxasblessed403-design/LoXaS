import React, { useState, useEffect } from 'react';
import { Sparkles, X, Brain, CheckCircle2, ShieldCheck, Zap, Server, RefreshCw } from 'lucide-react';
import type { ScanItemResult, SupportedLanguage } from '../types.js';

interface AiDoctorModalProps {
  item: ScanItemResult | null;
  onClose: () => void;
  language: SupportedLanguage;
}

export const AiDoctorModal: React.FC<AiDoctorModalProps> = ({
  item,
  onClose,
  language,
}) => {
  const [analysisText, setAnalysisText] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (!item) return;

    const fetchAnalysis = async () => {
      setIsLoading(true);
      try {
        const res = await fetch('/api/ai/diagnose', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target: item.target,
            pingData: item.ping,
            cdnData: item.cdn,
            sniData: item.sni,
            routeHops: item.traceroute?.hops,
          }),
        });

        if (res.ok) {
          const data = await res.json();
          setAnalysisText(data.analysis || 'Analysis complete.');
        }
      } catch (err) {
        setAnalysisText('Failed to reach AI diagnostic engine.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchAnalysis();
  }, [item]);

  if (!item) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
      <div className="bg-zinc-950 border border-purple-800/60 rounded-2xl p-6 max-w-2xl w-full shadow-2xl font-mono text-xs space-y-4 relative">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-zinc-500 hover:text-zinc-200 p-1"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 border-b border-zinc-900 pb-3">
          <div className="w-9 h-9 rounded-lg bg-purple-950/80 border border-purple-600/50 flex items-center justify-center">
            <Sparkles className="w-5 h-5 text-purple-400 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-zinc-100 uppercase tracking-wide flex items-center gap-2">
              <span>Paragon AI Bughost & Route Doctor</span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-700/60">
                Gemini 2.5 Engine
              </span>
            </h3>
            <p className="text-[11px] text-zinc-400">
              Target: <b className="text-emerald-400">{item.target}</b> ({item.resolvedIp || 'N/A'})
            </p>
          </div>
        </div>

        {/* Target Quick Stats Summary */}
        <div className="grid grid-cols-3 gap-2 bg-zinc-900/60 p-3 rounded-lg border border-zinc-800 text-[11px]">
          <div>
            <span className="text-zinc-500 block">Ping Avg / Loss:</span>
            <span className="font-bold text-zinc-200">
              {item.ping.latencyAvg}ms ({item.ping.packetLoss}% loss)
            </span>
          </div>
          <div>
            <span className="text-zinc-500 block">CDN Classification:</span>
            <span className="font-bold text-purple-300">{item.cdn.provider}</span>
          </div>
          <div>
            <span className="text-zinc-500 block">SNI & ALPN:</span>
            <span className="font-bold text-amber-300">
              {item.sni.hasSni ? item.sni.alpnProtocols?.join('/') || 'TLS Valid' : 'None'}
            </span>
          </div>
        </div>

        {/* AI Output Content Box */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 min-h-[160px] text-zinc-200 leading-relaxed whitespace-pre-wrap">
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-8 space-y-2 text-purple-400">
              <RefreshCw className="w-6 h-6 animate-spin" />
              <span className="text-xs">Analyzing packet loss, CDN headers & route hops...</span>
            </div>
          ) : (
            analysisText
          )}
        </div>

        {/* Bottom Actions */}
        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-zinc-950 font-bold transition-colors"
          >
            Close Diagnostics
          </button>
        </div>
      </div>
    </div>
  );
};
