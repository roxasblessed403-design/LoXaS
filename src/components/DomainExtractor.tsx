import React, { useState } from 'react';
import { FileSearch, Copy, Check, Play, Download, Trash2 } from 'lucide-react';
import type { SupportedLanguage } from '../types.js';

interface DomainExtractorProps {
  language: SupportedLanguage;
  onSendToBatchScan?: (targets: string[]) => void;
}

export const DomainExtractor: React.FC<DomainExtractorProps> = ({
  language,
  onSendToBatchScan,
}) => {
  const [inputText, setInputText] = useState(
    `Here is a messy proxy list with URLs and configs:
https://speed.cloudflare.com/test
104.16.240.5:443
http://cdn.zoom.us/login?ref=1
172.67.180.12
vless://uuid@1.1.1.1:443?sni=gateway.icloud.com
api.whatsapp.com/v1/status`
  );
  const [extracted, setExtracted] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);

  const handleExtract = () => {
    const domainRegex = /([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3}/g;
    const matches = inputText.match(domainRegex) || [];

    // Filter and clean
    const cleaned = Array.from(
      new Set(
        matches
          .map((m) => m.toLowerCase().replace(/:\d+$/, ''))
          .filter((m) => m.length > 3 && !m.endsWith('.png') && !m.endsWith('.jpg') && !m.endsWith('.js'))
      )
    );

    setExtracted(cleaned);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(extracted.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <span className="font-bold text-zinc-200 uppercase tracking-wider text-sm">
            Domain & IP Extractor (Menu [07])
          </span>
          <span className="text-zinc-500">Extracts clean domains & IPs from raw text/HTML</span>
        </div>

        <textarea
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          rows={6}
          placeholder="Paste raw text, HTML source, proxy configurations, or messy server logs..."
          className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-zinc-200 focus:outline-none focus:border-emerald-500"
        />

        <div className="flex justify-between items-center pt-2">
          <button
            onClick={() => setInputText('')}
            className="flex items-center gap-1 text-zinc-500 hover:text-rose-400"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Input</span>
          </button>

          <button
            onClick={handleExtract}
            className="px-6 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-bold shadow-md"
          >
            EXTRACT TARGETS
          </button>
        </div>
      </div>

      {extracted.length > 0 && (
        <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-900 pb-3">
            <span className="font-bold text-zinc-200 uppercase tracking-wide">
              Extracted Targets ({extracted.length})
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 hover:bg-zinc-800"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy List'}</span>
              </button>

              {onSendToBatchScan && (
                <button
                  onClick={() => onSendToBatchScan(extracted)}
                  className="flex items-center gap-1 px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-bold"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Send to Batch Scanner</span>
                </button>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {extracted.map((target, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded bg-zinc-900/80 border border-zinc-800 text-zinc-200 truncate"
              >
                {target}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
