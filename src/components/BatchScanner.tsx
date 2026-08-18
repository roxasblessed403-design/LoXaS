import React, { useState, useRef } from 'react';
import {
  Play,
  Square,
  Upload,
  Layers,
  Activity,
  CheckCircle2,
  AlertTriangle,
  FolderArchive,
  Download,
  Filter,
  Server,
  Zap,
  Radio,
  FileText,
  Copy,
} from 'lucide-react';
import type { ScanItemResult, SupportedLanguage, TargetCategory } from '../types.js';
import { TRANSLATIONS } from '../translations.js';

interface BatchScannerProps {
  onScanCompleteItem?: (item: ScanItemResult) => void;
  language: SupportedLanguage;
  onOpenItem?: (item: ScanItemResult) => void;
  onOpenFileInManager?: (path: string) => void;
}

const QUICK_TEST_PRESETS = [
  'speed.cloudflare.com',
  'www.cloudflare.com',
  '104.16.240.5',
  '172.67.180.12',
  'd1.awsstatic.com',
  'www.fastly.com',
  'cdn.zoom.us',
  '1.1.1.1',
  '8.8.8.8',
  'gateway.icloud.com',
  'api.whatsapp.com',
];

export const BatchScanner: React.FC<BatchScannerProps> = ({
  onScanCompleteItem,
  language,
  onOpenItem,
  onOpenFileInManager,
}) => {
  const [rawText, setRawText] = useState(
    'speed.cloudflare.com\n104.16.240.5\n172.67.180.12\ncdn.zoom.us\n1.1.1.1\n8.8.8.8\n104.16.0.0/28'
  );
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<ScanItemResult[]>([]);
  const [activeFilter, setActiveFilter] = useState<string>('all');
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [concurrency, setConcurrency] = useState(6);
  const [pingCount, setPingCount] = useState(4);
  const [checkCdn, setCheckCdn] = useState(true);
  const [checkSni, setCheckSni] = useState(true);
  const [checkTraceroute, setCheckTraceroute] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  const t = TRANSLATIONS[language] || TRANSLATIONS.en;

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setRawText(content);
      }
    };
    reader.readAsText(file);
  };

  const handleLoadQuickPreset = () => {
    setRawText(QUICK_TEST_PRESETS.join('\n'));
  };

  const handleStartScan = () => {
    const targets = rawText
      .split('\n')
      .map((t) => t.trim())
      .filter((t) => t.length > 0 && !t.startsWith('#'));

    if (targets.length === 0) return;

    setIsScanning(true);
    setResults([]);
    setProgress({ current: 0, total: targets.length });

    // Close any previous stream
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const queryParams = new URLSearchParams({
      targets: targets.join(','),
      pingCount: String(pingCount),
      checkCdn: String(checkCdn),
      checkSni: String(checkSni),
      checkTraceroute: String(checkTraceroute),
      concurrency: String(concurrency),
    });

    const es = new EventSource(`/api/scan/stream?${queryParams.toString()}`);
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'start') {
          setProgress({ current: 0, total: data.total });
        } else if (data.type === 'item') {
          const item: ScanItemResult = data.result;
          setResults((prev) => [item, ...prev]);
          setProgress({ current: data.completed, total: data.total });
          if (onScanCompleteItem) {
            onScanCompleteItem(item);
          }
        } else if (data.type === 'done') {
          setIsScanning(false);
          es.close();
        }
      } catch (err) {
        console.error('Error parsing SSE stream message:', err);
      }
    };

    es.onerror = () => {
      setIsScanning(false);
      es.close();
    };
  };

  const handleStopScan = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    setIsScanning(false);
  };

  const filteredResults = results.filter((item) => {
    if (activeFilter === 'all') return true;
    if (activeFilter === 'cdn') return item.cdn.isCdn;
    if (activeFilter === 'sni') return item.sni.hasSni;
    if (activeFilter === 'direct') return item.direct.directReachable;
    if (activeFilter === 'alive') return item.ping.isAlive;
    if (activeFilter === 'unreachable') return !item.ping.isAlive;
    return true;
  });

  const cdnCount = results.filter((r) => r.cdn.isCdn).length;
  const sniCount = results.filter((r) => r.sni.hasSni).length;
  const directCount = results.filter((r) => r.direct.directReachable).length;
  const aliveCount = results.filter((r) => r.ping.isAlive).length;

  const handleExportTxt = () => {
    const textContent = results
      .map(
        (r) =>
          `${r.target.padEnd(25)} | IP: ${(r.resolvedIp || 'N/A').padEnd(16)} | Ping: ${String(
            r.ping.latencyAvg + 'ms'
          ).padEnd(8)} | Loss: ${String(r.ping.packetLoss + '%').padEnd(6)} | CDN: ${
            r.cdn.provider
          } | SNI: ${r.sni.hasSni ? 'YES' : 'NO'}`
      )
      .join('\n');

    const blob = new Blob([textContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `paragon_scan_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Configuration & Input Card */}
      <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-5 shadow-xl font-mono text-xs space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-emerald-400" />
            <span className="font-bold text-zinc-200 uppercase tracking-wider text-sm">
              Bulk Host & CIDR Batch Scanner
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleLoadQuickPreset}
              className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 hover:bg-zinc-800 transition-colors"
            >
              Quick Test Presets (10)
            </button>

            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".txt,.csv,.list"
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 hover:bg-zinc-800 transition-colors"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Browse .txt file</span>
            </button>
          </div>
        </div>

        {/* Input Textarea */}
        <div>
          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste domains, IPs, or CIDRs (e.g. 104.16.0.0/24), one per line..."
            rows={5}
            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-zinc-200 font-mono text-xs focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
          />
        </div>

        {/* Scanner Control Options */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-zinc-900">
          <div className="flex flex-wrap items-center gap-4 text-zinc-400">
            <div className="flex items-center gap-2">
              <span>Workers:</span>
              <select
                value={concurrency}
                onChange={(e) => setConcurrency(parseInt(e.target.value, 10))}
                className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-200 outline-none"
              >
                <option value="4">4 Workers</option>
                <option value="8">8 Workers</option>
                <option value="12">12 Workers</option>
                <option value="16">16 Workers</option>
              </select>
            </div>

            <label className="flex items-center gap-1.5 cursor-pointer text-zinc-300">
              <input
                type="checkbox"
                checked={checkCdn}
                onChange={(e) => setCheckCdn(e.target.checked)}
                className="rounded bg-zinc-900 border-zinc-700 text-emerald-500"
              />
              <span>Detect CDN</span>
            </label>

            <label className="flex items-center gap-1.5 cursor-pointer text-zinc-300">
              <input
                type="checkbox"
                checked={checkSni}
                onChange={(e) => setCheckSni(e.target.checked)}
                className="rounded bg-zinc-900 border-zinc-700 text-emerald-500"
              />
              <span>Check SNI/TLS</span>
            </label>

            <label className="flex items-center gap-1.5 cursor-pointer text-zinc-300">
              <input
                type="checkbox"
                checked={checkTraceroute}
                onChange={(e) => setCheckTraceroute(e.target.checked)}
                className="rounded bg-zinc-900 border-zinc-700 text-emerald-500"
              />
              <span>Trace Hops</span>
            </label>
          </div>

          <div className="flex items-center gap-2">
            {isScanning ? (
              <button
                onClick={handleStopScan}
                className="flex items-center gap-1.5 px-5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-zinc-950 font-bold shadow-md transition-colors"
              >
                <Square className="w-4 h-4 fill-current" />
                <span>STOP SCAN</span>
              </button>
            ) : (
              <button
                onClick={handleStartScan}
                className="flex items-center gap-1.5 px-6 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-bold shadow-md shadow-emerald-950/50 transition-colors"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>START BATCH SCAN</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Progress Bar */}
        {progress.total > 0 && (
          <div className="space-y-1.5 pt-2">
            <div className="flex justify-between text-[11px] text-zinc-400">
              <span className="flex items-center gap-1.5">
                {isScanning && <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />}
                <span>Progress: {progress.current} / {progress.total} scanned</span>
              </span>
              <span>{Math.round((progress.current / Math.max(1, progress.total)) * 100)}%</span>
            </div>
            <div className="w-full h-2 bg-zinc-900 rounded-full overflow-hidden border border-zinc-800">
              <div
                className="h-full bg-gradient-to-r from-emerald-600 via-teal-500 to-cyan-400 transition-all duration-300"
                style={{
                  width: `${(progress.current / Math.max(1, progress.total)) * 100}%`,
                }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Summary Filter Cards */}
      {results.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono text-xs">
          <button
            onClick={() => setActiveFilter('all')}
            className={`p-3 rounded-lg border text-left transition-all ${
              activeFilter === 'all'
                ? 'bg-zinc-900 border-emerald-500 text-zinc-100 shadow-sm'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
            }`}
          >
            <div className="text-[11px] text-zinc-400">Total Scanned</div>
            <div className="text-lg font-bold text-zinc-100">{results.length}</div>
          </button>

          <button
            onClick={() => setActiveFilter('cdn')}
            className={`p-3 rounded-lg border text-left transition-all ${
              activeFilter === 'cdn'
                ? 'bg-purple-950/40 border-purple-500 text-purple-200'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
            }`}
          >
            <div className="text-[11px] text-purple-400">CDN Edge Hosts</div>
            <div className="text-lg font-bold text-purple-300">{cdnCount}</div>
          </button>

          <button
            onClick={() => setActiveFilter('sni')}
            className={`p-3 rounded-lg border text-left transition-all ${
              activeFilter === 'sni'
                ? 'bg-amber-950/40 border-amber-500 text-amber-200'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
            }`}
          >
            <div className="text-[11px] text-amber-400">SNI Hosts</div>
            <div className="text-lg font-bold text-amber-300">{sniCount}</div>
          </button>

          <button
            onClick={() => setActiveFilter('direct')}
            className={`p-3 rounded-lg border text-left transition-all ${
              activeFilter === 'direct'
                ? 'bg-blue-950/40 border-blue-500 text-blue-200'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
            }`}
          >
            <div className="text-[11px] text-blue-400">Direct IP Reachable</div>
            <div className="text-lg font-bold text-blue-300">{directCount}</div>
          </button>

          <button
            onClick={() => setActiveFilter('alive')}
            className={`p-3 rounded-lg border text-left transition-all ${
              activeFilter === 'alive'
                ? 'bg-emerald-950/40 border-emerald-500 text-emerald-200'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
            }`}
          >
            <div className="text-[11px] text-emerald-400">Active / Alive</div>
            <div className="text-lg font-bold text-emerald-300">{aliveCount}</div>
          </button>
        </div>
      )}

      {/* Results Table View */}
      {results.length > 0 && (
        <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 font-mono text-xs space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-900 pb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              <span className="font-bold text-zinc-200 uppercase tracking-wide">
                Live Scan Items ({filteredResults.length})
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleExportTxt}
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 hover:bg-zinc-800 transition-colors text-xs"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export TXT</span>
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-zinc-800 text-[11px] text-zinc-400">
                  <th className="py-2.5 px-2">Target Host</th>
                  <th className="py-2.5 px-2">Resolved IP</th>
                  <th className="py-2.5 px-2">Ping Latency</th>
                  <th className="py-2.5 px-2">Packet Loss</th>
                  <th className="py-2.5 px-2">CDN Edge</th>
                  <th className="py-2.5 px-2">SNI / TLS</th>
                  <th className="py-2.5 px-2">Auto-Saved Directory</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-900 text-xs">
                {filteredResults.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => onOpenItem?.(item)}
                    className="hover:bg-zinc-900/60 cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 px-2 font-bold text-zinc-200">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            item.ping.isAlive ? 'bg-emerald-500' : 'bg-rose-500'
                          }`}
                        />
                        <span>{item.target}</span>
                      </div>
                    </td>

                    <td className="py-2.5 px-2 text-zinc-400">
                      {item.resolvedIp || 'N/A'}
                    </td>

                    <td className="py-2.5 px-2 font-bold text-zinc-200">
                      {item.ping.isAlive ? `${item.ping.latencyAvg} ms` : 'TIMEOUT'}
                    </td>

                    <td className="py-2.5 px-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          item.ping.packetLoss === 0
                            ? 'text-emerald-400 bg-emerald-950/60'
                            : item.ping.packetLoss < 50
                            ? 'text-amber-400 bg-amber-950/60'
                            : 'text-rose-400 bg-rose-950/60'
                        }`}
                      >
                        {item.ping.packetLoss}%
                      </span>
                    </td>

                    <td className="py-2.5 px-2">
                      {item.cdn.isCdn ? (
                        <span className="px-2 py-0.5 rounded bg-purple-950/80 border border-purple-700/60 text-purple-300 text-[11px] font-bold">
                          {item.cdn.provider}
                        </span>
                      ) : (
                        <span className="text-zinc-600">None</span>
                      )}
                    </td>

                    <td className="py-2.5 px-2">
                      {item.sni.hasSni ? (
                        <span className="px-2 py-0.5 rounded bg-amber-950/80 border border-amber-700/60 text-amber-300 text-[11px]">
                          {item.sni.tlsVersion || 'TLS Valid'}
                        </span>
                      ) : (
                        <span className="text-zinc-600">No SNI</span>
                      )}
                    </td>

                    <td className="py-2.5 px-2">
                      {item.savedDirectory ? (
                        <span
                          onClick={(e) => {
                            e.stopPropagation();
                            onOpenFileInManager?.(item.savedDirectory + '/' + item.savedFileName);
                          }}
                          className="text-emerald-400 hover:underline text-[11px]"
                        >
                          {item.savedDirectory}/{item.savedFileName}
                        </span>
                      ) : (
                        <span className="text-zinc-600">-</span>
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
  );
};
