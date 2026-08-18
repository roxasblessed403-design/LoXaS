import React, { useState, useEffect, useRef } from 'react';
import { Terminal as TermIcon, Play, RefreshCw, Copy, Download, Trash2, ArrowUp, ArrowDown, ExternalLink } from 'lucide-react';
import type { ScanItemResult, SupportedLanguage } from '../types.js';

interface TerminalViewProps {
  onScanComplete?: (item: ScanItemResult) => void;
  language: SupportedLanguage;
  onSwitchToDashboard?: () => void;
  onSwitchToFiles?: () => void;
}

interface TerminalLogLine {
  id: string;
  type: 'banner' | 'menu_1' | 'menu_2' | 'menu_3' | 'menu_4' | 'menu_5' | 'menu_6' | 'menu_7' | 'menu_8' | 'menu_9' | 'menu_0' | 'prompt' | 'input' | 'output' | 'success' | 'warn' | 'error' | 'cdn' | 'sni' | 'hop';
  text: string;
  choiceKey?: string;
}

export const TerminalView: React.FC<TerminalViewProps> = ({
  onScanComplete,
  language,
  onSwitchToDashboard,
  onSwitchToFiles,
}) => {
  const [inputVal, setInputVal] = useState('');
  const [currentMenuStep, setCurrentMenuStep] = useState<
    'main' | 'prompt_host' | 'prompt_subfinder' | 'prompt_iplookup' | 'prompt_portscan' | 'prompt_dns' | 'prompt_hostinfo'
  >('main');
  const [history, setHistory] = useState<TerminalLogLine[]>([]);
  const [isRunning, setIsRunning] = useState(false);

  const logsEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const appendLine = (
    text: string,
    type: TerminalLogLine['type'] = 'output',
    choiceKey?: string
  ) => {
    setHistory((prev) => [
      ...prev,
      { id: `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, type, text, choiceKey },
    ]);
  };

  const showMainMenu = () => {
    setHistory([
      { id: 'm_1', type: 'menu_1', text: '[1]  HOST SCANNER', choiceKey: '1' },
      { id: 'm_2', type: 'menu_2', text: '[2]  SUBFINDER', choiceKey: '2' },
      { id: 'm_3', type: 'menu_3', text: '[3]  IP LOOKUP', choiceKey: '3' },
      { id: 'm_4', type: 'menu_4', text: '[4]  FILE TOOLKIT', choiceKey: '4' },
      { id: 'm_5', type: 'menu_5', text: '[5]  PORT SCANNER', choiceKey: '5' },
      { id: 'm_6', type: 'menu_6', text: '[6]  DNS RECORD', choiceKey: '6' },
      { id: 'm_7', type: 'menu_7', text: '[7]  HOST INFO', choiceKey: '7' },
      { id: 'm_8', type: 'menu_8', text: '[8]  HELP', choiceKey: '8' },
      { id: 'm_9', type: 'menu_9', text: '[9]  UPDATE', choiceKey: '9' },
      { id: 'm_0', type: 'menu_0', text: '[0]  EXIT', choiceKey: '0' },
      { id: 'sep_blank', type: 'output', text: '' },
    ]);
    setCurrentMenuStep('main');
  };

  useEffect(() => {
    showMainMenu();
  }, []);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  const handleCommandSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const val = inputVal.trim();
    if (!val && currentMenuStep === 'main') return;

    setInputVal('');

    if (currentMenuStep === 'main') {
      appendLine(`[-]  Your Choice: ${val}`, 'input');

      switch (val) {
        case '1':
        case '01':
          setCurrentMenuStep('prompt_host');
          appendLine('[-]  [1] HOST SCANNER: Ping, ICMP, Loss, Route Hops & CDN Probe', 'menu_1');
          appendLine('[-]  Enter Host, Domain, IP, or CIDR (e.g. speed.cloudflare.com or 104.16.0.0/28):', 'warn');
          break;

        case '2':
        case '02':
          setCurrentMenuStep('prompt_subfinder');
          appendLine('[-]  [2] SUBFINDER: Cloud CDN & Root Subdomain Enumeration', 'menu_2');
          appendLine('[-]  Enter Root Domain (e.g. cloudflare.com, tiktok.com, zoom.us):', 'warn');
          break;

        case '3':
        case '03':
          setCurrentMenuStep('prompt_iplookup');
          appendLine('[-]  [3] IP LOOKUP: Reverse PTR, ASN, ISP & Cloud CDN Detection', 'menu_3');
          appendLine('[-]  Enter IP address or Hostname to inspect:', 'warn');
          break;

        case '4':
        case '04':
          appendLine('[-]  [4] FILE TOOLKIT: Storage & Directory Hub', 'menu_4');
          runFileToolkit();
          break;

        case '5':
        case '05':
          setCurrentMenuStep('prompt_portscan');
          appendLine('[-]  [5] PORT SCANNER: Multi-Port TCP & Tunnel TTFB Inspector', 'menu_5');
          appendLine('[-]  Enter Host or IP to scan tunneling ports (80, 443, 8080, 8443, 2052-2096, 22):', 'warn');
          break;

        case '6':
        case '06':
          setCurrentMenuStep('prompt_dns');
          appendLine('[-]  [6] DNS RECORD: Query A, AAAA, CNAME, MX, TXT, NS, SOA Records', 'menu_6');
          appendLine('[-]  Enter Domain name to query:', 'warn');
          break;

        case '7':
        case '07':
          setCurrentMenuStep('prompt_hostinfo');
          appendLine('[-]  [7] HOST INFO: SSL/TLS Certificate, Issuer, SANs & Fronting Info', 'menu_7');
          appendLine('[-]  Enter Domain or Host for TLS certificate deep inspection:', 'warn');
          break;

        case '8':
        case '08':
        case 'help':
          showHelpMenu();
          break;

        case '9':
        case '09':
          runUpdateCheck();
          break;

        case '0':
        case '00':
        case 'exit':
        case 'clear':
          showMainMenu();
          break;

        default:
          appendLine(`[-]  Invalid Choice "${val}". Please enter 1 - 0.`, 'error');
          appendLine('', 'output');
          showMainMenu();
          break;
      }
    } else if (currentMenuStep === 'prompt_host') {
      appendLine(`[-]  Target: ${val}`, 'input');
      runHostScanner(val);
      setCurrentMenuStep('main');
    } else if (currentMenuStep === 'prompt_subfinder') {
      appendLine(`[-]  Domain: ${val}`, 'input');
      runSubfinder(val);
      setCurrentMenuStep('main');
    } else if (currentMenuStep === 'prompt_iplookup') {
      appendLine(`[-]  IP / Target: ${val}`, 'input');
      runIpLookup(val);
      setCurrentMenuStep('main');
    } else if (currentMenuStep === 'prompt_portscan') {
      appendLine(`[-]  Target: ${val}`, 'input');
      runPortScanner(val);
      setCurrentMenuStep('main');
    } else if (currentMenuStep === 'prompt_dns') {
      appendLine(`[-]  Domain: ${val}`, 'input');
      runDnsRecord(val);
      setCurrentMenuStep('main');
    } else if (currentMenuStep === 'prompt_hostinfo') {
      appendLine(`[-]  Target: ${val}`, 'input');
      runHostInfo(val);
      setCurrentMenuStep('main');
    }
  };

  // [1] HOST SCANNER
  const runHostScanner = async (target: string) => {
    setIsRunning(true);
    appendLine(`[+] Resolving DNS & executing probe on: ${target}...`, 'output');

    if (target.includes('/')) {
      // CIDR range scan
      try {
        const expandRes = await fetch('/api/cidr/expand', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ cidr: target, limit: 16 }),
        });
        const expandData = await expandRes.json();
        appendLine(`[+] Probing ${expandData.count} IPs from subnet ${target}...`, 'output');

        const batchRes = await fetch('/api/scan/batch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            targets: expandData.ips,
            options: { pingCount: 3, checkCdn: true, checkSni: true, autoSave: true },
          }),
        });
        const batchData = await batchRes.json();

        appendLine(`-----------------------------------------------------------------`, 'output');
        appendLine(`[+] CIDR SCAN COMPLETED: ${batchData.completed} hosts probed`, 'success');
        batchData.results?.forEach((item: ScanItemResult) => {
          onScanComplete?.(item);
          const statusBadge = item.ping.isAlive ? `[${item.ping.latencyAvg}ms]` : `[TIMEOUT]`;
          const cdnBadge = item.cdn.isCdn ? `[${item.cdn.provider}]` : `[Direct]`;
          appendLine(
            `• ${item.target.padEnd(20)} ${statusBadge.padEnd(10)} Loss: ${String(item.ping.packetLoss + '%').padEnd(5)} ${cdnBadge.padEnd(14)} -> ${item.savedDirectory}`,
            item.ping.isAlive ? (item.cdn.isCdn ? 'cdn' : 'success') : 'error'
          );
        });
        appendLine(`-----------------------------------------------------------------`, 'output');
      } catch (err: any) {
        appendLine(`[!] CIDR probe error: ${err.message}`, 'error');
      } finally {
        setIsRunning(false);
        appendLine('', 'output');
      }
      return;
    }

    try {
      const res = await fetch('/api/scan/single', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          options: {
            pingCount: 4,
            checkTraceroute: true,
            checkCdn: true,
            checkSni: true,
            checkPayloads: true,
            autoSave: true,
          },
        }),
      });

      const data: ScanItemResult = await res.json();
      onScanComplete?.(data);

      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
      appendLine(`TARGET      : ${data.target} (Resolved: ${data.resolvedIp || 'N/A'})`, 'success');
      appendLine(
        `PING STATUS : ${data.ping.isAlive ? 'ALIVE' : 'DEAD / TIMEOUT'} | Avg: ${data.ping.latencyAvg}ms | Loss: ${data.ping.packetLoss}% | Jitter: ${data.ping.jitter}ms`,
        data.ping.isAlive ? 'success' : 'error'
      );
      appendLine(
        `CDN EDGE    : ${data.cdn.isCdn ? `DETECTED (${data.cdn.provider})` : 'None / Direct Origin'}`,
        data.cdn.isCdn ? 'cdn' : 'output'
      );
      if (data.cdn.matchedHeaders.length > 0) {
        appendLine(`CDN HEADERS : ${data.cdn.matchedHeaders.join(', ')}`, 'cdn');
      }
      appendLine(
        `TLS / SNI   : ${data.sni.hasSni ? `VALID (${data.sni.tlsVersion}) | ALPN: ${data.sni.alpnProtocols.join('/')}` : 'No TLS'} | Frontable: ${data.sni.isFrontable ? 'YES' : 'NO'}`,
        data.sni.hasSni ? 'sni' : 'output'
      );
      appendLine(
        `DIRECT TCP  : Open Ports: [${data.direct.openPorts.join(', ')}] | TTFB: ${data.direct.ttfbMs}ms`,
        'output'
      );

      if (data.traceroute && data.traceroute.hops.length > 0) {
        appendLine(`ROUTE HOPS  : ${data.traceroute.totalHops} hops mapped (Transit delay: ${data.traceroute.avgRtt}ms)`, 'hop');
        data.traceroute.hops.slice(0, 6).forEach((h) => {
          appendLine(`   Hop #${h.hop}: ${h.ip.padEnd(16)} | ${h.rtt}ms | ${h.status}`, 'hop');
        });
      }

      if (data.savedDirectory) {
        appendLine(`AUTO-SAVED  : data_storage/${data.savedDirectory}/${data.savedFileName}`, 'success');
      }
      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    } catch (err: any) {
      appendLine(`[!] Host scan error: ${err.message}`, 'error');
    } finally {
      setIsRunning(false);
      appendLine('', 'output');
    }
  };

  // [2] SUBFINDER
  const runSubfinder = async (domain: string) => {
    setIsRunning(true);
    appendLine(`[+] Discovering subdomains and edge nodes for ${domain}...`, 'output');

    try {
      const res = await fetch('/api/subdomains/enum', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });

      const data = await res.json();
      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
      appendLine(`FOUND ${data.found} SUBDOMAINS FOR ${data.domain}:`, 'success');

      data.subdomains?.forEach((sub: any) => {
        appendLine(
          `• ${sub.subdomain.padEnd(28)} | IP: ${(sub.ip || 'N/A').padEnd(15)} | CDN: ${sub.provider}`,
          sub.isCdn ? 'cdn' : 'success'
        );
      });
      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    } catch (err: any) {
      appendLine(`[!] Subfinder error: ${err.message}`, 'error');
    } finally {
      setIsRunning(false);
      appendLine('', 'output');
    }
  };

  // [3] IP LOOKUP
  const runIpLookup = async (target: string) => {
    setIsRunning(true);
    appendLine(`[+] Performing IP lookup & ASN inspection for ${target}...`, 'output');

    try {
      const res = await fetch('/api/ip/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });
      const data = await res.json();

      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
      appendLine(`IP LOOKUP RESULTS FOR: ${data.target}`, 'menu_3');
      appendLine(`Resolved IPv4  : ${data.ip}`, 'success');
      appendLine(`Reverse PTR    : ${data.reversePtr.length > 0 ? data.reversePtr.join(', ') : 'None (No PTR)'}`, 'output');
      appendLine(`Cloud Provider : ${data.cloudProvider}`, data.isCdn ? 'cdn' : 'output');
      appendLine(`Autonomous Sys : ${data.suggestedAsn}`, 'warn');
      appendLine(`Network Type   : ${data.isPrivate ? 'Private / RFC1918' : 'Public Internet IPv4'}`, 'output');
      appendLine(`CDN Edge Node  : ${data.isCdn ? 'YES (Edge Proxy)' : 'No (Direct Origin)'}`, data.isCdn ? 'cdn' : 'output');
      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    } catch (err: any) {
      appendLine(`[!] IP lookup error: ${err.message}`, 'error');
    } finally {
      setIsRunning(false);
      appendLine('', 'output');
    }
  };

  // [4] FILE TOOLKIT
  const runFileToolkit = async () => {
    setIsRunning(true);
    try {
      const res = await fetch('/api/storage/tree');
      const tree = await res.json();

      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
      appendLine(`📁 LOCAL FILE DIRECTORIES & AUTO-SAVED PROBES:`, 'menu_4');
      appendLine(`Root Storage: ./data_storage/`, 'output');
      appendLine(`Total Files Stored: ${tree.totalFiles || 0}`, 'success');

      tree.categories?.forEach((cat: any) => {
        appendLine(` • ./${cat.path.padEnd(20)} (${cat.fileCount} items)`, 'menu_1');
      });

      appendLine(`Actions:`, 'warn');
      appendLine(` - Click [DIR] button in footer or switch to Directory Tab to manage`, 'output');
      appendLine(` - Download all files ZIP: /api/storage/download-zip`, 'success');
      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    } catch (err: any) {
      appendLine(`[!] File toolkit error: ${err.message}`, 'error');
    } finally {
      setIsRunning(false);
      appendLine('', 'output');
    }
  };

  // [5] PORT SCANNER
  const runPortScanner = async (target: string) => {
    setIsRunning(true);
    appendLine(`[+] Scanning tunneling & proxy ports on ${target}...`, 'output');

    try {
      const res = await fetch('/api/scan/ports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });
      const data = await res.json();

      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
      appendLine(`PORT SCAN RESULTS FOR: ${data.target} (${data.resolvedIp})`, 'menu_5');
      appendLine(`PORT   STATUS     TTFB (ms)   SERVICE / PROTOCOL`, 'warn');
      appendLine(`────   ──────     ─────────   ──────────────────`, 'output');

      data.openPorts?.forEach((p: any) => {
        const statusColor = p.status === 'OPEN' ? 'success' : p.status === 'CLOSED' ? 'output' : 'error';
        const portStr = String(p.port).padEnd(6);
        const statStr = `[${p.status}]`.padEnd(10);
        const latencyStr = (p.status === 'OPEN' ? `${p.latencyMs}ms` : '-').padEnd(11);
        appendLine(`${portStr} ${statStr} ${latencyStr} ${p.service}`, statusColor);
      });
      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    } catch (err: any) {
      appendLine(`[!] Port scanner error: ${err.message}`, 'error');
    } finally {
      setIsRunning(false);
      appendLine('', 'output');
    }
  };

  // [6] DNS RECORD
  const runDnsRecord = async (domain: string) => {
    setIsRunning(true);
    appendLine(`[+] Querying authoritative DNS records for ${domain}...`, 'output');

    try {
      const res = await fetch('/api/dns/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json();

      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
      appendLine(`DNS RECORDS FOR: ${data.domain}`, 'menu_6');
      if (data.a?.length > 0) appendLine(`A (IPv4)   : ${data.a.join(', ')}`, 'success');
      if (data.aaaa?.length > 0) appendLine(`AAAA (IPv6): ${data.aaaa.join(', ')}`, 'output');
      if (data.cname?.length > 0) appendLine(`CNAME      : ${data.cname.join(', ')}`, 'cdn');
      if (data.mx?.length > 0) {
        appendLine(`MX Records :`, 'warn');
        data.mx.forEach((m: any) => appendLine(`   - [Priority: ${m.priority}] ${m.exchange}`, 'output'));
      }
      if (data.txt?.length > 0) {
        appendLine(`TXT Records:`, 'warn');
        data.txt.slice(0, 4).forEach((t: string) => appendLine(`   - ${t}`, 'output'));
      }
      if (data.ns?.length > 0) appendLine(`NS Servers : ${data.ns.join(', ')}`, 'output');
      if (data.soa) appendLine(`SOA Primary: ${data.soa.nsname} (Serial: ${data.soa.serial})`, 'output');
      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    } catch (err: any) {
      appendLine(`[!] DNS lookup error: ${err.message}`, 'error');
    } finally {
      setIsRunning(false);
      appendLine('', 'output');
    }
  };

  // [7] HOST INFO
  const runHostInfo = async (target: string) => {
    setIsRunning(true);
    appendLine(`[+] Extracting SSL/TLS certificate details and SANs for ${target}...`, 'output');

    try {
      const res = await fetch('/api/host/info', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });
      const data = await res.json();

      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
      appendLine(`HOST SSL/TLS INFO FOR: ${data.target}`, 'menu_7');
      appendLine(`TLS Version    : ${data.tlsVersion}`, data.hasTls ? 'success' : 'error');
      appendLine(`Cipher Suite   : ${data.cipherName}`, 'output');
      appendLine(`Issuer Org     : ${data.issuer?.O || data.issuer?.CN || 'Unknown'}`, 'cdn');
      appendLine(`Subject CN     : ${data.subject?.CN || 'Unknown'}`, 'output');
      appendLine(`Valid Range    : ${data.validFrom || '-'} to ${data.validTo || '-'}`, 'output');
      appendLine(`Days Remaining : ${data.daysRemaining || 0} days`, (data.daysRemaining || 0) > 30 ? 'success' : 'warn');
      appendLine(`Wildcard Cert  : ${data.isWildcard ? 'YES (*.domain)' : 'No'}`, 'warn');
      appendLine(`CDN Frontable  : ${data.isFrontable ? 'YES (Domain Fronting Capable)' : 'No'}`, data.isFrontable ? 'success' : 'output');
      appendLine(`ALPN Protocols : ${data.alpnProtocols?.join(', ') || 'http/1.1'}`, 'output');
      appendLine(`HTTP/2 Support : ${data.http2Supported ? 'YES (h2)' : 'No'}`, data.http2Supported ? 'success' : 'output');
      if (data.sanList?.length > 0) {
        appendLine(`SANs (${data.sanList.length} domains):`, 'warn');
        appendLine(`  ${data.sanList.slice(0, 8).join(', ')}`, 'output');
      }
      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    } catch (err: any) {
      appendLine(`[!] Host info error: ${err.message}`, 'error');
    } finally {
      setIsRunning(false);
      appendLine('', 'output');
    }
  };

  // [8] HELP
  const showHelpMenu = () => {
    appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    appendLine(`LoXaSB PRO 5.4 - COMMAND LINE & SHORTCUT GUIDE`, 'menu_8');
    appendLine(`[1] HOST SCANNER  : Probe ping latency, loss %, CDN detection & route hops`, 'menu_1');
    appendLine(`[2] SUBFINDER     : Enumerate and test edge subdomains for a domain`, 'menu_2');
    appendLine(`[3] IP LOOKUP     : Geolocation, ASN, reverse PTR, and cloud detection`, 'menu_3');
    appendLine(`[4] FILE TOOLKIT  : Explore categorized storage folders and export files`, 'menu_4');
    appendLine(`[5] PORT SCANNER  : Scan proxy/tunneling ports with TTFB response times`, 'menu_5');
    appendLine(`[6] DNS RECORD    : Query A, AAAA, CNAME, MX, TXT, NS, SOA records`, 'menu_6');
    appendLine(`[7] HOST INFO     : Inspect SSL/TLS certificate, SANs, and fronting`, 'menu_7');
    appendLine(`[8] HELP          : Display this documentation manual`, 'menu_8');
    appendLine(`[9] UPDATE        : Check engine status and download latest Termux binary`, 'menu_9');
    appendLine(`[0] EXIT          : Clear terminal and return to standby`, 'menu_0');
    appendLine(`\nTermux CLI Standalone Commands:`, 'warn');
    appendLine(` • ./loxasb -t speed.cloudflare.com -trace`, 'output');
    appendLine(` • ./loxasb -cidr 104.16.0.0/24 -w 10`, 'output');
    appendLine(` • ./loxasb -f hosts.txt -w 8`, 'output');
    appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    appendLine('', 'output');
  };

  // [9] UPDATE
  const runUpdateCheck = async () => {
    setIsRunning(true);
    appendLine(`[+] Checking LoXaSB PRO engine version and server telemetry...`, 'output');

    try {
      const res = await fetch('/api/health');
      const data = await res.json();

      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
      appendLine(`LoXaSB ENGINE TELEMETRY & UPDATE:`, 'menu_9');
      appendLine(`Core Version  : LoXaSB PRO ${data.version} SUPREME`, 'success');
      appendLine(`Engine Status : ${data.status.toUpperCase()}`, 'success');
      appendLine(`Server Uptime : ${Math.round(data.uptime)} seconds`, 'output');
      appendLine(`Memory (RSS)  : ${(data.memory.rss / (1024 * 1024)).toFixed(1)} MB`, 'output');
      appendLine(`\nTermux 1-Line Installer:`, 'warn');
      appendLine(`curl -sSL /install_termux.sh | bash`, 'menu_1');
      appendLine(`Direct Go Source: /loxasb.go`, 'menu_2');
      appendLine(`─────────────────────────────────────────────────────────────────`, 'output');
    } catch (err: any) {
      appendLine(`[!] Update check error: ${err.message}`, 'error');
    } finally {
      setIsRunning(false);
      appendLine('', 'output');
    }
  };

  // Quick choice selection by clicking menu items or buttons
  const handleQuickSelect = (choice: string) => {
    setInputVal(choice);
    setTimeout(() => {
      const form = document.getElementById('terminal-form') as HTMLFormElement;
      form?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
    }, 50);
  };

  return (
    <div className="bg-black border border-zinc-800 rounded-xl overflow-hidden shadow-2xl font-mono text-xs flex flex-col min-h-[620px]">
      {/* Top Status Bar matching mobile terminal style */}
      <div className="bg-zinc-950 border-b border-zinc-800 px-4 py-2 flex items-center justify-between text-zinc-400 select-none">
        <div className="flex items-center gap-2">
          <span className="text-zinc-200 font-bold">LoXaSB CLI</span>
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
        </div>

        <div className="flex items-center gap-3 text-[11px]">
          <span className="px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
            Termux Mode
          </span>
          <span className="text-cyan-400 font-bold">v5.4</span>
        </div>
      </div>

      {/* Terminal Screen Body - Exact Screenshot Colors */}
      <div
        onClick={() => inputRef.current?.focus()}
        className="flex-1 p-5 overflow-y-auto space-y-1.5 bg-black text-zinc-300 font-mono text-sm select-text cursor-text leading-relaxed"
        style={{ minHeight: '440px', maxHeight: '560px' }}
      >
        {history.map((line) => {
          if (line.type === 'menu_1') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('1')}
                className="text-cyan-400 font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'menu_2') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('2')}
                className="text-fuchsia-400 font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'menu_3') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('3')}
                className="text-cyan-300 font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'menu_4') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('4')}
                className="text-pink-400 font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'menu_5') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('5')}
                className="text-white font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'menu_6') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('6')}
                className="text-emerald-400 font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'menu_7') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('7')}
                className="text-blue-400 font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'menu_8') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('8')}
                className="text-yellow-400 font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'menu_9') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('9')}
                className="text-pink-400 font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'menu_0') {
            return (
              <div
                key={line.id}
                onClick={() => handleQuickSelect('0')}
                className="text-red-500 font-bold cursor-pointer hover:underline tracking-wide select-none"
              >
                {line.text}
              </div>
            );
          }
          if (line.type === 'input') {
            return (
              <div key={line.id} className="text-cyan-400 font-bold">
                {line.text}
              </div>
            );
          }
          if (line.type === 'warn') {
            return (
              <div key={line.id} className="text-yellow-400 font-medium">
                {line.text}
              </div>
            );
          }
          if (line.type === 'success') {
            return (
              <div key={line.id} className="text-emerald-400 font-medium">
                {line.text}
              </div>
            );
          }
          if (line.type === 'cdn') {
            return (
              <div key={line.id} className="text-fuchsia-400 font-medium">
                {line.text}
              </div>
            );
          }
          if (line.type === 'sni') {
            return (
              <div key={line.id} className="text-amber-400 font-medium">
                {line.text}
              </div>
            );
          }
          if (line.type === 'hop') {
            return (
              <div key={line.id} className="text-teal-300 font-medium">
                {line.text}
              </div>
            );
          }
          if (line.type === 'error') {
            return (
              <div key={line.id} className="text-red-500 font-bold">
                {line.text}
              </div>
            );
          }
          return (
            <div key={line.id} className="text-zinc-400">
              {line.text}
            </div>
          );
        })}

        {/* Active Command Prompt Line - matching screenshot [-] Your Choice: */}
        <form
          id="terminal-form"
          onSubmit={handleCommandSubmit}
          className="flex items-center gap-2 pt-3 text-cyan-400 font-mono text-sm font-bold"
        >
          <span className="text-cyan-400 select-none whitespace-nowrap">
            {currentMenuStep === 'main' ? '[-]  Your Choice:' : '[-]  Input:'}
          </span>
          <input
            ref={inputRef}
            type="text"
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            disabled={isRunning}
            autoFocus
            className="flex-1 bg-transparent border-none outline-none text-white font-mono text-sm caret-white"
            placeholder={
              isRunning
                ? 'Running probe...'
                : currentMenuStep === 'main'
                ? 'Enter 1 - 0'
                : 'Enter value & press ENTER'
            }
          />
          {isRunning && <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />}
        </form>

        <div ref={logsEndRef} />
      </div>

      {/* Bottom Virtual Keypad Navigation */}
      <div className="bg-zinc-950 border-t border-zinc-800 p-2 select-none">
        <div className="grid grid-cols-6 sm:grid-cols-12 gap-1.5 text-[11px] font-mono">
          <button
            onClick={() => showMainMenu()}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 active:bg-zinc-700 text-center font-bold text-red-400"
          >
            ESC
          </button>
          <button
            onClick={() => handleQuickSelect('1')}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 text-center text-cyan-400 font-bold"
            title="[1] HOST SCANNER"
          >
            [1] SCAN
          </button>
          <button
            onClick={() => handleQuickSelect('2')}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 text-center text-fuchsia-400 font-bold"
            title="[2] SUBFINDER"
          >
            [2] SUB
          </button>
          <button
            onClick={() => handleQuickSelect('3')}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 text-center text-sky-400 font-bold"
            title="[3] IP LOOKUP"
          >
            [3] IP
          </button>
          <button
            onClick={() => handleQuickSelect('4')}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 text-center text-pink-400 font-bold"
            title="[4] FILE TOOLKIT"
          >
            [4] FILE
          </button>
          <button
            onClick={() => handleQuickSelect('5')}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 text-center text-white font-bold"
            title="[5] PORT SCANNER"
          >
            [5] PORT
          </button>
          <button
            onClick={() => handleQuickSelect('6')}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 text-center text-emerald-400 font-bold"
            title="[6] DNS RECORD"
          >
            [6] DNS
          </button>
          <button
            onClick={() => handleQuickSelect('7')}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 text-center text-blue-400 font-bold"
            title="[7] HOST INFO"
          >
            [7] INFO
          </button>
          <button
            onClick={() => handleQuickSelect('8')}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 text-center text-yellow-400 font-bold"
            title="[8] HELP"
          >
            [8] HELP
          </button>
          <button
            onClick={() => handleQuickSelect('9')}
            className="p-1.5 rounded bg-zinc-900 hover:bg-zinc-800 text-center text-pink-400 font-bold"
            title="[9] UPDATE"
          >
            [9] UPD
          </button>
          <button
            onClick={onSwitchToDashboard}
            className="p-1.5 rounded bg-cyan-950 border border-cyan-700/60 text-cyan-300 text-center font-bold"
            title="Switch to GUI Dashboard"
          >
            GUI
          </button>
          <button
            onClick={() => {
              const form = document.getElementById('terminal-form') as HTMLFormElement;
              form?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
            }}
            className="p-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-black font-bold text-center"
          >
            ENTER ↵
          </button>
        </div>
      </div>
    </div>
  );
};
