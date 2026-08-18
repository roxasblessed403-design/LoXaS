import React, { useState } from 'react';
import {
  Code2,
  Copy,
  Check,
  Download,
  Terminal,
  Smartphone,
  CheckCircle2,
  Zap,
  FolderArchive,
  Layers,
  Cpu,
  Play,
} from 'lucide-react';
import type { SupportedLanguage } from '../types.js';

interface GolangScriptViewProps {
  language: SupportedLanguage;
}

export const GolangScriptView: React.FC<GolangScriptViewProps> = ({ language }) => {
  const [copiedScript, setCopiedScript] = useState(false);
  const [copiedInstallCmd, setCopiedInstallCmd] = useState(false);

  const installCommand = `pkg update -y && pkg install golang git traceroute dnsutils -y && curl -sSL https://raw.githubusercontent.com/.../loxasb.go -o loxasb.go || nano loxasb.go`;
  const runCommand = `go run loxasb.go`;
  const buildCommand = `go build -ldflags="-s -w" -o loxasb loxasb.go && ./loxasb`;

  const handleCopyInstall = () => {
    navigator.clipboard.writeText(`pkg update -y && pkg install golang git -y\ncat << 'EOF' > loxasb.go\n// paste code\nEOF\ngo run loxasb.go`);
    setCopiedInstallCmd(true);
    setTimeout(() => setCopiedInstallCmd(false), 2500);
  };

  const handleDownloadGoFile = async () => {
    try {
      const res = await fetch('/loxasb.go');
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'loxasb.go';
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert('Downloading loxasb.go');
    }
  };

  const handleDownloadShellScript = async () => {
    try {
      const res = await fetch('/install_termux.sh');
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/x-sh;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'install_termux.sh';
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert('Downloading installer script');
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-teal-950/80 via-zinc-950 to-emerald-950/80 border border-teal-800/60 rounded-xl p-5 shadow-xl space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-teal-500/20 border border-teal-400/40 flex items-center justify-center">
              <Cpu className="w-6 h-6 text-teal-300" />
            </div>
            <div>
              <h2 className="text-base font-bold text-zinc-100 uppercase tracking-wide flex items-center gap-2">
                <span>LoXaSB Go (Golang) Termux CLI Script</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-teal-950 text-teal-300 border border-teal-700/60 font-mono">
                  100% Pure Go Stdlib • Zero Dependencies
                </span>
              </h2>
              <p className="text-zinc-400 text-xs">
                Lightweight, crash-proof Goroutines concurrency engine for Android Termux, Linux, and macOS.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadShellScript}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 hover:bg-zinc-800 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-amber-400" />
              <span>Download install.sh</span>
            </button>

            <button
              onClick={handleDownloadGoFile}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-teal-600 hover:bg-teal-500 text-zinc-950 font-bold shadow-md transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download loxasb.go</span>
            </button>
          </div>
        </div>
      </div>

      {/* 3 Step Termux Quickstart Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Step 1 */}
        <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 space-y-2">
          <div className="flex items-center gap-2 text-teal-400 font-bold text-xs">
            <span className="w-5 h-5 rounded-full bg-teal-950 border border-teal-600 flex items-center justify-center text-[10px]">
              1
            </span>
            <span>Install Go in Termux</span>
          </div>
          <p className="text-zinc-400 text-[11px]">
            Open Termux on Android and install the Golang compiler and tools:
          </p>
          <div className="bg-zinc-900 border border-zinc-800 rounded p-2 text-[11px] text-zinc-200 font-mono select-all">
            pkg update -y && pkg install golang git -y
          </div>
        </div>

        {/* Step 2 */}
        <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 space-y-2">
          <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs">
            <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-600 flex items-center justify-center text-[10px]">
              2
            </span>
            <span>Save & Compile</span>
          </div>
          <p className="text-zinc-400 text-[11px]">
            Save <code className="text-teal-300">loxasb.go</code> and build a fast native binary:
          </p>
          <div className="bg-zinc-900 border border-zinc-800 rounded p-2 text-[11px] text-zinc-200 font-mono select-all">
            go build -ldflags="-s -w" -o loxasb loxasb.go
          </div>
        </div>

        {/* Step 3 */}
        <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 space-y-2">
          <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs">
            <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-600 flex items-center justify-center text-[10px]">
              3
            </span>
            <span>Launch LoXaSB</span>
          </div>
          <p className="text-zinc-400 text-[11px]">
            Run interactive menu or single-command scans:
          </p>
          <div className="bg-zinc-900 border border-zinc-800 rounded p-2 text-[11px] text-zinc-200 font-mono select-all">
            ./loxasb
          </div>
        </div>
      </div>

      {/* Termux CLI Flags Reference */}
      <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2 border-b border-zinc-900 pb-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span className="font-bold text-zinc-200 uppercase tracking-wide">
            Termux Command-Line Flags Cheat Sheet
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="bg-zinc-900/80 p-2.5 rounded border border-zinc-800 space-y-1">
            <code className="text-emerald-400 font-bold">./loxasb</code>
            <p className="text-zinc-400 text-[11px]">
              Interactive full-screen menu with 10 modes matching your Termux layout ([1] HOST SCANNER to [0] EXIT).
            </p>
          </div>

          <div className="bg-zinc-900/80 p-2.5 rounded border border-zinc-800 space-y-1">
            <code className="text-teal-300 font-bold">./loxasb -t speed.cloudflare.com -trace</code>
            <p className="text-zinc-400 text-[11px]">
              Probes single target, calculates latency/jitter/loss and prints route hops.
            </p>
          </div>

          <div className="bg-zinc-900/80 p-2.5 rounded border border-zinc-800 space-y-1">
            <code className="text-purple-300 font-bold">./loxasb -cidr 104.16.0.0/24 -w 12</code>
            <p className="text-zinc-400 text-[11px]">
              Scans entire CIDR subnet with 12 parallel goroutine workers.
            </p>
          </div>

          <div className="bg-zinc-900/80 p-2.5 rounded border border-zinc-800 space-y-1">
            <code className="text-amber-300 font-bold">./loxasb -f my_hosts.txt -w 8</code>
            <p className="text-zinc-400 text-[11px]">
              Batch reads a host list file and sorts them into <code className="text-zinc-200">cdn/</code> and <code className="text-zinc-200">sni/</code> directories.
            </p>
          </div>
        </div>
      </div>

      {/* Directory Auto-Categorization Architecture */}
      <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2 border-b border-zinc-900 pb-2">
          <FolderArchive className="w-4 h-4 text-amber-400" />
          <span className="font-bold text-zinc-200 uppercase tracking-wide">
            Automated Disk Directory Categorization in Go
          </span>
        </div>

        <p className="text-zinc-400 text-xs leading-relaxed">
          The Go script automatically creates and organizes results on disk inside Termux (<code className="text-emerald-400">~/cdn/</code>, <code className="text-amber-400">~/sni/</code>, <code className="text-blue-400">~/direct-ip/</code>) using concurrent safe file appends:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-[11px]">
          <div className="bg-purple-950/30 border border-purple-800/40 rounded p-2.5">
            <b className="text-purple-300 block mb-1">cdn/cloudflare/</b>
            <span className="text-zinc-400">Cloudflare edge nodes with CF-Ray & server headers.</span>
          </div>

          <div className="bg-purple-950/30 border border-purple-800/40 rounded p-2.5">
            <b className="text-purple-300 block mb-1">cdn/cloudfront/ & fastly/</b>
            <span className="text-zinc-400">Amazon & Fastly CDN bughosts.</span>
          </div>

          <div className="bg-amber-950/30 border border-amber-800/40 rounded p-2.5">
            <b className="text-amber-300 block mb-1">sni/valid_sni_hosts.txt</b>
            <span className="text-zinc-400">Hosts with valid TLS 1.3 / HTTP/2 SNI handshakes.</span>
          </div>

          <div className="bg-blue-950/30 border border-blue-800/40 rounded p-2.5">
            <b className="text-blue-300 block mb-1">direct-ip/</b>
            <span className="text-zinc-400">Direct reachable clean IPs with open TCP ports 80/443.</span>
          </div>
        </div>
      </div>
    </div>
  );
};
