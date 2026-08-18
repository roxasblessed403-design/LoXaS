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
  GitBranch,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  RefreshCw,
} from 'lucide-react';
import type { SupportedLanguage } from '../types.js';

interface GolangScriptViewProps {
  language: SupportedLanguage;
}

export const GolangScriptView: React.FC<GolangScriptViewProps> = ({ language }) => {
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(key);
    setTimeout(() => setCopiedIndex(null), 2000);
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

      {/* GitHub to Termux Complete Step-by-Step Guide */}
      <div className="bg-zinc-950 border border-teal-900/60 rounded-xl p-5 shadow-2xl space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-900 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-teal-500/20 text-teal-400 border border-teal-500/30">
              <GitBranch className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-zinc-100 uppercase tracking-wide">
                How to Import & Run from GitHub in Termux
              </h3>
              <p className="text-[11px] text-zinc-400">
                Follow these 4 simple steps in Termux on your Android phone
              </p>
            </div>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-900 text-zinc-300 border border-zinc-800">
            Termux Guide
          </span>
        </div>

        <div className="space-y-4">
          {/* Step 1: Update & Install Git & Go */}
          <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-teal-400 text-xs flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-teal-950 border border-teal-500 flex items-center justify-center text-[10px]">
                  1
                </span>
                Step 1: Install Git and Golang in Termux
              </span>
              <button
                onClick={() =>
                  copyToClipboard('pkg update -y && pkg install git golang -y', 'step1')
                }
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-[11px] transition-colors"
              >
                {copiedIndex === 'step1' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <p className="text-zinc-400 text-[11px]">
              Open Termux and run this command to update packages and install git + go:
            </p>
            <div className="bg-black/80 border border-zinc-800 rounded p-2.5 text-teal-300 font-mono text-xs select-all">
              pkg update -y && pkg install git golang -y
            </div>
          </div>

          {/* Step 2: Clone from GitHub */}
          <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-400 text-xs flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-500 flex items-center justify-center text-[10px]">
                  2
                </span>
                Step 2: Clone Repository or Download Script
              </span>
              <button
                onClick={() =>
                  copyToClipboard(
                    'git clone https://github.com/roxasblessed403-design/LoXaS.git\ncd LoXaS',
                    'step2'
                  )
                }
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-[11px] transition-colors"
              >
                {copiedIndex === 'step2' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <p className="text-zinc-400 text-[11px]">
              Clone your repository from GitHub into Termux and navigate into the directory:
            </p>
            <div className="bg-black/80 border border-zinc-800 rounded p-2.5 text-cyan-300 font-mono text-xs select-all">
              git clone https://github.com/roxasblessed403-design/LoXaS.git && cd LoXaS
            </div>
            <div className="text-[11px] text-zinc-400 pt-1">
              <span className="text-amber-400 font-bold">Alternative (Single File):</span> If you only want the script directly without full git repo:
            </div>
            <div className="bg-black/80 border border-zinc-800 rounded p-2 text-zinc-300 font-mono text-xs select-all">
              curl -sSL -O https://raw.githubusercontent.com/roxasblessed403-design/LoXaS/main/loxasb.go
            </div>
          </div>

          {/* Step 3: Compile and Install Globally */}
          <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-emerald-400 text-xs flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-500 flex items-center justify-center text-[10px]">
                  3
                </span>
                Step 3: Install Globally as 'loxas' & 'lx' (Run Anywhere!)
              </span>
              <button
                onClick={() =>
                  copyToClipboard(
                    'go build -ldflags="-s -w" -o loxasb loxasb.go && cp loxasb $PREFIX/bin/loxas && cp loxasb $PREFIX/bin/lx && chmod +x $PREFIX/bin/loxas $PREFIX/bin/lx && loxas',
                    'step3'
                  )
                }
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-[11px] transition-colors"
              >
                {copiedIndex === 'step3' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <p className="text-zinc-400 text-[11px]">
              Copy the binary into Termux's global bin directory so you can type <code className="text-emerald-300 font-bold">loxas</code> or <code className="text-emerald-300 font-bold">lx</code> from <b>any directory</b>:
            </p>
            <div className="bg-black/80 border border-zinc-800 rounded p-2.5 text-emerald-300 font-mono text-xs select-all">
              go build -ldflags="-s -w" -o loxasb loxasb.go && cp loxasb $PREFIX/bin/loxas && cp loxasb $PREFIX/bin/lx && chmod +x $PREFIX/bin/loxas $PREFIX/bin/lx
            </div>
            <div className="text-[11px] text-zinc-400 pt-1">
              Now simply type <b className="text-cyan-400">loxas</b> or <b className="text-cyan-400">lx</b> anywhere in Termux!
            </div>
          </div>

          {/* Step 4: Updating from GitHub */}
          <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-purple-400 text-xs flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-purple-950 border border-purple-500 flex items-center justify-center text-[10px]">
                  4
                </span>
                Step 4: Update to Latest Version in Future
              </span>
              <button
                onClick={() =>
                  copyToClipboard('cd LoXaS && git pull && go build -ldflags="-s -w" -o loxasb loxasb.go', 'step4')
                }
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-[11px] transition-colors"
              >
                {copiedIndex === 'step4' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-zinc-400" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <p className="text-zinc-400 text-[11px]">
              Whenever new updates are pushed to GitHub, pull changes with a single command:
            </p>
            <div className="bg-black/80 border border-zinc-800 rounded p-2.5 text-purple-300 font-mono text-xs select-all">
              cd LoXaS && git pull && go build -ldflags="-s -w" -o loxasb loxasb.go
            </div>
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
