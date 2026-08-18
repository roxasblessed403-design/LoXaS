import React, { useState } from 'react';
import {
  Terminal as TermIcon,
  LayoutDashboard,
  FolderArchive,
  Cpu,
  Layers,
  Zap,
  Search,
  FileSearch,
  Activity,
  Globe,
  Sparkles,
} from 'lucide-react';
import type { ScanItemResult, SupportedLanguage } from './types.js';
import { Header } from './components/Header.js';
import { TerminalView } from './components/TerminalView.js';
import { SingleHostProbe } from './components/SingleHostProbe.js';
import { BatchScanner } from './components/BatchScanner.js';
import { FileManager } from './components/FileManager.js';
import { GolangScriptView } from './components/GolangScriptView.js';
import { SubdomainFinder } from './components/SubdomainFinder.js';
import { DomainExtractor } from './components/DomainExtractor.js';
import { AiDoctorModal } from './components/AiDoctorModal.js';
import { TRANSLATIONS } from './translations.js';

export default function App() {
  const [currentView, setCurrentView] = useState<'terminal' | 'dashboard' | 'files'>('terminal');
  const [activeTab, setActiveTab] = useState<'single' | 'batch' | 'subdomains' | 'extractor' | 'golang'>('single');
  const [language, setLanguage] = useState<SupportedLanguage>('en');
  const [selectedFileForManager, setSelectedFileForManager] = useState<string | undefined>(undefined);
  const [aiDoctorItem, setAiDoctorItem] = useState<ScanItemResult | null>(null);
  const [recentScans, setRecentScans] = useState<ScanItemResult[]>([]);

  const t = TRANSLATIONS[language] || TRANSLATIONS.en;

  const handleScanItemRecorded = (item: ScanItemResult) => {
    setRecentScans((prev) => [item, ...prev.slice(0, 49)]);
  };

  const handleOpenFileInManager = (filePath: string) => {
    setSelectedFileForManager(filePath);
    setCurrentView('files');
  };

  const handleOpenAiDoctor = (item?: ScanItemResult) => {
    if (item) {
      setAiDoctorItem(item);
    } else if (recentScans.length > 0) {
      setAiDoctorItem(recentScans[0]);
    } else {
      // Default sample item for AI doctor
      setAiDoctorItem({
        id: 'sample_cf',
        target: 'speed.cloudflare.com',
        type: 'domain',
        resolvedIp: '104.16.123.96',
        timestamp: Date.now(),
        ping: {
          target: 'speed.cloudflare.com',
          resolvedIp: '104.16.123.96',
          isAlive: true,
          packetsSent: 4,
          packetsReceived: 4,
          packetLoss: 0,
          latencyMin: 14.2,
          latencyAvg: 16.8,
          latencyMax: 19.5,
          jitter: 1.8,
          probes: [
            { seq: 1, rtt: 14.2, status: 'success' },
            { seq: 2, rtt: 16.5, status: 'success' },
            { seq: 3, rtt: 17.0, status: 'success' },
            { seq: 4, rtt: 19.5, status: 'success' },
          ],
        },
        cdn: {
          isCdn: true,
          provider: 'Cloudflare',
          matchedHeaders: ['CF-Ray header', 'Server: cloudflare'],
          isCloudflare: true,
          isAkamai: false,
          isFastly: false,
          isCloudfront: false,
        },
        sni: {
          hasSni: true,
          tlsVersion: 'TLSv1.3',
          alpnProtocols: ['h2', 'http/1.1'],
          sanList: ['speed.cloudflare.com', '*.cloudflare.com'],
          isWildcard: true,
          isFrontable: true,
        },
        direct: {
          directReachable: true,
          openPorts: [80, 443],
          testedPorts: [80, 443],
          tcpHandshakeMs: 14.5,
          ttfbMs: 18.2,
        },
        category: 'cdn',
        savedDirectory: 'cdn/cloudflare',
        savedFileName: 'cloudflare_hosts.txt',
        status: 'completed',
      });
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans selection:bg-emerald-500 selection:text-zinc-950">
      {/* Top Header */}
      <Header
        currentView={currentView}
        onViewChange={(v) => setCurrentView(v)}
        language={language}
        onLanguageChange={(l) => setLanguage(l)}
        onOpenAiDoctor={() => handleOpenAiDoctor()}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-6">
        {/* VIEW 1: Authenticity Paragon Pro Supreme Terminal View (Matching Termux Screenshot) */}
        {currentView === 'terminal' && (
          <div className="space-y-4">
            <TerminalView
              onScanComplete={handleScanItemRecorded}
              language={language}
              onSwitchToDashboard={() => setCurrentView('dashboard')}
              onSwitchToFiles={() => setCurrentView('files')}
            />
          </div>
        )}

        {/* VIEW 2: Modern Cyber-Diagnostic Dashboard */}
        {currentView === 'dashboard' && (
          <div className="space-y-6">
            {/* Dashboard Sub-Navigation Tabs */}
            <div className="bg-zinc-950 border border-zinc-800/80 rounded-xl p-1.5 flex flex-wrap gap-1 font-mono text-xs shadow-md">
              <button
                onClick={() => setActiveTab('single')}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg transition-all ${
                  activeTab === 'single'
                    ? 'bg-emerald-600 text-zinc-950 font-bold shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
                }`}
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Single Host Probe</span>
              </button>

              <button
                onClick={() => setActiveTab('batch')}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg transition-all ${
                  activeTab === 'batch'
                    ? 'bg-emerald-600 text-zinc-950 font-bold shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Batch & CIDR Scanner</span>
              </button>

              <button
                onClick={() => setActiveTab('subdomains')}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg transition-all ${
                  activeTab === 'subdomains'
                    ? 'bg-emerald-600 text-zinc-950 font-bold shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
                }`}
              >
                <Search className="w-3.5 h-3.5" />
                <span>Subdomain Discovery</span>
              </button>

              <button
                onClick={() => setActiveTab('extractor')}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg transition-all ${
                  activeTab === 'extractor'
                    ? 'bg-emerald-600 text-zinc-950 font-bold shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
                }`}
              >
                <FileSearch className="w-3.5 h-3.5" />
                <span>Domain & IP Extractor</span>
              </button>

              <button
                onClick={() => setActiveTab('golang')}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg transition-all ${
                  activeTab === 'golang'
                    ? 'bg-teal-500 text-zinc-950 font-bold shadow-sm'
                    : 'text-teal-400 hover:text-teal-200 hover:bg-zinc-900'
                }`}
              >
                <Cpu className="w-3.5 h-3.5" />
                <span>Go (Golang) Termux Script</span>
              </button>
            </div>

            {/* Sub-View Content */}
            {activeTab === 'single' && (
              <SingleHostProbe
                onScanComplete={handleScanItemRecorded}
                onOpenAiDoctor={handleOpenAiDoctor}
                language={language}
                onOpenFileInManager={handleOpenFileInManager}
              />
            )}

            {activeTab === 'batch' && (
              <BatchScanner
                onScanCompleteItem={handleScanItemRecorded}
                language={language}
                onOpenFileInManager={handleOpenFileInManager}
                onOpenItem={(item) => {
                  setActiveTab('single');
                }}
              />
            )}

            {activeTab === 'subdomains' && (
              <SubdomainFinder
                language={language}
                onSelectHost={(host) => {
                  setActiveTab('single');
                }}
              />
            )}

            {activeTab === 'extractor' && (
              <DomainExtractor
                language={language}
                onSendToBatchScan={(targets) => {
                  setActiveTab('batch');
                }}
              />
            )}

            {activeTab === 'golang' && (
              <GolangScriptView language={language} />
            )}
          </div>
        )}

        {/* VIEW 3: Dedicated Directory & File Storage Manager */}
        {currentView === 'files' && (
          <FileManager
            language={language}
            initialSelectedFile={selectedFileForManager}
          />
        )}
      </main>

      {/* AI Doctor Modal */}
      {aiDoctorItem && (
        <AiDoctorModal
          item={aiDoctorItem}
          onClose={() => setAiDoctorItem(null)}
          language={language}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-zinc-900 bg-zinc-950 py-4 px-4 text-center font-mono text-[11px] text-zinc-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>LoXaSB PRO 5.4 SUPREME • Zero-Credit Tunneling & CDN Route Diagnostics</span>
          <span>Dual Runtime: Full-Stack Web + Pure Golang Termux CLI Script</span>
        </div>
      </footer>
    </div>
  );
}
