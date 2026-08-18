import React, { useState, useEffect } from 'react';
import {
  Folder,
  FolderOpen,
  FileText,
  Download,
  Trash2,
  Save,
  Plus,
  RefreshCw,
  FolderArchive,
  Copy,
  Check,
  FileCode,
  Layers,
  ArrowRight,
  ShieldCheck,
  Server,
} from 'lucide-react';
import type { DirectoryNode, StoredFile, SupportedLanguage } from '../types.js';
import { TRANSLATIONS } from '../translations.js';

interface FileManagerProps {
  language: SupportedLanguage;
  initialSelectedFile?: string;
}

export const FileManager: React.FC<FileManagerProps> = ({
  language,
  initialSelectedFile,
}) => {
  const [tree, setTree] = useState<DirectoryNode | null>(null);
  const [selectedFile, setSelectedFile] = useState<StoredFile | null>(null);
  const [fileContent, setFileContent] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [copied, setCopied] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [newFileName, setNewFileName] = useState('');
  const [showNewFileModal, setShowNewFileModal] = useState(false);
  const [newFileCategory, setNewFileCategory] = useState('cdn/cloudflare');
  const [exportModalFormat, setExportModalFormat] = useState<string | null>(null);

  const t = TRANSLATIONS[language] || TRANSLATIONS.en;

  const fetchDirectoryTree = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/storage/tree');
      if (res.ok) {
        const data = await res.json();
        setTree(data);
      }
    } catch (err) {
      console.error('Failed to load storage tree:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const openFile = async (filePath: string) => {
    try {
      const res = await fetch(`/api/storage/file?path=${encodeURIComponent(filePath)}`);
      if (res.ok) {
        const file: StoredFile = await res.json();
        setSelectedFile(file);
        setFileContent(file.rawContent || '');
      }
    } catch (err) {
      console.error('Failed to open file:', err);
    }
  };

  useEffect(() => {
    fetchDirectoryTree();
    if (initialSelectedFile) {
      openFile(initialSelectedFile);
    } else {
      // Open default curated file
      openFile('cdn/cloudflare/sample_cf_bughosts.txt');
    }
  }, [initialSelectedFile]);

  const handleSaveFile = async () => {
    if (!selectedFile) return;
    setIsSaving(true);
    try {
      const res = await fetch('/api/storage/file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path: selectedFile.path,
          content: fileContent,
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedFile(updated);
        setStatusMsg('File saved successfully');
        setTimeout(() => setStatusMsg(null), 3000);
        fetchDirectoryTree();
      }
    } catch (err) {
      console.error('Failed to save file:', err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleDeleteFile = async (filePath: string) => {
    if (!confirm(`Are you sure you want to delete ${filePath}?`)) return;
    try {
      const res = await fetch(`/api/storage/file?path=${encodeURIComponent(filePath)}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        setSelectedFile(null);
        setFileContent('');
        fetchDirectoryTree();
      }
    } catch (err) {
      console.error('Failed to delete file:', err);
    }
  };

  const handleCreateNewFile = async () => {
    if (!newFileName.trim()) return;
    const cleanName = newFileName.trim().endsWith('.txt') ? newFileName.trim() : `${newFileName.trim()}.txt`;
    const fullPath = `${newFileCategory}/${cleanName}`;

    try {
      const initialHeader = `# Custom File: ${cleanName}\n# Created on ${new Date().toISOString()}\n`;
      const res = await fetch('/api/storage/file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path: fullPath,
          content: initialHeader,
        }),
      });

      if (res.ok) {
        setShowNewFileModal(false);
        setNewFileName('');
        fetchDirectoryTree();
        openFile(fullPath);
      }
    } catch (err) {
      console.error('Failed to create file:', err);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(fileContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadFile = () => {
    if (!selectedFile) return;
    const blob = new Blob([fileContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedFile.name;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Generate proxy configurations for Clash / V2Ray / Sing-box
  const generateConfigSnippet = (format: 'v2ray' | 'clash' | 'singbox') => {
    if (!fileContent) return '';
    const lines = fileContent
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith('#'));

    if (format === 'v2ray') {
      return lines
        .map((line, idx) => {
          const host = line.split('|')[0]?.trim() || line;
          return `vless://00000000-0000-0000-0000-000000000000@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F#Paragon-Node-${idx + 1}`;
        })
        .join('\n');
    }

    if (format === 'clash') {
      const proxies = lines.map((line, idx) => {
        const host = line.split('|')[0]?.trim() || line;
        return `  - name: "Node-${idx + 1}-${host}"\n    type: vless\n    server: ${host}\n    port: 443\n    uuid: 00000000-0000-0000-0000-000000000000\n    tls: true\n    servername: ${host}\n    network: ws\n    ws-opts:\n      path: /\n      headers:\n        Host: ${host}`;
      });
      return `proxies:\n${proxies.join('\n')}`;
    }

    if (format === 'singbox') {
      const outbounds = lines.map((line, idx) => {
        const host = line.split('|')[0]?.trim() || line;
        return {
          type: 'vless',
          tag: `vless-${idx + 1}`,
          server: host,
          server_port: 443,
          uuid: '00000000-0000-0000-0000-000000000000',
          tls: {
            enabled: true,
            server_name: host,
          },
          transport: {
            type: 'ws',
            path: '/',
            headers: {
              Host: host,
            },
          },
        };
      });
      return JSON.stringify({ outbounds }, null, 2);
    }

    return fileContent;
  };

  // Helper recursive renderer for directory nodes
  const renderDirectoryNode = (node: DirectoryNode) => {
    if (node.type === 'directory') {
      return (
        <div key={node.path || node.name} className="space-y-1">
          <div className="flex items-center gap-1.5 px-2 py-1 rounded text-zinc-300 font-bold text-xs">
            <Folder className="w-3.5 h-3.5 text-amber-400" />
            <span className="uppercase tracking-wider">
              {node.name === 'root' || node.name === 'storage' ? 'DATA_STORAGE/' : node.name}
            </span>
          </div>
          <div className="pl-3 border-l border-zinc-800 space-y-0.5">
            {node.children?.map((child) => renderDirectoryNode(child))}
          </div>
        </div>
      );
    }

    const isSelected = selectedFile?.path === node.path;

    return (
      <button
        key={node.path}
        onClick={() => openFile(node.path)}
        className={`w-full flex items-center justify-between px-2 py-1 rounded text-xs text-left transition-colors font-mono ${
          isSelected
            ? 'bg-emerald-950/80 border border-emerald-700/60 text-emerald-300 font-bold'
            : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60'
        }`}
      >
        <div className="flex items-center gap-1.5 truncate">
          <FileText className="w-3.5 h-3.5 text-zinc-500" />
          <span className="truncate">{node.name}</span>
        </div>
        {node.size !== undefined && (
          <span className="text-[10px] text-zinc-600 ml-1">
            {node.size > 1024 ? `${Math.round(node.size / 1024)}KB` : `${node.size}B`}
          </span>
        )}
      </button>
    );
  };

  return (
    <div className="space-y-6">
      {/* Top Action Header */}
      <div className="bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3 font-mono text-xs shadow-xl">
        <div className="flex items-center gap-2">
          <FolderArchive className="w-4 h-4 text-emerald-400" />
          <span className="font-bold text-zinc-200 uppercase tracking-wider text-sm">
            Categorized Storage Directories
          </span>
          <span className="text-zinc-500 hidden sm:inline">(cdn/, sni/, direct-ip/, subdomains/, payloads/)</span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowNewFileModal(true)}
            className="flex items-center gap-1 px-3 py-1.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 hover:bg-zinc-800 transition-colors"
          >
            <Plus className="w-3.5 h-3.5 text-emerald-400" />
            <span>New File</span>
          </button>

          <a
            href="/api/storage/download-zip"
            className="flex items-center gap-1 px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-bold shadow-md transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download All (ZIP)</span>
          </a>
        </div>
      </div>

      {/* Main Split Layout: Directory Tree (Left) + File Editor (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Tree Explorer (4 cols) */}
        <div className="lg:col-span-4 bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 font-mono text-xs space-y-4 max-h-[600px] overflow-y-auto">
          <div className="flex items-center justify-between border-b border-zinc-900 pb-2">
            <span className="font-bold text-zinc-400 uppercase tracking-wider text-[11px]">
              Directory Structure
            </span>
            <button
              onClick={fetchDirectoryTree}
              className="text-zinc-500 hover:text-zinc-300 p-1"
              title="Refresh tree"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="space-y-1">
            {tree ? renderDirectoryNode(tree) : <div className="text-zinc-500">Loading tree...</div>}
          </div>
        </div>

        {/* Right Editor & Export Panel (8 cols) */}
        <div className="lg:col-span-8 bg-zinc-950 border border-zinc-800/90 rounded-xl p-4 font-mono text-xs space-y-4">
          {selectedFile ? (
            <>
              {/* File Info Bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-900 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm text-zinc-100">{selectedFile.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-emerald-400">
                      {selectedFile.category}
                    </span>
                  </div>
                  <div className="text-[11px] text-zinc-500 mt-0.5">
                    Path: {selectedFile.path} • {selectedFile.itemCount} entries
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  {/* Copy Button */}
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 hover:bg-zinc-800 transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>

                  {/* Export format dropdown */}
                  <button
                    onClick={() => setExportModalFormat('v2ray')}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-purple-950/60 border border-purple-700/60 text-purple-300 hover:bg-purple-900/50 transition-colors"
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    <span>Generate V2Ray / Clash</span>
                  </button>

                  {/* Save Button */}
                  <button
                    onClick={handleSaveFile}
                    disabled={isSaving}
                    className="flex items-center gap-1 px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-bold transition-colors shadow-sm"
                  >
                    <Save className="w-3.5 h-3.5" />
                    <span>{isSaving ? 'Saving...' : 'Save'}</span>
                  </button>

                  {/* Delete Button */}
                  <button
                    onClick={() => handleDeleteFile(selectedFile.path)}
                    className="p-1 text-zinc-500 hover:text-rose-400 transition-colors"
                    title="Delete file"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {statusMsg && (
                <div className="p-2 rounded bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs">
                  {statusMsg}
                </div>
              )}

              {/* Textarea Editor */}
              <div className="relative">
                <textarea
                  value={fileContent}
                  onChange={(e) => setFileContent(e.target.value)}
                  rows={16}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-zinc-100 font-mono text-xs leading-relaxed focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                />
              </div>
            </>
          ) : (
            <div className="p-12 text-center text-zinc-500 font-mono">
              <FileText className="w-8 h-8 mx-auto mb-2 text-zinc-700" />
              <span>Select a file from the directory tree to inspect, edit, or export.</span>
            </div>
          )}
        </div>
      </div>

      {/* New File Modal */}
      {showNewFileModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 max-w-md w-full font-mono text-xs space-y-4">
            <h3 className="text-sm font-bold text-zinc-100 uppercase tracking-wide">
              Create New Storage File
            </h3>

            <div>
              <label className="block text-zinc-400 mb-1">Target Directory Category</label>
              <select
                value={newFileCategory}
                onChange={(e) => setNewFileCategory(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-700 rounded p-2 text-zinc-200 outline-none"
              >
                <option value="cdn/cloudflare">cdn/cloudflare</option>
                <option value="cdn/cloudfront">cdn/cloudfront</option>
                <option value="cdn/fastly">cdn/fastly</option>
                <option value="cdn/akamai">cdn/akamai</option>
                <option value="cdn/gcore">cdn/gcore</option>
                <option value="cdn/google">cdn/google</option>
                <option value="cdn/others">cdn/others</option>
                <option value="sni">sni</option>
                <option value="direct-ip">direct-ip</option>
                <option value="subdomains">subdomains</option>
                <option value="tricks-payloads">tricks-payloads</option>
              </select>
            </div>

            <div>
              <label className="block text-zinc-400 mb-1">File Name (.txt)</label>
              <input
                type="text"
                value={newFileName}
                onChange={(e) => setNewFileName(e.target.value)}
                placeholder="e.g. my_clean_hosts.txt"
                className="w-full bg-zinc-900 border border-zinc-700 rounded p-2 text-zinc-200 outline-none focus:border-emerald-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setShowNewFileModal(false)}
                className="px-3 py-1.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateNewFile}
                className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-bold"
              >
                Create File
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Export Format Modal */}
      {exportModalFormat && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 max-w-2xl w-full font-mono text-xs space-y-4">
            <div className="flex items-center justify-between border-b border-zinc-900 pb-2">
              <span className="font-bold text-sm text-zinc-100 uppercase tracking-wide">
                Export Config Generator
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setExportModalFormat('v2ray')}
                  className={`px-2.5 py-1 rounded ${
                    exportModalFormat === 'v2ray'
                      ? 'bg-purple-900 text-purple-200 border border-purple-500'
                      : 'bg-zinc-900 text-zinc-400'
                  }`}
                >
                  V2Ray (VLESS-WS)
                </button>
                <button
                  onClick={() => setExportModalFormat('clash')}
                  className={`px-2.5 py-1 rounded ${
                    exportModalFormat === 'clash'
                      ? 'bg-purple-900 text-purple-200 border border-purple-500'
                      : 'bg-zinc-900 text-zinc-400'
                  }`}
                >
                  Clash YAML
                </button>
                <button
                  onClick={() => setExportModalFormat('singbox')}
                  className={`px-2.5 py-1 rounded ${
                    exportModalFormat === 'singbox'
                      ? 'bg-purple-900 text-purple-200 border border-purple-500'
                      : 'bg-zinc-900 text-zinc-400'
                  }`}
                >
                  Sing-Box JSON
                </button>
              </div>
            </div>

            <textarea
              readOnly
              value={generateConfigSnippet(exportModalFormat as any)}
              rows={12}
              className="w-full bg-zinc-900 border border-zinc-800 rounded p-3 text-zinc-100 font-mono text-xs"
            />

            <div className="flex justify-between items-center pt-2">
              <span className="text-[11px] text-zinc-500">
                Ready to import into Clash, V2RayN, Nekobox, or Sing-Box.
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(generateConfigSnippet(exportModalFormat as any));
                    alert('Export config copied to clipboard!');
                  }}
                  className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-bold"
                >
                  Copy Config
                </button>
                <button
                  onClick={() => setExportModalFormat(null)}
                  className="px-3 py-1.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-300"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
