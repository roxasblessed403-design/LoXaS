import fs from 'fs';
import path from 'path';
import JSZip from 'jszip';
import type { DirectoryNode, ScanItemResult, StoredFile, TargetCategory } from '../src/types.js';

const STORAGE_ROOT = path.join(process.cwd(), 'data_storage');

const DEFAULT_DIRS = [
  'cdn/cloudflare',
  'cdn/cloudfront',
  'cdn/fastly',
  'cdn/akamai',
  'cdn/gcore',
  'cdn/google',
  'cdn/others',
  'sni',
  'direct-ip',
  'subdomains',
  'tricks-payloads',
  'unreachable',
];

/**
 * Initializes the disk storage structure with default directories and presets.
 */
export function initializeStorage() {
  try {
    if (!fs.existsSync(STORAGE_ROOT)) {
      fs.mkdirSync(STORAGE_ROOT, { recursive: true });
    }

    for (const dir of DEFAULT_DIRS) {
      const fullPath = path.join(STORAGE_ROOT, dir);
      if (!fs.existsSync(fullPath)) {
        fs.mkdirSync(fullPath, { recursive: true });
      }
    }

    // Populate initial curated reference files if empty
    const seedFiles: { file: string; content: string }[] = [
      {
        file: 'cdn/cloudflare/sample_cf_bughosts.txt',
        content: `# Cloudflare CDN Edge Bughost Presets
# Format: HOST | IP | PING_AVG | STATUS | DATE
104.16.240.5 | 104.16.240.5 | 18.2ms | 200 OK | 2026-08-18
172.67.180.12 | 172.67.180.12 | 22.4ms | 200 OK | 2026-08-18
speed.cloudflare.com | 104.16.123.96 | 15.1ms | 200 OK | 2026-08-18
www.cloudflare.com | 104.16.132.229 | 19.5ms | 200 OK | 2026-08-18
`,
      },
      {
        file: 'sni/curated_sni_hosts.txt',
        content: `# High-Trust SSL/TLS SNI Bughosts
# Format: HOST | ISSUER | TLS_VER | ALPN | FRONTABLE
cdn.zoom.us | DigiCert Inc | TLSv1.3 | h2,http/1.1 | YES
gateway.icloud.com | Apple Inc. | TLSv1.3 | h2 | YES
api.whatsapp.com | Meta Platforms | TLSv1.3 | h2 | YES
`,
      },
      {
        file: 'direct-ip/open_direct_nodes.txt',
        content: `# Direct IP Clean Nodes (Non-CDN)
# Format: IP | PORTS | TCP_HANDSHAKE | TTFB
1.1.1.1 | 80, 443 | 12.0ms | 18.5ms
8.8.8.8 | 80, 443 | 14.1ms | 21.0ms
9.9.9.9 | 80, 443 | 16.3ms | 24.2ms
`,
      },
      {
        file: 'tricks-payloads/websocket_loopholes.txt',
        content: `# WebSocket 101 Switching Protocols & HTTP Injection Loopholes
# Format: HOST | METHOD | STATUS | RESP_TIME | HEADERS
ws.speedtest.net | GET / HTTP/1.1 (Upgrade: websocket) | 101 Switching Protocols | 24.5ms | Upgrade: websocket
cloudflare.com | GET / HTTP/1.1 | 200 OK | 18.0ms | cf-ray
`,
      },
    ];

    for (const item of seedFiles) {
      const p = path.join(STORAGE_ROOT, item.file);
      if (!fs.existsSync(p)) {
        fs.writeFileSync(p, item.content, 'utf8');
      }
    }
  } catch (err) {
    console.error('Failed to initialize storage folders:', err);
  }
}

/**
 * Automatically classifies and persists a scanned item into the appropriate directory.
 */
export function autoSaveScanItem(item: ScanItemResult): {
  directory: string;
  fileName: string;
  category: TargetCategory;
} {
  let category: TargetCategory = 'unreachable';
  let targetSubDir = 'unreachable';
  let fileName = 'unreachable_hosts.txt';

  if (!item.ping.isAlive && item.ping.packetLoss === 100 && !item.direct.directReachable) {
    category = 'unreachable';
    targetSubDir = 'unreachable';
    fileName = 'packet_loss_100.txt';
  } else if (item.cdn.isCdn) {
    category = 'cdn';
    const prov = item.cdn.provider.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (prov.includes('cloudflare')) {
      targetSubDir = 'cdn/cloudflare';
      fileName = 'cloudflare_hosts.txt';
    } else if (prov.includes('cloudfront')) {
      targetSubDir = 'cdn/cloudfront';
      fileName = 'cloudfront_hosts.txt';
    } else if (prov.includes('fastly')) {
      targetSubDir = 'cdn/fastly';
      fileName = 'fastly_hosts.txt';
    } else if (prov.includes('akamai')) {
      targetSubDir = 'cdn/akamai';
      fileName = 'akamai_hosts.txt';
    } else if (prov.includes('gcore')) {
      targetSubDir = 'cdn/gcore';
      fileName = 'gcore_hosts.txt';
    } else {
      targetSubDir = 'cdn/others';
      fileName = 'other_cdn_hosts.txt';
    }
  } else if (item.sni.hasSni) {
    category = 'sni';
    targetSubDir = 'sni';
    fileName = item.sni.isFrontable ? 'frontable_sni.txt' : 'valid_sni_hosts.txt';
  } else if (item.direct.directReachable) {
    category = 'direct-ip';
    targetSubDir = 'direct-ip';
    fileName = 'direct_reachable_ips.txt';
  } else {
    category = 'subdomains';
    targetSubDir = 'subdomains';
    fileName = 'discovered_nodes.txt';
  }

  // Format line for persistence
  const dateStr = new Date(item.timestamp || Date.now()).toISOString().replace('T', ' ').slice(0, 19);
  const line = `${item.target.padEnd(28)} | IP: ${(item.resolvedIp || 'N/A').padEnd(16)} | Ping: ${String(item.ping.latencyAvg + 'ms').padEnd(8)} | Loss: ${String(item.ping.packetLoss + '%').padEnd(6)} | CDN: ${item.cdn.provider.padEnd(12)} | SNI: ${item.sni.hasSni ? 'YES' : 'NO'} | ${dateStr}\n`;

  try {
    const dirPath = path.join(STORAGE_ROOT, targetSubDir);
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }

    const filePath = path.join(dirPath, fileName);
    fs.appendFileSync(filePath, line, 'utf8');

    // Also update a global category list
    if (category === 'cdn') {
      const globalCdn = path.join(STORAGE_ROOT, 'cdn', 'all_cdn_hosts.txt');
      fs.appendFileSync(globalCdn, line, 'utf8');
    }
  } catch (err) {
    console.error('Error auto-saving scanned item:', err);
  }

  return {
    directory: targetSubDir,
    fileName,
    category,
  };
}

/**
 * Returns recursive directory node tree for file explorer.
 */
export function getDirectoryTree(relativeDir: string = ''): DirectoryNode {
  const currentPath = path.join(STORAGE_ROOT, relativeDir);

  if (!fs.existsSync(currentPath)) {
    return {
      name: 'root',
      path: '',
      type: 'directory',
      children: [],
    };
  }

  const stat = fs.statSync(currentPath);
  const baseName = relativeDir ? path.basename(relativeDir) : 'storage';

  if (!stat.isDirectory()) {
    return {
      name: baseName,
      path: relativeDir,
      type: 'file',
      size: stat.size,
      updatedAt: stat.mtime.toISOString(),
    };
  }

  const entries = fs.readdirSync(currentPath);
  const children: DirectoryNode[] = [];
  let totalFiles = 0;
  let totalBytes = 0;

  for (const entry of entries) {
    const entryRel = relativeDir ? `${relativeDir}/${entry}` : entry;
    const entryFull = path.join(STORAGE_ROOT, entryRel);
    const entryStat = fs.statSync(entryFull);

    if (entryStat.isDirectory()) {
      const subTree = getDirectoryTree(entryRel);
      children.push(subTree);
      totalFiles += subTree.fileCount || 0;
      totalBytes += subTree.size || 0;
    } else {
      children.push({
        name: entry,
        path: entryRel,
        type: 'file',
        size: entryStat.size,
        updatedAt: entryStat.mtime.toISOString(),
      });
      totalFiles += 1;
      totalBytes += entryStat.size;
    }
  }

  return {
    name: baseName,
    path: relativeDir,
    type: 'directory',
    children,
    fileCount: totalFiles,
    size: totalBytes,
    updatedAt: stat.mtime.toISOString(),
  };
}

/**
 * Reads file content.
 */
export function readStoredFile(filePath: string): StoredFile {
  const safeRelPath = path.normalize(filePath).replace(/^(\.\.(\/|\\|$))+/, '');
  const fullPath = path.join(STORAGE_ROOT, safeRelPath);

  if (!fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
    throw new Error('File not found');
  }

  const stat = fs.statSync(fullPath);
  const rawContent = fs.readFileSync(fullPath, 'utf8');
  const lines = rawContent.split('\n').filter((l) => l.trim().length > 0);

  const category = safeRelPath.split('/')[0] || 'custom';

  return {
    name: path.basename(safeRelPath),
    path: safeRelPath,
    category,
    size: stat.size,
    updatedAt: stat.mtime.toISOString(),
    itemCount: lines.filter((l) => !l.startsWith('#')).length,
    lines,
    rawContent,
  };
}

/**
 * Saves or updates content of a file in storage.
 */
export function writeStoredFile(filePath: string, content: string): StoredFile {
  const safeRelPath = path.normalize(filePath).replace(/^(\.\.(\/|\\|$))+/, '');
  const fullPath = path.join(STORAGE_ROOT, safeRelPath);

  const dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(fullPath, content, 'utf8');
  return readStoredFile(safeRelPath);
}

/**
 * Deletes a file or directory.
 */
export function deleteStoredPath(filePath: string): boolean {
  const safeRelPath = path.normalize(filePath).replace(/^(\.\.(\/|\\|$))+/, '');
  const fullPath = path.join(STORAGE_ROOT, safeRelPath);

  if (!fs.existsSync(fullPath)) return false;

  const stat = fs.statSync(fullPath);
  if (stat.isDirectory()) {
    fs.rmSync(fullPath, { recursive: true, force: true });
  } else {
    fs.unlinkSync(fullPath);
  }
  return true;
}

/**
 * Creates a zip archive buffer of all storage directories.
 */
export async function createStorageZip(): Promise<Buffer> {
  const zip = new JSZip();

  function addFolderToZip(folderPath: string, zipFolder: JSZip) {
    if (!fs.existsSync(folderPath)) return;
    const entries = fs.readdirSync(folderPath);

    for (const entry of entries) {
      const fullPath = path.join(folderPath, entry);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory()) {
        const subZip = zipFolder.folder(entry);
        if (subZip) {
          addFolderToZip(fullPath, subZip);
        }
      } else {
        const content = fs.readFileSync(fullPath);
        zipFolder.file(entry, content);
      }
    }
  }

  addFolderToZip(STORAGE_ROOT, zip);

  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}
