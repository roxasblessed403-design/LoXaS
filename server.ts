import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import {
  executePayloadTests,
  expandCidrIps,
  inspectCdnAndHeaders,
  inspectHostTlsInfo,
  inspectTlsAndSni,
  lookupIpDetails,
  performTcpPing,
  performTraceroute,
  probeDirectPorts,
  queryAllDnsRecords,
  resolveTargetDns,
  scanPortList,
} from './server/networkEngine.js';
import {
  autoSaveScanItem,
  createStorageZip,
  deleteStoredPath,
  getDirectoryTree,
  initializeStorage,
  readStoredFile,
  writeStoredFile,
} from './server/storageManager.js';
import type { ScanItemResult, ScanOptions } from './src/types.js';

const PORT = 3000;

// Lazy initialization for Gemini AI
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI | null {
  if (!aiClient && process.env.GEMINI_API_KEY) {
    aiClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  }
  return aiClient;
}

// Initialize directory structure
initializeStorage();

async function startServer() {
  const app = express();

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Health endpoint
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      version: '5.4.0',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: Date.now(),
    });
  });

  /**
   * Helper function to probe a single target comprehensively.
   */
  async function probeSingleTargetInternal(
    target: string,
    options: Partial<ScanOptions> = {}
  ): Promise<ScanItemResult> {
    const id = `scan_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const pingCount = Math.min(10, Math.max(1, options.pingCount || 4));
    const pingTimeout = options.pingTimeout || 2500;
    const ports = options.ports && options.ports.length > 0 ? options.ports : [80, 443];

    const isCidr = target.includes('/');
    const targetType = isCidr ? 'cidr' : /^(\d{1,3}\.){3}\d{1,3}$/.test(target) ? 'ip' : 'domain';

    try {
      // 1. DNS & IP resolution
      const dnsInfo = await resolveTargetDns(target);

      // 2. Ping latency & packet loss
      const pingStats = await performTcpPing(dnsInfo.host, dnsInfo.ip, dnsInfo.port || 80, pingCount, pingTimeout);

      // 3. CDN and header detection
      const cdnInfo = options.checkCdn !== false
        ? await inspectCdnAndHeaders(dnsInfo.host, dnsInfo.ip, dnsInfo.cnames)
        : {
            isCdn: false,
            provider: 'None' as const,
            matchedHeaders: [],
            isCloudflare: false,
            isAkamai: false,
            isFastly: false,
            isCloudfront: false,
          };

      // 4. TLS SNI check
      const sniInfo = options.checkSni !== false
        ? await inspectTlsAndSni(dnsInfo.host, dnsInfo.ip, 443, 2500)
        : {
            hasSni: false,
            alpnProtocols: [],
            sanList: [],
            isWildcard: false,
            isFrontable: false,
          };

      // 5. Direct port probing
      const directInfo = await probeDirectPorts(dnsInfo.host, dnsInfo.ip, ports);

      // 6. Route hop / Traceroute
      let tracerouteInfo;
      if (options.checkTraceroute) {
        tracerouteInfo = await performTraceroute(dnsInfo.host, dnsInfo.ip, 12);
      }

      // 7. Loophole & payload discovery
      let payloadResults;
      if (options.checkPayloads) {
        payloadResults = await executePayloadTests(dnsInfo.host, dnsInfo.ip);
      }

      // 8. Classify item
      const item: ScanItemResult = {
        id,
        target,
        type: targetType,
        resolvedIp: dnsInfo.ip,
        timestamp: Date.now(),
        ping: pingStats,
        traceroute: tracerouteInfo,
        cdn: cdnInfo,
        sni: sniInfo,
        direct: directInfo,
        payloads: payloadResults,
        category: 'unreachable',
        savedDirectory: '',
        savedFileName: '',
        status: 'completed',
      };

      // 9. Auto-save to directory structure if enabled
      if (options.autoSave !== false) {
        const saveRes = autoSaveScanItem(item);
        item.category = saveRes.category;
        item.savedDirectory = saveRes.directory;
        item.savedFileName = saveRes.fileName;
      }

      return item;
    } catch (err: any) {
      return {
        id,
        target,
        type: targetType,
        timestamp: Date.now(),
        ping: {
          target,
          isAlive: false,
          packetsSent: pingCount,
          packetsReceived: 0,
          packetLoss: 100,
          latencyMin: 0,
          latencyAvg: 0,
          latencyMax: 0,
          jitter: 0,
          probes: [],
        },
        cdn: {
          isCdn: false,
          provider: 'None',
          matchedHeaders: [],
          isCloudflare: false,
          isAkamai: false,
          isFastly: false,
          isCloudfront: false,
        },
        sni: {
          hasSni: false,
          alpnProtocols: [],
          sanList: [],
          isWildcard: false,
          isFrontable: false,
        },
        direct: {
          directReachable: false,
          openPorts: [],
          testedPorts: ports,
          tcpHandshakeMs: 0,
          ttfbMs: 0,
        },
        category: 'unreachable',
        savedDirectory: 'unreachable',
        savedFileName: 'unreachable_hosts.txt',
        status: 'failed',
        errorMessage: err.message || 'Scan failed',
      };
    }
  }

  // Single target probe API
  app.post('/api/scan/single', async (req, res) => {
    const { target, options = {} } = req.body;
    if (!target || typeof target !== 'string') {
      return res.status(400).json({ error: 'Target is required' });
    }

    try {
      const result = await probeSingleTargetInternal(target.trim(), options);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Internal probe error' });
    }
  });

  // Batch probe API with worker pool
  app.post('/api/scan/batch', async (req, res) => {
    const { targets = [], options = {} } = req.body;
    if (!Array.isArray(targets) || targets.length === 0) {
      return res.status(400).json({ error: 'Targets array is required' });
    }

    // Expand CIDRs if needed
    const expandedTargets: string[] = [];
    for (const t of targets) {
      if (typeof t === 'string' && t.includes('/')) {
        const ips = expandCidrIps(t, 64);
        expandedTargets.push(...ips);
      } else if (typeof t === 'string' && t.trim().length > 0) {
        expandedTargets.push(t.trim());
      }
    }

    const limit = Math.min(256, expandedTargets.length);
    const targetsToScan = expandedTargets.slice(0, limit);
    const concurrency = Math.min(20, Math.max(1, options.concurrency || 5));

    const results: ScanItemResult[] = [];
    let currentIndex = 0;

    async function worker() {
      while (currentIndex < targetsToScan.length) {
        const idx = currentIndex++;
        const target = targetsToScan[idx];
        const res = await probeSingleTargetInternal(target, options);
        results.push(res);
      }
    }

    const workers = Array.from({ length: Math.min(concurrency, targetsToScan.length) }, () => worker());
    await Promise.all(workers);

    res.json({
      total: targetsToScan.length,
      completed: results.length,
      results,
    });
  });

  // Real-time SSE Scan Stream
  app.get('/api/scan/stream', async (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const targetsParam = (req.query.targets as string) || '';
    const rawTargets = targetsParam.split(',').map((t) => t.trim()).filter(Boolean);

    const pingCount = parseInt(req.query.pingCount as string, 10) || 4;
    const checkCdn = req.query.checkCdn !== 'false';
    const checkSni = req.query.checkSni !== 'false';
    const checkTraceroute = req.query.checkTraceroute === 'true';
    const checkPayloads = req.query.checkPayloads === 'true';
    const concurrency = Math.min(10, parseInt(req.query.concurrency as string, 10) || 4);

    const expanded: string[] = [];
    for (const t of rawTargets) {
      if (t.includes('/')) {
        expanded.push(...expandCidrIps(t, 32));
      } else {
        expanded.push(t);
      }
    }

    const targets = expanded.slice(0, 128);

    res.write(`data: ${JSON.stringify({ type: 'start', total: targets.length })}\n\n`);

    let current = 0;
    let completedCount = 0;
    let isClientClosed = false;

    req.on('close', () => {
      isClientClosed = true;
    });

    async function streamWorker() {
      while (current < targets.length && !isClientClosed) {
        const idx = current++;
        const target = targets[idx];

        const item = await probeSingleTargetInternal(target, {
          pingCount,
          checkCdn,
          checkSni,
          checkTraceroute,
          checkPayloads,
          autoSave: true,
        });

        completedCount++;

        if (!isClientClosed) {
          res.write(
            `data: ${JSON.stringify({
              type: 'item',
              index: idx,
              completed: completedCount,
              total: targets.length,
              result: item,
            })}\n\n`
          );
        }
      }
    }

    const workers = Array.from({ length: Math.min(concurrency, targets.length) }, () => streamWorker());
    await Promise.all(workers);

    if (!isClientClosed) {
      res.write(`data: ${JSON.stringify({ type: 'done', total: targets.length })}\n\n`);
      res.end();
    }
  });

  // CIDR expansion preview
  app.post('/api/cidr/expand', (req, res) => {
    const { cidr, limit = 256 } = req.body;
    if (!cidr || typeof cidr !== 'string') {
      return res.status(400).json({ error: 'CIDR string is required' });
    }
    const ips = expandCidrIps(cidr, Math.min(1024, limit));
    res.json({ cidr, count: ips.length, ips });
  });

  // Subdomain Enumeration
  app.post('/api/subdomains/enum', async (req, res) => {
    const { domain } = req.body;
    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ error: 'Domain is required' });
    }

    const cleanDomain = domain.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    const prefixes = [
      'www', 'cdn', 'api', 'static', 'edge', 'gateway', 'stream', 'm', 'app',
      'dev', 'portal', 'ws', 'speed', 'node', 'free', 'zero', 'direct', 'dns',
      'auth', 'media', 'secure', 'cloud', 'proxy', 'relay'
    ];

    const results: { subdomain: string; ip?: string; isAlive: boolean; isCdn: boolean; provider: string }[] = [];

    // Probe subdomains
    const tasks = prefixes.map(async (prefix) => {
      const fullSub = `${prefix}.${cleanDomain}`;
      try {
        const dnsInfo = await resolveTargetDns(fullSub);
        if (dnsInfo.ip && dnsInfo.ip !== fullSub) {
          const pingRes = await performTcpPing(fullSub, dnsInfo.ip, 80, 2, 1500);
          const cdnRes = await inspectCdnAndHeaders(fullSub, dnsInfo.ip, dnsInfo.cnames);

          results.push({
            subdomain: fullSub,
            ip: dnsInfo.ip,
            isAlive: pingRes.isAlive,
            isCdn: cdnRes.isCdn,
            provider: cdnRes.provider,
          });
        }
      } catch {
        // Not resolvable
      }
    });

    await Promise.all(tasks);

    res.json({
      domain: cleanDomain,
      found: results.length,
      subdomains: results,
    });
  });

  // Comprehensive DNS Record lookup
  app.post('/api/dns/lookup', async (req, res) => {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }
    try {
      const records = await queryAllDnsRecords(domain);
      res.json(records);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // IP Details & Reverse PTR lookup
  app.post('/api/ip/lookup', async (req, res) => {
    const { target } = req.body;
    if (!target) {
      return res.status(400).json({ error: 'Target is required' });
    }
    try {
      const info = await lookupIpDetails(target);
      res.json(info);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Detailed Port Scanner
  app.post('/api/scan/ports', async (req, res) => {
    const { target, ports } = req.body;
    if (!target) {
      return res.status(400).json({ error: 'Target is required' });
    }
    try {
      const scanResults = await scanPortList(target, ports);
      res.json(scanResults);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Deep Host SSL / TLS Certificate Info
  app.post('/api/host/info', async (req, res) => {
    const { target } = req.body;
    if (!target) {
      return res.status(400).json({ error: 'Target is required' });
    }
    try {
      const hostInfo = await inspectHostTlsInfo(target);
      res.json(hostInfo);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Storage API endpoints
  app.get('/api/storage/tree', (req, res) => {
    try {
      const tree = getDirectoryTree();
      res.json(tree);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/storage/file', (req, res) => {
    const filePath = req.query.path as string;
    if (!filePath) {
      return res.status(400).json({ error: 'path parameter is required' });
    }
    try {
      const file = readStoredFile(filePath);
      res.json(file);
    } catch (err: any) {
      res.status(404).json({ error: err.message });
    }
  });

  app.post('/api/storage/file', (req, res) => {
    const { path: filePath, content } = req.body;
    if (!filePath || content === undefined) {
      return res.status(400).json({ error: 'path and content are required' });
    }
    try {
      const updated = writeStoredFile(filePath, content);
      res.json(updated);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.delete('/api/storage/file', (req, res) => {
    const filePath = req.query.path as string;
    if (!filePath) {
      return res.status(400).json({ error: 'path parameter is required' });
    }
    try {
      const success = deleteStoredPath(filePath);
      res.json({ success });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/storage/download-zip', async (req, res) => {
    try {
      const zipBuffer = await createStorageZip();
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="paragon_storage_directories.zip"');
      res.send(zipBuffer);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // AI Network Diagnostics using Gemini
  app.post('/api/ai/diagnose', async (req, res) => {
    const { target, pingData, cdnData, sniData, routeHops } = req.body;

    const genAI = getGeminiClient();
    if (!genAI) {
      return res.json({
        analysis: `AI network diagnostic summary for ${target}:\n- Host latency is ${pingData?.latencyAvg || 'N/A'}ms with ${pingData?.packetLoss || 0}% packet loss.\n- CDN classification: ${cdnData?.provider || 'None'}.\n- TLS SNI: ${sniData?.hasSni ? 'Enabled' : 'Disabled'}.\n- Recommended usage: ${cdnData?.isCdn ? 'Use as CDN/WAF fronting bughost' : 'Use as direct SNI tunnel target'}.`,
        recommendation: cdnData?.isCdn ? 'CDN WebSocket Tunneling' : 'Direct SNI / TCP Tunneling',
      });
    }

    try {
      const prompt = `You are an elite network engineer and telecommunications protocol diagnostic assistant.
Analyze these network test metrics for the target: "${target}"
Metrics:
- Ping Avg: ${pingData?.latencyAvg}ms (Min: ${pingData?.latencyMin}ms, Max: ${pingData?.latencyMax}ms, Jitter: ${pingData?.jitter}ms)
- Packet Loss: ${pingData?.packetLoss}%
- CDN Edge Provider: ${cdnData?.provider} (Server: ${cdnData?.serverHeader || 'None'}, Headers: ${cdnData?.matchedHeaders?.join(', ') || 'None'})
- SNI / TLS: Version ${sniData?.tlsVersion}, ALPN ${sniData?.alpnProtocols?.join('/')}, Frontable: ${sniData?.isFrontable ? 'Yes' : 'No'}
- Route Hops Count: ${routeHops?.length || 'N/A'}

Provide a concise, expert diagnostic summary (3-4 concise bullet points) outlining:
1. Connection Quality & Latency Rating
2. CDN / Edge Behavior & Cloudflare/Fastly/Akamai routing
3. SNI Tunneling / Bughost Viability (e.g. WebSocket 101, HTTP/2 fronting)
4. Recommended tunnel protocol (Vless-WS-TLS, Trojan-gRPC, Direct TCP, etc.)`;

      const response = await genAI.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
      });

      res.json({
        analysis: response.text || 'Analysis completed.',
      });
    } catch (err: any) {
      res.json({
        analysis: `Diagnostic complete: ${target} is ${pingData?.isAlive ? 'Active' : 'Unreachable'} (${pingData?.latencyAvg}ms). CDN: ${cdnData?.provider || 'None'}.`,
      });
    }
  });

  // Direct download routes for standalone CLI scripts
  app.get('/loxasb.go', (req, res) => {
    res.sendFile(path.join(process.cwd(), 'loxasb.go'));
  });

  app.get('/paragon.go', (req, res) => {
    res.sendFile(path.join(process.cwd(), 'paragon.go'));
  });

  app.get('/install_termux.sh', (req, res) => {
    res.setHeader('Content-Type', 'text/x-sh');
    res.sendFile(path.join(process.cwd(), 'install_termux.sh'));
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`LoXaSB Network Diagnostic server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
