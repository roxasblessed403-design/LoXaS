export type TargetType = 'domain' | 'ip' | 'cidr';

export interface PingProbeResult {
  seq: number;
  rtt: number; // in milliseconds
  status: 'success' | 'timeout' | 'error';
  error?: string;
}

export interface PingStats {
  target: string;
  resolvedIp?: string;
  isAlive: boolean;
  packetsSent: number;
  packetsReceived: number;
  packetLoss: number; // percentage 0-100
  latencyMin: number;
  latencyAvg: number;
  latencyMax: number;
  jitter: number;
  probes: PingProbeResult[];
}

export interface RouteHop {
  hop: number;
  ip: string;
  hostname?: string;
  rtt: number;
  asn?: string;
  country?: string;
  city?: string;
  flag?: string;
  status: 'ok' | 'timeout';
}

export interface TracerouteResult {
  target: string;
  resolvedIp: string;
  totalHops: number;
  hops: RouteHop[];
  destinationReached: boolean;
  maxRtt: number;
  avgRtt: number;
}

export interface CdnDetection {
  isCdn: boolean;
  provider: 'Cloudflare' | 'CloudFront' | 'Akamai' | 'Fastly' | 'GCore' | 'EdgeCast' | 'Google Cloud CDN' | 'Azure Edge' | 'Alibaba CDN' | 'Tencent CDN' | 'Imperva' | 'StackPath' | 'Custom / Other CDN' | 'None';
  cname?: string;
  serverHeader?: string;
  viaHeader?: string;
  matchedHeaders: string[];
  matchedAsn?: string;
  asnOrg?: string;
  isCloudflare: boolean;
  isAkamai: boolean;
  isFastly: boolean;
  isCloudfront: boolean;
}

export interface SniTlsInfo {
  hasSni: boolean;
  tlsVersion?: string;
  cipher?: string;
  alpnProtocols: string[];
  certSubject?: string;
  certIssuer?: string;
  certValidFrom?: string;
  certValidTo?: string;
  isExpired?: boolean;
  sanList: string[];
  isWildcard: boolean;
  isFrontable: boolean;
}

export interface DirectConnection {
  directReachable: boolean;
  openPorts: number[];
  testedPorts: number[];
  tcpHandshakeMs: number;
  ttfbMs: number;
  httpStatus?: number;
  httpStatusText?: string;
  httpProtocol?: string;
  banner?: string;
}

export interface PayloadResult {
  id: string;
  name: string;
  method: string;
  path: string;
  payloadPattern: string;
  statusCode?: number;
  statusText?: string;
  responseTimeMs: number;
  isLoophole: boolean;
  matchedFeature?: string;
  responseHeaders?: Record<string, string>;
  snippet?: string;
}

export type TargetCategory = 'cdn' | 'sni' | 'direct-ip' | 'subdomains' | 'tricks-payloads' | 'unreachable';

export interface ScanItemResult {
  id: string;
  target: string;
  type: TargetType;
  resolvedIp?: string;
  timestamp: number;
  ping: PingStats;
  traceroute?: TracerouteResult;
  cdn: CdnDetection;
  sni: SniTlsInfo;
  direct: DirectConnection;
  payloads?: PayloadResult[];
  category: TargetCategory;
  savedDirectory: string; // e.g. "cdn/cloudflare" or "sni" or "direct-ip"
  savedFileName: string;
  notes?: string;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  errorMessage?: string;
}

export interface ScanOptions {
  targets: string[];
  pingCount: number; // e.g. 4
  pingTimeout: number; // ms e.g. 2500
  ports: number[]; // e.g. [80, 443, 8080, 8443]
  checkTraceroute: boolean;
  checkSni: boolean;
  checkCdn: boolean;
  checkPayloads: boolean;
  concurrency: number; // 1 - 20
  autoSave: boolean;
  subdomainEnum?: boolean;
  cidrScan?: boolean;
}

export interface StoredFile {
  name: string;
  path: string;
  category: string;
  size: number;
  updatedAt: string;
  itemCount: number;
  lines?: string[];
  rawContent?: string;
}

export interface DirectoryNode {
  name: string;
  path: string;
  type: 'directory' | 'file';
  category?: string;
  children?: DirectoryNode[];
  fileCount?: number;
  size?: number;
  updatedAt?: string;
}

export interface AppLanguageText {
  title: string;
  subtitle: string;
  singleHost: string;
  browseScan: string;
  quickTest: string;
  cidrScan: string;
  subdomainEnum: string;
  reverseIp: string;
  domainExtractor: string;
  proxyRelay: string;
  multiplierHosts: string;
  trickLab: string;
  payloadDiscovery: string;
  h2Detector: string;
  cloudSubdomain: string;
  directoryManager: string;
  aiDiagnostics: string;
  startScan: string;
  stopScan: string;
  exportResults: string;
  pingLatency: string;
  packetLoss: string;
  routeHops: string;
  cdnDetected: string;
  sniSecure: string;
  directIp: string;
  savedToDirectory: string;
  exportFormat: string;
}

export type SupportedLanguage = 'en' | 'es' | 'pt' | 'id' | 'ru' | 'fr';
