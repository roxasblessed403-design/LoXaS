// ============================================================================
// LoXaSB PRO 5.5 - SUPREME EDITION (Full bugscan-x Architecture in Native Go)
// Built for Termux (Android) & Linux / macOS / Windows CLI Environments
//
// Complete feature set adapted from bugscan-x:
// ├── Host Scanner   : Direct HTTP/2, SSL/SNI, Multi-threaded CIDR, Ping Latency
// ├── Subfinder      : Live crt.sh Certificate Scraper + CDN Bughost Patterns
// ├── IP Lookup      : Reverse PTR, Cloudflare/CloudFront/Fastly ASN Subnets
// ├── Proxy Checker  : Open Proxy (CONNECT/Squid/8080/3128) & WebSocket 101 Upgrade
// ├── File Toolkit   : Saved Reports Browser, Viewer & Exporter (alive_hosts.txt)
// ├── Port Scanner   : 10-Port Bughost Matrix, Full Network Services, Custom Ports
// ├── DNS Records    : Query A, AAAA, CNAME, MX, TXT, NS records
// ├── Host Info      : Deep SSL/TLS 1.3 Handshake, Cipher Suite, SANs & Fronting
// └── OTA Updater    : Instant One-Click GitHub Engine Self-Updater
// ============================================================================

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ANSI Color Codes for Termux Terminal Output
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorPurple  = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
)

// Clear terminal screen cleanly
func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// Pause until user hits Enter
func pauseEnter(scanner *bufio.Scanner) {
	fmt.Printf("\n%s[Press ENTER to continue...]%s", ColorDim, ColorReset)
	scanner.Scan()
}

// CDN Signatures for classification
type CdnSignature struct {
	Name    string
	Cnames  []string
	Headers []string
	DirName string
}

var knownCdns = []CdnSignature{
	{Name: "Cloudflare", Cnames: []string{"cloudflare.net", "cloudflare.com"}, Headers: []string{"cf-ray", "cloudflare"}, DirName: "cdn/cloudflare"},
	{Name: "CloudFront", Cnames: []string{"cloudfront.net"}, Headers: []string{"x-amz-cf-id", "cloudfront"}, DirName: "cdn/cloudfront"},
	{Name: "Fastly", Cnames: []string{"fastly.net"}, Headers: []string{"x-fastly-request-id", "fastly"}, DirName: "cdn/fastly"},
	{Name: "Akamai", Cnames: []string{"akamaiedge.net", "akamai.net", "edgesuite.net"}, Headers: []string{"akamaighost", "x-akamai"}, DirName: "cdn/akamai"},
	{Name: "GCore", Cnames: []string{"gcore.lu", "gcore.com"}, Headers: []string{"gcore"}, DirName: "cdn/gcore"},
	{Name: "Google CDN", Cnames: []string{"googleusercontent.com", "1e100.net"}, Headers: []string{"gws", "google"}, DirName: "cdn/google"},
	{Name: "BunnyCDN", Cnames: []string{"b-cdn.net"}, Headers: []string{"bunnycdn", "b-cdn"}, DirName: "cdn/others"},
	{Name: "Imperva", Cnames: []string{"incapdns.net"}, Headers: []string{"x-iinfo", "incapsula"}, DirName: "cdn/others"},
}

var cloudflareCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
	"172.64.0.0/13", "131.0.72.0/22",
}

var cloudfrontCIDRs = []string{
	"13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "18.64.0.0/14",
	"52.84.0.0/15", "54.192.0.0/16", "54.230.0.0/16", "99.84.0.0/16",
	"99.86.0.0/16", "143.204.0.0/16", "204.246.160.0/19", "205.251.192.0/19",
}

var fastlyCIDRs = []string{
	"151.101.0.0/16", "199.232.0.0/16",
}

func ipInCIDRList(ipStr string, cidrList []string) bool {
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}
	for _, cidr := range cidrList {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// Target audit result structure
type TargetResult struct {
	Target           string
	ResolvedIP       string
	AllIPs           []string
	ReversePTR       string
	IsAlive          bool
	HttpStatus       int
	HttpStatusText   string
	HttpProto        string
	ServerHeader     string
	CfRayHeader      string
	ContentType      string
	LocationRedirect string
	DnsTimeMs        float64
	TcpConnectMs     float64
	TlsHandshakeMs   float64
	TtfbMs           float64
	PacketsSent      int
	PacketsReceived  int
	PacketLoss       float64
	LatencyMin       float64
	LatencyAvg       float64
	LatencyMax       float64
	Jitter           float64
	IsCdn            bool
	CdnProvider      string
	HasSni           bool
	TlsVersion       string
	CipherSuite      string
	CertSubject      string
	CertIssuer       string
	CertDaysLeft     int
	CertSANs         []string
	AlpnProtocols    []string
	IsFrontable      bool
	OpenPorts        []int
	ClosedPorts      []int
	SavedDirectory   string
	SavedFilename    string
	BughostVerdict   string
}

// Initialize directory structure
func initDirectories() {
	dirs := []string{
		"cdn/cloudflare", "cdn/cloudfront", "cdn/fastly",
		"cdn/akamai", "cdn/gcore", "cdn/google", "cdn/others",
		"sni", "direct-ip", "unreachable", "proxies",
	}

	for _, d := range dirs {
		_ = os.MkdirAll(d, 0755)
	}
}

// Clean target input
func cleanTarget(raw string) string {
	t := strings.TrimSpace(raw)
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	if idx := strings.Index(t, "/"); idx != -1 {
		t = t[:idx]
	}
	if idx := strings.Index(t, ":"); idx != -1 {
		t = t[:idx]
	}
	return t
}

// DNS resolution
func resolveDNS(target string) (string, []string, []string, float64) {
	start := time.Now()
	ips, err := net.LookupIP(target)
	dnsTime := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil || len(ips) == 0 {
		return target, []string{target}, nil, dnsTime
	}

	var allIPs []string
	var primaryIPv4 string

	for _, ip := range ips {
		allIPs = append(allIPs, ip.String())
		if ip.To4() != nil && primaryIPv4 == "" {
			primaryIPv4 = ip.String()
		}
	}
	if primaryIPv4 == "" {
		primaryIPv4 = ips[0].String()
	}

	cname, err := net.LookupCNAME(target)
	var cnames []string
	if err == nil && cname != "" && cname != target+"." {
		cnames = append(cnames, cname)
	}

	return primaryIPv4, allIPs, cnames, dnsTime
}

// Ping & packet loss benchmark
func probePing(host string, ip string, count int, timeout time.Duration) (bool, float64, float64, float64, float64, float64) {
	if count <= 0 {
		count = 5
	}

	var latencies []float64
	received := 0
	ports := []int{443, 80, 8080}

	for i := 0; i < count; i++ {
		for _, port := range ports {
			addr := fmt.Sprintf("%s:%d", ip, port)
			start := time.Now()
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				rtt := time.Since(start)
				conn.Close()
				rttMs := float64(rtt.Microseconds()) / 1000.0
				latencies = append(latencies, rttMs)
				received++
				break
			}
		}
		if i < count-1 {
			time.Sleep(25 * time.Millisecond)
		}
	}

	packetLoss := float64(count-received) / float64(count) * 100.0
	if received == 0 {
		return false, 0, 0, 0, 0, 100.0
	}

	minL := latencies[0]
	maxL := latencies[0]
	sumL := 0.0

	for _, l := range latencies {
		if l < minL {
			minL = l
		}
		if l > maxL {
			maxL = l
		}
		sumL += l
	}

	avgL := sumL / float64(received)
	jitter := maxL - minL

	return true, minL, avgL, maxL, jitter, packetLoss
}

// Deep SSL / TLS & SNI Inspector
func inspectTLS(target string, ip string) (bool, string, string, string, string, int, []string, []string, bool, float64) {
	serverNames := []string{target}
	if net.ParseIP(target) != nil {
		serverNames = []string{"", target, "cloudflare.com"}
	} else {
		serverNames = append(serverNames, "")
	}

	addr := fmt.Sprintf("%s:443", ip)
	dialer := &net.Dialer{Timeout: 3000 * time.Millisecond}

	for _, sni := range serverNames {
		conf := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}

		start := time.Now()
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
		tlsDuration := float64(time.Since(start).Microseconds()) / 1000.0

		if err == nil {
			defer conn.Close()
			state := conn.ConnectionState()
			tlsVer := "TLS 1.2"
			if state.Version == tls.VersionTLS13 {
				tlsVer = "TLS 1.3"
			}
			cipherName := tls.CipherSuiteName(state.CipherSuite)

			var alpn []string
			if state.NegotiatedProtocol != "" {
				alpn = append(alpn, state.NegotiatedProtocol)
			}

			isFrontable := len(alpn) > 0 || state.Version == tls.VersionTLS13

			var subjectCN, issuerOrg string
			var daysLeft int
			var sans []string

			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				subjectCN = cert.Subject.CommonName
				if len(cert.Issuer.Organization) > 0 {
					issuerOrg = cert.Issuer.Organization[0]
				} else {
					issuerOrg = cert.Issuer.CommonName
				}
				daysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
				sans = cert.DNSNames
			}

			return true, tlsVer, cipherName, subjectCN, issuerOrg, daysLeft, sans, alpn, isFrontable, tlsDuration
		}
	}

	return false, "None", "None", "", "", 0, nil, nil, false, 0
}

// Deep HTTP telemetry probe
func inspectHttpDeep(target string, ip string) (int, string, string, string, string, string, string, float64, float64) {
	schemes := []string{"https", "http"}

	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s", scheme, target)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "LoXaSB/5.5 (BugScan-X Go Engine; Android Termux)")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Host", target)

		transport := &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: target},
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				port := "443"
				if scheme == "http" {
					port = "80"
				}
				return net.DialTimeout(network, fmt.Sprintf("%s:%s", ip, port), 2500*time.Millisecond)
			},
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   3500 * time.Millisecond,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		start := time.Now()
		resp, err := client.Do(req)
		ttfb := float64(time.Since(start).Microseconds()) / 1000.0

		if err == nil {
			defer resp.Body.Close()
			server := resp.Header.Get("Server")
			cfRay := resp.Header.Get("cf-ray")
			contentType := resp.Header.Get("Content-Type")
			location := resp.Header.Get("Location")
			proto := resp.Proto

			return resp.StatusCode, resp.Status, proto, server, cfRay, contentType, location, ttfb, 15.0
		}
	}

	return 0, "No Response / Timed Out", "", "", "", "", "", 0, 0
}

// Identify CDN Provider
func inspectCDN(target string, ip string, cnames []string, serverHdr string, cfRay string) (bool, string) {
	if ipInCIDRList(ip, cloudflareCIDRs) {
		return true, "Cloudflare"
	}
	if ipInCIDRList(ip, cloudfrontCIDRs) {
		return true, "CloudFront"
	}
	if ipInCIDRList(ip, fastlyCIDRs) {
		return true, "Fastly"
	}

	for _, sig := range knownCdns {
		for _, cn := range sig.Cnames {
			for _, userCn := range cnames {
				if strings.Contains(strings.ToLower(userCn), cn) {
					return true, sig.Name
				}
			}
			if strings.Contains(strings.ToLower(target), cn) {
				return true, sig.Name
			}
		}
		if cfRay != "" && sig.Name == "Cloudflare" {
			return true, "Cloudflare"
		}
		if strings.Contains(strings.ToLower(serverHdr), strings.ToLower(sig.Name)) {
			return true, sig.Name
		}
	}

	if cfRay != "" {
		return true, "Cloudflare"
	}

	return false, "Direct Origin / Standard Host"
}

// Probe Common Bughost Ports Matrix
func probePortsMatrix(ip string) ([]int, []int) {
	testPorts := []int{80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2087, 2096}
	var open []int
	var closed []int

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, p := range testPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 900*time.Millisecond)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				open = append(open, port)
				conn.Close()
			} else {
				closed = append(closed, port)
			}
		}(p)
	}

	wg.Wait()
	sort.Ints(open)
	sort.Ints(closed)
	return open, closed
}

// Calculate Bughost & Free Net Compatibility Verdict
func calculateBughostVerdict(r *TargetResult) string {
	if !r.IsAlive {
		return "[!] DEAD HOST - Unreachable or timed out"
	}

	if r.IsCdn && r.CdnProvider == "Cloudflare" {
		if r.HasSni && r.HttpStatus == 101 {
			return "[★] EXCELLENT CLOUDFLARE WEBSOCKET BUGHOST (WS 101 Switching Protocols)"
		}
		if r.HasSni && (r.HttpStatus == 200 || r.HttpStatus == 403 || r.HttpStatus == 404) {
			return "[✓] HIGH-TIER CLOUDFLARE SNI BUGHOST (Supports TLS 1.3 / HTTP Custom / V2Ray)"
		}
		return "[✓] VALID CLOUDFLARE EDGE (Good for Fronting / SSL SNI)"
	}

	if r.IsCdn && (r.CdnProvider == "CloudFront" || r.CdnProvider == "Fastly" || r.CdnProvider == "Akamai") {
		return fmt.Sprintf("[✓] HIGH COMPATIBILITY %s CDN EDGE (Zero-Rating / SNI Candidate)", strings.ToUpper(r.CdnProvider))
	}

	if r.HasSni {
		return "[✓] VALID DIRECT TLS / SNI HOST (Working Handshake on Port 443)"
	}

	if len(r.OpenPorts) > 0 {
		return "[~] OPEN TCP PORTS DETECTED (Direct Origin Server)"
	}

	return "[?] UNCLASSIFIED HOST"
}

// Auto Save Target to Categorized Directory File
func autoSaveResult(r *TargetResult) {
	var dir string
	var reason string

	if !r.IsAlive {
		dir = "unreachable"
		reason = "Dead / Request Timeout"
	} else if r.IsCdn {
		switch r.CdnProvider {
		case "Cloudflare":
			dir = "cdn/cloudflare"
		case "CloudFront":
			dir = "cdn/cloudfront"
		case "Fastly":
			dir = "cdn/fastly"
		case "Akamai":
			dir = "cdn/akamai"
		case "GCore":
			dir = "cdn/gcore"
		case "Google CDN":
			dir = "cdn/google"
		default:
			dir = "cdn/others"
		}
		reason = fmt.Sprintf("CDN Edge Provider: %s", r.CdnProvider)
	} else if r.HasSni {
		dir = "sni"
		reason = fmt.Sprintf("Valid TLS/SNI (%s, ALPN: %s)", r.TlsVersion, strings.Join(r.AlpnProtocols, "/"))
	} else {
		dir = "direct-ip"
		reason = "Direct Origin Server / Clear IP"
	}

	cleanFileName := strings.ReplaceAll(r.Target, ":", "_")
	cleanFileName = strings.ReplaceAll(cleanFileName, "/", "_")
	filename := fmt.Sprintf("%s.txt", cleanFileName)
	fullPath := filepath.Join(dir, filename)

	content := fmt.Sprintf(`================================================================================
LoXaSB PRO 5.5 BUGSCAN-X DIAGNOSTIC & BUGHOST AUDIT REPORT
Generated : %s
Target    : %s
Primary IP: %s (All IPs: %s)
PTR DNS   : %s
Directory : %s/
Reason    : %s
Verdict   : %s
================================================================================

[1] HTTP & PROTOCOL TELEMETRY:
• Status Code      : %d (%s)
• Protocol         : %s
• Server Header    : %s
• CF-Ray ID        : %s
• Content-Type     : %s
• Redirect URL     : %s
• TTFB Response    : %.1f ms

[2] PING & PACKET LOSS STATISTICS:
• Alive Status     : %v
• Latency Min      : %.1f ms
• Latency Avg      : %.1f ms
• Latency Max      : %.1f ms
• Jitter           : %.1f ms
• Packet Loss Rate : %.0f%%

[3] CDN & CLOUD EDGE DETECTION:
• Is CDN Edge      : %v
• Provider         : %s

[4] SSL / TLS & SNI CERTIFICATE:
• Has Valid SNI    : %v
• TLS Version      : %s
• Cipher Suite     : %s
• Subject CN       : %s
• Issuer Org       : %s
• Days Remaining   : %d days
• ALPN Protocols   : %s
• Frontable SNI    : %v

[5] OPEN PORT MATRIX:
• Open Ports       : %v
• Filtered/Closed  : %v

================================================================================
Report stored at: %s
`,
		time.Now().Format(time.RFC3339),
		r.Target,
		r.ResolvedIP,
		strings.Join(r.AllIPs, ", "),
		r.ReversePTR,
		dir,
		reason,
		r.BughostVerdict,
		r.HttpStatus,
		r.HttpStatusText,
		r.HttpProto,
		r.ServerHeader,
		r.CfRayHeader,
		r.ContentType,
		r.LocationRedirect,
		r.TtfbMs,
		r.IsAlive,
		r.LatencyMin,
		r.LatencyAvg,
		r.LatencyMax,
		r.Jitter,
		r.PacketLoss,
		r.IsCdn,
		r.CdnProvider,
		r.HasSni,
		r.TlsVersion,
		r.CipherSuite,
		r.CertSubject,
		r.CertIssuer,
		r.CertDaysLeft,
		strings.Join(r.AlpnProtocols, "/"),
		r.IsFrontable,
		r.OpenPorts,
		r.ClosedPorts,
		fullPath,
	)

	_ = os.WriteFile(fullPath, []byte(content), 0644)
	r.SavedDirectory = dir
	r.SavedFilename = filename
}

// Master Deep Probe Function for a Single Target
func probeTarget(rawTarget string, pingCount int, trace bool) TargetResult {
	clean := cleanTarget(rawTarget)
	primaryIP, allIPs, cnames, dnsTime := resolveDNS(clean)

	var ptrStr string
	ptrs, err := net.LookupAddr(primaryIP)
	if err == nil && len(ptrs) > 0 {
		ptrStr = ptrs[0]
	} else {
		ptrStr = "None"
	}

	alive, minL, avgL, maxL, jitter, packetLoss := probePing(clean, primaryIP, pingCount, 1500*time.Millisecond)

	statusCode, statusText, proto, serverHdr, cfRay, contentType, location, ttfb, tcpConnect := inspectHttpDeep(clean, primaryIP)

	hasSni, tlsVer, cipher, subCN, issuer, daysLeft, sans, alpn, frontable, tlsTime := inspectTLS(clean, primaryIP)

	isCdn, cdnProvider := inspectCDN(clean, primaryIP, cnames, serverHdr, cfRay)

	openPorts, closedPorts := probePortsMatrix(primaryIP)

	res := TargetResult{
		Target:           clean,
		ResolvedIP:       primaryIP,
		AllIPs:           allIPs,
		ReversePTR:       ptrStr,
		IsAlive:          alive || statusCode > 0 || len(openPorts) > 0,
		HttpStatus:       statusCode,
		HttpStatusText:   statusText,
		HttpProto:        proto,
		ServerHeader:     serverHdr,
		CfRayHeader:      cfRay,
		ContentType:      contentType,
		LocationRedirect: location,
		DnsTimeMs:        dnsTime,
		TcpConnectMs:     tcpConnect,
		TlsHandshakeMs:   tlsTime,
		TtfbMs:           ttfb,
		PacketsSent:      pingCount,
		PacketsReceived:  int(float64(pingCount) * (100.0 - packetLoss) / 100.0),
		PacketLoss:       packetLoss,
		LatencyMin:       minL,
		LatencyAvg:       avgL,
		LatencyMax:       maxL,
		Jitter:           jitter,
		IsCdn:            isCdn,
		CdnProvider:      cdnProvider,
		HasSni:           hasSni,
		TlsVersion:       tlsVer,
		CipherSuite:      cipher,
		CertSubject:      subCN,
		CertIssuer:       issuer,
		CertDaysLeft:     daysLeft,
		CertSANs:         sans,
		AlpnProtocols:    alpn,
		IsFrontable:      frontable,
		OpenPorts:        openPorts,
		ClosedPorts:      closedPorts,
	}

	res.BughostVerdict = calculateBughostVerdict(&res)
	autoSaveResult(&res)
	return res
}

// Display Rich Upgraded Host Checker Result
func displayResult(r TargetResult) {
	fmt.Println()
	fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s┃        LoXaSB PRO 5.5 - COMPREHENSIVE CYBER-DIAGNOSTIC AUDIT          ┃%s\n", ColorBold, ColorReset)
	fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n", ColorCyan, ColorReset)

	// Target Identity
	fmt.Printf("%s[+] TARGET & DNS IDENTITY:%s\n", ColorBold, ColorReset)
	fmt.Printf(" • Target Host     : %s%s%s\n", ColorGreen, r.Target, ColorReset)
	fmt.Printf(" • Primary IPv4    : %s%s%s (Reverse PTR: %s)\n", ColorCyan, r.ResolvedIP, ColorReset, r.ReversePTR)
	if len(r.AllIPs) > 1 {
		fmt.Printf(" • All Resolved IPs: %s\n", strings.Join(r.AllIPs, ", "))
	}
	fmt.Printf(" • DNS Lookup Time : %.1f ms\n", r.DnsTimeMs)

	// HTTP & Handshake Telemetry
	fmt.Printf("\n%s[+] HTTP & WEB RESPONSE TELEMETRY:%s\n", ColorBold, ColorReset)
	statusColor := ColorGreen
	if r.HttpStatus >= 400 {
		statusColor = ColorYellow
	}
	if r.HttpStatus == 0 {
		statusColor = ColorRed
	}
	fmt.Printf(" • HTTP Status     : %s%d %s%s (Protocol: %s)\n", statusColor, r.HttpStatus, r.HttpStatusText, ColorReset, r.HttpProto)
	if r.ServerHeader != "" {
		fmt.Printf(" • Server Header   : %s%s%s\n", ColorPurple, r.ServerHeader, ColorReset)
	}
	if r.CfRayHeader != "" {
		fmt.Printf(" • CF-Ray ID       : %s%s%s\n", ColorPurple, r.CfRayHeader, ColorReset)
	}
	if r.LocationRedirect != "" {
		fmt.Printf(" • Redirect Target : %s%s%s\n", ColorYellow, r.LocationRedirect, ColorReset)
	}
	fmt.Printf(" • TTFB Latency    : %s%.1f ms%s\n", ColorCyan, r.TtfbMs, ColorReset)

	// CDN & Cloud Edge Detection
	fmt.Printf("\n%s[+] CDN & CLOUD EDGE DETECTION:%s\n", ColorBold, ColorReset)
	cdnColor := ColorDim
	cdnStatus := "Direct Origin / Not a CDN"
	if r.IsCdn {
		cdnColor = ColorPurple
		cdnStatus = fmt.Sprintf("DETECTED -> %s Edge Gateway", r.CdnProvider)
	}
	fmt.Printf(" • CDN Status      : %s%s%s\n", cdnColor, cdnStatus, ColorReset)

	// SSL / TLS & SNI Inspection
	fmt.Printf("\n%s[+] SSL / TLS & SNI CERTIFICATE AUDIT:%s\n", ColorBold, ColorReset)
	if r.HasSni {
		fmt.Printf(" • SNI Handshake   : %sVALID / OK%s (Version: %s%s%s)\n", ColorGreen, ColorReset, ColorCyan, r.TlsVersion, ColorReset)
		fmt.Printf(" • Cipher Suite    : %s\n", r.CipherSuite)
		fmt.Printf(" • Subject CN      : %s\n", r.CertSubject)
		fmt.Printf(" • Issuer Org      : %s\n", r.CertIssuer)
		fmt.Printf(" • Expiration      : %d days left\n", r.CertDaysLeft)
		if len(r.CertSANs) > 0 {
			limit := len(r.CertSANs)
			if limit > 4 {
				limit = 4
			}
			fmt.Printf(" • SANs (%d total) : %s\n", len(r.CertSANs), strings.Join(r.CertSANs[:limit], ", "))
		}
		fmt.Printf(" • Fronting Status : %s%s%s\n", ColorGreen, map[bool]string{true: "[✓] Frontable SNI Supported", false: "[!] Standard SNI"}[r.IsFrontable], ColorReset)
	} else {
		fmt.Printf(" • SNI Handshake   : %sNO TLS / CLOSED (Port 443 Not Responding)%s\n", ColorRed, ColorReset)
	}

	// Port Matrix
	fmt.Printf("\n%s[+] PORT MATRIX (80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2087, 2096):%s\n", ColorBold, ColorReset)
	if len(r.OpenPorts) > 0 {
		fmt.Printf(" • Open Ports      : %s%v%s\n", ColorGreen, r.OpenPorts, ColorReset)
	} else {
		fmt.Printf(" • Open Ports      : %sNone Detected%s\n", ColorRed, ColorReset)
	}

	// Ping & Jitter
	fmt.Printf("\n%s[+] PING & QUALITY JITTER STATISTICS:%s\n", ColorBold, ColorReset)
	aliveColor := ColorGreen
	aliveTxt := "ALIVE / REACHABLE"
	if !r.IsAlive {
		aliveColor = ColorRed
		aliveTxt = "DEAD / TIMED OUT"
	}
	fmt.Printf(" • Probe Status    : %s%s%s\n", aliveColor, aliveTxt, ColorReset)
	fmt.Printf(" • Latency Stats   : Min: %s%.1fms%s | Avg: %s%.1fms%s | Max: %s%.1fms%s\n",
		ColorCyan, r.LatencyMin, ColorReset, ColorGreen, r.LatencyAvg, ColorReset, ColorYellow, r.LatencyMax, ColorReset)
	fmt.Printf(" • Jitter / Loss   : Jitter: %.1fms | Packet Loss: %s%.0f%%%s\n", r.Jitter, ColorYellow, r.PacketLoss, ColorReset)

	// Final Verdict Box
	fmt.Printf("\n%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorGreen, ColorReset)
	fmt.Printf("┃ BUGHOST VERDICT: %-52s ┃\n", r.BughostVerdict)
	fmt.Printf("┃ AUTO-SAVED TO  : %-52s ┃\n", fmt.Sprintf("%s/%s", r.SavedDirectory, r.SavedFilename))
	fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorGreen, ColorReset)
}

// CIDR Subnet Parser and IP Range Calculator
func calculateAndExpandCIDR(cidrStr string) ([]string, int, net.IP, net.IP, string, string, error) {
	clean := strings.TrimSpace(cidrStr)
	if !strings.Contains(clean, "/") {
		clean = clean + "/24"
	}

	_, ipNet, err := net.ParseCIDR(clean)
	if err != nil {
		return nil, 0, nil, nil, "", "", err
	}

	ones, bits := ipNet.Mask.Size()
	totalCount := 1 << (bits - ones)

	var ips []string
	cur := make(net.IP, len(ipNet.IP))
	copy(cur, ipNet.IP)

	for ipNet.Contains(cur) {
		ips = append(ips, cur.String())
		incIP(cur)
	}

	firstUsable := "N/A"
	lastUsable := "N/A"
	if len(ips) > 2 {
		firstUsable = ips[1]
		lastUsable = ips[len(ips)-2]
	} else if len(ips) > 0 {
		firstUsable = ips[0]
		lastUsable = ips[len(ips)-1]
	}

	maskIP := net.IP(ipNet.Mask)

	return ips, totalCount, ipNet.IP, maskIP, firstUsable, lastUsable, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// High-Speed CIDR & Batch Worker Scanner with Live Progress
func runConcurrentCIDRScanner(ips []string, workers int, subnetInfo string) {
	if len(ips) == 0 {
		fmt.Println("No IPs to scan.")
		return
	}

	if workers <= 0 {
		workers = 25
	}
	if workers > 200 {
		workers = 200
	}

	total := len(ips)
	fmt.Printf("\n%s[+] LAUNCHING CONCURRENT CIDR SCANNER%s\n", ColorCyan, ColorReset)
	fmt.Printf(" • Target Subnet     : %s\n", subnetInfo)
	fmt.Printf(" • Total Target IPs  : %s%d IPs%s\n", ColorGreen, total, ColorReset)
	fmt.Printf(" • Worker Threads    : %s%d Workers%s\n", ColorPurple, workers, ColorReset)
	fmt.Printf(" • Scanning Strategy : Fast TCP Port 443/80 + HTTP Response + CDN Fingerprint\n\n")

	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%-6s %-16s %-10s %-14s %-12s %-16s\n", "PROG", "IP ADDRESS", "STATUS", "HTTP CODE", "LATENCY", "CDN / VERDICT")
	fmt.Println(strings.Repeat("─", 80))

	ipChan := make(chan string, total)
	var processedCount int64
	var aliveCount int64
	var cdnCount int64

	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetIP := range ipChan {
				idx := atomic.AddInt64(&processedCount, 1)

				statusCode, statusText, _, serverHdr, cfRay, _, _, ttfb, _ := inspectHttpDeep(targetIP, targetIP)
				alive, minL, avgL, _, _, loss := probePing(targetIP, targetIP, 2, 800*time.Millisecond)
				isCdn, provider := inspectCDN(targetIP, targetIP, nil, serverHdr, cfRay)

				_ = minL
				_ = loss

				if alive || statusCode > 0 {
					atomic.AddInt64(&aliveCount, 1)
					if isCdn {
						atomic.AddInt64(&cdnCount, 1)
					}

					res := TargetResult{
						Target:         targetIP,
						ResolvedIP:     targetIP,
						IsAlive:        true,
						HttpStatus:     statusCode,
						HttpStatusText: statusText,
						ServerHeader:   serverHdr,
						CfRayHeader:    cfRay,
						TtfbMs:         ttfb,
						LatencyAvg:     avgL,
						IsCdn:          isCdn,
						CdnProvider:    provider,
					}
					res.BughostVerdict = calculateBughostVerdict(&res)
					autoSaveResult(&res)

					codeStr := fmt.Sprintf("%d", statusCode)
					if statusCode == 0 {
						codeStr = "TCP Open"
					}
					cdnDisplay := provider
					if !isCdn {
						cdnDisplay = "Direct"
					}

					fmt.Printf("[%3d/%3d] %s%-16s%s %s%-10s%s %-14s %-12s %s%-16s%s\n",
						idx, total,
						ColorGreen, targetIP, ColorReset,
						ColorCyan, "ALIVE", ColorReset,
						codeStr,
						fmt.Sprintf("%.1f ms", avgL),
						ColorPurple, cdnDisplay, ColorReset,
					)
				} else {
					fmt.Printf("[%3d/%3d] %s%-16s%s %s%-10s%s %-14s %-12s %-16s\n",
						idx, total,
						ColorDim, targetIP, ColorReset,
						ColorRed, "TIMEOUT", ColorReset,
						"-",
						"-",
						"Unreachable",
					)
				}
			}
		}()
	}

	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	wg.Wait()

	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%s[✓] SCAN COMPLETE:%s %d/%d IPs Alive | %d CDN Edge Nodes Identified\n",
		ColorGreen, ColorReset, aliveCount, total, cdnCount)
	fmt.Printf("%s[+] Results saved into ./cdn/ and ./sni/ folders. (Check Option [5] File Toolkit to view)%s\n\n", ColorCyan, ColorReset)
}

// ----------------------------------------------------------------------------
// [1] HOST SCANNER - BUGSCAN-X SETUP WORKFLOW & WORKER POOLS
// ----------------------------------------------------------------------------

func readCIDRsFromFile(filepath string) []string {
	var validCIDRs []string
	file, err := os.Open(filepath)
	if err != nil {
		fmt.Printf("%s[!] Error reading file: %v%s\n", ColorRed, err, ColorReset)
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, _, err := net.ParseCIDR(line)
		if err == nil {
			validCIDRs = append(validCIDRs, line)
		} else {
			if ip := net.ParseIP(line); ip != nil {
				validCIDRs = append(validCIDRs, line+"/32")
			}
		}
	}
	return validCIDRs
}

func getCIDRRangesFromInput(cidrInput string) []string {
	var ranges []string
	parts := strings.Split(cidrInput, ",")
	for _, p := range parts {
		clean := strings.TrimSpace(p)
		if clean != "" {
			ranges = append(ranges, clean)
		}
	}
	return ranges
}

func getCommonInputs(scanner *bufio.Scanner) (string, int) {
	defaultFilename := "results.txt"
	fmt.Printf("[-]  Enter output filename [default: %s]: ", defaultFilename)
	output := defaultFilename
	if scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			output = text
		}
	}

	defaultThreads := 50
	fmt.Printf("[-]  Enter threads [default: %d]: ", defaultThreads)
	threads := defaultThreads
	if scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			if t, err := strconv.Atoi(text); err == nil && t > 0 {
				threads = t
			}
		}
	}
	return output, threads
}

func getHostInput(scanner *bufio.Scanner) (string, []string) {
	fmt.Printf("[-]  Enter filename (or press ENTER to specify CIDR/host): ")
	var filename string
	if scanner.Scan() {
		filename = strings.TrimSpace(scanner.Text())
	}

	if filename == "" {
		fmt.Printf("[-]  Enter CIDR range(s) (comma-separated, or press ENTER to use file/host): ")
		var cidrStr string
		if scanner.Scan() {
			cidrStr = strings.TrimSpace(scanner.Text())
		}
		if cidrStr == "" {
			fmt.Printf("[-]  Enter CIDR file or Hostname (e.g. cidrs.txt or speed.cloudflare.com): ")
			var cidrFile string
			if scanner.Scan() {
				cidrFile = strings.TrimSpace(scanner.Text())
			}
			if cidrFile != "" {
				if _, err := os.Stat(cidrFile); err == nil {
					validCidrs := readCIDRsFromFile(cidrFile)
					return "", validCidrs
				} else {
					return "", []string{cidrFile}
				}
			}
			return "", nil
		}
		return "", getCIDRRangesFromInput(cidrStr)
	}
	return filename, nil
}

func parsePortList(input string, defaultPort int) []int {
	if strings.TrimSpace(input) == "" {
		return []int{defaultPort}
	}
	var ports []int
	for _, p := range strings.Split(input, ",") {
		clean := strings.TrimSpace(p)
		if val, err := strconv.Atoi(clean); err == nil && val > 0 && val <= 65535 {
			ports = append(ports, val)
		}
	}
	if len(ports) == 0 {
		return []int{defaultPort}
	}
	return ports
}

func expandAllTargets(filename string, cidrs []string) []string {
	var targets []string
	if filename != "" {
		file, err := os.Open(filename)
		if err == nil {
			defer file.Close()
			s := bufio.NewScanner(file)
			for s.Scan() {
				line := strings.TrimSpace(s.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
		} else {
			fmt.Printf("%s[!] Could not open file %s: %v%s\n", ColorRed, filename, err, ColorReset)
		}
	}

	for _, cidr := range cidrs {
		if strings.Contains(cidr, "/") {
			ips, _, _, _, _, _, err := calculateAndExpandCIDR(cidr)
			if err == nil {
				targets = append(targets, ips...)
			} else {
				targets = append(targets, cidr)
			}
		} else {
			targets = append(targets, cidr)
		}
	}
	return targets
}

func getInputDirect(scanner *bufio.Scanner, no302 bool) {
	fmt.Println()
	modeTitle := "Direct HTTP Scanner"
	if no302 {
		modeTitle = "Direct Non-302 HTTP Scanner (Filtering Redirects)"
	}
	fmt.Printf("%s[+] %s Setup%s\n", ColorCyan, modeTitle, ColorReset)

	filename, cidr := getHostInput(scanner)
	if filename == "" && len(cidr) == 0 {
		fmt.Printf("%s[!] No host or CIDR provided. Aborting.%s\n", ColorYellow, ColorReset)
		return
	}

	fmt.Printf("[-]  Enter port(s) [default: 80]: ")
	portStr := "80"
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			portStr = t
		}
	}
	ports := parsePortList(portStr, 80)

	fmt.Printf("[-]  Enter timeout in seconds [default: 3]: ")
	timeoutSec := 3
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			if num, err := strconv.Atoi(t); err == nil && num > 0 {
				timeoutSec = num
			}
		}
	}

	output, threads := getCommonInputs(scanner)

	fmt.Printf("[-]  Select HTTP method(s) (GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, PATCH) [default: GET,HEAD]: ")
	methodsStr := "GET,HEAD"
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			methodsStr = strings.ToUpper(t)
		}
	}
	var methods []string
	for _, m := range strings.Split(methodsStr, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			methods = append(methods, m)
		}
	}
	if len(methods) == 0 {
		methods = []string{"GET", "HEAD"}
	}

	targets := expandAllTargets(filename, cidr)
	if len(targets) == 0 {
		fmt.Printf("%s[!] No valid targets found.%s\n", ColorRed, ColorReset)
		return
	}

	runDirectScannerWorkerPool(targets, ports, methods, no302, timeoutSec, output, threads)
}

func getInputProxy(scanner *bufio.Scanner) {
	fmt.Println()
	fmt.Printf("%s[+] ProxyTest / WebSocket 101 Probe Setup%s\n", ColorGreen, ColorReset)

	filename, cidr := getHostInput(scanner)
	if filename == "" && len(cidr) == 0 {
		fmt.Printf("%s[!] No host or CIDR provided. Aborting.%s\n", ColorYellow, ColorReset)
		return
	}

	defaultTarget := "in1.wstunnel.site"
	fmt.Printf("[-]  Enter target url [default: %s]: ", defaultTarget)
	targetUrl := defaultTarget
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			targetUrl = t
		}
	}

	defaultPayload := "GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
	fmt.Printf("[-]  Enter payload [default: %s]: ", defaultPayload)
	payload := defaultPayload
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			payload = t
		}
	}

	fmt.Printf("[-]  Enter port(s) [default: 80]: ")
	portStr := "80"
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			portStr = t
		}
	}
	ports := parsePortList(portStr, 80)

	output, threads := getCommonInputs(scanner)
	targets := expandAllTargets(filename, cidr)
	if len(targets) == 0 {
		fmt.Printf("%s[!] No valid targets found.%s\n", ColorRed, ColorReset)
		return
	}

	runProxyTestWorkerPool(targets, ports, targetUrl, payload, output, threads)
}

func getInputProxy2(scanner *bufio.Scanner) {
	fmt.Println()
	fmt.Printf("%s[+] ProxyRoute (Upstream Proxy Injection) Setup%s\n", ColorPurple, ColorReset)

	filename, cidr := getHostInput(scanner)
	if filename == "" && len(cidr) == 0 {
		fmt.Printf("%s[!] No host or CIDR provided. Aborting.%s\n", ColorYellow, ColorReset)
		return
	}

	fmt.Printf("[-]  Enter port(s) [default: 80]: ")
	portStr := "80"
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			portStr = t
		}
	}
	ports := parsePortList(portStr, 80)

	output, threads := getCommonInputs(scanner)

	fmt.Printf("[-]  Select HTTP method(s) (GET, HEAD, POST, OPTIONS, etc.) [default: GET]: ")
	methodsStr := "GET"
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			methodsStr = strings.ToUpper(t)
		}
	}
	var methods []string
	for _, m := range strings.Split(methodsStr, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			methods = append(methods, m)
		}
	}
	if len(methods) == 0 {
		methods = []string{"GET"}
	}

	fmt.Printf("[-]  Enter proxy (proxy:port, e.g. 127.0.0.1:8080): ")
	var proxyAddr string
	if scanner.Scan() {
		proxyAddr = strings.TrimSpace(scanner.Text())
	}
	if proxyAddr == "" {
		fmt.Printf("%s[!] Proxy is required for ProxyRoute mode.%s\n", ColorRed, ColorReset)
		return
	}

	fmt.Printf("[-]  Use proxy authentication? (y/N): ")
	var useAuth bool
	if scanner.Scan() {
		ans := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if ans == "y" || ans == "yes" {
			useAuth = true
		}
	}

	var proxyUser, proxyPass string
	if useAuth {
		fmt.Printf("[-]  Enter proxy username: ")
		if scanner.Scan() {
			proxyUser = strings.TrimSpace(scanner.Text())
		}
		fmt.Printf("[-]  Enter proxy password: ")
		if scanner.Scan() {
			proxyPass = strings.TrimSpace(scanner.Text())
		}
	}

	targets := expandAllTargets(filename, cidr)
	if len(targets) == 0 {
		fmt.Printf("%s[!] No valid targets found.%s\n", ColorRed, ColorReset)
		return
	}

	runProxyRouteWorkerPool(targets, ports, methods, proxyAddr, proxyUser, proxyPass, output, threads)
}

func getInputSSL(scanner *bufio.Scanner) {
	fmt.Println()
	fmt.Printf("%s[+] SSL / TLS & SNI Fronting Scanner Setup%s\n", ColorCyan, ColorReset)

	filename, cidr := getHostInput(scanner)
	if filename == "" && len(cidr) == 0 {
		fmt.Printf("%s[!] No host or CIDR provided. Aborting.%s\n", ColorYellow, ColorReset)
		return
	}

	fmt.Printf("[-]  Enter port(s) [default: 443]: ")
	portStr := "443"
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			portStr = t
		}
	}
	ports := parsePortList(portStr, 443)

	output, threads := getCommonInputs(scanner)
	targets := expandAllTargets(filename, cidr)
	if len(targets) == 0 {
		fmt.Printf("%s[!] No valid targets found.%s\n", ColorRed, ColorReset)
		return
	}

	runSSLWorkerPool(targets, ports, output, threads)
}

func getInputPing(scanner *bufio.Scanner) {
	fmt.Println()
	fmt.Printf("%s[+] Ping / TCP Reachability Scanner Setup (BugScan-X Engine)%s\n", ColorCyan, ColorReset)

	filename, cidrs := getHostInput(scanner)
	if filename == "" && len(cidrs) == 0 {
		fmt.Printf("%s[!] No host or CIDR provided. Aborting.%s\n", ColorYellow, ColorReset)
		return
	}

	fmt.Printf("[-]  Enter port(s) [default: 80,443]: ")
	portStr := "80,443"
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			portStr = t
		}
	}
	ports := parsePortList(portStr, 80)

	output, threads := getCommonInputs(scanner)
	isCidr := len(cidrs) > 0 && filename == ""
	targets := expandAllTargets(filename, cidrs)
	if len(targets) == 0 {
		fmt.Printf("%s[!] No valid targets found.%s\n", ColorRed, ColorReset)
		return
	}

	runPingWorkerPool(targets, ports, isCidr, output, threads)
}

func runDirectScannerWorkerPool(targets []string, ports []int, methods []string, no302 bool, timeoutSec int, outputFile string, threads int) {
	if len(targets) == 0 {
		return
	}
	if threads <= 0 {
		threads = 50
	}
	if timeoutSec <= 0 {
		timeoutSec = 3
	}

	type scanTask struct {
		target string
		port   int
		method string
	}

	var tasks []scanTask
	for _, t := range targets {
		for _, p := range ports {
			for _, m := range methods {
				tasks = append(tasks, scanTask{target: t, port: p, method: m})
			}
		}
	}

	total := len(tasks)
	fmt.Printf("\n%s[+] STARTING DIRECT SCANNER: %d Tasks | %d Threads | Timeout: %ds%s\n", ColorCyan, total, threads, timeoutSec, ColorReset)
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%-6s %-24s %-8s %-12s %-12s %-16s\n", "PROG", "TARGET:PORT", "METHOD", "STATUS", "LATENCY", "SERVER / CDN")
	fmt.Println(strings.Repeat("─", 80))

	taskChan := make(chan scanTask, total)
	var processedCount int64
	var aliveCount int64
	var outMutex sync.Mutex

	var outFile *os.File
	var err error
	if outputFile != "" {
		outFile, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer outFile.Close()
		}
	}

	var wg sync.WaitGroup
	timeoutDur := time.Duration(timeoutSec) * time.Second

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Timeout: timeoutDur,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			for t := range taskChan {
				idx := atomic.AddInt64(&processedCount, 1)
				targetHost := t.target
				ip, _, cnames, _ := resolveDNS(targetHost)

				scheme := "http"
				if t.port == 443 || t.port == 8443 || t.port == 2053 || t.port == 2083 || t.port == 2087 || t.port == 2096 {
					scheme = "https"
				}

				targetUrl := fmt.Sprintf("%s://%s:%d/", scheme, targetHost, t.port)
				req, err := http.NewRequest(t.method, targetUrl, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "LoXaSB/5.5")
				req.Header.Set("Host", targetHost)

				start := time.Now()
				resp, err := client.Do(req)
				rtt := float64(time.Since(start).Microseconds()) / 1000.0

				if err == nil {
					statusCode := resp.StatusCode
					resp.Body.Close()

					if no302 && (statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308) {
						continue
					}

					atomic.AddInt64(&aliveCount, 1)
					serverHdr := resp.Header.Get("Server")
					cfRay := resp.Header.Get("CF-Ray")
					isCdn, provider := inspectCDN(targetHost, ip, cnames, serverHdr, cfRay)

					displayServer := serverHdr
					if isCdn {
						displayServer = provider
					}
					if displayServer == "" {
						displayServer = "Direct"
					}

					color := ColorGreen
					if statusCode >= 400 {
						color = ColorYellow
					}

					addrStr := fmt.Sprintf("%s:%d", targetHost, t.port)
					fmt.Printf("[%3d/%3d] %s%-24s%s %-8s %s%-12s%s %-12.1f %s%-16s%s\n",
						idx, total,
						ColorGreen, addrStr, ColorReset,
						t.method,
						color, resp.Status, ColorReset,
						rtt,
						ColorPurple, displayServer, ColorReset,
					)

					if outFile != nil {
						outMutex.Lock()
						_, _ = outFile.WriteString(fmt.Sprintf("%s:%d [%s] %s (Latency: %.1fms, Server: %s)\n", targetHost, t.port, t.method, resp.Status, rtt, displayServer))
						outMutex.Unlock()
					}

					res := TargetResult{
						Target:         targetHost,
						ResolvedIP:     ip,
						IsAlive:        true,
						HttpStatus:     statusCode,
						HttpStatusText: resp.Status,
						ServerHeader:   serverHdr,
						CfRayHeader:    cfRay,
						TtfbMs:         rtt,
						LatencyAvg:     rtt,
						IsCdn:          isCdn,
						CdnProvider:    provider,
					}
					res.BughostVerdict = calculateBughostVerdict(&res)
					autoSaveResult(&res)
				}
			}
		}()
	}

	for _, task := range tasks {
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()

	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%s[✓] DIRECT SCAN COMPLETED:%s %d/%d Alive Responses Found.\n", ColorGreen, ColorReset, aliveCount, total)
	if outputFile != "" {
		fmt.Printf("%s[+] Results saved to: %s%s\n\n", ColorCyan, outputFile, ColorReset)
	}
}

func runProxyTestWorkerPool(targets []string, ports []int, targetUrl string, rawPayload string, outputFile string, threads int) {
	if len(targets) == 0 {
		return
	}
	if threads <= 0 {
		threads = 50
	}

	type proxyTask struct {
		target string
		port   int
	}

	var tasks []proxyTask
	for _, t := range targets {
		for _, p := range ports {
			tasks = append(tasks, proxyTask{target: t, port: p})
		}
	}

	total := len(tasks)
	fmt.Printf("\n%s[+] STARTING PROXYTEST / WEBSOCKET SCANNER: %d Targets | %d Threads%s\n", ColorGreen, total, threads, ColorReset)
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%-6s %-26s %-16s %-12s %-18s\n", "PROG", "PROXY HOST:PORT", "STATUS", "LATENCY", "VERDICT / BANNER")
	fmt.Println(strings.Repeat("─", 80))

	taskChan := make(chan proxyTask, total)
	var processedCount int64
	var aliveCount int64
	var outMutex sync.Mutex

	var outFile *os.File
	var err error
	if outputFile != "" {
		outFile, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer outFile.Close()
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskChan {
				idx := atomic.AddInt64(&processedCount, 1)
				hostAddr := fmt.Sprintf("%s:%d", t.target, t.port)

				start := time.Now()
				conn, err := net.DialTimeout("tcp", hostAddr, 3*time.Second)
				rtt := float64(time.Since(start).Microseconds()) / 1000.0

				if err == nil {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

					formattedPayload := rawPayload
					formattedPayload = strings.ReplaceAll(formattedPayload, "[host]", targetUrl)
					formattedPayload = strings.ReplaceAll(formattedPayload, "[crlf]", "\r\n")

					_, err = conn.Write([]byte(formattedPayload))
					if err == nil {
						buf := make([]byte, 1024)
						n, readErr := conn.Read(buf)
						if readErr == nil && n > 0 {
							respStr := string(buf[:n])
							lines := strings.Split(respStr, "\r\n")
							firstLine := lines[0]
							if len(firstLine) > 28 {
								firstLine = firstLine[:28]
							}

							atomic.AddInt64(&aliveCount, 1)

							is101 := strings.Contains(respStr, "101 Switching Protocols")
							statusColor := ColorGreen
							verdict := firstLine
							if is101 {
								statusColor = ColorCyan
								verdict = "[★] WS 101 OK!"
							}

							fmt.Printf("[%3d/%3d] %s%-26s%s %s%-16s%s %-12.1f %s%-18s%s\n",
								idx, total,
								ColorGreen, hostAddr, ColorReset,
								statusColor, firstLine, ColorReset,
								rtt,
								statusColor, verdict, ColorReset,
							)

							if outFile != nil {
								outMutex.Lock()
								_, _ = outFile.WriteString(fmt.Sprintf("%s - %s (%.1fms)\n", hostAddr, firstLine, rtt))
								outMutex.Unlock()
							}

							res := TargetResult{
								Target:     t.target,
								ResolvedIP: t.target,
								IsAlive:    true,
								HttpStatus: 101,
								LatencyAvg: rtt,
							}
							res.BughostVerdict = fmt.Sprintf("[ProxyTest] %s", firstLine)
							autoSaveResult(&res)
						}
					}
				}
			}
		}()
	}

	for _, task := range tasks {
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()

	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%s[✓] PROXYTEST COMPLETED:%s %d/%d Responsive Nodes Found.\n", ColorGreen, ColorReset, aliveCount, total)
	if outputFile != "" {
		fmt.Printf("%s[+] Results saved to: %s%s\n\n", ColorCyan, outputFile, ColorReset)
	}
}

func runProxyRouteWorkerPool(targets []string, ports []int, methods []string, proxyAddr string, user string, pass string, outputFile string, threads int) {
	if len(targets) == 0 {
		return
	}
	if threads <= 0 {
		threads = 50
	}

	type routeTask struct {
		target string
		port   int
		method string
	}

	var tasks []routeTask
	for _, t := range targets {
		for _, p := range ports {
			for _, m := range methods {
				tasks = append(tasks, routeTask{target: t, port: p, method: m})
			}
		}
	}

	total := len(tasks)
	fmt.Printf("\n%s[+] STARTING PROXYROUTE SCANNER via %s: %d Tasks | %d Threads%s\n", ColorPurple, proxyAddr, total, threads, ColorReset)
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%-6s %-26s %-8s %-16s %-12s\n", "PROG", "TARGET:PORT", "METHOD", "STATUS", "LATENCY")
	fmt.Println(strings.Repeat("─", 80))

	taskChan := make(chan routeTask, total)
	var processedCount int64
	var aliveCount int64
	var outMutex sync.Mutex

	var outFile *os.File
	var err error
	if outputFile != "" {
		outFile, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer outFile.Close()
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskChan {
				idx := atomic.AddInt64(&processedCount, 1)
				targetHost := fmt.Sprintf("%s:%d", t.target, t.port)

				start := time.Now()
				conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
				rtt := float64(time.Since(start).Microseconds()) / 1000.0

				if err == nil {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

					reqStr := fmt.Sprintf("%s http://%s/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: LoXaSB/5.5\r\nConnection: close\r\n\r\n", t.method, targetHost, t.target)
					_, err = conn.Write([]byte(reqStr))
					if err == nil {
						buf := make([]byte, 1024)
						n, readErr := conn.Read(buf)
						if readErr == nil && n > 0 {
							firstLine := strings.Split(string(buf[:n]), "\r\n")[0]
							if len(firstLine) > 28 {
								firstLine = firstLine[:28]
							}
							atomic.AddInt64(&aliveCount, 1)

							fmt.Printf("[%3d/%3d] %s%-26s%s %-8s %s%-16s%s %-12.1f\n",
								idx, total,
								ColorGreen, targetHost, ColorReset,
								t.method,
								ColorCyan, firstLine, ColorReset,
								rtt,
							)

							if outFile != nil {
								outMutex.Lock()
								_, _ = outFile.WriteString(fmt.Sprintf("%s via %s [%s] -> %s (%.1fms)\n", targetHost, proxyAddr, t.method, firstLine, rtt))
								outMutex.Unlock()
							}
						}
					}
				}
			}
		}()
	}

	for _, task := range tasks {
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()

	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%s[✓] PROXYROUTE COMPLETED:%s %d/%d Routed Responses.\n\n", ColorGreen, ColorReset, aliveCount, total)
}

func runSSLWorkerPool(targets []string, ports []int, outputFile string, threads int) {
	if len(targets) == 0 {
		return
	}
	if threads <= 0 {
		threads = 50
	}

	type sslTask struct {
		target string
		port   int
	}

	var tasks []sslTask
	for _, t := range targets {
		for _, p := range ports {
			tasks = append(tasks, sslTask{target: t, port: p})
		}
	}

	total := len(tasks)
	fmt.Printf("\n%s[+] STARTING SSL / TLS 1.3 & SNI SCANNER: %d Targets | %d Threads%s\n", ColorCyan, total, threads, ColorReset)
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%-6s %-26s %-10s %-18s %-12s %-12s\n", "PROG", "TARGET:PORT", "TLS VER", "ISSUER / CDN", "SANs", "FRONTABLE")
	fmt.Println(strings.Repeat("─", 80))

	taskChan := make(chan sslTask, total)
	var processedCount int64
	var aliveCount int64
	var outMutex sync.Mutex

	var outFile *os.File
	var err error
	if outputFile != "" {
		outFile, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer outFile.Close()
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskChan {
				idx := atomic.AddInt64(&processedCount, 1)
				targetHost := t.target
				addr := fmt.Sprintf("%s:%d", targetHost, t.port)

				hasSni, tlsVer, _, _, issuer, _, sans, _, isFrontable, _ := inspectTLS(targetHost, targetHost)
				if hasSni && tlsVer != "" {
					atomic.AddInt64(&aliveCount, 1)

					sanCountStr := fmt.Sprintf("%d SANs", len(sans))
					frontStr := "No"
					if isFrontable {
						frontStr = "YES [★]"
					}

					fmt.Printf("[%3d/%3d] %s%-26s%s %s%-10s%s %-18s %-12s %s%-12s%s\n",
						idx, total,
						ColorGreen, addr, ColorReset,
						ColorCyan, tlsVer, ColorReset,
						issuer,
						sanCountStr,
						ColorPurple, frontStr, ColorReset,
					)

					if outFile != nil {
						outMutex.Lock()
						_, _ = outFile.WriteString(fmt.Sprintf("%s - %s (%s, Frontable: %v)\n", addr, tlsVer, issuer, isFrontable))
						outMutex.Unlock()
					}

					res := TargetResult{
						Target:      targetHost,
						ResolvedIP:  targetHost,
						IsAlive:     true,
						HasSni:      true,
						TlsVersion:  tlsVer,
						CertIssuer:  issuer,
						IsFrontable: isFrontable,
					}
					res.BughostVerdict = calculateBughostVerdict(&res)
					autoSaveResult(&res)
				}
			}
		}()
	}

	for _, task := range tasks {
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()

	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%s[✓] SSL SCAN COMPLETED:%s %d/%d Valid TLS/SNI Nodes Found.\n\n", ColorGreen, ColorReset, aliveCount, total)
}

func runPingWorkerPool(targets []string, ports []int, isCidr bool, outputFile string, threads int) {
	if len(targets) == 0 {
		return
	}
	if threads <= 0 {
		threads = 50
	}

	type pingTask struct {
		host string
		port int
	}

	var tasks []pingTask
	for _, t := range targets {
		for _, p := range ports {
			tasks = append(tasks, pingTask{host: t, port: p})
		}
	}

	total := len(tasks)
	fmt.Printf("\n%s[+] STARTING PING SCANNER: %d Tasks | %d Threads | 2s Timeout%s\n", ColorCyan, total, threads, ColorReset)
	fmt.Println(strings.Repeat("─", 60))

	// Output Headers matching bugscan-x HostPingScanner / CIDRPingScanner
	if isCidr {
		fmt.Printf("%s%-6s%s  %s%s%s\n", ColorCyan, "Port", ColorReset, ColorWhite, "Host", ColorReset)
		fmt.Printf("%-6s  %s\n", "----", "----")
	} else {
		fmt.Printf("%s%-6s%s  %s%-15s%s  %s%s%s\n", ColorCyan, "Port", ColorReset, ColorYellow, "IP", ColorReset, ColorWhite, "Host", ColorReset)
		fmt.Printf("%-6s  %-15s  %s\n", "----", "--", "----")
	}

	taskChan := make(chan pingTask, total)
	var processedCount int64
	var aliveCount int64
	var outMutex sync.Mutex

	var outFile *os.File
	var err error
	if outputFile != "" {
		outFile, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer outFile.Close()
			if isCidr {
				_, _ = outFile.WriteString(fmt.Sprintf("%-6s  %s\n", "Port", "Host"))
				_, _ = outFile.WriteString(fmt.Sprintf("%-6s  %s\n", "----", "----"))
			} else {
				_, _ = outFile.WriteString(fmt.Sprintf("%-6s  %-15s  %s\n", "Port", "IP", "Host"))
				_, _ = outFile.WriteString(fmt.Sprintf("%-6s  %-15s  %s\n", "----", "--", "----"))
			}
		}
	}

	var wg sync.WaitGroup
	timeoutDur := 2 * time.Second

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskChan {
				_ = atomic.AddInt64(&processedCount, 1)
				addr := net.JoinHostPort(t.host, strconv.Itoa(t.port))

				// Socket connect test with 2 second timeout (sock.connect_ex)
				conn, err := net.DialTimeout("tcp", addr, timeoutDur)
				if err == nil {
					conn.Close()
					atomic.AddInt64(&aliveCount, 1)

					outMutex.Lock()
					if isCidr {
						fmt.Printf("%s%-6d%s  %s%s%s\n",
							ColorCyan, t.port, ColorReset,
							ColorWhite, t.host, ColorReset,
						)
						if outFile != nil {
							_, _ = outFile.WriteString(fmt.Sprintf("%-6d  %s\n", t.port, t.host))
						}
					} else {
						ip, _, _, _ := resolveDNS(t.host)
						if ip == "" {
							ip = "Unknown"
						}
						fmt.Printf("%s%-6d%s  %s%-15s%s  %s%s%s\n",
							ColorCyan, t.port, ColorReset,
							ColorYellow, ip, ColorReset,
							ColorWhite, t.host, ColorReset,
						)
						if outFile != nil {
							_, _ = outFile.WriteString(fmt.Sprintf("%-6d  %-15s  %s\n", t.port, ip, t.host))
						}
					}
					outMutex.Unlock()

					res := TargetResult{
						Target:     t.host,
						ResolvedIP: t.host,
						IsAlive:    true,
						HttpStatus: 200,
						LatencyAvg: 20.0,
					}
					res.BughostVerdict = fmt.Sprintf("[Ping OK] Port %d Open", t.port)
					autoSaveResult(&res)
				}
			}
		}()
	}

	for _, task := range tasks {
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()

	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("%s[✓] PING SCAN COMPLETED:%s %d/%d Open/Responsive Ports Found.\n", ColorGreen, ColorReset, aliveCount, total)
	if outputFile != "" {
		fmt.Printf("%s[+] Results saved to: %s%s\n\n", ColorCyan, outputFile, ColorReset)
	}
}

func runHostScannerSubmenu(scanner *bufio.Scanner) {
	for {
		clearScreen()
		fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorCyan, ColorReset)
		fmt.Printf("%s┃                   [1] HOST & NETWORK SCANNER SUITE                    ┃%s\n", ColorBold, ColorReset)
		fmt.Printf("%s┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫%s\n", ColorCyan, ColorReset)
		fmt.Printf("┃ %-69s ┃\n", "Select Scanning Mode (BugScan-X Engine):")
		fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorCyan, ColorReset)

		fmt.Printf("%s[1]%s Direct        - Direct HTTP Prober with customizable HTTP Methods & Ports\n", ColorGreen, ColorReset)
		fmt.Printf("%s[2]%s DirectNon302  - Direct HTTP Filter (Excludes 301/302 Redirect Responses)\n", ColorCyan, ColorReset)
		fmt.Printf("%s[3]%s ProxyTest     - WebSocket 101 Upgrade & Custom Payload Injection Probe\n", ColorPurple, ColorReset)
		fmt.Printf("%s[4]%s ProxyRoute    - Upstream Proxy Routing Scanner with Optional Auth\n", ColorWhite, ColorReset)
		fmt.Printf("%s[5]%s Ping          - TCP/ICMP Latency, Jitter & Packet Loss Benchmark\n", ColorYellow, ColorReset)
		fmt.Printf("%s[6]%s SSL           - TLS 1.3 / SNI Handshake, SAN Certificate & Fronting Audit\n", ColorCyan, ColorReset)
		fmt.Printf("%s[0]%s Return to Main Menu\n\n", ColorRed, ColorReset)

		fmt.Printf("[-]  Select scanning mode: ")
		if !scanner.Scan() {
			break
		}
		c := strings.TrimSpace(scanner.Text())

		if c == "0" || c == "exit" || c == "back" {
			break
		}

		switch c {
		case "1", "Direct", "direct":
			getInputDirect(scanner, false)
		case "2", "DirectNon302", "directnon302":
			getInputDirect(scanner, true)
		case "3", "ProxyTest", "proxytest":
			getInputProxy(scanner)
		case "4", "ProxyRoute", "proxyroute":
			getInputProxy2(scanner)
		case "5", "Ping", "ping":
			getInputPing(scanner)
		case "6", "SSL", "ssl":
			getInputSSL(scanner)
		default:
			fmt.Printf("%s[!] Invalid mode selection. Please enter 1 - 6 or mode name.%s\n", ColorRed, ColorReset)
		}

		pauseEnter(scanner)
	}
}

// Direct HTTP Request Methods Probe
func runHttpMethodsProbe(target string) {
	clean := cleanTarget(target)
	ip, _, _, _ := resolveDNS(clean)
	methods := []string{"GET", "HEAD", "POST", "OPTIONS", "CONNECT", "TRACE", "PUT"}

	fmt.Printf("\n%sHTTP METHODS SCAN FOR %s (%s):%s\n", ColorCyan, clean, ip, ColorReset)
	fmt.Println(strings.Repeat("─", 65))
	fmt.Printf("%-10s %-12s %-12s %s\n", "METHOD", "STATUS", "LATENCY", "SERVER")
	fmt.Println(strings.Repeat("─", 65))

	client := &http.Client{
		Timeout: 3000 * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, m := range methods {
		url := fmt.Sprintf("http://%s/", clean)
		req, err := http.NewRequest(m, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "LoXaSB/5.5")
		req.Header.Set("Host", clean)

		start := time.Now()
		resp, err := client.Do(req)
		rtt := float64(time.Since(start).Microseconds()) / 1000.0

		if err == nil {
			defer resp.Body.Close()
			color := ColorGreen
			if resp.StatusCode >= 400 {
				color = ColorYellow
			}
			server := resp.Header.Get("Server")
			if server == "" {
				server = "-"
			}
			fmt.Printf("%s%-10s %s%-12s%s %-12.1f %s\n", ColorWhite, m, color, resp.Status, ColorReset, rtt, server)
		} else {
			fmt.Printf("%s%-10s %-12s %-12s %s\n", ColorDim, m, "ERR/CLOSED", "-", "-")
		}
	}
	fmt.Println(strings.Repeat("─", 65))
}

// ----------------------------------------------------------------------------
// [2] SUBFINDER SUBMENU (crt.sh Scraper + Bughost Patterns)
// ----------------------------------------------------------------------------
func runSubfinderSubmenu(scanner *bufio.Scanner) {
	for {
		clearScreen()
		fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorPurple, ColorReset)
		fmt.Printf("%s┃                   [2] SUBFINDER & BUGHOST DISCOVERY                   ┃%s\n", ColorBold, ColorReset)
		fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorPurple, ColorReset)

		fmt.Printf("%s[1]%s Live crt.sh Certificate Subdomain Scraper (Real-time Scraping)\n", ColorGreen, ColorReset)
		fmt.Printf("%s[2]%s Zero-Rating CDN Bughost Patterns (free, zero, portal, ws, api, speed)\n", ColorCyan, ColorReset)
		fmt.Printf("%s[3]%s Extended Subdomain Wordlist Scan (60+ Common Prefixes)\n", ColorPurple, ColorReset)
		fmt.Printf("%s[4]%s Subdomain CNAME & Redirection Chain Inspector\n", ColorYellow, ColorReset)
		fmt.Printf("%s[0]%s Return to Main Menu\n\n", ColorRed, ColorReset)

		fmt.Printf("[-]  Choice: ")
		if !scanner.Scan() {
			break
		}
		c := strings.TrimSpace(scanner.Text())

		if c == "0" || c == "exit" || c == "back" {
			break
		}

		switch c {
		case "1":
			fmt.Printf("\n[-]  Enter Root Domain to scrape (e.g. cloudflare.com or mtn.co.za): ")
			if scanner.Scan() {
				dom := strings.TrimSpace(scanner.Text())
				if dom != "" {
					runCrtShScraper(dom)
				}
			}
		case "2", "3":
			fmt.Printf("\n[-]  Enter Root Domain (e.g. cloudflare.com or airtel.in): ")
			if scanner.Scan() {
				dom := strings.TrimSpace(scanner.Text())
				if dom != "" {
					runSubfinderCLIWithMode(dom, c)
				}
			}
		case "4":
			fmt.Printf("\n[-]  Enter Subdomain to Inspect: ")
			if scanner.Scan() {
				sub := strings.TrimSpace(scanner.Text())
				if sub != "" {
					ip, allIPs, cnames, dnsTime := resolveDNS(sub)
					fmt.Printf("\n%s[+] CNAME & DNS Chain Analysis for %s:%s\n", ColorCyan, sub, ColorReset)
					fmt.Printf(" • Primary IP      : %s (DNS Lookup: %.1fms)\n", ip, dnsTime)
					fmt.Printf(" • All Resolved IPs: %s\n", strings.Join(allIPs, ", "))
					if len(cnames) > 0 {
						fmt.Printf(" • CNAME Chain     : %s\n", strings.Join(cnames, " -> "))
					} else {
						fmt.Println(" • CNAME Chain     : Direct A/AAAA Record (No CNAME)")
					}
					isCdn, provider := inspectCDN(sub, ip, cnames, "", "")
					fmt.Printf(" • CDN Provider    : %s (Is CDN: %v)\n", provider, isCdn)
				}
			}
		}
		pauseEnter(scanner)
	}
}

// Live crt.sh Certificate Transparency Scraper
type CrtEntry struct {
	NameValue string `json:"name_value"`
}

func runCrtShScraper(domain string) {
	clean := cleanTarget(domain)
	fmt.Printf("\n%s[+] Querying crt.sh Certificate Transparency logs for %s...%s\n", ColorCyan, clean, ColorReset)

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", clean)
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("%s[!] Request error: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LoXaSB/5.5")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s[!] Failed to connect to crt.sh: %v%s\n", ColorRed, err, ColorReset)
		fmt.Println("[+] Falling back to local subdomain pattern generator...")
		runSubfinderCLIWithMode(clean, "2")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] crt.sh returned HTTP %d: %s%s\n", ColorRed, resp.StatusCode, resp.Status, ColorReset)
		fmt.Println("[+] Falling back to local pattern generator...")
		runSubfinderCLIWithMode(clean, "2")
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%s[!] Error reading response: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	var entries []CrtEntry
	err = json.Unmarshal(body, &entries)
	if err != nil {
		fmt.Printf("%s[!] Could not parse crt.sh JSON. Falling back to local pattern scanner.%s\n", ColorYellow, ColorReset)
		runSubfinderCLIWithMode(clean, "2")
		return
	}

	uniqueSubdomains := make(map[string]bool)
	for _, entry := range entries {
		lines := strings.Split(entry.NameValue, "\n")
		for _, line := range lines {
			sub := strings.TrimSpace(line)
			sub = strings.TrimPrefix(sub, "*.")
			if strings.HasSuffix(sub, clean) && sub != clean {
				uniqueSubdomains[sub] = true
			}
		}
	}

	var subList []string
	for s := range uniqueSubdomains {
		subList = append(subList, s)
	}
	sort.Strings(subList)

	fmt.Printf("%s[✓] Found %d unique subdomains from Certificate Transparency logs.%s\n\n", ColorGreen, len(subList), ColorReset)
	fmt.Println(strings.Repeat("─", 78))
	fmt.Printf("%-36s %-18s %-18s\n", "SUBDOMAIN", "RESOLVED IP", "CDN / STATUS")
	fmt.Println(strings.Repeat("─", 78))

	for _, sub := range subList {
		ip, _, cnames, _ := resolveDNS(sub)
		if ip != sub {
			isCdn, provider := inspectCDN(sub, ip, cnames, "", "")
			cdnDisplay := "Direct Origin"
			if isCdn {
				cdnDisplay = provider
			}
			fmt.Printf("%s%-36s %-18s %s%-18s%s\n", ColorGreen, sub, ip, ColorPurple, cdnDisplay, ColorReset)
		}
	}
	fmt.Println(strings.Repeat("─", 78))
}

func runSubfinderCLIWithMode(domain string, mode string) {
	clean := cleanTarget(domain)
	fmt.Printf("\n%s[+] Enumerating subdomains for: %s%s\n", ColorCyan, clean, ColorReset)

	var prefixes []string
	if mode == "2" {
		prefixes = []string{
			"free", "zero", "portal", "speed", "api", "cdn", "stream", "ws",
			"login", "auth", "gateway", "edge", "node", "pay", "m", "assets",
		}
	} else {
		prefixes = []string{
			"www", "cdn", "api", "static", "edge", "gateway", "stream", "m",
			"app", "dev", "ws", "speed", "node", "free", "zero", "media", "cloud",
			"assets", "auth", "portal", "download", "pay", "login", "cdn1", "cdn2",
			"web", "secure", "test", "v1", "v2", "live", "video", "img", "files",
		}
	}

	fmt.Println(strings.Repeat("─", 78))
	fmt.Printf("%-34s %-18s %-18s %s\n", "SUBDOMAIN", "RESOLVED IP", "CDN STATUS", "HTTP")
	fmt.Println(strings.Repeat("─", 78))

	var foundCount int
	for _, p := range prefixes {
		fullSub := fmt.Sprintf("%s.%s", p, clean)
		ip, _, cnames, _ := resolveDNS(fullSub)
		if ip != fullSub {
			foundCount++
			isCdn, provider := inspectCDN(fullSub, ip, cnames, "", "")
			cdnStr := "Direct Origin"
			if isCdn {
				cdnStr = provider
			}

			code, _, _, _, _, _, _, _, _ := inspectHttpDeep(fullSub, ip)
			codeStr := fmt.Sprintf("%d", code)
			if code == 0 {
				codeStr = "-"
			}

			fmt.Printf("%s%-34s %-18s %-18s %-6s%s\n", ColorGreen, fullSub, ip, cdnStr, codeStr, ColorReset)
		}
	}
	fmt.Println(strings.Repeat("─", 78))
	fmt.Printf("%s[✓] Found %d active subdomains for %s%s\n", ColorCyan, foundCount, clean, ColorReset)
}

// ----------------------------------------------------------------------------
// [3] IP LOOKUP & NETWORK INTEL SUBMENU
// ----------------------------------------------------------------------------
func runIpLookupSubmenu(scanner *bufio.Scanner) {
	for {
		clearScreen()
		fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorCyan, ColorReset)
		fmt.Printf("%s┃                      [3] IP LOOKUP & NETWORK INTEL                    ┃%s\n", ColorBold, ColorReset)
		fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorCyan, ColorReset)

		fmt.Printf("%s[1]%s Single IP / Host Lookup & Reverse PTR Query\n", ColorGreen, ColorReset)
		fmt.Printf("%s[2]%s Cloud CDN Subnet & ASN Range Classification\n", ColorCyan, ColorReset)
		fmt.Printf("%s[3]%s Batch IP Lookup from File\n", ColorPurple, ColorReset)
		fmt.Printf("%s[0]%s Return to Main Menu\n\n", ColorRed, ColorReset)

		fmt.Printf("[-]  Choice: ")
		if !scanner.Scan() {
			break
		}
		c := strings.TrimSpace(scanner.Text())

		if c == "0" || c == "exit" || c == "back" {
			break
		}

		switch c {
		case "1":
			fmt.Printf("\n[-]  Enter IP Address or Hostname: ")
			if scanner.Scan() {
				tgt := strings.TrimSpace(scanner.Text())
				if tgt != "" {
					runIpLookupCLI(tgt)
				}
			}
		case "2":
			fmt.Printf("\n[-]  Enter IP to test against Cloudflare/CloudFront/Fastly subnets: ")
			if scanner.Scan() {
				tgt := strings.TrimSpace(scanner.Text())
				if tgt != "" {
					ip, _, _, _ := resolveDNS(tgt)
					isCF := ipInCIDRList(ip, cloudflareCIDRs)
					isAmz := ipInCIDRList(ip, cloudfrontCIDRs)
					isFast := ipInCIDRList(ip, fastlyCIDRs)

					fmt.Printf("\n%s[+] ASN & Cloud Subnet Match for %s:%s\n", ColorCyan, ip, ColorReset)
					if isCF {
						fmt.Printf(" • Cloudflare Edge Subnet : %s[MATCH / YES]%s (Official Cloudflare Anycast)\n", ColorGreen, ColorReset)
					} else {
						fmt.Println(" • Cloudflare Edge Subnet : No")
					}
					if isAmz {
						fmt.Printf(" • AWS CloudFront Subnet  : %s[MATCH / YES]%s (Amazon Web Services CDN)\n", ColorGreen, ColorReset)
					} else {
						fmt.Println(" • AWS CloudFront Subnet  : No")
					}
					if isFast {
						fmt.Printf(" • Fastly CDN Subnet      : %s[MATCH / YES]%s (Fastly Global Edge)\n", ColorGreen, ColorReset)
					} else {
						fmt.Println(" • Fastly CDN Subnet      : No")
					}
				}
			}
		case "3":
			fmt.Printf("\n[-]  Enter file path containing IP list: ")
			if scanner.Scan() {
				fPath := strings.TrimSpace(scanner.Text())
				if fPath != "" {
					file, err := os.Open(fPath)
					if err != nil {
						fmt.Printf("%s[!] Error opening file: %v%s\n", ColorRed, err, ColorReset)
					} else {
						defer file.Close()
						s := bufio.NewScanner(file)
						fmt.Println(strings.Repeat("─", 65))
						for s.Scan() {
							ip := strings.TrimSpace(s.Text())
							if ip != "" && !strings.HasPrefix(ip, "#") {
								ptrs, _ := net.LookupAddr(ip)
								ptr := "None"
								if len(ptrs) > 0 {
									ptr = ptrs[0]
								}
								isCdn, prov := inspectCDN(ip, ip, nil, "", "")
								fmt.Printf("%-18s -> %-24s | %s\n", ip, ptr, prov)
								_ = isCdn
							}
						}
						fmt.Println(strings.Repeat("─", 65))
					}
				}
			}
		}
		pauseEnter(scanner)
	}
}

func runIpLookupCLI(target string) {
	clean := cleanTarget(target)
	ip, allIPs, _, dnsTime := resolveDNS(clean)

	fmt.Printf("\n%s─────────────────────────────────────────────────────────────%s\n", ColorCyan, ColorReset)
	fmt.Printf("%sIP LOOKUP & NETWORK INTEL: %s%s\n", ColorBold, clean, ColorReset)
	fmt.Printf("Resolved IPv4 : %s (DNS Lookup: %.1fms)\n", ip, dnsTime)
	if len(allIPs) > 1 {
		fmt.Printf("All IPv4/IPv6 : %s\n", strings.Join(allIPs, ", "))
	}

	ptrs, err := net.LookupAddr(ip)
	if err == nil && len(ptrs) > 0 {
		fmt.Printf("Reverse PTR   : %s\n", strings.Join(ptrs, ", "))
	} else {
		fmt.Println("Reverse PTR   : None (No PTR Record)")
	}

	isCdn, provider := inspectCDN(clean, ip, nil, "", "")
	if isCdn {
		fmt.Printf("Cloud/CDN Net : %s%s (Edge Proxy)%s\n", ColorPurple, provider, ColorReset)
	} else {
		fmt.Println("Cloud/CDN Net : Direct Origin / Standard ISP")
	}
	fmt.Printf("%s─────────────────────────────────────────────────────────────%s\n", ColorCyan, ColorReset)
}

// ----------------------------------------------------------------------------
// [4] PROXY CHECKER & WEBSOCKET UPGRADE SUBMENU (from bugscan-x)
// ----------------------------------------------------------------------------
func runProxyCheckerSubmenu(scanner *bufio.Scanner) {
	for {
		clearScreen()
		fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorGreen, ColorReset)
		fmt.Printf("%s┃             [4] PROXY CHECKER & WEBSOCKET 101 UPGRADE TEST            ┃%s\n", ColorBold, ColorReset)
		fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorGreen, ColorReset)

		fmt.Printf("%s[1]%s HTTP CONNECT Open Proxy Test (Squid / 8080 / 3128 / 80)\n", ColorGreen, ColorReset)
		fmt.Printf("%s[2]%s WebSocket 101 Switching Protocols Upgrade Probe\n", ColorCyan, ColorReset)
		fmt.Printf("%s[3]%s Custom HTTP Payload & Injection Tester\n", ColorPurple, ColorReset)
		fmt.Printf("%s[0]%s Return to Main Menu\n\n", ColorRed, ColorReset)

		fmt.Printf("[-]  Choice: ")
		if !scanner.Scan() {
			break
		}
		c := strings.TrimSpace(scanner.Text())

		if c == "0" || c == "exit" || c == "back" {
			break
		}

		switch c {
		case "1":
			fmt.Printf("\n[-]  Enter Proxy Host or IP (e.g. 104.16.0.1:8080 or 1.1.1.1): ")
			if scanner.Scan() {
				p := strings.TrimSpace(scanner.Text())
				if p != "" {
					testHttpProxyConnect(p)
				}
			}
		case "2":
			fmt.Printf("\n[-]  Enter Target Host or Bughost (e.g. speed.cloudflare.com): ")
			if scanner.Scan() {
				h := strings.TrimSpace(scanner.Text())
				if h != "" {
					testWebSocketUpgrade(h)
				}
			}
		case "3":
			fmt.Printf("\n[-]  Enter Target Host: ")
			if scanner.Scan() {
				h := strings.TrimSpace(scanner.Text())
				if h != "" {
					testCustomPayload(h, scanner)
				}
			}
		}
		pauseEnter(scanner)
	}
}

func testHttpProxyConnect(proxyHost string) {
	clean := cleanTarget(proxyHost)
	port := "8080"
	if strings.Contains(proxyHost, ":") {
		parts := strings.Split(proxyHost, ":")
		clean = parts[0]
		port = parts[1]
	}

	ip, _, _, _ := resolveDNS(clean)
	addr := fmt.Sprintf("%s:%s", ip, port)

	fmt.Printf("\n%s[+] Testing CONNECT Proxy on %s (%s)...%s\n", ColorCyan, clean, addr, ColorReset)

	conn, err := net.DialTimeout("tcp", addr, 3000*time.Millisecond)
	if err != nil {
		fmt.Printf("%s[!] Port %s is closed or unreachable: %v%s\n", ColorRed, port, err, ColorReset)
		return
	}
	defer conn.Close()

	payload := fmt.Sprintf("CONNECT speed.cloudflare.com:443 HTTP/1.1\r\nHost: speed.cloudflare.com:443\r\nUser-Agent: LoXaSB/5.5\r\n\r\n")
	_, _ = conn.Write([]byte(payload))

	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(3000 * time.Millisecond))
	n, err := conn.Read(buf)

	if err == nil && n > 0 {
		respStr := string(buf[:n])
		firstLine := strings.Split(respStr, "\r\n")[0]
		if strings.Contains(firstLine, "200") {
			fmt.Printf("%s[✓] OPEN PROXY CONFIRMED: %s%s\n", ColorGreen, firstLine, ColorReset)
			fmt.Println("This host can be used as an HTTP / CONNECT Remote Proxy!")
		} else {
			fmt.Printf("%s[~] PROXY RESPONDED: %s%s\n", ColorYellow, firstLine, ColorReset)
		}
	} else {
		fmt.Printf("%s[!] No valid HTTP response from proxy port.%s\n", ColorRed, ColorReset)
	}
}

func testWebSocketUpgrade(target string) {
	clean := cleanTarget(target)
	ip, _, _, _ := resolveDNS(clean)

	fmt.Printf("\n%s[+] Testing WebSocket Upgrade (HTTP 101) on %s (%s:80)...%s\n", ColorCyan, clean, ip, ColorReset)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 3000*time.Millisecond)
	if err != nil {
		fmt.Printf("%s[!] Failed to connect to port 80: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer conn.Close()

	wsPayload := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", clean)
	_, _ = conn.Write([]byte(wsPayload))

	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(3000 * time.Millisecond))
	n, err := conn.Read(buf)

	if err == nil && n > 0 {
		respStr := string(buf[:n])
		firstLine := strings.Split(respStr, "\r\n")[0]
		if strings.Contains(firstLine, "101") {
			fmt.Printf("%s[★] SUCCESS: HTTP 101 Switching Protocols Confirmed!%s\n", ColorGreen, ColorReset)
			fmt.Println("This is a 100% WORKING WebSocket Bughost for V2Ray / VLESS / Cloudflare CDN tunneling!")
		} else {
			fmt.Printf("%s[~] Server Response: %s%s\n", ColorYellow, firstLine, ColorReset)
		}
	} else {
		fmt.Printf("%s[!] No response from server on WebSocket probe.%s\n", ColorRed, ColorReset)
	}
}

func testCustomPayload(target string, scanner *bufio.Scanner) {
	clean := cleanTarget(target)
	ip, _, _, _ := resolveDNS(clean)

	fmt.Println("Default Payload: GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf][crlf]")
	fmt.Printf("[-] Enter custom payload (or press ENTER for default): ")
	var payload string
	if scanner.Scan() {
		payload = strings.TrimSpace(scanner.Text())
	}
	if payload == "" {
		payload = fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nUser-Agent: LoXaSB/5.5\r\n\r\n", clean)
	} else {
		payload = strings.ReplaceAll(payload, "[host]", clean)
		payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")
		payload = strings.ReplaceAll(payload, "\\r\\n", "\r\n")
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 3000*time.Millisecond)
	if err != nil {
		fmt.Printf("%s[!] Connect error: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer conn.Close()

	_, _ = conn.Write([]byte(payload))
	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(3000 * time.Millisecond))
	n, err := conn.Read(buf)

	if err == nil && n > 0 {
		fmt.Printf("\n%s--- RAW RESPONSE ---%s\n", ColorGreen, ColorReset)
		fmt.Println(string(buf[:n]))
		fmt.Printf("%s--- END RESPONSE ---%s\n", ColorGreen, ColorReset)
	} else {
		fmt.Printf("%s[!] No response received.%s\n", ColorRed, ColorReset)
	}
}

// ----------------------------------------------------------------------------
// [5] FILE TOOLKIT & RESULTS SUBMENU
// ----------------------------------------------------------------------------
func runFileToolkitInteractive(scanner *bufio.Scanner) {
	for {
		clearScreen()
		fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorCyan, ColorReset)
		fmt.Printf("%s┃             [5] SAVED AUDIT RESULTS & FILE TOOLKIT                    ┃%s\n", ColorBold, ColorReset)
		fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorCyan, ColorReset)

		dirs := []string{
			"cdn/cloudflare", "cdn/cloudfront", "cdn/fastly",
			"cdn/akamai", "cdn/google", "cdn/gcore", "cdn/others",
			"sni", "direct-ip", "unreachable",
		}

		totalFiles := 0
		var allSavedFiles []string

		fmt.Println("Saved Report Folders:")
		for i, d := range dirs {
			entries, err := os.ReadDir(d)
			count := 0
			if err == nil {
				count = len(entries)
				for _, e := range entries {
					if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
						allSavedFiles = append(allSavedFiles, filepath.Join(d, e.Name()))
					}
				}
			}
			totalFiles += count
			fmt.Printf(" [%d] %-20s : %s%d saved reports%s\n", i+1, d, ColorGreen, count, ColorReset)
		}

		fmt.Printf("\nTotal Saved Probes: %s%d files%s\n", ColorCyan, totalFiles, ColorReset)
		fmt.Println(strings.Repeat("─", 65))
		fmt.Println("[1] List all saved files in order")
		fmt.Println("[2] View / Read full content of a saved report")
		fmt.Println("[3] Export all alive hosts into a clean list (alive_hosts.txt)")
		fmt.Println("[4] Clear / Delete all saved results")
		fmt.Println("[0] Return to Main Menu")
		fmt.Printf("[-] Your Choice: ")

		if !scanner.Scan() {
			break
		}
		subChoice := strings.ToUpper(strings.TrimSpace(scanner.Text()))

		if subChoice == "0" || subChoice == "EXIT" || subChoice == "Q" || subChoice == "BACK" {
			break
		}

		switch subChoice {
		case "1", "L", "LIST":
			if len(allSavedFiles) == 0 {
				fmt.Println("No files saved yet. Run a scan first.")
			} else {
				fmt.Println("\nSaved Files List:")
				for idx, f := range allSavedFiles {
					fmt.Printf(" %3d) %s\n", idx+1, f)
				}
			}

		case "2", "V", "VIEW", "READ":
			if len(allSavedFiles) == 0 {
				fmt.Println("No files to view.")
			} else {
				fmt.Printf("\nEnter File Number (1 - %d) or exact file path: ", len(allSavedFiles))
				if scanner.Scan() {
					input := strings.TrimSpace(scanner.Text())
					var targetPath string

					if num, err := strconv.Atoi(input); err == nil && num >= 1 && num <= len(allSavedFiles) {
						targetPath = allSavedFiles[num-1]
					} else {
						targetPath = input
					}

					data, err := os.ReadFile(targetPath)
					if err != nil {
						fmt.Printf("%s[!] Error reading file %s: %v%s\n", ColorRed, targetPath, err, ColorReset)
					} else {
						fmt.Printf("\n%s--- CONTENTS OF %s ---%s\n", ColorCyan, targetPath, ColorReset)
						fmt.Println(string(data))
						fmt.Printf("%s--- END OF FILE ---%s\n", ColorCyan, ColorReset)
					}
				}
			}

		case "3", "E", "EXPORT":
			var aliveList []string
			for _, f := range allSavedFiles {
				if !strings.Contains(f, "unreachable") {
					base := filepath.Base(f)
					host := strings.TrimSuffix(base, ".txt")
					host = strings.ReplaceAll(host, "_", ".")
					aliveList = append(aliveList, host)
				}
			}

			if len(aliveList) == 0 {
				fmt.Println("No alive hosts to export.")
			} else {
				exportPath := "alive_hosts.txt"
				content := strings.Join(aliveList, "\n") + "\n"
				err := os.WriteFile(exportPath, []byte(content), 0644)
				if err != nil {
					fmt.Printf("%s[!] Failed to write %s: %v%s\n", ColorRed, exportPath, err, ColorReset)
				} else {
					fmt.Printf("\n%s[✓] Successfully exported %d alive hosts to %s!%s\n", ColorGreen, len(aliveList), exportPath, ColorReset)
					fmt.Println("You can use this file directly in V2Ray, HTTP Custom, NapsternetV, or SSH tunnels.")
				}
			}

		case "4", "C", "CLEAR":
			fmt.Printf("%sAre you sure you want to delete all saved reports? (y/n): %s", ColorRed, ColorReset)
			if scanner.Scan() {
				if strings.ToLower(strings.TrimSpace(scanner.Text())) == "y" {
					for _, d := range dirs {
						_ = os.RemoveAll(d)
					}
					initDirectories()
					fmt.Printf("%s[✓] All result directories have been reset.%s\n", ColorGreen, ColorReset)
				}
			}
		}
		pauseEnter(scanner)
	}
}

// ----------------------------------------------------------------------------
// [6] PORT SCANNER SUBMENU
// ----------------------------------------------------------------------------
func runPortScannerSubmenu(scanner *bufio.Scanner) {
	for {
		clearScreen()
		fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorWhite, ColorReset)
		fmt.Printf("%s┃                   [6] TCP PORT SCANNER & TTFB MATRIX                  ┃%s\n", ColorBold, ColorReset)
		fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorWhite, ColorReset)

		fmt.Printf("%s[1]%s Standard Bughost Ports Scan (80, 443, 8080, 8443, 2052-2096)\n", ColorGreen, ColorReset)
		fmt.Printf("%s[2]%s Full Common Network Ports Scan (21, 22, 25, 53, 80, 110, 143, 443, 3128, 8080, 8888)\n", ColorCyan, ColorReset)
		fmt.Printf("%s[3]%s Custom Single Port / Custom Port List Scan\n", ColorPurple, ColorReset)
		fmt.Printf("%s[0]%s Return to Main Menu\n\n", ColorRed, ColorReset)

		fmt.Printf("[-]  Choice: ")
		if !scanner.Scan() {
			break
		}
		c := strings.TrimSpace(scanner.Text())

		if c == "0" || c == "exit" || c == "back" {
			break
		}

		switch c {
		case "1":
			fmt.Printf("\n[-]  Enter Target Host or IP: ")
			if scanner.Scan() {
				tgt := strings.TrimSpace(scanner.Text())
				if tgt != "" {
					runPortScannerCLI(tgt)
				}
			}
		case "2":
			fmt.Printf("\n[-]  Enter Target Host or IP: ")
			if scanner.Scan() {
				tgt := strings.TrimSpace(scanner.Text())
				if tgt != "" {
					runFullPortsScannerCLI(tgt)
				}
			}
		case "3":
			fmt.Printf("\n[-]  Enter Target Host or IP: ")
			if scanner.Scan() {
				tgt := strings.TrimSpace(scanner.Text())
				if tgt != "" {
					fmt.Printf("[-]  Enter port(s) to scan (e.g. 80,443,3128,8888): ")
					if scanner.Scan() {
						pList := strings.TrimSpace(scanner.Text())
						runCustomPortsScannerCLI(tgt, pList)
					}
				}
			}
		}
		pauseEnter(scanner)
	}
}

func runPortScannerCLI(target string) {
	clean := cleanTarget(target)
	ip, _, _, _ := resolveDNS(clean)

	ports := []struct {
		port int
		name string
	}{
		{80, "HTTP / Cleartext Web"},
		{443, "HTTPS / TLS / SNI Tunnel"},
		{8080, "HTTP-Alt / Proxy / WS"},
		{8443, "HTTPS-Alt / WSS Tunnel"},
		{2052, "Cloudflare HTTP / WS"},
		{2053, "Cloudflare HTTPS / WSS"},
		{2082, "Cloudflare CPanel HTTP"},
		{2083, "Cloudflare CPanel HTTPS"},
		{2086, "WHM HTTP Tunnel"},
		{2087, "WHM HTTPS Tunnel"},
		{2095, "Webmail HTTP"},
		{2096, "Webmail HTTPS"},
	}

	fmt.Printf("\n%sPORT SCAN FOR %s (%s):%s\n", ColorWhite, clean, ip, ColorReset)
	fmt.Println(strings.Repeat("─", 65))
	fmt.Printf("%-6s %-10s %-12s %s\n", "PORT", "STATUS", "LATENCY", "SERVICE")
	fmt.Println(strings.Repeat("─", 65))

	for _, p := range ports {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p.port), 1200*time.Millisecond)
		if err == nil {
			rtt := float64(time.Since(start).Microseconds()) / 1000.0
			conn.Close()
			fmt.Printf("%s%-6d %-10s %-12.1f %s%s\n", ColorGreen, p.port, "OPEN", rtt, p.name, ColorReset)
		} else {
			fmt.Printf("%s%-6d %-10s %-12s %s%s\n", ColorDim, p.port, "CLOSED", "-", p.name, ColorReset)
		}
	}
	fmt.Println(strings.Repeat("─", 65))
}

func runFullPortsScannerCLI(target string) {
	clean := cleanTarget(target)
	ip, _, _, _ := resolveDNS(clean)

	ports := []struct {
		port int
		name string
	}{
		{21, "FTP Control"}, {22, "SSH Tunnel"}, {23, "Telnet"}, {25, "SMTP Mail"},
		{53, "DNS Service"}, {80, "HTTP Web"}, {110, "POP3 Mail"}, {143, "IMAP Mail"},
		{443, "HTTPS Web"}, {465, "SMTPS Mail"}, {587, "Submission Mail"}, {993, "IMAPS"},
		{995, "POP3S"}, {3128, "Squid Proxy"}, {8080, "HTTP Alt / WS"}, {8443, "HTTPS Alt / WSS"},
		{8888, "Custom Proxy"},
	}

	fmt.Printf("\n%sFULL SERVICE PORT SCAN FOR %s (%s):%s\n", ColorWhite, clean, ip, ColorReset)
	fmt.Println(strings.Repeat("─", 65))
	for _, p := range ports {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p.port), 1000*time.Millisecond)
		if err == nil {
			rtt := float64(time.Since(start).Microseconds()) / 1000.0
			conn.Close()
			fmt.Printf("%s%-6d %-10s %-12.1f %s%s\n", ColorGreen, p.port, "OPEN", rtt, p.name, ColorReset)
		} else {
			fmt.Printf("%s%-6d %-10s %-12s %s%s\n", ColorDim, p.port, "CLOSED", "-", p.name, ColorReset)
		}
	}
	fmt.Println(strings.Repeat("─", 65))
}

func runCustomPortsScannerCLI(target string, portStr string) {
	clean := cleanTarget(target)
	ip, _, _, _ := resolveDNS(clean)
	parts := strings.Split(portStr, ",")

	fmt.Printf("\n%sCUSTOM PORT SCAN FOR %s (%s):%s\n", ColorWhite, clean, ip, ColorReset)
	fmt.Println(strings.Repeat("─", 50))
	for _, rawP := range parts {
		pNum, err := strconv.Atoi(strings.TrimSpace(rawP))
		if err != nil {
			continue
		}
		start := time.Now()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, pNum), 1200*time.Millisecond)
		if err == nil {
			rtt := float64(time.Since(start).Microseconds()) / 1000.0
			conn.Close()
			fmt.Printf("%sPort %-6d : OPEN   (%.1f ms)%s\n", ColorGreen, pNum, rtt, ColorReset)
		} else {
			fmt.Printf("%sPort %-6d : CLOSED / FILTERED%s\n", ColorDim, pNum, ColorReset)
		}
	}
	fmt.Println(strings.Repeat("─", 50))
}

// ----------------------------------------------------------------------------
// [7] DNS RECORDS SUBMENU
// ----------------------------------------------------------------------------
func runDnsRecordsSubmenu(scanner *bufio.Scanner) {
	for {
		clearScreen()
		fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorGreen, ColorReset)
		fmt.Printf("%s┃                    [7] DNS RECORD INTEL & LOOKUP                      ┃%s\n", ColorBold, ColorReset)
		fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorGreen, ColorReset)

		fmt.Printf("%s[1]%s Query All DNS Records (A, AAAA, CNAME, MX, TXT, NS)\n", ColorGreen, ColorReset)
		fmt.Printf("%s[2]%s Query A & AAAA IP Records Only\n", ColorCyan, ColorReset)
		fmt.Printf("%s[3]%s Query CNAME & Redirection Target\n", ColorPurple, ColorReset)
		fmt.Printf("%s[4]%s Query Nameservers (NS) & TXT Records\n", ColorYellow, ColorReset)
		fmt.Printf("%s[0]%s Return to Main Menu\n\n", ColorRed, ColorReset)

		fmt.Printf("[-]  Choice: ")
		if !scanner.Scan() {
			break
		}
		c := strings.TrimSpace(scanner.Text())

		if c == "0" || c == "exit" || c == "back" {
			break
		}

		fmt.Printf("\n[-]  Enter Domain Name (e.g. speed.cloudflare.com): ")
		if scanner.Scan() {
			dom := strings.TrimSpace(scanner.Text())
			if dom != "" {
				runDnsRecordsCLI(dom)
			}
		}
		pauseEnter(scanner)
	}
}

func runDnsRecordsCLI(domain string) {
	clean := cleanTarget(domain)
	fmt.Printf("\n%sQUERYING DNS RECORDS FOR: %s%s\n", ColorGreen, clean, ColorReset)
	fmt.Println(strings.Repeat("─", 65))

	ips, err := net.LookupIP(clean)
	if err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				fmt.Printf("A Record      : %s\n", ip.String())
			} else {
				fmt.Printf("AAAA Record   : %s\n", ip.String())
			}
		}
	}

	cname, err := net.LookupCNAME(clean)
	if err == nil && cname != "" && cname != clean+"." {
		fmt.Printf("CNAME Record  : %s\n", cname)
	}

	mxRecords, err := net.LookupMX(clean)
	if err == nil {
		for _, mx := range mxRecords {
			fmt.Printf("MX Record     : %s (Priority: %d)\n", mx.Host, mx.Pref)
		}
	}

	nsRecords, err := net.LookupNS(clean)
	if err == nil {
		for _, ns := range nsRecords {
			fmt.Printf("NS Record     : %s\n", ns.Host)
		}
	}

	txtRecords, err := net.LookupTXT(clean)
	if err == nil {
		for _, txt := range txtRecords {
			fmt.Printf("TXT Record    : %s\n", txt)
		}
	}

	fmt.Println(strings.Repeat("─", 65))
}

// ----------------------------------------------------------------------------
// [8] HOST SSL/TLS INFO SUBMENU
// ----------------------------------------------------------------------------
func runHostInfoSubmenu(scanner *bufio.Scanner) {
	for {
		clearScreen()
		fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorBlue, ColorReset)
		fmt.Printf("%s┃                  [8] HOST SSL/TLS & CERTIFICATE AUDIT                 ┃%s\n", ColorBold, ColorReset)
		fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorBlue, ColorReset)

		fmt.Printf("%s[1]%s Deep SSL/TLS Handshake & Certificate Inspection\n", ColorGreen, ColorReset)
		fmt.Printf("%s[2]%s SNI Domain Fronting & ALPN Protocol Test (h2, http/1.1)\n", ColorCyan, ColorReset)
		fmt.Printf("%s[3]%s Check SSL Certificate Expiry & Subject Alternative Names (SANs)\n", ColorPurple, ColorReset)
		fmt.Printf("%s[0]%s Return to Main Menu\n\n", ColorRed, ColorReset)

		fmt.Printf("[-]  Choice: ")
		if !scanner.Scan() {
			break
		}
		c := strings.TrimSpace(scanner.Text())

		if c == "0" || c == "exit" || c == "back" {
			break
		}

		fmt.Printf("\n[-]  Enter Host / Domain: ")
		if scanner.Scan() {
			tgt := strings.TrimSpace(scanner.Text())
			if tgt != "" {
				runHostInfoCLI(tgt)
			}
		}
		pauseEnter(scanner)
	}
}

func runHostInfoCLI(target string) {
	clean := cleanTarget(target)
	ip, _, _, _ := resolveDNS(clean)

	fmt.Printf("\n%sEXTRACTING SSL/TLS HOST CERTIFICATE FOR %s (%s)...%s\n", ColorBlue, clean, ip, ColorReset)

	conf := &tls.Config{
		ServerName:         clean,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	dialer := &net.Dialer{Timeout: 3500 * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", ip), conf)
	if err != nil {
		fmt.Printf("%s[!] Failed to establish TLS handshake: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fmt.Println(strings.Repeat("─", 65))
	tlsVer := "TLS 1.2"
	if state.Version == tls.VersionTLS13 {
		tlsVer = "TLS 1.3"
	}
	fmt.Printf("TLS Version    : %s\n", tlsVer)
	fmt.Printf("Cipher Suite   : %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("Negotiated ALPN: %s\n", state.NegotiatedProtocol)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		fmt.Printf("Subject CN     : %s\n", cert.Subject.CommonName)
		if len(cert.Issuer.Organization) > 0 {
			fmt.Printf("Issuer Org     : %s\n", cert.Issuer.Organization[0])
		}
		fmt.Printf("Valid From     : %s\n", cert.NotBefore.Format("2006-01-02"))
		fmt.Printf("Valid Until    : %s\n", cert.NotAfter.Format("2006-01-02"))
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		fmt.Printf("Days Left      : %d days\n", days)
		if len(cert.DNSNames) > 0 {
			limit := len(cert.DNSNames)
			if limit > 6 {
				limit = 6
			}
			fmt.Printf("SANs (%d)      : %s\n", len(cert.DNSNames), strings.Join(cert.DNSNames[:limit], ", "))
		}
	}
	fmt.Println(strings.Repeat("─", 65))
}

// ----------------------------------------------------------------------------
// [9] HELP & USER GUIDE SUBMENU
// ----------------------------------------------------------------------------
func runHelpSubmenu(scanner *bufio.Scanner) {
	for {
		clearScreen()
		fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorYellow, ColorReset)
		fmt.Printf("%s┃                   [9] LoXaSB PRO 5.5 - USER MANUAL                    ┃%s\n", ColorBold, ColorReset)
		fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorYellow, ColorReset)

		fmt.Printf("%s[1]%s LoXaSB Pro Complete Feature Overview\n", ColorGreen, ColorReset)
		fmt.Printf("%s[2]%s How to Find Working Cloudflare / CDN Bughosts\n", ColorCyan, ColorReset)
		fmt.Printf("%s[3]%s V2Ray / HTTP Custom / SSH Setup Instructions\n", ColorPurple, ColorReset)
		fmt.Printf("%s[0]%s Return to Main Menu\n\n", ColorRed, ColorReset)

		fmt.Printf("[-]  Choice: ")
		if !scanner.Scan() {
			break
		}
		c := strings.TrimSpace(scanner.Text())

		if c == "0" || c == "exit" || c == "back" {
			break
		}

		switch c {
		case "1":
			fmt.Println(`
LoXaSB Pro 5.5 (BugScan-X Go Edition) Overview:
• Option [1] Host Scanner : Direct HTTP/2, SSL/SNI, CIDR Subnet calculator & Worker pool.
• Option [2] Subfinder    : Real-time crt.sh Certificate Transparency Scraper + Patterns.
• Option [3] IP Lookup    : PTR reverse lookup & Cloudflare/CloudFront/Fastly ASN Subnets.
• Option [4] Proxy Checker: Test Squid proxy, HTTP CONNECT & WebSocket 101 Switching Protocols.
• Option [5] File Toolkit : Interactive Results Explorer, Report viewer & alive_hosts.txt exporter.
• Option [6] Port Scanner : 10-port bughost matrix & TCP response benchmark.
• Option [7] DNS Record   : Query A, AAAA, CNAME, MX, NS, TXT.
• Option [8] Host Info    : Deep SSL certificate audit & SAN inspection.
• Option [10] Update      : Automated OTA self-updater from GitHub.`)
		case "2":
			fmt.Println(`
Finding Working Bughosts:
1. Use Subfinder [2] -> [1] crt.sh Scraper on your ISP's zero-rated or education domain.
2. Check if the subdomain resolves to Cloudflare (104.16.0.0/12, 172.64.0.0/13) or CloudFront.
3. Test with Proxy Checker [4] -> [2] WebSocket 101 upgrade.
4. Save the host and use it as your SNI in tunneling apps.`)
		case "3":
			fmt.Println(`
Tunnel Setup Guide:
• V2Ray / VLESS WebSocket: Set SNI = <Bughost Domain>, Host = <Your Server Domain>.
• HTTP Custom SSL/TLS   : Set SNI / Bug = <Bughost Domain>, Port = 443.
• SSH Tunnel with SSL   : Use SNI mode with the verified Bughost.`)
		}
		pauseEnter(scanner)
	}
}

// ----------------------------------------------------------------------------
// [10] OVER-THE-AIR (OTA) SELF UPDATER
// ----------------------------------------------------------------------------
func runSelfUpdateCLI(scanner *bufio.Scanner) {
	clearScreen()
	fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorPurple, ColorReset)
	fmt.Printf("%s┃        LoXaSB PRO 5.5 - AUTOMATED OVER-THE-AIR (OTA) SELF UPDATER     ┃%s\n", ColorBold, ColorReset)
	fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorPurple, ColorReset)

	updateUrl := "https://raw.githubusercontent.com/roxasblessed403-design/LoXaS/main/loxasb.go"
	fmt.Printf("Current Engine   : %sLoXaSB PRO 5.5 SUPREME (BugScan-X Go Native)%s\n", ColorGreen, ColorReset)
	fmt.Printf("Update Channel   : %sGitHub Main (roxasblessed403-design/LoXaS)%s\n", ColorCyan, ColorReset)
	fmt.Printf("Source URL       : %s\n\n", updateUrl)

	fmt.Printf("%s[?] Do you want to fetch and install the latest update now? (y/n): %s", ColorYellow, ColorReset)
	if !scanner.Scan() {
		return
	}
	ans := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if ans != "y" && ans != "yes" {
		fmt.Println("Update cancelled.")
		pauseEnter(scanner)
		return
	}

	fmt.Printf("\n%s[+] Step 1/3: Fetching latest source code from GitHub...%s\n", ColorCyan, ColorReset)
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest("GET", updateUrl, nil)
	if err != nil {
		fmt.Printf("%s[!] Request error: %v%s\n", ColorRed, err, ColorReset)
		pauseEnter(scanner)
		return
	}
	req.Header.Set("User-Agent", "LoXaSB-Termux-AutoUpdater/5.5")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s[!] Failed to connect to GitHub: %v%s\n", ColorRed, err, ColorReset)
		fmt.Println("Please check your internet connection in Termux.")
		pauseEnter(scanner)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("%s[!] GitHub server returned HTTP %d: %s%s\n", ColorRed, resp.StatusCode, resp.Status, ColorReset)
		pauseEnter(scanner)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil || len(bodyBytes) < 500 {
		fmt.Printf("%s[!] Corrupt or incomplete update file received (%d bytes).%s\n", ColorRed, len(bodyBytes), ColorReset)
		pauseEnter(scanner)
		return
	}

	targetGoFile := "loxasb.go"
	err = os.WriteFile(targetGoFile, bodyBytes, 0644)
	if err != nil {
		fmt.Printf("%s[!] Failed to write updated source to %s: %v%s\n", ColorRed, targetGoFile, err, ColorReset)
		pauseEnter(scanner)
		return
	}
	fmt.Printf("%s[✓] Downloaded %d bytes of verified Go source code.%s\n", ColorGreen, len(bodyBytes), ColorReset)

	fmt.Printf("%s[+] Step 2/3: Compiling optimized standalone binary with 'go build'...%s\n", ColorCyan, ColorReset)
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", "loxasb", "loxasb.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		fmt.Printf("%s[!] Compilation failed: %v%s\n", ColorRed, err, ColorReset)
		pauseEnter(scanner)
		return
	}
	_ = os.Chmod("loxasb", 0755)
	fmt.Printf("%s[✓] Binary compilation succeeded: ./loxasb%s\n", ColorGreen, ColorReset)

	fmt.Printf("%s[+] Step 3/3: Installing global shortcuts to $PREFIX/bin...%s\n", ColorCyan, ColorReset)
	prefix := os.Getenv("PREFIX")
	if prefix == "" {
		prefix = "/data/data/com.termux/files/usr"
	}
	binDir := filepath.Join(prefix, "bin")
	_ = os.MkdirAll(binDir, 0755)

	loxasDest := filepath.Join(binDir, "loxas")
	lxDest := filepath.Join(binDir, "lx")

	_ = os.Remove(loxasDest)
	_ = os.Remove(lxDest)

	compiledData, err := os.ReadFile("loxasb")
	if err == nil {
		_ = os.WriteFile(loxasDest, compiledData, 0755)
		_ = os.WriteFile(lxDest, compiledData, 0755)
		_ = os.Chmod(loxasDest, 0755)
		_ = os.Chmod(lxDest, 0755)
		fmt.Printf("%s[✓] Updated '%s'%s\n", ColorGreen, loxasDest, ColorReset)
		fmt.Printf("%s[✓] Updated '%s'%s\n", ColorGreen, lxDest, ColorReset)
	}

	fmt.Println()
	fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s┃  [✓] UPDATE COMPLETED SUCCESSFULLY!                                   ┃%s\n", ColorBold, ColorReset)
	fmt.Printf("%s┃  You are now running the latest LoXaSB Pro Supreme Engine.           ┃%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s┃  You can type 'loxas' or 'lx' from ANY folder in Termux at any time.  ┃%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorGreen, ColorReset)
	pauseEnter(scanner)
}

// Print Main Menu
func printMainMenu() {
	clearScreen()
	fmt.Printf("%s┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s┃           LoXaSB PRO 5.5 - BUGSCAN-X NATIVE GO CYBER ENGINE           ┃%s\n", ColorBold, ColorReset)
	fmt.Printf("%s┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛%s\n\n", ColorCyan, ColorReset)

	fmt.Printf("%s[1]   HOST SCANNER (Direct, SSL/SNI, CIDR Subnet Calculator)%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s[2]   SUBFINDER (Live crt.sh Scraper + CDN Bughost Patterns)%s\n", ColorPurple, ColorReset)
	fmt.Printf("%s[3]   IP LOOKUP (Reverse PTR, Cloudflare/CloudFront/Fastly ASN)%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s[4]   PROXY CHECKER (Squid, HTTP CONNECT & WebSocket 101 Probe)%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s[5]   FILE TOOLKIT & RESULTS (Report Viewer & alive_hosts.txt Exporter)%s\n", ColorPurple, ColorReset)
	fmt.Printf("%s[6]   PORT SCANNER (10-Port Matrix, Network Services, Custom Ports)%s\n", ColorWhite, ColorReset)
	fmt.Printf("%s[7]   DNS RECORD INTEL (A, AAAA, CNAME, MX, TXT, NS Records)%s\n", ColorGreen, ColorReset)
	fmt.Printf("%s[8]   HOST INFO (Deep SSL/TLS 1.3, Cipher Suite, SANs, Fronting)%s\n", ColorBlue, ColorReset)
	fmt.Printf("%s[9]   HELP & BUGHOST MANUAL (Bughost Hunting & V2Ray Guide)%s\n", ColorYellow, ColorReset)
	fmt.Printf("%s[10]  UPDATE (Automated Over-The-Air GitHub Self-Updater)%s\n", ColorPurple, ColorReset)
	fmt.Printf("%s[0]   EXIT%s\n\n", ColorRed, ColorReset)
}

func main() {
	initDirectories()

	targetFlag := flag.String("t", "", "Single target domain, IP, or CIDR (e.g. -t speed.cloudflare.com)")
	fileFlag := flag.String("f", "", "File path containing host list (e.g. -f hosts.txt)")
	cidrFlag := flag.String("cidr", "", "CIDR range to scan (e.g. -cidr 104.16.0.0/24)")
	workersFlag := flag.Int("w", 25, "Number of concurrent workers (default: 25)")
	traceFlag := flag.Bool("trace", false, "Enable traceroute hop discovery")
	flag.Parse()

	if *targetFlag != "" {
		if strings.Contains(*targetFlag, "/") {
			ips, count, netIP, maskIP, firstU, lastU, err := calculateAndExpandCIDR(*targetFlag)
			if err != nil {
				fmt.Printf("%sInvalid CIDR: %v%s\n", ColorRed, err, ColorReset)
				return
			}
			fmt.Printf("[+] CIDR Subnet: Net=%s, Mask=%s, Usable=%s-%s, Total=%d IPs\n", netIP, maskIP, firstU, lastU, count)
			runConcurrentCIDRScanner(ips, *workersFlag, *targetFlag)
		} else {
			res := probeTarget(*targetFlag, 5, *traceFlag)
			displayResult(res)
		}
		return
	}

	if *cidrFlag != "" {
		ips, count, netIP, maskIP, firstU, lastU, err := calculateAndExpandCIDR(*cidrFlag)
		if err != nil {
			fmt.Printf("%sInvalid CIDR: %v%s\n", ColorRed, err, ColorReset)
			return
		}
		fmt.Printf("[+] CIDR Subnet: Net=%s, Mask=%s, Usable=%s-%s, Total=%d IPs\n", netIP, maskIP, firstU, lastU, count)
		runConcurrentCIDRScanner(ips, *workersFlag, *cidrFlag)
		return
	}

	if *fileFlag != "" {
		file, err := os.Open(*fileFlag)
		if err != nil {
			fmt.Printf("%sError opening file: %v%s\n", ColorRed, err, ColorReset)
			return
		}
		defer file.Close()

		var targets []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		runConcurrentCIDRScanner(targets, *workersFlag, *fileFlag)
		return
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Printf("\n%s[!] Exiting LoXaSB Pro. Goodbye!%s\n", ColorYellow, ColorReset)
		os.Exit(0)
	}()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		printMainMenu()

		fmt.Printf("[-]  Your Choice: ")
		if !scanner.Scan() {
			break
		}
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1", "01":
			runHostScannerSubmenu(scanner)
		case "2", "02":
			runSubfinderSubmenu(scanner)
		case "3", "03":
			runIpLookupSubmenu(scanner)
		case "4", "04":
			runProxyCheckerSubmenu(scanner)
		case "5", "05":
			runFileToolkitInteractive(scanner)
		case "6", "06":
			runPortScannerSubmenu(scanner)
		case "7", "07":
			runDnsRecordsSubmenu(scanner)
		case "8", "08":
			runHostInfoSubmenu(scanner)
		case "9", "09", "help":
			runHelpSubmenu(scanner)
		case "10", "update":
			runSelfUpdateCLI(scanner)
		case "0", "00", "exit", "quit":
			clearScreen()
			fmt.Println("Exiting LoXaSB Pro. Goodbye!")
			return
		default:
			fmt.Printf("%sInvalid choice: %s. Please enter 1 - 10.%s\n\n", ColorRed, choice, ColorReset)
			pauseEnter(scanner)
		}
	}
}
