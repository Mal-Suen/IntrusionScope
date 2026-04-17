// Package collector provides forensic artifact collection capabilities
// This file contains network-related collectors
package collector

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// NetworkConnectionsCollector collects active network connections
type NetworkConnectionsCollector struct{}

func (c *NetworkConnectionsCollector) Name() string {
	return "network.connections"
}

func (c *NetworkConnectionsCollector) Description() string {
	return "Collects active network connections (TCP/UDP)"
}

func (c *NetworkConnectionsCollector) Platform() string {
	return "all"
}

func (c *NetworkConnectionsCollector) IsAvailable() bool {
	return true
}

func (c *NetworkConnectionsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record
	var err error

	if runtime.GOOS == "windows" {
		records, err = c.collectWindows(ctx, opts)
	} else {
		records, err = c.collectLinux(ctx, opts)
	}

	if err != nil {
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   false,
			Error:     err.Error(),
		}, err
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

func (c *NetworkConnectionsCollector) collectLinux(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// Read TCP connections
	tcpRecords, err := c.readProcNet("/proc/net/tcp", "tcp")
	if err == nil {
		records = append(records, tcpRecords...)
	}

	// Read TCP6 connections
	tcp6Records, err := c.readProcNet("/proc/net/tcp6", "tcp6")
	if err == nil {
		records = append(records, tcp6Records...)
	}

	// Read UDP connections
	udpRecords, err := c.readProcNet("/proc/net/udp", "udp")
	if err == nil {
		records = append(records, udpRecords...)
	}

	// Read UDP6 connections
	udp6Records, err := c.readProcNet("/proc/net/udp6", "udp6")
	if err == nil {
		records = append(records, udp6Records...)
	}

	// Map PIDs to connections
	c.mapPidsToConnections(records)

	return records, nil
}

func (c *NetworkConnectionsCollector) readProcNet(path, proto string) ([]Record, error) {
	var records []Record

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if lineNum == 1 { // Skip header
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse local address:port
		localAddr, localPort := c.parseHexAddr(fields[1])
		remoteAddr, remotePort := c.parseHexAddr(fields[2])

		// Parse state (for TCP)
		state := ""
		if strings.HasPrefix(proto, "tcp") {
			state = c.tcpStateToString(fields[3])
		}

		// Parse UID
		uid, _ := strconv.Atoi(fields[7])

		// Parse inode
		inode, _ := strconv.Atoi(fields[9])

		record := Record{
			Timestamp: time.Now(),
			Source:    "procfs_net",
			Data: map[string]interface{}{
				"proto":       proto,
				"local_ip":    localAddr,
				"local_port":  localPort,
				"remote_ip":   remoteAddr,
				"remote_port": remotePort,
				"state":       state,
				"uid":         uid,
				"inode":       inode,
			},
		}
		records = append(records, record)
	}

	return records, nil
}

func (c *NetworkConnectionsCollector) parseHexAddr(hexAddr string) (string, int) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0
	}

	// Parse port
	port, _ := strconv.ParseInt(parts[1], 16, 32)

	// Parse IP address (little-endian for IPv4)
	ipHex := parts[0]
	if len(ipHex) == 8 {
		// IPv4
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			b, _ := strconv.ParseInt(ipHex[6-2*i:8-2*i], 16, 32)
			ip[i] = byte(b)
		}
		return ip.String(), int(port)
	} else if len(ipHex) == 32 {
		// IPv6
		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			b, _ := strconv.ParseInt(ipHex[30-2*i:32-2*i], 16, 32)
			ip[i] = byte(b)
		}
		return ip.String(), int(port)
	}

	return "", int(port)
}

func (c *NetworkConnectionsCollector) tcpStateToString(stateHex string) string {
	state, _ := strconv.ParseInt(stateHex, 16, 32)
	states := map[int64]string{
		0x01: "ESTABLISHED",
		0x02: "SYN_SENT",
		0x03: "SYN_RECV",
		0x04: "FIN_WAIT1",
		0x05: "FIN_WAIT2",
		0x06: "TIME_WAIT",
		0x07: "CLOSE",
		0x08: "CLOSE_WAIT",
		0x09: "LAST_ACK",
		0x0A: "LISTEN",
		0x0B: "CLOSING",
		0x0C: "NEW_SYN_RECV",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

// parseAddress parses an address in the format "IP:port" or "[IPv6]:port"
// Returns the IP and port, or empty IP and 0 port if parsing fails
func parseAddress(addr string) (string, int) {
	if addr == "" || addr == "*" {
		return "", 0
	}

	// Check for IPv6 format [address]:port
	if strings.HasPrefix(addr, "[") {
		// Find closing bracket
		closeBracket := strings.Index(addr, "]")
		if closeBracket == -1 {
			return "", 0
		}
		ip := addr[1:closeBracket]
		// Port should follow after "]:"
		if closeBracket+2 < len(addr) && addr[closeBracket+1] == ':' {
			port, err := strconv.Atoi(addr[closeBracket+2:])
			if err != nil {
				return ip, 0
			}
			return ip, port
		}
		return ip, 0
	}

	// IPv4 format: find last colon (port separator)
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr, 0
	}
	ip := addr[:lastColon]
	port, err := strconv.Atoi(addr[lastColon+1:])
	if err != nil {
		return ip, 0
	}
	return ip, port
}

// parseAddressWithValidation parses and validates an IP address
func parseAddressWithValidation(addr string) (string, int, error) {
	ip, port := parseAddress(addr)
	if port == 0 {
		return "", 0, fmt.Errorf("invalid address format: %s", addr)
	}
	// Validate IP
	if ip != "" && ip != "*" {
		if net.ParseIP(ip) == nil {
			return "", 0, fmt.Errorf("invalid IP address: %s", ip)
		}
	}
	return ip, port, nil
}

func (c *NetworkConnectionsCollector) mapPidsToConnections(records []Record) {
	// Read /proc/[pid]/fd to find socket inodes
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	inodeToPid := make(map[int]int)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdPath := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			linkPath := fdPath + "/" + fd.Name()
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			// Parse socket:[inode]
			if strings.HasPrefix(target, "socket:[") {
				inodeStr := strings.TrimPrefix(target, "socket:[")
				inodeStr = strings.TrimSuffix(inodeStr, "]")
				inode, _ := strconv.Atoi(inodeStr)
				inodeToPid[inode] = pid
			}
		}
	}

	// Map PIDs to records
	for i := range records {
		inode, ok := records[i].Data["inode"].(int)
		if !ok {
			continue
		}
		if pid, found := inodeToPid[inode]; found {
			records[i].Data["pid"] = pid
		}
	}
}

func (c *NetworkConnectionsCollector) collectWindows(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// Use netstat command
	cmd := exec.CommandContext(ctx, "netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run netstat: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and header
		if line == "" || strings.HasPrefix(line, "Active") || strings.HasPrefix(line, "Proto") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		proto := strings.ToLower(fields[0])

		// Parse local address (handle IPv6 format [address]:port)
		localIP, localPort := parseAddress(fields[1])
		if localPort == 0 {
			continue
		}

		// Parse remote address
		remoteIP := ""
		remotePort := 0
		if fields[2] != "*" && fields[2] != "" {
			remoteIP, remotePort = parseAddress(fields[2])
		}

		// Parse state
		state := ""
		pid := 0
		if proto == "tcp" {
			if len(fields) >= 5 {
				state = fields[3]
				pid, _ = strconv.Atoi(fields[4])
			}
		} else {
			// UDP doesn't have state
			if len(fields) >= 4 {
				pid, _ = strconv.Atoi(fields[3])
			}
		}

		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "netstat",
			Data: map[string]interface{}{
				"proto":       proto,
				"local_ip":    localIP,
				"local_port":  localPort,
				"remote_ip":   remoteIP,
				"remote_port": remotePort,
				"state":       state,
				"pid":         pid,
			},
		})
	}

	return records, nil
}

// ListeningPortsCollector collects listening ports
type ListeningPortsCollector struct{}

func (c *ListeningPortsCollector) Name() string {
	return "network.listening_ports"
}

func (c *ListeningPortsCollector) Description() string {
	return "Collects all listening ports"
}

func (c *ListeningPortsCollector) Platform() string {
	return "all"
}

func (c *ListeningPortsCollector) IsAvailable() bool {
	return true
}

func (c *ListeningPortsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()

	// Use NetworkConnectionsCollector and filter
	ncc := &NetworkConnectionsCollector{}
	allConns, err := ncc.Collect(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Filter for listening ports
	var records []Record
	for _, r := range allConns.Records {
		state, _ := r.Data["state"].(string)
		if state == "LISTEN" {
			records = append(records, r)
		}
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

// DNSCacheCollector collects DNS cache entries
type DNSCacheCollector struct{}

func (c *DNSCacheCollector) Name() string {
	return "network.dns_cache"
}

func (c *DNSCacheCollector) Description() string {
	return "Collects DNS cache entries"
}

func (c *DNSCacheCollector) Platform() string {
	return "all"
}

func (c *DNSCacheCollector) IsAvailable() bool {
	return true
}

func (c *DNSCacheCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record
	var err error

	if runtime.GOOS == "windows" {
		records, err = c.collectWindows(ctx, opts)
	} else {
		// Linux doesn't have a standard DNS cache
		// Check systemd-resolved if available
		records, err = c.collectLinux(ctx, opts)
	}

	if err != nil {
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   false,
			Error:     err.Error(),
		}, err
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

func (c *DNSCacheCollector) collectWindows(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// Use ipconfig /displaydns
	cmd := exec.CommandContext(ctx, "ipconfig", "/displaydns")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run ipconfig: %w", err)
	}

	// Parse output
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var currentRecord map[string]interface{}

	recordNameRegex := regexp.MustCompile(`^\s*Record Name\s*:\s*(.+)$`)
	recordTypeRegex := regexp.MustCompile(`^\s*A \(Host\) Record\s*:\s*(.+)$`)
	recordTTLRegex := regexp.MustCompile(`^\s*Time To Live\s*:\s*(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()

		if matches := recordNameRegex.FindStringSubmatch(line); matches != nil {
			if currentRecord != nil {
				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "ipconfig",
					Data:      currentRecord,
				})
			}
			currentRecord = map[string]interface{}{
				"name": matches[1],
			}
		} else if currentRecord != nil {
			if matches := recordTypeRegex.FindStringSubmatch(line); matches != nil {
				currentRecord["ip"] = matches[1]
			} else if matches := recordTTLRegex.FindStringSubmatch(line); matches != nil {
				currentRecord["ttl"] = matches[1]
			}
		}
	}

	// Add last record
	if currentRecord != nil {
		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "ipconfig",
			Data:      currentRecord,
		})
	}

	return records, nil
}

func (c *DNSCacheCollector) collectLinux(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// Try systemd-resolve --statistics
	cmd := exec.CommandContext(ctx, "systemd-resolve", "--statistics")
	if output, err := cmd.Output(); err == nil {
		// Parse DNS cache statistics
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Current Cache Size") {
				parts := strings.Fields(line)
				if len(parts) >= 4 {
					records = append(records, Record{
						Timestamp: time.Now(),
						Source:    "systemd-resolve",
						Data: map[string]interface{}{
							"cache_size": parts[3],
						},
					})
				}
			}
		}
	}

	// Try resolvectl statistics (newer systems)
	cmd = exec.CommandContext(ctx, "resolvectl", "statistics")
	if output, err := cmd.Output(); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Cache") {
				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "resolvectl",
					Data: map[string]interface{}{
						"info": line,
					},
				})
			}
		}
	}

	return records, nil
}

// ArpCacheCollector collects ARP cache entries
type ArpCacheCollector struct{}

func (c *ArpCacheCollector) Name() string {
	return "network.arp_cache"
}

func (c *ArpCacheCollector) Description() string {
	return "Collects ARP cache entries"
}

func (c *ArpCacheCollector) Platform() string {
	return "all"
}

func (c *ArpCacheCollector) IsAvailable() bool {
	return true
}

func (c *ArpCacheCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record
	var err error

	if runtime.GOOS == "windows" {
		records, err = c.collectWindows(ctx, opts)
	} else {
		records, err = c.collectLinux(ctx, opts)
	}

	if err != nil {
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   false,
			Error:     err.Error(),
		}, err
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

func (c *ArpCacheCollector) collectLinux(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// Read /proc/net/arp
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/net/arp: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if lineNum == 1 { // Skip header
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "procfs_arp",
			Data: map[string]interface{}{
				"ip_address":  fields[0],
				"hw_type":     fields[1],
				"flags":       fields[2],
				"hw_address":  fields[3],
				"mask":        fields[4],
				"device":      fields[5],
			},
		})
	}

	return records, nil
}

func (c *ArpCacheCollector) collectWindows(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	cmd := exec.CommandContext(ctx, "arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run arp: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and interface headers
		if line == "" || strings.HasPrefix(line, "Interface") || strings.HasPrefix(line, "  Interface") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			ip := fields[0]
			mac := fields[1]
			itype := fields[2]

			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "arp",
				Data: map[string]interface{}{
					"ip_address": ip,
					"hw_address": mac,
					"type":       itype,
				},
			})
		}
	}

	return records, nil
}

// HostsFileCollector collects hosts file entries
type HostsFileCollector struct{}

func (c *HostsFileCollector) Name() string {
	return "network.hosts"
}

func (c *HostsFileCollector) Description() string {
	return "Collects hosts file entries"
}

func (c *HostsFileCollector) Platform() string {
	return "all"
}

func (c *HostsFileCollector) IsAvailable() bool {
	return true
}

func (c *HostsFileCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	var hostsPath string
	if runtime.GOOS == "windows" {
		hostsPath = os.Getenv("SystemRoot") + "\\System32\\drivers\\etc\\hosts"
	} else {
		hostsPath = "/etc/hosts"
	}

	file, err := os.Open(hostsPath)
	if err != nil {
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   false,
			Error:     fmt.Sprintf("failed to open hosts file: %v", err),
		}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNum++

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			hostnames := fields[1:]

			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "hosts_file",
				Data: map[string]interface{}{
					"ip":        ip,
					"hostnames": hostnames,
					"line":      lineNum,
				},
			})
		}
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}
