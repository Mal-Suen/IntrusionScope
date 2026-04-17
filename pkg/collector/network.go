// Package collector 提供取证工件收集能力
// 本文件包含网络相关的收集器实现
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

// NetworkConnectionsCollector 网络连接收集器，收集活动的 TCP/UDP 连接
type NetworkConnectionsCollector struct{}

// Name 返回收集器名称
func (c *NetworkConnectionsCollector) Name() string {
	return "network.connections"
}

// Description 返回收集器描述
func (c *NetworkConnectionsCollector) Description() string {
	return "Collects active network connections (TCP/UDP)"
}

// Platform 返回支持的平台
func (c *NetworkConnectionsCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *NetworkConnectionsCollector) IsAvailable() bool {
	return true
}

// Collect 执行网络连接收集
func (c *NetworkConnectionsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record
	var err error

	// 根据操作系统选择收集方法
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

// collectLinux 在 Linux 系统上收集网络连接信息
func (c *NetworkConnectionsCollector) collectLinux(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// 读取 TCP 连接
	tcpRecords, err := c.readProcNet("/proc/net/tcp", "tcp")
	if err == nil {
		records = append(records, tcpRecords...)
	}

	// 读取 TCP6 连接
	tcp6Records, err := c.readProcNet("/proc/net/tcp6", "tcp6")
	if err == nil {
		records = append(records, tcp6Records...)
	}

	// 读取 UDP 连接
	udpRecords, err := c.readProcNet("/proc/net/udp", "udp")
	if err == nil {
		records = append(records, udpRecords...)
	}

	// 读取 UDP6 连接
	udp6Records, err := c.readProcNet("/proc/net/udp6", "udp6")
	if err == nil {
		records = append(records, udp6Records...)
	}

	// 将 PID 映射到连接
	c.mapPidsToConnections(records)

	return records, nil
}

// readProcNet 读取 /proc/net/ 下的网络连接文件
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

		if lineNum == 1 { // 跳过标题行
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// 解析本地地址和端口（十六进制格式）
		localAddr, localPort := c.parseHexAddr(fields[1])
		remoteAddr, remotePort := c.parseHexAddr(fields[2])

		// 解析 TCP 状态
		state := ""
		if strings.HasPrefix(proto, "tcp") {
			state = c.tcpStateToString(fields[3])
		}

		// 解析 UID 和 inode
		uid, _ := strconv.Atoi(fields[7])
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

// parseHexAddr 解析十六进制格式的地址和端口
func (c *NetworkConnectionsCollector) parseHexAddr(hexAddr string) (string, int) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0
	}

	// 解析端口（十六进制）
	port, _ := strconv.ParseInt(parts[1], 16, 32)

	// 解析 IP 地址（小端序）
	ipHex := parts[0]
	if len(ipHex) == 8 {
		// IPv4 地址（小端序存储）
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			start := 6 - 2*i
			end := 8 - 2*i
			if start < 0 || end > len(ipHex) {
				return "", int(port)
			}
			b, _ := strconv.ParseInt(ipHex[start:end], 16, 32)
			ip[i] = byte(b)
		}
		return ip.String(), int(port)
	} else if len(ipHex) == 32 {
		// IPv6 地址
		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			start := 30 - 2*i
			end := 32 - 2*i
			if start < 0 || end > len(ipHex) {
				return "", int(port)
			}
			b, _ := strconv.ParseInt(ipHex[start:end], 16, 32)
			ip[i] = byte(b)
		}
		return ip.String(), int(port)
	}

	return "", int(port)
}

// tcpStateToString 将 TCP 状态码转换为可读字符串
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

// parseAddress 解析地址格式 "IP:port" 或 "[IPv6]:port"
// 返回 IP 和端口，解析失败则返回空 IP 和 0 端口
func parseAddress(addr string) (string, int) {
	if addr == "" || addr == "*" {
		return "", 0
	}

	// 检查 IPv6 格式 [address]:port
	if strings.HasPrefix(addr, "[") {
		// 查找右括号
		closeBracket := strings.Index(addr, "]")
		if closeBracket == -1 {
			return "", 0
		}
		ip := addr[1:closeBracket]
		// 端口应在 "]:" 之后
		if closeBracket+2 < len(addr) && addr[closeBracket+1] == ':' {
			port, err := strconv.Atoi(addr[closeBracket+2:])
			if err != nil {
				return ip, 0
			}
			return ip, port
		}
		return ip, 0
	}

	// IPv4 格式：查找最后一个冒号（端口分隔符）
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

// parseAddressWithValidation 解析并验证 IP 地址
func parseAddressWithValidation(addr string) (string, int, error) {
	ip, port := parseAddress(addr)
	if port == 0 {
		return "", 0, fmt.Errorf("invalid address format: %s", addr)
	}
	// 验证 IP 地址有效性
	if ip != "" && ip != "*" {
		if net.ParseIP(ip) == nil {
			return "", 0, fmt.Errorf("invalid IP address: %s", ip)
		}
	}
	return ip, port, nil
}

// mapPidsToConnections 将进程 PID 映射到网络连接
func (c *NetworkConnectionsCollector) mapPidsToConnections(records []Record) {
	// 读取 /proc/[pid]/fd 查找 socket inode
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

			// 解析 socket:[inode] 格式
			if strings.HasPrefix(target, "socket:[") {
				inodeStr := strings.TrimPrefix(target, "socket:[")
				inodeStr = strings.TrimSuffix(inodeStr, "]")
				inode, _ := strconv.Atoi(inodeStr)
				inodeToPid[inode] = pid
			}
		}
	}

	// 将 PID 映射到记录
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

// collectWindows 在 Windows 系统上收集网络连接信息
func (c *NetworkConnectionsCollector) collectWindows(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// 使用 netstat 命令获取网络连接
	cmd := exec.CommandContext(ctx, "netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run netstat: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和标题行
		if line == "" || strings.HasPrefix(line, "Active") || strings.HasPrefix(line, "Proto") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		proto := strings.ToLower(fields[0])

		// 解析本地地址（处理 IPv6 格式 [address]:port）
		localIP, localPort := parseAddress(fields[1])
		if localPort == 0 {
			continue
		}

		// 解析远程地址
		remoteIP := ""
		remotePort := 0
		if fields[2] != "*" && fields[2] != "" {
			remoteIP, remotePort = parseAddress(fields[2])
		}

		// 解析状态和 PID
		state := ""
		pid := 0
		if proto == "tcp" {
			if len(fields) >= 5 {
				state = fields[3]
				pid, _ = strconv.Atoi(fields[4])
			}
		} else {
			// UDP 没有状态字段
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

// ListeningPortsCollector 监听端口收集器，收集所有监听中的端口
type ListeningPortsCollector struct{}

// Name 返回收集器名称
func (c *ListeningPortsCollector) Name() string {
	return "network.listening_ports"
}

// Description 返回收集器描述
func (c *ListeningPortsCollector) Description() string {
	return "Collects all listening ports"
}

// Platform 返回支持的平台
func (c *ListeningPortsCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *ListeningPortsCollector) IsAvailable() bool {
	return true
}

// Collect 收集监听端口信息
func (c *ListeningPortsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()

	// 复用 NetworkConnectionsCollector 并过滤监听状态
	ncc := &NetworkConnectionsCollector{}
	allConns, err := ncc.Collect(ctx, opts)
	if err != nil {
		return nil, err
	}

	// 过滤出监听状态的连接
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

// DNSCacheCollector DNS 缓存收集器，收集 DNS 缓存条目
type DNSCacheCollector struct{}

// Name 返回收集器名称
func (c *DNSCacheCollector) Name() string {
	return "network.dns_cache"
}

// Description 返回收集器描述
func (c *DNSCacheCollector) Description() string {
	return "Collects DNS cache entries"
}

// Platform 返回支持的平台
func (c *DNSCacheCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *DNSCacheCollector) IsAvailable() bool {
	return true
}

// Collect 收集 DNS 缓存信息
func (c *DNSCacheCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record
	var err error

	if runtime.GOOS == "windows" {
		records, err = c.collectWindows(ctx, opts)
	} else {
		// Linux 没有标准的 DNS 缓存，检查 systemd-resolved
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

// collectWindows 在 Windows 系统上收集 DNS 缓存
func (c *DNSCacheCollector) collectWindows(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// 使用 ipconfig /displaydns 显示 DNS 缓存
	cmd := exec.CommandContext(ctx, "ipconfig", "/displaydns")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run ipconfig: %w", err)
	}

	// 解析输出
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var currentRecord map[string]interface{}

	// 正则表达式匹配各字段
	recordNameRegex := regexp.MustCompile(`^\s*Record Name\s*:\s*(.+)$`)
	recordTypeRegex := regexp.MustCompile(`^\s*A \(Host\) Record\s*:\s*(.+)$`)
	recordTTLRegex := regexp.MustCompile(`^\s*Time To Live\s*:\s*(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()

		if matches := recordNameRegex.FindStringSubmatch(line); matches != nil {
			// 遇到新的记录名称，保存上一条记录
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
			// 解析其他字段
			if matches := recordTypeRegex.FindStringSubmatch(line); matches != nil {
				currentRecord["ip"] = matches[1]
			} else if matches := recordTTLRegex.FindStringSubmatch(line); matches != nil {
				currentRecord["ttl"] = matches[1]
			}
		}
	}

	// 添加最后一条记录
	if currentRecord != nil {
		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "ipconfig",
			Data:      currentRecord,
		})
	}

	return records, nil
}

// collectLinux 在 Linux 系统上收集 DNS 缓存信息
func (c *DNSCacheCollector) collectLinux(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// 尝试 systemd-resolve --statistics
	cmd := exec.CommandContext(ctx, "systemd-resolve", "--statistics")
	if output, err := cmd.Output(); err == nil {
		// 解析 DNS 缓存统计信息
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

	// 尝试 resolvectl statistics（新版本系统）
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

// ArpCacheCollector ARP 缓存收集器，收集 ARP 表条目
type ArpCacheCollector struct{}

// Name 返回收集器名称
func (c *ArpCacheCollector) Name() string {
	return "network.arp_cache"
}

// Description 返回收集器描述
func (c *ArpCacheCollector) Description() string {
	return "Collects ARP cache entries"
}

// Platform 返回支持的平台
func (c *ArpCacheCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *ArpCacheCollector) IsAvailable() bool {
	return true
}

// Collect 收集 ARP 缓存信息
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

// collectLinux 在 Linux 系统上收集 ARP 缓存
func (c *ArpCacheCollector) collectLinux(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// 读取 /proc/net/arp 文件
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

		if lineNum == 1 { // 跳过标题行
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
				"ip_address": fields[0],
				"hw_type":    fields[1],
				"flags":      fields[2],
				"hw_address": fields[3],
				"mask":       fields[4],
				"device":     fields[5],
			},
		})
	}

	return records, nil
}

// collectWindows 在 Windows 系统上收集 ARP 缓存
func (c *ArpCacheCollector) collectWindows(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// 使用 arp -a 命令
	cmd := exec.CommandContext(ctx, "arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run arp: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和接口标题行
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

// HostsFileCollector hosts 文件收集器，收集 hosts 文件条目
type HostsFileCollector struct{}

// Name 返回收集器名称
func (c *HostsFileCollector) Name() string {
	return "network.hosts"
}

// Description 返回收集器描述
func (c *HostsFileCollector) Description() string {
	return "Collects hosts file entries"
}

// Platform 返回支持的平台
func (c *HostsFileCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *HostsFileCollector) IsAvailable() bool {
	return true
}

// Collect 收集 hosts 文件内容
func (c *HostsFileCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 根据操作系统确定 hosts 文件路径
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

		// 跳过注释和空行
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
