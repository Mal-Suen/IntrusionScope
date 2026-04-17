// Package detector provides threat detection capabilities
// This file contains IOC (Indicator of Compromise) detection
package detector

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// IOCDetector detects IOCs in collected data
type IOCDetector struct {
	hashIndex     map[string]*Signature // MD5, SHA1, SHA256
	filenameIndex map[string]*Signature // File names
	ipIndex       *ipTrie
	domainIndex   map[string]*Signature
	urlIndex      map[string]*Signature
	emailIndex    map[string]*Signature
	filePathIndex map[string]*Signature // File paths
}

type ipTrie struct {
	root *ipTrieNode
}

type ipTrieNode struct {
	children map[byte]*ipTrieNode
	signature *Signature
}

func newIPTrie() *ipTrie {
	return &ipTrie{
		root: &ipTrieNode{
			children: make(map[byte]*ipTrieNode),
		},
	}
}

// NewIOCDetector creates a new IOC detector
func NewIOCDetector() *IOCDetector {
	return &IOCDetector{
		hashIndex:     make(map[string]*Signature),
		filenameIndex: make(map[string]*Signature),
		ipIndex:       newIPTrie(),
		domainIndex:   make(map[string]*Signature),
		urlIndex:      make(map[string]*Signature),
		emailIndex:    make(map[string]*Signature),
		filePathIndex: make(map[string]*Signature),
	}
}

func (d *IOCDetector) Name() string {
	return "ioc"
}

func (d *IOCDetector) Description() string {
	return "Detects IOCs (hashes, IPs, domains, URLs) in collected data"
}

func (d *IOCDetector) IsAvailable() bool {
	return true
}

// LoadSignatures loads IOC signatures into the detector
func (d *IOCDetector) LoadSignatures(signatures []Signature) error {
	for i := range signatures {
		sig := &signatures[i]

		// Get IOC type from metadata
		iocType, ok := sig.Metadata["type"].(string)
		if !ok {
			continue
		}
		iocType = strings.ToLower(iocType)

		// Get IOC value from metadata
		value, ok := sig.Metadata["value"].(string)
		if !ok {
			continue
		}

		switch iocType {
		case "hash", "md5", "sha1", "sha256":
			d.hashIndex[strings.ToLower(value)] = sig
		case "filename":
			d.filenameIndex[strings.ToLower(value)] = sig
		case "filepath", "path":
			d.filePathIndex[strings.ToLower(value)] = sig
		case "ip":
			d.addIP(value, sig)
		case "domain":
			d.domainIndex[strings.ToLower(value)] = sig
		case "url":
			d.urlIndex[strings.ToLower(value)] = sig
		case "email":
			d.emailIndex[strings.ToLower(value)] = sig
		}
	}
	return nil
}

func (d *IOCDetector) addIP(ip string, sig *Signature) {
	// Parse IP and add to trie
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}

	// For simplicity, store in domain index for now
	// TODO: Implement proper IP trie for CIDR matching
	d.domainIndex[ip] = sig
}

func (d *IOCDetector) Detect(ctx context.Context, input *DetectionInput) (*DetectionResult, error) {
	start := time.Now()
	result := &DetectionResult{
		Detector:  d.Name(),
		Timestamp: start,
		Matches:   []Match{},
	}

	stats := DetectionStats{
		TotalRecords:   len(input.Records),
		MatchesByLevel: make(map[int]int),
	}

	for i, record := range input.Records {
		matches := d.detectRecord(record)
		for _, match := range matches {
			match.RecordIndex = i
			match.RecordData = record.Data
			match.Timestamp = time.Now()
			result.Matches = append(result.Matches, match)

			stats.TotalMatches++
			stats.MatchesByLevel[match.Severity]++
		}
	}

	stats.Duration = time.Since(start)
	result.Stats = stats
	result.Success = true
	result.Duration = stats.Duration

	return result, nil
}

func (d *IOCDetector) detectRecord(record Record) []Match {
	var matches []Match

	// Safety check for nil Data
	if record.Data == nil {
		return matches
	}

	// Check hashes
	if hash, ok := record.Data["md5"].(string); ok && hash != "" {
		if sig, found := d.hashIndex[strings.ToLower(hash)]; found {
			matches = append(matches, d.createMatch(sig, "md5", hash))
		}
	}
	if hash, ok := record.Data["sha1"].(string); ok && hash != "" {
		if sig, found := d.hashIndex[strings.ToLower(hash)]; found {
			matches = append(matches, d.createMatch(sig, "sha1", hash))
		}
	}
	if hash, ok := record.Data["sha256"].(string); ok && hash != "" {
		if sig, found := d.hashIndex[strings.ToLower(hash)]; found {
			matches = append(matches, d.createMatch(sig, "sha256", hash))
		}
	}

	// Check IPs
	if ip, ok := record.Data["remote_ip"].(string); ok && ip != "" {
		if sig, found := d.domainIndex[ip]; found {
			matches = append(matches, d.createMatch(sig, "ip", ip))
		}
	}
	if ip, ok := record.Data["local_ip"].(string); ok && ip != "" {
		if sig, found := d.domainIndex[ip]; found {
			matches = append(matches, d.createMatch(sig, "ip", ip))
		}
	}

	// Check domains/URLs
	if url, ok := record.Data["url"].(string); ok && url != "" {
		if sig, found := d.urlIndex[strings.ToLower(url)]; found {
			matches = append(matches, d.createMatch(sig, "url", url))
		}
	}
	if domain, ok := record.Data["domain"].(string); ok && domain != "" {
		if sig, found := d.domainIndex[strings.ToLower(domain)]; found {
			matches = append(matches, d.createMatch(sig, "domain", domain))
		}
	}

	// Check file paths - use filenameIndex and filePathIndex
	if path, ok := record.Data["path"].(string); ok && path != "" {
		// Check full path first
		if sig, found := d.filePathIndex[strings.ToLower(path)]; found {
			matches = append(matches, d.createMatch(sig, "filepath", path))
		}
		// Check filename
		filename := filepath.Base(path)
		if sig, found := d.filenameIndex[strings.ToLower(filename)]; found {
			matches = append(matches, d.createMatch(sig, "filename", filename))
		}
	}
	if exe, ok := record.Data["exe"].(string); ok && exe != "" {
		// Check full path first
		if sig, found := d.filePathIndex[strings.ToLower(exe)]; found {
			matches = append(matches, d.createMatch(sig, "filepath", exe))
		}
		// Check filename
		filename := filepath.Base(exe)
		if sig, found := d.filenameIndex[strings.ToLower(filename)]; found {
			matches = append(matches, d.createMatch(sig, "filename", filename))
		}
	}

	// Check command lines
	if cmdline, ok := record.Data["cmdline"].(string); ok {
		matches = append(matches, d.checkCommandline(cmdline)...)
	}

	return matches
}

func (d *IOCDetector) checkCommandline(cmdline string) []Match {
	var matches []Match
	lowerCmd := strings.ToLower(cmdline)

	// Check for suspicious commands
	suspiciousPatterns := []struct {
		pattern   string
		name      string
		severity  int
	}{
		{"powershell -enc", "Encoded PowerShell", SeverityHigh},
		{"powershell -e ", "Encoded PowerShell", SeverityHigh},
		{"certutil -urlcache", "Certutil Download", SeverityHigh},
		{"bitsadmin /transfer", "BITSAdmin Download", SeverityMedium},
		{"reg save ", "Registry Dump", SeverityMedium},
		{"reg add ", "Registry Modification", SeverityMedium},
		{"net user ", "User Account Manipulation", SeverityMedium},
		{"net localgroup ", "Group Manipulation", SeverityMedium},
		{"wmic ", "WMIC Execution", SeverityLow},
		{"rundll32 ", "Rundll32 Execution", SeverityLow},
	}

	for _, sp := range suspiciousPatterns {
		if strings.Contains(lowerCmd, sp.pattern) {
			matches = append(matches, Match{
				SignatureID:   fmt.Sprintf("suspicious-cmd-%s", sp.name),
				SignatureName: sp.name,
				Severity:      sp.severity,
				MatchDetails: map[string]interface{}{
					"type":    "suspicious_command",
					"pattern": sp.pattern,
					"matched": cmdline,
				},
				Tags: []string{"suspicious", "command"},
			})
		}
	}

	return matches
}

func (d *IOCDetector) createMatch(sig *Signature, matchType, value string) Match {
	return Match{
		SignatureID:   sig.ID,
		SignatureName: sig.Name,
		Severity:      sig.Severity,
		MatchDetails: map[string]interface{}{
			"type":  matchType,
			"value": value,
		},
		Tags: sig.Tags,
	}
}
