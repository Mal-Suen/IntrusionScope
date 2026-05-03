//go:build !cgo

// Package detector provides threat detection capabilities
// This file contains a pure Go fallback when CGO is not available
package detector

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RustEngine is a pure Go fallback when CGO is not available
type RustEngine struct {
	iocs     map[string][]IOCDefinition
	patterns map[string]int
	built    bool
}

// NewRustEngine creates a new detection engine (Go fallback)
func NewRustEngine() (*RustEngine, error) {
	return &RustEngine{
		iocs: map[string][]IOCDefinition{
			"hash":   {},
			"ip":     {},
			"domain": {},
			"url":    {},
		},
		patterns: make(map[string]int),
		built:    false,
	}, nil
}

// Close releases the engine resources
func (e *RustEngine) Close() {
	// Nothing to do in Go fallback
}

// LoadIOCs loads IOC definitions into the engine
func (e *RustEngine) LoadIOCs(iocs []IOCDefinition) error {
	for _, ioc := range iocs {
		iocType := strings.ToLower(ioc.IOCType)
		switch iocType {
		case "md5", "sha1", "sha256", "hash":
			e.iocs["hash"] = append(e.iocs["hash"], ioc)
		case "ip", "ipv4", "ipv6":
			e.iocs["ip"] = append(e.iocs["ip"], ioc)
		case "domain":
			e.iocs["domain"] = append(e.iocs["domain"], ioc)
		case "url":
			e.iocs["url"] = append(e.iocs["url"], ioc)
		}
	}
	return nil
}

// LoadIOCsFromJSON loads IOCs from a JSON string
func (e *RustEngine) LoadIOCsFromJSON(jsonStr string) error {
	var iocs []IOCDefinition
	if err := json.Unmarshal([]byte(jsonStr), &iocs); err != nil {
		return fmt.Errorf("failed to parse IOCs: %w", err)
	}
	return e.LoadIOCs(iocs)
}

// AddPattern adds a pattern to the matcher
func (e *RustEngine) AddPattern(pattern string, id int) error {
	e.patterns[pattern] = id
	return nil
}

// Build finalizes the engine after loading IOCs/patterns
func (e *RustEngine) Build() error {
	e.built = true
	return nil
}

// Detect performs detection on the given content
func (e *RustEngine) Detect(content string) (*EngineResult, error) {
	if !e.built {
		return nil, fmt.Errorf("engine not built, call Build() first")
	}

	var matches []EngineMatch
	contentLower := strings.ToLower(content)

	// Check hash IOCs
	for _, ioc := range e.iocs["hash"] {
		if strings.Contains(contentLower, strings.ToLower(ioc.Value)) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check IP IOCs
	for _, ioc := range e.iocs["ip"] {
		if strings.Contains(content, ioc.Value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check domain IOCs
	for _, ioc := range e.iocs["domain"] {
		if strings.Contains(contentLower, strings.ToLower(ioc.Value)) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check URL IOCs
	for _, ioc := range e.iocs["url"] {
		if strings.Contains(contentLower, strings.ToLower(ioc.Value)) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check patterns
	for pattern, id := range e.patterns {
		if strings.Contains(contentLower, strings.ToLower(pattern)) {
			matches = append(matches, EngineMatch{
				SignatureID:   fmt.Sprintf("pattern_%d", id),
				SignatureName: fmt.Sprintf("Pattern %d", id),
				Severity:      2,
				Details:       map[string]string{"pattern": pattern},
			})
		}
	}

	return &EngineResult{Matches: matches, TotalMatches: len(matches)}, nil
}

// DetectMap performs detection on a map of data
func (e *RustEngine) DetectMap(data map[string]interface{}) (*EngineResult, error) {
	content, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	return e.Detect(string(content))
}

// DetectString performs detection on a string
func (e *RustEngine) DetectString(content string) (*EngineResult, error) {
	return e.Detect(content)
}

// LoadIOCsFromFile loads IOCs from a JSON file
func (e *RustEngine) LoadIOCsFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read IOC file: %w", err)
	}

	var iocFile struct {
		IOCs []IOCDefinition `json:"iocs"`
	}

	if err := json.Unmarshal(data, &iocFile); err != nil {
		// Try as direct array
		var iocs []IOCDefinition
		if err := json.Unmarshal(data, &iocs); err != nil {
			return fmt.Errorf("failed to parse IOC file: %w", err)
		}
		iocFile.IOCs = iocs
	}

	if len(iocFile.IOCs) == 0 {
		return fmt.Errorf("no IOCs found in file: %s", filePath)
	}

	return e.LoadIOCs(iocFile.IOCs)
}

// AddPatterns adds multiple patterns at once
func (e *RustEngine) AddPatterns(patterns map[string]int) error {
	for pattern, id := range patterns {
		e.patterns[pattern] = id
	}
	return nil
}

// QuickDetect is a convenience method that creates an engine, loads IOCs, and detects
func QuickDetect(content string, iocs []IOCDefinition) (*EngineResult, error) {
	engine, err := NewRustEngine()
	if err != nil {
		return nil, err
	}
	defer engine.Close()

	if len(iocs) > 0 {
		if err := engine.LoadIOCs(iocs); err != nil {
			return nil, err
		}
		if err := engine.Build(); err != nil {
			return nil, err
		}
	}

	return engine.Detect(content)
}

// DetectHashes checks if any hash matches known bad hashes
func (e *RustEngine) DetectHashes(hashes map[string]string) (*EngineResult, error) {
	content, _ := json.Marshal(hashes)
	return e.Detect(string(content))
}

// DetectIPs checks if any IP addresses match known bad IPs
func (e *RustEngine) DetectIPs(ips []string) (*EngineResult, error) {
	content := strings.Join(ips, "\n")
	return e.Detect(content)
}

// DetectDomains checks if any domains match known bad domains
func (e *RustEngine) DetectDomains(domains []string) (*EngineResult, error) {
	content := strings.Join(domains, "\n")
	return e.Detect(content)
}

// DetectURLs checks if any URLs match known bad URLs
func (e *RustEngine) DetectURLs(urls []string) (*EngineResult, error) {
	content := strings.Join(urls, "\n")
	return e.Detect(content)
}
