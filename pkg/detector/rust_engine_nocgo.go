// +build !cgo

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
	patterns map[string]string
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
		patterns: make(map[string]string),
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
		iocType := strings.ToLower(ioc.Type)
		if _, ok := e.iocs[iocType]; ok {
			e.iocs[iocType] = append(e.iocs[iocType], ioc)
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
func (e *RustEngine) AddPattern(pattern, tag string) error {
	e.patterns[pattern] = tag
	return nil
}

// Build finalizes the engine after loading IOCs/patterns
func (e *RustEngine) Build() error {
	e.built = true
	return nil
}

// Detect performs detection on the given content
func (e *RustEngine) Detect(content string) (*DetectionResult, error) {
	if !e.built {
		return nil, fmt.Errorf("engine not built, call Build() first")
	}

	var matches []DetectionMatch
	contentLower := strings.ToLower(content)

	// Check hash IOCs
	for _, ioc := range e.iocs["hash"] {
		if strings.Contains(contentLower, strings.ToLower(ioc.Value)) {
			matches = append(matches, DetectionMatch{
				IOCType:  "hash",
				Value:    ioc.Value,
				Tag:      ioc.Tag,
				Severity: 3,
			})
		}
	}

	// Check IP IOCs
	for _, ioc := range e.iocs["ip"] {
		if strings.Contains(content, ioc.Value) {
			matches = append(matches, DetectionMatch{
				IOCType:  "ip",
				Value:    ioc.Value,
				Tag:      ioc.Tag,
				Severity: 3,
			})
		}
	}

	// Check domain IOCs
	for _, ioc := range e.iocs["domain"] {
		if strings.Contains(contentLower, strings.ToLower(ioc.Value)) {
			matches = append(matches, DetectionMatch{
				IOCType:  "domain",
				Value:    ioc.Value,
				Tag:      ioc.Tag,
				Severity: 2,
			})
		}
	}

	// Check URL IOCs
	for _, ioc := range e.iocs["url"] {
		if strings.Contains(contentLower, strings.ToLower(ioc.Value)) {
			matches = append(matches, DetectionMatch{
				IOCType:  "url",
				Value:    ioc.Value,
				Tag:      ioc.Tag,
				Severity: 2,
			})
		}
	}

	// Check patterns
	for pattern, tag := range e.patterns {
		if strings.Contains(contentLower, strings.ToLower(pattern)) {
			matches = append(matches, DetectionMatch{
				IOCType:  "pattern",
				Value:    pattern,
				Tag:      tag,
				Severity: 1,
			})
		}
	}

	return &DetectionResult{Matches: matches}, nil
}

// DetectMap performs detection on a map of data
func (e *RustEngine) DetectMap(data map[string]interface{}) (*DetectionResult, error) {
	content, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	return e.Detect(string(content))
}

// DetectString performs detection on a string
func (e *RustEngine) DetectString(content string) (*DetectionResult, error) {
	return e.Detect(content)
}

// LoadIOCsFromFile loads IOCs from a JSON file
func (e *RustEngine) LoadIOCsFromFile(filepath string) error {
	return fmt.Errorf("not implemented")
}

// AddPatterns adds multiple patterns at once
func (e *RustEngine) AddPatterns(patterns map[string]string) error {
	for pattern, tag := range patterns {
		e.patterns[pattern] = tag
	}
	return nil
}

// QuickDetect is a convenience method that creates an engine, loads IOCs, and detects
func QuickDetect(content string, iocs []IOCDefinition) (*DetectionResult, error) {
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
func (e *RustEngine) DetectHashes(hashes map[string]string) (*DetectionResult, error) {
	content, _ := json.Marshal(hashes)
	return e.Detect(string(content))
}

// DetectIPs checks if any IP addresses match known bad IPs
func (e *RustEngine) DetectIPs(ips []string) (*DetectionResult, error) {
	content := strings.Join(ips, "\n")
	return e.Detect(content)
}

// DetectDomains checks if any domains match known bad domains
func (e *RustEngine) DetectDomains(domains []string) (*DetectionResult, error) {
	content := strings.Join(domains, "\n")
	return e.Detect(content)
}

// DetectURLs checks if any URLs match known bad URLs
func (e *RustEngine) DetectURLs(urls []string) (*DetectionResult, error) {
	content := strings.Join(urls, "\n")
	return e.Detect(content)
}
