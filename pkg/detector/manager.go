// Package detector provides threat detection capabilities
package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Manager manages multiple detection engines
type Manager struct {
	mu       sync.RWMutex
	engine   *RustEngine
	iocDB    *IOCDatabase
	rulesDir string
}

// ManagerConfig holds configuration for the detection manager
type ManagerConfig struct {
	RulesDir string `json:"rules_dir" yaml:"rules_dir"`
	IOCsDir  string `json:"iocs_dir" yaml:"iocs_dir"`
}

// NewManager creates a new detection manager
func NewManager(config *ManagerConfig) (*Manager, error) {
	m := &Manager{
		iocDB:    NewIOCDatabase(),
		rulesDir: config.RulesDir,
	}

	// Initialize engine
	engine, err := NewRustEngine()
	if err != nil {
		// Log warning but continue with Go fallback
		fmt.Printf("Warning: Rust engine not available, using Go fallback: %v\n", err)
	} else {
		m.engine = engine
	}

	// Load IOCs from directory
	if config.IOCsDir != "" {
		if err := m.LoadIOCsFromDir(config.IOCsDir); err != nil {
			fmt.Printf("Warning: failed to load IOCs: %v\n", err)
		}
	}

	return m, nil
}

// Close releases all resources
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.engine != nil {
		m.engine.Close()
		m.engine = nil
	}
}

// LoadIOCsFromDir loads IOCs from a directory of JSON files
func (m *Manager) LoadIOCsFromDir(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to list IOC files: %w", err)
	}

	var allIOCs []IOCDefinition

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var iocs []IOCDefinition
		if err := json.Unmarshal(data, &iocs); err != nil {
			// Try as object with iocs array
			var wrapper struct {
				IOCs []IOCDefinition `json:"iocs"`
			}
			if err := json.Unmarshal(data, &wrapper); err != nil {
				continue
			}
			iocs = wrapper.IOCs
		}

		allIOCs = append(allIOCs, iocs...)
	}

	return m.LoadIOCs(allIOCs)
}

// LoadIOCs loads IOCs into all engines
func (m *Manager) LoadIOCs(iocs []IOCDefinition) error {
	// Skip if no IOCs to load
	if len(iocs) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to IOC database
	for _, ioc := range iocs {
		m.iocDB.Add(ioc)
	}

	// Load into engine if available
	if m.engine != nil {
		if err := m.engine.LoadIOCs(iocs); err != nil {
			return fmt.Errorf("failed to load IOCs into engine: %w", err)
		}
	}

	return nil
}

// Build finalizes all engines
func (m *Manager) Build() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.engine != nil {
		return m.engine.Build()
	}
	return nil
}

// Detect performs detection on content
func (m *Manager) Detect(content string) (*EngineResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Use engine if available
	if m.engine != nil {
		return m.engine.Detect(content)
	}

	// Fallback to IOC database
	return m.iocDB.Detect(content), nil
}

// DetectMap performs detection on a map
func (m *Manager) DetectMap(data map[string]interface{}) (*EngineResult, error) {
	content, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	return m.Detect(string(content))
}

// DetectProcess performs detection on process data
func (m *Manager) DetectProcess(process map[string]interface{}) (*EngineResult, error) {
	// Check various process fields
	var matches []EngineMatch

	// Check exe path
	if exe, ok := process["exe"].(string); ok {
		result, _ := m.Detect(exe)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	// Check cmdline
	if cmdline, ok := process["cmdline"].(string); ok {
		result, _ := m.Detect(cmdline)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	// Check name
	if name, ok := process["name"].(string); ok {
		result, _ := m.Detect(name)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	return &EngineResult{Matches: matches}, nil
}

// DetectNetworkConnection performs detection on network connection data
func (m *Manager) DetectNetworkConnection(conn map[string]interface{}) (*EngineResult, error) {
	var matches []EngineMatch

	// Check remote IP
	if remoteIP, ok := conn["remote_ip"].(string); ok && remoteIP != "" {
		result, _ := m.Detect(remoteIP)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	// Check local IP
	if localIP, ok := conn["local_ip"].(string); ok && localIP != "" {
		result, _ := m.Detect(localIP)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	return &EngineResult{Matches: matches}, nil
}

// DetectFile performs detection on file data
func (m *Manager) DetectFile(file map[string]interface{}) (*EngineResult, error) {
	var matches []EngineMatch

	// Check hashes
	if hashes, ok := file["hashes"].(map[string]string); ok {
		for _, hash := range hashes {
			result, _ := m.Detect(hash)
			if result != nil {
				matches = append(matches, result.Matches...)
			}
		}
	}

	// Check path
	if path, ok := file["path"].(string); ok {
		result, _ := m.Detect(path)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	return &EngineResult{Matches: matches}, nil
}

// GetIOCDatabase returns the IOC database
func (m *Manager) GetIOCDatabase() *IOCDatabase {
	return m.iocDB
}

// AddPattern adds a pattern to the engine
func (m *Manager) AddPattern(pattern string, id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.engine != nil {
		return m.engine.AddPattern(pattern, id)
	}
	return nil
}

// AddPatterns adds multiple patterns
func (m *Manager) AddPatterns(patterns map[string]int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.engine != nil {
		return m.engine.AddPatterns(patterns)
	}
	return nil
}

// IOCDatabase is a simple in-memory IOC database
type IOCDatabase struct {
	mu      sync.RWMutex
	hashes  map[string]IOCDefinition
	ips     map[string]IOCDefinition
	domains map[string]IOCDefinition
	urls    map[string]IOCDefinition
}

// NewIOCDatabase creates a new IOC database
func NewIOCDatabase() *IOCDatabase {
	return &IOCDatabase{
		hashes:  make(map[string]IOCDefinition),
		ips:     make(map[string]IOCDefinition),
		domains: make(map[string]IOCDefinition),
		urls:    make(map[string]IOCDefinition),
	}
}

// Add adds an IOC to the database
func (db *IOCDatabase) Add(ioc IOCDefinition) {
	db.mu.Lock()
	defer db.mu.Unlock()

	iocType := strings.ToLower(ioc.IOCType)
	iocValue := strings.ToLower(ioc.Value)

	switch iocType {
	case "md5", "sha1", "sha256", "hash":
		db.hashes[iocValue] = ioc
	case "ip", "ipv4", "ipv6":
		db.ips[iocValue] = ioc
	case "domain":
		db.domains[iocValue] = ioc
	case "url":
		db.urls[iocValue] = ioc
	}
}

// Detect performs detection using the database
func (db *IOCDatabase) Detect(content string) *EngineResult {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var matches []EngineMatch
	contentLower := strings.ToLower(content)

	// Check hashes
	for value, ioc := range db.hashes {
		if strings.Contains(contentLower, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check IPs
	for value, ioc := range db.ips {
		if strings.Contains(content, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check domains
	for value, ioc := range db.domains {
		if strings.Contains(contentLower, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check URLs
	for value, ioc := range db.urls {
		if strings.Contains(contentLower, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	return &EngineResult{Matches: matches}
}

// Stats returns statistics about the IOC database
func (db *IOCDatabase) Stats() map[string]int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return map[string]int{
		"hashes":  len(db.hashes),
		"ips":     len(db.ips),
		"domains": len(db.domains),
		"urls":    len(db.urls),
		"total":   len(db.hashes) + len(db.ips) + len(db.domains) + len(db.urls),
	}
}
