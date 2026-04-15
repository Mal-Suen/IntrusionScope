// +build cgo

// Package detector provides threat detection capabilities
// This file contains the Rust engine integration via CGO
package detector

/*
#cgo windows LDFLAGS: -L${SRCDIR}/../../engine/target/release -lintrusionscope_engine
#cgo linux LDFLAGS: -L${SRCDIR}/../../engine/target/release -lintrusionscope_engine
#cgo darwin LDFLAGS: -L${SRCDIR}/../../engine/target/release -lintrusionscope_engine

#include <stdlib.h>
#include <stdint.h>

// Opaque handle to the engine
typedef void* EngineHandle;

// Engine creation and destruction
extern EngineHandle engine_new();
extern void engine_free(EngineHandle engine);

// IOC loading
extern int engine_load_iocs(EngineHandle engine, const char* iocs_json);
extern int engine_add_pattern(EngineHandle engine, const char* pattern, const char* tag);
extern int engine_build(EngineHandle engine);

// Detection
extern char* engine_detect(EngineHandle engine, const char* content);
extern char* engine_detect_json(EngineHandle engine, const char* content);

// Result accessors
extern int result_count(EngineHandle engine);
extern char* result_get_ioc_type(EngineHandle engine, int index);
extern char* result_get_value(EngineHandle engine, int index);
extern char* result_get_tag(EngineHandle engine, int index);
extern int result_get_severity(EngineHandle engine, int index);
extern void result_free(EngineHandle engine);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"
)

// RustEngine wraps the Rust detection engine
type RustEngine struct {
	handle unsafe.Pointer
}

// IOCDefinition represents an IOC to load into the engine
type IOCDefinition struct {
	Type  string `json:"type"`  // hash, ip, domain, url
	Value string `json:"value"` // The IOC value
	Tag   string `json:"tag"`   // Optional tag
}

// DetectionMatch represents a detection result
type DetectionMatch struct {
	IOCType  string `json:"ioc_type"`
	Value    string `json:"value"`
	Tag      string `json:"tag"`
	Severity int    `json:"severity"`
}

// DetectionResult represents the result of a detection operation
type DetectionResult struct {
	Matches []DetectionMatch `json:"matches"`
	Error   string           `json:"error,omitempty"`
}

// NewRustEngine creates a new Rust detection engine
func NewRustEngine() (*RustEngine, error) {
	handle := C.engine_new()
	if handle == nil {
		return nil, fmt.Errorf("failed to create Rust engine")
	}
	return &RustEngine{handle: handle}, nil
}

// Close releases the engine resources
func (e *RustEngine) Close() {
	if e.handle != nil {
		C.engine_free(e.handle)
		e.handle = nil
	}
}

// LoadIOCs loads IOC definitions into the engine
func (e *RustEngine) LoadIOCs(iocs []IOCDefinition) error {
	if e.handle == nil {
		return fmt.Errorf("engine not initialized")
	}

	data, err := json.Marshal(iocs)
	if err != nil {
		return fmt.Errorf("failed to marshal IOCs: %w", err)
	}

	cJSON := C.CString(string(data))
	defer C.free(unsafe.Pointer(cJSON))

	result := C.engine_load_iocs(e.handle, cJSON)
	if result != 0 {
		return fmt.Errorf("failed to load IOCs, error code: %d", result)
	}

	return nil
}

// LoadIOCsFromJSON loads IOCs from a JSON string
func (e *RustEngine) LoadIOCsFromJSON(jsonStr string) error {
	if e.handle == nil {
		return fmt.Errorf("engine not initialized")
	}

	cJSON := C.CString(jsonStr)
	defer C.free(unsafe.Pointer(cJSON))

	result := C.engine_load_iocs(e.handle, cJSON)
	if result != 0 {
		return fmt.Errorf("failed to load IOCs, error code: %d", result)
	}

	return nil
}

// AddPattern adds a pattern to the Aho-Corasick matcher
func (e *RustEngine) AddPattern(pattern, tag string) error {
	if e.handle == nil {
		return fmt.Errorf("engine not initialized")
	}

	cPattern := C.CString(pattern)
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cPattern))
	defer C.free(unsafe.Pointer(cTag))

	result := C.engine_add_pattern(e.handle, cPattern, cTag)
	if result != 0 {
		return fmt.Errorf("failed to add pattern, error code: %d", result)
	}

	return nil
}

// Build finalizes the engine after loading IOCs/patterns
func (e *RustEngine) Build() error {
	if e.handle == nil {
		return fmt.Errorf("engine not initialized")
	}

	result := C.engine_build(e.handle)
	if result != 0 {
		return fmt.Errorf("failed to build engine, error code: %d", result)
	}

	return nil
}

// Detect performs detection on the given content
func (e *RustEngine) Detect(content string) (*DetectionResult, error) {
	if e.handle == nil {
		return nil, fmt.Errorf("engine not initialized")
	}

	cContent := C.CString(content)
	defer C.free(unsafe.Pointer(cContent))

	result := C.engine_detect_json(e.handle, cContent)
	if result == nil {
		return &DetectionResult{Matches: []DetectionMatch{}}, nil
	}
	defer C.free(unsafe.Pointer(result))

	resultStr := C.GoString(result)
	var detectionResult DetectionResult
	if err := json.Unmarshal([]byte(resultStr), &detectionResult); err != nil {
		return nil, fmt.Errorf("failed to parse detection result: %w", err)
	}

	return &detectionResult, nil
}

// DetectMap performs detection on a map of data
func (e *RustEngine) DetectMap(data map[string]interface{}) (*DetectionResult, error) {
	// Convert map to JSON string for detection
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
	// This would read the file and call LoadIOCsFromJSON
	// Implementation depends on file format
	return fmt.Errorf("not implemented")
}

// AddPatterns adds multiple patterns at once
func (e *RustEngine) AddPatterns(patterns map[string]string) error {
	for pattern, tag := range patterns {
		if err := e.AddPattern(pattern, tag); err != nil {
			return err
		}
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
	var iocs []IOCDefinition
	for hashType, hashValue := range hashes {
		iocs = append(iocs, IOCDefinition{
			Type:  "hash",
			Value: strings.ToLower(hashValue),
			Tag:   hashType,
		})
	}

	// Create a temporary engine with these IOCs
	tempEngine, err := NewRustEngine()
	if err != nil {
		return nil, err
	}
	defer tempEngine.Close()

	// Load the hash IOCs
	if err := tempEngine.LoadIOCs(iocs); err != nil {
		return nil, err
	}
	if err := tempEngine.Build(); err != nil {
		return nil, err
	}

	// Detect in the content
	content, _ := json.Marshal(hashes)
	return tempEngine.Detect(string(content))
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
