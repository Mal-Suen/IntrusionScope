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

// Detection result handle
typedef void* ResultHandle;

// Engine creation and destruction
extern EngineHandle engine_new();
extern void engine_free(EngineHandle engine);

// IOC loading
extern int engine_load_iocs(EngineHandle engine, const char* iocs_json);

// Pattern matching - third param is pattern id (size_t)
extern int engine_add_pattern(EngineHandle engine, const char* pattern, size_t id);
extern int engine_build(EngineHandle engine);

// Detection - returns ResultHandle, not string
extern ResultHandle engine_detect_json(EngineHandle engine, const char* json);

// Result accessors
extern size_t result_match_count(ResultHandle result);
extern char* result_match_signature_id(ResultHandle result, size_t index);
extern int result_match_severity(ResultHandle result, size_t index);
extern char* result_to_json(ResultHandle result);
extern void result_free(ResultHandle result);
extern void string_free(char* s);
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
	handle C.EngineHandle
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

	// Skip if no IOCs
	if len(iocs) == 0 {
		return nil
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
func (e *RustEngine) AddPattern(pattern string, id int) error {
	if e.handle == nil {
		return fmt.Errorf("engine not initialized")
	}

	cPattern := C.CString(pattern)
	defer C.free(unsafe.Pointer(cPattern))

	result := C.engine_add_pattern(e.handle, cPattern, C.size_t(id))
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
func (e *RustEngine) Detect(content string) (*EngineResult, error) {
	if e.handle == nil {
		return nil, fmt.Errorf("engine not initialized")
	}

	cContent := C.CString(content)
	defer C.free(unsafe.Pointer(cContent))

	resultHandle := C.engine_detect_json(e.handle, cContent)
	if resultHandle == nil {
		return &EngineResult{Matches: []EngineMatch{}}, nil
	}
	defer C.result_free(resultHandle)

	// Get JSON result
	jsonPtr := C.result_to_json(resultHandle)
	if jsonPtr == nil {
		return &EngineResult{Matches: []EngineMatch{}}, nil
	}
	defer C.string_free(jsonPtr)

	resultStr := C.GoString(jsonPtr)
	var engineResult EngineResult
	if err := json.Unmarshal([]byte(resultStr), &engineResult); err != nil {
		return nil, fmt.Errorf("failed to parse detection result: %w", err)
	}

	return &engineResult, nil
}

// DetectMap performs detection on a map of data
func (e *RustEngine) DetectMap(data map[string]interface{}) (*EngineResult, error) {
	// Convert map to JSON string for detection
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
func (e *RustEngine) LoadIOCsFromFile(filepath string) error {
	// This would read the file and call LoadIOCsFromJSON
	// Implementation depends on file format
	return fmt.Errorf("not implemented")
}

// AddPatterns adds multiple patterns at once
func (e *RustEngine) AddPatterns(patterns map[string]int) error {
	for pattern, id := range patterns {
		if err := e.AddPattern(pattern, id); err != nil {
			return err
		}
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
	var iocs []IOCDefinition
	for hashType, hashValue := range hashes {
		iocs = append(iocs, IOCDefinition{
			ID:       hashType + "_" + hashValue[:16],
			Value:    strings.ToLower(hashValue),
			IOCType:  "SHA256",
			Severity: 3,
			Tags:     []string{hashType},
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
