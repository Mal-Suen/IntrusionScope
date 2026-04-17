// Package detector provides threat detection capabilities
// This file contains shared type definitions used by both CGO and non-CGO builds
package detector

// IOCDefinition represents an IOC to load into the engine
// Must match Rust's IOC struct in engine/src/types.rs
type IOCDefinition struct {
	ID          string   `json:"id"`                    // IOC identifier
	Value       string   `json:"value"`                 // The IOC value
	IOCType     string   `json:"ioc_type"`              // MD5, SHA1, SHA256, IP, Domain, URL, Email, FilePath, Registry
	Severity    int      `json:"severity"`              // 1-5 (Info, Low, Medium, High, Critical)
	Description string   `json:"description,omitempty"` // Optional description
	Tags        []string `json:"tags,omitempty"`        // Optional tags
	Source      string   `json:"source,omitempty"`      // Optional source
}

// EngineMatch represents a detection match from the Rust engine
type EngineMatch struct {
	SignatureID   string            `json:"signature_id"`
	SignatureName string            `json:"signature_name"`
	Severity      int               `json:"severity"`
	Position      int               `json:"position"`
	Length        int               `json:"length"`
	Details       map[string]string `json:"details"`
}

// EngineResult represents the result of a detection operation
type EngineResult struct {
	Matches       []EngineMatch `json:"matches"`
	TotalMatches  int           `json:"total_matches"`
	DetectionTime uint64        `json:"detection_time_us"`
}
