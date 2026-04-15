// Package detector provides threat detection capabilities
package detector

import (
	"context"
	"time"
)

// Detector is the interface for threat detectors
type Detector interface {
	// Name returns the detector name
	Name() string

	// Description returns a brief description
	Description() string

	// Detect performs detection on input data
	Detect(ctx context.Context, input *DetectionInput) (*DetectionResult, error)

	// IsAvailable checks if the detector is available
	IsAvailable() bool
}

// DetectionInput contains data to be analyzed
type DetectionInput struct {
	Records    []Record
	Signatures []Signature
	Config     *DetectionConfig
}

// Record represents a single data record to analyze
type Record struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Signature represents a detection signature
type Signature struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // ioc, sigma, yara
	Severity    int                    `json:"severity"` // 1-5
	Description string                 `json:"description"`
	Rule        string                 `json:"rule"` // Rule content (YARA, Sigma YAML, etc.)
	Metadata    map[string]interface{} `json:"metadata"`
	Tags        []string               `json:"tags"`
}

// DetectionResult contains detection results
type DetectionResult struct {
	Detector    string       `json:"detector"`
	Timestamp   time.Time    `json:"timestamp"`
	Success     bool         `json:"success"`
	Matches     []Match      `json:"matches"`
	Duration    time.Duration `json:"duration"`
	Stats       DetectionStats `json:"stats"`
}

// Match represents a detection match
type Match struct {
	SignatureID   string                 `json:"signature_id"`
	SignatureName string                 `json:"signature_name"`
	Severity      int                    `json:"severity"`
	RecordIndex   int                    `json:"record_index"`
	RecordData    map[string]interface{} `json:"record_data"`
	MatchDetails  map[string]interface{} `json:"match_details"`
	Tags          []string               `json:"tags"`
	Timestamp     time.Time              `json:"timestamp"`
}

// DetectionStats contains detection statistics
type DetectionStats struct {
	TotalRecords   int            `json:"total_records"`
	TotalMatches   int            `json:"total_matches"`
	MatchesByLevel map[int]int    `json:"matches_by_level"`
	Duration       time.Duration  `json:"duration"`
}

// DetectionConfig contains detection configuration
type DetectionConfig struct {
	MinSeverity   int      `json:"min_severity"`
	EnableIOC     bool     `json:"enable_ioc"`
	EnableSigma   bool     `json:"enable_sigma"`
	EnableYARA    bool     `json:"enable_yara"`
	MaxMemoryMB   int      `json:"max_memory_mb"`
	Timeout       time.Duration `json:"timeout"`
}

// Registry manages all detectors
type Registry struct {
	detectors map[string]Detector
}

// NewRegistry creates a new detector registry
func NewRegistry() *Registry {
	return &Registry{
		detectors: make(map[string]Detector),
	}
}

// Register registers a detector
func (r *Registry) Register(d Detector) {
	r.detectors[d.Name()] = d
}

// Get retrieves a detector by name
func (r *Registry) Get(name string) (Detector, bool) {
	d, ok := r.detectors[name]
	return d, ok
}

// List returns all detector names
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.detectors))
	for name := range r.detectors {
		names = append(names, name)
	}
	return names
}

// Severity levels
const (
	SeverityInfo     = 1
	SeverityLow      = 2
	SeverityMedium   = 3
	SeverityHigh     = 4
	SeverityCritical = 5
)

// SeverityToString converts severity level to string
func SeverityToString(level int) string {
	switch level {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}
