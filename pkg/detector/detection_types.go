// Package detector provides threat detection capabilities
// This file contains shared type definitions used by all detectors (IOC, Sigma, YARA)
package detector

import (
	"time"
)

// Severity levels for detection matches
const (
	SeverityInfo     = 1
	SeverityLow      = 2
	SeverityMedium   = 3
	SeverityHigh     = 4
	SeverityCritical = 5
)

// DetectionInput represents input data for detection
type DetectionInput struct {
	Records  []DetectionRecord `json:"records"`
	Source   string            `json:"source"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// DetectionRecord represents a single record for detection
type DetectionRecord struct {
	Type      string                 `json:"type"`      // process, network, file, registry, log
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Raw       []byte                 `json:"raw,omitempty"`
}

// DetectionResult represents the result of a detection operation
type DetectionResult struct {
	Detector    string        `json:"detector"`
	Timestamp   time.Time     `json:"timestamp"`
	Success     bool          `json:"success"`
	Error       string        `json:"error,omitempty"`
	Matches     []Match       `json:"matches"`
	Stats       DetectionStats `json:"stats"`
	Duration    time.Duration `json:"duration"`
}

// DetectionStats contains statistics about the detection operation
type DetectionStats struct {
	TotalRecords   int           `json:"total_records"`
	TotalMatches   int           `json:"total_matches"`
	Duration       time.Duration `json:"duration"`
	MatchesByLevel map[int]int   `json:"matches_by_level"`
}

// Match represents a single detection match
type Match struct {
	SignatureID   string                 `json:"signature_id"`
	SignatureName string                 `json:"signature_name"`
	Severity      int                    `json:"severity"`
	RecordIndex   int                    `json:"record_index"`
	RecordData    map[string]interface{} `json:"record_data"`
	MatchDetails  map[string]interface{} `json:"match_details,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
}

// Detector interface defines the common interface for all detectors
type Detector interface {
	// Name returns the detector name
	Name() string

	// Description returns the detector description
	Description() string

	// IsAvailable checks if the detector is available
	IsAvailable() bool

	// Detect performs detection on the input
	Detect(input *DetectionInput) (*DetectionResult, error)
}

// ConvertCollectorRecords converts collector records to detection records
func ConvertCollectorRecords(records []interface{}) []DetectionRecord {
	var result []DetectionRecord
	for _, r := range records {
		// Handle collector.Record type
		if cr, ok := r.(map[string]interface{}); ok {
			dr := DetectionRecord{
				Data: cr,
			}
			if ts, ok := cr["timestamp"].(time.Time); ok {
				dr.Timestamp = ts
			}
			if src, ok := cr["source"].(string); ok {
				dr.Source = src
			}
			// Infer type from source or data fields
			dr.Type = inferRecordType(cr)
			result = append(result, dr)
		}
	}
	return result
}

// inferRecordType infers the record type from data fields
func inferRecordType(data map[string]interface{}) string {
	// Check for process-related fields
	if _, ok := data["pid"]; ok {
		if _, ok2 := data["exe"]; ok2 {
			return "process"
		}
	}
	// Check for network-related fields
	if _, ok := data["local_ip"]; ok {
		return "network"
	}
	if _, ok := data["local_port"]; ok {
		return "network"
	}
	// Check for file-related fields
	if _, ok := data["path"]; ok {
		return "file"
	}
	// Check for registry-related fields (Windows)
	if _, ok := data["key"]; ok {
		return "registry"
	}
	// Check for log-related fields
	if _, ok := data["event_id"]; ok {
		return "log"
	}
	return "unknown"
}