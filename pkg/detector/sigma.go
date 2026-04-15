// Package detector provides threat detection capabilities
// This file contains Sigma rule detection
package detector

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SigmaDetector detects threats using Sigma rules
type SigmaDetector struct {
	rules []*SigmaRule
}

// SigmaRule represents a parsed Sigma rule
type SigmaRule struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Level       string                 `json:"level"`
	Status      string                 `json:"status"`
	Author      string                 `json:"author"`
	Logsource   SigmaLogsource         `json:"logsource"`
	Detection   SigmaDetection         `json:"detection"`
	FalsePositives []string            `json:"falsepositives"`
	Tags        []string               `json:"tags"`
	Raw         string                 `json:"raw"`
}

// SigmaLogsource defines the log source for a Sigma rule
type SigmaLogsource struct {
	Category string `json:"category"`
	Product  string `json:"product"`
	Service  string `json:"service"`
}

// SigmaDetection defines the detection logic
type SigmaDetection struct {
	Selection   map[string]interface{} `json:"selection"`
	Condition   string                 `json:"condition"`
	Timeframe   string                 `json:"timeframe"`
}

// NewSigmaDetector creates a new Sigma detector
func NewSigmaDetector() *SigmaDetector {
	return &SigmaDetector{
		rules: []*SigmaRule{},
	}
}

func (d *SigmaDetector) Name() string {
	return "sigma"
}

func (d *SigmaDetector) Description() string {
	return "Detects threats using Sigma rules"
}

func (d *SigmaDetector) IsAvailable() bool {
	return true
}

// LoadRules loads Sigma rules into the detector
func (d *SigmaDetector) LoadRules(rules []SigmaRule) error {
	for i := range rules {
		d.rules = append(d.rules, &rules[i])
	}
	return nil
}

func (d *SigmaDetector) Detect(ctx context.Context, input *DetectionInput) (*DetectionResult, error) {
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
		for _, rule := range d.rules {
			if d.matchRule(rule, record) {
				severity := d.levelToSeverity(rule.Level)

				match := Match{
					SignatureID:   rule.ID,
					SignatureName: rule.Title,
					Severity:      severity,
					RecordIndex:   i,
					RecordData:    record.Data,
					MatchDetails: map[string]interface{}{
						"rule_id":     rule.ID,
						"description": rule.Description,
						"level":       rule.Level,
					},
					Tags:      rule.Tags,
					Timestamp: time.Now(),
				}

				result.Matches = append(result.Matches, match)
				stats.TotalMatches++
				stats.MatchesByLevel[severity]++
			}
		}
	}

	stats.Duration = time.Since(start)
	result.Stats = stats
	result.Success = true
	result.Duration = stats.Duration

	return result, nil
}

func (d *SigmaDetector) matchRule(rule *SigmaRule, record Record) bool {
	// Simplified Sigma matching
	// TODO: Implement full Sigma detection logic with condition parser

	selection := rule.Detection.Selection
	if selection == nil {
		return false
	}

	// Check if record type matches logsource
	if !d.matchLogsource(rule.Logsource, record) {
		return false
	}

	// Match selection criteria
	return d.matchSelection(selection, record.Data)
}

func (d *SigmaDetector) matchLogsource(logsource SigmaLogsource, record Record) bool {
	// Check if record matches the logsource
	recordType := record.Type

	// Map record types to Sigma categories
	categoryMap := map[string]string{
		"process_creation": "process",
		"network_connection": "network",
		"file_event": "file",
		"registry_event": "registry",
	}

	if logsource.Category != "" {
		if mapped, ok := categoryMap[logsource.Category]; ok {
			return strings.Contains(recordType, mapped)
		}
	}

	return true // Default to true for flexibility
}

func (d *SigmaDetector) matchSelection(selection map[string]interface{}, data map[string]interface{}) bool {
	// Simple AND logic: all conditions must match
	for key, value := range selection {
		if !d.matchField(key, value, data) {
			return false
		}
	}
	return true
}

func (d *SigmaDetector) matchField(key string, value interface{}, data map[string]interface{}) bool {
	dataValue, exists := data[key]
	if !exists {
		return false
	}

	switch v := value.(type) {
	case string:
		strData, ok := dataValue.(string)
		if !ok {
			return false
		}

		// Handle wildcards
		if strings.Contains(v, "*") {
			return strings.Contains(strings.ToLower(strData), strings.ToLower(strings.Trim(v, "*")))
		}
		return strings.EqualFold(strData, v)

	case []interface{}:
		// OR logic: any value matches
		for _, item := range v {
			if d.matchField(key, item, data) {
				return true
			}
		}
		return false

	case map[string]interface{}:
		// Modifiers (contains, startswith, endswith, etc.)
		for modifier, modValue := range v {
			switch modifier {
			case "contains":
				strData, ok := dataValue.(string)
				if !ok {
					return false
				}
				strMod, ok := modValue.(string)
				if !ok {
					return false
				}
				if !strings.Contains(strings.ToLower(strData), strings.ToLower(strMod)) {
					return false
				}

			case "startswith":
				strData, ok := dataValue.(string)
				if !ok {
					return false
				}
				strMod, ok := modValue.(string)
				if !ok {
					return false
				}
				if !strings.HasPrefix(strings.ToLower(strData), strings.ToLower(strMod)) {
					return false
				}

			case "endswith":
				strData, ok := dataValue.(string)
				if !ok {
					return false
				}
				strMod, ok := modValue.(string)
				if !ok {
					return false
				}
				if !strings.HasSuffix(strings.ToLower(strData), strings.ToLower(strMod)) {
					return false
				}
			}
		}
		return true

	default:
		return fmt.Sprintf("%v", dataValue) == fmt.Sprintf("%v", value)
	}
}

func (d *SigmaDetector) levelToSeverity(level string) int {
	switch strings.ToLower(level) {
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}
