// Package detector provides threat detection capabilities
// This file contains YARA rule detection
package detector

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// YARADetector detects threats using YARA rules
type YARADetector struct {
	rules []*YARARule
}

// YARARule represents a parsed YARA rule
type YARARule struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Tags        []string          `json:"tags"`
	Meta        map[string]string `json:"meta"`
	Strings     []YARAString      `json:"strings"`
	Condition   string            `json:"condition"`
	Raw         string            `json:"raw"`
}

// YARAString represents a YARA string definition
type YARAString struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // text, hex, regex
	Value string `json:"value"`
}

// NewYARADetector creates a new YARA detector
func NewYARADetector() *YARADetector {
	return &YARADetector{
		rules: []*YARARule{},
	}
}

func (d *YARADetector) Name() string {
	return "yara"
}

func (d *YARADetector) Description() string {
	return "Detects threats using YARA rules"
}

func (d *YARADetector) IsAvailable() bool {
	return true
}

// LoadRules loads YARA rules into the detector
func (d *YARADetector) LoadRules(rules []YARARule) error {
	for i := range rules {
		d.rules = append(d.rules, &rules[i])
	}
	return nil
}

func (d *YARADetector) Detect(ctx context.Context, input *DetectionInput) (*DetectionResult, error) {
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
				severity := d.getSeverity(rule)

				match := Match{
					SignatureID:   rule.Name,
					SignatureName: rule.Name,
					Severity:      severity,
					RecordIndex:   i,
					RecordData:    record.Data,
					MatchDetails: map[string]interface{}{
						"rule_name": rule.Name,
						"namespace": rule.Namespace,
						"meta":      rule.Meta,
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

func (d *YARADetector) matchRule(rule *YARARule, record Record) bool {
	// Simplified YARA matching
	// TODO: Implement full YARA condition parser

	// Get content to scan
	content := d.getScannableContent(record)
	if content == "" {
		return false
	}

	// Check each string in the rule
	matchedStrings := make(map[string]bool)

	for _, yaraString := range rule.Strings {
		if d.matchString(yaraString, content) {
			matchedStrings[yaraString.ID] = true
		}
	}

	// Simple condition: any of them
	// TODO: Implement proper condition evaluation
	return len(matchedStrings) > 0
}

func (d *YARADetector) matchString(yaraString YARAString, content string) bool {
	switch yaraString.Type {
	case "text":
		return strings.Contains(content, yaraString.Value)

	case "hex":
		// Simplified hex matching
		hexValue := strings.ReplaceAll(yaraString.Value, " ", "")
		hexValue = strings.ReplaceAll(hexValue, "?", "")
		return strings.Contains(content, hexValue)

	case "regex":
		// Simplified regex matching (exact substring for now)
		// TODO: Implement proper regex matching
		pattern := yaraString.Value
		pattern = strings.Trim(pattern, "/")
		pattern = strings.ReplaceAll(pattern, ".*", "")
		return strings.Contains(content, pattern)

	default:
		return false
	}
}

func (d *YARADetector) getScannableContent(record Record) string {
	var content strings.Builder

	// Concatenate all string values from the record
	for _, v := range record.Data {
		switch val := v.(type) {
		case string:
			content.WriteString(val)
			content.WriteString(" ")
		case []byte:
			content.Write(val)
		}
	}

	return content.String()
}

func (d *YARADetector) getSeverity(rule *YARARule) int {
	if rule.Meta == nil {
		return SeverityMedium
	}

	// Check meta for severity
	if severity, ok := rule.Meta["severity"]; ok {
		switch strings.ToLower(severity) {
		case "low":
			return SeverityLow
		case "medium":
			return SeverityMedium
		case "high":
			return SeverityHigh
		case "critical":
			return SeverityCritical
		}
	}

	// Check tags for severity
	for _, tag := range rule.Tags {
		switch strings.ToLower(tag) {
		case "apt":
			return SeverityCritical
		case "malware":
			return SeverityHigh
		case "suspicious":
			return SeverityMedium
		}
	}

	return SeverityMedium
}
