// Package detector provides threat detection capabilities
// This file contains YARA rule detection
package detector

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
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
	// Get content to scan
	content := d.getScannableContent(record)
	if content == "" {
		return false
	}

	// Check each string in the rule
	matchedStrings := make(map[string]bool)
	definedStrings := make(map[string]bool)

	for _, yaraString := range rule.Strings {
		definedStrings[yaraString.ID] = true
		if d.matchString(yaraString, content) {
			matchedStrings[yaraString.ID] = true
		}
	}

	// Evaluate condition
	condition := strings.TrimSpace(rule.Condition)
	if condition == "" {
		// Default: any of them
		return len(matchedStrings) > 0
	}

	return d.evaluateCondition(condition, matchedStrings, definedStrings)
}

// evaluateCondition evaluates a YARA condition expression
// Supports: any of them, all of them, $a, $a and $b, $a or $b, N of ($a, $b, $c)
func (d *YARADetector) evaluateCondition(condition string, matchedStrings map[string]bool, definedStrings map[string]bool) bool {
	condition = strings.ToLower(strings.TrimSpace(condition))

	// Handle "any of them"
	if condition == "any of them" {
		return len(matchedStrings) > 0
	}

	// Handle "all of them" - all defined strings must match
	if condition == "all of them" {
		if len(definedStrings) == 0 {
			return false
		}
		for strID := range definedStrings {
			if !matchedStrings[strID] {
				return false
			}
		}
		return true
	}

	// Handle "N of them"
	if strings.HasSuffix(condition, "of them") {
		parts := strings.Fields(condition)
		if len(parts) >= 1 {
			var required int
			if parts[0] == "any" {
				return len(matchedStrings) > 0
			}
			if parts[0] == "all" {
				for strID := range definedStrings {
					if !matchedStrings[strID] {
						return false
					}
				}
				return true
			}
			if _, err := fmt.Sscanf(parts[0], "%d", &required); err == nil {
				return len(matchedStrings) >= required
			}
		}
	}

	// Handle "N of ($a, $b, $c)" pattern
	if strings.Contains(condition, "of (") {
		return d.evaluateOfPattern(condition, matchedStrings)
	}

	// Handle "and" operator
	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		for _, part := range parts {
			if !d.evaluateCondition(part, matchedStrings, definedStrings) {
				return false
			}
		}
		return true
	}

	// Handle "or" operator
	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		for _, part := range parts {
			if d.evaluateCondition(part, matchedStrings, definedStrings) {
				return true
			}
		}
		return false
	}

	// Handle single string reference like $a or $a1
	if strings.HasPrefix(condition, "$") {
		return matchedStrings[condition]
	}

	// Default: check if any string matched
	return len(matchedStrings) > 0
}

// evaluateOfPattern handles "N of ($a, $b, $c)" conditions
func (d *YARADetector) evaluateOfPattern(condition string, matchedStrings map[string]bool) bool {
	// Parse "N of ($a, $b, $c)"
	match := regexp.MustCompile(`(\d+)\s+of\s+\(([^)]+)\)`).FindStringSubmatch(condition)
	if len(match) < 3 {
		return false
	}

	required, err := strconv.Atoi(match[1])
	if err != nil {
		return false
	}

	// Parse string IDs
	stringIDs := strings.Split(match[2], ",")
	count := 0
	for _, id := range stringIDs {
		id = strings.TrimSpace(id)
		if matchedStrings[id] {
			count++
		}
	}

	return count >= required
}

func (d *YARADetector) matchString(yaraString YARAString, content string) bool {
	switch yaraString.Type {
	case "text":
		return strings.Contains(content, yaraString.Value)

	case "hex":
		// Hex matching: convert hex pattern to binary and search
		hexValue := strings.ReplaceAll(yaraString.Value, " ", "")
		hexValue = strings.ReplaceAll(hexValue, "\t", "")
		hexValue = strings.ReplaceAll(hexValue, "\n", "")
		
		// Handle wildcards (?) - convert to regex pattern
		if strings.Contains(hexValue, "?") {
			// Convert hex with wildcards to regex
			regexPattern := ""
			for i := 0; i < len(hexValue); i += 2 {
				if i+1 >= len(hexValue) {
					break
				}
				hexPair := hexValue[i : i+1]
				if hexPair == "??" || hexPair == "?" {
					regexPattern += "."
				} else if strings.Contains(hexPair, "?") {
					// Partial wildcard like "A?"
					regexPattern += "[" + string(hexPair[0]) + "0-9a-fA-F]"
				} else {
					// Convert hex pair to character
					regexPattern += regexp.QuoteMeta(string(hexPair))
				}
			}
			matched, _ := regexp.MatchString("(?i)"+regexPattern, content)
			return matched
		}
		
		// Simple hex matching without wildcards
		return strings.Contains(content, hexValue)

	case "regex":
		// Proper regex matching
		pattern := yaraString.Value
		
		// Handle YARA regex syntax variations
		// YARA uses /regex/ syntax, remove delimiters if present
		if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
			pattern = strings.TrimSuffix(strings.TrimPrefix(pattern, "/"), "/")
		} else if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/i") {
			// Case insensitive flag
			pattern = strings.TrimSuffix(strings.TrimPrefix(pattern, "/"), "/i")
			matched, err := regexp.MatchString("(?i)"+pattern, content)
			if err != nil {
				// Invalid regex, fall back to substring match
				return strings.Contains(content, pattern)
			}
			return matched
		}
		
		// Compile and match the regex
		matched, err := regexp.MatchString(pattern, content)
		if err != nil {
			// Invalid regex pattern, fall back to substring match
			// This handles edge cases where YARA regex syntax differs from Go regex
			return strings.Contains(content, pattern)
		}
		return matched

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
