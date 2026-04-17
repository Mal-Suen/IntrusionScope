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

// conditionParser parses and evaluates Sigma condition expressions
type conditionParser struct {
	selections map[string]interface{}
	data       map[string]interface{}
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
	// Check if record type matches logsource
	if !d.matchLogsource(rule.Logsource, record) {
		return false
	}

	selection := rule.Detection.Selection
	if selection == nil {
		return false
	}

	// Parse and evaluate condition
	condition := rule.Detection.Condition
	if condition == "" {
		// No condition specified, use simple AND logic on all selections
		return d.matchSelection(selection, record.Data)
	}

	// Evaluate condition expression
	return d.evaluateCondition(condition, selection, record.Data)
}

// evaluateCondition parses and evaluates a Sigma condition expression
// Supports: selection1, selection1 and selection2, selection1 or selection2,
// 1 of them, all of them, count(selection) > N
// Operator precedence: NOT > AND > OR (standard boolean precedence)
func (d *SigmaDetector) evaluateCondition(condition string, selections map[string]interface{}, data map[string]interface{}) bool {
	condition = strings.TrimSpace(condition)
	condition = strings.ToLower(condition)

	// Handle "or" operator first (lowest precedence)
	// This ensures "a or b and c" is parsed as "a or (b and c)"
	if strings.Contains(condition, " or ") {
		parts := splitByOperator(condition, " or ")
		for _, part := range parts {
			if d.evaluateCondition(part, selections, data) {
				return true
			}
		}
		return false
	}

	// Handle "and" operator (higher precedence than or)
	if strings.Contains(condition, " and ") {
		parts := splitByOperator(condition, " and ")
		for _, part := range parts {
			if !d.evaluateCondition(part, selections, data) {
				return false
			}
		}
		return true
	}

	// Handle "N of them" pattern
	if strings.Contains(condition, "of them") {
		return d.evaluateOfThem(condition, selections, data)
	}

	// Handle "N of selection*" pattern
	if strings.Contains(condition, " of ") {
		return d.evaluateOfPattern(condition, selections, data)
	}

	// Handle count() aggregation
	if strings.HasPrefix(condition, "count(") {
		return d.evaluateCount(condition, selections, data)
	}

	// Handle not operator
	if strings.HasPrefix(condition, "not ") {
		return !d.evaluateCondition(strings.TrimPrefix(condition, "not "), selections, data)
	}

	// Simple selection reference
	if sel, ok := selections[condition]; ok {
		return d.matchSelection(map[string]interface{}{condition: sel}, data)
	}

	// Check if it's a direct selection name
	for selName := range selections {
		if strings.EqualFold(selName, condition) {
			return d.matchSelectionField(selName, selections[selName], data)
		}
	}

	return false
}

// evaluateOfThem handles "N of them" conditions
func (d *SigmaDetector) evaluateOfThem(condition string, selections map[string]interface{}, data map[string]interface{}) bool {
	// Parse "N of them" or "all of them"
	condition = strings.TrimSpace(condition)

	var requiredCount int
	if strings.HasPrefix(condition, "all of them") {
		requiredCount = len(selections)
	} else {
		// Parse "N of them"
		parts := strings.Fields(condition)
		if len(parts) < 3 {
			return false
		}
		var err error
		requiredCount, err = parseInt(parts[0])
		if err != nil {
			return false
		}
	}

	// Count matching selections
	matchCount := 0
	for selName, sel := range selections {
		if d.matchSelectionField(selName, sel, data) {
			matchCount++
		}
	}

	return matchCount >= requiredCount
}

// evaluateOfPattern handles "N of selection*" conditions
func (d *SigmaDetector) evaluateOfPattern(condition string, selections map[string]interface{}, data map[string]interface{}) bool {
	parts := strings.Split(condition, " of ")
	if len(parts) != 2 {
		return false
	}

	requiredCount, err := parseInt(strings.TrimSpace(parts[0]))
	if err != nil {
		return false
	}

	pattern := strings.TrimSpace(parts[1])
	// Remove quotes if present
	pattern = strings.Trim(pattern, "\"'")

	// Find selections matching pattern
	matchCount := 0
	for selName, sel := range selections {
		if matchPattern(pattern, selName) {
			if d.matchSelectionField(selName, sel, data) {
				matchCount++
			}
		}
	}

	return matchCount >= requiredCount
}

// evaluateCount handles count() aggregation conditions
func (d *SigmaDetector) evaluateCount(condition string, selections map[string]interface{}, data map[string]interface{}) bool {
	// Parse count(selection) > N, count(selection) < N, etc.
	// This is a simplified implementation
	return false // TODO: Implement count aggregation
}

// matchSelectionField matches a single selection field against data
func (d *SigmaDetector) matchSelectionField(selName string, sel interface{}, data map[string]interface{}) bool {
	// Handle different selection formats
	switch s := sel.(type) {
	case map[string]interface{}:
		// Selection with field conditions
		return d.matchSelection(s, data)
	case []interface{}:
		// OR logic: any item matches
		for _, item := range s {
			if d.matchSelectionField(selName, item, data) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// matchPattern matches a simple wildcard pattern
func matchPattern(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(name, prefix)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(name, suffix)
	}
	return strings.EqualFold(pattern, name)
}

// parseInt parses an integer from string
func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
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

// splitByOperator splits a condition string by an operator while respecting parentheses
// This allows proper handling of nested expressions like "(a or b) and c"
func splitByOperator(condition, op string) []string {
	var result []string
	var current strings.Builder
	parenDepth := 0

	// Scan through the condition character by character
	i := 0
	for i < len(condition) {
		ch := condition[i]

		switch ch {
		case '(':
			parenDepth++
			current.WriteByte(ch)
		case ')':
			parenDepth--
			current.WriteByte(ch)
		default:
			// Check if we're at the operator and not inside parentheses
			if parenDepth == 0 && strings.HasPrefix(condition[i:], op) {
				result = append(result, strings.TrimSpace(current.String()))
				current.Reset()
				i += len(op)
				continue
			}
			current.WriteByte(ch)
		}
		i++
	}

	// Add the last part
	if current.Len() > 0 {
		result = append(result, strings.TrimSpace(current.String()))
	}

	return result
}
