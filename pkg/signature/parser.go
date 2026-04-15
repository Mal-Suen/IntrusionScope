// Package signature provides threat signature library management
// This file contains signature parsers for various formats
package signature

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parser parses signatures from various formats
type Parser struct{}

// NewParser creates a new signature parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseIOC parses an IOC from JSON format
func (p *Parser) ParseIOC(data []byte, source string) ([]*Signature, error) {
	var iocs []struct {
		ID          string                 `json:"id"`
		Indicator   string                 `json:"indicator"`
		Type        string                 `json:"type"` // hash, ip, domain, url, email
		ThreatType  string                 `json:"threat_type"`
		Description string                 `json:"description"`
		Tags        []string               `json:"tags"`
		Confidence  int                    `json:"confidence"`
		Metadata    map[string]interface{} `json:"metadata"`
	}

	if err := json.Unmarshal(data, &iocs); err != nil {
		return nil, err
	}

	var signatures []*Signature
	for _, ioc := range iocs {
		severity := p.confidenceToSeverity(ioc.Confidence)

		sig := &Signature{
			ID:          ioc.ID,
			Name:        ioc.Indicator,
			Type:        TypeIOC,
			Severity:    severity,
			Description: ioc.Description,
			Tags:        ioc.Tags,
			Source:      source,
			Metadata: map[string]interface{}{
				"type":        ioc.Type,
				"value":       ioc.Indicator,
				"threat_type": ioc.ThreatType,
			},
			Enabled: true,
		}

		if sig.ID == "" {
			sig.ID = fmt.Sprintf("ioc-%s-%s", ioc.Type, ioc.Indicator)
		}

		signatures = append(signatures, sig)
	}

	return signatures, nil
}

// ParseSigma parses a Sigma rule from YAML format
func (p *Parser) ParseSigma(data []byte, source string) ([]*Signature, error) {
	var rule struct {
		ID          string                 `yaml:"id"`
		Title       string                 `yaml:"title"`
		Description string                 `yaml:"description"`
		Level       string                 `yaml:"level"`
		Status      string                 `yaml:"status"`
		Author      string                 `yaml:"author"`
		Tags        []string               `yaml:"tags"`
		Logsource   map[string]string      `yaml:"logsource"`
		Detection   map[string]interface{} `yaml:"detection"`
		FalsePositives []string            `yaml:"falsepositives"`
	}

	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, err
	}

	severity := p.levelToSeverity(rule.Level)

	// Convert detection to string for storage
	detectionBytes, _ := yaml.Marshal(rule.Detection)

	sig := &Signature{
		ID:          rule.ID,
		Name:        rule.Title,
		Type:        TypeSigma,
		Severity:    severity,
		Description: rule.Description,
		Rule:        string(detectionBytes),
		Tags:        rule.Tags,
		Source:      source,
		Metadata: map[string]interface{}{
			"level":           rule.Level,
			"status":          rule.Status,
			"author":          rule.Author,
			"false_positives": rule.FalsePositives,
			"logsource":       rule.Logsource,
		},
		Enabled: true,
	}

	if sig.ID == "" {
		sig.ID = fmt.Sprintf("sigma-%s", strings.ReplaceAll(strings.ToLower(rule.Title), " ", "-"))
	}

	return []*Signature{sig}, nil
}

// ParseYARA parses a YARA rule
func (p *Parser) ParseYARA(data []byte, source string) ([]*Signature, error) {
	// Simple YARA parser
	// TODO: Implement full YARA parsing

	content := string(data)
	var signatures []*Signature

	// Find rule blocks
	lines := strings.Split(content, "\n")
	var currentRule *Signature
	var inStrings bool
	var inCondition bool

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || line == "" {
			continue
		}

		// Start of rule
		if strings.HasPrefix(line, "rule ") {
			if currentRule != nil {
				signatures = append(signatures, currentRule)
			}

			// Parse rule name and tags
			parts := strings.Fields(line)
			name := strings.TrimSuffix(parts[1], "{")

			currentRule = &Signature{
				ID:        fmt.Sprintf("yara-%s", name),
				Name:      name,
				Type:      TypeYARA,
				Source:    source,
				Enabled:   true,
				Metadata:  make(map[string]interface{}),
				Tags:      []string{},
			}

			// Parse tags
			if strings.Contains(line, ":") {
				tagPart := strings.Split(line, ":")[0]
				tagPart = strings.TrimPrefix(tagPart, "rule "+name)
				tags := strings.Fields(tagPart)
				for _, tag := range tags {
					if tag != "" {
						currentRule.Tags = append(currentRule.Tags, tag)
					}
				}
			}

			inStrings = false
			inCondition = false
			continue
		}

		if currentRule == nil {
			continue
		}

		// Parse meta section
		if strings.HasPrefix(line, "meta:") || strings.HasPrefix(line, "meta {") {
			continue
		}

		if strings.Contains(line, "=") && !inStrings && !inCondition {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				currentRule.Metadata[key] = value

				// Handle common meta fields
				switch key {
				case "description":
					currentRule.Description = value
				case "author":
					currentRule.Metadata["author"] = value
				case "severity":
					currentRule.Severity = p.levelToSeverity(value)
				}
			}
		}

		// Parse strings section
		if strings.HasPrefix(line, "strings:") || strings.HasPrefix(line, "strings {") {
			inStrings = true
			inCondition = false
			continue
		}

		// Parse condition section
		if strings.HasPrefix(line, "condition:") || strings.HasPrefix(line, "condition {") {
			inStrings = false
			inCondition = true
			continue
		}

		// End of rule
		if line == "}" {
			inStrings = false
			inCondition = false
		}
	}

	// Add last rule
	if currentRule != nil {
		currentRule.Rule = content
		signatures = append(signatures, currentRule)
	}

	return signatures, nil
}

// ParseAuto automatically detects format and parses
func (p *Parser) ParseAuto(data []byte, source string) ([]*Signature, error) {
	// Try to detect format
	content := strings.TrimSpace(string(data))

	// Check for YAML (Sigma)
	if strings.HasPrefix(content, "title:") ||
		strings.HasPrefix(content, "id:") ||
		strings.Contains(content, "logsource:") {
		return p.ParseSigma(data, source)
	}

	// Check for YARA
	if strings.HasPrefix(content, "rule ") {
		return p.ParseYARA(data, source)
	}

	// Try JSON (IOC)
	if strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") {
		return p.ParseIOC(data, source)
	}

	return nil, fmt.Errorf("unable to detect signature format")
}

func (p *Parser) confidenceToSeverity(confidence int) int {
	switch {
	case confidence >= 90:
		return 5 // Critical
	case confidence >= 70:
		return 4 // High
	case confidence >= 50:
		return 3 // Medium
	case confidence >= 30:
		return 2 // Low
	default:
		return 1 // Info
	}
}

func (p *Parser) levelToSeverity(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium", "mid":
		return 3
	case "low":
		return 2
	case "informational", "info":
		return 1
	default:
		return 3 // Default to medium
	}
}
