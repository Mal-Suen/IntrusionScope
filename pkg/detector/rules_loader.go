// Package detector provides threat detection capabilities
// This file contains Sigma rule parsing and loading
package detector

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SigmaLoader handles loading Sigma rules from files
type SigmaLoader struct {
	rulesDir string
}

// NewSigmaLoader creates a new Sigma rule loader
func NewSigmaLoader(rulesDir string) *SigmaLoader {
	return &SigmaLoader{
		rulesDir: rulesDir,
	}
}

// LoadFromDir loads all Sigma rules from a directory
func (l *SigmaLoader) LoadFromDir() ([]SigmaRule, error) {
	var rules []SigmaRule

	err := filepath.Walk(l.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Only process YAML files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		rule, err := l.LoadFromFile(path)
		if err != nil {
			// Log error but continue
			fmt.Printf("Warning: failed to load Sigma rule %s: %v\n", path, err)
			return nil
		}

		rules = append(rules, rule...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk rules directory: %w", err)
	}

	return rules, nil
}

// LoadFromFile loads Sigma rules from a single file
func (l *SigmaLoader) LoadFromFile(path string) ([]SigmaRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return l.ParseYAML(data)
}

// ParseYAML parses Sigma rules from YAML content
func (l *SigmaLoader) ParseYAML(data []byte) ([]SigmaRule, error) {
	// Parse YAML into generic structure
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Check if it's a valid Sigma rule
	if _, ok := raw["detection"]; !ok {
		return nil, fmt.Errorf("not a valid Sigma rule: missing detection section")
	}

	rule := SigmaRule{
		Raw: string(data),
	}

	// Parse basic fields
	if id, ok := raw["id"].(string); ok {
		rule.ID = id
	}
	if title, ok := raw["title"].(string); ok {
		rule.Title = title
	}
	if desc, ok := raw["description"].(string); ok {
		rule.Description = desc
	}
	if level, ok := raw["level"].(string); ok {
		rule.Level = level
	}
	if status, ok := raw["status"].(string); ok {
		rule.Status = status
	}
	if author, ok := raw["author"].(string); ok {
		rule.Author = author
	}

	// Parse tags
	if tags, ok := raw["tags"].([]interface{}); ok {
		for _, t := range tags {
			if tag, ok := t.(string); ok {
				rule.Tags = append(rule.Tags, tag)
			}
		}
	}

	// Parse false positives
	if fps, ok := raw["falsepositives"].([]interface{}); ok {
		for _, fp := range fps {
			if fpStr, ok := fp.(string); ok {
				rule.FalsePositives = append(rule.FalsePositives, fpStr)
			}
		}
	}

	// Parse logsource
	if logsource, ok := raw["logsource"].(map[string]interface{}); ok {
		if cat, ok := logsource["category"].(string); ok {
			rule.Logsource.Category = cat
		}
		if prod, ok := logsource["product"].(string); ok {
			rule.Logsource.Product = prod
		}
		if svc, ok := logsource["service"].(string); ok {
			rule.Logsource.Service = svc
		}
	}

	// Parse detection
	if detection, ok := raw["detection"].(map[string]interface{}); ok {
		// Parse condition
		if cond, ok := detection["condition"].(string); ok {
			rule.Detection.Condition = cond
		}

		// Parse timeframe
		if tf, ok := detection["timeframe"].(string); ok {
			rule.Detection.Timeframe = tf
		}

		// Parse selections (everything except condition and timeframe)
		selection := make(map[string]interface{})
		for k, v := range detection {
			if k != "condition" && k != "timeframe" {
				selection[k] = v
			}
		}
		rule.Detection.Selection = selection
	}

	return []SigmaRule{rule}, nil
}

// Validate validates a Sigma rule
func (l *SigmaLoader) Validate(rule *SigmaRule) error {
	if rule.Title == "" {
		return fmt.Errorf("rule missing title")
	}
	if rule.Detection.Condition == "" {
		return fmt.Errorf("rule missing condition")
	}
	if len(rule.Detection.Selection) == 0 {
		return fmt.Errorf("rule has no detection selection")
	}
	return nil
}

// YARALoader handles loading YARA rules from files
type YARALoader struct {
	rulesDir string
}

// NewYARALoader creates a new YARA rule loader
func NewYARALoader(rulesDir string) *YARALoader {
	return &YARALoader{
		rulesDir: rulesDir,
	}
}

// LoadFromDir loads all YARA rules from a directory
func (l *YARALoader) LoadFromDir() ([]YARARule, error) {
	var rules []YARARule

	err := filepath.Walk(l.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Only process YARA files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yar" && ext != ".yara" {
			return nil
		}

		fileRules, err := l.LoadFromFile(path)
		if err != nil {
			fmt.Printf("Warning: failed to load YARA rules %s: %v\n", path, err)
			return nil
		}

		rules = append(rules, fileRules...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk rules directory: %w", err)
	}

	return rules, nil
}

// LoadFromFile loads YARA rules from a single file
func (l *YARALoader) LoadFromFile(path string) ([]YARARule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return l.Parse(string(data))
}

// Parse parses YARA rules from text content
func (l *YARALoader) Parse(content string) ([]YARARule, error) {
	var rules []YARARule

	// Simple YARA parser
	// Rule pattern: rule <name> [: <tags>] { ... }
	rulePattern := regexp.MustCompile(`(?s)rule\s+(\w+)\s*(?::\s*([^\{]+))?\s*\{([^}]+)\}`)
	matches := rulePattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		rule := YARARule{
			Name:  match[1],
			Raw:   match[0],
			Meta:  make(map[string]string),
		}

		// Parse tags
		if match[2] != "" {
			tags := strings.Split(match[2], " ")
			for _, tag := range tags {
				tag = strings.TrimSpace(tag)
				if tag != "" && tag != ":" {
					rule.Tags = append(rule.Tags, strings.TrimSuffix(tag, ","))
				}
			}
		}

		// Parse rule body
		body := match[3]
		l.parseRuleBody(&rule, body)

		rules = append(rules, rule)
	}

	return rules, nil
}

// parseRuleBody parses the body of a YARA rule
func (l *YARALoader) parseRuleBody(rule *YARARule, body string) {
	// Parse meta section (simplified without lookahead)
	metaStart := strings.Index(body, "meta:")
	if metaStart != -1 {
		metaEnd := strings.Index(body[metaStart:], "strings:")
		if metaEnd == -1 {
			metaEnd = strings.Index(body[metaStart:], "condition:")
		}
		if metaEnd == -1 {
			metaEnd = len(body) - metaStart
		}
		l.parseMeta(rule, body[metaStart+5:metaStart+metaEnd])
	}

	// Parse strings section
	stringsStart := strings.Index(body, "strings:")
	if stringsStart != -1 {
		stringsEnd := strings.Index(body[stringsStart:], "condition:")
		if stringsEnd == -1 {
			stringsEnd = len(body) - stringsStart
		}
		l.parseStrings(rule, body[stringsStart+8:stringsStart+stringsEnd])
	}

	// Parse condition
	condStart := strings.Index(body, "condition:")
	if condStart != -1 {
		rule.Condition = strings.TrimSpace(body[condStart+10:])
	}
}

// parseMeta parses the meta section of a YARA rule
func (l *YARALoader) parseMeta(rule *YARARule, meta string) {
	// Pattern: key = "value" or key = value
	metaPattern := regexp.MustCompile(`(\w+)\s*=\s*"([^"]*)"|(\w+)\s*=\s*(\S+)`)
	matches := metaPattern.FindAllStringSubmatch(meta, -1)

	for _, match := range matches {
		if match[1] != "" && match[2] != "" {
			rule.Meta[match[1]] = match[2]
		} else if match[3] != "" && match[4] != "" {
			rule.Meta[match[3]] = match[4]
		}
	}
}

// parseStrings parses the strings section of a YARA rule
func (l *YARALoader) parseStrings(rule *YARARule, stringsSection string) {
	// Pattern: $id = "text" or $id = { hex } or $id = /regex/
	// Text: $id = "value" [ascii|wide|nocase]
	textPattern := regexp.MustCompile(`(\$\w+)\s*=\s*"([^"]*)"(\s+\w+)*`)
	textMatches := textPattern.FindAllStringSubmatch(stringsSection, -1)
	for _, match := range textMatches {
		if len(match) >= 3 {
			rule.Strings = append(rule.Strings, YARAString{
				ID:    match[1],
				Type:  "text",
				Value: match[2],
			})
		}
	}

	// Hex: $id = { hex bytes }
	hexPattern := regexp.MustCompile(`(\$\w+)\s*=\s*\{([^}]+)\}`)
	hexMatches := hexPattern.FindAllStringSubmatch(stringsSection, -1)
	for _, match := range hexMatches {
		if len(match) >= 3 {
			rule.Strings = append(rule.Strings, YARAString{
				ID:    match[1],
				Type:  "hex",
				Value: strings.TrimSpace(match[2]),
			})
		}
	}

	// Regex: $id = /pattern/
	regexPattern := regexp.MustCompile(`(\$\w+)\s*=\s*/([^/]+)/`)
	regexMatches := regexPattern.FindAllStringSubmatch(stringsSection, -1)
	for _, match := range regexMatches {
		if len(match) >= 3 {
			rule.Strings = append(rule.Strings, YARAString{
				ID:    match[1],
				Type:  "regex",
				Value: match[2],
			})
		}
	}
}
