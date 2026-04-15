// Package artifact provides YAML-based artifact definitions and loading
package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Artifact represents a forensic artifact definition
type Artifact struct {
	// Metadata
	Name        string            `yaml:"name"`
	Version     string            `yaml:"version"`
	Author      string            `yaml:"author"`
	Description string            `yaml:"description"`
	References  []string          `yaml:"references"`
	Tags        []string          `yaml:"tags"`
	Platform    []string          `yaml:"platform"` // linux, windows, all

	// Parameters
	Parameters []Parameter `yaml:"parameters"`

	// Sources
	Sources []Source `yaml:"sources"`

	// Analysis
	Analysis Analysis `yaml:"analysis"`

	// Output
	Output Output `yaml:"output"`
}

// Parameter defines an artifact parameter
type Parameter struct {
	Name        string      `yaml:"name"`
	Type        string      `yaml:"type"` // string, int, bool, list
	Default     interface{} `yaml:"default"`
	Description string      `yaml:"description"`
	Required    bool        `yaml:"required"`
}

// Source defines where to collect data from
type Source struct {
	Name       string                 `yaml:"name"`
	Query      string                 `yaml:"query"`
	Type       string                 `yaml:"type"` // process, file, registry, network, etc.
	Platform   string                 `yaml:"platform"`
	Conditions []Condition            `yaml:"conditions"`
	Options    map[string]interface{} `yaml:"options"`
}

// Condition defines a precondition for collection
type Condition struct {
	Type    string      `yaml:"type"`    // file_exists, registry_exists, etc.
	Path    string      `yaml:"path"`    // Path to check
	Value   interface{} `yaml:"value"`   // Expected value
	Compare string      `yaml:"compare"` // equals, contains, matches
}

// Analysis defines post-processing rules
type Analysis struct {
	Queries    []Query    `yaml:"queries"`
	Enrichment []Enrich   `yaml:"enrichment"`
	Scoring    []ScoreRule `yaml:"scoring"`
}

// Query defines an analysis query
type Query struct {
	Name      string `yaml:"name"`
	Query     string `yaml:"query"`
	Severity  int    `yaml:"severity"`
	Condition string `yaml:"condition"`
}

// Enrich defines data enrichment rules
type Enrich struct {
	Type   string `yaml:"type"`   // hash, vt_lookup, etc.
	Fields []string `yaml:"fields"`
	Target string `yaml:"target"` // Target field to store result
}

// ScoreRule defines a scoring rule
type ScoreRule struct {
	Name      string `yaml:"name"`
	Condition string `yaml:"condition"`
	Score     int    `yaml:"score"`
}

// Output defines output configuration
type Output struct {
	Format    string   `yaml:"format"`    // json, csv, table
	Fields    []string `yaml:"fields"`    // Fields to include
	SortBy    string   `yaml:"sort_by"`   // Sort field
	SortOrder string   `yaml:"sort_order"` // asc, desc
}

// Loader loads artifacts from files
type Loader struct {
	paths      []string
	artifacts  map[string]*Artifact
	categories map[string][]string
}

// NewLoader creates a new artifact loader
func NewLoader(paths ...string) *Loader {
	return &Loader{
		paths:      paths,
		artifacts:  make(map[string]*Artifact),
		categories: make(map[string][]string),
	}
}

// Load loads all artifacts from configured paths
func (l *Loader) Load() error {
	for _, path := range l.paths {
		if err := l.loadPath(path); err != nil {
			return err
		}
	}
	return nil
}

func (l *Loader) loadPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat path %s: %w", path, err)
	}

	if info.IsDir() {
		return l.loadDirectory(path)
	}

	return l.loadFile(path)
}

func (l *Loader) loadDirectory(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if strings.HasSuffix(strings.ToLower(path), ".yaml") ||
			strings.HasSuffix(strings.ToLower(path), ".yml") {
			return l.loadFile(path)
		}

		return nil
	})
}

func (l *Loader) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read artifact file %s: %w", path, err)
	}

	var artifact Artifact
	if err := yaml.Unmarshal(data, &artifact); err != nil {
		return fmt.Errorf("failed to parse artifact file %s: %w", path, err)
	}

	// Validate artifact
	if artifact.Name == "" {
		return fmt.Errorf("artifact in %s has no name", path)
	}

	// Store artifact
	l.artifacts[artifact.Name] = &artifact

	// Categorize by tags
	for _, tag := range artifact.Tags {
		l.categories[tag] = append(l.categories[tag], artifact.Name)
	}

	return nil
}

// Get retrieves an artifact by name
func (l *Loader) Get(name string) (*Artifact, bool) {
	artifact, ok := l.artifacts[name]
	return artifact, ok
}

// List returns all artifact names
func (l *Loader) List() []string {
	names := make([]string, 0, len(l.artifacts))
	for name := range l.artifacts {
		names = append(names, name)
	}
	return names
}

// ListByTag returns artifacts with a specific tag
func (l *Loader) ListByTag(tag string) []string {
	return l.categories[tag]
}

// ListByPlatform returns artifacts for a specific platform
func (l *Loader) ListByPlatform(platform string) []string {
	var names []string
	for name, artifact := range l.artifacts {
		for _, p := range artifact.Platform {
			if p == platform || p == "all" {
				names = append(names, name)
				break
			}
		}
	}
	return names
}

// ResolveParameters resolves artifact parameters with provided values
func (a *Artifact) ResolveParameters(provided map[string]interface{}) map[string]interface{} {
	resolved := make(map[string]interface{})

	// Set defaults
	for _, param := range a.Parameters {
		if param.Default != nil {
			resolved[param.Name] = param.Default
		}
	}

	// Override with provided values
	for name, value := range provided {
		resolved[name] = value
	}

	return resolved
}

// ValidateParameters validates that all required parameters are provided
func (a *Artifact) ValidateParameters(params map[string]interface{}) error {
	for _, param := range a.Parameters {
		if param.Required {
			if _, ok := params[param.Name]; !ok {
				return fmt.Errorf("required parameter '%s' not provided", param.Name)
			}
		}
	}
	return nil
}

// GetQuery returns the IFQL query for a source with parameters substituted
func (s *Source) GetQuery(params map[string]interface{}) string {
	query := s.Query

	// Substitute parameters
	for name, value := range params {
		placeholder := fmt.Sprintf("{{.%s}}", name)
		query = strings.ReplaceAll(query, placeholder, fmt.Sprintf("%v", value))
	}

	return query
}
