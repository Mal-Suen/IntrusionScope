// Package signature provides threat signature library management
package signature

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus-labs/intrusionscope/pkg/detector"
)

// SignatureType represents the type of signature
type SignatureType string

const (
	TypeIOC   SignatureType = "ioc"
	TypeSigma SignatureType = "sigma"
	TypeYARA  SignatureType = "yara"
)

// Signature represents a threat signature
type Signature struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        SignatureType          `json:"type"`
	Severity    int                    `json:"severity"`
	Description string                 `json:"description"`
	Rule        string                 `json:"rule"`
	Metadata    map[string]interface{} `json:"metadata"`
	Tags        []string               `json:"tags"`
	Source      string                 `json:"source"`      // Where it came from
	UpdatedAt   time.Time              `json:"updated_at"`
	Enabled     bool                   `json:"enabled"`
}

// Library manages the signature library
type Library struct {
	mu         sync.RWMutex
	signatures map[string]*Signature
	byType     map[SignatureType][]string
	byTag      map[string][]string
	bySource   map[string][]string
	cacheDir   string
}

// NewLibrary creates a new signature library
func NewLibrary(cacheDir string) *Library {
	return &Library{
		signatures: make(map[string]*Signature),
		byType:     make(map[SignatureType][]string),
		byTag:      make(map[string][]string),
		bySource:   make(map[string][]string),
		cacheDir:   cacheDir,
	}
}

// Add adds a signature to the library
func (l *Library) Add(sig *Signature) error {
	if sig.ID == "" {
		return fmt.Errorf("signature must have an ID")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.signatures[sig.ID] = sig
	l.byType[sig.Type] = append(l.byType[sig.Type], sig.ID)

	for _, tag := range sig.Tags {
		l.byTag[tag] = append(l.byTag[tag], sig.ID)
	}

	if sig.Source != "" {
		l.bySource[sig.Source] = append(l.bySource[sig.Source], sig.ID)
	}

	return nil
}

// Get retrieves a signature by ID
func (l *Library) Get(id string) (*Signature, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	sig, ok := l.signatures[id]
	return sig, ok
}

// Remove removes a signature from the library
func (l *Library) Remove(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	sig, ok := l.signatures[id]
	if !ok {
		return
	}

	delete(l.signatures, id)

	// Remove from indexes
	if slice, ok := l.byType[sig.Type]; ok {
		l.byType[sig.Type] = l.removeFromSliceValue(slice, id)
	}
	for _, tag := range sig.Tags {
		if slice, ok := l.byTag[tag]; ok {
			l.byTag[tag] = l.removeFromSliceValue(slice, id)
		}
	}
	if sig.Source != "" {
		if slice, ok := l.bySource[sig.Source]; ok {
			l.bySource[sig.Source] = l.removeFromSliceValue(slice, id)
		}
	}
}

func (l *Library) removeFromSliceValue(slice []string, id string) []string {
	for i, s := range slice {
		if s == id {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// List returns all signature IDs
func (l *Library) List() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	ids := make([]string, 0, len(l.signatures))
	for id := range l.signatures {
		ids = append(ids, id)
	}
	return ids
}

// ListByType returns signatures of a specific type
func (l *Library) ListByType(typ SignatureType) []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.byType[typ]
}

// ListByTag returns signatures with a specific tag
func (l *Library) ListByTag(tag string) []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.byTag[tag]
}

// ListBySource returns signatures from a specific source
func (l *Library) ListBySource(source string) []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.bySource[source]
}

// GetDetectorSignatures returns signatures in detector format
func (l *Library) GetDetectorSignatures(typ SignatureType, minSeverity int) []detector.Signature {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []detector.Signature

	for _, id := range l.byType[typ] {
		sig := l.signatures[id]
		if !sig.Enabled || sig.Severity < minSeverity {
			continue
		}

		result = append(result, detector.Signature{
			ID:          sig.ID,
			Name:        sig.Name,
			Type:        string(sig.Type),
			Severity:    sig.Severity,
			Description: sig.Description,
			Rule:        sig.Rule,
			Metadata:    sig.Metadata,
			Tags:        sig.Tags,
		})
	}

	return result
}

// Stats returns library statistics
func (l *Library) Stats() LibraryStats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := LibraryStats{
		Total:       len(l.signatures),
		ByType:      make(map[string]int),
		BySource:    make(map[string]int),
		BySeverity:  make(map[int]int),
	}

	for typ, ids := range l.byType {
		stats.ByType[string(typ)] = len(ids)
	}

	for source, ids := range l.bySource {
		stats.BySource[source] = len(ids)
	}

	for _, sig := range l.signatures {
		stats.BySeverity[sig.Severity]++
		if sig.Enabled {
			stats.Enabled++
		}
	}

	return stats
}

// LibraryStats contains library statistics
type LibraryStats struct {
	Total      int            `json:"total"`
	Enabled    int            `json:"enabled"`
	ByType     map[string]int `json:"by_type"`
	BySource   map[string]int `json:"by_source"`
	BySeverity map[int]int    `json:"by_severity"`
}

// Save saves the library to disk
func (l *Library) Save() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if err := os.MkdirAll(l.cacheDir, 0755); err != nil {
		return err
	}

	// Save each type separately
	for typ := range l.byType {
		filename := filepath.Join(l.cacheDir, string(typ)+".json")
		if err := l.saveType(typ, filename); err != nil {
			return err
		}
	}

	// Save metadata
	metadata := map[string]interface{}{
		"updated_at": time.Now(),
		"stats":      l.Stats(),
	}
	metadataFile := filepath.Join(l.cacheDir, "metadata.json")
	data, _ := json.MarshalIndent(metadata, "", "  ")
	return os.WriteFile(metadataFile, data, 0644)
}

func (l *Library) saveType(typ SignatureType, filename string) error {
	var signatures []*Signature
	for _, id := range l.byType[typ] {
		signatures = append(signatures, l.signatures[id])
	}

	data, err := json.MarshalIndent(signatures, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// Load loads the library from disk
func (l *Library) Load() error {
	if l.cacheDir == "" {
		return nil
	}

	files, err := filepath.Glob(filepath.Join(l.cacheDir, "*.json"))
	if err != nil {
		return err
	}

	for _, file := range files {
		if strings.HasSuffix(file, "metadata.json") {
			continue
		}

		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var signatures []*Signature
		if err := json.Unmarshal(data, &signatures); err != nil {
			continue
		}

		for _, sig := range signatures {
			sig.Enabled = true
			l.Add(sig)
		}
	}

	return nil
}

// Clear removes all signatures from the library
func (l *Library) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.signatures = make(map[string]*Signature)
	l.byType = make(map[SignatureType][]string)
	l.byTag = make(map[string][]string)
	l.bySource = make(map[string][]string)
}

// Count returns the total number of signatures
func (l *Library) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return len(l.signatures)
}
