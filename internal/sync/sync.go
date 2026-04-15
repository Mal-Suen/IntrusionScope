// Package sync provides signature library synchronization
package sync

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus-labs/intrusionscope/internal/config"
	"github.com/prometheus-labs/intrusionscope/internal/logger"
)

// Source represents a signature source
type Source struct {
	Name        string
	URL         string
	Enabled     bool
	LastSync    time.Time
	SignatureCount int
}

// Result holds sync operation results
type Result struct {
	SourcesSynced    int
	SignaturesAdded  int
	SignaturesUpdated int
	Errors           int
	Duration         time.Duration
}

// Manager manages signature synchronization
type Manager struct {
	config  *config.Config
	logger  *logger.Logger
	client  *http.Client
	sources map[string]*Source
}

// NewManager creates a new sync manager
func NewManager(cfg *config.Config, log *logger.Logger) *Manager {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	m := &Manager{
		config: cfg,
		logger: log,
		client: client,
		sources: make(map[string]*Source),
	}

	// Initialize sources
	m.initSources()

	return m
}

func (m *Manager) initSources() {
	// Define available sources
	defaultSources := map[string]Source{
		"malwarebazaar": {
			Name:    "MalwareBazaar",
			URL:     "https://bazaar.abuse.ch/export/",
			Enabled: true,
		},
		"urlhaus": {
			Name:    "URLhaus",
			URL:     "https://urlhaus.abuse.ch/api/",
			Enabled: true,
		},
		"threatfox": {
			Name:    "ThreatFox",
			URL:     "https://threatfox.abuse.ch/api/",
			Enabled: true,
		},
		"dshield": {
			Name:    "DShield",
			URL:     "https://isc.sans.edu/api/",
			Enabled: true,
		},
		"spamhaus": {
			Name:    "Spamhaus",
			URL:     "https://www.spamhaus.org/drop/",
			Enabled: true,
		},
		"sigmahq": {
			Name:    "SigmaHQ",
			URL:     "https://github.com/SigmaHQ/sigma",
			Enabled: true,
		},
		"yarahq": {
			Name:    "YARAHQ",
			URL:     "https://github.com/YARAHQ/yara-rules",
			Enabled: true,
		},
	}

	for k, v := range defaultSources {
		m.sources[k] = &v
	}
}

// GetAvailableSources returns list of available sources
func (m *Manager) GetAvailableSources() []string {
	var names []string
	for name, src := range m.sources {
		if src.Enabled {
			names = append(names, name)
		}
	}
	return names
}

// Sync performs signature synchronization
func (m *Manager) Sync(specificSources []string, force bool) (*Result, error) {
	startTime := time.Now()
	result := &Result{}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sources := specificSources
	if len(sources) == 0 {
		sources = m.GetAvailableSources()
	}

	for _, name := range sources {
		src, ok := m.sources[name]
		if !ok {
			m.logger.Warn("Unknown source", "source", name)
			continue
		}

		if !src.Enabled {
			m.logger.Debug("Source disabled, skipping", "source", name)
			continue
		}

		// Check if sync needed
		if !force && time.Since(src.LastSync) < time.Duration(m.config.Sync.UpdateInterval)*time.Hour {
			m.logger.Debug("Source recently synced, skipping", "source", name, "last_sync", src.LastSync)
			continue
		}

		m.logger.Info("Syncing source", "source", name)

		added, updated, err := m.syncSource(ctx, src)
		if err != nil {
			m.logger.Error("Failed to sync source", "source", name, "error", err)
			result.Errors++
			continue
		}

		result.SourcesSynced++
		result.SignaturesAdded += added
		result.SignaturesUpdated += updated

		src.LastSync = time.Now()
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

func (m *Manager) syncSource(ctx context.Context, src *Source) (added, updated int, err error) {
	// TODO: Implement actual sync logic for each source
	// This is a placeholder that simulates sync

	m.logger.Debug("Fetching signatures from source", "source", src.Name, "url", src.URL)

	// Simulate network request
	req, err := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch signatures: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// TODO: Parse response and update local database
	// For now, return placeholder values
	src.SignatureCount = 1000 // Placeholder

	return 100, 50, nil
}

// GetSourceStatus returns status of all sources
func (m *Manager) GetSourceStatus() map[string]Source {
	status := make(map[string]Source)
	for k, v := range m.sources {
		status[k] = *v
	}
	return status
}
