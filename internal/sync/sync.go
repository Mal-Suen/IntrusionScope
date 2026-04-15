// Package sync provides signature library synchronization
package sync

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus-labs/intrusionscope/internal/config"
	"github.com/prometheus-labs/intrusionscope/internal/logger"
)

// Source represents a signature source
type Source struct {
	Name           string
	URL            string
	Enabled        bool
	LastSync       time.Time
	SignatureCount int
	Type           string // "ioc", "sigma", "yara"
}

// Result holds sync operation results
type Result struct {
	SourcesSynced     int
	SignaturesAdded   int
	SignaturesUpdated int
	Errors            int
	Duration          time.Duration
}

// Manager manages signature synchronization
type Manager struct {
	config     *config.Config
	logger     *logger.Logger
	client     *http.Client
	sources    map[string]*Source
	dataDir    string
}

// NewManager creates a new sync manager
func NewManager(cfg *config.Config, log *logger.Logger) *Manager {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	m := &Manager{
		config:  cfg,
		logger:  log,
		client:  client,
		sources: make(map[string]*Source),
		dataDir: cfg.Sync.CacheDir,
	}

	// Ensure data directory exists
	os.MkdirAll(m.dataDir, 0755)
	os.MkdirAll(filepath.Join(m.dataDir, "ioc"), 0755)
	os.MkdirAll(filepath.Join(m.dataDir, "sigma"), 0755)
	os.MkdirAll(filepath.Join(m.dataDir, "yara"), 0755)

	// Initialize sources
	m.initSources()

	return m
}

func (m *Manager) initSources() {
	// Define available sources
	defaultSources := map[string]Source{
		// IOC Sources - Abuse.ch
		"malwarebazaar": {
			Name:    "MalwareBazaar",
			URL:     "https://bazaar.abuse.ch/export/csv/sha256/full/",
			Enabled: true,
			Type:    "ioc",
		},
		"urlhaus": {
			Name:    "URLhaus",
			URL:     "https://urlhaus.abuse.ch/export/csv/",
			Enabled: true,
			Type:    "ioc",
		},
		"threatfox": {
			Name:    "ThreatFox",
			URL:     "https://threatfox.abuse.ch/export/csv/sha256/full/",
			Enabled: true,
			Type:    "ioc",
		},
		"feodotracker": {
			Name:    "Feodo Tracker",
			URL:     "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
			Enabled: true,
			Type:    "ioc",
		},
		"sslblacklist": {
			Name:    "SSL Blacklist",
			URL:     "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
			Enabled: true,
			Type:    "ioc",
		},
		// Spamhaus
		"spamhaus_drop": {
			Name:    "Spamhaus DROP",
			URL:     "https://www.spamhaus.org/drop/drop.txt",
			Enabled: true,
			Type:    "ioc",
		},
		"spamhaus_edrop": {
			Name:    "Spamhaus EDROP",
			URL:     "https://www.spamhaus.org/drop/edrop.txt",
			Enabled: true,
			Type:    "ioc",
		},
		// Phishing
		"openphish": {
			Name:    "OpenPhish",
			URL:     "https://openphish.com/feed.txt",
			Enabled: true,
			Type:    "ioc",
		},
		"phishing": {
			Name:    "Phishing.Database",
			URL:     "https://data.phishing.army/phishing_army_blocklist.txt",
			Enabled: true,
			Type:    "ioc",
		},
		// IP Blocklists
		"ipsum": {
			Name:    "IPSum",
			URL:     "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
			Enabled: true,
			Type:    "ioc",
		},
		"firehol1": {
			Name:    "FireHOL Level 1",
			URL:     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
			Enabled: true,
			Type:    "ioc",
		},
		"firehol2": {
			Name:    "FireHOL Level 2",
			URL:     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
			Enabled: true,
			Type:    "ioc",
		},
		"firehol3": {
			Name:    "FireHOL Level 3",
			URL:     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
			Enabled: true,
			Type:    "ioc",
		},
		"blocklistde": {
			Name:    "BlockList.de",
			URL:     "https://lists.blocklist.de/lists/all.txt",
			Enabled: true,
			Type:    "ioc",
		},
		"ciarmy": {
			Name:    "CINS Army",
			URL:     "https://cinsscore.com/list/ci-badguys.txt",
			Enabled: true,
			Type:    "ioc",
		},
		"binarydefense": {
			Name:    "Binary Defense",
			URL:     "https://www.binarydefense.com/banlist.txt",
			Enabled: true,
			Type:    "ioc",
		},
		// Threat Intelligence
		"dshield": {
			Name:    "DShield Block List",
			URL:     "https://isc.sans.edu/api/threatlist/shodan?json",
			Enabled: true,
			Type:    "ioc",
		},
		"alienvault": {
			Name:    "AlienVault OTX",
			URL:     "https://otx.alienvault.com/api/v1/indicators/export",
			Enabled: true,
			Type:    "ioc",
		},
		// Tor Exit Nodes
		"torexits": {
			Name:    "Tor Exit Nodes",
			URL:     "https://check.torproject.org/torbulkexitlist",
			Enabled: true,
			Type:    "ioc",
		},
		// Sigma Rules
		"sigmahq": {
			Name:    "SigmaHQ",
			URL:     "https://github.com/SigmaHQ/sigma",
			Enabled: true,
			Type:    "sigma",
		},
		// YARA Rules
		"yarahq": {
			Name:    "YARAHQ",
			URL:     "https://github.com/YARAHQ/yara-rules",
			Enabled: true,
			Type:    "yara",
		},
		"yararuleshub": {
			Name:    "YARA Rules Hub",
			URL:     "https://github.com/Yara-Rules/rules",
			Enabled: true,
			Type:    "yara",
		},
		"bartblaze": {
			Name:    "BartBlaze YARA",
			URL:     "https://github.com/bartblaze/YARA-rules",
			Enabled: true,
			Type:    "yara",
		},
		"stratosphere": {
			Name:    "Stratosphere YARA",
			URL:     "https://github.com/stratosphereips/yara-rules",
			Enabled: true,
			Type:    "yara",
		},
	}

	for k, v := range defaultSources {
		// Create a copy of v to avoid all sources pointing to the same address
		source := v
		m.sources[k] = &source
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
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
	m.logger.Info("Fetching signatures from source", "source", src.Name, "url", src.URL)

	switch src.Name {
	case "MalwareBazaar":
		return m.syncMalwareBazaar(ctx, src)
	case "URLhaus":
		return m.syncURLhaus(ctx, src)
	case "ThreatFox":
		return m.syncThreatFox(ctx, src)
	case "Spamhaus DROP":
		return m.syncSpamhausDROP(ctx, src)
	case "Spamhaus EDROP":
		return m.syncSpamhausEDROP(ctx, src)
	case "Spamhaus ASN-DROP":
		return m.syncSpamhausASNDROP(ctx, src)
	case "DShield Block List":
		return m.syncDShield(ctx, src)
	case "AlienVault OTX":
		return m.syncAlienVault(ctx, src)
	case "OpenPhish":
		return m.syncOpenPhish(ctx, src)
	case "Phishing.Database":
		return m.syncPhishingDB(ctx, src)
	case "SSL Blacklist":
		return m.syncSSLBlacklist(ctx, src)
	case "Binary Defense":
		return m.syncBinaryDefense(ctx, src)
	case "CINS Army":
		return m.syncCINSArmy(ctx, src)
	case "Emerging Threats":
		return m.syncEmergingThreats(ctx, src)
	case "Feodo Tracker":
		return m.syncFeodoTracker(ctx, src)
	case "IPSum":
		return m.syncIPSum(ctx, src)
	case "FireHOL Level 1":
		return m.syncFireHOL(ctx, src, "firehol1.json")
	case "FireHOL Level 2":
		return m.syncFireHOL(ctx, src, "firehol2.json")
	case "FireHOL Level 3":
		return m.syncFireHOL(ctx, src, "firehol3.json")
	case "BlockList.de":
		return m.syncBlockListDE(ctx, src)
	case "Tor Exit Nodes":
		return m.syncTorExits(ctx, src)
	case "SigmaHQ":
		return m.syncSigmaHQ(ctx, src)
	case "YARAHQ":
		return m.syncYARAHQ(ctx, src)
	case "YARA Rules Hub":
		return m.syncYARARulesHub(ctx, src)
	case "BartBlaze YARA":
		return m.syncBartBlaze(ctx, src)
	case "Stratosphere YARA":
		return m.syncStratosphere(ctx, src)
	default:
		m.logger.Warn("No specific handler for source, using generic", "source", src.Name)
		return m.syncGeneric(ctx, src)
	}
}

// newRequest creates a new HTTP request with proper headers
func (m *Manager) newRequest(ctx context.Context, method, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "IntrusionScope/1.0 (Threat Intelligence Tool)")
	req.Header.Set("Accept", "*/*")
	return req, nil
}

// syncMalwareBazaar syncs malware hashes from MalwareBazaar
func (m *Manager) syncMalwareBazaar(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Parse CSV
	reader := csv.NewReader(resp.Body)
	records, err := reader.ReadAll()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse CSV: %w", err)
	}

	// Skip header and extract SHA256 hashes
	var iocs []map[string]interface{}
	for i, record := range records {
		if i == 0 { // Skip header
			continue
		}
		if len(record) < 1 {
			continue
		}
		sha256 := strings.TrimSpace(record[0])
		if len(sha256) == 64 { // Valid SHA256
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("mb_%s", sha256[:16]),
				"value":       sha256,
				"ioc_type":    "SHA256",
				"severity":    4,
				"description": "MalwareBazaar malware hash",
				"tags":        []string{"malware", "malwarebazaar"},
				"source":      "MalwareBazaar",
			})
		}
	}

	// Save to file
	outputPath := filepath.Join(m.dataDir, "ioc", "malwarebazaar.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncURLhaus syncs malicious URLs from URLhaus
func (m *Manager) syncURLhaus(ctx context.Context, src *Source) (added, updated int, err error) {
	// URLhaus CSV export
	url := "https://urlhaus.abuse.ch/export/csv/"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Parse CSV
	reader := csv.NewReader(resp.Body)
	records, err := reader.ReadAll()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse CSV: %w", err)
	}

	var iocs []map[string]interface{}
	for i, record := range records {
		if i == 0 || len(record) < 3 {
			continue
		}
		// Skip comment lines
		if strings.HasPrefix(record[0], "#") {
			continue
		}
		urlVal := strings.TrimSpace(record[2])
		if urlVal != "" && strings.HasPrefix(urlVal, "http") {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("uh_%d", i),
				"value":       urlVal,
				"ioc_type":    "URL",
				"severity":    3,
				"description": "URLhaus malicious URL",
				"tags":        []string{"url", "urlhaus"},
				"source":      "URLhaus",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "urlhaus.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncThreatFox syncs IOCs from ThreatFox
func (m *Manager) syncThreatFox(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	reader := csv.NewReader(resp.Body)
	records, err := reader.ReadAll()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse CSV: %w", err)
	}

	var iocs []map[string]interface{}
	for i, record := range records {
		if i == 0 || len(record) < 1 {
			continue
		}
		sha256 := strings.TrimSpace(record[0])
		if len(sha256) == 64 {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("tf_%s", sha256[:16]),
				"value":       sha256,
				"ioc_type":    "SHA256",
				"severity":    4,
				"description": "ThreatFox IOC",
				"tags":        []string{"malware", "threatfox"},
				"source":      "ThreatFox",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "threatfox.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncSpamhausDROP syncs IP blocklist from Spamhaus DROP
func (m *Manager) syncSpamhausDROP(ctx context.Context, src *Source) (added, updated int, err error) {
	return m.syncIPBlocklist(ctx, src, "spamhaus_drop.json")
}

// syncSpamhausEDROP syncs IP blocklist from Spamhaus EDROP
func (m *Manager) syncSpamhausEDROP(ctx context.Context, src *Source) (added, updated int, err error) {
	return m.syncIPBlocklist(ctx, src, "spamhaus_edrop.json")
}

// syncIPBlocklist syncs IP blocklists (Spamhaus format)
func (m *Manager) syncIPBlocklist(ctx context.Context, src *Source, filename string) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// Extract CIDR (format: 1.0.0.0/24 ; SBL12345)
		parts := strings.Split(line, ";")
		cidr := strings.TrimSpace(parts[0])
		if cidr != "" && strings.Contains(cidr, "/") {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("sh_%s", strings.ReplaceAll(cidr, "/", "_")),
				"value":       cidr,
				"ioc_type":    "IP",
				"severity":    3,
				"description": fmt.Sprintf("Spamhaus blocklist: %s", src.Name),
				"tags":        []string{"spam", "blocklist", "spamhaus"},
				"source":      src.Name,
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", filename)
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncDShield syncs IP blocklist from DShield
func (m *Manager) syncDShield(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// DShield format: IP	attacks
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			ip := parts[0]
			if ip != "" {
				iocs = append(iocs, map[string]interface{}{
					"id":          fmt.Sprintf("ds_%s", strings.ReplaceAll(ip, ".", "_")),
					"value":       ip,
					"ioc_type":    "IP",
					"severity":    3,
					"description": "DShield blocklist IP",
					"tags":        []string{"attack", "dshield"},
					"source":      "DShield",
				})
			}
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "dshield.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncAlienVault syncs IOCs from AlienVault OTX
func (m *Manager) syncAlienVault(ctx context.Context, src *Source) (added, updated int, err error) {
	// AlienVault OTX requires API key for full access
	// Use public export endpoint
	url := "https://otx.alienvault.com/api/v1/indicators/export?types=sha256,domain,ip,url"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Parse JSON response
	var data struct {
		Indicators []struct {
			Indicator string `json:"indicator"`
			Type      string `json:"type"`
		} `json:"indicators"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, 0, fmt.Errorf("failed to parse JSON: %w", err)
	}

	var iocs []map[string]interface{}
	for i, ind := range data.Indicators {
		iocType := "SHA256"
		switch ind.Type {
		case "IPv4", "IPv6":
			iocType = "IP"
		case "domain":
			iocType = "Domain"
		case "URL":
			iocType = "URL"
		case "sha256":
			iocType = "SHA256"
		}

		iocs = append(iocs, map[string]interface{}{
			"id":          fmt.Sprintf("av_%d", i),
			"value":       ind.Indicator,
			"ioc_type":    iocType,
			"severity":    3,
			"description": "AlienVault OTX IOC",
			"tags":        []string{"otx", "alienvault"},
			"source":      "AlienVault OTX",
		})
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "alienvault.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncSigmaHQ syncs Sigma rules from GitHub
func (m *Manager) syncSigmaHQ(ctx context.Context, src *Source) (added, updated int, err error) {
	// Clone or update Sigma repository
	sigmaDir := filepath.Join(m.dataDir, "sigma", "rules")

	// Check if repo exists
	if _, err := os.Stat(sigmaDir); os.IsNotExist(err) {
		// Clone repo
		m.logger.Info("Downloading SigmaHQ rules...")
		// For simplicity, download release archive
		url := "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
		if err := m.downloadAndExtract(url, filepath.Join(m.dataDir, "sigma")); err != nil {
			return 0, 0, fmt.Errorf("failed to download Sigma rules: %w", err)
		}
	}

	// Count rules
	count, err := m.countYAMLFiles(sigmaDir)
	if err != nil {
		return 0, 0, err
	}

	src.SignatureCount = count
	return count, 0, nil
}

// syncYARAHQ syncs YARA rules from GitHub
func (m *Manager) syncYARAHQ(ctx context.Context, src *Source) (added, updated int, err error) {
	yaraDir := filepath.Join(m.dataDir, "yara", "rules")

	if _, err := os.Stat(yaraDir); os.IsNotExist(err) {
		m.logger.Info("Downloading YARA rules...")
		url := "https://github.com/YARAHQ/yara-rules/archive/refs/heads/master.zip"
		if err := m.downloadAndExtract(url, filepath.Join(m.dataDir, "yara")); err != nil {
			return 0, 0, fmt.Errorf("failed to download YARA rules: %w", err)
		}
	}

	count, err := m.countYARAFiles(yaraDir)
	if err != nil {
		return 0, 0, err
	}

	src.SignatureCount = count
	return count, 0, nil
}

// syncGeneric handles unknown sources
func (m *Manager) syncGeneric(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Just save the response
	outputPath := filepath.Join(m.dataDir, src.Type, fmt.Sprintf("%s.txt", src.Name))
	out, err := os.Create(outputPath)
	if err != nil {
		return 0, 0, err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return 0, 0, err
}

// saveIOCs saves IOCs to a JSON file
func (m *Manager) saveIOCs(iocs []map[string]interface{}, path string) error {
	data, err := json.MarshalIndent(iocs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal IOCs: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// downloadAndExtract downloads and extracts a zip file
func (m *Manager) downloadAndExtract(url, dest string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "IntrusionScope/1.0 (Threat Intelligence Tool)")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Save zip file
	zipPath := dest + ".zip"
	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		return err
	}

	m.logger.Info("Downloaded archive", "path", zipPath)

	// Extract zip file
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		os.Remove(zipPath)
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	// Create destination directory
	os.MkdirAll(dest, 0755)

	for _, f := range r.File {
		// Skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		// Open file in zip
		rc, err := f.Open()
		if err != nil {
			continue
		}

		// Create destination file path
		// Remove the top-level directory from the path (e.g., "rules-master/" -> "")
		parts := strings.SplitN(f.Name, "/", 2)
		var relPath string
		if len(parts) > 1 {
			relPath = parts[1]
		} else {
			relPath = f.Name
		}

		if relPath == "" {
			rc.Close()
			continue
		}

		dstPath := filepath.Join(dest, relPath)

		// Create parent directories
		os.MkdirAll(filepath.Dir(dstPath), 0755)

		// Create and write file
		dstFile, err := os.Create(dstPath)
		if err != nil {
			rc.Close()
			continue
		}

		io.Copy(dstFile, rc)
		dstFile.Close()
		rc.Close()
	}

	r.Close()
	return os.Remove(zipPath)
}

// countYAMLFiles counts YAML files in a directory
func (m *Manager) countYAMLFiles(dir string) (int, error) {
	count := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			count++
		}
		return nil
	})
	return count, err
}

// countYARAFiles counts YARA files in a directory
func (m *Manager) countYARAFiles(dir string) (int, error) {
	count := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".yar") {
			count++
		}
		return nil
	})
	return count, err
}

// GetSourceStatus returns status of all sources
func (m *Manager) GetSourceStatus() map[string]Source {
	status := make(map[string]Source)
	for k, v := range m.sources {
		status[k] = *v
	}
	return status
}

// syncSpamhausASNDROP syncs ASN blocklist from Spamhaus
func (m *Manager) syncSpamhausASNDROP(ctx context.Context, src *Source) (added, updated int, err error) {
	return m.syncIPBlocklist(ctx, src, "spamhaus_asndrop.json")
}

// syncOpenPhish syncs phishing URLs from OpenPhish
func (m *Manager) syncOpenPhish(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "http") {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("op_%d", len(iocs)),
				"value":       line,
				"ioc_type":    "URL",
				"severity":    3,
				"description": "OpenPhish phishing URL",
				"tags":        []string{"phishing", "openphish"},
				"source":      "OpenPhish",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "openphish.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncPhishingDB syncs phishing URLs from Phishing.Database
func (m *Manager) syncPhishingDB(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}
	maxIOCs := 50000 // Limit to prevent memory issues

	for scanner.Scan() && len(iocs) < maxIOCs {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "http") {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("pdb_%d", len(iocs)),
				"value":       line,
				"ioc_type":    "URL",
				"severity":    3,
				"description": "Phishing.Database URL",
				"tags":        []string{"phishing"},
				"source":      "Phishing.Database",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "phishing_db.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncRansomwareTracker syncs ransomware URLs
func (m *Manager) syncRansomwareTracker(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "http") {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("rw_%d", len(iocs)),
				"value":       line,
				"ioc_type":    "URL",
				"severity":    4,
				"description": "Ransomware Tracker URL",
				"tags":        []string{"ransomware"},
				"source":      "Ransomware Tracker",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "ransomware_tracker.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncSSLBlacklist syncs SSL certificate blacklists
func (m *Manager) syncSSLBlacklist(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	reader := csv.NewReader(resp.Body)
	records, err := reader.ReadAll()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse CSV: %w", err)
	}

	var iocs []map[string]interface{}
	for i, record := range records {
		if i == 0 { // Skip header
			continue
		}
		if len(record) >= 1 {
			sha1 := strings.TrimSpace(record[0])
			if len(sha1) == 40 { // Valid SHA1
				description := "SSL Blacklist certificate"
				if len(record) > 1 {
					description = record[1]
				}
				iocs = append(iocs, map[string]interface{}{
					"id":          fmt.Sprintf("ssl_%s", sha1[:16]),
					"value":       sha1,
					"ioc_type":    "SHA1",
					"severity":    4,
					"description": description,
					"tags":        []string{"ssl", "malware"},
					"source":      "SSL Blacklist",
				})
			}
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "ssl_blacklist.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncBinaryDefense syncs IP blocklist from Binary Defense
func (m *Manager) syncBinaryDefense(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Parse IP address
		ip := strings.Fields(line)[0]
		if ip != "" && !strings.Contains(ip, ":") {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("bd_%s", strings.ReplaceAll(ip, ".", "_")),
				"value":       ip,
				"ioc_type":    "IP",
				"severity":    3,
				"description": "Binary Defense banlist IP",
				"tags":        []string{"attack", "binarydefense"},
				"source":      "Binary Defense",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "binary_defense.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncCINSArmy syncs IP blocklist from CINS Army
func (m *Manager) syncCINSArmy(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.Fields(line)[0]
		if ip != "" {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("cins_%s", strings.ReplaceAll(ip, ".", "_")),
				"value":       ip,
				"ioc_type":    "IP",
				"severity":    3,
				"description": "CINS Army malicious IP",
				"tags":        []string{"attack", "cins"},
				"source":      "CINS Army",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "cins_army.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncEmergingThreats syncs IP blocklist from Emerging Threats
func (m *Manager) syncEmergingThreats(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.Fields(line)[0]
		if ip != "" && !strings.Contains(ip, ":") {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("et_%s", strings.ReplaceAll(ip, ".", "_")),
				"value":       ip,
				"ioc_type":    "IP",
				"severity":    3,
				"description": "Emerging Threats blocklist IP",
				"tags":        []string{"attack", "emergingthreats"},
				"source":      "Emerging Threats",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "emerging_threats.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncFeodoTracker syncs botnet C2 IPs from Feodo Tracker
func (m *Manager) syncFeodoTracker(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.Fields(line)[0]
		if ip != "" {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("feodo_%s", strings.ReplaceAll(ip, ".", "_")),
				"value":       ip,
				"ioc_type":    "IP",
				"severity":    4,
				"description": "Feodo Tracker botnet C2",
				"tags":        []string{"botnet", "c2", "feodo"},
				"source":      "Feodo Tracker",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "feodo_tracker.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncIPSum syncs aggregated IP blocklist from IPSum
func (m *Manager) syncIPSum(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}
	maxIOCs := 100000 // Limit for IPSum

	for scanner.Scan() && len(iocs) < maxIOCs {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			ip := parts[0]
			if ip != "" {
				iocs = append(iocs, map[string]interface{}{
					"id":          fmt.Sprintf("ipsum_%s", strings.ReplaceAll(ip, ".", "_")),
					"value":       ip,
					"ioc_type":    "IP",
					"severity":    3,
					"description": "IPSum aggregated blocklist",
					"tags":        []string{"attack", "ipsum"},
					"source":      "IPSum",
				})
			}
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "ipsum.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncYARARulesHub syncs YARA rules from YARA Rules Hub
func (m *Manager) syncYARARulesHub(ctx context.Context, src *Source) (added, updated int, err error) {
	yaraDir := filepath.Join(m.dataDir, "yara", "ruleshub")

	if _, err := os.Stat(yaraDir); os.IsNotExist(err) {
		m.logger.Info("Downloading YARA Rules Hub...")
		url := "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
		if err := m.downloadAndExtract(url, filepath.Join(m.dataDir, "yara")); err != nil {
			return 0, 0, fmt.Errorf("failed to download YARA rules: %w", err)
		}
	}

	count, err := m.countYARAFiles(yaraDir)
	if err != nil {
		return 0, 0, err
	}

	src.SignatureCount = count
	return count, 0, nil
}

// syncBartBlaze syncs YARA rules from BartBlaze
func (m *Manager) syncBartBlaze(ctx context.Context, src *Source) (added, updated int, err error) {
	yaraDir := filepath.Join(m.dataDir, "yara", "rules")

	if _, err := os.Stat(yaraDir); os.IsNotExist(err) {
		m.logger.Info("Downloading BartBlaze YARA rules...")
		url := "https://github.com/bartblaze/YARA-rules/archive/refs/heads/master.zip"
		if err := m.downloadAndExtract(url, filepath.Join(m.dataDir, "yara")); err != nil {
			return 0, 0, fmt.Errorf("failed to download YARA rules: %w", err)
		}
	}

	count, err := m.countYARAFiles(yaraDir)
	if err != nil {
		return 0, 0, err
	}

	src.SignatureCount = count
	return count, 0, nil
}

// syncStratosphere syncs YARA rules from Stratosphere
func (m *Manager) syncStratosphere(ctx context.Context, src *Source) (added, updated int, err error) {
	yaraDir := filepath.Join(m.dataDir, "yara", "rules")

	if _, err := os.Stat(yaraDir); os.IsNotExist(err) {
		m.logger.Info("Downloading Stratosphere YARA rules...")
		url := "https://github.com/stratosphereips/yara-rules/archive/refs/heads/master.zip"
		if err := m.downloadAndExtract(url, filepath.Join(m.dataDir, "yara")); err != nil {
			return 0, 0, fmt.Errorf("failed to download YARA rules: %w", err)
		}
	}

	count, err := m.countYARAFiles(yaraDir)
	if err != nil {
		return 0, 0, err
	}

	src.SignatureCount = count
	return count, 0, nil
}

// syncFireHOL syncs IP blocklists from FireHOL
func (m *Manager) syncFireHOL(ctx context.Context, src *Source, filename string) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}
	maxIOCs := 50000 // Limit for FireHOL

	for scanner.Scan() && len(iocs) < maxIOCs {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Parse IP or CIDR
		fields := strings.Fields(line)
		if len(fields) > 0 {
			ip := fields[0]
			if strings.Contains(ip, "/") {
				iocs = append(iocs, map[string]interface{}{
					"id":          fmt.Sprintf("fh_%d", len(iocs)),
					"value":       ip,
					"ioc_type":    "IP_CIDR",
					"severity":    3,
					"description": "FireHOL blocklist",
					"tags":        []string{"firehol", "blocklist"},
					"source":      src.Name,
				})
			} else {
				iocs = append(iocs, map[string]interface{}{
					"id":          fmt.Sprintf("fh_%d", len(iocs)),
					"value":       ip,
					"ioc_type":    "IP",
					"severity":    3,
					"description": "FireHOL blocklist",
					"tags":        []string{"firehol", "blocklist"},
					"source":      src.Name,
				})
			}
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", filename)
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncBlockListDE syncs IP blocklists from BlockList.de
func (m *Manager) syncBlockListDE(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}
	maxIOCs := 100000

	for scanner.Scan() && len(iocs) < maxIOCs {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.Fields(line)[0]
		if ip != "" {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("bld_%s", strings.ReplaceAll(ip, ".", "_")),
				"value":       ip,
				"ioc_type":    "IP",
				"severity":    3,
				"description": "BlockList.de malicious IP",
				"tags":        []string{"attack", "blocklistde"},
				"source":      "BlockList.de",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "blocklist_de.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}

// syncTorExits syncs Tor exit node IPs
func (m *Manager) syncTorExits(ctx context.Context, src *Source) (added, updated int, err error) {
	req, err := m.newRequest(ctx, "GET", src.URL)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var iocs []map[string]interface{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.Fields(line)[0]
		if ip != "" {
			iocs = append(iocs, map[string]interface{}{
				"id":          fmt.Sprintf("tor_%s", strings.ReplaceAll(ip, ".", "_")),
				"value":       ip,
				"ioc_type":    "IP",
				"severity":    2,
				"description": "Tor exit node",
				"tags":        []string{"tor", "anonymizer"},
				"source":      "Tor Project",
			})
		}
	}

	outputPath := filepath.Join(m.dataDir, "ioc", "tor_exits.json")
	if err := m.saveIOCs(iocs, outputPath); err != nil {
		return 0, 0, err
	}

	src.SignatureCount = len(iocs)
	return len(iocs), 0, nil
}
