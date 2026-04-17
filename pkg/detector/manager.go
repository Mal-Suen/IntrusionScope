// Package detector provides threat detection capabilities
package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Manager manages multiple detection engines
type Manager struct {
	mu       sync.RWMutex
	engine   *RustEngine
	iocDB    *IOCDatabase
	rulesDir string
}

// ManagerConfig holds configuration for the detection manager
type ManagerConfig struct {
	RulesDir string `json:"rules_dir" yaml:"rules_dir"`
	IOCsDir  string `json:"iocs_dir" yaml:"iocs_dir"`
}

// NewManager creates a new detection manager
func NewManager(config *ManagerConfig) (*Manager, error) {
	m := &Manager{
		iocDB:    NewIOCDatabase(),
		rulesDir: config.RulesDir,
	}

	// Initialize engine
	engine, err := NewRustEngine()
	if err != nil {
		// Log warning but continue with Go fallback
		fmt.Printf("Warning: Rust engine not available, using Go fallback: %v\n", err)
	} else {
		m.engine = engine
	}

	// Load IOCs from directory
	if config.IOCsDir != "" {
		if err := m.LoadIOCsFromDir(config.IOCsDir); err != nil {
			fmt.Printf("Warning: failed to load IOCs: %v\n", err)
		}
	}

	return m, nil
}

// Close releases all resources
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.engine != nil {
		m.engine.Close()
		m.engine = nil
	}
}

// LoadIOCsFromDir loads IOCs from a directory of JSON files
func (m *Manager) LoadIOCsFromDir(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to list IOC files: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no IOC files found in directory: %s", dir)
	}

	var allIOCs []IOCDefinition
	loadErrors := []string{}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: read error: %v", filepath.Base(file), err))
			continue
		}

		var iocs []IOCDefinition
		if err := json.Unmarshal(data, &iocs); err != nil {
			// Try as object with iocs array
			var wrapper struct {
				IOCs []IOCDefinition `json:"iocs"`
			}
			if err := json.Unmarshal(data, &wrapper); err != nil {
				loadErrors = append(loadErrors, fmt.Sprintf("%s: parse error: %v", filepath.Base(file), err))
				continue
			}
			iocs = wrapper.IOCs
		}

		// Validate IOCs
		validIOCs := 0
		for _, ioc := range iocs {
			if ioc.Value == "" {
				loadErrors = append(loadErrors, fmt.Sprintf("%s: IOC with empty value skipped", filepath.Base(file)))
				continue
			}
			allIOCs = append(allIOCs, ioc)
			validIOCs++
		}
	}

	// Log warnings for files that had issues
	if len(loadErrors) > 0 {
		fmt.Printf("Warning: some IOC files had issues: %s\n", strings.Join(loadErrors, "; "))
	}

	if len(allIOCs) == 0 {
		return fmt.Errorf("no valid IOCs loaded from directory: %s", dir)
	}

	return m.LoadIOCs(allIOCs)
}

// LoadIOCs loads IOCs into all engines
func (m *Manager) LoadIOCs(iocs []IOCDefinition) error {
	// Skip if no IOCs to load
	if len(iocs) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to IOC database
	for _, ioc := range iocs {
		m.iocDB.Add(ioc)
	}

	// Load into engine if available
	if m.engine != nil {
		if err := m.engine.LoadIOCs(iocs); err != nil {
			return fmt.Errorf("failed to load IOCs into engine: %w", err)
		}
	}

	return nil
}

// Build finalizes all engines
func (m *Manager) Build() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.engine != nil {
		return m.engine.Build()
	}
	return nil
}

// Detect performs detection on content
func (m *Manager) Detect(content string) (*EngineResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Use engine if available
	if m.engine != nil {
		return m.engine.Detect(content)
	}

	// Fallback to IOC database
	return m.iocDB.Detect(content), nil
}

// DetectMap performs detection on a map
func (m *Manager) DetectMap(data map[string]interface{}) (*EngineResult, error) {
	content, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	return m.Detect(string(content))
}

// DetectProcess performs detection on process data
func (m *Manager) DetectProcess(process map[string]interface{}) (*EngineResult, error) {
	// Check various process fields
	var matches []EngineMatch

	// Check exe path
	if exe, ok := process["exe"].(string); ok {
		result, _ := m.Detect(exe)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	// Check cmdline
	if cmdline, ok := process["cmdline"].(string); ok {
		result, _ := m.Detect(cmdline)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	// Check name
	if name, ok := process["name"].(string); ok {
		result, _ := m.Detect(name)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	return &EngineResult{Matches: matches}, nil
}

// DetectNetworkConnection performs detection on network connection data
func (m *Manager) DetectNetworkConnection(conn map[string]interface{}) (*EngineResult, error) {
	var matches []EngineMatch

	// Check remote IP
	if remoteIP, ok := conn["remote_ip"].(string); ok && remoteIP != "" {
		result, _ := m.Detect(remoteIP)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	// Check local IP
	if localIP, ok := conn["local_ip"].(string); ok && localIP != "" {
		result, _ := m.Detect(localIP)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	// Check remote port (convert to string for IOC matching)
	if remotePort, ok := conn["remote_port"]; ok {
		portStr := fmt.Sprintf("%v", remotePort)
		if portStr != "" && portStr != "0" {
			result, _ := m.Detect(portStr)
			if result != nil {
				matches = append(matches, result.Matches...)
			}
		}
	}

	// Check local port (convert to string for IOC matching)
	if localPort, ok := conn["local_port"]; ok {
		portStr := fmt.Sprintf("%v", localPort)
		if portStr != "" && portStr != "0" {
			result, _ := m.Detect(portStr)
			if result != nil {
				matches = append(matches, result.Matches...)
			}
		}
	}

	return &EngineResult{Matches: matches}, nil
}

// DetectFile performs detection on file data
func (m *Manager) DetectFile(file map[string]interface{}) (*EngineResult, error) {
	var matches []EngineMatch

	// Check hashes
	if hashes, ok := file["hashes"].(map[string]string); ok {
		for _, hash := range hashes {
			result, _ := m.Detect(hash)
			if result != nil {
				matches = append(matches, result.Matches...)
			}
		}
	}

	// Check path
	if path, ok := file["path"].(string); ok {
		result, _ := m.Detect(path)
		if result != nil {
			matches = append(matches, result.Matches...)
		}
	}

	return &EngineResult{Matches: matches}, nil
}

// GetIOCDatabase returns the IOC database
func (m *Manager) GetIOCDatabase() *IOCDatabase {
	return m.iocDB
}

// AddPattern adds a pattern to the engine
func (m *Manager) AddPattern(pattern string, id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.engine != nil {
		return m.engine.AddPattern(pattern, id)
	}
	return nil
}

// AddPatterns adds multiple patterns
func (m *Manager) AddPatterns(patterns map[string]int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.engine != nil {
		return m.engine.AddPatterns(patterns)
	}
	return nil
}

// IOCDatabase is a simple in-memory IOC database
type IOCDatabase struct {
	mu        sync.RWMutex
	hashes    map[string]IOCDefinition
	ips       map[string]IOCDefinition
	domains   map[string]IOCDefinition
	urls      map[string]IOCDefinition
	processes map[string]IOCDefinition
	paths     map[string]IOCDefinition
	ports     map[string]IOCDefinition
}

// NewIOCDatabase creates a new IOC database
func NewIOCDatabase() *IOCDatabase {
	return &IOCDatabase{
		hashes:    make(map[string]IOCDefinition),
		ips:       make(map[string]IOCDefinition),
		domains:   make(map[string]IOCDefinition),
		urls:      make(map[string]IOCDefinition),
		processes: make(map[string]IOCDefinition),
		paths:     make(map[string]IOCDefinition),
		ports:     make(map[string]IOCDefinition),
	}
}

// Add adds an IOC to the database
func (db *IOCDatabase) Add(ioc IOCDefinition) {
	db.mu.Lock()
	defer db.mu.Unlock()

	iocType := strings.ToLower(ioc.IOCType)
	iocValue := strings.ToLower(ioc.Value)

	switch iocType {
	case "md5", "sha1", "sha256", "hash":
		db.hashes[iocValue] = ioc
	case "ip", "ipv4", "ipv6":
		db.ips[iocValue] = ioc
	case "domain":
		db.domains[iocValue] = ioc
	case "url":
		db.urls[iocValue] = ioc
	case "process":
		db.processes[iocValue] = ioc
	case "path":
		db.paths[iocValue] = ioc
	case "port":
		db.ports[iocValue] = ioc
	}
}

// Detect performs detection using the database
func (db *IOCDatabase) Detect(content string) *EngineResult {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var matches []EngineMatch
	contentLower := strings.ToLower(content)

	// Check hashes
	for value, ioc := range db.hashes {
		if strings.Contains(contentLower, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check IPs
	for value, ioc := range db.ips {
		if strings.Contains(content, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check domains
	for value, ioc := range db.domains {
		if strings.Contains(contentLower, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check URLs
	for value, ioc := range db.urls {
		if strings.Contains(contentLower, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check processes
	for value, ioc := range db.processes {
		if strings.Contains(contentLower, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check paths
	for value, ioc := range db.paths {
		if strings.Contains(contentLower, value) {
			matches = append(matches, EngineMatch{
				SignatureID:   ioc.ID,
				SignatureName: ioc.Description,
				Severity:      ioc.Severity,
				Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
			})
		}
	}

	// Check ports - use more precise matching to avoid false positives
	for value, ioc := range db.ports {
		// Match port with colon prefix (e.g., ":4444" in "127.0.0.1:4444")
		if strings.Contains(content, ":"+value) {
			// Verify it's actually a port number and not part of a larger number
			// by checking the character after the port number
			idx := strings.Index(content, ":"+value)
			if idx >= 0 {
				portEnd := idx + len(value) + 1
				// Check if port is followed by a non-digit character or end of string
				if portEnd >= len(content) || !isDigit(content[portEnd]) {
					matches = append(matches, EngineMatch{
						SignatureID:   ioc.ID,
						SignatureName: ioc.Description,
						Severity:      ioc.Severity,
						Details:       map[string]string{"ioc_type": ioc.IOCType, "value": ioc.Value},
					})
				}
			}
		}
	}

	// Check for suspicious command patterns
	matches = append(matches, db.detectSuspiciousPatterns(content, contentLower)...)

	return &EngineResult{Matches: matches}
}

// detectSuspiciousPatterns detects suspicious command patterns
func (db *IOCDatabase) detectSuspiciousPatterns(content, contentLower string) []EngineMatch {
	var matches []EngineMatch

	// Suspicious command patterns
	patterns := []struct {
		pattern     string
		id          string
		name        string
		severity    int
		description string
	}{
		// PowerShell attacks
		{"powershell -enc", "ps_encode", "Encoded PowerShell Command", 4, "PowerShell with encoded command - often used for obfuscation"},
		{"powershell -e ", "ps_encode2", "Encoded PowerShell Command", 4, "PowerShell with encoded command"},
		{"powershell -windowstyle hidden", "ps_hidden", "Hidden PowerShell Window", 4, "PowerShell running in hidden window"},
		{"-executionpolicy bypass", "ps_bypass", "PowerShell Execution Policy Bypass", 3, "Bypassing PowerShell security"},
		{"-ep bypass", "ps_bypass2", "PowerShell Execution Policy Bypass", 3, "Bypassing PowerShell security"},
		{"downloadstring(", "ps_download", "PowerShell Download", 3, "PowerShell downloading content"},
		{"downloadfile(", "ps_download2", "PowerShell File Download", 3, "PowerShell downloading file"},
		{"iex(", "ps_iex", "PowerShell Invoke Expression", 3, "Dynamic code execution"},
		{"iex (", "ps_iex2", "PowerShell Invoke Expression", 3, "Dynamic code execution"},
		{"invoke-webrequest", "ps_iwr", "PowerShell Web Request", 2, "PowerShell making web request"},
		{"invoke-expression", "ps_invoke", "PowerShell Invoke Expression", 3, "Dynamic code execution"},

		// Credential theft
		{"sekurlsa::logonpasswords", "mimikatz_logonpwd", "Mimikatz Credential Dump", 5, "Mimikatz extracting credentials"},
		{"sekurlsa::", "mimikatz_sekurlsa", "Mimikatz Sekurlsa Module", 5, "Mimikatz credential operations"},
		{"lsadump::", "mimikatz_lsadump", "Mimikatz LSA Dump", 5, "Mimikatz LSA operations"},
		{"privilege::debug", "mimikatz_debug", "Mimikatz Debug Privilege", 5, "Mimikatz requesting debug privilege"},
		{"kerberos::", "mimikatz_kerberos", "Mimikatz Kerberos Attack", 5, "Mimikatz Kerberos operations"},
		{"procdump -ma", "procdump_full", "Full Process Dump", 4, "Creating full process memory dump"},
		{"procdump ", "procdump", "Process Dump Tool", 3, "Process dump execution"},

		// Living off the land binaries (LOLBins)
		{"certutil -urlcache", "lolbin_certutil", "Certutil Download", 4, "Using certutil to download files"},
		{"certutil -split", "lolbin_certutil2", "Certutil Split", 3, "Certutil file operations"},
		{"bitsadmin /transfer", "lolbin_bitsadmin", "BITSAdmin Download", 3, "Using BITS for download"},
		{"bitsadmin /create", "lolbin_bitsadmin2", "BITSAdmin Job", 2, "BITS job creation"},
		{"mshta vbscript", "lolbin_mshta", "MSHTA VBScript Execution", 4, "MSHTA executing VBScript"},
		{"mshta http", "lolbin_mshta2", "MSHTA Remote Execution", 4, "MSHTA executing remote content"},
		{"regsvr32 /i:http", "lolbin_regsvr32", "Regsvr32 Remote Execution", 4, "Regsvr32 executing remote script"},
		{"regsvr32 /i:https", "lolbin_regsvr32_2", "Regsvr32 Remote Execution", 4, "Regsvr32 executing remote script"},
		{"rundll32.exe javascript:", "lolbin_rundll32", "Rundll32 JavaScript", 4, "Rundll32 executing JavaScript"},
		{"wmic process call create", "lolbin_wmic", "WMIC Process Creation", 3, "WMIC creating process"},
		{"msiexec /i http", "lolbin_msiexec", "MSIExec Remote Install", 3, "MSIExec installing from remote"},

		// Persistence mechanisms
		{"currentversion\\\\run", "persist_run", "Run Key Modification", 4, "注册表Run键持久化"},
		{"currentversion\\run", "persist_run2", "Run Key Modification", 4, "注册表Run键持久化"},
		{"schtasks /create", "persist_schtasks", "Scheduled Task Creation", 3, "Creating scheduled task"},
		{"sc create", "persist_service", "Service Creation", 3, "Creating Windows service"},

		// Reconnaissance
		{"whoami /all", "recon_whoami", "User Privilege Recon", 2, "Enumerating user privileges"},
		{"net user ", "recon_netuser", "User Enumeration", 2, "Enumerating users"},
		{"net localgroup ", "recon_localgroup", "Group Enumeration", 2, "Enumerating local groups"},
		{"net group ", "recon_group", "Domain Group Enumeration", 3, "Enumerating domain groups"},
		{"net view ", "recon_netview", "Network Recon", 2, "Network enumeration"},
		{"nltest /domain_trusts", "recon_trusts", "Domain Trust Recon", 3, "Enumerating domain trusts"},
		{"dsquery ", "recon_dsquery", "AD Recon", 3, "Active Directory enumeration"},
		{"bloodhound", "recon_bloodhound", "BloodHound Execution", 4, "AD reconnaissance tool"},

		// Lateral movement
		{"psexec ", "lateral_psexec", "PsExec Execution", 3, "Remote execution via PsExec"},
		{"wmic /node:", "lateral_wmic", "WMIC Remote Execution", 3, "Remote WMI execution"},
		{"enter-pssession", "lateral_pssession", "PowerShell Remote Session", 2, "Remote PowerShell session"},
		{"invoke-command", "lateral_invoke", "PowerShell Remote Command", 2, "Remote PowerShell command"},
		{"winrs ", "lateral_winrs", "WinRS Remote Execution", 3, "Remote execution via WinRS"},

		// Defense evasion
		{"wevtutil cl", "evasion_clearlog", "Event Log Clearing", 4, "Clearing Windows event logs"},
		{"clear-eventlog", "evasion_psclearlog", "PowerShell Log Clearing", 4, "Clearing event logs via PowerShell"},
		{"auditpol /clear", "evasion_auditpol", "Audit Policy Clear", 4, "Clearing audit policy"},
		{"sc delete ", "evasion_scdelete", "Service Deletion", 3, "Deleting Windows service"},
		{"taskkill /f", "evasion_taskkill", "Force Kill Process", 2, "Forcefully killing process"},
		{"netsh advfirewall set allprofiles state off", "evasion_firewall", "Firewall Disabled", 4, "Disabling Windows firewall"},
		{"netsh firewall set opmode disable", "evasion_firewall2", "Firewall Disabled", 4, "Disabling Windows firewall"},

		// Data exfiltration
		{"ftp -s:", "exfil_ftp", "FTP Script Execution", 3, "FTP with script file"},
		{"curl -o", "exfil_curl", "Curl Download", 2, "Downloading with curl"},
		{"wget ", "exfil_wget", "Wget Download", 2, "Downloading with wget"},

		// Account manipulation
		{"/add", "account_add", "User Account Creation", 3, "Creating new user account"},
		{"net localgroup administrators", "account_admin", "Admin Group Modification", 4, "Modifying administrators group"},
		{"/delete", "account_delete", "User Account Deletion", 3, "Deleting user account"},

		// Suspicious file locations
		{"\\temp\\", "susp_path_temp", "Temp Directory Execution", 2, "Executing from temp directory"},
		{"\\users\\public\\", "susp_path_public", "Public Directory Execution", 3, "Executing from public directory"},
		{"\\appdata\\local\\temp\\", "susp_path_appdata", "AppData Temp Execution", 2, "Executing from AppData temp"},
		{"\\\\temp\\\\", "susp_path_temp2", "Temp Directory Execution", 2, "Executing from temp directory"},
		{"\\\\users\\\\public\\\\", "susp_path_public2", "Public Directory Execution", 3, "Executing from public directory"},

		// Suspicious script execution
		{"wscript ", "susp_wscript", "WScript Execution", 2, "Windows Script Host execution"},
		{"cscript ", "susp_cscript", "CScript Execution", 2, "Console Script Host execution"},
		{".vbs", "susp_vbs", "VBScript File", 2, "VBScript file execution"},
		{"rundll32.exe ", "susp_rundll32", "Rundll32 Execution", 2, "Rundll32 loading DLL"},

		// Reverse shell indicators
		{"nc.exe ", "revshell_nc", "Netcat Execution", 4, "Netcat - potential reverse shell"},
		{"ncat ", "revshell_ncat", "Ncat Execution", 4, "Ncat - potential reverse shell"},
		{"-e /bin", "revshell_bin", "Potential Reverse Shell", 4, "Shell execution flag"},
		{"-e cmd", "revshell_cmd", "Potential Reverse Shell", 4, "Shell execution flag"},
		{":4444", "revshell_port", "Common Shell Port", 3, "Common reverse shell port"},
		{":5555", "revshell_port2", "Common Shell Port", 3, "Common reverse shell port"},
	}

	for _, p := range patterns {
		if strings.Contains(contentLower, p.pattern) {
			matches = append(matches, EngineMatch{
				SignatureID:   p.id,
				SignatureName: p.name,
				Severity:      p.severity,
				Details:       map[string]string{"ioc_type": "behavioral", "pattern": p.pattern, "description": p.description},
			})
		}
	}

	return matches
}

// Stats returns statistics about the IOC database
func (db *IOCDatabase) Stats() map[string]int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return map[string]int{
		"hashes":  len(db.hashes),
		"ips":     len(db.ips),
		"domains": len(db.domains),
		"urls":    len(db.urls),
		"total":   len(db.hashes) + len(db.ips) + len(db.domains) + len(db.urls),
	}
}

// isDigit checks if a byte is a digit (0-9)
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
