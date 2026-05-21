// Package detector provides threat detection capabilities
package detector

import (
	"testing"
)

// TestMatchIPExact tests precise IP matching
func TestMatchIPExact(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		ip       string
		expected bool
	}{
		{"exact match", "45.33.32.156", "45.33.32.156", true},
		{"partial match should fail", "145.33.32.156", "45.33.32.156", false},
		{"embedded match should fail", "145.33.32.1560", "45.33.32.156", false},
		{"match in JSON", `"remote_ip": "45.33.32.156"`, "45.33.32.156", true},
		{"match with port", "45.33.32.156:443", "45.33.32.156", true},
		{"different IP", "8.8.8.8", "45.33.32.156", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchIPExact(tt.content, tt.ip)
			if result != tt.expected {
				t.Errorf("MatchIPExact(%s, %s) = %v, expected %v", tt.content, tt.ip, result, tt.expected)
			}
		})
	}
}

// TestMatchHashExact tests precise hash matching
func TestMatchHashExact(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		hash     string
		expected bool
	}{
		{"MD5 exact match", "5ad82b42d8c9f1a5d5d5d5d5d5d5d5d5", "5ad82b42d8c9f1a5d5d5d5d5d5d5d5d5", true},
		{"MD5 partial should fail", "5ad82b42d8c9f1a5d5d5d5d5d5d5d5d50", "5ad82b42d8c9f1a5d5d5d5d5d5d5d5d5", false},
		{"SHA256 in JSON", `"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"different hash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "5ad82b42d8c9f1a5d5d5d5d5d5d5d5d5", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchHashExact(tt.content, tt.hash)
			if result != tt.expected {
				t.Errorf("MatchHashExact(%s, %s) = %v, expected %v", tt.content, tt.hash, result, tt.expected)
			}
		})
	}
}

// TestMatchDomainExact tests precise domain matching
func TestMatchDomainExact(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		domain   string
		expected bool
	}{
		{"exact match", "malware.example.com", "malware.example.com", true},
		{"subdomain should fail", "notmalware.example.com", "malware.example.com", false},
		{"different TLD should fail", "malware.example.org", "malware.example.com", false},
		{"match in URL", "http://malware.example.com/payload", "malware.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchDomainExact(tt.content, tt.domain)
			if result != tt.expected {
				t.Errorf("MatchDomainExact(%s, %s) = %v, expected %v", tt.content, tt.domain, result, tt.expected)
			}
		})
	}
}

// TestMatchProcessNameExact tests precise process name matching
func TestProcessNameExact(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		process  string
		expected bool
	}{
		{"exact match", "mimikatz.exe", "mimikatz", true},
		{"match without extension", "mimikatz", "mimikatz", true},
		{"partial should fail", "mimikatz.exe.bak", "mimikatz", false},
		{"different process", "notmimikatz.exe", "mimikatz", false},
		{"match in path", "C:\\Temp\\mimikatz.exe", "mimikatz", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchProcessNameExact(tt.content, tt.process)
			if result != tt.expected {
				t.Errorf("MatchProcessNameExact(%s, %s) = %v, expected %v", tt.content, tt.process, result, tt.expected)
			}
		})
	}
}

// TestMatchPortExact tests precise port matching
func TestMatchPortExact(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		port     string
		expected bool
	}{
		{"match with colon", "127.0.0.1:4444", "4444", true},
		{"match in JSON", `"remote_port": 4444`, "4444", true},
		{"partial should fail", "127.0.0.1:44444", "4444", false},
		{"different port", "127.0.0.1:80", "4444", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchPortExact(tt.content, tt.port)
			if result != tt.expected {
				t.Errorf("MatchPortExact(%s, %s) = %v, expected %v", tt.content, tt.port, result, tt.expected)
			}
		})
	}
}

// TestIOCDatabase tests IOC database operations
func TestIOCDatabase(t *testing.T) {
	db := NewIOCDatabase()

	// Add test IOCs
	db.Add(IOCDefinition{
		ID:          "test_ip",
		Value:       "192.168.1.100",
		IOCType:     "IP",
		Severity:    3,
		Description: "Test malicious IP",
	})

	db.Add(IOCDefinition{
		ID:          "test_hash",
		Value:       "abc123def456abc123def456abc123de",
		IOCType:     "MD5",
		Severity:    4,
		Description: "Test malicious hash",
	})

	// Test IP detection
	result := db.Detect("Connection to 192.168.1.100 detected")
	if len(result.Matches) == 0 {
		t.Error("Expected IP match, got none")
	}

	// Test hash detection
	result = db.Detect("File hash: abc123def456abc123def456abc123de")
	if len(result.Matches) == 0 {
		t.Error("Expected hash match, got none")
	}

	// Test no match
	result = db.Detect("Normal traffic to 8.8.8.8")
	if len(result.Matches) > 0 {
		t.Error("Expected no match for normal IP, got matches")
	}
}

// TestCompileRegexPattern tests concurrent-safe regex compilation
func TestCompileRegexPattern(t *testing.T) {
	// Test basic compilation
	re, err := CompileRegexPattern("test.*pattern")
	if err != nil {
		t.Errorf("Failed to compile regex: %v", err)
	}
	if re == nil {
		t.Error("Compiled regex is nil")
	}

	// Test caching (second call should return cached)
	re2, err := CompileRegexPattern("test.*pattern")
	if err != nil {
		t.Errorf("Failed to compile cached regex: %v", err)
	}
	if re2 != re {
		t.Error("Cache should return same regex object")
	}

	// Test invalid regex
	_, err = CompileRegexPattern("[invalid")
	if err == nil {
		t.Error("Expected error for invalid regex")
	}
}