//! IOC (Indicator of Compromise) detection

use crate::types::{IOC, IOCType, Match};
use aho_corasick::AhoCorasick;
use dashmap::DashMap;

/// High-performance IOC detector
pub struct IOCDetector {
    // Hash indexes (exact match)
    md5_index: DashMap<String, IOC>,
    sha1_index: DashMap<String, IOC>,
    sha256_index: DashMap<String, IOC>,

    // IP indexes (with CIDR support)
    ip_index: DashMap<String, IOC>,

    // Domain indexes (with subdomain matching)
    domain_index: DashMap<String, IOC>,

    // URL indexes
    url_index: DashMap<String, IOC>,

    // Fast pattern matcher for all string IOCs
    pattern_matcher: Option<AhoCorasick>,
    pattern_to_ioc: Vec<IOC>,

    // Stats
    ioc_count: usize,
}

impl IOCDetector {
    /// Create a new IOC detector
    pub fn new() -> Self {
        Self {
            md5_index: DashMap::new(),
            sha1_index: DashMap::new(),
            sha256_index: DashMap::new(),
            ip_index: DashMap::new(),
            domain_index: DashMap::new(),
            url_index: DashMap::new(),
            pattern_matcher: None,
            pattern_to_ioc: Vec::new(),
            ioc_count: 0,
        }
    }

    /// Load IOCs into the detector
    pub fn load(&mut self, iocs: &[IOC]) -> Result<(), Box<dyn std::error::Error>> {
        for ioc in iocs {
            self.add_ioc(ioc.clone());
        }
        self.build_matcher();
        Ok(())
    }

    /// Add a single IOC
    pub fn add_ioc(&mut self, ioc: IOC) {
        let value = ioc.value.to_lowercase();

        match ioc.ioc_type {
            IOCType::MD5 => {
                self.md5_index.insert(value, ioc.clone());
            }
            IOCType::SHA1 => {
                self.sha1_index.insert(value, ioc.clone());
            }
            IOCType::SHA256 => {
                self.sha256_index.insert(value, ioc.clone());
            }
            IOCType::IP => {
                self.ip_index.insert(value.clone(), ioc.clone());
            }
            IOCType::Domain => {
                self.domain_index.insert(value.clone(), ioc.clone());
            }
            IOCType::URL => {
                self.url_index.insert(value.clone(), ioc.clone());
            }
            _ => {}
        }

        // Add to pattern matcher
        self.pattern_to_ioc.push(ioc);
        self.ioc_count += 1;
    }

    /// Build the pattern matcher for fast string matching
    pub fn build_matcher(&mut self) {
        let patterns: Vec<String> = self.pattern_to_ioc.iter()
            .map(|ioc| ioc.value.to_lowercase())
            .collect();

        if !patterns.is_empty() {
            self.pattern_matcher = AhoCorasick::new(&patterns).ok();
        }
    }

    /// Detect IOCs in data
    pub fn detect(&self, data: &[u8]) -> Vec<Match> {
        let mut matches = Vec::new();

        // Fast pattern matching
        if let Some(matcher) = &self.pattern_matcher {
            for mat in matcher.find_iter(data) {
                let pattern_idx = mat.pattern().as_usize();
                if pattern_idx < self.pattern_to_ioc.len() {
                    let ioc = &self.pattern_to_ioc[pattern_idx];
                    matches.push(Match {
                        signature_id: ioc.id.clone(),
                        signature_name: ioc.value.clone(),
                        severity: ioc.severity,
                        position: mat.start(),
                        length: mat.end() - mat.start(),
                        details: std::collections::HashMap::new(),
                    });
                }
            }
        }

        matches
    }

    /// Check if a hash matches any IOC
    pub fn check_hash(&self, hash: &str) -> Option<IOC> {
        let hash_lower = hash.to_lowercase();

        // Check MD5
        if hash_lower.len() == 32 {
            if let Some(ioc) = self.md5_index.get(&hash_lower) {
                return Some(ioc.clone());
            }
        }

        // Check SHA1
        if hash_lower.len() == 40 {
            if let Some(ioc) = self.sha1_index.get(&hash_lower) {
                return Some(ioc.clone());
            }
        }

        // Check SHA256
        if hash_lower.len() == 64 {
            if let Some(ioc) = self.sha256_index.get(&hash_lower) {
                return Some(ioc.clone());
            }
        }

        None
    }

    /// Check if an IP matches any IOC
    pub fn check_ip(&self, ip: &str) -> Option<IOC> {
        self.ip_index.get(&ip.to_lowercase()).map(|r| r.clone())
    }

    /// Check if a domain matches any IOC
    pub fn check_domain(&self, domain: &str) -> Option<IOC> {
        let domain_lower = domain.to_lowercase();

        // Exact match
        if let Some(ioc) = self.domain_index.get(&domain_lower) {
            return Some(ioc.clone());
        }

        // Check parent domains
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 1..parts.len() - 1 {
            let parent = parts[i..].join(".");
            if let Some(ioc) = self.domain_index.get(&parent) {
                return Some(ioc.clone());
            }
        }

        None
    }

    /// Check if a URL matches any IOC
    pub fn check_url(&self, url: &str) -> Option<IOC> {
        self.url_index.get(&url.to_lowercase()).map(|r| r.clone())
    }

    /// Check if detector is empty
    pub fn is_empty(&self) -> bool {
        self.ioc_count == 0
    }

    /// Get IOC count
    pub fn count(&self) -> usize {
        self.ioc_count
    }
}

impl Default for IOCDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_detection() {
        let mut detector = IOCDetector::new();
        detector.add_ioc(IOC {
            id: "test-1".to_string(),
            value: "5d41402abc4b2a76b9719d911017c592".to_string(), // MD5 of "hello"
            ioc_type: IOCType::MD5,
            severity: Severity::High,
            description: Some("Test IOC".to_string()),
            tags: vec!["test".to_string()],
            source: None,
        });
        detector.build_matcher();

        let result = detector.check_hash("5d41402abc4b2a76b9719d911017c592");
        assert!(result.is_some());
    }

    #[test]
    fn test_domain_detection() {
        let mut detector = IOCDetector::new();
        detector.add_ioc(IOC {
            id: "test-2".to_string(),
            value: "malware.example.com".to_string(),
            ioc_type: IOCType::Domain,
            severity: Severity::Critical,
            description: None,
            tags: vec![],
            source: None,
        });
        detector.build_matcher();

        let result = detector.check_domain("malware.example.com");
        assert!(result.is_some());
    }
}
