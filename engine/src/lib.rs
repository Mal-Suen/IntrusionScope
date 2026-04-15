//! IntrusionScope Detection Engine
//!
//! High-performance detection engine written in Rust for:
//! - IOC matching (hash, IP, domain, URL)
//! - YARA rule matching
//! - Sigma rule evaluation
//! - Pattern matching with Aho-Corasick

pub mod ioc;
pub mod yara;
pub mod sigma;
pub mod matcher;
pub mod ffi;
pub mod types;

pub use types::{DetectionResult, Match, Severity};
pub use ioc::IOCDetector;
pub use yara::YARADetector;
pub use sigma::SigmaDetector;
pub use matcher::PatternMatcher;

/// Detection engine combining all detectors
pub struct Engine {
    ioc: IOCDetector,
    yara: YARADetector,
    sigma: SigmaDetector,
    matcher: PatternMatcher,
}

impl Engine {
    /// Create a new detection engine
    pub fn new() -> Self {
        Self {
            ioc: IOCDetector::new(),
            yara: YARADetector::new(),
            sigma: SigmaDetector::new(),
            matcher: PatternMatcher::new(),
        }
    }

    /// Load IOC signatures
    pub fn load_iocs(&mut self, iocs: &[types::IOC]) -> Result<(), Box<dyn std::error::Error>> {
        self.ioc.load(iocs)?;
        Ok(())
    }

    /// Load YARA rules
    pub fn load_yara_rules(&mut self, rules: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        for rule in rules {
            self.yara.add_rule(rule)?;
        }
        Ok(())
    }

    /// Load Sigma rules
    pub fn load_sigma_rules(&mut self, rules: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        for rule in rules {
            self.sigma.add_rule(rule)?;
        }
        Ok(())
    }

    /// Add pattern for fast matching
    pub fn add_pattern(&mut self, pattern: &str, id: usize) {
        self.matcher.add_pattern(pattern, id);
    }

    /// Build pattern matcher (call after adding all patterns)
    pub fn build_matcher(&mut self) {
        self.matcher.build();
    }

    /// Detect threats in data
    pub fn detect(&self, data: &[u8]) -> DetectionResult {
        let mut result = DetectionResult::default();

        // IOC detection
        let ioc_matches = self.ioc.detect(data);
        result.matches.extend(ioc_matches);

        // YARA detection
        let yara_matches = self.yara.detect(data);
        result.matches.extend(yara_matches);

        // Pattern matching
        let pattern_matches = self.matcher.find(data);
        for (id, pos) in pattern_matches {
            result.matches.push(Match {
                signature_id: format!("pattern_{}", id),
                signature_name: format!("Pattern {}", id),
                severity: Severity::Medium,
                position: pos,
                length: 0,
                details: Default::default(),
            });
        }

        result.total_matches = result.matches.len();
        result
    }

    /// Detect in structured data (JSON)
    pub fn detect_json(&self, json: &str) -> DetectionResult {
        let mut result = DetectionResult::default();

        // Parse JSON and check each field
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(json) {
            self.detect_value(&value, &mut result);
        }

        result.total_matches = result.matches.len();
        result
    }

    fn detect_value(&self, value: &serde_json::Value, result: &mut DetectionResult) {
        match value {
            serde_json::Value::String(s) => {
                let matches = self.ioc.detect(s.as_bytes());
                result.matches.extend(matches);
            }
            serde_json::Value::Object(map) => {
                for (_, v) in map {
                    self.detect_value(v, result);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    self.detect_value(v, result);
                }
            }
            _ => {}
        }
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = Engine::new();
        assert!(engine.ioc.is_empty());
    }

    #[test]
    fn test_pattern_matching() {
        let mut engine = Engine::new();
        engine.add_pattern("malware", 1);
        engine.add_pattern("suspicious", 2);
        engine.build_matcher();

        let result = engine.detect(b"this is a malware test");
        assert!(result.total_matches > 0);
    }
}
