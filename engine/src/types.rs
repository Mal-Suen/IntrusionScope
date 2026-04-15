//! Common types for the detection engine

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity level for detections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum Severity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

impl From<i32> for Severity {
    fn from(value: i32) -> Self {
        match value {
            1 => Severity::Info,
            2 => Severity::Low,
            3 => Severity::Medium,
            4 => Severity::High,
            5 => Severity::Critical,
            _ => Severity::Medium,
        }
    }
}

/// A single detection match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    /// Signature ID that matched
    pub signature_id: String,
    /// Signature name
    pub signature_name: String,
    /// Severity level
    pub severity: Severity,
    /// Position in data where match occurred
    pub position: usize,
    /// Length of matched content
    pub length: usize,
    /// Additional match details
    pub details: HashMap<String, String>,
}

/// Detection result containing all matches
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectionResult {
    /// All matches found
    pub matches: Vec<Match>,
    /// Total number of matches
    pub total_matches: usize,
    /// Detection time in microseconds
    pub detection_time_us: u64,
}

/// IOC (Indicator of Compromise)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOC {
    /// IOC identifier
    pub id: String,
    /// IOC value (hash, IP, domain, URL, etc.)
    pub value: String,
    /// IOC type
    pub ioc_type: IOCType,
    /// Severity level
    pub severity: Severity,
    /// Description
    pub description: Option<String>,
    /// Tags
    pub tags: Vec<String>,
    /// Source where IOC was obtained
    pub source: Option<String>,
}

/// Type of IOC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IOCType {
    /// MD5 hash
    MD5,
    /// SHA1 hash
    SHA1,
    /// SHA256 hash
    SHA256,
    /// IP address
    IP,
    /// Domain name
    Domain,
    /// URL
    URL,
    /// Email address
    Email,
    /// File path
    FilePath,
    /// Registry key
    Registry,
}

/// Record to analyze
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Record type
    pub record_type: String,
    /// Record data as key-value pairs
    pub data: HashMap<String, serde_json::Value>,
}

/// Statistics for the detection engine
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngineStats {
    /// Number of IOC signatures loaded
    pub ioc_count: usize,
    /// Number of YARA rules loaded
    pub yara_count: usize,
    /// Number of Sigma rules loaded
    pub sigma_count: usize,
    /// Number of patterns loaded
    pub pattern_count: usize,
    /// Memory usage in bytes
    pub memory_bytes: usize,
}
