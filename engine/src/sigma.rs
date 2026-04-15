//! Sigma rule detection

use crate::types::{Match, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parsed Sigma rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub level: Option<String>,
    pub status: Option<String>,
    pub author: Option<String>,
    pub tags: Vec<String>,
    pub logsource: LogSource,
    pub detection: Detection,
}

/// Sigma log source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

/// Sigma detection section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub selection: HashMap<String, serde_json::Value>,
    pub condition: Option<String>,
}

/// Sigma rule detector
pub struct SigmaDetector {
    rules: Vec<SigmaRule>,
}

impl SigmaDetector {
    /// Create a new Sigma detector
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
        }
    }

    /// Add a Sigma rule (YAML format)
    pub fn add_rule(&mut self, yaml: &str) -> Result<(), Box<dyn std::error::Error>> {
        let rule: SigmaRule = serde_yaml::from_str(yaml)?;
        self.rules.push(rule);
        Ok(())
    }

    /// Add a parsed Sigma rule
    pub fn add_parsed_rule(&mut self, rule: SigmaRule) {
        self.rules.push(rule);
    }

    /// Detect matches in JSON data
    pub fn detect_json(&self, json: &str) -> Vec<Match> {
        let mut matches = Vec::new();

        if let Ok(value) = serde_json::from_str::<serde_json::Value>(json) {
            for rule in &self.rules {
                if self.match_rule(rule, &value) {
                    matches.push(Match {
                        signature_id: rule.id.clone().unwrap_or_else(|| rule.title.clone()),
                        signature_name: rule.title.clone(),
                        severity: self.get_severity(rule),
                        position: 0,
                        length: 0,
                        details: HashMap::new(),
                    });
                }
            }
        }

        matches
    }

    /// Check if a rule matches the data
    fn match_rule(&self, rule: &SigmaRule, value: &serde_json::Value) -> bool {
        // Check logsource compatibility
        if !self.match_logsource(&rule.logsource, value) {
            return false;
        }

        // Check selection criteria
        for (field, criteria) in &rule.detection.selection {
            if !self.match_criteria(field, criteria, value) {
                return false;
            }
        }

        true
    }

    /// Check logsource compatibility
    fn match_logsource(&self, logsource: &LogSource, value: &serde_json::Value) -> bool {
        if let Some(obj) = value.as_object() {
            if let Some(record_type) = obj.get("type").and_then(|v| v.as_str()) {
                if let Some(ref category) = logsource.category {
                    // Map Sigma categories to record types
                    let mapped = match category.as_str() {
                        "process_creation" => "process",
                        "network_connection" => "network",
                        "file_event" => "filesystem",
                        _ => category.as_str(),
                    };
                    return record_type.contains(mapped);
                }
            }
        }
        true
    }

    /// Match selection criteria
    fn match_criteria(&self, field: &str, criteria: &serde_json::Value, data: &serde_json::Value) -> bool {
        // Get field value from data
        let field_value = self.get_field(field, data);

        match criteria {
            serde_json::Value::String(pattern) => {
                self.match_string_pattern(&field_value, pattern)
            }
            serde_json::Value::Array(values) => {
                // OR logic: any value matches
                values.iter().any(|v| self.match_criteria(field, v, data))
            }
            serde_json::Value::Object(modifiers) => {
                // Handle modifiers like contains, startswith, endswith
                for (modifier, value) in modifiers {
                    match modifier.as_str() {
                        "contains" => {
                            if let Some(pattern) = value.as_str() {
                                let fv = self.value_to_string(&field_value);
                                if !fv.to_lowercase().contains(&pattern.to_lowercase()) {
                                    return false;
                                }
                            }
                        }
                        "startswith" => {
                            if let Some(pattern) = value.as_str() {
                                let fv = self.value_to_string(&field_value);
                                if !fv.to_lowercase().starts_with(&pattern.to_lowercase()) {
                                    return false;
                                }
                            }
                        }
                        "endswith" => {
                            if let Some(pattern) = value.as_str() {
                                let fv = self.value_to_string(&field_value);
                                if !fv.to_lowercase().ends_with(&pattern.to_lowercase()) {
                                    return false;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Get field value from nested data
    fn get_field(&self, field: &str, data: &serde_json::Value) -> serde_json::Value {
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = data.clone();

        for part in parts {
            if let Some(obj) = current.as_object() {
                if let Some(value) = obj.get(part) {
                    current = value.clone();
                } else {
                    return serde_json::Value::Null;
                }
            } else {
                return serde_json::Value::Null;
            }
        }

        current
    }

    /// Match string pattern (with wildcard support)
    fn match_string_pattern(&self, value: &serde_json::Value, pattern: &str) -> bool {
        let value_str = self.value_to_string(value);

        if pattern.contains('*') {
            // Convert wildcard to regex
            let regex_pattern = pattern.replace('*', ".*");
            if let Ok(re) = Regex::new(&format!("(?i)^{}$", regex_pattern)) {
                return re.is_match(&value_str);
            }
        }

        value_str.eq_ignore_ascii_case(pattern)
    }

    /// Convert JSON value to string
    fn value_to_string(&self, value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => String::new(),
        }
    }

    /// Get severity from rule
    fn get_severity(&self, rule: &SigmaRule) -> Severity {
        if let Some(ref level) = rule.level {
            match level.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                "informational" => Severity::Info,
                _ => Severity::Medium,
            }
        } else {
            Severity::Medium
        }
    }

    /// Get rule count
    pub fn count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for SigmaDetector {
    fn default() -> Self {
        Self::new()
    }
}

// Minimal serde_yaml implementation for parsing
mod serde_yaml {
    use serde::de::DeserializeOwned;

    pub fn from_str<T: DeserializeOwned>(s: &str) -> Result<T, Box<dyn std::error::Error>> {
        // Simplified YAML parsing - just use JSON for now
        // In production, use the serde_yaml crate
        let json = yaml_to_json(s);
        Ok(serde_json::from_str(&json)?)
    }

    fn yaml_to_json(yaml: &str) -> String {
        // Very basic YAML to JSON conversion
        let mut result = String::from("{");

        for line in yaml.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.contains(':') {
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                if parts.len() == 2 {
                    if !result.ends_with('{') {
                        result.push(',');
                    }
                    result.push_str(&format!("\"{}\":", parts[0].trim()));
                    let value = parts[1].trim();
                    if value.starts_with('"') || value.starts_with('\'') {
                        result.push_str(value);
                    } else if value.is_empty() {
                        result.push_str("null");
                    } else {
                        result.push_str(&format!("\"{}\"", value));
                    }
                }
            }
        }

        result.push('}');
        result
    }
}
