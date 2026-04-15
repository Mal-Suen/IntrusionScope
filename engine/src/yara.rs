//! YARA rule matching

use crate::types::{Match, Severity};
use regex::Regex;
use std::collections::HashMap;

/// Parsed YARA rule
#[derive(Debug, Clone)]
pub struct YaraRule {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub strings: Vec<YaraString>,
    pub condition: String,
}

/// YARA string definition
#[derive(Debug, Clone)]
pub struct YaraString {
    pub id: String,
    pub string_type: YaraStringType,
    pub value: String,
    pub modifiers: Vec<String>,
}

/// Type of YARA string
#[derive(Debug, Clone)]
pub enum YaraStringType {
    Text,
    Hex,
    Regex,
}

/// YARA rule detector
pub struct YARADetector {
    rules: Vec<YaraRule>,
    compiled_patterns: Vec<(usize, Regex)>, // (rule_index, compiled_regex)
    text_patterns: Vec<(usize, String)>,    // (rule_index, text_pattern)
}

impl YARADetector {
    /// Create a new YARA detector
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled_patterns: Vec::new(),
            text_patterns: Vec::new(),
        }
    }

    /// Add a YARA rule
    pub fn add_rule(&mut self, rule_text: &str) -> Result<(), Box<dyn std::error::Error>> {
        let rule = self.parse_rule(rule_text)?;
        let rule_index = self.rules.len();

        // Compile patterns
        for yara_string in &rule.strings {
            match yara_string.string_type {
                YaraStringType::Text => {
                    self.text_patterns.push((rule_index, yara_string.value.clone()));
                }
                YaraStringType::Regex => {
                    if let Ok(re) = Regex::new(&yara_string.value) {
                        self.compiled_patterns.push((rule_index, re));
                    }
                }
                YaraStringType::Hex => {
                    // Convert hex pattern to regex
                    let regex_pattern = self.hex_to_regex(&yara_string.value);
                    if let Ok(re) = Regex::new(&regex_pattern) {
                        self.compiled_patterns.push((rule_index, re));
                    }
                }
            }
        }

        self.rules.push(rule);
        Ok(())
    }

    /// Parse a YARA rule (simplified)
    fn parse_rule(&self, rule_text: &str) -> Result<YaraRule, Box<dyn std::error::Error>> {
        let mut rule = YaraRule {
            name: String::new(),
            namespace: String::new(),
            tags: Vec::new(),
            meta: HashMap::new(),
            strings: Vec::new(),
            condition: String::new(),
        };

        let lines: Vec<&str> = rule_text.lines().collect();
        let mut in_strings = false;
        let mut in_condition = false;

        for line in lines {
            let trimmed = line.trim();

            // Parse rule header
            if trimmed.starts_with("rule ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    rule.name = parts[1].trim_end_matches('{').to_string();
                }
                continue;
            }

            // Parse meta
            if trimmed.starts_with("meta") {
                continue;
            }

            if trimmed.contains('=') && !in_strings && !in_condition {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim().to_string();
                    let value = parts[1].trim().trim_matches('"').to_string();
                    rule.meta.insert(key, value);
                }
            }

            // Parse strings section
            if trimmed.starts_with("strings") {
                in_strings = true;
                continue;
            }

            if in_strings && trimmed != "}" && !trimmed.starts_with("condition") {
                if let Some(yara_string) = self.parse_yara_string(trimmed) {
                    rule.strings.push(yara_string);
                }
            }

            // Parse condition section
            if trimmed.starts_with("condition") {
                in_strings = false;
                in_condition = true;
                continue;
            }

            if in_condition && trimmed != "}" {
                rule.condition.push_str(trimmed);
                rule.condition.push(' ');
            }
        }

        Ok(rule)
    }

    /// Parse a YARA string definition
    fn parse_yara_string(&self, line: &str) -> Option<YaraString> {
        // Format: $id = "value" or $id = { hex } or $id = /regex/
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 {
            return None;
        }

        let id = parts[0].trim().to_string();
        let value_part = parts[1].trim();

        let (string_type, value) = if value_part.starts_with('"') {
            (YaraStringType::Text, value_part.trim_matches('"').to_string())
        } else if value_part.starts_with('{') {
            let hex = value_part.trim_start_matches('{').trim_end_matches('}');
            (YaraStringType::Hex, hex.replace(' ', "").replace('\n', ""))
        } else if value_part.starts_with('/') {
            let regex = value_part.trim_start_matches('/').trim_end_matches('/');
            (YaraStringType::Regex, regex.to_string())
        } else {
            return None;
        };

        Some(YaraString {
            id,
            string_type,
            value,
            modifiers: Vec::new(),
        })
    }

    /// Convert hex pattern to regex
    fn hex_to_regex(&self, hex: &str) -> String {
        let mut regex = String::new();
        let chars: Vec<char> = hex.chars().collect();

        for chunk in chars.chunks(2) {
            if chunk.len() == 2 {
                if chunk[0] == '?' || chunk[1] == '?' {
                    regex.push_str(".");
                } else {
                    let byte = u8::from_str_radix(&chunk.iter().collect::<String>(), 16).unwrap_or(0);
                    regex.push_str(&format!("\\x{:02x}", byte));
                }
            }
        }

        regex
    }

    /// Detect matches in data
    pub fn detect(&self, data: &[u8]) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut rule_matches: HashMap<usize, bool> = HashMap::new();

        // Check text patterns
        for (rule_index, pattern) in &self.text_patterns {
            if data.windows(pattern.len()).any(|w| w == pattern.as_bytes()) {
                rule_matches.insert(*rule_index, true);
            }
        }

        // Check regex patterns
        let data_str = String::from_utf8_lossy(data);
        for (rule_index, regex) in &self.compiled_patterns {
            if regex.is_match(&data_str) {
                rule_matches.insert(*rule_index, true);
            }
        }

        // Create matches for matched rules
        for (rule_index, _) in rule_matches {
            if rule_index < self.rules.len() {
                let rule = &self.rules[rule_index];
                let severity = self.get_severity(rule);

                matches.push(Match {
                    signature_id: format!("yara_{}", rule.name),
                    signature_name: rule.name.clone(),
                    severity,
                    position: 0,
                    length: 0,
                    details: HashMap::new(),
                });
            }
        }

        matches
    }

    /// Get severity from rule metadata
    fn get_severity(&self, rule: &YaraRule) -> Severity {
        if let Some(sev) = rule.meta.get("severity") {
            match sev.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
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

impl Default for YARADetector {
    fn default() -> Self {
        Self::new()
    }
}
