//! Fast pattern matching using Aho-Corasick algorithm

use aho_corasick::AhoCorasick;

/// High-performance pattern matcher
pub struct PatternMatcher {
    patterns: Vec<String>,
    matcher: Option<AhoCorasick>,
    built: bool,
}

impl PatternMatcher {
    /// Create a new pattern matcher
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            matcher: None,
            built: false,
        }
    }

    /// Add a pattern
    pub fn add_pattern(&mut self, pattern: &str, _id: usize) {
        self.patterns.push(pattern.to_lowercase());
        self.built = false;
    }

    /// Add multiple patterns
    pub fn add_patterns(&mut self, patterns: &[&str]) {
        for pattern in patterns {
            self.patterns.push(pattern.to_lowercase());
        }
        self.built = false;
    }

    /// Build the matcher (must call before find)
    pub fn build(&mut self) {
        if !self.patterns.is_empty() {
            self.matcher = AhoCorasick::new(&self.patterns).ok();
            self.built = true;
        }
    }

    /// Find all pattern matches in data
    pub fn find(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut results = Vec::new();

        if let Some(matcher) = &self.matcher {
            for mat in matcher.find_iter(data) {
                let pattern_id = mat.pattern().as_usize();
                let position = mat.start();
                results.push((pattern_id, position));
            }
        }

        results
    }

    /// Find all pattern matches in string
    pub fn find_in_str(&self, text: &str) -> Vec<(usize, usize)> {
        self.find(text.as_bytes())
    }

    /// Check if any pattern matches
    pub fn is_match(&self, data: &[u8]) -> bool {
        if let Some(matcher) = &self.matcher {
            matcher.is_match(data)
        } else {
            false
        }
    }

    /// Replace all matches with replacement
    pub fn replace_all(&self, text: &str, replacement: &str) -> String {
        if let Some(matcher) = &self.matcher {
            matcher.replace_all(text, &[replacement])
        } else {
            text.to_string()
        }
    }

    /// Get pattern count
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Check if matcher is built
    pub fn is_built(&self) -> bool {
        self.built
    }

    /// Clear all patterns
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.matcher = None;
        self.built = false;
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Suspicious pattern presets
pub mod presets {
    /// Common malware strings
    pub const MALWARE_PATTERNS: &[&str] = &[
        "mimikatz",
        "metasploit",
        "cobaltstrike",
        "meterpreter",
        "powersploit",
        "empire",
        "covenant",
        "brute rat",
        "njrat",
        "nanocore",
        "remcos",
        "darkcomet",
        "pluton",
        "dridex",
        "emotet",
        "trickbot",
        "ryuk",
        "conti",
        "lockbit",
        "blackcat",
    ];

    /// Suspicious PowerShell patterns
    pub const POWERSHELL_PATTERNS: &[&str] = &[
        "-enc",
        "-encodedcommand",
        "-e ",
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "iwr ",
        "invoke-expression",
        "iex ",
        "frombase64string",
        "net.webclient",
        "start-bitstransfer",
        "set-mppreference",
        "bypass",
        "hidden",
        "noprofile",
        "windowstyle hidden",
    ];

    /// Suspicious command patterns
    pub const COMMAND_PATTERNS: &[&str] = &[
        "certutil -urlcache",
        "certutil -split",
        "bitsadmin /transfer",
        "reg save",
        "reg add",
        "net user",
        "net localgroup",
        "wmic process",
        "rundll32",
        "mshta",
        "regsvr32",
        "scriptrunner",
        "forfiles",
        "pcalua",
        "syncappvpublishingserver",
    ];

    /// Living off the land binaries (LOLBins)
    pub const LOLBINS: &[&str] = &[
        "certutil.exe",
        "bitsadmin.exe",
        "regsvr32.exe",
        "mshta.exe",
        "rundll32.exe",
        "cmstp.exe",
        "control.exe",
        "cscript.exe",
        "wscript.exe",
        "forfiles.exe",
        "pcalua.exe",
        "syncappvpublishingserver.exe",
        "scriptrunner.exe",
        "odbcconf.exe",
        "infdefaultinstall.exe",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let mut matcher = PatternMatcher::new();
        matcher.add_patterns(&["hello", "world"]);
        matcher.build();

        let results = matcher.find_in_str("hello world");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_malware_patterns() {
        let mut matcher = PatternMatcher::new();
        matcher.add_patterns(presets::MALWARE_PATTERNS);
        matcher.build();

        assert!(matcher.is_match(b"this is mimikatz test"));
        assert!(matcher.is_match(b"cobaltstrike beacon"));
        assert!(!matcher.is_match(b"normal text"));
    }
}
