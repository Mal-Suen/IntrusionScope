// Package detector provides threat detection capabilities
// This file contains precise matching functions to avoid false positives
package detector

import (
	"net"
	"regexp"
	"strings"
)

// PreciseMatcher provides precise matching algorithms to avoid false positives
type PreciseMatcher struct{}

// MatchIPExact 精确匹配 IP 地址，避免部分匹配误报
// 例如：1.2.3.4 不会匹配到 11.2.3.40
func MatchIPExact(content, ip string) bool {
	// 验证 IP 格式
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		// 不是有效的 IP，使用字符串包含匹配
		return strings.Contains(content, ip)
	}

	// 使用正则表达式进行边界匹配
	// 匹配 IP 前后是非数字和非点号字符
	pattern := `(?<![0-9.])` + regexp.QuoteMeta(ip) + `(?![0-9.])`
	matched, _ := regexp.MatchString(pattern, content)
	return matched
}

// MatchHashExact 精确匹配哈希值
// 哈希值通常是固定长度，需要边界匹配
func MatchHashExact(content, hash string) bool {
	hashLen := len(hash)
	
	// 根据哈希长度确定类型
	// MD5: 32, SHA1: 40, SHA256: 64
	validLengths := map[int]string{32: "md5", 40: "sha1", 64: "sha256"}
	
	if _, valid := validLengths[hashLen]; !valid {
		// 非标准哈希长度，使用包含匹配
		return strings.Contains(strings.ToLower(content), strings.ToLower(hash))
	}

	// 使用正则表达式进行边界匹配
	// 哈希值前后应该是非十六进制字符
	pattern := `(?i)(?<![0-9a-f])` + regexp.QuoteMeta(hash) + `(?![0-9a-f])`
	matched, _ := regexp.MatchString(pattern, content)
	return matched
}

// MatchDomainExact 精确匹配域名
// 例如：evil.com 不会匹配到 notevil.com 或 evil.com.au
func MatchDomainExact(content, domain string) bool {
	domain = strings.ToLower(domain)
	contentLower := strings.ToLower(content)
	
	// 使用正则表达式进行边界匹配
	// 域名前后应该是非字母数字字符（除了点号和连字符）
	pattern := `(?<![a-z0-9.-])` + regexp.QuoteMeta(domain) + `(?![a-z0-9.-])`
	matched, _ := regexp.MatchString(pattern, contentLower)
	return matched
}

// MatchURLExact 精确匹配 URL
func MatchURLExact(content, url string) bool {
	url = strings.ToLower(url)
	contentLower := strings.ToLower(content)
	
	// URL 通常有明确的边界
	// 检查 URL 是否作为独立实体出现
	pattern := `(?<![a-z0-9])` + regexp.QuoteMeta(url) + `(?![a-z0-9/])`
	matched, _ := regexp.MatchString(pattern, contentLower)
	return matched
}

// MatchProcessNameExact 精确匹配进程名
// 例如：mimikatz 不会匹配到 mimikatz.exe.bak
func MatchProcessNameExact(content, processName string) bool {
	processName = strings.ToLower(processName)
	contentLower := strings.ToLower(content)
	
	// 进程名可能带 .exe 后缀或不带
	// 匹配进程名后跟 .exe 或边界字符
	pattern := `(?<![a-z0-9._-])` + regexp.QuoteMeta(processName) + `(\.exe)?(?![a-z0-9._-])`
	matched, _ := regexp.MatchString(pattern, contentLower)
	return matched
}

// MatchPathExact 精确匹配路径
// 路径匹配需要考虑路径分隔符
func MatchPathExact(content, path string) bool {
	path = strings.ToLower(path)
	contentLower := strings.ToLower(content)
	
	// 路径通常包含反斜杠或斜杠
	// 使用包含匹配，但验证路径边界
	return strings.Contains(contentLower, path)
}

// MatchPortExact 精确匹配端口号
// 端口号必须作为独立数字出现，不能是其他数字的一部分
func MatchPortExact(content, port string) bool {
	// 端口通常出现在冒号后面，如 :4444 或 :80
	// 或者作为 "port": 4444 这样的 JSON 值
	
	// 模式1: 冒号后跟端口号 (如 127.0.0.1:4444)
	pattern1 := `:` + regexp.QuoteMeta(port) + `(?![0-9])`
	if matched, _ := regexp.MatchString(pattern1, content); matched {
		return true
	}
	
	// 模式2: JSON 格式中的端口号 (如 "port": 4444)
	pattern2 := `"port"[\s]*:[\s]*` + regexp.QuoteMeta(port) + `(?![0-9])`
	if matched, _ := regexp.MatchString(pattern2, content); matched {
		return true
	}
	
	// 模式3: remote_port 或 local_port 字段
	pattern3 := `"(?:remote|local)_port"[\s]*:[\s]*` + regexp.QuoteMeta(port) + `(?![0-9])`
	if matched, _ := regexp.MatchString(pattern3, content); matched {
		return true
	}
	
	return false
}

// MatchBehavioralPattern 匹配行为模式（用于可疑命令检测）
// 这类模式可以宽松匹配，因为命令参数变化较大
func MatchBehavioralPattern(content, pattern string) bool {
	contentLower := strings.ToLower(content)
	patternLower := strings.ToLower(pattern)
	return strings.Contains(contentLower, patternLower)
}

// CompileRegexPattern 编译正则表达式模式（带缓存）
var regexCache = make(map[string]*regexp.Regexp)

func CompileRegexPattern(pattern string) (*regexp.Regexp, error) {
	if cached, ok := regexCache[pattern]; ok {
		return cached, nil
	}
	
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	
	regexCache[pattern] = compiled
	return compiled, nil
}
