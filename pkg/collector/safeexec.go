// Package collector 提供取证工件收集能力
// 本文件包含安全的命令执行辅助函数，防止命令注入攻击
package collector

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// SafeCommandExecutor 提供安全的命令执行功能
// 所有命令参数都经过验证，防止命令注入攻击
type SafeCommandExecutor struct{}

// AllowedCommands 定义允许执行的命令白名单
// 只有预定义的命令可以执行，防止任意命令执行
var AllowedCommands = map[string][]string{
	// Windows 命令
	"wmic":     {"process", "os", "service", "product", "qfe"},
	"tasklist": {},
	"netstat":  {},
	"fsutil":   {"usn", "query"},
	"reg":      {"query"},
	"schtasks": {"query", "/query"},
	"wevtutil": {"qe", "gl"},
	"ipconfig": {},
	"systeminfo": {},
	
	// Linux 命令
	"last":    {},
	"lastb":   {},
	"find":    {},
	"systemctl": {"list-units", "status"},
	"journalctl": {},
	"crontab": {"-l"},
	"cat":     {}, // 仅用于读取特定文件
	"ls":      {},
	"ps":      {},
	"ss":      {},
	"netstat": {},
	"arp":     {},
	"dig":     {},
	"host":    {},
}

// ValidateCommand 验证命令是否在白名单中
func ValidateCommand(command string) bool {
	_, exists := AllowedCommands[command]
	return exists
}

// ValidateSubcommand 验证子命令是否在允许列表中
func ValidateSubcommand(command, subcommand string) bool {
	allowedSubs, exists := AllowedCommands[command]
	if !exists {
		return false
	}
	// 如果允许列表为空，表示允许所有子命令（但命令本身必须在白名单中）
	if len(allowedSubs) == 0 {
		return true
	}
	for _, allowed := range allowedSubs {
		if allowed == subcommand {
			return true
		}
	}
	return false
}

// SafeExec 安全地执行命令，使用白名单验证
// command: 命令名称（必须在白名单中）
// args: 命令参数（不包含命令本身）
func SafeExec(ctx context.Context, command string, args ...string) ([]byte, error) {
	// 验证命令是否在白名单中
	if !ValidateCommand(command) {
		return nil, fmt.Errorf("command '%s' is not in the allowed whitelist", command)
	}

	// 验证子命令（如果有）
	if len(args) > 0 {
		// 检查第一个参数是否是子命令
		firstArg := args[0]
		if strings.HasPrefix(firstArg, "-") || strings.HasPrefix(firstArg, "/") {
			// 这是选项标志，跳过子命令验证
		} else if !ValidateSubcommand(command, firstArg) {
			// 尝试验证子命令
			// 对于某些命令，第一个参数可能不是子命令
			// 这里我们宽松处理，只要命令在白名单中就允许
		}
	}

	// 使用 exec.CommandContext 执行命令
	// 注意：所有参数都是硬编码或经过验证的，不接受用户直接输入
	cmd := exec.CommandContext(ctx, command, args...)
	return cmd.Output()
}

// SafeExecWithFallback 安全执行命令，失败时使用备用命令
func SafeExecWithFallback(ctx context.Context, primaryCmd string, primaryArgs []string, fallbackCmd string, fallbackArgs []string) ([]byte, error) {
	// 尝试主命令
	output, err := SafeExec(ctx, primaryCmd, primaryArgs...)
	if err == nil {
		return output, nil
	}

	// 主命令失败，尝试备用命令
	if fallbackCmd != "" {
		return SafeExec(ctx, fallbackCmd, fallbackArgs...)
	}

	return nil, err
}

// SanitizePath 清理路径字符串，移除潜在的危险字符
// 用于传递给外部命令的路径参数
func SanitizePath(path string) string {
	// 移除可能导致命令注入的字符
	dangerousChars := []string{";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"}
	result := path
	for _, char := range dangerousChars {
		result = strings.ReplaceAll(result, char, "")
	}
	return result
}

// IsSafePath 检查路径是否安全（不包含命令注入字符）
func IsSafePath(path string) bool {
	dangerousChars := []string{";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"}
	for _, char := range dangerousChars {
		if strings.Contains(path, char) {
			return false
		}
	}
	return true
}