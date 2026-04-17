// Package logger 提供 IntrusionScope 的结构化日志功能。
// 支持 JSON 和 Text 两种输出格式。
package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// Level 日志级别
type Level int

const (
	// Debug 调试级别
	Debug Level = iota
	// Info 信息级别
	Info
	// Warn 警告级别
	Warn
	// Error 错误级别
	Error
)

// String 返回日志级别的字符串表示
func (l Level) String() string {
	switch l {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger 结构化日志记录器
type Logger struct {
	level     Level                   // 日志级别
	format    string                  // 输出格式："json" 或 "text"
	writer    io.Writer               // 输出目标
	mu        sync.Mutex              // 互斥锁
	fields    map[string]interface{}  // 附加字段
}

// New 创建新的日志记录器
func New(verbose bool) *Logger {
	level := Info
	if verbose {
		level = Debug
	}

	return &Logger{
		level:  level,
		format: "json",
		writer: os.Stderr,
		fields: make(map[string]interface{}),
	}
}

// NewWithConfig 使用指定配置创建日志记录器
func NewWithConfig(level string, format string, writer io.Writer) *Logger {
	l := Info
	switch level {
	case "debug":
		l = Debug
	case "warn":
		l = Warn
	case "error":
		l = Error
	}

	if writer == nil {
		writer = os.Stderr
	}

	return &Logger{
		level:  l,
		format: format,
		writer: writer,
		fields: make(map[string]interface{}),
	}
}

// WithFields 返回带有附加字段的新日志记录器
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	newLogger := &Logger{
		level:  l.level,
		format: l.format,
		writer: l.writer,
		fields: make(map[string]interface{}),
	}

	// 复制现有字段
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// 添加新字段
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	return newLogger
}

// log 写入日志条目
func (l *Logger) log(level Level, msg string, args ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// 构建日志条目
	entry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"level":     level.String(),
		"message":   msg,
	}

	// 添加现有字段
	for k, v := range l.fields {
		entry[k] = v
	}

	// 处理键值对参数（必须为偶数个）
	for i := 0; i < len(args)-1; i += 2 {
		if key, ok := args[i].(string); ok {
			entry[key] = args[i+1]
		}
	}

	if l.format == "json" {
		data, err := json.Marshal(entry)
		if err != nil {
			log.Printf("error marshaling log entry: %v", err)
			return
		}
		fmt.Fprintln(l.writer, string(data))
	} else {
		// Text 格式
		fmt.Fprintf(l.writer, "[%s] %s: %s", entry["timestamp"], level.String(), entry["message"])
		for k, v := range l.fields {
			fmt.Fprintf(l.writer, " %s=%v", k, v)
		}
		fmt.Fprintln(l.writer)
	}
}

// Debug 记录调试消息
func (l *Logger) Debug(msg string, args ...interface{}) {
	l.log(Debug, msg, args...)
}

// Info 记录信息消息
func (l *Logger) Info(msg string, args ...interface{}) {
	l.log(Info, msg, args...)
}

// Warn 记录警告消息
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.log(Warn, msg, args...)
}

// Error 记录错误消息
func (l *Logger) Error(msg string, args ...interface{}) {
	l.log(Error, msg, args...)
}

// Fatal 记录错误消息并退出程序
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.log(Error, msg, args...)
	os.Exit(1)
}
