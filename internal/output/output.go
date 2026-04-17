// Package output 提供 IntrusionScope 扫描结果的输出格式化功能
// 支持 JSON、CSV、HTML 和文本表格等多种输出格式
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// Format 表示输出格式类型
type Format string

const (
	// FormatJSON 以 JSON 格式输出
	FormatJSON Format = "json"
	// FormatCSV 以 CSV 格式输出
	FormatCSV Format = "csv"
	// FormatHTML 以 HTML 格式输出
	FormatHTML Format = "html"
	// FormatTable 以文本表格格式输出
	FormatTable Format = "table"
)

// Result 表示单个扫描结果项
type Result struct {
	Timestamp   time.Time              `json:"timestamp"`             // 时间戳
	Artifact    string                 `json:"artifact"`              // 产物名称
	Source      string                 `json:"source"`                // 数据来源
	Data        map[string]interface{} `json:"data"`                  // 结果数据
	ThreatLevel int                    `json:"threat_level,omitempty"` // 威胁等级
	Tags        []string               `json:"tags,omitempty"`        // 标签列表
}

// Report 表示完整的输出报告
type Report struct {
	StartTime   time.Time `json:"start_time"` // 扫描开始时间
	EndTime     time.Time `json:"end_time"`   // 扫描结束时间
	HostInfo    HostInfo  `json:"host_info"`  // 主机信息
	Results     []Result  `json:"results"`    // 扫描结果列表
	Summary     Summary   `json:"summary"`    // 扫描摘要统计
}

// HostInfo 包含被扫描主机的信息
type HostInfo struct {
	Hostname string   `json:"hostname"` // 主机名
	OS       string   `json:"os"`       // 操作系统
	Platform string   `json:"platform"` // 平台类型
	IPs      []string `json:"ips"`      // IP 地址列表
}

// Summary 包含扫描摘要统计信息
type Summary struct {
	TotalArtifacts  int            `json:"total_artifacts"`   // 产物总数
	TotalFindings   int            `json:"total_findings"`    // 发现总数
	ThreatsByLevel  map[int]int    `json:"threats_by_level"`  // 按威胁等级统计
	ArtifactsByType map[string]int `json:"artifacts_by_type"` // 按产物类型统计
}

// Writer 处理多种格式的输出写入
type Writer struct {
	format Format    // 输出格式
	writer io.Writer // 输出写入器
}

// NewWriter 创建一个新的输出写入器
func NewWriter(format Format, w io.Writer) *Writer {
	return &Writer{
		format: format,
		writer: w,
	}
}

// WriteReport 写入完整的报告
func (w *Writer) WriteReport(report *Report) error {
	switch w.format {
	case FormatJSON:
		return w.writeJSON(report)
	case FormatCSV:
		return w.writeCSV(report)
	case FormatHTML:
		return w.writeHTML(report)
	case FormatTable:
		return w.writeTable(report)
	default:
		return fmt.Errorf("unsupported format: %s", w.format)
	}
}

// writeJSON 以 JSON 格式写入报告
func (w *Writer) writeJSON(report *Report) error {
	encoder := json.NewEncoder(w.writer)
	encoder.SetIndent("", "  ") // 设置缩进为两个空格
	return encoder.Encode(report)
}

// writeCSV 以 CSV 格式写入报告
func (w *Writer) writeCSV(report *Report) error {
	cw := csv.NewWriter(w.writer)
	defer cw.Flush()

	// 写入表头
	header := []string{"Timestamp", "Artifact", "Source", "Threat Level", "Tags", "Data"}
	if err := cw.Write(header); err != nil {
		return err
	}

	// 写入数据行
	for _, r := range report.Results {
		tags := strings.Join(r.Tags, ";") // 标签用分号分隔
		data, _ := json.Marshal(r.Data)   // 数据字段序列化为 JSON
		row := []string{
			r.Timestamp.Format(time.RFC3339),
			r.Artifact,
			r.Source,
			fmt.Sprintf("%d", r.ThreatLevel),
			tags,
			string(data),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// writeHTML 以 HTML 格式写入报告
func (w *Writer) writeHTML(report *Report) error {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IntrusionScope Report - {{.HostInfo.Hostname}}</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #1f2937;
            --light: #f3f4f6;
            --border: #e5e7eb;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        
        /* Header */
        .header {
            background: white;
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        .header h1 {
            color: var(--dark);
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .header h1::before {
            content: "🔍";
            font-size: 1em;
        }
        .header-meta {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px; margin-top: 20px;
        }
        .meta-item {
            background: var(--light); padding: 15px; border-radius: 8px;
            border-left: 4px solid var(--primary);
        }
        .meta-label { font-size: 0.85em; color: #6b7280; margin-bottom: 5px; }
        .meta-value { font-size: 1.1em; font-weight: 600; color: var(--dark); }
        
        /* Stats Cards */
        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px; margin-bottom: 20px;
        }
        .stat-card {
            background: white; border-radius: 12px; padding: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .stat-card:hover { transform: translateY(-5px); box-shadow: 0 8px 30px rgba(0,0,0,0.12); }
        .stat-icon { font-size: 2.5em; margin-bottom: 10px; }
        .stat-value { font-size: 2em; font-weight: 700; color: var(--dark); }
        .stat-label { color: #6b7280; font-size: 0.9em; margin-top: 5px; }
        .stat-card.success .stat-icon { color: var(--success); }
        .stat-card.warning .stat-icon { color: var(--warning); }
        .stat-card.danger .stat-icon { color: var(--danger); }
        .stat-card.primary .stat-icon { color: var(--primary); }
        
        /* Sections */
        .section {
            background: white; border-radius: 16px; padding: 25px;
            margin-bottom: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        }
        .section h2 {
            color: var(--dark); font-size: 1.5em; margin-bottom: 20px;
            padding-bottom: 15px; border-bottom: 2px solid var(--light);
            display: flex; align-items: center; gap: 10px;
        }
        
        /* Artifact Summary */
        .artifact-grid {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
        }
        .artifact-item {
            background: var(--light); padding: 15px; border-radius: 8px;
            display: flex; justify-content: space-between; align-items: center;
        }
        .artifact-name { font-weight: 600; color: var(--dark); }
        .artifact-count {
            background: var(--primary); color: white; padding: 4px 12px;
            border-radius: 20px; font-size: 0.85em; font-weight: 600;
        }
        
        /* Results Table */
        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: var(--dark); color: white; font-weight: 600; position: sticky; top: 0; }
        tr:hover { background: var(--light); }
        .timestamp { font-family: 'Monaco', 'Consolas', monospace; font-size: 0.85em; color: #6b7280; }
        .threat-badge {
            display: inline-block; padding: 4px 10px; border-radius: 20px;
            font-size: 0.8em; font-weight: 600;
        }
        .threat-0 { background: #d1fae5; color: #065f46; }
        .threat-1 { background: #fef3c7; color: #92400e; }
        .threat-2 { background: #fed7aa; color: #9a3412; }
        .threat-3 { background: #fecaca; color: #991b1b; }
        .threat-4 { background: #fca5a5; color: #7f1d1d; }
        .threat-5 { background: #ef4444; color: white; }
        
        /* Data Preview */
        .data-preview {
            background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 8px;
            font-family: 'Monaco', 'Consolas', monospace; font-size: 0.85em;
            max-height: 200px; overflow: auto; white-space: pre-wrap;
            word-break: break-all;
        }
        
        /* Footer */
        .footer {
            text-align: center; padding: 20px; color: white;
            font-size: 0.9em; opacity: 0.8;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .header h1 { font-size: 1.8em; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>IntrusionScope Report</h1>
            <div class="header-meta">
                <div class="meta-item">
                    <div class="meta-label">Hostname</div>
                    <div class="meta-value">{{.HostInfo.Hostname}}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Operating System</div>
                    <div class="meta-value">{{.HostInfo.OS}}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Platform</div>
                    <div class="meta-value">{{.HostInfo.Platform}}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">IP Addresses</div>
                    <div class="meta-value">{{range $i, $ip := .HostInfo.IPs}}{{if $i}}, {{end}}{{$ip}}{{end}}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scan Started</div>
                    <div class="meta-value">{{.StartTime.Format "2006-01-02 15:04:05"}}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scan Completed</div>
                    <div class="meta-value">{{.EndTime.Format "2006-01-02 15:04:05"}}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Duration</div>
                    <div class="meta-value">{{.EndTime.Sub .StartTime}}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Generated</div>
                    <div class="meta-value">{{.EndTime.Format "2006-01-02 15:04:05 MST"}}</div>
                </div>
            </div>
        </div>
        
        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card primary">
                <div class="stat-icon">📦</div>
                <div class="stat-value">{{.Summary.TotalArtifacts}}</div>
                <div class="stat-label">Artifacts Collected</div>
            </div>
            <div class="stat-card success">
                <div class="stat-icon">📊</div>
                <div class="stat-value">{{.Summary.TotalFindings}}</div>
                <div class="stat-label">Total Records</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-icon">⚠️</div>
                <div class="stat-value">{{index .Summary.ThreatsByLevel 1}}</div>
                <div class="stat-label">Low Severity</div>
            </div>
            <div class="stat-card danger">
                <div class="stat-icon">🚨</div>
                <div class="stat-value">{{index .Summary.ThreatsByLevel 3}}</div>
                <div class="stat-label">High Severity</div>
            </div>
        </div>
        
        <!-- Artifacts Summary -->
        <div class="section">
            <h2>📁 Artifacts Summary</h2>
            <div class="artifact-grid">
                {{range $artifact, $count := .Summary.ArtifactsByType}}
                <div class="artifact-item">
                    <span class="artifact-name">{{$artifact}}</span>
                    <span class="artifact-count">{{$count}} records</span>
                </div>
                {{end}}
            </div>
        </div>
        
        <!-- Results -->
        <div class="section">
            <h2>📋 Collection Results</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Artifact</th>
                            <th>Source</th>
                            <th>Threat</th>
                            <th>Tags</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Results}}
                        <tr>
                            <td class="timestamp">{{.Timestamp.Format "2006-01-02 15:04:05"}}</td>
                            <td><strong>{{.Artifact}}</strong></td>
                            <td>{{.Source}}</td>
                            <td><span class="threat-badge threat-{{.ThreatLevel}}">
                                {{if eq .ThreatLevel 0}}None{{else if eq .ThreatLevel 1}}Low{{else if eq .ThreatLevel 2}}Medium{{else if eq .ThreatLevel 3}}High{{else if eq .ThreatLevel 4}}Critical{{else}}Unknown{{end}}
                            </span></td>
                            <td>{{range .Tags}}<span style="background:#e0e7ff;color:#3730a3;padding:2px 8px;border-radius:4px;font-size:0.8em;margin:2px;">{{.}}</span>{{end}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Sample Data -->
        {{if .Results}}
        <div class="section">
            <h2>🔍 Sample Data Preview</h2>
            <div class="data-preview">{{range $i, $r := .Results}}{{if lt $i 5}}[{{$r.Artifact}}] {{$r.Timestamp.Format "2006-01-02 15:04:05"}}
{{json $r.Data}}
{{end}}{{end}}</div>
        </div>
        {{end}}
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by IntrusionScope - Fast Host Forensics & Threat Hunting</p>
            <p>Report generated at {{.EndTime.Format "2006-01-02 15:04:05 MST"}}</p>
        </div>
    </div>
</body>
</html>`

	// 创建模板并添加 json 函数
	t, err := template.New("report").Funcs(template.FuncMap{
		"json": func(v interface{}) string {
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b)
		},
	}).Parse(tmpl)
	if err != nil {
		return err
	}

	// 执行模板并写入输出
	return t.Execute(w.writer, report)
}

// writeTable 以文本表格格式写入报告
func (w *Writer) writeTable(report *Report) error {
	// 输出报告头部信息
	fmt.Fprintf(w.writer, "IntrusionScope Report\n")
	fmt.Fprintf(w.writer, "=====================\n\n")
	fmt.Fprintf(w.writer, "Host: %s (%s)\n", report.HostInfo.Hostname, report.HostInfo.OS)
	fmt.Fprintf(w.writer, "Scan Time: %s - %s\n", report.StartTime, report.EndTime)
	fmt.Fprintf(w.writer, "Total Findings: %d\n\n", report.Summary.TotalFindings)

	// 输出每个结果项
	for _, r := range report.Results {
		fmt.Fprintf(w.writer, "[%s] %s - %s (Threat: %d)\n",
			r.Timestamp.Format(time.RFC3339),
			r.Artifact,
			r.Source,
			r.ThreatLevel,
		)
	}

	return nil
}

// WriteFile 将报告写入指定文件
func WriteFile(report *Report, format Format, path string) error {
	// 确保目标目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 创建目标文件
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// 使用 Writer 写入报告
	w := NewWriter(format, f)
	return w.WriteReport(report)
}
