// Package output provides output formatting for IntrusionScope results
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

// Format represents output format
type Format string

const (
	// FormatJSON outputs in JSON format
	FormatJSON Format = "json"
	// FormatCSV outputs in CSV format
	FormatCSV Format = "csv"
	// FormatHTML outputs in HTML format
	FormatHTML Format = "html"
	// FormatTable outputs as text table
	FormatTable Format = "table"
)

// Result represents a single result item
type Result struct {
	Timestamp   time.Time              `json:"timestamp"`
	Artifact    string                 `json:"artifact"`
	Source      string                 `json:"source"`
	Data        map[string]interface{} `json:"data"`
	ThreatLevel int                    `json:"threat_level,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
}

// Report represents a complete output report
type Report struct {
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	HostInfo    HostInfo  `json:"host_info"`
	Results     []Result  `json:"results"`
	Summary     Summary   `json:"summary"`
}

// HostInfo contains information about the scanned host
type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Platform string `json:"platform"`
	IPs      []string `json:"ips"`
}

// Summary contains scan summary statistics
type Summary struct {
	TotalArtifacts  int            `json:"total_artifacts"`
	TotalFindings   int            `json:"total_findings"`
	ThreatsByLevel  map[int]int    `json:"threats_by_level"`
	ArtifactsByType map[string]int `json:"artifacts_by_type"`
}

// Writer handles writing output in various formats
type Writer struct {
	format Format
	writer io.Writer
}

// NewWriter creates a new output writer
func NewWriter(format Format, w io.Writer) *Writer {
	return &Writer{
		format: format,
		writer: w,
	}
}

// WriteReport writes a complete report
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

func (w *Writer) writeJSON(report *Report) error {
	encoder := json.NewEncoder(w.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (w *Writer) writeCSV(report *Report) error {
	cw := csv.NewWriter(w.writer)
	defer cw.Flush()

	// Write header
	header := []string{"Timestamp", "Artifact", "Source", "Threat Level", "Tags", "Data"}
	if err := cw.Write(header); err != nil {
		return err
	}

	// Write rows
	for _, r := range report.Results {
		tags := strings.Join(r.Tags, ";")
		data, _ := json.Marshal(r.Data)
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

func (w *Writer) writeHTML(report *Report) error {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>IntrusionScope Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .summary { background: #f5f5f5; padding: 15px; margin: 20px 0; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #4CAF50; color: white; }
        tr:nth-child(even) { background: #f9f9f9; }
        .threat-1 { background: #fff3cd; }
        .threat-2 { background: #ffe0b2; }
        .threat-3 { background: #ffccbc; }
        .threat-4 { background: #ffcdd2; }
        .threat-5 { background: #ef9a9a; }
    </style>
</head>
<body>
    <h1>IntrusionScope Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Host:</strong> {{.HostInfo.Hostname}} ({{.HostInfo.OS}})</p>
        <p><strong>Scan Time:</strong> {{.StartTime}} - {{.EndTime}}</p>
        <p><strong>Total Artifacts:</strong> {{.Summary.TotalArtifacts}}</p>
        <p><strong>Total Findings:</strong> {{.Summary.TotalFindings}}</p>
    </div>
    <h2>Results</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Artifact</th>
            <th>Source</th>
            <th>Threat Level</th>
            <th>Tags</th>
        </tr>
        {{range .Results}}
        <tr class="threat-{{.ThreatLevel}}">
            <td>{{.Timestamp}}</td>
            <td>{{.Artifact}}</td>
            <td>{{.Source}}</td>
            <td>{{.ThreatLevel}}</td>
            <td>{{range .Tags}}{{.}} {{end}}</td>
        </tr>
        {{end}}
    </table>
</body>
</html>`

	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return err
	}

	return t.Execute(w.writer, report)
}

func (w *Writer) writeTable(report *Report) error {
	fmt.Fprintf(w.writer, "IntrusionScope Report\n")
	fmt.Fprintf(w.writer, "=====================\n\n")
	fmt.Fprintf(w.writer, "Host: %s (%s)\n", report.HostInfo.Hostname, report.HostInfo.OS)
	fmt.Fprintf(w.writer, "Scan Time: %s - %s\n", report.StartTime, report.EndTime)
	fmt.Fprintf(w.writer, "Total Findings: %d\n\n", report.Summary.TotalFindings)

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

// WriteFile writes output to a file
func WriteFile(report *Report, format Format, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := NewWriter(format, f)
	return w.WriteReport(report)
}
