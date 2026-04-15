// Package ifql provides IFQL (IntrusionScope Forensic Query Language) parsing and execution
package ifql

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Executor executes IFQL queries against collected data
type Executor struct {
	dataDir string
}

// NewExecutor creates a new IFQL executor
func NewExecutor(dataDir string) *Executor {
	return &Executor{dataDir: dataDir}
}

// Execute runs an IFQL query and returns results
func (e *Executor) Execute(query *Query) ([]map[string]interface{}, error) {
	if query == nil {
		return nil, fmt.Errorf("nil query")
	}

	// Load data from the source
	records, err := e.loadSource(query.Source)
	if err != nil {
		return nil, fmt.Errorf("failed to load source %s: %w", query.Source, err)
	}

	// Apply WHERE filter
	if query.Where != nil {
		records = e.applyFilter(records, query.Where)
	}

	// Apply SELECT columns
	if len(query.Columns) > 0 && query.Columns[0] != "*" {
		records = e.selectColumns(records, query.Columns)
	}

	// Apply ORDER BY
	if query.OrderBy != "" {
		records = e.applyOrderBy(records, query.OrderBy, query.OrderDir)
	}

	// Apply LIMIT
	if query.Limit > 0 && len(records) > query.Limit {
		records = records[:query.Limit]
	}

	// Apply OFFSET
	if query.Offset > 0 && len(records) > query.Offset {
		records = records[query.Offset:]
	}

	return records, nil
}

// loadSource loads data from the specified source
func (e *Executor) loadSource(source string) ([]map[string]interface{}, error) {
	var records []map[string]interface{}

	// Map source names to file patterns
	sourceFiles := map[string]string{
		"process.list":            "process.list*.json",
		"process.tree":            "process.tree*.json",
		"network.connections":     "network.connections*.json",
		"network.dns_cache":       "network.dns_cache*.json",
		"filesystem.recent_files": "filesystem.recent_files*.json",
		"filesystem.bash_history": "filesystem.bash_history*.json",
		"registry.run_keys":       "registry.run_keys*.json",
		"log.auth":                "log.auth*.json",
		"users.logged_in":         "users.logged_in*.json",
	}

	pattern, ok := sourceFiles[source]
	if !ok {
		// Try as direct file pattern
		pattern = source + "*.json"
	}

	// Find matching files
	matches, err := filepath.Glob(filepath.Join(e.dataDir, pattern))
	if err != nil {
		return nil, err
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no data files found for source: %s", source)
	}

	// Load records from all matching files
	for _, file := range matches {
		fileRecords, err := e.loadJSONFile(file)
		if err != nil {
			continue
		}
		records = append(records, fileRecords...)
	}

	return records, nil
}

// loadJSONFile loads records from a JSON file
func (e *Executor) loadJSONFile(path string) ([]map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var result struct {
		Records []map[string]interface{} `json:"records"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		// Try as array of records
		var records []map[string]interface{}
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, err
		}
		return records, nil
	}

	return result.Records, nil
}

// applyFilter filters records based on WHERE conditions
func (e *Executor) applyFilter(records []map[string]interface{}, expr Expression) []map[string]interface{} {
	var result []map[string]interface{}

	for _, record := range records {
		if e.evaluateExpression(record, expr) {
			result = append(result, record)
		}
	}

	return result
}

// evaluateExpression evaluates an expression against a record
func (e *Executor) evaluateExpression(record map[string]interface{}, expr Expression) bool {
	switch ex := expr.(type) {
	case *BinaryExpr:
		left := e.evaluateExpression(record, ex.Left)
		right := e.evaluateExpression(record, ex.Right)
		if ex.Operator == "AND" {
			return left && right
		} else if ex.Operator == "OR" {
			return left || right
		}
	case *ComparisonExpr:
		return e.evaluateComparison(record, ex)
	case *InExpr:
		return e.evaluateIn(record, ex)
	case *LikeExpr:
		return e.evaluateLike(record, ex)
	case *BetweenExpr:
		return e.evaluateBetween(record, ex)
	case *IsNullExpr:
		return e.evaluateIsNull(record, ex)
	}
	return false
}

// evaluateComparison evaluates a comparison expression
func (e *Executor) evaluateComparison(record map[string]interface{}, c *ComparisonExpr) bool {
	// Handle nested data structure (collector.Result wraps data in "data" field)
	value, exists := record[c.Left]
	if !exists {
		// Try nested "data" field
		if data, ok := record["data"].(map[string]interface{}); ok {
			value, exists = data[c.Left]
		}
	}
	if !exists {
		return false
	}

	// Convert values for comparison
	recordValue := fmt.Sprintf("%v", value)
	compareValue := fmt.Sprintf("%v", c.Right)

	switch c.Operator {
	case "=", "==":
		return recordValue == compareValue
	case "!=", "<>":
		return recordValue != compareValue
	case "<":
		return e.compareNumbers(recordValue, compareValue) < 0
	case "<=":
		return e.compareNumbers(recordValue, compareValue) <= 0
	case ">":
		return e.compareNumbers(recordValue, compareValue) > 0
	case ">=":
		return e.compareNumbers(recordValue, compareValue) >= 0
	default:
		return false
	}
}

// evaluateIn evaluates an IN expression
func (e *Executor) evaluateIn(record map[string]interface{}, c *InExpr) bool {
	value, exists := record[c.Column]
	if !exists {
		// Try nested "data" field
		if data, ok := record["data"].(map[string]interface{}); ok {
			value, exists = data[c.Column]
		}
	}
	if !exists {
		return false
	}

	valueStr := fmt.Sprintf("%v", value)
	for _, v := range c.Values {
		if valueStr == fmt.Sprintf("%v", v) {
			return !c.Not // NOT IN inverts the result
		}
	}

	return c.Not // NOT IN returns true if not found
}

// evaluateLike evaluates a LIKE expression
func (e *Executor) evaluateLike(record map[string]interface{}, c *LikeExpr) bool {
	value, exists := record[c.Column]
	if !exists {
		// Try nested "data" field
		if data, ok := record["data"].(map[string]interface{}); ok {
			value, exists = data[c.Column]
		}
	}
	if !exists {
		return false
	}

	valueStr := strings.ToLower(fmt.Sprintf("%v", value))
	pattern := strings.ToLower(c.Pattern)

	// Convert SQL LIKE pattern to regex
	regexPattern := "^" + strings.ReplaceAll(pattern, "%", ".*") + "$"
	regexPattern = strings.ReplaceAll(regexPattern, "_", ".")

	matched, err := regexp.MatchString(regexPattern, valueStr)
	if err != nil {
		return false
	}

	if c.Not {
		return !matched
	}
	return matched
}

// evaluateBetween evaluates a BETWEEN expression
func (e *Executor) evaluateBetween(record map[string]interface{}, c *BetweenExpr) bool {
	value, exists := record[c.Column]
	if !exists {
		return false
	}

	valueStr := fmt.Sprintf("%v", value)
	lowStr := fmt.Sprintf("%v", c.Low)
	highStr := fmt.Sprintf("%v", c.High)

	cmpLow := e.compareNumbers(valueStr, lowStr)
	cmpHigh := e.compareNumbers(valueStr, highStr)

	return cmpLow >= 0 && cmpHigh <= 0
}

// evaluateIsNull evaluates an IS NULL expression
func (e *Executor) evaluateIsNull(record map[string]interface{}, c *IsNullExpr) bool {
	value, exists := record[c.Column]
	if c.Not {
		return exists && value != nil
	}
	return !exists || value == nil
}

// compareNumbers compares two numeric strings
func (e *Executor) compareNumbers(a, b string) int {
	aNum, aErr := strconv.ParseFloat(a, 64)
	bNum, bErr := strconv.ParseFloat(b, 64)

	if aErr != nil || bErr != nil {
		// Fall back to string comparison
		return strings.Compare(a, b)
	}

	if aNum < bNum {
		return -1
	} else if aNum > bNum {
		return 1
	}
	return 0
}

// selectColumns selects only the specified columns from records
func (e *Executor) selectColumns(records []map[string]interface{}, columns []string) []map[string]interface{} {
	var result []map[string]interface{}

	for _, record := range records {
		newRecord := make(map[string]interface{})
		for _, col := range columns {
			if val, exists := record[col]; exists {
				newRecord[col] = val
			}
		}
		result = append(result, newRecord)
	}

	return result
}

// applyOrderBy sorts records by the specified column
func (e *Executor) applyOrderBy(records []map[string]interface{}, orderBy, orderDir string) []map[string]interface{} {
	if orderBy == "" {
		return records
	}

	// Simple bubble sort (can be optimized)
	result := make([]map[string]interface{}, len(records))
	copy(result, records)

	descending := strings.ToUpper(orderDir) == "DESC"

	for i := 0; i < len(result)-1; i++ {
		for j := 0; j < len(result)-i-1; j++ {
			aVal := fmt.Sprintf("%v", result[j][orderBy])
			bVal := fmt.Sprintf("%v", result[j+1][orderBy])

			cmp := e.compareNumbers(aVal, bVal)
			shouldSwap := false
			if descending {
				shouldSwap = cmp < 0
			} else {
				shouldSwap = cmp > 0
			}

			if shouldSwap {
				result[j], result[j+1] = result[j+1], result[j]
			}
		}
	}

	return result
}

// ExecuteString parses and executes an IFQL query string
func (e *Executor) ExecuteString(queryStr string) ([]map[string]interface{}, error) {
	parser := NewParser()
	query, err := parser.Parse(queryStr)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	return e.Execute(query)
}

// ExecuteAndFormat executes a query and returns formatted output
func (e *Executor) ExecuteAndFormat(queryStr, format string) (string, error) {
	results, err := e.ExecuteString(queryStr)
	if err != nil {
		return "", err
	}

	switch strings.ToLower(format) {
	case "json":
		return e.formatJSON(results)
	case "csv":
		return e.formatCSV(results)
	case "table":
		return e.formatTable(results)
	default:
		return e.formatJSON(results)
	}
}

// formatJSON formats results as JSON
func (e *Executor) formatJSON(results []map[string]interface{}) (string, error) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// formatCSV formats results as CSV
func (e *Executor) formatCSV(results []map[string]interface{}) (string, error) {
	if len(results) == 0 {
		return "", nil
	}

	var lines []string

	// Get headers from first record
	var headers []string
	for k := range results[0] {
		headers = append(headers, k)
	}
	lines = append(lines, strings.Join(headers, ","))

	// Add data rows
	for _, record := range results {
		var values []string
		for _, h := range headers {
			val := fmt.Sprintf("%v", record[h])
			// Quote values containing commas
			if strings.Contains(val, ",") || strings.Contains(val, "\"") {
				val = "\"" + strings.ReplaceAll(val, "\"", "\"\"") + "\""
			}
			values = append(values, val)
		}
		lines = append(lines, strings.Join(values, ","))
	}

	return strings.Join(lines, "\n"), nil
}

// formatTable formats results as a text table
func (e *Executor) formatTable(results []map[string]interface{}) (string, error) {
	if len(results) == 0 {
		return "No results found.", nil
	}

	// Get headers
	var headers []string
	for k := range results[0] {
		headers = append(headers, k)
	}

	// Calculate column widths
	widths := make(map[string]int)
	for _, h := range headers {
		widths[h] = len(h)
		for _, record := range results {
			val := fmt.Sprintf("%v", record[h])
			if len(val) > widths[h] {
				widths[h] = len(val)
			}
		}
	}

	var lines []string

	// Header
	var headerParts []string
	for _, h := range headers {
		headerParts = append(headerParts, fmt.Sprintf("%-*s", widths[h], h))
	}
	lines = append(lines, strings.Join(headerParts, " | "))

	// Separator
	var sepParts []string
	for _, h := range headers {
		sepParts = append(sepParts, strings.Repeat("-", widths[h]))
	}
	lines = append(lines, strings.Join(sepParts, "-+-"))

	// Data rows
	for _, record := range results {
		var rowParts []string
		for _, h := range headers {
			val := fmt.Sprintf("%v", record[h])
			rowParts = append(rowParts, fmt.Sprintf("%-*s", widths[h], val))
		}
		lines = append(lines, strings.Join(rowParts, " | "))
	}

	return strings.Join(lines, "\n"), nil
}

// FormatResults formats results in the specified format
func (e *Executor) FormatResults(results []map[string]interface{}, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json":
		return e.formatJSON(results)
	case "csv":
		return e.formatCSV(results)
	case "table":
		return e.formatTable(results)
	default:
		return e.formatTable(results)
	}
}
