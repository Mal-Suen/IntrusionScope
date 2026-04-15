// Package ifql provides the IntrusionScope Forensic Query Language
package ifql

import (
	"fmt"
	"strings"
)

// Query represents a parsed IFQL query
type Query struct {
	Source   string       // FROM clause
	Columns  []string     // SELECT clause
	Where    Expression   // WHERE clause
	Limit    int          // LIMIT clause
	Offset   int          // OFFSET clause
	OrderBy  string       // ORDER BY clause
	OrderDir string       // ASC or DESC
}

// Expression represents a WHERE clause expression
type Expression interface {
	String() string
}

// BinaryExpr represents a binary expression (AND, OR)
type BinaryExpr struct {
	Left     Expression
	Operator string
	Right    Expression
}

func (e *BinaryExpr) String() string {
	return fmt.Sprintf("(%s %s %s)", e.Left.String(), e.Operator, e.Right.String())
}

// ComparisonExpr represents a comparison expression
type ComparisonExpr struct {
	Left     string
	Operator string
	Right    interface{}
}

func (e *ComparisonExpr) String() string {
	return fmt.Sprintf("%s %s %v", e.Left, e.Operator, e.Right)
}

// InExpr represents an IN expression
type InExpr struct {
	Column string
	Values []interface{}
	Not    bool
}

func (e *InExpr) String() string {
	not := ""
	if e.Not {
		not = "NOT "
	}
	return fmt.Sprintf("%s %sIN %v", e.Column, not, e.Values)
}

// LikeExpr represents a LIKE expression
type LikeExpr struct {
	Column string
	Pattern string
	Not    bool
}

func (e *LikeExpr) String() string {
	not := ""
	if e.Not {
		not = "NOT "
	}
	return fmt.Sprintf("%s %sLIKE '%s'", e.Column, not, e.Pattern)
}

// BetweenExpr represents a BETWEEN expression
type BetweenExpr struct {
	Column string
	Low    interface{}
	High   interface{}
}

func (e *BetweenExpr) String() string {
	return fmt.Sprintf("%s BETWEEN %v AND %v", e.Column, e.Low, e.High)
}

// IsNullExpr represents an IS NULL expression
type IsNullExpr struct {
	Column string
	Not    bool
}

func (e *IsNullExpr) String() string {
	not := ""
	if e.Not {
		not = "NOT "
	}
	return fmt.Sprintf("%s IS %sNULL", e.Column, not)
}

// Parser parses IFQL queries
type Parser struct {
	tokens []token
	pos    int
}

type token struct {
	typ   tokenType
	value string
}

type tokenType int

const (
	tokenEOF tokenType = iota
	tokenIdent
	tokenString
	tokenNumber
	tokenOperator
	tokenKeyword
	tokenPunctuation
)

// NewParser creates a new IFQL parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses an IFQL query string
func (p *Parser) Parse(queryStr string) (*Query, error) {
	// Tokenize
	p.tokens = p.tokenize(queryStr)
	p.pos = 0

	query := &Query{
		Limit: -1, // No limit by default
	}

	// Parse SELECT
	if !p.expectKeyword("SELECT") {
		return nil, fmt.Errorf("expected SELECT")
	}

	// Parse column list
	columns, err := p.parseColumnList()
	if err != nil {
		return nil, err
	}
	query.Columns = columns

	// Parse FROM
	if !p.expectKeyword("FROM") {
		return nil, fmt.Errorf("expected FROM")
	}

	// Parse source
	source, err := p.parseIdent()
	if err != nil {
		return nil, err
	}
	query.Source = source

	// Parse optional WHERE
	if p.peekKeyword("WHERE") {
		p.advance()
		where, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		query.Where = where
	}

	// Parse optional ORDER BY
	if p.peekKeyword("ORDER") {
		p.advance()
		if !p.expectKeyword("BY") {
			return nil, fmt.Errorf("expected BY after ORDER")
		}
		orderBy, err := p.parseIdent()
		if err != nil {
			return nil, err
		}
		query.OrderBy = orderBy

		// Optional ASC/DESC
		if p.peekKeyword("ASC") {
			p.advance()
			query.OrderDir = "ASC"
		} else if p.peekKeyword("DESC") {
			p.advance()
			query.OrderDir = "DESC"
		}
	}

	// Parse optional LIMIT
	if p.peekKeyword("LIMIT") {
		p.advance()
		limit, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		query.Limit = limit
	}

	// Parse optional OFFSET
	if p.peekKeyword("OFFSET") {
		p.advance()
		offset, err := p.parseNumber()
		if err != nil {
			return nil, err
		}
		query.Offset = offset
	}

	return query, nil
}

func (p *Parser) tokenize(input string) []token {
	var tokens []token
	i := 0

	for i < len(input) {
		// Skip whitespace
		for i < len(input) && isWhitespace(input[i]) {
			i++
		}
		if i >= len(input) {
			break
		}

		ch := input[i]

		// String literal
		if ch == '\'' || ch == '"' {
			start := i
			quote := ch
			i++
			for i < len(input) && input[i] != quote {
				if input[i] == '\\' {
					i++
				}
				i++
			}
			i++
			tokens = append(tokens, token{tokenString, input[start:i]})
			continue
		}

		// Number
		if isDigit(ch) {
			start := i
			for i < len(input) && (isDigit(input[i]) || input[i] == '.') {
				i++
			}
			tokens = append(tokens, token{tokenNumber, input[start:i]})
			continue
		}

		// Identifier or keyword
		if isAlpha(ch) {
			start := i
			for i < len(input) && (isAlphaNum(input[i]) || input[i] == '_' || input[i] == '.') {
				i++
			}
			value := input[start:i]
			if isKeyword(value) {
				tokens = append(tokens, token{tokenKeyword, strings.ToUpper(value)})
			} else {
				tokens = append(tokens, token{tokenIdent, value})
			}
			continue
		}

		// Operators
		if ch == '=' || ch == '<' || ch == '>' || ch == '!' {
			start := i
			i++
			if i < len(input) && input[i] == '=' {
				i++
			}
			tokens = append(tokens, token{tokenOperator, input[start:i]})
			continue
		}

		// Punctuation
		if ch == ',' || ch == '(' || ch == ')' || ch == '*' {
			tokens = append(tokens, token{tokenPunctuation, string(ch)})
			i++
			continue
		}

		// Unknown character, skip
		i++
	}

	tokens = append(tokens, token{tokenEOF, ""})
	return tokens
}

func (p *Parser) current() token {
	if p.pos >= len(p.tokens) {
		return token{tokenEOF, ""}
	}
	return p.tokens[p.pos]
}

func (p *Parser) advance() token {
	t := p.current()
	p.pos++
	return t
}

func (p *Parser) expectKeyword(kw string) bool {
	t := p.current()
	if t.typ == tokenKeyword && t.value == kw {
		p.advance()
		return true
	}
	return false
}

func (p *Parser) peekKeyword(kw string) bool {
	t := p.current()
	return t.typ == tokenKeyword && t.value == kw
}

func (p *Parser) parseColumnList() ([]string, error) {
	var columns []string

	// Handle SELECT *
	if p.current().typ == tokenPunctuation && p.current().value == "*" {
		p.advance()
		return []string{"*"}, nil
	}

	for {
		col, err := p.parseIdent()
		if err != nil {
			return nil, err
		}
		columns = append(columns, col)

		// Check for comma
		if p.current().typ == tokenPunctuation && p.current().value == "," {
			p.advance()
			continue
		}
		break
	}

	return columns, nil
}

func (p *Parser) parseIdent() (string, error) {
	t := p.current()
	if t.typ != tokenIdent {
		return "", fmt.Errorf("expected identifier, got %v", t)
	}
	p.advance()
	return t.value, nil
}

func (p *Parser) parseNumber() (int, error) {
	t := p.current()
	if t.typ != tokenNumber {
		return 0, fmt.Errorf("expected number, got %v", t)
	}
	p.advance()
	var num int
	fmt.Sscanf(t.value, "%d", &num)
	return num, nil
}

func (p *Parser) parseExpression() (Expression, error) {
	return p.parseOrExpression()
}

func (p *Parser) parseOrExpression() (Expression, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	for p.peekKeyword("OR") {
		p.advance()
		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Operator: "OR", Right: right}
	}

	return left, nil
}

func (p *Parser) parseAndExpression() (Expression, error) {
	left, err := p.parsePrimaryExpression()
	if err != nil {
		return nil, err
	}

	for p.peekKeyword("AND") {
		p.advance()
		right, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Operator: "AND", Right: right}
	}

	return left, nil
}

func (p *Parser) parsePrimaryExpression() (Expression, error) {
	// Handle parenthesized expressions
	if p.current().typ == tokenPunctuation && p.current().value == "(" {
		p.advance()
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if p.current().typ != tokenPunctuation || p.current().value != ")" {
			return nil, fmt.Errorf("expected )")
		}
		p.advance()
		return expr, nil
	}

	// Parse column name
	column, err := p.parseIdent()
	if err != nil {
		return nil, err
	}

	// Check for NOT
	not := false
	if p.peekKeyword("NOT") {
		p.advance()
		not = true
	}

	// Check for IN
	if p.peekKeyword("IN") {
		p.advance()
		return p.parseInExpr(column, not)
	}

	// Check for LIKE
	if p.peekKeyword("LIKE") {
		p.advance()
		return p.parseLikeExpr(column, not)
	}

	// Check for BETWEEN
	if p.peekKeyword("BETWEEN") {
		p.advance()
		return p.parseBetweenExpr(column)
	}

	// Check for IS NULL
	if p.peekKeyword("IS") {
		p.advance()
		if p.peekKeyword("NULL") {
			p.advance()
			return &IsNullExpr{Column: column, Not: not}, nil
		}
		return nil, fmt.Errorf("expected NULL after IS")
	}

	// Parse comparison operator
	op := p.current()
	if op.typ != tokenOperator {
		return nil, fmt.Errorf("expected operator, got %v", op)
	}
	p.advance()

	// Parse right side
	right, err := p.parseValue()
	if err != nil {
		return nil, err
	}

	return &ComparisonExpr{Left: column, Operator: op.value, Right: right}, nil
}

func (p *Parser) parseInExpr(column string, not bool) (Expression, error) {
	if p.current().typ != tokenPunctuation || p.current().value != "(" {
		return nil, fmt.Errorf("expected ( after IN")
	}
	p.advance()

	var values []interface{}
	for {
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		values = append(values, val)

		if p.current().typ == tokenPunctuation && p.current().value == "," {
			p.advance()
			continue
		}
		break
	}

	if p.current().typ != tokenPunctuation || p.current().value != ")" {
		return nil, fmt.Errorf("expected ) after IN values")
	}
	p.advance()

	return &InExpr{Column: column, Values: values, Not: not}, nil
}

func (p *Parser) parseLikeExpr(column string, not bool) (Expression, error) {
	t := p.current()
	if t.typ != tokenString {
		return nil, fmt.Errorf("expected string pattern after LIKE")
	}
	p.advance()

	// Remove quotes
	pattern := strings.Trim(t.value, "'\"")

	return &LikeExpr{Column: column, Pattern: pattern, Not: not}, nil
}

func (p *Parser) parseBetweenExpr(column string) (Expression, error) {
	low, err := p.parseValue()
	if err != nil {
		return nil, err
	}

	if !p.expectKeyword("AND") {
		return nil, fmt.Errorf("expected AND in BETWEEN expression")
	}

	high, err := p.parseValue()
	if err != nil {
		return nil, err
	}

	return &BetweenExpr{Column: column, Low: low, High: high}, nil
}

func (p *Parser) parseValue() (interface{}, error) {
	t := p.current()

	switch t.typ {
	case tokenString:
		p.advance()
		// Remove quotes
		return strings.Trim(t.value, "'\""), nil
	case tokenNumber:
		p.advance()
		var num float64
		fmt.Sscanf(t.value, "%f", &num)
		if num == float64(int(num)) {
			return int(num), nil
		}
		return num, nil
	case tokenIdent:
		p.advance()
		return t.value, nil
	default:
		return nil, fmt.Errorf("expected value, got %v", t)
	}
}

// Helper functions
func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isAlpha(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

func isAlphaNum(ch byte) bool {
	return isAlpha(ch) || isDigit(ch)
}

func isKeyword(s string) bool {
	kw := strings.ToUpper(s)
	keywords := []string{
		"SELECT", "FROM", "WHERE", "AND", "OR", "NOT",
		"IN", "LIKE", "BETWEEN", "IS", "NULL",
		"ORDER", "BY", "ASC", "DESC",
		"LIMIT", "OFFSET",
	}
	for _, k := range keywords {
		if kw == k {
			return true
		}
	}
	return false
}
