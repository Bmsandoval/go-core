package migrate

import "strings"

// SplitSQL splits a SQL script into individual statements on unquoted semicolons,
// returning the trimmed, non-empty statements in order. Trailing semicolons are
// dropped; a script with no trailing statement terminator still yields its final
// statement. Statements that are blank or consist solely of comments after
// trimming are omitted.
//
// Unlike a naive strings.Split on ";", the splitter understands the lexical
// constructs that can legitimately contain a semicolon, so it does not break
// statements apart inside them:
//
//   - single-quoted string literals:        'a;b'           and escaped quotes ” inside them
//   - double-quoted identifiers:            "weird;name"     and escaped quotes "" inside them
//   - PostgreSQL dollar-quoted blocks:      $$ ... ; ... $$  and tagged $tag$ ... $tag$
//   - line comments:                        -- ... to end of line
//   - block comments:                       /* ... ; ... */
//
// This is what makes it safe for PL/pgSQL function bodies, which embed multiple
// semicolon-terminated statements inside a single dollar-quoted CREATE FUNCTION.
//
// Examples:
//
//	SplitSQL("SELECT 1; SELECT 2;")
//	    => ["SELECT 1", "SELECT 2"]
//
//	SplitSQL("INSERT INTO t VALUES ('a;b');")
//	    => ["INSERT INTO t VALUES ('a;b')"]
//
//	SplitSQL("CREATE FUNCTION f() RETURNS int AS $$ BEGIN a; b; RETURN 1; END; $$ LANGUAGE plpgsql;")
//	    => ["CREATE FUNCTION f() RETURNS int AS $$ BEGIN a; b; RETURN 1; END; $$ LANGUAGE plpgsql"]
//
// Comments are preserved within the emitted statements (only fully
// comment-or-blank statements are dropped), so they remain available for drivers
// or readers that care about them.
func SplitSQL(script string) []string {
	var (
		out     []string
		current strings.Builder
	)

	flush := func() {
		stmt := strings.TrimSpace(current.String())
		current.Reset()
		if stmt != "" && !isCommentOnly(stmt) {
			out = append(out, stmt)
		}
	}

	for i := 0; i < len(script); {
		c := script[i]

		switch {
		// Line comment: consume through end of line (newline kept by default loop).
		case c == '-' && i+1 < len(script) && script[i+1] == '-':
			j := i
			for j < len(script) && script[j] != '\n' {
				j++
			}
			current.WriteString(script[i:j])
			i = j

		// Block comment: consume through the closing */ (or end of input).
		case c == '/' && i+1 < len(script) && script[i+1] == '*':
			j := i + 2
			for j < len(script) && !(script[j] == '*' && j+1 < len(script) && script[j+1] == '/') {
				j++
			}
			if j < len(script) {
				j += 2 // include closing "*/"
			} else {
				j = len(script)
			}
			current.WriteString(script[i:j])
			i = j

		// Single- or double-quoted literal/identifier. Doubled quotes ('' or "")
		// are the SQL escape for an embedded quote and do not terminate it.
		case c == '\'' || c == '"':
			j := scanQuoted(script, i, c)
			current.WriteString(script[i:j])
			i = j

		// Dollar-quoted block ($$ or $tag$). Only treated as such when a valid
		// opening tag is present; otherwise the '$' is an ordinary character.
		case c == '$':
			if tag, ok := dollarTagAt(script, i); ok {
				j := scanDollar(script, i, tag)
				current.WriteString(script[i:j])
				i = j
			} else {
				current.WriteByte(c)
				i++
			}

		// Statement terminator outside any quoted/comment context.
		case c == ';':
			flush()
			i++

		default:
			current.WriteByte(c)
			i++
		}
	}

	flush()
	return out
}

// scanQuoted returns the index just past a single- or double-quoted run that
// begins at start (script[start] == quote). Doubled quote characters are treated
// as an escaped quote and consumed. If the quote is unterminated, the end of the
// script is returned.
func scanQuoted(script string, start int, quote byte) int {
	i := start + 1
	for i < len(script) {
		if script[i] == quote {
			// Doubled quote => escaped quote, stay inside.
			if i+1 < len(script) && script[i+1] == quote {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return len(script)
}

// dollarTagAt reports whether a PostgreSQL dollar-quote opening tag begins at
// script[start] (which must be '$'). A tag is $$ or $name$ where name starts
// with a letter or underscore and contains only letters, digits, or underscores.
// On success it returns the full tag text (including both '$' delimiters).
func dollarTagAt(script string, start int) (string, bool) {
	if start >= len(script) || script[start] != '$' {
		return "", false
	}
	i := start + 1
	for i < len(script) {
		ch := script[i]
		if ch == '$' {
			return script[start : i+1], true
		}
		isFirst := i == start+1
		if !isTagChar(ch, isFirst) {
			return "", false
		}
		i++
	}
	return "", false
}

// scanDollar returns the index just past a dollar-quoted block that opens with
// tag at script[start]. The block runs until the matching closing tag; if the
// tag is never closed, the end of the script is returned.
func scanDollar(script string, start int, tag string) int {
	i := start + len(tag)
	for i < len(script) {
		if script[i] == '$' && strings.HasPrefix(script[i:], tag) {
			return i + len(tag)
		}
		i++
	}
	return len(script)
}

// isTagChar reports whether ch is valid within a dollar-quote tag name. The first
// character must be a letter or underscore; subsequent characters may also be
// digits.
func isTagChar(ch byte, first bool) bool {
	switch {
	case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch == '_':
		return true
	case ch >= '0' && ch <= '9':
		return !first
	default:
		return false
	}
}

// isCommentOnly reports whether a trimmed statement consists entirely of SQL
// comments and whitespace, in which case it carries no executable SQL and can be
// safely skipped.
func isCommentOnly(stmt string) bool {
	for i := 0; i < len(stmt); {
		c := stmt[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '-' && i+1 < len(stmt) && stmt[i+1] == '-':
			for i < len(stmt) && stmt[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(stmt) && stmt[i+1] == '*':
			i += 2
			for i < len(stmt) && !(stmt[i] == '*' && i+1 < len(stmt) && stmt[i+1] == '/') {
				i++
			}
			if i < len(stmt) {
				i += 2
			}
		default:
			return false
		}
	}
	return true
}
