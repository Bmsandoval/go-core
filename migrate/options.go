package migrate

import "fmt"

// config holds the resolved settings for a Run invocation. It is populated by
// applying the functional Options passed to Run on top of the defaults set in
// newConfig.
type config struct {
	// dir is the directory within the fs.FS to scan for *.sql migration files.
	// "." means the root of the provided filesystem.
	dir string

	// table is the name of the tracking table used to record applied
	// migrations. It is interpolated directly into SQL, so callers must only
	// supply a trusted, identifier-safe value (see WithTable).
	table string

	// splitStatements controls whether each migration file is split into
	// individual statements before being executed (see WithSplitStatements).
	splitStatements bool

	// allowChecksumMismatch, when true, suppresses the error normally returned
	// when an already-applied migration's on-disk checksum no longer matches
	// the recorded checksum (see WithAllowChecksumMismatch).
	allowChecksumMismatch bool

	// placeholderStyle selects the bind-parameter syntax used in the INSERT that
	// records an applied migration (see WithPlaceholderStyle).
	placeholderStyle PlaceholderStyle
}

// PlaceholderStyle identifies the bind-parameter syntax a driver expects. Only
// the single internal INSERT that records applied migrations is parameterized;
// the migration SQL itself is executed verbatim, so this never affects user DDL.
type PlaceholderStyle int

const (
	// PlaceholderQuestion uses "?" placeholders, expected by SQLite drivers
	// (modernc.org/sqlite, mattn/go-sqlite3) and the MySQL driver. This is the
	// default.
	PlaceholderQuestion PlaceholderStyle = iota

	// PlaceholderDollar uses "$1", "$2", ... placeholders, expected by the
	// PostgreSQL drivers pgx (stdlib) and lib/pq.
	PlaceholderDollar
)

// placeholder renders the bind placeholder for the n-th parameter (1-based)
// according to the configured PlaceholderStyle.
func (c config) placeholder(n int) string {
	if c.placeholderStyle == PlaceholderDollar {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// newConfig returns a config populated with the package defaults: migrations are
// read from the root of the filesystem, tracked in a table named
// "schema_migrations", split into individual statements before execution, and
// checksum mismatches are treated as errors.
func newConfig() config {
	return config{
		dir:                   ".",
		table:                 "schema_migrations",
		splitStatements:       true,
		allowChecksumMismatch: false,
		placeholderStyle:      PlaceholderQuestion,
	}
}

// Option configures the behavior of Run. Options follow the functional options
// pattern: pass any number of them to Run to override the defaults.
type Option func(*config)

// WithDir sets the subdirectory within the supplied fs.FS that is scanned for
// *.sql migration files. The default is the filesystem root ("."). The path is
// interpreted with io/fs semantics (forward slashes, no leading slash); an empty
// string is treated as the root.
//
// Example:
//
//	//go:embed migrations/*.sql
//	var assets embed.FS
//	err := migrate.Run(ctx, db, assets, migrate.WithDir("migrations"))
func WithDir(dir string) Option {
	return func(c *config) {
		if dir == "" {
			dir = "."
		}
		c.dir = dir
	}
}

// WithTable overrides the name of the migration tracking table (default
// "schema_migrations").
//
// The provided name is interpolated directly into the generated SQL and is NOT
// escaped or quoted, because portable identifier quoting differs across drivers.
// Only pass a trusted, hard-coded, identifier-safe value; never pass
// user-controlled input, or you risk SQL injection.
func WithTable(name string) Option {
	return func(c *config) {
		if name != "" {
			c.table = name
		}
	}
}

// WithSplitStatements controls how each migration file is executed.
//
// When enabled (the default), each file is parsed into individual SQL statements
// and executed one at a time within the migration's transaction. This is
// required for drivers that reject multiple statements in a single Exec call —
// notably the PostgreSQL extended-query protocol used by pgx and lib/pq's
// prepared-statement path. The statement splitter is dollar-quote, quote, and
// comment aware (see SplitSQL).
//
// When disabled, the entire file is passed to a single ExecContext call. This is
// simpler and avoids any splitter edge cases, but only works on drivers that
// accept multiple statements per Exec (e.g. modernc.org/sqlite, mattn/go-sqlite3,
// and lib/pq via the simple protocol). Choose this if your migrations contain
// SQL the splitter cannot reason about and your driver supports multi-statement
// execution.
func WithSplitStatements(split bool) Option {
	return func(c *config) {
		c.splitStatements = split
	}
}

// WithPlaceholderStyle selects the bind-parameter syntax used for the internal
// INSERT that records an applied migration. The default, PlaceholderQuestion
// ("?"), works for SQLite and MySQL drivers; use PlaceholderDollar ("$1", "$2",
// ...) for the PostgreSQL drivers pgx and lib/pq.
//
// This only affects the tracking INSERT — migration SQL is executed verbatim and
// is unaffected by this setting.
func WithPlaceholderStyle(style PlaceholderStyle) Option {
	return func(c *config) {
		c.placeholderStyle = style
	}
}

// WithAllowChecksumMismatch disables the integrity check that normally fails Run
// when an already-applied migration file's content (and therefore its sha256
// checksum) differs from what was recorded when it was first applied.
//
// By default a mismatch is an error: it usually means an applied migration was
// edited after the fact, which can silently desynchronize environments. Enable
// this only when you intentionally rewrite historical migrations (for example,
// reformatting) and accept that the change will not be re-applied.
func WithAllowChecksumMismatch() Option {
	return func(c *config) {
		c.allowChecksumMismatch = true
	}
}
