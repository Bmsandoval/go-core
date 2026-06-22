// Package migrate is a small, driver-agnostic runner for embedded SQL migrations.
//
// It discovers *.sql files from any fs.FS (typically an embed.FS), applies the
// ones that have not yet run inside a per-migration transaction, and records each
// applied migration — along with a sha256 checksum of its contents — in a
// tracking table so that subsequent runs are incremental and tamper-evident.
//
// The package depends only on the standard library and operates on a *sql.DB
// supplied by the caller, so it imposes no particular database driver. It is
// therefore portable across PostgreSQL (pgx, lib/pq), SQLite (modernc.org/sqlite,
// mattn/go-sqlite3), and other database/sql-compatible drivers.
//
// Typical usage:
//
//	//go:embed migrations/*.sql
//	var migrationsFS embed.FS
//
//	func migrateDB(ctx context.Context, db *sql.DB) error {
//	    return migrate.Run(ctx, db, migrationsFS, migrate.WithDir("migrations"))
//	}
//
// Migrations are applied in lexical filename order, so a zero-padded numeric or
// timestamp prefix (e.g. 0001_init.sql, 0002_add_users.sql) is recommended.
package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"
)

// ErrChecksumMismatch is returned (wrapped, with the offending filename) when an
// already-applied migration's current checksum differs from the checksum that
// was recorded when it was first applied, and WithAllowChecksumMismatch has not
// been set. Callers can test for it with errors.Is.
var ErrChecksumMismatch = errors.New("migrate: applied migration checksum mismatch")

// Run applies all pending SQL migrations found in fsys against db.
//
// Behavior:
//
//   - A tracking table (default "schema_migrations", see WithTable) is created
//     if it does not already exist.
//   - *.sql files are discovered in the configured directory (default: the root
//     of fsys, see WithDir) and sorted lexically by name.
//   - For each file not yet recorded in the tracking table, its statements are
//     executed inside a single transaction; on success the transaction is
//     committed and a row (name, checksum, applied_at) is inserted. On any error
//     the transaction is rolled back and Run returns an error naming the file.
//   - For each file already recorded, the on-disk sha256 checksum is compared
//     against the stored checksum. A mismatch returns ErrChecksumMismatch unless
//     WithAllowChecksumMismatch was supplied.
//
// Each migration is committed in its own transaction, so if migration N fails,
// migrations 1..N-1 remain applied and recorded; re-running Run resumes at N.
//
// The supplied context is honored for every database operation; cancelling it
// aborts the run and rolls back any in-flight migration.
func Run(ctx context.Context, db *sql.DB, fsys fs.FS, opts ...Option) error {
	if db == nil {
		return errors.New("migrate: nil *sql.DB")
	}
	if fsys == nil {
		return errors.New("migrate: nil fs.FS")
	}

	cfg := newConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	if err := ensureTable(ctx, db, cfg.table); err != nil {
		return err
	}

	migrations, err := discover(fsys, cfg.dir)
	if err != nil {
		return err
	}

	applied, err := loadApplied(ctx, db, cfg.table)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if recorded, ok := applied[m.name]; ok {
			if recorded != m.checksum && !cfg.allowChecksumMismatch {
				return fmt.Errorf("%w: %s (recorded %s, found %s)",
					ErrChecksumMismatch, m.name, recorded, m.checksum)
			}
			continue
		}
		if err := apply(ctx, db, cfg, m); err != nil {
			return err
		}
	}

	return nil
}

// migration is a discovered, not-yet-classified migration file: its name, raw
// SQL contents, and hex-encoded sha256 checksum.
type migration struct {
	name     string
	sql      string
	checksum string
}

// discover reads dir within fsys, collecting every regular *.sql file, and
// returns them sorted lexically by name with their contents and checksums.
func discover(fsys fs.FS, dir string) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("migrate: read dir %q: %w", dir, err)
	}

	var migrations []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		path := e.Name()
		if dir != "." && dir != "" {
			path = dir + "/" + e.Name()
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("migrate: read %q: %w", path, err)
		}
		sum := sha256.Sum256(data)
		migrations = append(migrations, migration{
			name:     e.Name(),
			sql:      string(data),
			checksum: hex.EncodeToString(sum[:]),
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].name < migrations[j].name
	})
	return migrations, nil
}

// ensureTable creates the tracking table if it does not exist.
//
// The applied_at column is stored as TEXT (RFC 3339 timestamps written by this
// package) rather than a native timestamp type. This keeps the DDL portable
// across drivers — SQLite has no dedicated timestamp type and PostgreSQL accepts
// an RFC 3339 string into TEXT without trouble — at the cost of not being able to
// do native timestamp arithmetic on the column in SQL. The value is purely
// informational; ordering and idempotency rely on the name primary key, not the
// timestamp.
func ensureTable(ctx context.Context, db *sql.DB, table string) error {
	stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
	name       TEXT PRIMARY KEY,
	checksum   TEXT NOT NULL,
	applied_at TEXT NOT NULL
)`, table)
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("migrate: create tracking table %q: %w", table, err)
	}
	return nil
}

// loadApplied returns a map of migration name -> recorded checksum for every row
// currently present in the tracking table.
func loadApplied(ctx context.Context, db *sql.DB, table string) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT name, checksum FROM %s`, table))
	if err != nil {
		return nil, fmt.Errorf("migrate: query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]string)
	for rows.Next() {
		var name, checksum string
		if err := rows.Scan(&name, &checksum); err != nil {
			return nil, fmt.Errorf("migrate: scan applied migration: %w", err)
		}
		applied[name] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: iterate applied migrations: %w", err)
	}
	return applied, nil
}

// apply runs a single migration inside its own transaction and, on success,
// records it in the tracking table. Any failure rolls back the transaction and
// returns an error naming the migration file.
func apply(ctx context.Context, db *sql.DB, cfg config, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate: begin tx for %s: %w", m.name, err)
	}
	// rollback is a no-op after a successful Commit; the error is intentionally
	// ignored because the meaningful failure has already been returned.
	defer func() { _ = tx.Rollback() }()

	if cfg.splitStatements {
		for _, stmt := range SplitSQL(m.sql) {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migrate: exec %s: %w", m.name, err)
			}
		}
	} else {
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("migrate: exec %s: %w", m.name, err)
		}
	}

	insert := fmt.Sprintf(`INSERT INTO %s (name, checksum, applied_at) VALUES (%s, %s, %s)`,
		cfg.table, cfg.placeholder(1), cfg.placeholder(2), cfg.placeholder(3))
	if _, err := tx.ExecContext(ctx, insert, m.name, m.checksum, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("migrate: record %s: %w", m.name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate: commit %s: %w", m.name, err)
	}
	return nil
}
