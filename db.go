package main

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// ---------------------------------------------------------------------------
// Database access. Go calls only the four SECURITY DEFINER functions; it never names a
// table. Every call is a single autocommit statement, so get_card's audit row commits with it.
// ---------------------------------------------------------------------------

// dbErr turns a database error into one that neither wraps nor quotes the original: a pgx error
// can carry argument values (encode errors format them; a unique-violation Detail names the
// token), and callers must never be able to reach a token or ciphertext through an error.
// Only the function name and SQLSTATE survive.
func dbErr(fn string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return errors.New(fn + ": sqlstate " + pgErr.Code)
	}
	return errors.New(fn + ": failed")
}

// dbPutCard stores an encrypted card via vault.put_card (which also writes the 'put' audit row).
func dbPutCard(ctx context.Context, db *sql.DB, token string, ciphertext []byte, last4 string, keyVersion int) error {
	if _, err := db.ExecContext(ctx, "SELECT vault.put_card($1, $2, $3, $4)", token, ciphertext, last4, keyVersion); err != nil {
		return dbErr("vault.put_card", err)
	}
	return nil
}

// dbGetCard fetches a card via vault.get_card, which enforces the velocity limits and writes the
// 'get' audit row: SQLSTATE P0001 → errVelocity; no row → errUnknownToken.
func dbGetCard(ctx context.Context, db *sql.DB, token, caller string) ([]byte, int, error) {
	var ciphertext []byte
	var keyVersion int
	err := db.QueryRowContext(ctx, "SELECT ciphertext, key_version FROM vault.get_card($1, $2)", token, caller).
		Scan(&ciphertext, &keyVersion)
	var pgErr *pgconn.PgError
	switch {
	case err == nil:
		return ciphertext, keyVersion, nil
	case errors.Is(err, sql.ErrNoRows):
		return nil, 0, errUnknownToken
	case errors.As(err, &pgErr) && pgErr.Code == "P0001":
		return nil, 0, errVelocity
	default:
		return nil, 0, dbErr("vault.get_card", err)
	}
}

// dbListDEKs returns every wrapped DEK by version via vault.list_deks.
func dbListDEKs(ctx context.Context, db *sql.DB) (map[int][]byte, error) {
	rows, err := db.QueryContext(ctx, "SELECT version, wrapped FROM vault.list_deks()")
	if err != nil {
		return nil, dbErr("vault.list_deks", err)
	}
	defer rows.Close()
	deks := map[int][]byte{}
	for rows.Next() {
		var version int
		var wrapped []byte
		if err := rows.Scan(&version, &wrapped); err != nil {
			return nil, dbErr("vault.list_deks", err)
		}
		deks[version] = wrapped
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr("vault.list_deks", err)
	}
	return deks, nil
}

// dbAddDEK stores a new KMS-wrapped DEK via vault.add_dek and returns its version.
func dbAddDEK(ctx context.Context, db *sql.DB, wrapped []byte) (int, error) {
	var version int
	if err := db.QueryRowContext(ctx, "SELECT vault.add_dek($1)", wrapped).Scan(&version); err != nil {
		return 0, dbErr("vault.add_dek", err)
	}
	return version, nil
}
