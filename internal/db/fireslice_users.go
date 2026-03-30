package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	appauth "github.com/mojomast/fireslice/internal/auth"
	gossh "golang.org/x/crypto/ssh"
)

func (d *DB) CreateFiresliceUser(ctx context.Context, handle, email string) (*User, error) {
	handle = strings.TrimSpace(handle)
	email = strings.TrimSpace(email)

	var user User
	err := d.WriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO users (handle, email) VALUES (?, ?)`, handle, email,
		)
		if err != nil {
			return fmt.Errorf("insert user: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		return tx.QueryRowContext(ctx,
			`SELECT id, handle, email, trust_level, created_at, updated_at FROM users WHERE id = ?`, id,
		).Scan(&user.ID, &user.Handle, &user.Email, &user.TrustLevel, &user.CreatedAt, &user.UpdatedAt)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (d *DB) GetFiresliceUser(ctx context.Context, id int64) (*User, error) {
	return d.UserByID(ctx, id)
}

func (d *DB) ListFiresliceUsers(ctx context.Context) ([]*User, error) {
	users := make([]*User, 0)
	err := d.ReadTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT id, handle, email, trust_level, created_at, updated_at FROM users ORDER BY handle ASC, id ASC`,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var user User
			if err := rows.Scan(&user.ID, &user.Handle, &user.Email, &user.TrustLevel, &user.CreatedAt, &user.UpdatedAt); err != nil {
				return err
			}
			users = append(users, &user)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (d *DB) DeleteFiresliceUser(ctx context.Context, id int64) error {
	return d.WriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (d *DB) AddFiresliceSSHKey(ctx context.Context, userID int64, publicKey, label string) (*SSHKey, error) {
	parsed, _, err := appauth.ParsePublicKey(strings.TrimSpace(publicKey))
	if err != nil {
		return nil, err
	}
	fingerprint := appauth.FingerprintKey(parsed)
	normalized := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(parsed)))

	var key SSHKey
	err = d.WriteTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id = ?`, userID).Scan(new(int64)); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`INSERT INTO ssh_keys (user_id, public_key, fingerprint, comment) VALUES (?, ?, ?, ?)`,
			userID, normalized, fingerprint, strings.TrimSpace(label),
		)
		if err != nil {
			return fmt.Errorf("insert ssh key: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		return tx.QueryRowContext(ctx,
			`SELECT id, user_id, public_key, fingerprint, comment, created_at FROM ssh_keys WHERE id = ?`, id,
		).Scan(&key.ID, &key.UserID, &key.PublicKey, &key.Fingerprint, &key.Comment, &key.CreatedAt)
	})
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (d *DB) DeleteFiresliceSSHKey(ctx context.Context, userID, keyID int64) error {
	return d.WriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM ssh_keys WHERE id = ? AND user_id = ?`, keyID, userID)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (d *DB) ListFiresliceSSHKeys(ctx context.Context, userID int64) ([]*SSHKey, error) {
	keys := make([]*SSHKey, 0)
	err := d.ReadTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT id, user_id, public_key, fingerprint, comment, created_at FROM ssh_keys WHERE user_id = ? ORDER BY created_at ASC, id ASC`,
			userID,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var key SSHKey
			if err := rows.Scan(&key.ID, &key.UserID, &key.PublicKey, &key.Fingerprint, &key.Comment, &key.CreatedAt); err != nil {
				return err
			}
			keys = append(keys, &key)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}
