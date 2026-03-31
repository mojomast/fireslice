package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	appauth "github.com/mojomast/fireslice/internal/auth"
	"golang.org/x/crypto/bcrypt"
	gossh "golang.org/x/crypto/ssh"
)

func (d *DB) CreateFiresliceUser(ctx context.Context, handle, email, passwordBcrypt, role string) (*User, error) {
	handle = strings.TrimSpace(handle)
	email = strings.TrimSpace(email)
	passwordBcrypt = strings.TrimSpace(passwordBcrypt)
	role = strings.TrimSpace(role)
	if role == "" {
		role = "user"
	}
	if passwordBcrypt != "" && !strings.HasPrefix(passwordBcrypt, "$2") {
		hash, err := bcrypt.GenerateFromPassword([]byte(passwordBcrypt), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("generate bcrypt hash: %w", err)
		}
		passwordBcrypt = string(hash)
	}

	var user User
	err := d.WriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO users (handle, email, password_bcrypt, role) VALUES (?, ?, ?, ?)`, handle, email, passwordBcrypt, role,
		)
		if err != nil {
			return fmt.Errorf("insert user: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		return tx.QueryRowContext(ctx,
			`SELECT id, handle, email, password_bcrypt, role, trust_level, vm_limit, cpu_limit, ram_limit_mb, disk_limit_mb, created_at, updated_at FROM users WHERE id = ?`, id,
		).Scan(&user.ID, &user.Handle, &user.Email, &user.PasswordBcrypt, &user.Role, &user.TrustLevel, &user.VMLimit, &user.CPULimit, &user.RAMLimitMB, &user.DiskLimitMB, &user.CreatedAt, &user.UpdatedAt)
	})
	if err != nil {
		return nil, err
	}
	if user.Role == "" {
		user.Role = "user"
	}
	return &user, nil
}

func (d *DB) GetFiresliceUser(ctx context.Context, id int64) (*User, error) {
	var user User
	err := d.ReadTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT id, handle, email, password_bcrypt, role, trust_level, vm_limit, cpu_limit, ram_limit_mb, disk_limit_mb, created_at, updated_at FROM users WHERE id = ?`, id,
		).Scan(&user.ID, &user.Handle, &user.Email, &user.PasswordBcrypt, &user.Role, &user.TrustLevel, &user.VMLimit, &user.CPULimit, &user.RAMLimitMB, &user.DiskLimitMB, &user.CreatedAt, &user.UpdatedAt)
	})
	if err != nil {
		return nil, err
	}
	if user.Role == "" {
		user.Role = "user"
	}
	return &user, nil
}

func (d *DB) GetFiresliceUserByHandle(ctx context.Context, handle string) (*User, error) {
	var user User
	err := d.ReadTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT id, handle, email, password_bcrypt, role, trust_level, vm_limit, cpu_limit, ram_limit_mb, disk_limit_mb, created_at, updated_at FROM users WHERE handle = ?`, strings.TrimSpace(handle),
		).Scan(&user.ID, &user.Handle, &user.Email, &user.PasswordBcrypt, &user.Role, &user.TrustLevel, &user.VMLimit, &user.CPULimit, &user.RAMLimitMB, &user.DiskLimitMB, &user.CreatedAt, &user.UpdatedAt)
	})
	if err != nil {
		return nil, err
	}
	if user.Role == "" {
		user.Role = "user"
	}
	return &user, nil
}

func (d *DB) ListFiresliceUsers(ctx context.Context) ([]*User, error) {
	users := make([]*User, 0)
	err := d.ReadTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT id, handle, email, password_bcrypt, role, trust_level, vm_limit, cpu_limit, ram_limit_mb, disk_limit_mb, created_at, updated_at FROM users ORDER BY handle ASC, id ASC`,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var user User
			if err := rows.Scan(&user.ID, &user.Handle, &user.Email, &user.PasswordBcrypt, &user.Role, &user.TrustLevel, &user.VMLimit, &user.CPULimit, &user.RAMLimitMB, &user.DiskLimitMB, &user.CreatedAt, &user.UpdatedAt); err != nil {
				return err
			}
			if user.Role == "" {
				user.Role = "user"
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

func (d *DB) UpdateFiresliceUserPassword(ctx context.Context, userID int64, password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("password is required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generate bcrypt hash: %w", err)
	}
	return d.WriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE users SET password_bcrypt = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?`,
			string(hash), userID,
		)
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

func (d *DB) UpdateFiresliceUserQuotas(ctx context.Context, userID int64, trustLevel string, vmLimit, cpuLimit, ramLimitMB, diskLimitMB int) error {
	trustLevel = strings.TrimSpace(trustLevel)
	if trustLevel == "" {
		return fmt.Errorf("trust level is required")
	}
	if !IsValidTrustLevel(trustLevel) {
		return fmt.Errorf("invalid trust level %q", trustLevel)
	}
	return d.WriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE users SET trust_level = ?, vm_limit = ?, cpu_limit = ?, ram_limit_mb = ?, disk_limit_mb = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?`,
			trustLevel, vmLimit, cpuLimit, ramLimitMB, diskLimitMB, userID,
		)
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
