package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type FiresliceCreateVMInput struct {
	UserID          int64
	Name            string
	Image           string
	VCPU            int
	MemoryMB        int
	DiskGB          int
	ExposeSubdomain bool
	Subdomain       string
	ExposedPort     int
}

type VMExposure struct {
	ExposeSubdomain bool
	Subdomain       string
	ExposedPort     int
}

func (d *DB) CreateFiresliceVM(ctx context.Context, input FiresliceCreateVMInput) (*VM, error) {
	var vm VM
	err := d.WriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO vms (user_id, name, image, vcpu, memory_mb, disk_gb, expose_subdomain, subdomain, exposed_port)
			 VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?)`,
			input.UserID, input.Name, input.Image, input.VCPU, input.MemoryMB, input.DiskGB,
			boolToInt(input.ExposeSubdomain), input.Subdomain, defaultPort(input.ExposedPort),
		)
		if err != nil {
			return fmt.Errorf("insert vm: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		return scanVM(tx.QueryRowContext(ctx, firesliceVMSelect+` WHERE id = ?`, id), &vm)
	})
	if err != nil {
		return nil, err
	}
	return &vm, nil
}

func (d *DB) GetFiresliceVM(ctx context.Context, id int64) (*VM, error) {
	var vm VM
	err := d.ReadTx(ctx, func(tx *sql.Tx) error {
		return scanVM(tx.QueryRowContext(ctx, firesliceVMSelect+` WHERE id = ?`, id), &vm)
	})
	if err != nil {
		return nil, err
	}
	return &vm, nil
}

func (d *DB) ListFiresliceVMs(ctx context.Context) ([]*VM, error) {
	vms := make([]*VM, 0)
	err := d.ReadTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, firesliceVMSelect+` ORDER BY created_at DESC, id DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var vm VM
			if err := scanVM(rows, &vm); err != nil {
				return err
			}
			vms = append(vms, &vm)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return vms, nil
}

func (d *DB) UpdateFiresliceVMStatus(ctx context.Context, id int64, status string) error {
	return d.WriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE vms SET status = ?, updated_at = ? WHERE id = ?`,
			status, time.Now().UTC().Format(time.RFC3339), id,
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

func (d *DB) UpdateFiresliceVMExposure(ctx context.Context, id int64, expose bool, subdomain string, port int) error {
	return d.WriteTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE vms
			 SET expose_subdomain = ?,
			     subdomain = CASE
			         WHEN ? = 0 THEN NULL
			         WHEN ? = '' THEN subdomain
			         ELSE ?
			     END,
			     exposed_port = ?,
			     updated_at = ?
			 WHERE id = ?`,
			boolToInt(expose), boolToInt(expose), subdomain, subdomain, defaultPort(port), time.Now().UTC().Format(time.RFC3339), id,
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

func (d *DB) GetFiresliceVMExposure(ctx context.Context, id int64) (VMExposure, error) {
	var exposure VMExposure
	var subdomain sql.NullString
	err := d.ReadTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT expose_subdomain, subdomain, exposed_port FROM vms WHERE id = ?`, id,
		).Scan(&exposure.ExposeSubdomain, &subdomain, &exposure.ExposedPort)
	})
	if err != nil {
		return VMExposure{}, err
	}
	if subdomain.Valid {
		exposure.Subdomain = subdomain.String
	}
	return exposure, nil
}

func (d *DB) DeleteFiresliceVM(ctx context.Context, id int64) error {
	return d.DeleteVM(ctx, id)
}

const firesliceVMSelect = `SELECT id, user_id, name, status, image, vcpu, memory_mb, disk_gb,
	       tap_device, ip_address, mac_address, pid, expose_subdomain, subdomain, exposed_port,
	       created_at, updated_at
	FROM vms`

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func defaultPort(port int) int {
	if port == 0 {
		return 8080
	}
	return port
}
