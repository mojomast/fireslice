package db

import (
	"context"
	"fmt"
)

func (d *DB) LogFiresliceAudit(ctx context.Context, action, targetType string, targetID int64, detail string) error {
	target := fmt.Sprintf("%d", targetID)
	var detailPtr *string
	if detail != "" {
		detailCopy := detail
		detailPtr = &detailCopy
	}
	_, err := d.CreateAuditLog(ctx, nil, action, targetType, &target, detailPtr)
	return err
}
