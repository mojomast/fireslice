-- +goose Up
ALTER TABLE vms ADD COLUMN expose_subdomain INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vms ADD COLUMN subdomain TEXT;
ALTER TABLE vms ADD COLUMN exposed_port INTEGER NOT NULL DEFAULT 8080;

CREATE UNIQUE INDEX IF NOT EXISTS idx_vms_subdomain
ON vms(subdomain)
WHERE subdomain IS NOT NULL;

-- +goose Down
-- keep columns in place for SQLite compatibility
DROP INDEX IF EXISTS idx_vms_subdomain;
