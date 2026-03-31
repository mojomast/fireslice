-- +goose Up

ALTER TABLE users ADD COLUMN password_bcrypt TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'));

-- +goose Down
ALTER TABLE users DROP COLUMN role;
ALTER TABLE users DROP COLUMN password_bcrypt;
