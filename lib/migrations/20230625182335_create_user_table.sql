-- "auth_user" definition
CREATE TABLE IF NOT EXISTS auth_user (
    id uuid NOT NULL UNIQUE,
    email VARCHAR(255) NULL UNIQUE,
    encrypted_password VARCHAR(255) NULL,
    is_super_user bool NOT NULL DEFAULT false,
    banned_until timestamptz NULL,
    confirmed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    CONSTRAINT users_pkey PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS users_instance_id_email_idx ON auth_user USING btree (email);
COMMENT ON TABLE auth_user is 'Auth: Stores User login data within a secure schema.';