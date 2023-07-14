-- Add identity table

CREATE TABLE IF NOT EXISTS identity (
    id text NOT NULL,
    user_id uuid NOT NULL,
    email text generated always as (lower(identity_data->>'email')) stored,
    identity_data JSONB NOT NULL,
    provider text NOT NULL,
    last_sign_in_at timestamptz NULL,
    created_at timestamptz NULL,
    updated_at timestamptz NULL,
    CONSTRAINT identities_pkey PRIMARY KEY (provider, id),
    CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth_user(id) ON DELETE CASCADE
);
COMMENT ON TABLE identity is 'Auth: Stores identities associated to a user.';
CREATE INDEX IF NOT EXISTS identities_user_id_idx ON identity using btree (user_id);