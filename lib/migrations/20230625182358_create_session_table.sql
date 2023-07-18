-- "auth_sessions" definition
CREATE TABLE IF NOT EXISTS auth_session (
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    CONSTRAINT sessions_pkey PRIMARY KEY (id),
    CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth_user(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx on auth_session (user_id);
COMMENT ON TABLE auth_session is 'Auth: Stores session data associated to a user.';