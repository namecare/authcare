-- "auth_refresh_tokens" definition
CREATE TABLE IF NOT EXISTS auth_refresh_token (
    id bigserial NOT NULL,
    "token" VARCHAR(255) NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    revoked bool NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT refresh_tokens_session_id_fkey FOREIGN KEY (session_id) REFERENCES auth_session(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS refresh_tokens_instance_id_user_id_idx ON auth_refresh_token USING btree (user_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_session_id_revoked_idx ON auth_refresh_token (session_id, revoked);
COMMENT ON TABLE auth_refresh_token is 'Auth: Store of tokens used to refresh JWT tokens once they expire.';