-- 1. The core User table (Profile & System-wide settings)
CREATE TABLE users (
    id BIGINT PRIMARY KEY,           -- Snowflake ID
    email VARCHAR(255) UNIQUE NOT NULL, -- The "Primary" email for notifications
    display_name VARCHAR(100),
    password_hash TEXT, -- NULL if the user ONLY uses OAuth
    token_version INT DEFAULT 1, -- For the global logout/revocation flow
    created_at BIGINT NOT NULL,      -- Unix Timestamp (Nanoseconds or Milliseconds)
    updated_at BIGINT NOT NULL
);

-- 2. The Identities table (Auth Methods)
CREATE TABLE identities (
    id BIGINT PRIMARY KEY,           -- Snowflake ID
    user_id BIGINT NOT NULL,
    provider VARCHAR(50) NOT NULL, -- 'google', 'github', 'apple', 'local'
    provider_user_id VARCHAR(255) NOT NULL, -- The 'sub' or 'id' from the OAuth provider
    provider_email VARCHAR(255), -- The email returned by the provider at time of link
    last_login_at BIGINT,
    
    -- Ensure a user can't link the same Google account twice
    UNIQUE(provider, provider_user_id)
);

-- 3. The Refresh Tokens table (Stateful Session Management)
CREATE TABLE refresh_tokens (
    id BIGINT PRIMARY KEY,           -- Snowflake ID
    user_id BIGINT NOT NULL,
    token_hash TEXT NOT NULL, -- Store a hash of the refresh token UUID
    expires_at BIGINT NOT NULL,      -- Unix Timestamp
    created_at BIGINT NOT NULL
);