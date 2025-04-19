-- Table to store ring signatures metadata
CREATE TABLE IF NOT EXISTS signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    v TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table to store each member's contribution (x_i) and order for each signature
CREATE TABLE IF NOT EXISTS signature_members (
    signature_id UUID NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    member_username TEXT NOT NULL,
    x_value TEXT NOT NULL,
    PRIMARY KEY(signature_id, position)
);

-- Index for efficient lookup by member username
CREATE INDEX IF NOT EXISTS idx_signature_members_member_username
    ON signature_members (member_username);