-- PostgreSQL initialization script
-- Runs once when the container is first created.

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- The database and user are already created by the POSTGRES_* env vars.
-- Grant explicit privileges in case they're needed.
GRANT ALL PRIVILEGES ON DATABASE vulnvision TO vulnvision;
