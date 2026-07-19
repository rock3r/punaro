-- Integration-only bootstrap. Authentication is trusted only inside the
-- private, ephemeral Compose network and MUST NOT be copied to deployments.
CREATE ROLE punaro_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE punaro TO punaro_app;
