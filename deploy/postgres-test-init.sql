-- Integration-only bootstrap. Authentication is trusted only inside the
-- private, ephemeral Compose network and MUST NOT be copied to deployments.
CREATE ROLE punaro_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE punaro TO punaro_app;
CREATE DATABASE punaro_other OWNER punaro_owner;
GRANT CONNECT ON DATABASE punaro_other TO punaro_app;
CREATE DATABASE punaro_pair OWNER punaro_owner;
GRANT CONNECT ON DATABASE punaro_pair TO punaro_app;
