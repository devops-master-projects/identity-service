-- Create a dedicated role and database for Keycloak
CREATE USER keycloakuser WITH PASSWORD 'keycloakpassword';
CREATE DATABASE keycloak OWNER keycloakuser ENCODING 'UTF8';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloakuser;
