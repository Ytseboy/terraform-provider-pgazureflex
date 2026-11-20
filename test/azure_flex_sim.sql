-- Azure Database for PostgreSQL - Flexible Server simulation harness for local integration testing.
-- Models real Azure Flexible Server semantics:
--   1. Admin user (`flexadmin`) is a member of `azure_pg_admin` and is NOT a PostgreSQL SUPERUSER.
--   2. Provides `pgaadauth_create_principal_with_oid`, `pgaadauth_create_principal`, and
--      `pgaadauth_list_principals` matching Azure Flexible Server's `pgaadauth` signatures.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'azure_pg_admin') THEN
        CREATE ROLE azure_pg_admin NOLOGIN CREATEROLE CREATEDB REPLICATION BYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'flexadmin') THEN
        CREATE ROLE flexadmin LOGIN PASSWORD 'flexadmin-secret' CREATEROLE CREATEDB REPLICATION BYPASSRLS;
    END IF;
    GRANT azure_pg_admin TO flexadmin WITH ADMIN OPTION;
END $$;

CREATE SCHEMA IF NOT EXISTS pgaadauth_sim;

CREATE TABLE IF NOT EXISTS pgaadauth_sim.principals (
    rolname        text PRIMARY KEY,
    principal_type text NOT NULL,
    object_id      text NOT NULL,
    is_mfa         boolean NOT NULL DEFAULT false
);

GRANT USAGE ON SCHEMA pgaadauth_sim TO azure_pg_admin;
GRANT ALL ON TABLE pgaadauth_sim.principals TO azure_pg_admin;

-- Matches Azure Flexible Server: pgaadauth_create_principal_with_oid(roleName, objectId, objectType, isAdmin, isMfa)
CREATE OR REPLACE FUNCTION public.pgaadauth_create_principal_with_oid(
    role_name   text,
    object_id   text,
    object_type text,
    is_admin    boolean,
    is_mfa      boolean
) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF lower(object_type) NOT IN ('user', 'group', 'service') THEN
        RAISE EXCEPTION 'Invalid object_type %: must be user, group, or service', object_type;
    END IF;

    EXECUTE format('CREATE ROLE %I LOGIN', role_name);
    IF is_admin THEN
        EXECUTE format('GRANT azure_pg_admin TO %I', role_name);
    ELSE
        -- In vanilla PG 16 without Azure's engine patch, grant ADMIN OPTION on non-admin roles
        -- to azure_pg_admin so flexadmin can ALTER/DROP them.
        EXECUTE format('GRANT %I TO azure_pg_admin WITH ADMIN OPTION', role_name);
    END IF;

    INSERT INTO pgaadauth_sim.principals (rolname, principal_type, object_id, is_mfa)
    VALUES (role_name, lower(object_type), object_id, is_mfa)
    ON CONFLICT (rolname) DO UPDATE
        SET principal_type = EXCLUDED.principal_type,
            object_id = EXCLUDED.object_id,
            is_mfa = EXCLUDED.is_mfa;

    RETURN format('Created role %s', role_name);
END;
$$;

-- Matches Azure Flexible Server: pgaadauth_create_principal(roleName, isAdmin, isMfa)
CREATE OR REPLACE FUNCTION public.pgaadauth_create_principal(
    role_name text,
    is_admin  boolean,
    is_mfa    boolean
) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RETURN public.pgaadauth_create_principal_with_oid(
        role_name,
        '00000000-0000-0000-0000-000000000001',
        'user',
        is_admin,
        is_mfa
    );
END;
$$;

-- Matches Azure Flexible Server: pgaadauth_list_principals(isAdminOnly)
CREATE OR REPLACE FUNCTION public.pgaadauth_list_principals(is_admin_only boolean)
RETURNS TABLE(
    rolname       text,
    principalType text,
    objectId      text,
    isAdmin       boolean,
    isMfa         boolean
)
LANGUAGE sql
SECURITY DEFINER
AS $$
    SELECT
        p.rolname,
        p.principal_type AS principalType,
        p.object_id AS objectId,
        pg_has_role(r.oid, 'azure_pg_admin', 'MEMBER') AS isAdmin,
        p.is_mfa AS isMfa
    FROM pgaadauth_sim.principals p
    JOIN pg_roles r ON r.rolname = p.rolname
    WHERE (NOT is_admin_only) OR pg_has_role(r.oid, 'azure_pg_admin', 'MEMBER')
    ORDER BY p.rolname;
$$;

GRANT EXECUTE ON FUNCTION public.pgaadauth_create_principal_with_oid(text, text, text, boolean, boolean) TO azure_pg_admin;
GRANT EXECUTE ON FUNCTION public.pgaadauth_create_principal(text, boolean, boolean) TO azure_pg_admin;
GRANT EXECUTE ON FUNCTION public.pgaadauth_list_principals(boolean) TO azure_pg_admin;
