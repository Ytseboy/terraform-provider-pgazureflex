/*
 * Minimal PostgreSQL 16 C extension simulating Azure Flexible Server's `pgaadauth`
 * security label provider and `azure.extensions` GUC for local E2E testing.
 *
 * Loaded via: shared_preload_libraries = 'pgaadauth_mock'
 */
#include "postgres.h"
#include "fmgr.h"
#include "catalog/pg_authid.h"
#include "commands/seclabel.h"
#include "utils/guc.h"

#include <string.h>

PG_MODULE_MAGIC;

void _PG_init(void);

static char *azure_extensions_guc = NULL;
static char *pgaudit_log_guc = NULL;

static void
pgaadauth_object_relabel(const ObjectAddress *object, const char *seclabel)
{
    if (object->classId != AuthIdRelationId)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("pgaadauth security labels are only supported on ROLE objects")));

    if (seclabel == NULL)
        return;

    if (strncmp(seclabel, "aadauth,", 8) != 0 || strstr(seclabel, "oid=") == NULL || strstr(seclabel, "type=") == NULL)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("invalid pgaadauth security label \"%s\": expected format aadauth,oid=<uuid>,type=<user|group|service>[,admin][,mfa]", seclabel)));
}

void
_PG_init(void)
{
    register_label_provider("pgaadauth", pgaadauth_object_relabel);

    DefineCustomStringVariable(
        "azure.extensions",
        "Simulated Azure Flexible Server allow-listed extensions.",
        NULL,
        &azure_extensions_guc,
        "PGCRYPTO,UUID-OSSP,VECTOR",
        PGC_SIGHUP,
        0,
        NULL,
        NULL,
        NULL
    );

    DefineCustomStringVariable(
        "pgaudit.log",
        "Simulated pgaudit.log GUC for testing dot-qualified role-in-database parameters.",
        NULL,
        &pgaudit_log_guc,
        "none",
        PGC_USERSET,
        0,
        NULL,
        NULL,
        NULL
    );
}
