package postgres

import "context"

// attachmentRecipientControlsAvailable verifies the exact schema-v11 stable
// principal snapshot and download authority. Application code receives only
// narrow routine execution, never direct lifecycle-table authority.
func attachmentRecipientControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('attachment.endpoint_principals') AS endpoint_oid,
           to_regclass('attachment.conversation_projects') AS conversation_oid,
           to_regclass('attachment.message_artifacts') AS message_oid,
           to_regclass('attachment.recipient_grants') AS grant_oid,
           to_regclass('attachment.recipient_grant_endpoints') AS evidence_oid,
           to_regclass('attachment.endpoint_principals_principal') AS endpoint_index_oid,
           to_regclass('attachment.conversation_projects_project') AS conversation_index_oid,
           to_regclass('attachment.recipient_grants_principal') AS grant_index_oid,
           to_regprocedure('attachment.device_authority_current(uuid,uuid,bigint)') AS authority_oid,
           to_regprocedure('attachment.bind_endpoint_principals(text,uuid,uuid,bigint,jsonb,timestamp with time zone)') AS endpoint_bind_oid,
           to_regprocedure('attachment.bind_conversation_project(uuid,uuid,bigint,uuid,text,uuid)') AS conversation_bind_oid,
           to_regprocedure('attachment.bind_message_artifacts(uuid,uuid,bigint,uuid,jsonb)') AS message_bind_oid,
           to_regprocedure('attachment.project_has_recipient_records(uuid,uuid)') AS project_records_oid,
           to_regprocedure('attachment.authorize_download(uuid,uuid,bigint,uuid)') AS download_oid
), expected_columns(relation_name, column_name, type_name, type_modifier, required) AS (
    VALUES
      ('attachment.endpoint_principals','endpoint','text',-1,true),
      ('attachment.endpoint_principals','machine_id','text',-1,true),
      ('attachment.endpoint_principals','principal_id','uuid',-1,true),
      ('attachment.endpoint_principals','credential_lookup_id','uuid',-1,true),
      ('attachment.endpoint_principals','credential_generation','bigint',-1,true),
      ('attachment.endpoint_principals','ownership_generation','bigint',-1,true),
      ('attachment.endpoint_principals','bound_at','timestamp with time zone',-1,true),
      ('attachment.conversation_projects','conversation_id','uuid',-1,true),
      ('attachment.conversation_projects','project_id','uuid',-1,true),
      ('attachment.conversation_projects','bound_by','uuid',-1,true),
      ('attachment.conversation_projects','bound_at','timestamp with time zone',-1,true),
      ('attachment.message_artifacts','message_id','uuid',-1,true),
      ('attachment.message_artifacts','ordinal','smallint',-1,true),
      ('attachment.message_artifacts','artifact_id','uuid',-1,true),
      ('attachment.message_artifacts','sender_principal_id','uuid',-1,true),
      ('attachment.message_artifacts','linked_at','timestamp with time zone',-1,true),
      ('attachment.recipient_grants','artifact_id','uuid',-1,true),
      ('attachment.recipient_grants','recipient_principal_id','uuid',-1,true),
      ('attachment.recipient_grants','message_id','uuid',-1,true),
      ('attachment.recipient_grants','granted_at','timestamp with time zone',-1,true),
      ('attachment.recipient_grant_endpoints','artifact_id','uuid',-1,true),
      ('attachment.recipient_grant_endpoints','recipient_principal_id','uuid',-1,true),
      ('attachment.recipient_grant_endpoints','recipient_endpoint','text',-1,true),
      ('attachment.recipient_grant_endpoints','recipient_machine_id','text',-1,true),
      ('attachment.recipient_grant_endpoints','ownership_generation','bigint',-1,true),
      ('attachment.recipient_grant_endpoints','message_id','uuid',-1,true)
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text AS relation_name, attribute.attname AS column_name,
           attribute.atttypid::regtype::text AS type_name, attribute.atttypmod AS type_modifier,
           attribute.attnotnull AS required
    FROM pg_attribute AS attribute, objects
    WHERE attribute.attrelid = ANY(ARRAY[endpoint_oid,conversation_oid,message_oid,grant_oid,evidence_oid])
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
), expected_routines(oid, body_hash, volatility, application_execute, result_type, returns_set) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
      (authority_oid,'2b747828a74bec8059e8d91cdce5fd3e','s'::"char",false,'boolean',false),
      (endpoint_bind_oid,'c64c9ab67709cfd68977856025101cc4','v'::"char",true,'integer',false),
      (conversation_bind_oid,'9be80fae35482bb930c6583ed907cbe2','v'::"char",true,'uuid',false),
      (message_bind_oid,'69e391d03200ec08e286603c9e622683','v'::"char",true,'integer',false),
      (project_records_oid,'b3068ea4d3e069841d630136a396b69e','v'::"char",true,'boolean',false),
      (download_oid,'fdce23e16bba8fc36e3629413e54d7cd','s'::"char",true,'record',true)
    ) AS expected(oid,body_hash,volatility,application_execute,result_type,returns_set)
), routine_safety AS (
    SELECT count(*) = 6
       AND bool_and(pg_get_userbyid(proc.proowner) = 'punaro_owner')
       AND bool_and(language.lanname IN ('sql','plpgsql'))
       AND bool_and(proc.prokind = 'f' AND proc.prosecdef AND proc.provolatile = expected.volatility)
       AND bool_and(proc.proconfig = ARRAY['search_path=pg_catalog']::text[])
       AND bool_and(proc.prorettype::regtype::text = expected.result_type AND proc.proretset = expected.returns_set)
       AND bool_and(md5(btrim(proc.prosrc)) = expected.body_hash) AS exact
    FROM expected_routines AS expected
    JOIN pg_proc AS proc ON proc.oid = expected.oid
    JOIN pg_language AS language ON language.oid = proc.prolang
), routine_acl AS (
    SELECT count(*) = 11
       AND bool_and(acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable)
       AND bool_and(grantee.rolname IN ('punaro_owner','punaro_app'))
       AND count(*) FILTER (WHERE grantee.rolname = 'punaro_app') = 5 AS exact
    FROM expected_routines AS expected
    JOIN pg_proc AS proc ON proc.oid = expected.oid
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
), table_safety AS (
    SELECT count(*) = 5 AND bool_and(pg_get_userbyid(relation.relowner) = 'punaro_owner')
       AND bool_and(relation.relkind = 'r' AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity) AS exact
    FROM pg_class AS relation, objects
    WHERE relation.oid = ANY(ARRAY[endpoint_oid,conversation_oid,message_oid,grant_oid,evidence_oid])
), table_acl AS (
    SELECT count(*) = 40 AND bool_and(grantee.rolname = 'punaro_owner' AND NOT acl.is_grantable) AS exact
    FROM pg_class AS relation, objects
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee
    WHERE relation.oid = ANY(ARRAY[endpoint_oid,conversation_oid,message_oid,grant_oid,evidence_oid])
), constraint_safety AS (
    SELECT count(*) = 27 AND bool_and(convalidated AND NOT condeferrable AND NOT condeferred)
       AND count(*) FILTER (WHERE contype = 'f' AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's') = 13 AS exact
    FROM pg_constraint, objects
    WHERE conrelid = ANY(ARRAY[endpoint_oid,conversation_oid,message_oid,grant_oid,evidence_oid])
      AND contype <> 'n'
), critical_constraint_shapes(relation_name,constraint_name,constraint_type,column_keys,referenced_relation,referenced_keys) AS (
    VALUES
      ('attachment.message_artifacts','message_artifacts_artifact_message_key','u','3 1',NULL::text,NULL::text),
      ('attachment.message_artifacts','message_artifacts_artifact_key','u','3',NULL::text,NULL::text),
      ('attachment.recipient_grants','recipient_grants_artifact_message_fkey','f','1 3','attachment.message_artifacts','3 1'),
      ('attachment.recipient_grant_endpoints','recipient_grant_endpoints_grant_fkey','f','1 2','attachment.recipient_grants','1 2'),
      ('attachment.recipient_grant_endpoints','recipient_grant_endpoints_delivery_fkey','f','6 3','relay.mail_deliveries','2 3')
), actual_critical_constraint_shapes AS (
    SELECT constraint_row.conrelid::regclass::text, constraint_row.conname,
           constraint_row.contype::text, constraint_row.conkey::text,
           NULLIF(constraint_row.confrelid,0)::regclass::text,
           CASE WHEN constraint_row.confkey IS NULL THEN NULL ELSE constraint_row.confkey::text END
    FROM pg_constraint AS constraint_row, objects
    WHERE constraint_row.conrelid = ANY(ARRAY[message_oid,grant_oid,evidence_oid])
      AND constraint_row.conname IN (
          'message_artifacts_artifact_message_key','message_artifacts_artifact_key',
          'recipient_grants_artifact_message_fkey','recipient_grant_endpoints_grant_fkey',
          'recipient_grant_endpoints_delivery_fkey'
      )
), expected_checks(relation_name,constraint_name,column_keys,expression) AS (
    VALUES
      ('attachment.endpoint_principals','endpoint_principals_machine_id_check','2','((char_length(machine_id) >= 1) AND (char_length(machine_id) <= 128) AND (octet_length(machine_id) <= 512) AND (machine_id !~ ''[[:cntrl:]]''::text))'),
      ('attachment.endpoint_principals','endpoint_principals_credential_generation_check','5','(credential_generation >= 1)'),
      ('attachment.endpoint_principals','endpoint_principals_ownership_generation_check','6','(ownership_generation >= 1)'),
      ('attachment.message_artifacts','message_artifacts_ordinal_check','2','((ordinal >= 0) AND (ordinal <= 15))'),
      ('attachment.recipient_grant_endpoints','recipient_grant_endpoints_endpoint_check','3','((char_length(recipient_endpoint) >= 1) AND (char_length(recipient_endpoint) <= 512) AND (octet_length(recipient_endpoint) <= 2048) AND (recipient_endpoint !~ ''[[:cntrl:]]''::text))'),
      ('attachment.recipient_grant_endpoints','recipient_grant_endpoints_machine_check','4','((char_length(recipient_machine_id) >= 1) AND (char_length(recipient_machine_id) <= 128) AND (octet_length(recipient_machine_id) <= 512) AND (recipient_machine_id !~ ''[[:cntrl:]]''::text))'),
      ('attachment.recipient_grant_endpoints','recipient_grant_endpoints_generation_check','5','(ownership_generation >= 1)')
), actual_checks AS (
    SELECT constraint_row.conrelid::regclass::text, constraint_row.conname,
           constraint_row.conkey::text, pg_get_expr(constraint_row.conbin,constraint_row.conrelid)
    FROM pg_constraint AS constraint_row, objects
    WHERE constraint_row.conrelid = ANY(ARRAY[endpoint_oid,message_oid,evidence_oid])
      AND constraint_row.contype = 'c' AND constraint_row.convalidated
), check_safety AS (
    SELECT NOT EXISTS (SELECT * FROM expected_checks EXCEPT SELECT * FROM actual_checks)
       AND NOT EXISTS (SELECT * FROM actual_checks EXCEPT SELECT * FROM expected_checks) AS exact
), expected_indexes(relation_name,index_name,column_keys,is_unique,is_primary) AS (
    VALUES
      ('attachment.endpoint_principals','endpoint_principals_pkey','1',true,true),
      ('attachment.endpoint_principals','endpoint_principals_principal','3 1',false,false),
      ('attachment.conversation_projects','conversation_projects_pkey','1',true,true),
      ('attachment.conversation_projects','conversation_projects_project','2 1',false,false),
      ('attachment.message_artifacts','message_artifacts_pkey','1 2',true,true),
      ('attachment.message_artifacts','message_artifacts_artifact_message_key','3 1',true,false),
      ('attachment.message_artifacts','message_artifacts_artifact_key','3',true,false),
      ('attachment.recipient_grants','recipient_grants_pkey','1 2',true,true),
      ('attachment.recipient_grants','recipient_grants_principal','2 1',false,false),
      ('attachment.recipient_grant_endpoints','recipient_grant_endpoints_pkey','1 2 3',true,true)
), actual_indexes AS (
    SELECT index_row.indrelid::regclass::text, index_class.relname, index_row.indkey::text,
           index_row.indisunique, index_row.indisprimary
    FROM pg_index AS index_row
    JOIN pg_class AS index_class ON index_class.oid = index_row.indexrelid, objects
    WHERE index_row.indrelid = ANY(ARRAY[endpoint_oid,conversation_oid,message_oid,grant_oid,evidence_oid])
      AND index_row.indisvalid AND index_row.indisready
      AND index_row.indpred IS NULL AND index_row.indexprs IS NULL
), index_safety AS (
    SELECT NOT EXISTS (SELECT * FROM expected_indexes EXCEPT SELECT * FROM actual_indexes)
       AND NOT EXISTS (SELECT * FROM actual_indexes EXCEPT SELECT * FROM expected_indexes) AS exact
)
SELECT endpoint_oid IS NOT NULL AND conversation_oid IS NOT NULL AND message_oid IS NOT NULL
   AND grant_oid IS NOT NULL AND evidence_oid IS NOT NULL
   AND endpoint_index_oid IS NOT NULL AND conversation_index_oid IS NOT NULL AND grant_index_oid IS NOT NULL
   AND authority_oid IS NOT NULL AND endpoint_bind_oid IS NOT NULL AND conversation_bind_oid IS NOT NULL
   AND message_bind_oid IS NOT NULL AND project_records_oid IS NOT NULL AND download_oid IS NOT NULL
   AND pg_get_function_result(download_oid) = 'TABLE(artifact_id uuid, project_id uuid, storage_path text, size_bytes bigint, sha256 text, display_name text, media_type text, ready_at timestamp with time zone)'
   AND table_safety.exact AND table_acl.exact AND routine_safety.exact AND routine_acl.exact
   AND constraint_safety.exact AND check_safety.exact AND index_safety.exact
   AND NOT EXISTS (SELECT * FROM critical_constraint_shapes EXCEPT SELECT * FROM actual_critical_constraint_shapes)
   AND NOT EXISTS (SELECT * FROM actual_critical_constraint_shapes EXCEPT SELECT * FROM critical_constraint_shapes)
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (
       SELECT 1 FROM pg_class AS relation, objects
       WHERE relation.oid = ANY(ARRAY[endpoint_oid,conversation_oid,message_oid,grant_oid,evidence_oid])
         AND (has_table_privilege('punaro_app',relation.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
              OR has_any_column_privilege('punaro_app',relation.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
   )
   AND NOT has_function_privilege('punaro_app',authority_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',endpoint_bind_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',conversation_bind_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',message_bind_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',project_records_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',download_oid,'EXECUTE')
FROM objects, table_safety, table_acl, routine_safety, routine_acl, constraint_safety, check_safety, index_safety`).Scan(&available)
	return available, err
}
