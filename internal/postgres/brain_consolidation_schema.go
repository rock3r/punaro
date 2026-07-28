package postgres

import "context"

// memoryConsolidationControlsAvailable verifies the versioned durable
// checkpoint fence and its application-role boundary.
func memoryConsolidationControlsAvailable(ctx context.Context, q queryer, version int64) (bool, error) {
	var available bool
	claimMD5, advanceMD5 := memoryConsolidationClaimRoutineMD5, memoryConsolidationAdvanceRoutineMD5
	documentsMD5 := memoryConsolidationDocumentsRoutineMD5
	if version == 33 {
		claimMD5, advanceMD5 = memoryConsolidationV33ClaimRoutineMD5, memoryConsolidationV33AdvanceRoutineMD5
	}
	if version == 35 {
		documentsMD5 = memoryConsolidationV35DocumentsRoutineMD5
	}
	if version == 36 {
		documentsMD5 = memoryConsolidationV36DocumentsRoutineMD5
	}
	if version >= 38 {
		documentsMD5 = memoryConsolidationV38DocumentsRoutineMD5
	}
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('brain.memory_consolidation_checkpoints') AS table_oid,
           to_regprocedure('brain.claim_memory_consolidation_checkpoint(uuid,uuid,bigint)') AS claim_oid,
           to_regprocedure('brain.advance_memory_consolidation_checkpoint(uuid,uuid,bigint,uuid,bigint)') AS advance_oid,
           to_regprocedure('brain.read_memory_consolidation_sources(uuid,uuid,bigint)') AS sources_oid,
           to_regprocedure('brain.read_memory_consolidation_documents(uuid,uuid,bigint)') AS documents_oid,
           $5::boolean AS sources_required,
           $6::boolean AS documents_required,
           $7::boolean AS document_hash_required
), expected_columns(name,type_name,required,default_expression) AS (
    VALUES
      ('scope_id','uuid',true,''),('timeline_id','uuid',true,''),('change_sequence','bigint',true,'0'),
      ('lease_holder','uuid',false,''),('lease_token','uuid',false,''),('lease_generation','bigint',true,'0'),
      ('lease_until','timestamp with time zone',false,''),('updated_at','timestamp with time zone',true,'statement_timestamp()')
), actual_columns AS (
    SELECT attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute CROSS JOIN objects
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
    WHERE attribute.attrelid=table_oid AND attribute.attnum>0 AND NOT attribute.attisdropped
), routine_safety AS (
    SELECT count(*)=(CASE WHEN documents_required THEN 4 WHEN sources_required THEN 3 ELSE 2 END) AND bool_and(pg_get_userbyid(routine.proowner)='punaro_owner'
      AND routine.prokind='f' AND routine.prosecdef AND routine.provolatile='v'
      AND routine.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
      AND routine.proconfig=ARRAY['search_path=pg_catalog']::text[] AND NOT routine.proisstrict
      AND NOT routine.proleakproof AND routine.proparallel='u' AND routine.provariadic=0
      AND ((routine.oid=claim_oid AND routine.proretset AND routine.prorettype='record'::regtype
            AND routine.pronargs=3 AND routine.proargtypes='2950 2950 20'::oidvector
            AND routine.proallargtypes=ARRAY['uuid'::regtype,'uuid'::regtype,'bigint'::regtype,'uuid'::regtype,'uuid'::regtype,'bigint'::regtype,'uuid'::regtype,'uuid'::regtype,'bigint'::regtype,'timestamp with time zone'::regtype]::oid[]
            AND routine.proargmodes=ARRAY['i','i','i','t','t','t','t','t','t','t']::"char"[]
            AND routine.proargnames=ARRAY['requested_scope','requested_holder','requested_lease_micros','scope_id','timeline_id','change_sequence','lease_holder','lease_token','lease_generation','lease_until']::text[]
            AND md5(btrim(routine.prosrc,E' \n\r\t'))=$1)
        OR (routine.oid=advance_oid AND NOT routine.proretset AND routine.prorettype='boolean'::regtype
            AND routine.pronargs=5 AND routine.proargtypes='2950 2950 20 2950 20'::oidvector
            AND md5(btrim(routine.prosrc,E' \n\r\t'))=$2)
        OR (routine.oid=sources_oid AND routine.proretset AND routine.prorettype='record'::regtype
            AND routine.pronargs=3 AND routine.proargtypes='2950 2950 20'::oidvector
            AND routine.proallargtypes=ARRAY['uuid'::regtype,'uuid'::regtype,'bigint'::regtype,'uuid'::regtype,'uuid'::regtype,'bigint'::regtype,'bigint'::regtype,'boolean'::regtype]::oid[]
            AND routine.proargmodes=ARRAY['i','i','i','t','t','t','t','t']::"char"[]
            AND routine.proargnames=ARRAY['requested_scope','requested_token','requested_generation','timeline_id','item_id','revision','change_sequence','is_fence']::text[]
            AND md5(btrim(routine.prosrc,E' \n\r\t'))=$3)
        OR (routine.oid=documents_oid AND routine.proretset AND routine.prorettype='record'::regtype
            AND routine.pronargs=3 AND routine.proargtypes='2950 2950 20'::oidvector
            AND ((document_hash_required
                  AND routine.proallargtypes=ARRAY['uuid'::regtype,'uuid'::regtype,'bigint'::regtype,'uuid'::regtype,'uuid'::regtype,'bigint'::regtype,'bigint'::regtype,'jsonb'::regtype,'bytea'::regtype,'boolean'::regtype]::oid[]
                  AND routine.proargmodes=ARRAY['i','i','i','t','t','t','t','t','t','t']::"char"[]
                  AND routine.proargnames=ARRAY['requested_scope','requested_token','requested_generation','timeline_id','item_id','revision','change_sequence','document','content_sha256','is_fence']::text[])
                 OR (NOT document_hash_required
                  AND routine.proallargtypes=ARRAY['uuid'::regtype,'uuid'::regtype,'bigint'::regtype,'uuid'::regtype,'uuid'::regtype,'bigint'::regtype,'bigint'::regtype,'jsonb'::regtype,'boolean'::regtype]::oid[]
                  AND routine.proargmodes=ARRAY['i','i','i','t','t','t','t','t','t']::"char"[]
                  AND routine.proargnames=ARRAY['requested_scope','requested_token','requested_generation','timeline_id','item_id','revision','change_sequence','document','is_fence']::text[]))
            AND md5(btrim(routine.prosrc,E' \n\r\t'))=$4))) AS exact
    FROM pg_proc AS routine,objects
    WHERE routine.oid=ANY(ARRAY[claim_oid,advance_oid,sources_oid,documents_oid])
    GROUP BY sources_required,documents_required,document_hash_required
), constraint_safety AS (
    SELECT count(*)=5
       AND count(*) FILTER (WHERE contype='p' AND conkey=ARRAY[1]::smallint[])=1
       AND count(*) FILTER (WHERE contype='f' AND conkey=ARRAY[1]::smallint[] AND confrelid='brain.scopes'::regclass AND confdeltype='c')=1
       AND count(*) FILTER (WHERE contype='c' AND pg_get_constraintdef(oid) LIKE '%change_sequence >= 0%')=1
       AND count(*) FILTER (WHERE contype='c' AND pg_get_constraintdef(oid) LIKE '%lease_generation >= 0%')=1
       AND count(*) FILTER (WHERE contype='c' AND pg_get_constraintdef(oid) LIKE '%lease_holder IS NULL%' AND pg_get_constraintdef(oid) LIKE '%lease_until IS NOT NULL%')=1 AS exact
    FROM pg_constraint,objects WHERE conrelid=table_oid AND contype<>'n'
), expected_acl(routine_oid,grantee,privilege_type,is_grantable) AS (
    SELECT claim_oid,'punaro_owner','EXECUTE',false FROM objects UNION ALL
    SELECT claim_oid,'punaro_app','EXECUTE',false FROM objects UNION ALL
    SELECT advance_oid,'punaro_owner','EXECUTE',false FROM objects UNION ALL
    SELECT advance_oid,'punaro_app','EXECUTE',false FROM objects UNION ALL
    SELECT sources_oid,'punaro_owner','EXECUTE',false FROM objects WHERE sources_required UNION ALL
    SELECT sources_oid,'punaro_app','EXECUTE',false FROM objects WHERE sources_required UNION ALL
    SELECT documents_oid,'punaro_owner','EXECUTE',false FROM objects WHERE documents_required UNION ALL
    SELECT documents_oid,'punaro_app','EXECUTE',false FROM objects WHERE documents_required
), actual_acl AS (
    SELECT routine.oid,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS routine CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE routine.oid=ANY(ARRAY[claim_oid,advance_oid,sources_oid,documents_oid])
), table_acl_safety AS (
    SELECT NOT EXISTS (
        SELECT 1
        FROM pg_class AS relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS entry,objects
        WHERE relation.oid=table_oid AND entry.grantee<>relation.relowner
    ) AS exact
)
SELECT table_oid IS NOT NULL AND claim_oid IS NOT NULL AND advance_oid IS NOT NULL AND (NOT sources_required OR sources_oid IS NOT NULL) AND (NOT documents_required OR documents_oid IS NOT NULL)
   AND (SELECT count(*)=1 AND bool_and(pg_get_userbyid(relowner)='punaro_owner' AND relkind='r' AND relpersistence='p' AND NOT relrowsecurity AND NOT relforcerowsecurity) FROM pg_class WHERE oid=table_oid)
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND routine_safety.exact
   AND constraint_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
   AND NOT EXISTS (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl)
   AND table_acl_safety.exact
   AND NOT has_table_privilege('punaro_app',table_oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT EXISTS (SELECT 1 FROM pg_attribute,objects WHERE attrelid=table_oid AND attnum>0 AND NOT attisdropped AND attacl IS NOT NULL)
FROM objects,routine_safety,constraint_safety,table_acl_safety`, claimMD5, advanceMD5, memoryConsolidationSourcesRoutineMD5, documentsMD5, version >= 34, version >= 35, version >= 37).Scan(&available)
	return available, err
}

// memoryConsolidationProposalSourcesAvailable verifies the v38 immutable
// provenance relation and the narrow application-role boundary around it.
func memoryConsolidationProposalSourcesAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH relation AS (
    SELECT to_regclass('brain.memory_consolidation_proposal_sources') AS oid,
           to_regprocedure('brain.guard_memory_consolidation_proposal_source()') AS guard_oid
), expected_columns(name,type_name,required) AS (
    VALUES ('proposal_id','uuid',true),('ordinal','smallint',true),('timeline_id','uuid',true),
           ('item_id','uuid',true),('revision','bigint',true),('change_sequence','bigint',true)
), actual_columns AS (
    SELECT attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull
    FROM pg_attribute AS attribute,relation
    WHERE attribute.attrelid=relation.oid AND attribute.attnum>0 AND NOT attribute.attisdropped
), application_privileges AS (
    SELECT has_table_privilege('punaro_app',oid,'SELECT') AS selects,
           has_column_privilege('punaro_app',oid,'proposal_id','INSERT')
             AND has_column_privilege('punaro_app',oid,'ordinal','INSERT')
             AND has_column_privilege('punaro_app',oid,'timeline_id','INSERT')
             AND has_column_privilege('punaro_app',oid,'item_id','INSERT')
             AND has_column_privilege('punaro_app',oid,'revision','INSERT')
             AND has_column_privilege('punaro_app',oid,'change_sequence','INSERT') AS inserts,
           NOT has_table_privilege('punaro_app',oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
             AND NOT has_any_column_privilege('punaro_app',oid,'UPDATE,REFERENCES') AS no_writes
    FROM relation
), public_acl_safety AS (
    SELECT NOT has_table_privilege('public',oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_any_column_privilege('public',oid,'SELECT,INSERT,UPDATE,REFERENCES') AS exact
    FROM relation
), trigger_safety AS (
    SELECT count(*)=2
       AND count(*) FILTER (WHERE tgname='memory_consolidation_proposal_source_insert_guard' AND tgtype=7 AND tgfoid=guard_oid AND tgenabled='O')=1
       AND count(*) FILTER (WHERE tgname='application_mutation_fence' AND tgtype=62 AND tgfoid='jobs.guard_application_mutation()'::regprocedure AND tgenabled='O')=1 AS exact
    FROM pg_trigger,relation WHERE tgrelid=relation.oid AND NOT tgisinternal
), constraint_safety AS (
    SELECT count(*)=5
       AND count(*) FILTER (WHERE contype='p' AND conkey=ARRAY[1,2]::smallint[])=1
       AND count(*) FILTER (WHERE contype='f' AND conkey=ARRAY[1]::smallint[] AND confrelid='brain.memory_proposals'::regclass AND confdeltype='c')=1
       AND count(*) FILTER (WHERE contype='c')=3 AS exact
    FROM pg_constraint,relation WHERE conrelid=relation.oid AND contype<>'n'
), guard_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proowner)='punaro_owner' AND prokind='f' AND prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
      AND proconfig=ARRAY['search_path=pg_catalog']::text[] AND md5(btrim(prosrc,E' \n\r\t'))=$1 AND NOT has_function_privilege('public',oid,'EXECUTE')) AS exact
    FROM pg_proc,relation WHERE oid=guard_oid
)
SELECT relation.oid IS NOT NULL AND relation.guard_oid IS NOT NULL
   AND (SELECT count(*)=1 AND bool_and(pg_get_userbyid(relowner)='punaro_owner' AND relkind='r' AND relpersistence='p' AND NOT relrowsecurity AND NOT relforcerowsecurity) FROM pg_class WHERE oid=relation.oid)
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND application_privileges.selects AND application_privileges.inserts AND application_privileges.no_writes
   AND public_acl_safety.exact
   AND trigger_safety.exact AND constraint_safety.exact AND guard_safety.exact
FROM relation,application_privileges,public_acl_safety,trigger_safety,constraint_safety,guard_safety`, memoryConsolidationProposalSourceGuardRoutineMD5).Scan(&available)
	return available, err
}

const (
	memoryConsolidationProposalSourceGuardRoutineMD5 = "df081efa031414be22850049f25430b5"
	memoryConsolidationClaimRoutineMD5               = "121df7d09493be8662f4618208aaf342"
	memoryConsolidationAdvanceRoutineMD5             = "5666d576e054c6b06999a0b6ce7b6c62"
	memoryConsolidationSourcesRoutineMD5             = "2b180c012d8c1ae7332b81456845a8bf"
	memoryConsolidationDocumentsRoutineMD5           = "0b284fa1e93f9b8cd62604d4e2a3821c"
	memoryConsolidationV38DocumentsRoutineMD5        = "f34725c0ab56059bbaef422677f37357"
	memoryConsolidationV35DocumentsRoutineMD5        = "578fc76b7dd1ed66ccdd7895cd50e07c"
	memoryConsolidationV36DocumentsRoutineMD5        = "8eac22d68c0b50c43de1f8892c925c55"
	memoryConsolidationV33ClaimRoutineMD5            = "32e95c7fb6a9e73522c73b825bc3dcea"
	memoryConsolidationV33AdvanceRoutineMD5          = "cce038c3cca8f3c4f48da8b5e155443c"
)
