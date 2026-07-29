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
           to_regprocedure('brain.guard_memory_consolidation_proposal_source()') AS guard_oid,
           to_regprocedure('brain.lock_memory_consolidation_source_guards()') AS lock_guard_oid
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
), expected_table_acl(grantee,privilege_type,is_grantable) AS (
    VALUES
      ('punaro_owner','SELECT',false),('punaro_owner','INSERT',false),('punaro_owner','UPDATE',false),
      ('punaro_owner','DELETE',false),('punaro_owner','TRUNCATE',false),('punaro_owner','REFERENCES',false),
      ('punaro_owner','TRIGGER',false),('punaro_app','SELECT',false)
    UNION ALL SELECT 'punaro_owner','MAINTAIN',false WHERE current_setting('server_version_num')::integer >= 170000
), actual_table_acl AS (
    SELECT role.rolname,entry.privilege_type,entry.is_grantable
    FROM pg_class AS table_row
    CROSS JOIN LATERAL aclexplode(COALESCE(table_row.relacl,acldefault('r',table_row.relowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,relation
    WHERE table_row.oid=relation.oid
), table_acl_safety AS (
    SELECT NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
       AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl) AS exact
), column_acl_safety AS (
    SELECT count(*)=6 AND bool_and(role.rolname='punaro_app' AND entry.privilege_type='INSERT' AND NOT entry.is_grantable) AS exact
    FROM pg_attribute AS attribute
    CROSS JOIN LATERAL aclexplode(attribute.attacl) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,relation
    WHERE attribute.attrelid=relation.oid AND attribute.attnum>0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
), trigger_safety AS (
    SELECT count(*)=2
       AND count(*) FILTER (WHERE tgname='memory_consolidation_proposal_source_insert_guard' AND tgtype=7 AND tgfoid=guard_oid AND tgenabled='O' AND tgattr=''::int2vector AND tgqual IS NULL)=1
       AND count(*) FILTER (WHERE tgname='application_mutation_fence' AND tgtype=62 AND tgfoid='jobs.guard_application_mutation()'::regprocedure AND tgenabled='O' AND tgattr=''::int2vector AND tgqual IS NULL)=1 AS exact
    FROM pg_trigger,relation WHERE tgrelid=relation.oid AND NOT tgisinternal
), constraint_safety AS (
    SELECT count(*)=5 AND bool_and(convalidated AND NOT condeferrable AND NOT condeferred)
       AND count(*) FILTER (WHERE contype='p' AND conkey=ARRAY[1,2]::smallint[])=1
       AND count(*) FILTER (WHERE contype='f' AND conkey=ARRAY[1]::smallint[] AND confrelid='brain.memory_proposals'::regclass AND confdeltype='c')=1
       AND count(*) FILTER (WHERE contype='c')=3 AS exact
    FROM pg_constraint,relation WHERE conrelid=relation.oid AND contype<>'n'
), expected_checks(name,expression) AS (
    VALUES ('memory_consolidation_proposal_sources_ordinal_check','((ordinal >= 0) AND (ordinal <= 127))'),
           ('memory_consolidation_proposal_sources_revision_check','(revision >= 1)'),
           ('memory_consolidation_proposal_sources_sequence_check','(change_sequence >= 0)')
), actual_checks AS (
    SELECT constraint_row.conname,pg_get_expr(constraint_row.conbin,constraint_row.conrelid)
    FROM pg_constraint AS constraint_row,relation
    WHERE constraint_row.conrelid=relation.oid AND constraint_row.contype='c'
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), expected_lock_guard_acl(grantee,privilege_type,is_grantable) AS (
    VALUES ('punaro_owner','EXECUTE',false),('punaro_app','EXECUTE',false)
), actual_lock_guard_acl AS (
    SELECT role.rolname,entry.privilege_type,entry.is_grantable
    FROM pg_proc AS routine
    CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,relation
    WHERE routine.oid=lock_guard_oid
), guard_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proowner)='punaro_owner' AND prokind='f' AND prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
      AND proconfig=ARRAY['search_path=pg_catalog']::text[] AND md5(btrim(prosrc,E' \n\r\t'))=$1 AND NOT has_function_privilege('public',pg_proc.oid,'EXECUTE')) AS exact
    FROM pg_proc,relation WHERE pg_proc.oid=guard_oid
), lock_guard_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proowner)='punaro_owner' AND prokind='f' AND prosecdef AND provolatile='v'
      AND NOT proretset AND prorettype='void'::regtype AND pronargs=0
      AND prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
      AND proconfig=ARRAY['search_path=pg_catalog']::text[] AND md5(btrim(prosrc,E' \n\r\t'))=$2
      AND NOT EXISTS (SELECT * FROM expected_lock_guard_acl EXCEPT SELECT * FROM actual_lock_guard_acl)
      AND NOT EXISTS (SELECT * FROM actual_lock_guard_acl EXCEPT SELECT * FROM expected_lock_guard_acl)) AS exact
    FROM pg_proc,relation WHERE pg_proc.oid=lock_guard_oid
)
SELECT relation.oid IS NOT NULL AND relation.guard_oid IS NOT NULL AND relation.lock_guard_oid IS NOT NULL
   AND (SELECT count(*)=1 AND bool_and(pg_get_userbyid(relowner)='punaro_owner' AND relkind='r' AND relpersistence='p' AND NOT relrowsecurity AND NOT relforcerowsecurity) FROM pg_class WHERE oid=relation.oid)
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND application_privileges.selects AND application_privileges.inserts AND application_privileges.no_writes
   AND table_acl_safety.exact AND column_acl_safety.exact
   AND trigger_safety.exact AND constraint_safety.exact AND guard_safety.exact AND lock_guard_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_checks EXCEPT SELECT * FROM actual_checks)
   AND NOT EXISTS (SELECT * FROM actual_checks EXCEPT SELECT * FROM expected_checks)
FROM relation,application_privileges,table_acl_safety,column_acl_safety,trigger_safety,constraint_safety,guard_safety,lock_guard_safety`, memoryConsolidationProposalSourceGuardRoutineMD5, memoryConsolidationProposalSourceLockGuardRoutineMD5).Scan(&available)
	return available, err
}

// memoryConsolidationPassesAvailable verifies the immutable replay plan and
// its narrow application boundary. A missing or writable pass relation must
// leave the database non-current rather than permitting replacement outputs.
func memoryConsolidationPassesAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH relation AS (
    SELECT to_regclass('brain.memory_consolidation_passes') AS table_oid,
           to_regclass('brain.memory_consolidation_checkpoints') AS checkpoint_oid,
           to_regprocedure('brain.guard_memory_consolidation_pass()') AS guard_oid,
           to_regprocedure('brain.clear_memory_consolidation_passes_on_checkpoint_move()') AS cleanup_oid,
           to_regprocedure('brain.complete_memory_consolidation_pass(uuid,uuid,bigint,uuid,bigint,bigint,uuid,uuid)') AS complete_oid,
           to_regprocedure('brain.abandon_memory_consolidation_pass(uuid,uuid,bigint,uuid,bigint,bigint,uuid,uuid)') AS abandon_oid
), expected_columns(name,type_name,required,default_expression) AS (
    VALUES
      ('scope_id','uuid',true,''),('timeline_id','uuid',true,''),('start_sequence','bigint',true,''),
      ('next_sequence','bigint',true,''),('principal_id','uuid',true,''),('project_id','uuid',true,''),
      ('lease_token','uuid',true,''),('lease_generation','bigint',true,''),('source_sha256','bytea',true,''),
      ('sources','jsonb',true,''),('proposals','jsonb',true,''),('created_at','timestamp with time zone',true,'statement_timestamp()')
), actual_columns AS (
    SELECT attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute CROSS JOIN relation
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
    WHERE attribute.attrelid=table_oid AND attribute.attnum>0 AND NOT attribute.attisdropped
), table_acl AS (
    SELECT has_table_privilege('punaro_app',table_oid,'SELECT') AS selects,
           NOT has_table_privilege('punaro_app',table_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS no_writes,
           NOT has_table_privilege('public',table_oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS no_public
    FROM relation
), insert_acl AS (
    SELECT has_column_privilege('punaro_app',table_oid,'scope_id','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'timeline_id','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'start_sequence','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'next_sequence','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'principal_id','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'project_id','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'lease_token','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'lease_generation','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'source_sha256','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'sources','INSERT')
       AND has_column_privilege('punaro_app',table_oid,'proposals','INSERT')
       AND NOT has_table_privilege('punaro_app',table_oid,'INSERT') AS exact
    FROM relation
), triggers AS (
    SELECT count(*)=2
       AND count(*) FILTER (WHERE tgname='memory_consolidation_pass_insert_guard' AND tgtype=7 AND tgfoid=guard_oid AND tgenabled='O' AND tgattr=''::int2vector AND tgqual IS NULL)=1
       AND count(*) FILTER (WHERE tgname='application_mutation_fence' AND tgtype=62 AND tgfoid='jobs.guard_application_mutation()'::regprocedure AND tgenabled='O')=1 AS exact
    FROM pg_trigger,relation WHERE tgrelid=table_oid AND NOT tgisinternal
), checkpoint_triggers AS (
    SELECT count(*)=1 AND count(*) FILTER (WHERE tgname='memory_consolidation_pass_checkpoint_cleanup'
      AND tgtype=17 AND tgfoid=cleanup_oid AND tgenabled='O' AND tgattr='2 3'::int2vector
      AND tgqual IS NOT NULL)=1 AS exact
    FROM pg_trigger,relation WHERE tgrelid=checkpoint_oid AND NOT tgisinternal
), constraints AS (
    SELECT count(*)=6 AND bool_and(convalidated AND NOT condeferrable AND NOT condeferred)
       AND count(*) FILTER (WHERE contype='p' AND conkey=ARRAY[1,2,3]::smallint[])=1
       AND count(*) FILTER (WHERE contype='f' AND conkey=ARRAY[1]::smallint[] AND confrelid='brain.scopes'::regclass AND confdeltype='c')=1
       AND count(*) FILTER (WHERE contype='c')=4 AS exact
    FROM pg_constraint,relation WHERE conrelid=table_oid AND contype<>'n'
), routines AS (
    SELECT count(*)=4 AND bool_and(pg_get_userbyid(proowner)='punaro_owner' AND prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
      AND proconfig=ARRAY['search_path=pg_catalog']::text[] AND NOT has_function_privilege('public',oid,'EXECUTE')) AS exact
    FROM pg_proc,relation WHERE oid=ANY(ARRAY[guard_oid,cleanup_oid,complete_oid,abandon_oid])
), guard_routine AS (
    SELECT count(*)=1 AND bool_and(prosecdef AND md5(btrim(prosrc,E' \n\r\t'))=$2) AS exact
    FROM pg_proc,relation WHERE oid=guard_oid
), completion_routine AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proowner)='punaro_owner' AND prokind='f' AND prosecdef AND provolatile='v'
      AND NOT proretset AND prorettype='boolean'::regtype AND pronargs=8
      AND proargtypes='2950 2950 20 2950 20 20 2950 2950'::oidvector
      AND proargnames=ARRAY['requested_scope','requested_token','requested_generation','requested_timeline','requested_start_sequence','requested_next_sequence','requested_principal','requested_project']::text[]
      AND prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
      AND proconfig=ARRAY['search_path=pg_catalog']::text[]
      AND md5(btrim(prosrc,E' \n\r\t'))=$1) AS exact
    FROM pg_proc,relation WHERE oid=complete_oid
), abandon_routine AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proowner)='punaro_owner' AND prokind='f' AND prosecdef AND provolatile='v'
      AND NOT proretset AND prorettype='boolean'::regtype AND pronargs=8
      AND proargtypes='2950 2950 20 2950 20 20 2950 2950'::oidvector
      AND proargnames=ARRAY['requested_scope','requested_token','requested_generation','requested_timeline','requested_start_sequence','requested_next_sequence','requested_principal','requested_project']::text[]
      AND prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
      AND proconfig=ARRAY['search_path=pg_catalog']::text[]
      AND md5(btrim(prosrc,E' \n\r\t'))=$3) AS exact
    FROM pg_proc,relation WHERE oid=abandon_oid
), complete_acl AS (
    SELECT has_function_privilege('punaro_app',complete_oid,'EXECUTE') AND has_function_privilege('punaro_app',abandon_oid,'EXECUTE') AS app_exec,
           NOT has_function_privilege('public',complete_oid,'EXECUTE') AND NOT has_function_privilege('public',abandon_oid,'EXECUTE') AS no_public
    FROM relation
)
SELECT relation.table_oid IS NOT NULL AND relation.checkpoint_oid IS NOT NULL AND relation.guard_oid IS NOT NULL AND relation.cleanup_oid IS NOT NULL AND relation.complete_oid IS NOT NULL AND relation.abandon_oid IS NOT NULL
   AND (SELECT count(*)=1 AND bool_and(pg_get_userbyid(relowner)='punaro_owner' AND relkind='r' AND relpersistence='p' AND NOT relrowsecurity AND NOT relforcerowsecurity) FROM pg_class WHERE oid=table_oid)
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND table_acl.selects AND table_acl.no_writes AND table_acl.no_public AND insert_acl.exact
   AND triggers.exact AND checkpoint_triggers.exact AND constraints.exact AND routines.exact AND guard_routine.exact AND completion_routine.exact AND abandon_routine.exact AND complete_acl.app_exec AND complete_acl.no_public
FROM relation,table_acl,insert_acl,triggers,checkpoint_triggers,constraints,routines,guard_routine,completion_routine,abandon_routine,complete_acl`, memoryConsolidationPassCompleteRoutineMD5, memoryConsolidationPassGuardRoutineMD5, memoryConsolidationPassAbandonRoutineMD5).Scan(&available)
	return available, err
}

const (
	memoryConsolidationPassCompleteRoutineMD5            = "1319f8b0c9b50efcbc1c6e1df68c7945" // #nosec G101 -- immutable schema routine checksum
	memoryConsolidationPassGuardRoutineMD5               = "060b94eab7fe744984bd09efc2958a57" // #nosec G101 -- immutable schema routine checksum
	memoryConsolidationPassAbandonRoutineMD5             = "bfe14c5526ec0cba1761501b1581ffe9" // #nosec G101 -- immutable schema routine checksum
	memoryConsolidationProposalSourceGuardRoutineMD5     = "aaa45e19ae18202e97772cb7096ad117"
	memoryConsolidationProposalSourceLockGuardRoutineMD5 = "88c2c1cf6aabfec6303afb7a155f3de0"
	memoryConsolidationClaimRoutineMD5                   = "121df7d09493be8662f4618208aaf342"
	memoryConsolidationAdvanceRoutineMD5                 = "5666d576e054c6b06999a0b6ce7b6c62"
	memoryConsolidationSourcesRoutineMD5                 = "2b180c012d8c1ae7332b81456845a8bf"
	memoryConsolidationDocumentsRoutineMD5               = "0b284fa1e93f9b8cd62604d4e2a3821c"
	memoryConsolidationV38DocumentsRoutineMD5            = "d2d9593918a866b633499a2619609ce3"
	memoryConsolidationV35DocumentsRoutineMD5            = "578fc76b7dd1ed66ccdd7895cd50e07c"
	memoryConsolidationV36DocumentsRoutineMD5            = "8eac22d68c0b50c43de1f8892c925c55"
	memoryConsolidationV33ClaimRoutineMD5                = "32e95c7fb6a9e73522c73b825bc3dcea"
	memoryConsolidationV33AdvanceRoutineMD5              = "cce038c3cca8f3c4f48da8b5e155443c"
)
