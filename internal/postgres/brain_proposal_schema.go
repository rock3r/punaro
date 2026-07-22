package postgres

import "context"

// memoryProposalControlsAvailable verifies the exact schema-v18 proposal authority.
func memoryProposalControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('brain.memory_proposals') AS proposals_oid,
           to_regclass('brain.memory_proposal_steps') AS steps_oid,
           to_regclass('brain.memory_proposal_evidence') AS evidence_oid,
           to_regclass('brain.memory_proposal_results') AS results_oid,
           to_regclass('brain.memory_proposals_scope_state') AS scope_state_oid,
           to_regclass('brain.memory_proposal_steps_target') AS step_target_oid,
	       to_regclass('brain.memory_proposal_steps_create_key') AS step_create_key_oid,
           to_regclass('brain.memory_proposal_evidence_revision') AS evidence_revision_oid,
           to_regclass('brain.memory_proposal_results_item_revision') AS results_revision_oid,
           to_regprocedure('brain.guard_memory_proposal_update()') AS guard_oid,
           to_regprocedure('brain.guard_memory_proposal_child_insert()') AS child_guard_oid,
           to_regprocedure('brain.guard_memory_proposal_result_insert()') AS result_guard_oid,
           to_regprocedure('brain.guard_memory_proposal_results_complete()') AS complete_guard_oid,
           to_regprocedure('brain.prune_memory_proposals(uuid,uuid,uuid,timestamp with time zone,integer)') AS prune_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), expected_columns(relation_name,column_name,ordinal_position,data_type,not_null,default_expression) AS (
    VALUES
      ('brain.memory_proposals','id',1,'uuid',true,'gen_random_uuid()'),
      ('brain.memory_proposals','scope_id',2,'uuid',true,''),
      ('brain.memory_proposals','action',3,'text',true,''),
      ('brain.memory_proposals','state',4,'text',true,'''pending''::text'),
      ('brain.memory_proposals','proposed_by',5,'uuid',true,''),
      ('brain.memory_proposals','decided_by',6,'uuid',false,''),
      ('brain.memory_proposals','created_at',7,'timestamp with time zone',true,'transaction_timestamp()'),
      ('brain.memory_proposals','decided_at',8,'timestamp with time zone',false,''),
      ('brain.memory_proposals','payload_sha256',9,'bytea',true,''),
      ('brain.memory_proposals','payload',10,'bytea',true,''),
      ('brain.memory_proposals','assembly_xid',11,'xid8',true,'pg_current_xact_id()'),
      ('brain.memory_proposals','decided_xid',12,'xid8',false,''),
      ('brain.memory_proposals','expires_at',13,'timestamp with time zone',true,'(statement_timestamp() + ''7 days''::interval)'),
      ('brain.memory_proposal_steps','proposal_id',1,'uuid',true,''),
      ('brain.memory_proposal_steps','ordinal',2,'smallint',true,''),
      ('brain.memory_proposal_steps','operation',3,'text',true,''),
      ('brain.memory_proposal_steps','item_id',4,'uuid',false,''),
      ('brain.memory_proposal_steps','target_revision',5,'bigint',false,''),
      ('brain.memory_proposal_steps','logical_key',6,'text',false,''),
      ('brain.memory_proposal_steps','kind',7,'text',false,''),
      ('brain.memory_proposal_steps','trust',8,'text',false,''),
      ('brain.memory_proposal_steps','document',9,'bytea',false,''),
      ('brain.memory_proposal_steps','archived',10,'boolean',false,''),
      ('brain.memory_proposal_evidence','proposal_id',1,'uuid',true,''),
      ('brain.memory_proposal_evidence','ordinal',2,'smallint',true,''),
      ('brain.memory_proposal_evidence','item_id',3,'uuid',true,''),
      ('brain.memory_proposal_evidence','revision',4,'bigint',true,''),
      ('brain.memory_proposal_results','proposal_id',1,'uuid',true,''),
      ('brain.memory_proposal_results','ordinal',2,'smallint',true,''),
      ('brain.memory_proposal_results','item_id',3,'uuid',true,''),
      ('brain.memory_proposal_results','revision',4,'bigint',true,'')
), actual_columns AS (
    SELECT relation.oid::regclass::text,attribute.attname,attribute.attnum::integer,
           format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,
           COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_class AS relation
    JOIN objects ON relation.oid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid])
    JOIN pg_attribute AS attribute ON attribute.attrelid=relation.oid AND attribute.attnum>0 AND NOT attribute.attisdropped
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
), expected_relational_constraints(relation_name,constraint_name,constraint_type,column_keys,referenced_relation,referenced_keys,update_action,delete_action,match_type) AS (
    VALUES
      ('brain.memory_proposals','memory_proposals_pkey','p','{1}','','','','',''),
      ('brain.memory_proposals','memory_proposals_scope_id_fkey','f','{2}','brain.scopes','{1}','a','a','s'),
      ('brain.memory_proposals','memory_proposals_proposed_by_fkey','f','{5}','auth.principals','{1}','a','a','s'),
      ('brain.memory_proposals','memory_proposals_decided_by_fkey','f','{6}','auth.principals','{1}','a','a','s'),
      ('brain.memory_proposal_steps','memory_proposal_steps_proposal_id_fkey','f','{1}','brain.memory_proposals','{1}','a','c','s'),
      ('brain.memory_proposal_steps','memory_proposal_steps_pkey','p','{1,2}','','','','',''),
      ('brain.memory_proposal_evidence','memory_proposal_evidence_proposal_id_fkey','f','{1}','brain.memory_proposals','{1}','a','c','s'),
      ('brain.memory_proposal_evidence','memory_proposal_evidence_pkey','p','{1,2}','','','','',''),
      ('brain.memory_proposal_evidence','memory_proposal_evidence_exact_key','u','{1,3}','','','','',''),
      ('brain.memory_proposal_results','memory_proposal_results_pkey','p','{1,2}','','','','',''),
      ('brain.memory_proposal_results','memory_proposal_results_item_key','u','{1,3}','','','','',''),
      ('brain.memory_proposal_results','memory_proposal_results_step_fkey','f','{1,2}','brain.memory_proposal_steps','{1,2}','a','c','s')
), actual_relational_constraints AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,constraint_row.contype::text,constraint_row.conkey::text,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confrelid::regclass::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confkey::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confupdtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confdeltype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confmatchtype::text ELSE '' END
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid]) AND constraint_row.contype IN ('p','u','f')
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), expected_checks(relation_name,constraint_name,expression) AS (
    VALUES
      ('brain.memory_proposals','memory_proposals_action_check','(action = ANY (ARRAY[''create''::text, ''update''::text, ''archive''::text, ''merge''::text, ''split''::text]))'),
      ('brain.memory_proposals','memory_proposals_state_check','(state = ANY (ARRAY[''pending''::text, ''approved''::text, ''rejected''::text, ''expired''::text]))'),
      ('brain.memory_proposals','memory_proposals_decision_check','(((state = ''pending''::text) AND (decided_by IS NULL) AND (decided_at IS NULL) AND (decided_xid IS NULL)) OR ((state = ANY (ARRAY[''approved''::text, ''rejected''::text])) AND (decided_by IS NOT NULL) AND (decided_at IS NOT NULL) AND (decided_at >= created_at) AND (decided_xid IS NOT NULL)) OR ((state = ''expired''::text) AND (decided_by IS NULL) AND (decided_at = expires_at) AND (decided_xid IS NOT NULL)))'),
      ('brain.memory_proposals','memory_proposals_payload_sha256_check','(octet_length(payload_sha256) = 32)'),
      ('brain.memory_proposals','memory_proposals_payload_check','((octet_length(payload) >= 2) AND (octet_length(payload) <= 4194304))'),
      ('brain.memory_proposals','memory_proposals_expiry_check','(expires_at > created_at)'),
      ('brain.memory_proposal_steps','memory_proposal_steps_ordinal_check','((ordinal >= 0) AND (ordinal <= 7))'),
      ('brain.memory_proposal_steps','memory_proposal_steps_operation_check','(operation = ANY (ARRAY[''create''::text, ''update''::text, ''archive''::text]))'),
      ('brain.memory_proposal_steps','memory_proposal_steps_target_revision_check','((target_revision IS NULL) OR (target_revision >= 1))'),
      ('brain.memory_proposal_steps','memory_proposal_steps_logical_key_check','((logical_key IS NULL) OR (((char_length(logical_key) >= 1) AND (char_length(logical_key) <= 128)) AND (octet_length(logical_key) <= 512) AND (logical_key !~ ''[[:cntrl:]]''::text)))'),
      ('brain.memory_proposal_steps','memory_proposal_steps_kind_check','((kind IS NULL) OR (kind ~ ''^[a-z][a-z0-9_.:-]{0,63}$''::text))'),
      ('brain.memory_proposal_steps','memory_proposal_steps_trust_check','((trust IS NULL) OR (trust ~ ''^[a-z][a-z0-9_.:-]{0,63}$''::text))'),
      ('brain.memory_proposal_steps','memory_proposal_steps_document_check','((document IS NULL) OR ((jsonb_typeof((convert_from(document, ''UTF8''::name))::jsonb) = ''object''::text) AND (octet_length(document) <= 262144)))'),
      ('brain.memory_proposal_steps','memory_proposal_steps_shape_check','(((operation = ''create''::text) AND (item_id IS NULL) AND (target_revision IS NULL) AND (kind IS NOT NULL) AND (trust IS NOT NULL) AND (document IS NOT NULL) AND (archived IS NULL)) OR ((operation = ''update''::text) AND (item_id IS NOT NULL) AND (target_revision IS NOT NULL) AND (kind IS NOT NULL) AND (trust IS NOT NULL) AND (document IS NOT NULL) AND (archived IS NULL)) OR ((operation = ''archive''::text) AND (item_id IS NOT NULL) AND (target_revision IS NOT NULL) AND (logical_key IS NULL) AND (kind IS NULL) AND (trust IS NULL) AND (document IS NULL) AND (archived IS NOT NULL)))'),
      ('brain.memory_proposal_evidence','memory_proposal_evidence_ordinal_check','((ordinal >= 0) AND (ordinal <= 15))'),
      ('brain.memory_proposal_evidence','memory_proposal_evidence_revision_check','(revision >= 1)'),
      ('brain.memory_proposal_results','memory_proposal_results_revision_check','(revision >= 1)')
), actual_checks AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,
           CASE
             WHEN constraint_row.conname='memory_proposal_steps_logical_key_check'
              AND pg_get_expr(constraint_row.conbin,constraint_row.conrelid)='((logical_key IS NULL) OR ((char_length(logical_key) >= 1) AND (char_length(logical_key) <= 128) AND (octet_length(logical_key) <= 512) AND (logical_key !~ ''[[:cntrl:]]''::text)))'
             THEN '((logical_key IS NULL) OR (((char_length(logical_key) >= 1) AND (char_length(logical_key) <= 128)) AND (octet_length(logical_key) <= 512) AND (logical_key !~ ''[[:cntrl:]]''::text)))'
             ELSE pg_get_expr(constraint_row.conbin,constraint_row.conrelid)
           END
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid]) AND constraint_row.contype='c'
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), table_safety AS (
    SELECT count(*)=4 AND bool_and(relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity
        AND NOT relation.relforcerowsecurity AND pg_get_userbyid(relation.relowner)='punaro_owner') AS exact
    FROM pg_class AS relation,objects WHERE relation.oid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid])
), constraint_safety AS (
    SELECT count(*)=29 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred) AS exact
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid]) AND constraint_row.contype IN ('p','u','f','c')
), index_safety AS (
    SELECT count(*)=11 AND bool_and(index_row.indisvalid AND index_row.indisready) AS exact
    FROM pg_index AS index_row,objects WHERE index_row.indrelid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid])
), expected_table_acl(relation_name,grantee,privilege_type,is_grantable) AS (
    SELECT relation_name,'punaro_owner',privilege_type,false
    FROM (VALUES ('brain.memory_proposals'),('brain.memory_proposal_steps'),('brain.memory_proposal_evidence'),('brain.memory_proposal_results')) AS relations(relation_name)
    CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) AS privileges(privilege_type)
    UNION ALL
    SELECT relation_name,'punaro_app','SELECT',false
    FROM (VALUES ('brain.memory_proposals'),('brain.memory_proposal_steps'),('brain.memory_proposal_evidence'),('brain.memory_proposal_results')) AS relations(relation_name)
), actual_table_acl AS (
    SELECT relation.oid::regclass::text,COALESCE(grantee.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee,objects
    WHERE relation.oid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid])
), expected_column_acl(relation_name,column_name,grantee,privilege_type,is_grantable) AS (
    VALUES
      ('brain.memory_proposals','scope_id','punaro_app','INSERT',false),('brain.memory_proposals','action','punaro_app','INSERT',false),('brain.memory_proposals','proposed_by','punaro_app','INSERT',false),('brain.memory_proposals','payload_sha256','punaro_app','INSERT',false),('brain.memory_proposals','payload','punaro_app','INSERT',false),
      ('brain.memory_proposals','state','punaro_app','UPDATE',false),('brain.memory_proposals','decided_by','punaro_app','UPDATE',false),('brain.memory_proposals','decided_at','punaro_app','UPDATE',false),('brain.memory_proposals','decided_xid','punaro_app','UPDATE',false),
      ('brain.memory_proposal_steps','proposal_id','punaro_app','INSERT',false),('brain.memory_proposal_steps','ordinal','punaro_app','INSERT',false),('brain.memory_proposal_steps','operation','punaro_app','INSERT',false),
      ('brain.memory_proposal_steps','item_id','punaro_app','INSERT',false),('brain.memory_proposal_steps','target_revision','punaro_app','INSERT',false),('brain.memory_proposal_steps','logical_key','punaro_app','INSERT',false),
      ('brain.memory_proposal_steps','kind','punaro_app','INSERT',false),('brain.memory_proposal_steps','trust','punaro_app','INSERT',false),('brain.memory_proposal_steps','document','punaro_app','INSERT',false),('brain.memory_proposal_steps','archived','punaro_app','INSERT',false),
      ('brain.memory_proposal_evidence','proposal_id','punaro_app','INSERT',false),('brain.memory_proposal_evidence','ordinal','punaro_app','INSERT',false),('brain.memory_proposal_evidence','item_id','punaro_app','INSERT',false),('brain.memory_proposal_evidence','revision','punaro_app','INSERT',false),
      ('brain.memory_proposal_results','proposal_id','punaro_app','INSERT',false),('brain.memory_proposal_results','ordinal','punaro_app','INSERT',false),('brain.memory_proposal_results','item_id','punaro_app','INSERT',false),('brain.memory_proposal_results','revision','punaro_app','INSERT',false)
), actual_column_acl AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,COALESCE(grantee.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable
    FROM pg_attribute AS attribute CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee,objects
    WHERE attribute.attrelid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid]) AND attribute.attnum>0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
), expected_routine_acl(routine_oid,grantee,privilege_type,is_grantable) AS (
    SELECT routine_oid::oid,'punaro_owner','EXECUTE',false
    FROM objects CROSS JOIN LATERAL (VALUES (guard_oid),(child_guard_oid),(result_guard_oid),(complete_guard_oid),(prune_oid)) AS routines(routine_oid)
    UNION ALL
    SELECT prune_oid::oid,'punaro_app','EXECUTE',false FROM objects
), actual_routine_acl AS (
    SELECT proc.oid,COALESCE(grantee.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee,objects
    WHERE proc.oid=ANY(ARRAY[guard_oid,child_guard_oid,result_guard_oid,complete_guard_oid,prune_oid])
)
SELECT proposals_oid IS NOT NULL AND steps_oid IS NOT NULL AND evidence_oid IS NOT NULL AND results_oid IS NOT NULL
   AND scope_state_oid IS NOT NULL AND step_target_oid IS NOT NULL AND step_create_key_oid IS NOT NULL AND evidence_revision_oid IS NOT NULL AND results_revision_oid IS NOT NULL
   AND guard_oid IS NOT NULL AND child_guard_oid IS NOT NULL AND result_guard_oid IS NOT NULL AND complete_guard_oid IS NOT NULL AND prune_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND index_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_relational_constraints EXCEPT SELECT * FROM actual_relational_constraints)
   AND NOT EXISTS (SELECT * FROM actual_relational_constraints EXCEPT SELECT * FROM expected_relational_constraints)
   AND NOT EXISTS (SELECT * FROM expected_checks EXCEPT SELECT * FROM actual_checks)
   AND NOT EXISTS (SELECT * FROM actual_checks EXCEPT SELECT * FROM expected_checks)
   AND NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
   AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)
   AND NOT EXISTS (SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl)
   AND NOT EXISTS (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl)
   AND NOT EXISTS (SELECT * FROM expected_routine_acl EXCEPT SELECT * FROM actual_routine_acl)
   AND NOT EXISTS (SELECT * FROM actual_routine_acl EXCEPT SELECT * FROM expected_routine_acl)
   AND (SELECT count(*)=11 AND bool_and(
          CASE index_row.indexrelid
            WHEN scope_state_oid THEN NOT index_row.indisunique AND index_row.indnkeyatts=4 AND index_row.indkey='2 4 7 1'::int2vector AND index_row.indexprs IS NULL AND index_row.indpred IS NULL
            WHEN step_target_oid THEN index_row.indisunique AND index_row.indnkeyatts=2 AND index_row.indkey='1 4'::int2vector AND index_row.indexprs IS NULL AND pg_get_expr(index_row.indpred,index_row.indrelid)='(item_id IS NOT NULL)'
	        WHEN step_create_key_oid THEN index_row.indisunique AND index_row.indnkeyatts=2 AND index_row.indkey='1 6'::int2vector AND index_row.indexprs IS NULL AND pg_get_expr(index_row.indpred,index_row.indrelid)='((operation = ''create''::text) AND (logical_key IS NOT NULL))'
            WHEN evidence_revision_oid THEN NOT index_row.indisunique AND index_row.indnkeyatts=3 AND index_row.indkey='3 4 1'::int2vector AND index_row.indexprs IS NULL AND index_row.indpred IS NULL
            WHEN results_revision_oid THEN NOT index_row.indisunique AND index_row.indnkeyatts=3 AND index_row.indkey='3 4 1'::int2vector AND index_row.indexprs IS NULL AND index_row.indpred IS NULL
            ELSE index_row.indisunique AND index_row.indexprs IS NULL AND index_row.indpred IS NULL
          END)
        FROM pg_index AS index_row,objects WHERE index_row.indrelid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid]))
   AND (SELECT count(*)=4 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner' AND NOT proc.prosecdef AND proc.prokind='f'
          AND proc.provolatile='v' AND NOT proc.proretset AND proc.prorettype='trigger'::regtype AND proc.pronargs=0
          AND NOT proc.proisstrict AND NOT proc.proleakproof AND proc.proparallel='u'
          AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
          AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
          AND ((proc.oid=guard_oid AND md5(btrim(proc.prosrc,E' \n\r\t'))='f9c3eccbdb715b4ff0f8429948a0a8d1')
            OR (proc.oid=child_guard_oid AND md5(btrim(proc.prosrc,E' \n\r\t'))='94cc11906346e8ab340b449aacd09262')
            OR (proc.oid=result_guard_oid AND md5(btrim(proc.prosrc,E' \n\r\t'))='f075be9604c87bc897dd9ecdce849e28')
            OR (proc.oid=complete_guard_oid AND md5(btrim(proc.prosrc,E' \n\r\t'))='5131d49b7467b60cbb27b9fde5c2e4d6'))) AS exact
        FROM pg_proc AS proc,objects WHERE proc.oid=ANY(ARRAY[guard_oid,child_guard_oid,result_guard_oid,complete_guard_oid]))
   AND (SELECT pg_get_userbyid(proc.proowner)='punaro_owner' AND proc.prosecdef AND proc.prokind='f'
          AND proc.provolatile='v' AND NOT proc.proretset AND proc.prorettype='integer'::regtype AND proc.pronargs=5
          AND proc.proargtypes='2950 2950 2950 1184 23'::oidvector AND NOT proc.proisstrict AND NOT proc.proleakproof AND proc.proparallel='u'
          AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
          AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
          AND md5(btrim(proc.prosrc,E' \n\r\t'))='fdfdd2c25be431506219685458c84ef6'
        FROM pg_proc AS proc,objects WHERE proc.oid=prune_oid)
   AND (SELECT count(*)=4 AND bool_and(trigger_row.tgenabled='O' AND trigger_row.tgfoid=fence_oid AND trigger_row.tgtype=62 AND trigger_row.tgqual IS NULL)
        FROM pg_trigger AS trigger_row,objects WHERE trigger_row.tgrelid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid]) AND trigger_row.tgname='application_mutation_fence' AND NOT trigger_row.tgisinternal)
   AND EXISTS (SELECT 1 FROM pg_trigger AS trigger_row WHERE trigger_row.tgrelid=proposals_oid AND trigger_row.tgname='memory_proposal_transition_guard'
        AND trigger_row.tgenabled='O' AND trigger_row.tgfoid=guard_oid AND trigger_row.tgtype=19 AND trigger_row.tgattr=''::int2vector AND trigger_row.tgqual IS NULL AND NOT trigger_row.tgisinternal)
   AND EXISTS (SELECT 1 FROM pg_trigger AS trigger_row WHERE trigger_row.tgrelid=steps_oid AND trigger_row.tgname='memory_proposal_step_insert_guard' AND trigger_row.tgenabled='O' AND trigger_row.tgfoid=child_guard_oid AND trigger_row.tgtype=7 AND trigger_row.tgattr=''::int2vector AND trigger_row.tgqual IS NULL AND NOT trigger_row.tgisinternal)
   AND EXISTS (SELECT 1 FROM pg_trigger AS trigger_row WHERE trigger_row.tgrelid=evidence_oid AND trigger_row.tgname='memory_proposal_evidence_insert_guard' AND trigger_row.tgenabled='O' AND trigger_row.tgfoid=child_guard_oid AND trigger_row.tgtype=7 AND trigger_row.tgattr=''::int2vector AND trigger_row.tgqual IS NULL AND NOT trigger_row.tgisinternal)
   AND EXISTS (SELECT 1 FROM pg_trigger AS trigger_row WHERE trigger_row.tgrelid=results_oid AND trigger_row.tgname='memory_proposal_result_insert_guard'
        AND trigger_row.tgenabled='O' AND trigger_row.tgfoid=result_guard_oid AND trigger_row.tgtype=7 AND trigger_row.tgattr=''::int2vector AND trigger_row.tgqual IS NULL AND NOT trigger_row.tgisinternal)
   AND EXISTS (SELECT 1 FROM pg_trigger AS trigger_row WHERE trigger_row.tgrelid=proposals_oid AND trigger_row.tgname='memory_proposal_results_complete'
        AND trigger_row.tgenabled='O' AND trigger_row.tgfoid=complete_guard_oid AND trigger_row.tgtype=17 AND trigger_row.tgattr='4'::int2vector AND trigger_row.tgqual IS NULL AND trigger_row.tgdeferrable AND trigger_row.tginitdeferred AND NOT trigger_row.tgisinternal)
   AND (SELECT count(*)=9 FROM pg_trigger AS trigger_row,objects WHERE trigger_row.tgrelid=ANY(ARRAY[proposals_oid,steps_oid,evidence_oid,results_oid]) AND NOT trigger_row.tgisinternal)
FROM objects,table_safety,constraint_safety,index_safety`).Scan(&available)
	return available, err
}
