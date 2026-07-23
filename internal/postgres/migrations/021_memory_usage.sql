CREATE TABLE brain.memory_usage (
    item_id uuid PRIMARY KEY REFERENCES brain.memory_items(id) ON DELETE CASCADE,
    recall_count bigint NOT NULL,
    last_recalled_at timestamptz NOT NULL,
    CONSTRAINT memory_usage_recall_count_check CHECK (recall_count >= 0)
);

CREATE INDEX memory_usage_last_recalled
ON brain.memory_usage (last_recalled_at, item_id);

CREATE TRIGGER application_mutation_fence
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON brain.memory_usage
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();

CREATE FUNCTION brain.record_memory_recall(requested_project uuid, requested_items uuid[])
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF requested_project IS NULL OR cardinality(requested_items) < 1 OR cardinality(requested_items) > 64
       OR EXISTS (SELECT 1 FROM unnest(requested_items) AS requested_item(item_id) WHERE item_id IS NULL) THEN
        RAISE EXCEPTION 'invalid memory recall batch' USING ERRCODE = '22023';
    END IF;

    WITH requested AS (
        SELECT DISTINCT item_id
        FROM unnest(requested_items) AS requested_item(item_id)
    ), eligible AS (
        SELECT item.id
        FROM requested
        JOIN brain.memory_items AS item ON item.id=requested.item_id
        JOIN brain.scopes AS scope ON scope.id=item.scope_id
        LEFT JOIN relay.project_lookup_aliases AS alias ON alias.alias_project_id=scope.project_id
        WHERE item.state='active'
          AND COALESCE(alias.canonical_project_id,scope.project_id)=requested_project
    )
    INSERT INTO brain.memory_usage(item_id,recall_count,last_recalled_at)
    SELECT id,1,statement_timestamp() FROM eligible
    ON CONFLICT (item_id) DO UPDATE
    SET recall_count = CASE
            WHEN brain.memory_usage.recall_count = 9223372036854775807 THEN brain.memory_usage.recall_count
            ELSE brain.memory_usage.recall_count + 1
        END,
        last_recalled_at = GREATEST(brain.memory_usage.last_recalled_at,statement_timestamp());

    RETURN;
END
$$;

REVOKE ALL ON brain.memory_usage FROM PUBLIC, punaro_app;
GRANT SELECT ON brain.memory_usage TO punaro_app;

REVOKE ALL ON FUNCTION brain.record_memory_recall(uuid,uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.record_memory_recall(uuid,uuid[]) TO punaro_app;
