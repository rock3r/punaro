ALTER TABLE relay.mail_deliveries
    ADD COLUMN closed_reason text;

UPDATE relay.mail_deliveries
SET closed_reason = 'acked'
WHERE acked_at IS NOT NULL AND closed_reason IS NULL;

ALTER TABLE relay.mail_deliveries
    ADD CONSTRAINT mail_deliveries_closed_reason_check
        CHECK (closed_reason IS NULL OR closed_reason IN ('acked', 'expired', 'revoked')),
    ADD CONSTRAINT mail_deliveries_closed_state_check
        CHECK ((acked_at IS NULL) = (closed_reason IS NULL));

GRANT UPDATE (closed_reason) ON relay.mail_deliveries TO punaro_app;

CREATE FUNCTION relay.prune_mail_terminal(p_before timestamptz, p_limit integer)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    deleted_count bigint;
BEGIN
    IF p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid terminal prune limit';
    END IF;
    WITH candidates AS (
        SELECT id FROM relay.mail_deliveries
        WHERE acked_at IS NOT NULL AND acked_at <= p_before
        ORDER BY acked_at, id
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM relay.mail_deliveries AS delivery
    USING candidates
    WHERE delivery.id = candidates.id;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END
$function$;

REVOKE ALL ON FUNCTION relay.prune_mail_terminal(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION relay.prune_mail_terminal(timestamptz, integer) TO punaro_app;
