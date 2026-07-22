DO $block$
DECLARE
    existing_revisions bigint;
    existing_document_bytes bigint;
	document_bytes bigint;
BEGIN
	existing_revisions := 0;
	existing_document_bytes := 0;
	FOR document_bytes IN
		SELECT octet_length(document::text)
		FROM brain.memory_revisions
		ORDER BY item_id,revision
	LOOP
		existing_revisions := existing_revisions + 1;
		existing_document_bytes := existing_document_bytes + document_bytes;
		IF existing_revisions > 100000 OR existing_document_bytes > 268435456 THEN
			RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'memory lexical migration exceeds the inline migration ceiling';
		END IF;
	END LOOP;
END
$block$;

ALTER TABLE brain.memory_revisions
ADD COLUMN search_title text GENERATED ALWAYS AS (
	CASE WHEN jsonb_typeof(document -> 'title') = 'string' THEN document ->> 'title' ELSE '' END
) STORED NOT NULL,
ADD COLUMN search_vector tsvector GENERATED ALWAYS AS (
    setweight(to_tsvector('simple'::regconfig,
        CASE WHEN jsonb_typeof(document -> 'title') = 'string' THEN document ->> 'title' ELSE '' END), 'A')
    || setweight(to_tsvector('simple'::regconfig,
        CASE WHEN jsonb_typeof(document -> 'summary') = 'string' THEN document ->> 'summary' ELSE '' END), 'B')
    || setweight(to_tsvector('simple'::regconfig,
        CASE WHEN jsonb_typeof(document -> 'keywords') IN ('string', 'array') THEN document ->> 'keywords' ELSE '' END), 'C')
    || setweight(to_tsvector('simple'::regconfig,
        CASE WHEN jsonb_typeof(document -> 'body') = 'string' THEN document ->> 'body' ELSE '' END), 'D')
) STORED NOT NULL;

CREATE INDEX memory_revisions_search_title
ON brain.memory_revisions (search_title)
WHERE octet_length(search_title) <= 1024;

CREATE INDEX memory_revisions_search_vector
ON brain.memory_revisions USING gin (search_vector);
