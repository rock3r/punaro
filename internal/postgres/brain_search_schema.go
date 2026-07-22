package postgres

import "context"

// memoryLexicalControlsAvailable verifies the schema-v19 synchronous lexical
// projection and its exact title and GIN access paths.
func memoryLexicalControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
	SELECT to_regclass('brain.memory_revisions') AS revisions_oid,
	       to_regclass('brain.memory_revisions_search_vector') AS vector_index_oid,
	       to_regclass('brain.memory_revisions_search_title') AS title_index_oid
), search_column AS (
    SELECT attribute.attrelid,attribute.attnum,attribute.attnotnull,attribute.attgenerated,
           attribute.atttypid,attribute.attacl,pg_get_expr(default_value.adbin,default_value.adrelid) AS expression
    FROM pg_attribute AS attribute
    JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum,
         objects
	WHERE attribute.attrelid=revisions_oid AND attribute.attname='search_vector'
	  AND attribute.attnum>0 AND NOT attribute.attisdropped
), title_column AS (
	SELECT attribute.attrelid,attribute.attnum,attribute.attnotnull,attribute.attgenerated,
	       attribute.atttypid,attribute.attacl,pg_get_expr(default_value.adbin,default_value.adrelid) AS expression
	FROM pg_attribute AS attribute
	JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum,
	     objects
	WHERE attribute.attrelid=revisions_oid AND attribute.attname='search_title'
	  AND attribute.attnum>0 AND NOT attribute.attisdropped
), index_control AS (
    SELECT index_row.*,index_relation.relowner,index_relation.relam,access_method.amname,
           operator_class.opcname,operator_class.opcmethod
    FROM pg_index AS index_row
    JOIN pg_class AS index_relation ON index_relation.oid=index_row.indexrelid
    JOIN pg_am AS access_method ON access_method.oid=index_relation.relam
    JOIN pg_opclass AS operator_class ON operator_class.oid=index_row.indclass[0],objects
	WHERE index_row.indexrelid=ANY(ARRAY[vector_index_oid,title_index_oid]) AND index_row.indrelid=revisions_oid
)
SELECT revisions_oid IS NOT NULL AND vector_index_oid IS NOT NULL AND title_index_oid IS NOT NULL
   AND (SELECT count(*)=1 AND bool_and(
          attnotnull AND attgenerated='s' AND atttypid='tsvector'::regtype AND attacl IS NULL
		  AND md5(regexp_replace(expression,'[[:space:]]','','g'))='2a3dd873e4c6624ccd29f6433e109f20'
		) FROM search_column)
	AND (SELECT count(*)=1 AND bool_and(
	       attnotnull AND attgenerated='s' AND atttypid='text'::regtype AND attacl IS NULL
	       AND md5(regexp_replace(expression,'[[:space:]]','','g'))='36a962c507379702bc8da55727a41e19'
	     ) FROM title_column)
	AND (SELECT count(*)=2 AND bool_and(
	       indisvalid AND indisready AND NOT indisunique AND indnkeyatts=1 AND indnatts=1
	       AND indexprs IS NULL
	       AND opcmethod=relam AND pg_get_userbyid(relowner)='punaro_owner'
	       AND CASE indexrelid
	         WHEN vector_index_oid THEN indkey=(SELECT attnum::text::int2vector FROM search_column) AND amname='gin' AND opcname='tsvector_ops' AND indpred IS NULL
	         WHEN title_index_oid THEN indkey=(SELECT attnum::text::int2vector FROM title_column) AND amname='btree' AND opcname='text_ops'
	           AND pg_get_expr(indpred,indrelid)='(octet_length(search_title) <= 1024)'
	         ELSE false
	       END
	     ) FROM index_control)
FROM objects`).Scan(&available)
	return available, err
}
