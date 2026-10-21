BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SET LOCAL lock_timeout='1s';
SET LOCAL search_path=pg_catalog,public;
WITH batch AS (
 SELECT started_at FROM public.fetch_runs
 WHERE started_at >= to_timestamp(__LOWER_EPOCH__) AND started_at < to_timestamp(__UPPER_EPOCH__ + 1)
 GROUP BY started_at
 HAVING count(1)=3 AND count(DISTINCT source_id)=3
 AND bool_and(coalesce(status='ok' AND new_count=1
 AND detail @> '{"collectOnly":true,"processed":1,"revised":0}'::jsonb
 AND found_count=CASE source_id WHEN 'collect-accounting-today' THEN 10
 WHEN 'collect-dynamics-finance' THEN 10 WHEN 'collect-journal-accountancy' THEN 20 ELSE -1 END,false))
), items AS (
 SELECT a.id,a.source_id,a.title,s.name AS source_name,a.url AS original_url,
 a.published_at,a.discovered_at AS collected_at,coalesce(a.excerpt,'') AS summary
 FROM public.articles a JOIN public.sources s ON s.id=a.source_id
 WHERE a.created_at=(SELECT min(started_at) FROM batch)
 AND a.source_id IN ('collect-accounting-today','collect-dynamics-finance','collect-journal-accountancy')
 AND a.collect_only AND a.processing_state='skipped' AND a.revision=1
 AND NOT s.enabled AND s.collect_only AND s.participation_mode='isolated'
 AND octet_length(a.title)<=4000 AND octet_length(s.name)<=800
 AND octet_length(a.url)<=8192 AND octet_length(coalesce(a.excerpt,''))<=24000
)
SELECT CASE WHEN (SELECT count(1) FROM batch)=1 AND (SELECT count(1) FROM items)=3
 AND (SELECT count(1) FROM public.articles WHERE created_at=(SELECT min(started_at) FROM batch))=3
 AND (SELECT count(DISTINCT source_id) FROM items)=3
 AND current_user='postgres' AND current_database()='aifinance_preview'
 THEN jsonb_build_object('schema_version',1,'batch_id','retry-002',
 'collection_status','matched_retry_002','exported_at',CURRENT_TIMESTAMP,
 'articles',(SELECT jsonb_agg(to_jsonb(i) ORDER BY source_id) FROM items i))
 ELSE jsonb_build_object('refused',true) END;
ROLLBACK;
