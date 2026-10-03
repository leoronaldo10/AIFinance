-- Durable raw-material quarantine: independent of source enablement and worker restarts.
ALTER TABLE articles ADD COLUMN collect_only boolean NOT NULL DEFAULT false;
ALTER TABLE sources ADD COLUMN collect_only boolean NOT NULL DEFAULT false;
ALTER TABLE sources ADD CONSTRAINT collect_only_source_isolation CHECK (
  NOT collect_only OR (kind = 'rss' AND NOT enabled AND participation_mode = 'isolated'
    AND NOT site_fulltext AND NOT syndicate_fulltext)
);
