-- Immutable copy/evidence versions; the publication pointer only moves after an explicit review.
CREATE TABLE editorial_review_state (
  article_id text PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
  current_version integer NOT NULL DEFAULT 0,
  published_version integer,
  candidate_hash text,
  withdrawn boolean NOT NULL DEFAULT false
);
CREATE TABLE editorial_versions (
  article_id text NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  version integer NOT NULL,
  copy jsonb NOT NULL,
  evidence jsonb NOT NULL,
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'rejected')),
  actor text NOT NULL,
  note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (article_id, version)
);
ALTER TABLE publications ADD COLUMN finance jsonb;
ALTER TABLE publications ADD COLUMN review_version integer;
CREATE TABLE editorial_exports (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  title text NOT NULL,
  article_versions jsonb NOT NULL,
  html text NOT NULL,
  markdown text NOT NULL,
  actor text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_url text,
  published_at timestamptz
);

-- Existing automated publications enter review on upgrade. Keep their source/analysis records.
SELECT pg_advisory_xact_lock(hashtext('selected_ledger'));
INSERT INTO selected_ledger (seq, article_id, op, payload)
SELECT coalesce((SELECT max(seq) FROM selected_ledger), 0) + row_number() OVER (ORDER BY article_id), article_id, 'remove', NULL
FROM selected_state WHERE in_set;
UPDATE selected_state s SET in_set=false, payload_hash=NULL,
  last_seq=(SELECT max(l.seq) FROM selected_ledger l WHERE l.article_id=s.article_id)
WHERE s.in_set;
UPDATE publications SET visibility='withdrawn', eligible=false, selected=false, indexable=false;
