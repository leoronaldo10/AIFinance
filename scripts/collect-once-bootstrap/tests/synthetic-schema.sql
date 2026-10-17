CREATE TABLE sources (
  id                  text PRIMARY KEY,
  name                text NOT NULL,
  kind                text NOT NULL CHECK (kind IN ('rss', 'web_list', 'json_list', 'x_search', 'mp_account', 'external')),
  config              jsonb NOT NULL DEFAULT '{}',
  tags                text[] NOT NULL DEFAULT '{}',
  first_party         boolean NOT NULL DEFAULT false,
  owner_entity_id     text,
  tier                text NOT NULL DEFAULT 'T2' CHECK (tier IN ('T1', 'T1_5', 'T2', 'EXCLUDE_MP')),
  participation_mode  text NOT NULL DEFAULT 'editorial' CHECK (participation_mode IN ('editorial', 'hot_signal', 'isolated')),
  signal_group_id     text,
  interval_minutes    integer NOT NULL DEFAULT 30 CHECK (interval_minutes BETWEEN 1 AND 1440),
  -- Two separate licences: showing full text on this site, and redistributing it (full RSS).
  site_fulltext       boolean NOT NULL DEFAULT true,
  syndicate_fulltext  boolean NOT NULL DEFAULT false,
  enabled             boolean NOT NULL DEFAULT true,
  health              text NOT NULL DEFAULT 'unknown' CHECK (health IN ('ok', 'degraded', 'failing', 'paused', 'unknown')),
  fail_count          integer NOT NULL DEFAULT 0,
  last_fetch_at       timestamptz,
  last_ok_at          timestamptz,
  last_error          text,
  -- Successful collection position; never advanced by a failed fetch.
  cursor              jsonb,
  next_fetch_at       timestamptz,
  icon_url            text,
  imported_from       text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sources_due_idx ON sources (next_fetch_at) WHERE enabled;

CREATE TABLE fetch_runs (
  id            bigserial PRIMARY KEY,
  source_id     text NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
  started_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  status        text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'ok', 'failed', 'skipped')),
  found_count   integer NOT NULL DEFAULT 0,
  new_count     integer NOT NULL DEFAULT 0,
  error         text,
  detail        jsonb
);

CREATE INDEX fetch_runs_source_idx ON fetch_runs (source_id, started_at DESC);

-- ---------------------------------------------------------------------------
-- Articles (one per real-world material) and their revisions
-- ---------------------------------------------------------------------------

CREATE TABLE articles (
  id                 text PRIMARY KEY CHECK (id ~ '^[a-zA-Z0-9_-]{1,80}$'),
  source_id          text NOT NULL REFERENCES sources (id),
  identity_key       text NOT NULL UNIQUE,
  url                text NOT NULL,
  title              text NOT NULL,
  author             text,
  language           text,
  -- Trusted source publication time; null when unknown or claimed >1h in the future.
  published_at       timestamptz,
  published_at_claim timestamptz,
  discovered_at      timestamptz NOT NULL,
  source_updated_at  timestamptz,
  -- Timeline sort value: discovery time, or source time for archived backfill.
  timeline_at        timestamptz NOT NULL,
  backfill           boolean NOT NULL DEFAULT false,
  backfill_reason    text,
  revision           integer NOT NULL DEFAULT 1,
  content_hash       text,
  excerpt            text,
  body_text          text,
  body_html          text,
  body_status        text NOT NULL DEFAULT 'pending' CHECK (body_status IN ('pending', 'ok', 'unconfirmed', 'none')),
  media              jsonb NOT NULL DEFAULT '[]',
  x_post             jsonb,
  raw                jsonb,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX articles_source_idx ON articles (source_id, discovered_at DESC);
CREATE INDEX articles_discovered_idx ON articles (discovered_at DESC);

CREATE TABLE article_revisions (
  article_id    text NOT NULL REFERENCES articles (id) ON DELETE CASCADE,
  revision      integer NOT NULL,
  content_hash  text,
  title         text NOT NULL,
  body_text     text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (article_id, revision)
);

-- The same material found through several entrances keeps one article and many discoveries.
CREATE TABLE article_discoveries (
  article_id     text NOT NULL REFERENCES articles (id) ON DELETE CASCADE,
  source_id      text NOT NULL,
  via            text NOT NULL,
  discovered_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (article_id, source_id, via)
);

