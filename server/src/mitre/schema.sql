CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS mitre_tactics (
  id text PRIMARY KEY,
  stix_id text UNIQUE NOT NULL,
  name text NOT NULL,
  shortname text NOT NULL,
  description text,
  deprecated boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
  id text PRIMARY KEY,
  stix_id text UNIQUE NOT NULL,
  name text NOT NULL,
  description text,
  is_subtechnique boolean NOT NULL DEFAULT false,
  parent_technique_id text REFERENCES mitre_techniques(id),
  platforms text[] NOT NULL DEFAULT '{}',
  revoked boolean NOT NULL DEFAULT false,
  deprecated boolean NOT NULL DEFAULT false,
  modified timestamptz
);

CREATE TABLE IF NOT EXISTS mitre_technique_tactics (
  technique_id text REFERENCES mitre_techniques(id) ON DELETE CASCADE,
  tactic_id text REFERENCES mitre_tactics(id) ON DELETE CASCADE,
  PRIMARY KEY (technique_id, tactic_id)
);

CREATE TABLE IF NOT EXISTS mitre_data_sources (
  id text PRIMARY KEY,
  stix_id text UNIQUE NOT NULL,
  name text NOT NULL,
  description text,
  platforms text[] NOT NULL DEFAULT '{}',
  deprecated boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS mitre_data_components (
  id text PRIMARY KEY,
  stix_id text UNIQUE NOT NULL,
  name text NOT NULL,
  description text,
  revoked boolean NOT NULL DEFAULT false,
  deprecated boolean NOT NULL DEFAULT false
);

-- General log sources MITRE lists directly against a data component (x_mitre_log_sources).
CREATE TABLE IF NOT EXISTS mitre_data_component_log_sources (
  id serial PRIMARY KEY,
  data_component_id text REFERENCES mitre_data_components(id) ON DELETE CASCADE,
  log_source_name text NOT NULL,
  channel text
);

CREATE TABLE IF NOT EXISTS mitre_analytics (
  id text PRIMARY KEY,
  stix_id text UNIQUE NOT NULL,
  name text NOT NULL,
  description text,
  platforms text[] NOT NULL DEFAULT '{}',
  deprecated boolean NOT NULL DEFAULT false
);

-- Specific (data component, log source, channel/condition) triples an analytic actually keys on.
CREATE TABLE IF NOT EXISTS mitre_analytic_log_sources (
  id serial PRIMARY KEY,
  analytic_id text REFERENCES mitre_analytics(id) ON DELETE CASCADE,
  data_component_id text REFERENCES mitre_data_components(id),
  log_source_name text NOT NULL,
  channel text
);

CREATE TABLE IF NOT EXISTS mitre_detection_strategies (
  id text PRIMARY KEY,
  stix_id text UNIQUE NOT NULL,
  name text NOT NULL,
  description text,
  deprecated boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS mitre_detection_strategy_analytics (
  detection_strategy_id text REFERENCES mitre_detection_strategies(id) ON DELETE CASCADE,
  analytic_id text REFERENCES mitre_analytics(id) ON DELETE CASCADE,
  PRIMARY KEY (detection_strategy_id, analytic_id)
);

-- detection-strategy --detects--> technique (the join that turns a matched analytic into a candidate technique)
CREATE TABLE IF NOT EXISTS mitre_detects (
  detection_strategy_id text REFERENCES mitre_detection_strategies(id) ON DELETE CASCADE,
  technique_id text REFERENCES mitre_techniques(id) ON DELETE CASCADE,
  PRIMARY KEY (detection_strategy_id, technique_id)
);

CREATE INDEX IF NOT EXISTS idx_trgm_analytic_log_source ON mitre_analytic_log_sources USING gin (log_source_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_trgm_analytic_channel ON mitre_analytic_log_sources USING gin (channel gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_trgm_dc_log_source ON mitre_data_component_log_sources USING gin (log_source_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_trgm_technique_name ON mitre_techniques USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_trgm_analytic_name ON mitre_analytics USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_trgm_analytic_description ON mitre_analytics USING gin (description gin_trgm_ops);

-- Word-stemmed full-text search over name+description, used to rank/filter candidates by how
-- well a rule's own name+description actually describes the technique/analytic's behavior --
-- much stronger than character-trigram similarity for whole-sentence relevance, and (unlike
-- the old trigram nudge) can genuinely shrink a broad candidate set rather than just reorder it.
ALTER TABLE mitre_techniques ADD COLUMN IF NOT EXISTS search_vector tsvector
  GENERATED ALWAYS AS (to_tsvector('english', coalesce(name, '') || ' ' || coalesce(description, ''))) STORED;
CREATE INDEX IF NOT EXISTS idx_techniques_fts ON mitre_techniques USING gin (search_vector);

ALTER TABLE mitre_analytics ADD COLUMN IF NOT EXISTS search_vector tsvector
  GENERATED ALWAYS AS (to_tsvector('english', coalesce(name, '') || ' ' || coalesce(description, ''))) STORED;
CREATE INDEX IF NOT EXISTS idx_analytics_fts ON mitre_analytics USING gin (search_vector);

-- plainto_tsquery AND-combines every word, which is far too strict for matching a multi-
-- sentence rule description against a much shorter technique/analytic description -- almost
-- nothing would ever match on ALL terms. OR-combine the same stemmed lexemes instead, so
-- ts_rank_cd rewards overlap on ANY significant word, weighted by how many/how dense.
CREATE OR REPLACE FUNCTION mitre_or_tsquery(input text) RETURNS tsquery AS $$
  SELECT COALESCE(NULLIF(replace(plainto_tsquery('english', input)::text, ' & ', ' | '), '')::tsquery, ''::tsquery);
$$ LANGUAGE sql IMMUTABLE;
