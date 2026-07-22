CREATE TABLE IF NOT EXISTS upload_jobs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  total_rows INTEGER NOT NULL DEFAULT 0,
  processed_rows INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS rules (
  id SERIAL PRIMARY KEY,
  job_id INTEGER NOT NULL REFERENCES upload_jobs(id) ON DELETE CASCADE,
  row_no TEXT,
  rule_name TEXT NOT NULL,
  description TEXT,
  query TEXT,
  cron TEXT,
  timerange TEXT,
  applicable_datasource TEXT,
  applicable_platforms TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Best match per (rule, technique): the highest-scoring analytic, with the union of
-- platforms that analytic evidence actually covers for this rule.
CREATE TABLE IF NOT EXISTS rule_technique_matches (
  id SERIAL PRIMARY KEY,
  rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  analytic_id TEXT REFERENCES mitre_analytics(id),
  technique_id TEXT NOT NULL REFERENCES mitre_techniques(id),
  matched_platforms TEXT[] NOT NULL DEFAULT '{}',
  matched_log_source TEXT,
  score NUMERIC,
  platform_inferred BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- LLM adjudication layer: the structural match above is a candidate, not a verdict.
-- llm_selected marks the technique(s) the LLM actually confirmed from the rule's real query
-- logic; coverage is computed only from llm_selected=true rows.
ALTER TABLE rule_technique_matches ADD COLUMN IF NOT EXISTS llm_confidence NUMERIC;
ALTER TABLE rule_technique_matches ADD COLUMN IF NOT EXISTS llm_rationale TEXT;
ALTER TABLE rule_technique_matches ADD COLUMN IF NOT EXISTS llm_selected BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE rule_technique_matches ADD COLUMN IF NOT EXISTS needs_review BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE rule_technique_matches ADD COLUMN IF NOT EXISTS review_reason TEXT;

-- Snapshot of every pipeline stage's output for this rule (detected query language, extracted
-- tokens, raw per-signal search results, ranked candidates, and the LLM request/response) --
-- lets the UI show "what happened at each step" without re-running the pipeline.
ALTER TABLE rules ADD COLUMN IF NOT EXISTS detected_language TEXT;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS pipeline_debug JSONB;

-- Categorized {processes, actions, artifacts, objects, behaviors} extracted from the rule's
-- own name/description/query (see detectionProfile.js). JSONB + GIN gives fast, indexed
-- containment/overlap queries over this without needing a document store -- e.g.
-- `detection_profile -> 'artifacts' ?| array['EncodedCommand','Base64']`.
ALTER TABLE rules ADD COLUMN IF NOT EXISTS detection_profile JSONB;
CREATE INDEX IF NOT EXISTS idx_rules_detection_profile ON rules USING gin (detection_profile jsonb_path_ops);

-- QA / compliance checker output for the rule's final mapping (checks + overall pass/fail).
ALTER TABLE rules ADD COLUMN IF NOT EXISTS qa_result JSONB;

-- Editable, versioned prompts for the LLM-backed agents. One row per version; exactly one
-- is_active row per agent_key is the prompt actually used at runtime. Admins edit these in the
-- UI; every edit creates a new version so nothing is overwritten (audit-friendly).
CREATE TABLE IF NOT EXISTS prompt_templates (
  id SERIAL PRIMARY KEY,
  agent_key TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  is_active BOOLEAN NOT NULL DEFAULT true,
  updated_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_prompt_templates_active ON prompt_templates (agent_key, is_active);

-- Runtime-adjustable app settings (LLM model, base URL, API key) editable in the admin UI.
-- Values here override the corresponding environment variables when present.
CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rules_job ON rules(job_id);
CREATE INDEX IF NOT EXISTS idx_rtm_rule ON rule_technique_matches(rule_id);
CREATE INDEX IF NOT EXISTS idx_rtm_technique ON rule_technique_matches(technique_id);
