const { pool } = require('../db');
const { extractTokens, detectQueryLanguage } = require('./extract');
const { extractDetectionProfile, profileToSearchText } = require('./detectionProfile');

// Every search below blends in ts_rank_cd(..., mitre_or_tsquery(ruleText)) against both the
// analytic's and the technique's own text -- this is the rule's name+description+detection
// profile acting as a real filter at search time (word-stemmed, stopword-aware, OR-combined
// so a long rule description doesn't need to match every word), not just a late reorder of an
// already-huge candidate list. LIMIT is cut to 15 (was 50) since the ranking is now meaningful
// enough that the tail beyond that is very unlikely to matter.
//
// Every search also filters on platform: if the rule declares applicable platforms, only
// candidates where EITHER the analytic's own platforms overlap OR the technique's platforms
// overlap are considered -- a hard cut, not a ranking nudge, so a genuinely off-platform
// candidate never reaches aggregation. Checking the technique too (not just the analytic)
// matters: T1078.001 Default Accounts lists Windows as a valid platform at the technique
// level, but its only three published analytics in v19.1 happen to be tagged ESXi/Network
// Devices/Identity Provider -- MITRE just never published a Windows-specific example for this
// sub-technique. Filtering on the analytic alone silently excluded T1078.001 from every
// Windows-only rule, even when it was clearly the right technique.
//
// Ranking happens on the UNCAPPED raw_score so real differences between strong candidates
// survive; only the value actually stored/displayed as "confidence" is capped at 1.0. Capping
// before ORDER BY would flatten distinct candidates into ties at the ceiling and make LIMIT
// drop them essentially at random. Every ts_rank_cd call passes normalization flag 32
// (rank/(rank+1)) so its own contribution stays bounded to [0,1) regardless of document length
// or term clustering -- without it, a short technique description where a few common words
// (e.g. "network", "external", "traffic") happen to cluster tightly can out-rank the actual
// best match (T1499 "Endpoint Denial of Service" scored a HIGHER raw ts_rank_cd than T1571
// "Non-Standard Port" against a genuinely T1571-shaped rule, purely from cover-density on
// generic vocabulary), which then gets compounded across every signal merged in matchRule.
const RESULT_LIMIT = 15;
const PLATFORM_FILTER = `AND (cardinality($3::text[]) = 0 OR a.platforms && $3::text[] OR t.platforms && $3::text[])`;

// Collapse the scored (analytic x technique) rows to one representative row per technique, so
// RESULT_LIMIT bounds DISTINCT TECHNIQUES rather than analytic rows. Without this, a data
// component like "Authentication" (50+ analytics) lets a few prolific techniques consume the
// whole limit and starve single-analytic techniques (T1078.001 Default Accounts vanished this
// way). The representative is the datasource-consistent analytic with the highest score when
// one exists (platforms overlap the rule's declared data sources), else the highest-scoring
// analytic overall -- so a technique that has a same-datasource analytic is shown by it.
const PER_TECHNIQUE = `per_tech AS (
       SELECT DISTINCT ON (technique_id) *, (platforms && $3::text[]) AS ds_consistent
       FROM scored
       ORDER BY technique_id, (platforms && $3::text[]) DESC, raw_score DESC
     )`;

// For each extracted token, search mitre_analytic_log_sources: substring match first,
// pg_trgm similarity as a fuzzy fallback for near-misses (typos, slightly different casing).
// A bare sourcetype/index match (no specific event condition) is real but weak evidence --
// e.g. "WinEventLog:Sysmon" alone is shared by dozens of unrelated techniques -- so it's
// capped lower than a channel/event-code-specific hit from searchByEventCode.
async function searchBySourceToken(value, ruleText, platforms) {
  const { rows } = await pool.query(
    `WITH scored AS (
       SELECT DISTINCT a.id AS analytic_id, a.name AS analytic_name, a.platforms,
              als.log_source_name, als.channel, d.technique_id, t.name AS technique_name,
              LEAST(
                GREATEST(
                  similarity(als.log_source_name, $1),
                  CASE WHEN als.log_source_name ILIKE '%' || $1 || '%' THEN 0.5 ELSE 0 END
                ),
                0.5
              )
              + COALESCE(ts_rank_cd(a.search_vector, mitre_or_tsquery($2), 32), 0) * 0.2
              + COALESCE(ts_rank_cd(t.search_vector, mitre_or_tsquery($2), 32), 0) * 0.2
              AS raw_score,
              LEAST(GREATEST(similarity(als.log_source_name, $1), CASE WHEN als.log_source_name ILIKE '%' || $1 || '%' THEN 0.5 ELSE 0 END), 0.5) AS base_score,
              'fuzzy log-source match (capped at 0.5)'::text AS base_reason,
              COALESCE(ts_rank_cd(a.search_vector, mitre_or_tsquery($2), 32), 0) * 0.2 AS analytic_fts,
              COALESCE(ts_rank_cd(t.search_vector, mitre_or_tsquery($2), 32), 0) * 0.2 AS technique_fts
       FROM mitre_analytic_log_sources als
       JOIN mitre_analytics a ON a.id = als.analytic_id
       JOIN mitre_detection_strategy_analytics dsa ON dsa.analytic_id = a.id
       JOIN mitre_detects d ON d.detection_strategy_id = dsa.detection_strategy_id
       JOIN mitre_techniques t ON t.id = d.technique_id
       WHERE (als.log_source_name ILIKE '%' || $1 || '%' OR similarity(als.log_source_name, $1) > 0.35)
       ${PLATFORM_FILTER}
     ),
     ${PER_TECHNIQUE}
     SELECT *, LEAST(raw_score, 1.0) AS sim FROM per_tech
     ORDER BY raw_score DESC
     LIMIT ${RESULT_LIMIT}`,
    [value, ruleText, platforms]
  );
  return rows;
}

// Event codes are numeric and too ambiguous for trigram similarity, and a plain ILIKE
// substring is worse: "EventCode=1" would match any channel containing a "1" anywhere
// (e.g. "EventCode=10, 11, 21"). Require the digits to be a standalone number.
async function searchByEventCode(value, ruleText, platforms) {
  const boundaryPattern = `(^|[^0-9])${value}($|[^0-9])`;
  const { rows } = await pool.query(
    `WITH scored AS (
       SELECT DISTINCT a.id AS analytic_id, a.name AS analytic_name, a.platforms,
              als.log_source_name, als.channel, d.technique_id, t.name AS technique_name,
              0.95
              + COALESCE(ts_rank_cd(a.search_vector, mitre_or_tsquery($2), 32), 0) * 0.05
              + COALESCE(ts_rank_cd(t.search_vector, mitre_or_tsquery($2), 32), 0) * 0.05
              AS raw_score,
              0.95::float AS base_score,
              'exact event-code / channel match'::text AS base_reason,
              COALESCE(ts_rank_cd(a.search_vector, mitre_or_tsquery($2), 32), 0) * 0.05 AS analytic_fts,
              COALESCE(ts_rank_cd(t.search_vector, mitre_or_tsquery($2), 32), 0) * 0.05 AS technique_fts
       FROM mitre_analytic_log_sources als
       JOIN mitre_analytics a ON a.id = als.analytic_id
       JOIN mitre_detection_strategy_analytics dsa ON dsa.analytic_id = a.id
       JOIN mitre_detects d ON d.detection_strategy_id = dsa.detection_strategy_id
       JOIN mitre_techniques t ON t.id = d.technique_id
       WHERE als.channel ~ $1
       ${PLATFORM_FILTER}
     ),
     ${PER_TECHNIQUE}
     SELECT *, LEAST(raw_score, 1.0) AS sim FROM per_tech
     ORDER BY raw_score DESC
     LIMIT ${RESULT_LIMIT}`,
    [boundaryPattern, ruleText, platforms]
  );
  return rows;
}

// Concept-name searches: Splunk CIM data models (datamodel=Authentication.Authentication) and
// CrowdStrike event_simpleName values mapped to a concept (ProcessRollup2 -> "Process
// Creation") both resolve to a MITRE data component name instead of a raw log source string.
// Match against mitre_data_components.name and walk the same analytic/detects join from there.
// This is the signal most prone to broad ties (one data component can back 50+ techniques),
// so the rule-text relevance boost carries the most weight here -- it's what actually narrows
// "Authentication" down to the techniques the rule's own description is really about.
// Base is deliberately low (0.35, not the flat evidence tiers eventcode/artifact use) because
// this signal only proves "this technique is linked to the same broad telemetry category" --
// real discrimination has to come from the FTS relevance boost on top, or from a more precise
// signal (behavior phrase, event code, artifact) also matching the same candidate. With
// normalized ts_rank_cd (see below) capping each boost to <1.0, a base any higher would let a
// merely-plausible broad match outscore a genuinely precise one from another signal.
async function searchByConceptToken(value, ruleText, platforms) {
  const { rows } = await pool.query(
    `WITH scored AS (
       SELECT DISTINCT a.id AS analytic_id, a.name AS analytic_name, a.platforms,
              als.log_source_name, als.channel, d.technique_id, t.name AS technique_name,
              0.35
              + COALESCE(ts_rank_cd(a.search_vector, mitre_or_tsquery($2), 32), 0) * 0.25
              + COALESCE(ts_rank_cd(t.search_vector, mitre_or_tsquery($2), 32), 0) * 0.25
              AS raw_score,
              0.35::float AS base_score,
              'data-component / telemetry concept match'::text AS base_reason,
              COALESCE(ts_rank_cd(a.search_vector, mitre_or_tsquery($2), 32), 0) * 0.25 AS analytic_fts,
              COALESCE(ts_rank_cd(t.search_vector, mitre_or_tsquery($2), 32), 0) * 0.25 AS technique_fts
       FROM mitre_data_components dc
       JOIN mitre_analytic_log_sources als ON als.data_component_id = dc.id
       JOIN mitre_analytics a ON a.id = als.analytic_id
       JOIN mitre_detection_strategy_analytics dsa ON dsa.analytic_id = a.id
       JOIN mitre_detects d ON d.detection_strategy_id = dsa.detection_strategy_id
       JOIN mitre_techniques t ON t.id = d.technique_id
       WHERE dc.name ILIKE '%' || $1 || '%'
       ${PLATFORM_FILTER}
     ),
     ${PER_TECHNIQUE}
     SELECT *, LEAST(raw_score, 1.0) AS sim FROM per_tech
     ORDER BY raw_score DESC
     LIMIT ${RESULT_LIMIT}`,
    [value, ruleText, platforms]
  );
  if (rows.length > 0) return rows;
  // Not every CIM data model or CQL concept has a matching MITRE data component name --
  // "Identity_Management" doesn't literally appear in any DC name, even though ATT&CK has
  // plenty of identity/account-related techniques. Rather than returning nothing, fall back to
  // a pure full-text relevance search (no data-component anchor at all) over the concept name
  // plus the rule's own text. Weaker, unanchored evidence, so it's capped well below a real
  // structural match.
  return searchByFreeTextFallback(value, ruleText, platforms);
}

// Ranks by TECHNIQUE-level relevance only (not blended with per-analytic relevance): with no
// data-component anchor at all, the "evidence" here is purely a name/description-level
// heuristic, and averaging in analytic-level rank across every linked analytic diluted real
// technique-level signal with noise from unrelated analytics that happened to share common
// words. Picks one representative analytic per qualifying technique just for citation.
async function searchByFreeTextFallback(value, ruleText, platforms) {
  const combinedText = [value.replace(/_/g, ' '), ruleText].filter(Boolean).join('. ');
  const { rows } = await pool.query(
    `WITH ranked_techniques AS (
       SELECT t.id AS technique_id, t.name AS technique_name, t.platforms AS technique_platforms,
              ts_rank_cd(t.search_vector, mitre_or_tsquery($1), 32) AS t_rank
       FROM mitre_techniques t
       WHERE ts_rank_cd(t.search_vector, mitre_or_tsquery($1), 32) > 0
     ),
     picked AS (
       SELECT DISTINCT ON (rt.technique_id)
              rt.technique_id, rt.technique_name, rt.t_rank,
              a.id AS analytic_id, a.name AS analytic_name, a.platforms,
              als.log_source_name, als.channel
       FROM ranked_techniques rt
       JOIN mitre_detects d ON d.technique_id = rt.technique_id
       JOIN mitre_detection_strategy_analytics dsa ON dsa.detection_strategy_id = d.detection_strategy_id
       JOIN mitre_analytics a ON a.id = dsa.analytic_id
       JOIN mitre_analytic_log_sources als ON als.analytic_id = a.id
       WHERE (cardinality($2::text[]) = 0 OR a.platforms && $2::text[] OR rt.technique_platforms && $2::text[])
       ORDER BY rt.technique_id, rt.t_rank DESC
     )
     SELECT analytic_id, analytic_name, platforms, log_source_name, channel, technique_id, technique_name,
            LEAST(t_rank * 0.4, 0.4) AS sim,
            0::float AS base_score,
            'text-only semantic fallback (no log-source anchor)'::text AS base_reason,
            0::float AS analytic_fts,
            LEAST(t_rank * 0.4, 0.4)::float AS technique_fts
     FROM picked
     ORDER BY t_rank DESC
     LIMIT ${RESULT_LIMIT}`,
    [combinedText, platforms]
  );
  return rows;
}

// Artifact tokens come from the detection profile (EncodedCommand, HTTP, Base64, ...), not
// the raw query -- they're technical terms distinctive enough to search directly against the
// channel text, similar to an event code but textual rather than numeric. Base confidence
// sits between a concept match (0.35, broad) and an event-code match (0.95, exact/numeric).
async function searchByArtifactToken(value, ruleText, platforms) {
  const { rows } = await pool.query(
    `WITH scored AS (
       SELECT DISTINCT a.id AS analytic_id, a.name AS analytic_name, a.platforms,
              als.log_source_name, als.channel, d.technique_id, t.name AS technique_name,
              0.7
              + COALESCE(ts_rank_cd(a.search_vector, mitre_or_tsquery($2), 32), 0) * 0.15
              + COALESCE(ts_rank_cd(t.search_vector, mitre_or_tsquery($2), 32), 0) * 0.15
              AS raw_score,
              0.7::float AS base_score,
              'artifact term match in channel'::text AS base_reason,
              COALESCE(ts_rank_cd(a.search_vector, mitre_or_tsquery($2), 32), 0) * 0.15 AS analytic_fts,
              COALESCE(ts_rank_cd(t.search_vector, mitre_or_tsquery($2), 32), 0) * 0.15 AS technique_fts
       FROM mitre_analytic_log_sources als
       JOIN mitre_analytics a ON a.id = als.analytic_id
       JOIN mitre_detection_strategy_analytics dsa ON dsa.analytic_id = a.id
       JOIN mitre_detects d ON d.detection_strategy_id = dsa.detection_strategy_id
       JOIN mitre_techniques t ON t.id = d.technique_id
       WHERE als.channel ILIKE '%' || $1 || '%'
       ${PLATFORM_FILTER}
     ),
     ${PER_TECHNIQUE}
     SELECT *, LEAST(raw_score, 1.0) AS sim FROM per_tech
     ORDER BY raw_score DESC
     LIMIT ${RESULT_LIMIT}`,
    [value, ruleText, platforms]
  );
  return rows;
}

// Behavior phrases from the LLM detection profile ("Command and control over non-standard
// port") are ATT&CK-style paraphrases that often closely echo a technique's own NAME, not just
// its longer description. word_similarity(name, phrase) -- the best trigram match of the short
// technique name against ANY substring of the longer phrase -- surfaces this far more precisely
// than bag-of-words FTS ever can: "...encrypted channel to newly observed external
// infrastructure" scores 1.0 against T1573 "Encrypted Channel" this way, while ts_rank_cd
// against the full technique description buries it outside the top 20 (diluted by every other
// technique whose description happens to share common words like "network"/"external"/"C2").
// This is what lets techniques like T1571 (Non-Standard Port) and T1573 (Encrypted Channel)
// arrive as genuine ranked candidates with real evidence, instead of only being reachable via
// the LLM's own after-the-fact proposal (see reasonAboutRule's proposed_techniques path).
const BEHAVIOR_NAME_SIM_THRESHOLD = 0.3;
async function searchByBehaviorPhrase(phrase, ruleText, platforms) {
  const { rows } = await pool.query(
    `WITH ranked_techniques AS (
       SELECT t.id AS technique_id, t.name AS technique_name, t.platforms AS technique_platforms,
              word_similarity(t.name, $1) AS name_sim
       FROM mitre_techniques t
       WHERE t.revoked = false AND t.deprecated = false
         AND word_similarity(t.name, $1) >= ${BEHAVIOR_NAME_SIM_THRESHOLD}
     ),
     picked AS (
       SELECT DISTINCT ON (rt.technique_id)
              rt.technique_id, rt.technique_name, rt.name_sim,
              a.id AS analytic_id, a.name AS analytic_name, a.platforms,
              als.log_source_name, als.channel
       FROM ranked_techniques rt
       JOIN mitre_detects d ON d.technique_id = rt.technique_id
       JOIN mitre_detection_strategy_analytics dsa ON dsa.detection_strategy_id = d.detection_strategy_id
       JOIN mitre_analytics a ON a.id = dsa.analytic_id
       JOIN mitre_analytic_log_sources als ON als.analytic_id = a.id
       WHERE (cardinality($2::text[]) = 0 OR a.platforms && $2::text[] OR rt.technique_platforms && $2::text[])
       ORDER BY rt.technique_id, (a.platforms && $2::text[]) DESC, rt.name_sim DESC
     )
     SELECT analytic_id, analytic_name, platforms, log_source_name, channel, technique_id, technique_name,
            LEAST(name_sim * 0.9, 0.9) AS sim,
            LEAST(name_sim * 0.9, 0.9)::float AS base_score,
            ('profile behavior closely matches technique name (word_similarity=' || round(name_sim::numeric, 2) || ')')::text AS base_reason,
            0::float AS analytic_fts,
            0::float AS technique_fts
     FROM picked
     ORDER BY name_sim DESC
     LIMIT ${RESULT_LIMIT}`,
    [phrase, platforms]
  );
  return rows;
}

async function searchForToken(tok, ruleText, platforms) {
  if (tok.type === 'eventcode') return searchByEventCode(tok.value, ruleText, platforms);
  if (tok.type === 'datamodel' || tok.type === 'concept' || tok.type === 'telemetry')
    return searchByConceptToken(tok.value, ruleText, platforms);
  if (tok.type === 'artifact') return searchByArtifactToken(tok.value, ruleText, platforms);
  if (tok.type === 'behavior') return searchByBehaviorPhrase(tok.value, ruleText, platforms);
  // Seen and recorded for the audit trail, but no searchable log source: unmapped CrowdStrike
  // events, filter/allow-list macros, and macros whose name gave no inference.
  if (tok.type === 'concept-unknown' || tok.type === 'macro-filter' || tok.type === 'macro-unknown' || tok.type === 'repo-unknown') return [];
  return searchBySourceToken(tok.value, ruleText, platforms);
}

// Telemetry phrases from the LLM profile ("Authentication Logs", "Identity Provider Logs")
// are searched like concept tokens, but MITRE data-component names don't carry the trailing
// "Logs/Events/Telemetry" noise words, so strip them for a better name match (the free-text
// fallback inside searchByConceptToken still catches anything the DC-name match misses).
const MAX_TELEMETRY_TOKENS = 4;
function telemetryToTokens(telemetry) {
  const seen = new Set();
  const tokens = [];
  for (const raw of telemetry) {
    const cleaned = raw.replace(/\b(logs?|events?|telemetry|data)\b/gi, '').replace(/\s+/g, ' ').trim();
    if (!cleaned) continue;
    const key = cleaned.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    tokens.push({ type: 'telemetry', value: cleaned, source: `telemetry: ${raw}` });
    if (tokens.length >= MAX_TELEMETRY_TOKENS) break;
  }
  return tokens;
}

// LLM profile behaviors become their own high-precision search tokens (see
// searchByBehaviorPhrase above). Capped like telemetry tokens so a verbose profile doesn't
// balloon the number of queries per rule.
const MAX_BEHAVIOR_TOKENS = 4;
function behaviorToTokens(behavior) {
  return (behavior || []).slice(0, MAX_BEHAVIOR_TOKENS).map((value) => ({
    type: 'behavior',
    value,
    source: `profile behavior`,
  }));
}

const MAX_SIGNAL_RESULTS_STORED = 15;

// Runs the full structural-matching stage for one rule. `llmProfile` is the semantic
// detection profile extracted by the LLM in the prior stage (may be null if that call
// failed); its behaviors/intent/telemetry drive the relevance ranking and add telemetry
// search tokens. Returns everything needed both to proceed (matches) and to inspect what
// happened at each step -- the pipeline inspector UI renders these directly.
async function matchRule(rule, llmProfile) {
  const detectedLanguage = detectQueryLanguage(rule.query);
  // Deterministic query features still provide high-precision structural tokens (artifacts
  // like EncodedCommand/HTTP that appear literally in the query text).
  const queryFeatures = extractDetectionProfile(rule);

  const queryTokens = extractTokens(rule.query);
  const artifactTokens = queryFeatures.artifacts.map((value) => ({ type: 'artifact', value }));
  const telemetryTokens = llmProfile ? telemetryToTokens(llmProfile.telemetry) : [];
  const behaviorTokens = llmProfile ? behaviorToTokens(llmProfile.behavior) : [];
  const tokens = [...queryTokens, ...artifactTokens, ...telemetryTokens, ...behaviorTokens];

  const datasetHints = queryTokens.map((t) => t.dataset).filter(Boolean);
  // The LLM profile's behaviors + intent + telemetry are the strongest relevance signal --
  // they're ATT&CK-aligned paraphrases that match technique/analytic descriptions far better
  // than the vendor query text. Weight them first in the FTS relevance string.
  const profileText = llmProfile
    ? [...llmProfile.behavior, llmProfile.analytic_intent, ...llmProfile.telemetry, ...Object.values(llmProfile.entities || {})]
        .filter(Boolean)
        .join('. ')
    : '';
  const ruleText = [rule.rule_name, rule.description, profileText, profileToSearchText(queryFeatures), ...datasetHints]
    .filter(Boolean)
    .join('. ')
    .trim();
  const platforms = rule.applicable_platforms || [];
  // Cloud service-model values (IaaS/PaaS/SaaS) describe WHERE a workload runs, not WHICH
  // OS-tagged technique variant applies -- ATT&CK tags host/network techniques like T1571
  // Non-Standard Port and T1573 Encrypted Channel with OS platforms (Windows/Linux/macOS/
  // ESXi/Network Devices) even when the telemetry is cloud-native (e.g. AWS VPC Flow Logs),
  // since the flow log alone can't tell you the compromised host's OS. Hard-filtering on IaaS
  // therefore excluded these techniques at the SQL level entirely -- before the soft orphan-
  // keep logic in applyDatasourceFilter ever got a chance to run. Strip cloud service-model
  // values from the HARD filter only; applyDatasourceFilter still receives the full platform
  // list below and correctly flags these as orphans with a mild score penalty, same as any
  // other platform-inconsistent-but-real match.
  const CLOUD_SERVICE_MODEL_PLATFORMS = new Set(['IaaS', 'PaaS', 'SaaS']);
  const hardFilterPlatforms = platforms.filter((p) => !CLOUD_SERVICE_MODEL_PLATFORMS.has(p));

  const matches = new Map();
  const rawSignals = [];

  for (const tok of tokens) {
    const rows = await searchForToken(tok, ruleText, hardFilterPlatforms);
    rawSignals.push({ token: tok, rows });

    for (const row of rows) {
      const key = `${row.analytic_id}::${row.technique_id}`;
      const existing = matches.get(key);
      if (!existing || row.sim > existing.sim) {
        matches.set(key, {
          analytic_id: row.analytic_id,
          analytic_name: row.analytic_name,
          platforms: row.platforms || [],
          technique_id: row.technique_id,
          technique_name: row.technique_name,
          matched_log_source: row.log_source_name,
          sim: Number(row.sim),
          breakdown: {
            base: row.base_score != null ? Number(row.base_score) : null,
            baseReason: row.base_reason || null,
            analyticFts: row.analytic_fts != null ? Number(row.analytic_fts) : 0,
            techniqueFts: row.technique_fts != null ? Number(row.technique_fts) : 0,
            matchedBySignal: tok.type,
          },
        });
      }
    }
  }

  const { keptMatches, keptKeys } = applyDatasourceFilter([...matches.values()], platforms);

  // Build the inspector's per-signal view AFTER filtering, annotating each row with whether
  // its log source is consistent with the rule's declared data sources and whether it survived
  // the hybrid filter (kept), so the Stage 3 tables show exactly what was cut and why.
  const platformSet = new Set(platforms);
  const signalResults = rawSignals.map(({ token, rows }) => ({
    token,
    resultCount: rows.length,
    results: rows.slice(0, MAX_SIGNAL_RESULTS_STORED).map((r) => {
      const key = `${r.analytic_id}::${r.technique_id}`;
      return {
        analyticId: r.analytic_id,
        analyticName: r.analytic_name,
        techniqueId: r.technique_id,
        techniqueName: r.technique_name,
        matchedLogSource: r.log_source_name,
        score: Number(r.sim),
        datasourceConsistent: platformSet.size === 0 || (r.platforms || []).some((p) => platformSet.has(p)),
        kept: keptKeys.has(key),
      };
    }),
  }));

  return {
    detectedLanguage,
    queryFeatures,
    tokens,
    signalResults,
    matches: keptMatches,
  };
}

// Hybrid applicable-log-source filter (see task #37): a match is "datasource-consistent" when
// the analytic's own platforms overlap the rule's declared applicable data sources (derived
// from the CSV applicable_datasource column). Per technique: if any consistent analytic exists,
// keep only those and drop the rest; if a technique has ONLY inconsistent analytics, keep its
// single best one as an "orphan" (with a score penalty) so a correct-but-low-coverage technique
// like T1078.001 still reaches the LLM even when its only Authentication-linked analytics happen
// to be tagged for other platforms. With no declared data source, nothing is filtered.
// Mild only: an orphan (a technique whose only surfaced evidence is off-datasource) should sit
// just below equivalent same-datasource techniques, but must NOT be buried -- it's often the
// genuinely-correct low-coverage technique (T1078.001 for a Windows default-account rule).
const ORPHAN_SCORE_PENALTY = 0.85;
function applyDatasourceFilter(allMatches, platforms) {
  const platformSet = new Set(platforms);
  if (platformSet.size === 0) {
    return { keptMatches: allMatches, keptKeys: new Set(allMatches.map((m) => `${m.analytic_id}::${m.technique_id}`)) };
  }

  const byTechnique = new Map();
  for (const m of allMatches) {
    m.datasourceConsistent = (m.platforms || []).some((p) => platformSet.has(p));
    if (!byTechnique.has(m.technique_id)) byTechnique.set(m.technique_id, []);
    byTechnique.get(m.technique_id).push(m);
  }

  const keptMatches = [];
  for (const group of byTechnique.values()) {
    const consistent = group.filter((m) => m.datasourceConsistent);
    if (consistent.length) {
      keptMatches.push(...consistent);
    } else {
      const best = group.reduce((a, b) => (b.sim > a.sim ? b : a));
      best.datasourceOrphan = true;
      best.sim = best.sim * ORPHAN_SCORE_PENALTY;
      keptMatches.push(best);
    }
  }

  return { keptMatches, keptKeys: new Set(keptMatches.map((m) => `${m.analytic_id}::${m.technique_id}`)) };
}

module.exports = { matchRule };
