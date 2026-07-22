const { pool } = require('../db');
const { matchRule } = require('./match');
const { extractProfile, reasonAboutRule } = require('./llm');

// Aggregate raw (analytic, technique) matches for one rule up to one row per technique:
// the best-scoring analytic, and the union of platforms that evidence actually covers.
function aggregateByTechnique(rawMatches, rulePlatforms) {
  const byTechnique = new Map();

  for (const m of rawMatches) {
    const intersect = m.platforms.filter((p) => rulePlatforms.includes(p));
    const effectivePlatforms = intersect.length ? intersect : m.platforms;
    const inferred = intersect.length === 0 && m.platforms.length > 0;

    if (!byTechnique.has(m.technique_id)) {
      byTechnique.set(m.technique_id, {
        techniqueName: m.technique_name,
        platforms: new Set(),
        bestScore: 0,
        bestAnalytic: null,
        bestAnalyticName: null,
        bestLogSource: null,
        anyInferred: false,
      });
    }
    const entry = byTechnique.get(m.technique_id);
    for (const p of effectivePlatforms) entry.platforms.add(p);
    if (m.sim > entry.bestScore) {
      entry.bestScore = m.sim;
      entry.bestAnalytic = m.analytic_id;
      entry.bestAnalyticName = m.analytic_name;
      entry.bestLogSource = m.matched_log_source;
    }
    entry.anyInferred = entry.anyInferred || inferred;
  }

  return byTechnique;
}

// A broad structural signal (e.g. a CIM/CQL concept match against a data component like
// "Authentication") can tie many techniques at the same base score. Ranking now blends in
// real full-text relevance between the rule's own name+description and each candidate's
// text (see match.js), computed at search time -- not a late, weak trigram reorder -- so the
// candidates that reach here are already meaningfully filtered. That's what lets this cap be
// small without repeating the earlier bug (T1078 Valid Accounts got cut at a cap of 5 when
// ranking was untrustworthy); it exists to bound prompt size/cost, not to pre-decide the answer.
const MAX_TECHNIQUES_PER_RULE = 10;

function topCandidates(byTechnique) {
  return [...byTechnique.entries()]
    .sort((a, b) => b[1].bestScore - a[1].bestScore)
    .slice(0, MAX_TECHNIQUES_PER_RULE);
}

async function processJob(jobId) {
  const { rows: rules } = await pool.query('SELECT * FROM rules WHERE job_id=$1 ORDER BY id', [jobId]);

  for (const rule of rules) {
    let pipelineDebug = null;

    try {
      // Stage 1: LLM extracts a normalized, ATT&CK-aligned detection profile. This runs first
      // and its terms drive the search (better relevance) -- see match.js. Null on LLM failure,
      // in which case matchRule falls back to query-only search.
      const { profile: llmProfile, error: profileError } = await extractProfile(rule);

      const { detectedLanguage, queryFeatures, tokens, signalResults, matches: rawMatches } = await matchRule(rule, llmProfile);
      const byTechnique = aggregateByTechnique(rawMatches, rule.applicable_platforms || []);
      const candidates = topCandidates(byTechnique);

      const llmCandidates = candidates.map(([techniqueId, entry]) => ({
        techniqueId,
        techniqueName: entry.techniqueName,
        analyticId: entry.bestAnalytic,
        analyticName: entry.bestAnalyticName,
        matchedLogSource: entry.bestLogSource,
        structuralScore: entry.bestScore,
      }));

      const verdict = await reasonAboutRule(rule, llmCandidates, llmProfile);
      const selectionById = new Map(verdict.selections.map((s) => [s.technique_id, s]));

      pipelineDebug = {
        detectedLanguage,
        detectionProfile: llmProfile,
        profileError: profileError || null,
        queryFeatures,
        tokens,
        signalResults,
        rankedCandidates: llmCandidates.map((c) => ({
          ...c,
          platforms: [...(byTechnique.get(c.techniqueId)?.platforms || [])],
        })),
        llm: {
          request: llmCandidates,
          response: verdict,
        },
      };

      for (const [techniqueId, entry] of candidates) {
        const selection = selectionById.get(techniqueId);
        await pool.query(
          `INSERT INTO rule_technique_matches
             (rule_id, analytic_id, technique_id, matched_platforms, matched_log_source, score, platform_inferred,
              llm_confidence, llm_rationale, llm_selected, needs_review, review_reason)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [
            rule.id,
            entry.bestAnalytic,
            techniqueId,
            [...entry.platforms],
            entry.bestLogSource,
            entry.bestScore,
            entry.anyInferred,
            selection ? selection.confidence : null,
            selection ? selection.rationale : null,
            !!selection,
            verdict.needsReview,
            verdict.reviewReason || null,
          ]
        );
      }

      await pool.query('UPDATE rules SET detected_language=$1, pipeline_debug=$2, detection_profile=$3 WHERE id=$4', [
        detectedLanguage,
        JSON.stringify(pipelineDebug),
        llmProfile ? JSON.stringify(llmProfile) : null,
        rule.id,
      ]);
    } catch (err) {
      console.error(`Failed to match rule ${rule.id} (job ${jobId}):`, err);
    }

    await pool.query('UPDATE upload_jobs SET processed_rows = processed_rows + 1 WHERE id=$1', [jobId]);
  }

  await pool.query("UPDATE upload_jobs SET status='completed', completed_at=now() WHERE id=$1", [jobId]);
}

module.exports = { processJob };
