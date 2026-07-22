const { pool } = require('../db');
const { matchRule } = require('./match');
const { extractProfile, reasonAboutRule, runQa } = require('./llm');

// Aggregate raw (analytic, technique) matches for one rule up to one row per technique.
// bestScore is the technique's top score (drives candidate ranking); the REPRESENTATIVE
// analytic shown as evidence is chosen preferring datasource-consistency first, then score --
// so a Windows rule never displays a macOS analytic as the evidence for a technique that also
// has a Windows analytic. (The datasource filter already drops the inconsistent ones per
// technique, but this keeps representative selection correct even if both slip through.)
function aggregateByTechnique(rawMatches, rulePlatforms) {
  const byTechnique = new Map();
  const rulePlatformSet = new Set(rulePlatforms);

  for (const m of rawMatches) {
    const intersect = m.platforms.filter((p) => rulePlatformSet.has(p));
    const effectivePlatforms = intersect.length ? intersect : m.platforms;
    const inferred = intersect.length === 0 && m.platforms.length > 0;
    const consistent = rulePlatformSet.size === 0 || intersect.length > 0;

    if (!byTechnique.has(m.technique_id)) {
      byTechnique.set(m.technique_id, {
        techniqueName: m.technique_name,
        platforms: new Set(),
        bestScore: 0,
        repScore: -1,
        repConsistent: false,
        bestAnalytic: null,
        bestAnalyticName: null,
        bestLogSource: null,
        anyInferred: false,
      });
    }
    const entry = byTechnique.get(m.technique_id);
    for (const p of effectivePlatforms) entry.platforms.add(p);

    entry.bestScore = Math.max(entry.bestScore, m.sim);

    // Representative preference: a consistent analytic always beats an inconsistent one;
    // within the same consistency, higher score wins.
    const better =
      entry.bestAnalytic === null ||
      (consistent && !entry.repConsistent) ||
      (consistent === entry.repConsistent && m.sim > entry.repScore);
    if (better) {
      entry.repConsistent = consistent;
      entry.repScore = m.sim;
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

      // QA agent: independent check of the final mapping against the source rule. Runs even
      // when nothing was selected (it confirms the needs_review path was taken correctly).
      let qaResult = null;
      try {
        const qaSelections = verdict.selections.map((s) => {
          const entry = byTechnique.get(s.technique_id);
          return {
            technique_id: s.technique_id,
            technique_name: entry ? entry.techniqueName : undefined,
            analytic_id: entry ? entry.bestAnalytic : undefined,
            confidence: s.confidence,
            rationale: s.rationale,
          };
        });
        qaResult = await runQa(rule, llmProfile, qaSelections);
      } catch (qaErr) {
        qaResult = { checks: [], overall: 'error', error: qaErr.message };
      }

      await pool.query('UPDATE rules SET detected_language=$1, pipeline_debug=$2, detection_profile=$3, qa_result=$4 WHERE id=$5', [
        detectedLanguage,
        JSON.stringify(pipelineDebug),
        llmProfile ? JSON.stringify(llmProfile) : null,
        qaResult ? JSON.stringify(qaResult) : null,
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
