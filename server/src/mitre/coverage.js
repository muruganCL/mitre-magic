const { pool } = require('../db');

// A technique is:
//   Blind    - no matched analytic at all
//   Partial  - matched on some, but not all, of the platforms eligible for THIS customer
//   Covered  - matched on every eligible platform
// "Eligible" platforms = platforms this technique's analytics support, intersected with the
// customer's declared platforms (so a technique needing Windows/Linux/macOS reduces to
// Windows/Linux if the customer has no macOS data source -- matching Windows-only then reads
// as Covered against that narrower ceiling, not Partial against the full three).
async function computeCoverage(jobId) {
  const platRes = await pool.query('SELECT DISTINCT unnest(applicable_platforms) AS p FROM rules WHERE job_id=$1', [jobId]);
  const customerPlatforms = new Set(platRes.rows.map((r) => r.p));

  // Only llm_selected rows count toward coverage -- the structural search produces candidates,
  // not verdicts, and counting every candidate would inflate coverage with techniques the LLM
  // reviewed and rejected (or never confirmed against the rule's actual query logic).
  const matchRes = await pool.query(
    `SELECT rtm.technique_id, t.name AS technique_name, rtm.matched_platforms
     FROM rule_technique_matches rtm
     JOIN rules r ON r.id = rtm.rule_id
     JOIN mitre_techniques t ON t.id = rtm.technique_id
     WHERE r.job_id = $1 AND rtm.llm_selected = true`,
    [jobId]
  );

  if (matchRes.rows.length === 0) {
    return { customerPlatforms: [...customerPlatforms], techniques: [] };
  }

  const byTechnique = new Map();
  for (const row of matchRes.rows) {
    if (!byTechnique.has(row.technique_id)) {
      byTechnique.set(row.technique_id, { name: row.technique_name, matched: new Set() });
    }
    const entry = byTechnique.get(row.technique_id);
    for (const p of row.matched_platforms) entry.matched.add(p);
  }

  const techniqueIds = [...byTechnique.keys()];
  const eligRes = await pool.query(
    `SELECT DISTINCT d.technique_id, up.platform
     FROM mitre_detects d
     JOIN mitre_detection_strategy_analytics dsa ON dsa.detection_strategy_id = d.detection_strategy_id
     JOIN mitre_analytics a ON a.id = dsa.analytic_id
     CROSS JOIN LATERAL unnest(a.platforms) AS up(platform)
     WHERE d.technique_id = ANY($1)`,
    [techniqueIds]
  );

  const eligibleByTechnique = new Map();
  for (const row of eligRes.rows) {
    if (!eligibleByTechnique.has(row.technique_id)) eligibleByTechnique.set(row.technique_id, new Set());
    eligibleByTechnique.get(row.technique_id).add(row.platform);
  }

  const techniques = [];
  for (const [techniqueId, entry] of byTechnique) {
    const fullEligible = [...(eligibleByTechnique.get(techniqueId) || new Set())];
    const scopedEligible = customerPlatforms.size > 0 ? fullEligible.filter((p) => customerPlatforms.has(p)) : fullEligible;
    const matched = [...entry.matched];

    // Covered means every eligible platform is actually matched -- not just "as many platforms
    // matched as are eligible". A rule can match on a platform outside the eligible set (e.g. an
    // inferred/unfiltered platform from a low-confidence match), which must not count toward it.
    let state = 'Blind';
    if (matched.length > 0) {
      const matchedSet = new Set(matched);
      const fullyCovered = scopedEligible.length > 0 && scopedEligible.every((p) => matchedSet.has(p));
      state = fullyCovered ? 'Covered' : 'Partial';
    }

    techniques.push({
      techniqueId,
      techniqueName: entry.name,
      eligiblePlatforms: scopedEligible,
      matchedPlatforms: matched,
      state,
    });
  }

  techniques.sort((a, b) => a.techniqueId.localeCompare(b.techniqueId));

  return { customerPlatforms: [...customerPlatforms], techniques };
}

module.exports = { computeCoverage };
