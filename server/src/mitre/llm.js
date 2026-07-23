const { getActivePrompt } = require('./promptStore');
const { getLlmConfig } = require('./settingsStore');

function stripCodeFences(text) {
  return text
    .trim()
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/, '')
    .replace(/```\s*$/, '');
}

// Shared Pix call. Returns { ok, data } or { ok:false, error }. The model / gateway / API key
// are read from the runtime settings (admin-editable in the UI) at call time, falling back to
// env vars. The system prompt is passed per-call but stable per task, so the gateway caches its
// prefix (cache:true).
async function callPix(systemPrompt, userContent) {
  const cfg = await getLlmConfig();
  // meta is returned on every path so the exact prompt sent and raw response are always
  // available for the audit / reasoning-visibility view. The API key is only in the request
  // header, never in meta, so nothing secret is captured.
  const meta = { model: cfg.model, systemPrompt, userContent, rawResponse: null, usage: null };
  if (!cfg.apiKey) return { ok: false, error: 'LLM API key not configured (set it in Admin → LLM Provider)', meta };

  let res;
  try {
    res = await fetch(`${cfg.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${cfg.apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: cfg.model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userContent },
        ],
        cache: true,
      }),
    });
  } catch (err) {
    return { ok: false, error: `LLM call failed: ${err.message}`, meta };
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    meta.rawResponse = text.slice(0, 2000);
    return { ok: false, error: `LLM gateway returned ${res.status}: ${text.slice(0, 200)}`, meta };
  }

  const data = await res.json();
  const raw = data.choices?.[0]?.message?.content || '';
  meta.rawResponse = raw;
  meta.usage = data.usage || null;
  try {
    return { ok: true, data: JSON.parse(stripCodeFences(raw)), meta };
  } catch (err) {
    return { ok: false, error: `Could not parse LLM response as JSON: ${raw.slice(0, 200)}`, meta };
  }
}

// ---------------------------------------------------------------------------
// Stage 1: extract a normalized, ATT&CK-aligned detection profile from the rule.
// This runs BEFORE search and its terms drive the search -- the point is to translate
// vendor-specific query syntax (Splunk data models, CrowdStrike event names) into the
// generic behavioral/telemetry vocabulary ATT&CK actually uses, so keyword search over the
// ATT&CK corpus lands on the right techniques. The system prompt is loaded from the editable
// prompt registry (admins can change it in the UI without a code change).
// ---------------------------------------------------------------------------
function asStringArray(v) {
  if (!Array.isArray(v)) return [];
  return v.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim());
}

// promptBodyOverride lets the comparison harness run this agent against a specific prompt
// version instead of the active one; normal pipeline calls omit it and use the active prompt.
async function extractProfile(rule, promptBodyOverride) {
  const userContent = JSON.stringify(
    {
      rule_name: rule.rule_name,
      description: rule.description,
      query: rule.query,
      declared_platforms: rule.applicable_datasource,
    },
    null,
    2
  );

  const systemPrompt = promptBodyOverride || (await getActivePrompt('detection_profile'));
  const result = await callPix(systemPrompt, userContent);
  if (!result.ok) {
    return { profile: null, error: result.error, llm: result.meta };
  }

  const p = result.data || {};
  // Per-field provenance: each entry states which profile field it belongs to, the value, the
  // exact rule text it is grounded in, and the reasoning. Kept even if partial.
  const audit = Array.isArray(p.audit)
    ? p.audit
        .filter((a) => a && typeof a === 'object')
        .map((a) => ({
          field: typeof a.field === 'string' ? a.field : '',
          value: typeof a.value === 'string' ? a.value : '',
          evidence: typeof a.evidence === 'string' ? a.evidence : '',
          reasoning: typeof a.reasoning === 'string' ? a.reasoning : '',
        }))
    : [];
  const profile = {
    behavior: asStringArray(p.behavior),
    entities: p.entities && typeof p.entities === 'object' && !Array.isArray(p.entities) ? p.entities : {},
    telemetry: asStringArray(p.telemetry),
    platforms: asStringArray(p.platforms),
    analytic_intent: typeof p.analytic_intent === 'string' ? p.analytic_intent.trim() : '',
    audit,
  };
  return { profile, error: null, llm: result.meta };
}

// ---------------------------------------------------------------------------
// Stage 4: adjudicate the structurally-ranked candidates. System prompt from the registry.
// ---------------------------------------------------------------------------
async function reasonAboutRule(rule, candidates, profile) {
  if (candidates.length === 0) {
    return { selections: [], needsReview: false, reviewReason: '' };
  }

  const userContent = JSON.stringify(
    {
      rule: {
        rule_name: rule.rule_name,
        description: rule.description,
        query: rule.query,
        applicable_datasource: rule.applicable_datasource,
      },
      detection_profile: profile || undefined,
      candidates: candidates.map((c) => ({
        technique_id: c.techniqueId,
        technique_name: c.techniqueName,
        analytic_id: c.analyticId,
        analytic_name: c.analyticName,
        matched_log_source: c.matchedLogSource,
        structural_confidence: Math.round(c.structuralScore * 100) / 100,
      })),
    },
    null,
    2
  );

  const systemPrompt = await getActivePrompt('adjudication');
  const result = await callPix(systemPrompt, userContent);
  if (!result.ok) {
    return { selections: [], proposed: [], needsReview: true, reviewReason: result.error, llm: result.meta };
  }

  const parsed = result.data || {};
  const validIds = new Set(candidates.map((c) => c.techniqueId));
  const selections = (parsed.selections || []).filter(
    (s) => s && typeof s.technique_id === 'string' && validIds.has(s.technique_id)
  );
  // Techniques the LLM proposed beyond the candidate list (retrieval missed them). These are
  // NOT trusted yet -- processJob validates every id against the ATT&CK database before use, so
  // a hallucinated or deprecated id can never reach the output.
  const proposed = (parsed.proposed_techniques || []).filter(
    (s) => s && typeof s.technique_id === 'string' && !validIds.has(s.technique_id)
  );

  return {
    selections,
    proposed,
    needsReview: !!parsed.needs_review || (selections.length === 0 && proposed.length === 0),
    reviewReason: parsed.review_reason || (selections.length === 0 && proposed.length === 0 ? 'LLM found no candidate genuinely matched the rule logic.' : ''),
    llm: result.meta,
  };
}

// ---------------------------------------------------------------------------
// QA agent: checks the final mapping against the source rule. Applies no judgement of its own
// about correctness -- it verifies the process ran, rationales are present, and every cited
// piece of evidence actually exists in the source rule (grounding / anti-hallucination check).
// System prompt from the editable registry.
// ---------------------------------------------------------------------------
async function runQa(rule, profile, selections) {
  const userContent = JSON.stringify(
    {
      rule: {
        rule_name: rule.rule_name,
        description: rule.description,
        query: rule.query,
        applicable_datasource: rule.applicable_datasource,
      },
      detection_profile: profile || null,
      final_mapping: {
        selections: (selections || []).map((s) => ({
          technique_id: s.technique_id || s.techniqueId,
          technique_name: s.technique_name || s.techniqueName,
          analytic_id: s.analytic_id || s.analyticId,
          confidence: s.confidence,
          rationale: s.rationale,
        })),
      },
    },
    null,
    2
  );

  const systemPrompt = await getActivePrompt('qa');
  const result = await callPix(systemPrompt, userContent);
  if (!result.ok) {
    return { checks: [], overall: 'error', error: result.error, llm: result.meta };
  }

  const parsed = result.data || {};
  const checks = Array.isArray(parsed.checks) ? parsed.checks : [];
  const overall = parsed.overall === 'pass' && checks.every((c) => c && c.pass) ? 'pass' : (checks.length ? 'fail' : 'error');
  return { checks, overall, llm: result.meta };
}

module.exports = { extractProfile, reasonAboutRule, runQa };
