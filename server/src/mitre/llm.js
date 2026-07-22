const PIX_BASE_URL = process.env.PIX_BASE_URL || 'https://pix.positka.net/api/v1';
const PIX_API_KEY = process.env.PIX_API_KEY;
const PIX_MODEL = process.env.PIX_MODEL || 'claude-opus-4-5';

function stripCodeFences(text) {
  return text
    .trim()
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/, '')
    .replace(/```\s*$/, '');
}

// Shared Pix call. Returns { ok, data } or { ok:false, error }. The system prompt is passed
// per-call but is stable per task, so the gateway caches its prefix (cache:true).
async function callPix(systemPrompt, userContent) {
  if (!PIX_API_KEY) return { ok: false, error: 'PIX_API_KEY not configured' };

  let res;
  try {
    res = await fetch(`${PIX_BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${PIX_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: PIX_MODEL,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userContent },
        ],
        cache: true,
      }),
    });
  } catch (err) {
    return { ok: false, error: `LLM call failed: ${err.message}` };
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    return { ok: false, error: `LLM gateway returned ${res.status}: ${text.slice(0, 200)}` };
  }

  const data = await res.json();
  const raw = data.choices?.[0]?.message?.content || '';
  try {
    return { ok: true, data: JSON.parse(stripCodeFences(raw)) };
  } catch (err) {
    return { ok: false, error: `Could not parse LLM response as JSON: ${raw.slice(0, 200)}` };
  }
}

// ---------------------------------------------------------------------------
// Stage 1: extract a normalized, ATT&CK-aligned detection profile from the rule.
// This runs BEFORE search and its terms drive the search -- the point is to translate
// vendor-specific query syntax (Splunk data models, CrowdStrike event names) into the
// generic behavioral/telemetry vocabulary ATT&CK actually uses, so keyword search over the
// ATT&CK corpus lands on the right techniques.
// ---------------------------------------------------------------------------
const PROFILE_SYSTEM_PROMPT = `You are a detection-engineering assistant. Given a SIEM detection rule (name, description, query, and declared platforms), extract a concise, normalized "detection profile" describing WHAT the rule detects, independent of vendor-specific query syntax. This profile is used to search the MITRE ATT&CK knowledge base, so use ATT&CK-aligned language.

Respond with ONLY valid JSON, no markdown fences, no prose outside the JSON, in exactly this shape:
{
  "behavior": ["short ATT&CK-style phrase describing an adversary behavior the rule detects", ...],
  "entities": { "<entity_type>": "<normalized entity>" },
  "telemetry": ["normalized telemetry/log source category", ...],
  "platforms": ["platform the behavior applies to"],
  "analytic_intent": "one sentence stating what the rule is trying to detect"
}

Guidance:
- behavior: 1-5 items, phrased in ATT&CK terms (e.g. "Authentication using expired account", "Use of default credentials", "Process injection via remote thread creation"), NOT the rule's literal field names. Describe the adversary behavior, not the query mechanics.
- entities: the key security objects involved, normalized (e.g. {"identity": "User Account", "process": "powershell.exe"}). Omit if none are clear.
- telemetry: translate vendor telemetry (Splunk data models like Authentication/Identity_Management, CrowdStrike event_simpleName) into generic categories such as "Authentication Logs", "Identity Provider Logs", "Process Creation Logs", "Network Connection Logs".
- platforms: use MITRE platform names where possible (Windows, Linux, macOS, Identity Provider, SaaS, IaaS, Office Suite, Containers, Network Devices, ESXi).
- analytic_intent: a single crisp sentence.
- Do not invent behaviors the rule does not support. Keep everything concise.`;

function asStringArray(v) {
  if (!Array.isArray(v)) return [];
  return v.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim());
}

async function extractProfile(rule) {
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

  const result = await callPix(PROFILE_SYSTEM_PROMPT, userContent);
  if (!result.ok) {
    return { profile: null, error: result.error };
  }

  const p = result.data || {};
  const profile = {
    behavior: asStringArray(p.behavior),
    entities: p.entities && typeof p.entities === 'object' && !Array.isArray(p.entities) ? p.entities : {},
    telemetry: asStringArray(p.telemetry),
    platforms: asStringArray(p.platforms),
    analytic_intent: typeof p.analytic_intent === 'string' ? p.analytic_intent.trim() : '',
  };
  return { profile, error: null };
}

// ---------------------------------------------------------------------------
// Stage 5: adjudicate the structurally-ranked candidates.
// ---------------------------------------------------------------------------
const ADJUDICATION_SYSTEM_PROMPT = `You are a detection-engineering assistant mapping SIEM detection rules to MITRE ATT&CK techniques (Enterprise v19.1).

You will be given a JSON object with:
- "rule": the rule's name, description, SPL/CQL query, and declared platforms.
- "detection_profile": a normalized profile of what the rule detects (behaviors, entities, telemetry, intent).
- "candidates": a short list of technique candidates found by a structural search over MITRE ATT&CK v19.1 analytics. Each includes the analytic that matched, the log source evidence, and a structural_confidence (0-1).

Your job: read the rule's actual detection logic (query + profile) and decide which candidate(s), if any, the rule genuinely detects.

Rules you must follow:
- Choose ONLY from the candidate technique_id values given to you. Never invent, guess, or recall a technique ID from your own training -- if none of the candidates genuinely fit, return an empty selections array.
- A rule can legitimately support more than one candidate technique; do not force a single pick if several are truly justified. Equally, do not pick a candidate just because its log source matched -- the rule's actual behavior must plausibly detect that technique.
- If you are unsure, or the rule's real behavior does not clearly match any candidate well, set needs_review to true and explain why in review_reason. It is better to defer to a human analyst than to force a confident-looking wrong answer.
- confidence is your own calibrated judgment (0.0-1.0) of how well the rule's actual behavior supports each selected technique.

Respond with ONLY valid JSON, no markdown code fences, no prose outside the JSON, in exactly this shape:
{
  "selections": [
    { "technique_id": "T1234.001", "confidence": 0.0, "rationale": "one or two sentences citing the rule's actual behavior" }
  ],
  "needs_review": false,
  "review_reason": ""
}`;

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

  const result = await callPix(ADJUDICATION_SYSTEM_PROMPT, userContent);
  if (!result.ok) {
    return { selections: [], needsReview: true, reviewReason: result.error };
  }

  const parsed = result.data || {};
  const validIds = new Set(candidates.map((c) => c.techniqueId));
  const selections = (parsed.selections || []).filter(
    (s) => s && typeof s.technique_id === 'string' && validIds.has(s.technique_id)
  );

  return {
    selections,
    needsReview: !!parsed.needs_review || selections.length === 0,
    reviewReason: parsed.review_reason || (selections.length === 0 ? 'LLM found no candidate genuinely matched the rule logic.' : ''),
  };
}

module.exports = { extractProfile, reasonAboutRule };
