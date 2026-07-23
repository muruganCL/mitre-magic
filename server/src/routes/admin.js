const express = require('express');
const { parse } = require('csv-parse/sync');
const { requireAdmin } = require('../middleware/auth');
const { listActivePrompts, saveNewVersion, AGENT_ORDER, listVersions, getVersionBody } = require('../mitre/promptStore');
const { getLlmConfig, setSetting, maskKey } = require('../mitre/settingsStore');
const { extractProfile } = require('../mitre/llm');

const router = express.Router();

const SAMPLE_RULES_CSV = `rule_name,description,query,applicable_datasource
Windows AD add Self to Group,detects when a user adds themselves to an Active Directory group (privilege escalation),\`wineventlog_security\` EventCode IN (4728) | where lower(user)=lower(src_user),Windows
Encrypted C2 to new external IP,detects new outbound TLS sessions to external IPs with no prior history,#repo=aws_vpc_flow_logs | dstport in [443 8443] | session_count < 5,VPC Flow Logs`;

const MAX_COMPARE_RULES = 4;

router.get('/admin', requireAdmin, (req, res) => {
  res.redirect('/admin/prompts');
});

router.get('/admin/llm', requireAdmin, async (req, res) => {
  const cfg = await getLlmConfig();
  res.render('admin_llm', {
    user: req.session.user,
    cfg,
    maskedKey: maskKey(cfg.apiKey),
    saved: req.query.saved || null,
  });
});

router.post('/admin/llm', requireAdmin, async (req, res) => {
  const model = (req.body.model || '').trim();
  const baseUrl = (req.body.base_url || '').trim();
  const apiKey = (req.body.api_key || '').trim();
  const by = req.session.user.username;

  if (model) await setSetting('pix_model', model, by);
  if (baseUrl) await setSetting('pix_base_url', baseUrl, by);
  // Only overwrite the key when a new value is actually entered; blank means "keep current".
  if (apiKey) await setSetting('pix_api_key', apiKey, by);

  res.redirect('/admin/llm?saved=1');
});

router.get('/admin/prompts', requireAdmin, async (req, res) => {
  const prompts = await listActivePrompts();
  res.render('admin_prompts', { user: req.session.user, prompts, saved: req.query.saved || null });
});

// Outcome comparison for the detection-profile prompt: run two versions against a small set of
// sample rules and show the resulting profiles side by side, so a prompt change can be judged
// before it's made active. (This agent runs standalone; adjudication/QA need a full pipeline
// run and are a later addition.)
router.get('/admin/prompts/compare', requireAdmin, async (req, res) => {
  const versions = await listVersions('detection_profile');
  res.render('admin_compare', {
    user: req.session.user,
    versions,
    versionA: versions.find((v) => !v.is_active)?.version ?? versions[0]?.version,
    versionB: versions.find((v) => v.is_active)?.version ?? versions[0]?.version,
    sampleCsv: SAMPLE_RULES_CSV,
    results: null,
    error: null,
  });
});

router.post('/admin/prompts/compare', requireAdmin, async (req, res) => {
  const versions = await listVersions('detection_profile');
  const versionA = parseInt(req.body.version_a, 10);
  const versionB = parseInt(req.body.version_b, 10);
  const sampleCsv = req.body.sample_csv || '';

  const render = (extra) =>
    res.render('admin_compare', {
      user: req.session.user,
      versions,
      versionA,
      versionB,
      sampleCsv,
      results: null,
      error: null,
      ...extra,
    });

  let records;
  try {
    records = parse(sampleCsv, { columns: (h) => h.map((x) => x.trim().toLowerCase()), skip_empty_lines: true, trim: true });
  } catch (err) {
    return render({ error: `Could not parse sample rules: ${err.message}` });
  }
  if (!records.length) return render({ error: 'Provide at least one sample rule.' });

  const bodyA = await getVersionBody('detection_profile', versionA);
  const bodyB = await getVersionBody('detection_profile', versionB);
  if (!bodyA || !bodyB) return render({ error: 'Selected prompt version not found.' });

  const results = [];
  for (const rec of records.slice(0, MAX_COMPARE_RULES)) {
    const rule = {
      rule_name: rec.rule_name || '(unnamed)',
      description: rec.description || '',
      query: rec.query || '',
      applicable_datasource: rec.applicable_datasource || '',
    };
    const [a, b] = await Promise.all([extractProfile(rule, bodyA), extractProfile(rule, bodyB)]);
    results.push({ rule, a: a.profile, aError: a.error || null, b: b.profile, bError: b.error || null });
  }

  render({ results });
});

// Defined AFTER the /admin/prompts/compare routes so ":agentKey" doesn't capture "compare".
router.post('/admin/prompts/:agentKey', requireAdmin, async (req, res) => {
  const { agentKey } = req.params;
  if (!AGENT_ORDER.includes(agentKey)) {
    return res.status(400).send('Unknown agent');
  }
  const body = (req.body.body || '').trim();
  if (!body) {
    return res.redirect('/admin/prompts?saved=empty');
  }
  await saveNewVersion(agentKey, body, req.session.user.username);
  res.redirect(`/admin/prompts?saved=${encodeURIComponent(agentKey)}`);
});

module.exports = router;
