const express = require('express');
const { requireAdmin } = require('../middleware/auth');
const { listActivePrompts, saveNewVersion, AGENT_ORDER } = require('../mitre/promptStore');
const { getLlmConfig, setSetting, maskKey } = require('../mitre/settingsStore');

const router = express.Router();

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
