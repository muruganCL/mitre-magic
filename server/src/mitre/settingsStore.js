const { pool } = require('../db');

// Runtime settings live in the app_settings table and override the matching environment
// variable when set. This lets an admin change the LLM model / gateway / API key in the UI
// without a redeploy. Reads happen at call time so edits take effect on the next LLM call.

async function getSetting(key) {
  const { rows } = await pool.query('SELECT value FROM app_settings WHERE key=$1', [key]);
  return rows[0] ? rows[0].value : null;
}

async function setSetting(key, value, updatedBy) {
  await pool.query(
    `INSERT INTO app_settings (key, value, updated_by, updated_at)
     VALUES ($1,$2,$3,now())
     ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=now()`,
    [key, value, updatedBy || 'admin']
  );
}

// Effective LLM config: DB setting first, then env var, then a sane default. `keySource`
// records where the API key came from so the UI can show it without revealing the value.
async function getLlmConfig() {
  const [dbKey, dbModel, dbBase, dbCache] = await Promise.all([
    getSetting('pix_api_key'),
    getSetting('pix_model'),
    getSetting('pix_base_url'),
    getSetting('pix_cache_enabled'),
  ]);
  const apiKey = dbKey || process.env.PIX_API_KEY || null;
  // Prompt caching defaults ON (the system prompts are large and stable per agent, so caching
  // the prefix cuts cost/latency substantially). Admin can turn it off in the UI.
  const cacheEnabled = dbCache === null ? true : dbCache === 'true';
  return {
    apiKey,
    model: dbModel || process.env.PIX_MODEL || 'claude-opus-4-8',
    baseUrl: dbBase || process.env.PIX_BASE_URL || 'https://pix.positka.net/api/v1',
    cacheEnabled,
    keySource: dbKey ? 'ui' : process.env.PIX_API_KEY ? 'env' : 'none',
    modelSource: dbModel ? 'ui' : 'env',
    baseUrlSource: dbBase ? 'ui' : 'env',
  };
}

// Never return the raw key to the UI -- only a masked hint (last 4 chars).
function maskKey(key) {
  if (!key) return null;
  const last4 = key.slice(-4);
  return `••••••••${last4}`;
}

module.exports = { getSetting, setSetting, getLlmConfig, maskKey };
