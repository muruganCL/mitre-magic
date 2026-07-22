const express = require('express');
const multer = require('multer');
const { parse } = require('csv-parse/sync');

const { pool } = require('../db');
const { requireAuth } = require('../middleware/auth');
const { normalizePlatforms } = require('../mitre/platforms');
const { processJob } = require('../mitre/processJob');
const { computeCoverage } = require('../mitre/coverage');

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
const router = express.Router();

const REQUIRED_COLUMNS = ['rule_name', 'query'];

router.get('/rules/upload', requireAuth, (req, res) => {
  res.render('rules_upload', { user: req.session.user, error: null });
});

router.post('/rules/upload', requireAuth, upload.single('csv'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).render('rules_upload', { user: req.session.user, error: 'Please choose a CSV file.' });
    }

    const text = req.file.buffer.toString('utf8');
    const records = parse(text, {
      columns: (header) => header.map((h) => h.trim().toLowerCase()),
      skip_empty_lines: true,
      trim: true,
    });

    if (records.length === 0) {
      return res.status(400).render('rules_upload', { user: req.session.user, error: 'CSV has no rows.' });
    }

    const headerCols = Object.keys(records[0]);
    const missing = REQUIRED_COLUMNS.filter((c) => !headerCols.includes(c));
    if (missing.length) {
      return res.status(400).render('rules_upload', {
        user: req.session.user,
        error: `CSV is missing required column(s): ${missing.join(', ')}`,
      });
    }

    const jobRes = await pool.query(
      `INSERT INTO upload_jobs (user_id, filename, status, total_rows) VALUES ($1,$2,'processing',$3) RETURNING id`,
      [req.session.user.id, req.file.originalname, records.length]
    );
    const jobId = jobRes.rows[0].id;

    for (const rec of records) {
      const platforms = normalizePlatforms(rec.applicable_datasource);
      await pool.query(
        `INSERT INTO rules (job_id, row_no, rule_name, description, query, cron, timerange, applicable_datasource, applicable_platforms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          jobId,
          rec.no || null,
          rec.rule_name || '(unnamed rule)',
          rec.description || null,
          rec.query || null,
          rec.cron || null,
          rec.timerange || null,
          rec.applicable_datasource || null,
          platforms,
        ]
      );
    }

    // Fire-and-forget: the client tracks progress via /rules/upload/:jobId/status polling.
    processJob(jobId).catch((err) => {
      console.error(`Job ${jobId} failed:`, err);
      pool.query("UPDATE upload_jobs SET status='failed', error=$2 WHERE id=$1", [jobId, err.message]).catch(() => {});
    });

    res.redirect(`/rules/upload/${jobId}`);
  } catch (err) {
    console.error(err);
    res.status(500).render('rules_upload', { user: req.session.user, error: `Upload failed: ${err.message}` });
  }
});

router.get('/rules/upload/:jobId', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM upload_jobs WHERE id=$1 AND user_id=$2', [req.params.jobId, req.session.user.id]);
  const job = rows[0];
  if (!job) return res.status(404).send('Job not found');
  res.render('rules_progress', { user: req.session.user, job });
});

router.get('/rules/upload/:jobId/status', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, status, total_rows, processed_rows, error FROM upload_jobs WHERE id=$1 AND user_id=$2',
    [req.params.jobId, req.session.user.id]
  );
  const job = rows[0];
  if (!job) return res.status(404).json({ error: 'not found' });
  res.json(job);
});

router.get('/rules/upload/:jobId/results', requireAuth, async (req, res) => {
  const { rows: jobRows } = await pool.query('SELECT * FROM upload_jobs WHERE id=$1 AND user_id=$2', [req.params.jobId, req.session.user.id]);
  const job = jobRows[0];
  if (!job) return res.status(404).send('Job not found');

  const { rows } = await pool.query(
    `SELECT r.id AS rule_id, r.rule_name, r.applicable_datasource,
            rtm.technique_id, t.name AS technique_name, rtm.analytic_id, a.name AS analytic_name,
            rtm.matched_platforms, rtm.matched_log_source, rtm.score, rtm.platform_inferred,
            rtm.llm_confidence, rtm.llm_rationale, rtm.llm_selected, rtm.needs_review, rtm.review_reason
     FROM rules r
     LEFT JOIN rule_technique_matches rtm ON rtm.rule_id = r.id
     LEFT JOIN mitre_techniques t ON t.id = rtm.technique_id
     LEFT JOIN mitre_analytics a ON a.id = rtm.analytic_id
     WHERE r.job_id = $1
     ORDER BY r.id, rtm.llm_selected DESC NULLS LAST, rtm.score DESC NULLS LAST`,
    [req.params.jobId]
  );

  const coverage = await computeCoverage(req.params.jobId);

  const { rows: pipelines } = await pool.query(
    `SELECT id, rule_name, query, detected_language, pipeline_debug
     FROM rules WHERE job_id = $1 ORDER BY id`,
    [req.params.jobId]
  );

  // Final mapping: one entry per rule with its rule name, description, the analytic(s) and
  // technique(s) the pipeline actually selected, and the QA verdict.
  const { rows: finalRaw } = await pool.query(
    `SELECT r.id AS rule_id, r.rule_name, r.description, r.qa_result,
            rtm.technique_id, t.name AS technique_name, rtm.analytic_id, a.name AS analytic_name,
            rtm.llm_confidence, rtm.needs_review
     FROM rules r
     LEFT JOIN rule_technique_matches rtm ON rtm.rule_id = r.id AND rtm.llm_selected = true
     LEFT JOIN mitre_techniques t ON t.id = rtm.technique_id
     LEFT JOIN mitre_analytics a ON a.id = rtm.analytic_id
     WHERE r.job_id = $1
     ORDER BY r.id, rtm.llm_confidence DESC NULLS LAST`,
    [req.params.jobId]
  );

  const finalById = new Map();
  for (const row of finalRaw) {
    if (!finalById.has(row.rule_id)) {
      finalById.set(row.rule_id, {
        ruleId: row.rule_id,
        ruleName: row.rule_name,
        description: row.description,
        qa: row.qa_result || null,
        selections: [],
      });
    }
    if (row.technique_id) {
      finalById.get(row.rule_id).selections.push({
        techniqueId: row.technique_id,
        techniqueName: row.technique_name,
        analyticId: row.analytic_id,
        analyticName: row.analytic_name,
        confidence: row.llm_confidence,
      });
    }
  }
  const finalMappings = [...finalById.values()];

  res.render('rules_results', { user: req.session.user, job, rows, coverage, pipelines, finalMappings });
});

module.exports = router;
