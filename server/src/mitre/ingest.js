require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { pool } = require('../db');

function externalId(obj) {
  const ref = (obj.external_references || []).find((r) => r.source_name === 'mitre-attack');
  return ref ? ref.external_id : null;
}

async function run() {
  const jsonPath = process.argv[2];
  if (!jsonPath) {
    console.error('Usage: node src/mitre/ingest.js <path-to-enterprise-attack.json>');
    process.exit(1);
  }

  console.log(`Reading ${jsonPath} ...`);
  const bundle = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  const objects = bundle.objects || bundle;
  console.log(`Loaded ${objects.length} STIX objects.`);

  const schemaSql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schemaSql);
  console.log('Schema ensured.');

  const tactics = objects.filter((o) => o.type === 'x-mitre-tactic');
  const techniques = objects.filter((o) => o.type === 'attack-pattern');
  const dataSources = objects.filter((o) => o.type === 'x-mitre-data-source');
  const dataComponents = objects.filter((o) => o.type === 'x-mitre-data-component');
  const analytics = objects.filter((o) => o.type === 'x-mitre-analytic');
  const detectionStrategies = objects.filter((o) => o.type === 'x-mitre-detection-strategy');
  const relationships = objects.filter((o) => o.type === 'relationship');

  // stix_id -> external_id maps, per type, for resolving refs/relationships later
  const techniqueIdByStix = new Map();
  const tacticShortnameToId = new Map();
  const dataComponentIdByStix = new Map();
  const analyticIdByStix = new Map();
  const detectionStrategyIdByStix = new Map();

  for (const t of tactics) {
    const id = externalId(t);
    if (id) tacticShortnameToId.set(t.x_mitre_shortname, id);
  }
  for (const t of techniques) {
    const id = externalId(t);
    if (id) techniqueIdByStix.set(t.id, id);
  }
  for (const dc of dataComponents) {
    const id = externalId(dc);
    if (id) dataComponentIdByStix.set(dc.id, id);
  }
  for (const a of analytics) {
    const id = externalId(a);
    if (id) analyticIdByStix.set(a.id, id);
  }
  for (const ds of detectionStrategies) {
    const id = externalId(ds);
    if (id) detectionStrategyIdByStix.set(ds.id, id);
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    console.log(`Upserting ${tactics.length} tactics ...`);
    for (const t of tactics) {
      const id = externalId(t);
      if (!id) continue;
      await client.query(
        `INSERT INTO mitre_tactics (id, stix_id, name, shortname, description, deprecated)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (id) DO UPDATE SET stix_id=$2, name=$3, shortname=$4, description=$5, deprecated=$6`,
        [id, t.id, t.name, t.x_mitre_shortname, t.description || null, !!t.x_mitre_deprecated]
      );
    }

    console.log(`Upserting ${techniques.length} techniques ...`);
    for (const t of techniques) {
      const id = externalId(t);
      if (!id) continue;
      await client.query(
        `INSERT INTO mitre_techniques (id, stix_id, name, description, is_subtechnique, platforms, revoked, deprecated, modified)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (id) DO UPDATE SET stix_id=$2, name=$3, description=$4, is_subtechnique=$5, platforms=$6, revoked=$7, deprecated=$8, modified=$9`,
        [
          id,
          t.id,
          t.name,
          t.description || null,
          !!t.x_mitre_is_subtechnique,
          t.x_mitre_platforms || [],
          !!t.revoked,
          !!t.x_mitre_deprecated,
          t.modified || null,
        ]
      );
    }

    console.log('Linking sub-techniques to parents ...');
    const subOfRels = relationships.filter((r) => r.relationship_type === 'subtechnique-of');
    for (const r of subOfRels) {
      const childId = techniqueIdByStix.get(r.source_ref);
      const parentId = techniqueIdByStix.get(r.target_ref);
      if (!childId || !parentId) continue;
      await client.query(`UPDATE mitre_techniques SET parent_technique_id=$1 WHERE id=$2`, [parentId, childId]);
    }

    console.log('Linking techniques to tactics (kill chain phases) ...');
    for (const t of techniques) {
      const id = externalId(t);
      if (!id) continue;
      for (const phase of t.kill_chain_phases || []) {
        if (phase.kill_chain_name !== 'mitre-attack') continue;
        const tacticId = tacticShortnameToId.get(phase.phase_name);
        if (!tacticId) continue;
        await client.query(
          `INSERT INTO mitre_technique_tactics (technique_id, tactic_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
          [id, tacticId]
        );
      }
    }

    console.log(`Upserting ${dataSources.length} data sources ...`);
    for (const ds of dataSources) {
      const id = externalId(ds);
      if (!id) continue;
      await client.query(
        `INSERT INTO mitre_data_sources (id, stix_id, name, description, platforms, deprecated)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (id) DO UPDATE SET stix_id=$2, name=$3, description=$4, platforms=$5, deprecated=$6`,
        [id, ds.id, ds.name, ds.description || null, ds.x_mitre_platforms || [], !!ds.x_mitre_deprecated]
      );
    }

    console.log(`Upserting ${dataComponents.length} data components ...`);
    for (const dc of dataComponents) {
      const id = externalId(dc);
      if (!id) continue;
      await client.query(
        `INSERT INTO mitre_data_components (id, stix_id, name, description, revoked, deprecated)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (id) DO UPDATE SET stix_id=$2, name=$3, description=$4, revoked=$5, deprecated=$6`,
        [id, dc.id, dc.name, dc.description || null, !!dc.revoked, !!dc.x_mitre_deprecated]
      );
      await client.query(`DELETE FROM mitre_data_component_log_sources WHERE data_component_id=$1`, [id]);
      for (const ls of dc.x_mitre_log_sources || []) {
        await client.query(
          `INSERT INTO mitre_data_component_log_sources (data_component_id, log_source_name, channel) VALUES ($1,$2,$3)`,
          [id, ls.name || null, ls.channel || null]
        );
      }
    }

    console.log(`Upserting ${analytics.length} analytics ...`);
    for (const a of analytics) {
      const id = externalId(a);
      if (!id) continue;
      await client.query(
        `INSERT INTO mitre_analytics (id, stix_id, name, description, platforms, deprecated)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (id) DO UPDATE SET stix_id=$2, name=$3, description=$4, platforms=$5, deprecated=$6`,
        [id, a.id, a.name, a.description || null, a.x_mitre_platforms || [], !!a.x_mitre_deprecated]
      );
      await client.query(`DELETE FROM mitre_analytic_log_sources WHERE analytic_id=$1`, [id]);
      for (const ref of a.x_mitre_log_source_references || []) {
        const dcId = dataComponentIdByStix.get(ref.x_mitre_data_component_ref) || null;
        await client.query(
          `INSERT INTO mitre_analytic_log_sources (analytic_id, data_component_id, log_source_name, channel) VALUES ($1,$2,$3,$4)`,
          [id, dcId, ref.name || null, ref.channel || null]
        );
      }
    }

    console.log(`Upserting ${detectionStrategies.length} detection strategies ...`);
    for (const ds of detectionStrategies) {
      const id = externalId(ds);
      if (!id) continue;
      await client.query(
        `INSERT INTO mitre_detection_strategies (id, stix_id, name, description, deprecated)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (id) DO UPDATE SET stix_id=$2, name=$3, description=$4, deprecated=$5`,
        [id, ds.id, ds.name, ds.description || null, !!ds.x_mitre_deprecated]
      );
      await client.query(`DELETE FROM mitre_detection_strategy_analytics WHERE detection_strategy_id=$1`, [id]);
      for (const analyticStixRef of ds.x_mitre_analytic_refs || []) {
        const analyticId = analyticIdByStix.get(analyticStixRef);
        if (!analyticId) continue;
        await client.query(
          `INSERT INTO mitre_detection_strategy_analytics (detection_strategy_id, analytic_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
          [id, analyticId]
        );
      }
    }

    console.log('Linking detection strategies to techniques (detects) ...');
    const detectsRels = relationships.filter((r) => r.relationship_type === 'detects');
    for (const r of detectsRels) {
      const dsId = detectionStrategyIdByStix.get(r.source_ref);
      const techId = techniqueIdByStix.get(r.target_ref);
      if (!dsId || !techId) continue;
      await client.query(
        `INSERT INTO mitre_detects (detection_strategy_id, technique_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
        [dsId, techId]
      );
    }

    await client.query('COMMIT');
    console.log('Ingest complete.');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  await pool.end();
}

run().catch((err) => {
  console.error('Ingest failed:', err);
  process.exit(1);
});
