(function () {
  const pipelines = window.PIPELINES || [];
  const select = document.getElementById('rule-select');
  const container = document.getElementById('pipeline-inspector');
  if (!select || !container || pipelines.length === 0) {
    if (container) container.innerHTML = '<p class="dim">No rules to inspect.</p>';
    return;
  }

  for (const p of pipelines) {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.rule_name;
    select.appendChild(opt);
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[c]);
  }

  function pct(n) {
    return n === null || n === undefined ? '' : Math.round(n * 100) + '%';
  }

  function chipGroup(label, values) {
    if (!values || !values.length) return '';
    return `<div style="margin-bottom: 8px;"><span class="dim" style="text-transform: uppercase; font-size: 10px; letter-spacing: 0.4px;">${esc(
      label
    )}</span><div class="token-chips" style="margin-top: 4px;">${values
      .map((v) => `<span class="token-chip">${esc(v)}</span>`)
      .join('')}</div></div>`;
  }

  function renderDetectionProfile(profile, profileError) {
    if (!profile) {
      return `<p class="dim">No LLM detection profile for this rule${
        profileError ? ` (${esc(profileError)})` : ''
      }. Search fell back to the raw query text.</p>`;
    }
    const entityValues = profile.entities
      ? Object.entries(profile.entities).map(([k, v]) => `${k}: ${v}`)
      : [];
    let html = '';
    if (profile.analytic_intent) {
      html += `<div style="margin-bottom: 12px;"><span class="dim" style="text-transform: uppercase; font-size: 10px; letter-spacing: 0.4px;">analytic intent</span><div style="margin-top: 4px; font-style: italic;">${esc(
        profile.analytic_intent
      )}</div></div>`;
    }
    html += chipGroup('behavior', profile.behavior);
    html += chipGroup('entities', entityValues);
    html += chipGroup('telemetry', profile.telemetry);
    html += chipGroup('platforms', profile.platforms);
    return html || '<p class="dim">Profile was empty.</p>';
  }

  function methodBadge(method) {
    if (!method) return '';
    const cls = method === 'inference' ? 'state-partial' : method === 'dictionary' ? 'state-covered' : '';
    return `<span class="state-badge ${cls}" style="font-size:9.5px; padding:2px 7px;">${esc(method)}</span>`;
  }

  function renderTokens(tokens) {
    if (!tokens || tokens.length === 0) return '<p class="dim">No sourcetype/EventCode/datamodel/event_simpleName/macro signal found in this query.</p>';
    const rows = tokens
      .map((t) => {
        const note = t.assumption
          ? `<div class="dim" style="margin-top:3px;"><em>assumption:</em> ${esc(t.assumption)}</div>`
          : t.dataset
          ? `<div class="dim" style="margin-top:3px;">dataset hint: ${esc(t.dataset)}</div>`
          : '';
        return `<tr>
          <td><span class="token-chip token-chip-${esc(t.type)}">${esc(t.type)}</span></td>
          <td><code>${esc(t.value)}</code>${note}</td>
          <td>${methodBadge(t.method)}</td>
          <td><code class="dim">${esc(t.evidence || '')}</code></td>
        </tr>`;
      })
      .join('');
    return `<table class="data-table"><thead><tr><th>Signal</th><th>Value / assumption</th><th>Method</th><th>Evidence in query</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  function renderSignalResults(signalResults) {
    if (!signalResults || signalResults.length === 0) return '';
    return signalResults
      .map((sig) => {
        const rows = sig.results
          .map((r) => {
            const excluded = r.kept === false;
            let tag = '';
            if (r.datasourceConsistent === false && !excluded) tag = ' <span class="dim">(orphan kept)</span>';
            else if (r.datasourceConsistent === false) tag = ' <span class="dim">(off data source)</span>';
            const rowStyle = excluded ? ' style="opacity: 0.4;"' : '';
            const logCell = excluded
              ? `${esc(r.matchedLogSource)} <span class="dim">— excluded</span>`
              : `${esc(r.matchedLogSource)}${tag}`;
            return `<tr${rowStyle}><td>${esc(r.analyticName)} <span class="dim">(${esc(r.analyticId)})</span></td>
              <td>${esc(r.techniqueName)} <span class="dim">(${esc(r.techniqueId)})</span></td>
              <td>${logCell}</td><td>${pct(r.score)}</td></tr>`;
          })
          .join('');
        const truncatedNote =
          sig.resultCount > sig.results.length
            ? `<p class="dim" style="margin: 6px 0 0;">Showing ${sig.results.length} of ${sig.resultCount} matches.</p>`
            : '';
        return `
          <div class="stage-block">
            <p class="stage-block-label">Token: <strong>${esc(sig.token.type)}</strong> = <code>${esc(sig.token.value)}</code>${
          sig.token.source ? ` <span class="dim">(from ${esc(sig.token.source)})</span>` : ''
        } &mdash; ${sig.resultCount} analytic match(es)</p>
            ${
              sig.results.length
                ? `<table class="data-table"><thead><tr><th>Analytic</th><th>Technique</th><th>Log Source</th><th>Score</th></tr></thead><tbody>${rows}</tbody></table>`
                : '<p class="dim">No analytics matched this token.</p>'
            }
            ${truncatedNote}
          </div>`;
      })
      .join('');
  }

  function renderRankedCandidates(candidates) {
    if (!candidates || candidates.length === 0) return '<p class="dim">No candidates survived to ranking.</p>';
    const rows = candidates
      .map(
        (c) => `<tr><td>${esc(c.techniqueName)} <span class="dim">(${esc(c.techniqueId)})</span></td>
          <td>${esc(c.analyticName)} <span class="dim">(${esc(c.analyticId)})</span></td>
          <td>${esc(c.matchedLogSource)}</td><td>${(c.platforms || []).join(', ')}</td><td>${pct(c.structuralScore)}</td></tr>`
      )
      .join('');
    return `<table class="data-table"><thead><tr><th>Technique</th><th>Analytic</th><th>Log Source</th><th>Platforms</th><th>Structural Score</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  function renderLlm(llm) {
    if (!llm) return '<p class="dim">LLM was not called (no candidates reached this stage).</p>';
    const resp = llm.response || {};
    const selectedIds = new Set((resp.selections || []).map((s) => s.technique_id));
    const banner = resp.needsReview
      ? `<p><span class="state-badge state-partial">Needs Review</span> ${esc(resp.reviewReason)}</p>`
      : `<p><span class="state-badge state-covered">Confirmed</span> LLM selected ${selectedIds.size} technique(s) without reservation.</p>`;
    const rows = (llm.request || [])
      .map((c) => {
        const sel = (resp.selections || []).find((s) => s.technique_id === c.techniqueId);
        return `<tr><td>${esc(c.techniqueName)} <span class="dim">(${esc(c.techniqueId)})</span></td>
          <td>${selectedIds.has(c.techniqueId) ? '<span class="state-badge state-covered">Picked</span>' : '<span class="dim">Not picked</span>'}</td>
          <td>${sel ? pct(sel.confidence) : ''}</td>
          <td style="max-width: 360px;">${sel ? esc(sel.rationale) : ''}</td></tr>`;
      })
      .join('');
    return `${banner}<table class="data-table"><thead><tr><th>Candidate Sent</th><th>Verdict</th><th>Confidence</th><th>Rationale</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  function render(ruleId) {
    const p = pipelines.find((x) => String(x.id) === String(ruleId));
    if (!p) {
      container.innerHTML = '<p class="dim">Rule not found.</p>';
      return;
    }
    const dbg = p.pipeline_debug;
    if (!dbg) {
      container.innerHTML = `<p class="dim">No pipeline data captured for this rule (it may have failed during processing).</p>`;
      return;
    }

    container.innerHTML = `
      <div class="stage-block">
        <p class="stage-block-label">Query <span class="dim">(detected language: ${esc(p.detected_language || 'unknown')})</span></p>
        <pre class="query-block">${esc(p.query)}</pre>
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 1 &middot; Detection Profile <span class="dim">(LLM-extracted)</span></p>
        ${renderDetectionProfile(dbg.detectionProfile, dbg.profileError)}
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 2 &middot; Extracted Signals <span class="dim">(query tokens + telemetry)</span></p>
        ${renderTokens(dbg.tokens)}
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 3 &middot; Structural Matches (per signal) <span class="dim">(filtered to declared data sources; off-datasource rows excluded unless they're a technique's only evidence)</span></p>
        ${renderSignalResults(dbg.signalResults)}
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 4 &middot; Ranked Candidates (sent to LLM)</p>
        ${renderRankedCandidates(dbg.rankedCandidates)}
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 5 &middot; LLM Adjudication</p>
        ${renderLlm(dbg.llm)}
      </div>
    `;
  }

  select.addEventListener('change', () => render(select.value));
  render(pipelines[0].id);
})();
