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
    if (profile.queryLogic && profile.queryLogic.implementsDescribedBehavior !== null) {
      const ok = profile.queryLogic.implementsDescribedBehavior;
      html += `<div class="stage-block" style="margin-top:0; padding-top:0; border-top:none; margin-bottom:12px;">
        <span class="dim" style="text-transform: uppercase; font-size: 10px; letter-spacing: 0.4px;">query logic</span>
        <div style="margin-top:4px;">
          <span class="state-badge ${ok ? 'state-covered' : 'state-blind'}">${ok ? 'Implements described behavior' : 'Does not implement described behavior'}</span>
          ${profile.queryLogic.assessment ? `<div class="dim" style="margin-top:6px;">${esc(profile.queryLogic.assessment)}</div>` : ''}
        </div>
      </div>`;
    }
    html += chipGroup('behavior', profile.behavior);
    html += chipGroup('entities', entityValues);
    html += chipGroup('telemetry', profile.telemetry);
    html += chipGroup('platforms', profile.platforms);

    if (Array.isArray(profile.audit) && profile.audit.length) {
      const rows = profile.audit
        .map((a) => {
          const inferred = /^inferred/i.test(a.evidence || '');
          return `<tr>
            <td><span class="dim">${esc(a.field)}</span></td>
            <td>${esc(a.value)}</td>
            <td>${inferred ? '<span class="dim"><em>' + esc(a.evidence) + '</em></span>' : '“' + esc(a.evidence) + '”'}</td>
            <td class="dim">${esc(a.reasoning)}</td>
          </tr>`;
        })
        .join('');
      html += `<div style="margin-top:14px;">
        <span class="dim" style="text-transform: uppercase; font-size: 10px; letter-spacing: 0.4px;">Audit — evidence per item</span>
        <table class="data-table" style="margin-top:6px;"><thead><tr><th>Field</th><th>Value</th><th>Evidence in rule</th><th>Reasoning</th></tr></thead><tbody>${rows}</tbody></table>
      </div>`;
    }
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

  // Static explanations of the Stage 3 / Stage 4 scoring logic, shown inline so a reviewer can
  // see why a candidate scored the way it did without reading match.js. Kept in sync by hand
  // with the base scores / weights in server/src/mitre/match.js -- update both together.
  const STAGE3_SCORING_NOTE = `
    <div class="scoring-note">
      <strong>How Stage 3 scores are computed.</strong> Each signal type (the "Token" rows below) is a different
      kind of evidence linking the rule to a technique, and starts from a different base confidence depending on
      how strong that kind of evidence is on its own. A full-text relevance boost is then added on top, comparing
      the rule's own wording (name, description, LLM-extracted profile) against each candidate's analytic text and
      technique text.
      <ul>
        <li><strong>eventcode</strong> &mdash; base <strong>95%</strong>. An exact, unambiguous match on a numeric event ID / channel.</li>
        <li><strong>behavior</strong> &mdash; up to <strong>90%</strong>, scaled by how closely an LLM-extracted behavior phrase
          (e.g. &ldquo;command and control over non-standard port&rdquo;) matches a technique's own ATT&amp;CK name
          (e.g. &ldquo;Non-Standard Port&rdquo;), via trigram <code>word_similarity</code>. This is what lets a technique whose
          name is itself a behavioral description get surfaced even when its analytic text shares little vocabulary with the rule.</li>
        <li><strong>artifact</strong> &mdash; base <strong>70%</strong>. A specific technical term from the detection profile
          (e.g. <code>EncodedCommand</code>, <code>Base64</code>) found directly in a log source's channel text.</li>
        <li><strong>concept / telemetry / datamodel</strong> &mdash; base <strong>35%</strong>, plus up to +25% each from
          analytic-text and technique-text relevance. Deliberately the lowest base: this signal only proves the technique
          shares a broad MITRE data component (e.g. &ldquo;Network Traffic Flow&rdquo;) with dozens of others, so real
          discrimination has to come from the relevance boost or from a more precise signal also matching.</li>
        <li><strong>source</strong> (fuzzy log-source name) &mdash; up to <strong>50%</strong> from trigram similarity to a
          known log source name, plus a small relevance nudge.</li>
      </ul>
      Scores are capped at 100% for display. Rows marked <span class="dim">(off data source)</span> matched structurally but
      have no platform overlap with the rule's declared data source and were excluded here; <span class="dim">(orphan kept)</span>
      means it's a technique's only evidence and was kept anyway (see Stage 4).
    </div>`;

  const STAGE4_SCORING_NOTE = `
    <div class="scoring-note">
      <strong>How Stage 4 ranking works.</strong> Every (technique, analytic) pair scored in Stage 3, across all signals,
      is collapsed to one representative row per <strong>technique</strong>: whichever analytic scored highest is shown,
      preferring one whose platform overlaps the rule's declared data source when one exists. If a technique has
      <strong>no</strong> platform-matching analytic at all, its single best analytic is still kept &mdash; flagged
      <span class="dim">off-datasource</span> &mdash; but its score is multiplied by <strong>0.85</strong> (an "orphan"
      penalty) rather than dropped outright, so a genuinely correct but low-coverage technique still reaches the LLM,
      just ranked slightly lower. Techniques are then sorted by this final score and the top 10 are sent to the LLM for
      adjudication in Stage 5 &mdash; that cap only bounds prompt size/cost, not which techniques are eligible, since the
      ranking itself is already meaningful by this point.
    </div>`;

  function breakdownCell(b) {
    if (!b) return '';
    const parts = [];
    if (b.base != null) parts.push(`base ${b.base.toFixed(2)}${b.baseReason ? ' <span class="dim">(' + esc(b.baseReason) + ')</span>' : ''}`);
    if (b.analyticFts) parts.push(`+${b.analyticFts.toFixed(2)} analytic text`);
    if (b.techniqueFts) parts.push(`+${b.techniqueFts.toFixed(2)} technique text`);
    if (b.datasourceConsistent === false) parts.push('<span class="dim">off-datasource</span>');
    return `<div class="dim" style="margin-top:3px; font-size:11.5px;">${parts.join(' · ')}</div>`;
  }

  function renderRankedCandidates(candidates) {
    if (!candidates || candidates.length === 0) return '<p class="dim">No candidates survived to ranking.</p>';
    const rows = candidates
      .map(
        (c) => `<tr><td>${esc(c.techniqueName)} <span class="dim">(${esc(c.techniqueId)})</span></td>
          <td>${esc(c.analyticName)} <span class="dim">(${esc(c.analyticId)})</span></td>
          <td>${esc(c.matchedLogSource)}</td><td>${(c.platforms || []).join(', ')}</td>
          <td>${pct(c.structuralScore)}${breakdownCell(c.scoreBreakdown)}</td></tr>`
      )
      .join('');
    return `<table class="data-table"><thead><tr><th>Technique</th><th>Analytic</th><th>Log Source</th><th>Platforms</th><th>Structural Score &amp; breakdown</th></tr></thead><tbody>${rows}</tbody></table>`;
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

  // Collapsible raw request/response for one LLM call, so the exact prompt and model output
  // are inspectable without cluttering the stage.
  function renderRawLlm(call, label) {
    if (!call) return '';
    const usage = call.usage
      ? ` <span class="dim">· ${call.usage.total_tokens || (call.usage.prompt_tokens || 0) + (call.usage.completion_tokens || 0) || '?'} tokens${
          call.usage.prompt_tokens_details && call.usage.prompt_tokens_details.cached_tokens
            ? ', ' + call.usage.prompt_tokens_details.cached_tokens + ' cached'
            : ''
        }</span>`
      : '';
    return `<details class="raw-llm">
      <summary>Raw ${esc(label)} LLM call <span class="dim">— ${esc(call.model || '')}</span>${usage}</summary>
      <div class="raw-llm-body">
        <div class="raw-llm-part"><span class="dim">System prompt</span><pre class="query-block">${esc(call.systemPrompt || '')}</pre></div>
        <div class="raw-llm-part"><span class="dim">User message</span><pre class="query-block">${esc(call.userContent || '')}</pre></div>
        <div class="raw-llm-part"><span class="dim">Model response</span><pre class="query-block">${esc(call.rawResponse || '(none)')}</pre></div>
      </div>
    </details>`;
  }

  function renderQa(qa, call) {
    let html = '';
    if (qa && Array.isArray(qa.checks) && qa.checks.length) {
      const rows = qa.checks
        .map((c) => `<tr>
          <td><code>${esc(c.id)}</code></td>
          <td>${c.pass ? '<span class="state-badge state-covered">Pass</span>' : '<span class="state-badge state-blind">Fail</span>'}</td>
          <td style="max-width:520px;">${esc(c.detail || '')}</td></tr>`)
        .join('');
      html += `<p>Overall: ${qa.overall === 'pass' ? '<span class="state-badge state-covered">Pass</span>' : '<span class="state-badge state-blind">' + esc(qa.overall) + '</span>'}</p>
        <table class="data-table"><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
    } else {
      html += '<p class="dim">No QA result captured.</p>';
    }
    html += renderRawLlm(call, 'QA');
    return html;
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
    const calls = dbg.llmCalls || {};

    container.innerHTML = `
      <div class="stage-block">
        <p class="stage-block-label">Query <span class="dim">(detected language: ${esc(p.detected_language || 'unknown')})</span></p>
        <pre class="query-block">${esc(p.query)}</pre>
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 1 &middot; Detection Profile <span class="dim">(LLM-extracted)</span></p>
        ${renderDetectionProfile(dbg.detectionProfile, dbg.profileError)}
        ${renderRawLlm(calls.profile, 'Detection Profile')}
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 2 &middot; Extracted Signals <span class="dim">(query tokens + telemetry)</span></p>
        ${renderTokens(dbg.tokens)}
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 3 &middot; Structural Matches (per signal) <span class="dim">(filtered to declared data sources; off-datasource rows excluded unless they're a technique's only evidence)</span></p>
        ${STAGE3_SCORING_NOTE}
        ${renderSignalResults(dbg.signalResults)}
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 4 &middot; Ranked Candidates (sent to LLM)</p>
        ${STAGE4_SCORING_NOTE}
        ${renderRankedCandidates(dbg.rankedCandidates)}
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 5 &middot; LLM Adjudication</p>
        ${renderLlm(dbg.llm)}
        ${renderRawLlm(calls.adjudication, 'Adjudication')}
      </div>

      <div class="stage-block">
        <p class="stage-block-label">Stage 6 &middot; QA / Compliance Check</p>
        ${renderQa(p.qa_result, calls.qa)}
      </div>
    `;
  }

  select.addEventListener('change', () => render(select.value));
  render(pipelines[0].id);
})();
