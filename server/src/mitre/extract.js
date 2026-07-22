// Best-effort mapping of common CrowdStrike Falcon event_simpleName values to a MITRE data
// component name concept -- there's no MITRE-published cross-walk for this, so treat it as a
// heuristic layer (like the platform synonym map), not authoritative. Unmapped event types
// fall through with no candidates rather than guessing.
const CROWDSTRIKE_EVENT_CONCEPTS = {
  processrollup2: 'Process Creation',
  processrollup: 'Process Creation',
  syntheticprocessrollup2: 'Process Creation',
  networkconnectip4: 'Network Connection Creation',
  networkconnectip6: 'Network Connection Creation',
  networklistenip4: 'Network Connection Creation',
  networkreceiveacceptip4: 'Network Connection Creation',
  dnsrequest: 'Active DNS',
  regsetvalue: 'Windows Registry Key Modification',
  regcreatekey: 'Windows Registry Key Creation',
  regdeletekey: 'Windows Registry Key Deletion',
  regdeletevalue: 'Windows Registry Key Deletion',
  regqueryvalue: 'Windows Registry Key Access',
  filecreateinfo: 'File Creation',
  fileopeninfo: 'File Creation',
  filewritten: 'File Modification',
  filedeleteinfo: 'File Deletion',
  filedeleted: 'File Deletion',
  userlogon: 'User Account Authentication',
  userlogonfailed2: 'User Account Authentication',
  userlogoff: 'User Account Authentication',
  authactivityauditdata: 'User Account Authentication',
  scheduledtaskregistered: 'Scheduled Job Creation',
  scheduledtaskdeleted: 'Scheduled Job Deletion',
  moduleload: 'Module Load',
  useraccountcreated: 'User Account Creation',
  useraccountdeleted: 'User Account Deletion',
  useraccountmodified: 'User Account Modification',
  remotethreadcreation: 'Process Access',
};

// Heuristics only -- these signals are distinctive enough in practice (CrowdStrike's own
// field names vs. Splunk's) but neither vendor publishes a formal grammar we can parse against.
function detectQueryLanguage(query) {
  if (!query) return 'unknown';
  if (/(#?event_simpleName|#repo\s*=|event_platform\s*=|\bComputerName\s*=|\baid\s*=|\bcid\s*=)/i.test(query)) {
    return 'cql';
  }
  if (/(sourcetype\s*=|datamodel\s*[:=]|\|\s*tstats|\|\s*eval|\|\s*stats|\|\s*from|`[a-z_]+`)/i.test(query)) {
    return 'spl';
  }
  return 'unknown';
}

// Scripted (deterministic) extraction of log-source signals from a raw query. Runs before
// any fuzzy/semantic matching -- it's the highest-precision signal. Handles both Splunk SPL
// and CrowdStrike CQL/Falcon Event Search syntax.
function extractTokens(query) {
  if (!query) return [];

  const tokens = new Map(); // dedupe by `${type}:${value}`
  let m;

  const sourceRe = /(sourcetype|source|index)\s*=\s*"?([\w:\-.\/]+)"?/gi;
  while ((m = sourceRe.exec(query))) {
    const value = m[2];
    tokens.set(`source:${value.toLowerCase()}`, { type: 'source', value });
  }

  const eventCodeRe = /(EventCode|EventID)\s*=\s*"?(\d+)"?/gi;
  while ((m = eventCodeRe.exec(query))) {
    const value = m[2];
    tokens.set(`eventcode:${value}`, { type: 'eventcode', value });
  }

  // Splunk commonly filters on a SET of event codes: `EventCode IN (4728, 4729, 4732)`. The
  // plain "EventCode=NNNN" regex above misses this entirely (which dropped the 4728 anchor on
  // a real AD rule and let the search wander off-platform). Capture the parenthesized list and
  // emit one event-code token per number inside it.
  const eventCodeInRe = /(EventCode|EventID)\s+IN\s*\(([^)]*)\)/gi;
  while ((m = eventCodeInRe.exec(query))) {
    const nums = m[2].match(/\d+/g) || [];
    for (const value of nums) {
      tokens.set(`eventcode:${value}`, { type: 'eventcode', value });
    }
  }

  // Splunk CIM/data-model searches don't reference a raw sourcetype/index/EventCode at all --
  // the data model name itself ("Authentication") is the log-source signal, and maps
  // reasonably well onto MITRE data component names (e.g. "User Account Authentication").
  // Two syntaxes in the wild: `datamodel=Authentication.Authentication` (tstats) and
  // `datamodel:"Authentication"."Successful_Default_Authentication"` (| from datamodel:...),
  // the latter with quotes and a colon instead of "=". The optional second part is a dataset
  // name, not itself searchable against data component names, but its words (once split on
  // underscores) are often genuinely descriptive ("Successful_Default_Authentication") and
  // get folded into the rule-text relevance boost.
  const dataModelRe = /datamodel\s*[:=]\s*"?([\w]+)"?(?:\s*\.\s*"?([\w]+)"?)?/gi;
  while ((m = dataModelRe.exec(query))) {
    const value = m[1];
    const dataset = m[2] && m[2].toLowerCase() !== value.toLowerCase() ? m[2].replace(/_/g, ' ') : null;
    tokens.set(`datamodel:${value.toLowerCase()}`, { type: 'datamodel', value, dataset });
  }

  // CrowdStrike Falcon/CQL event_simpleName is the closest analogue to Splunk's EventCode --
  // it names the specific telemetry event type. Map it to a data component concept when known.
  const eventSimpleNameRe = /#?event_simpleName\s*(?:=|:)\s*['"]?([\w]+)['"]?/gi;
  while ((m = eventSimpleNameRe.exec(query))) {
    const raw = m[1];
    const concept = CROWDSTRIKE_EVENT_CONCEPTS[raw.toLowerCase()];
    if (concept) {
      tokens.set(`concept:${concept.toLowerCase()}`, { type: 'concept', value: concept, source: `event_simpleName=${raw}` });
    } else {
      // Recorded so the pipeline inspector shows it was seen, even though nothing searches on it.
      tokens.set(`concept-unknown:${raw.toLowerCase()}`, { type: 'concept-unknown', value: raw });
    }
  }

  return [...tokens.values()];
}

module.exports = { extractTokens, detectQueryLanguage, CROWDSTRIKE_EVENT_CONCEPTS };
