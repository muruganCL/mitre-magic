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

// Heuristic macro-name -> log-source inference. Splunk macros (`macro_name`) hide their real
// definition in macros.conf, which we don't have. When a macro name clearly denotes a known
// telemetry source we INFER the standardized log source and record it as a labelled assumption
// (see the audit trail) -- never as a silent fact. This is exactly the "if it translates a
// macro into an index, it has to say what it applied" requirement.
const MACRO_INFERENCE = [
  { re: /wineventlog[_-]?security|windows[_-]?sec(urity)?/i, standardized: 'WinEventLog:Security', note: 'macro name denotes the Windows Security event log' },
  { re: /wineventlog[_-]?system/i, standardized: 'WinEventLog:System', note: 'macro name denotes the Windows System event log' },
  { re: /sysmon/i, standardized: 'WinEventLog:Sysmon', note: 'macro name denotes Sysmon telemetry' },
  { re: /powershell/i, standardized: 'WinEventLog:Microsoft-Windows-PowerShell/Operational', note: 'macro name denotes PowerShell operational logs' },
  { re: /(^|[_-])wmi([_-]|$)/i, standardized: 'WinEventLog:Microsoft-Windows-WMI-Activity/Operational', note: 'macro name denotes WMI activity logs' },
  { re: /wineventlog|windows[_-]?event/i, standardized: 'WinEventLog', note: 'macro name denotes Windows event logs' },
  { re: /auditd|linux[_-]?(secure|audit)/i, standardized: 'auditd', note: 'macro name denotes Linux auditd telemetry' },
  { re: /(^|[_-])(o365|office365|m365)([_-]|$)/i, standardized: 'o365:management:activity', note: 'macro name denotes Office 365 audit logs' },
  { re: /(^|[_-])(aws|cloudtrail)([_-]|$)/i, standardized: 'aws:cloudtrail', note: 'macro name denotes AWS CloudTrail logs' },
  { re: /(^|[_-])azure([_-]|$)/i, standardized: 'azure:signinlogs', note: 'macro name denotes Azure sign-in logs' },
  { re: /okta/i, standardized: 'Okta:SystemLog', note: 'macro name denotes Okta system logs' },
];

// Macros that only filter/allow-list results carry no log-source meaning -- record that they
// were seen (for the audit trail) but derive no search signal from them.
const FILTER_MACRO_RE = /(_filter|_whitelist|_allowlist|_exclusion|_exclude|_drop|_suppress|_tune)$/i;

// Scripted (deterministic) extraction of log-source signals from a raw query. Runs before
// any fuzzy/semantic matching -- it's the highest-precision signal. Handles both Splunk SPL
// and CrowdStrike CQL/Falcon Event Search syntax. Every emitted signal carries provenance:
//   method   = how it was derived (regex | dictionary | inference)
//   evidence = the exact substring of the query it was read from
//   assumption = present only for inferred signals, stating what was applied and why
function extractTokens(query) {
  if (!query) return [];

  const tokens = new Map(); // dedupe by `${type}:${value}`
  let m;

  const sourceRe = /(sourcetype|source|index)\s*=\s*"?([\w:\-.\/]+)"?/gi;
  while ((m = sourceRe.exec(query))) {
    const value = m[2];
    tokens.set(`source:${value.toLowerCase()}`, { type: 'source', value, method: 'regex', evidence: m[0].trim() });
  }

  const eventCodeRe = /(EventCode|EventID)\s*=\s*"?(\d+)"?/gi;
  while ((m = eventCodeRe.exec(query))) {
    const value = m[2];
    tokens.set(`eventcode:${value}`, { type: 'eventcode', value, method: 'regex', evidence: m[0].trim() });
  }

  // Splunk commonly filters on a SET of event codes: `EventCode IN (4728, 4729, 4732)`. The
  // plain "EventCode=NNNN" regex above misses this entirely (which dropped the 4728 anchor on
  // a real AD rule and let the search wander off-platform). Capture the parenthesized list and
  // emit one event-code token per number inside it.
  const eventCodeInRe = /(EventCode|EventID)\s+IN\s*\(([^)]*)\)/gi;
  while ((m = eventCodeInRe.exec(query))) {
    const nums = m[2].match(/\d+/g) || [];
    for (const value of nums) {
      tokens.set(`eventcode:${value}`, { type: 'eventcode', value, method: 'regex', evidence: m[0].trim() });
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
    tokens.set(`datamodel:${value.toLowerCase()}`, { type: 'datamodel', value, dataset, method: 'regex', evidence: m[0].trim() });
  }

  // CrowdStrike Falcon/CQL event_simpleName is the closest analogue to Splunk's EventCode --
  // it names the specific telemetry event type. Map it to a data component concept when known.
  const eventSimpleNameRe = /#?event_simpleName\s*(?:=|:)\s*['"]?([\w]+)['"]?/gi;
  while ((m = eventSimpleNameRe.exec(query))) {
    const raw = m[1];
    const concept = CROWDSTRIKE_EVENT_CONCEPTS[raw.toLowerCase()];
    if (concept) {
      tokens.set(`concept:${concept.toLowerCase()}`, {
        type: 'concept', value: concept, source: `event_simpleName=${raw}`,
        method: 'dictionary', evidence: m[0].trim(),
        assumption: `CrowdStrike event "${raw}" mapped to MITRE data component "${concept}"`,
      });
    } else {
      tokens.set(`concept-unknown:${raw.toLowerCase()}`, { type: 'concept-unknown', value: raw, method: 'regex', evidence: m[0].trim() });
    }
  }

  // Splunk macros: `macro_name`. Infer a log source where the name clearly denotes one (recorded
  // as an assumption), note filter/allow-list macros as seen-but-not-searchable, and record any
  // other macro as unknown so the audit trail shows it was encountered.
  const macroRe = /`([a-zA-Z_][a-zA-Z0-9_]*)(?:\([^`]*\))?`/g;
  while ((m = macroRe.exec(query))) {
    const name = m[1];
    const evidence = m[0];
    const inferred = MACRO_INFERENCE.find((mi) => mi.re.test(name));
    if (inferred) {
      const key = `source:${inferred.standardized.toLowerCase()}`;
      // Don't let an inferred source overwrite an explicit sourcetype= of the same value.
      if (!tokens.has(key)) {
        tokens.set(key, {
          type: 'source',
          value: inferred.standardized,
          method: 'inference',
          evidence,
          assumption: `Macro ${evidence} → log source "${inferred.standardized}" (${inferred.note})`,
        });
      }
    } else if (FILTER_MACRO_RE.test(name)) {
      tokens.set(`macro-filter:${name.toLowerCase()}`, { type: 'macro-filter', value: name, method: 'regex', evidence, assumption: 'Filter/allow-list macro — no log-source signal derived' });
    } else {
      tokens.set(`macro-unknown:${name.toLowerCase()}`, { type: 'macro-unknown', value: name, method: 'regex', evidence, assumption: 'Macro definition unavailable — no log source could be inferred from the name' });
    }
  }

  return [...tokens.values()];
}

module.exports = { extractTokens, detectQueryLanguage, CROWDSTRIKE_EVENT_CONCEPTS };
