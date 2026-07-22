// Scripted (deterministic) extraction of a categorized "detection profile" from a rule's
// name, description, and query text -- {processes, actions, artifacts, objects, behaviors}.
// This is a heuristic dictionary layer (same spirit as platforms.js and the CrowdStrike
// event_simpleName map), not an NLP model: it catches known technical terms and common
// verbs/nouns via regex/word lists, not genuine semantic understanding. It exists to hand the
// search stage a small set of dense, meaningful terms instead of a full prose sentence -- an
// LLM-based extractor would be more accurate but costs an extra call per rule; this is free
// and runs before anything else.

const ACTION_KEYWORDS = {
  download: 'download', downloaded: 'download', downloading: 'download',
  upload: 'upload', uploaded: 'upload', exfiltrate: 'exfiltrate', exfiltration: 'exfiltrate',
  execute: 'execute', executed: 'execute', execution: 'execute', executing: 'execute',
  inject: 'inject', injected: 'inject', injection: 'inject',
  dump: 'dump', dumped: 'dump', dumping: 'dump',
  escalate: 'escalate', escalation: 'escalate',
  encode: 'encode', encoded: 'encode', encoding: 'encode',
  decode: 'decode', decoded: 'decode',
  connect: 'connect', connection: 'connect',
  create: 'create', created: 'create', creation: 'create',
  delete: 'delete', deleted: 'delete', deletion: 'delete',
  modify: 'modify', modified: 'modify', modification: 'modify',
  spawn: 'spawn', spawned: 'spawn', spawning: 'spawn',
  login: 'login', logon: 'login', 'log on': 'login',
  authenticate: 'authenticate', authentication: 'authenticate',
  bypass: 'bypass', bypassed: 'bypass', bypassing: 'bypass',
  persist: 'persist', persistence: 'persist',
  scan: 'scan', scanning: 'scan', enumerate: 'enumerate', enumeration: 'enumerate',
  tamper: 'tamper', tampering: 'tamper', disable: 'disable', disabled: 'disable',
};

const ARTIFACT_KEYWORDS = [
  'EncodedCommand', 'Base64', 'HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP', 'SMB', 'RDP', 'SSH',
  'LDAP', 'Kerberos', 'NTLM', 'RegistryKey', 'NamedPipe', 'Mutex', 'ScheduledTask', 'WMI',
  'PowerShell', 'MSHTA', 'Rundll32', 'Regsvr32', 'CertUtil', 'Macro', 'VBA', 'JavaScript',
  'Cookie', 'Token', 'Certificate', 'ZIP', 'ISO', 'LNK', 'DLL', 'Shellcode',
];

const OBJECT_KEYWORDS = [
  'script', 'file', 'process', 'registry key', 'network connection', 'service', 'task',
  'account', 'credential', 'token', 'certificate', 'user', 'group', 'policy', 'container',
  'pod', 'image', 'module', 'thread', 'driver', 'firewall rule', 'mailbox', 'document',
];

// Behavior labels synthesized from combinations of the signals above -- a small, explicit
// rule set, not general reasoning. Order matters: more specific rules first.
const BEHAVIOR_RULES = [
  { if: (p) => p.processes.some((x) => /powershell/i.test(x)) || p.artifacts.includes('PowerShell'), label: 'PowerShell execution' },
  { if: (p) => p.artifacts.includes('EncodedCommand') || p.artifacts.includes('Base64'), label: 'Encoded/obfuscated command execution' },
  { if: (p) => p.actions.includes('inject'), label: 'Process injection' },
  { if: (p) => p.actions.includes('dump'), label: 'Credential access' },
  { if: (p) => p.actions.includes('download') && p.actions.includes('execute'), label: 'Remote payload download and execution' },
  { if: (p) => p.actions.includes('download'), label: 'Remote payload download' },
  { if: (p) => p.actions.includes('exfiltrate'), label: 'Data exfiltration' },
  { if: (p) => p.actions.includes('escalate'), label: 'Privilege escalation' },
  { if: (p) => p.actions.includes('persist'), label: 'Persistence mechanism' },
  { if: (p) => p.actions.includes('login') || p.actions.includes('authenticate'), label: 'Authentication activity' },
  { if: (p) => p.actions.includes('tamper') || p.actions.includes('disable'), label: 'Defense evasion / tampering' },
];

function extractProcesses(text) {
  const found = new Set();
  const exeRe = /\b([\w][\w\-]*\.exe)\b/gi;
  let m;
  while ((m = exeRe.exec(text))) found.add(m[1].toLowerCase());
  return [...found];
}

function extractActions(text) {
  const found = new Set();
  const lower = text.toLowerCase();
  for (const [word, canonical] of Object.entries(ACTION_KEYWORDS)) {
    if (new RegExp(`\\b${word}\\b`, 'i').test(lower)) found.add(canonical);
  }
  return [...found];
}

function extractArtifacts(text) {
  const found = new Set();
  for (const artifact of ARTIFACT_KEYWORDS) {
    if (new RegExp(`\\b${artifact}\\b`, 'i').test(text)) found.add(artifact);
  }
  return [...found];
}

function extractObjects(text) {
  const found = new Set();
  const lower = text.toLowerCase();
  for (const obj of OBJECT_KEYWORDS) {
    if (lower.includes(obj)) found.add(obj);
  }
  return [...found];
}

function extractBehaviors(profile) {
  const found = [];
  for (const rule of BEHAVIOR_RULES) {
    if (rule.if(profile)) found.push(rule.label);
  }
  return found;
}

function extractDetectionProfile(rule) {
  const text = [rule.rule_name, rule.description, rule.query].filter(Boolean).join(' \n ');

  const profile = {
    processes: extractProcesses(text),
    actions: extractActions(text),
    artifacts: extractArtifacts(text),
    objects: extractObjects(text),
    behaviors: [],
  };
  profile.behaviors = extractBehaviors(profile);

  return profile;
}

// Flattened, deduped term list -- denser and more precise than the raw rule text, used to
// boost the full-text relevance search (see match.js) alongside rule_name+description.
function profileToSearchText(profile) {
  return [...profile.processes, ...profile.actions, ...profile.artifacts, ...profile.objects, ...profile.behaviors].join(' ');
}

module.exports = { extractDetectionProfile, profileToSearchText };
