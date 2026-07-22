// Canonical platform vocabulary, matching what's actually stored in mitre_analytics.platforms
// and mitre_techniques.platforms after ingesting the ATT&CK v19.1 bundle.
const CANONICAL_PLATFORMS = [
  'Windows',
  'Linux',
  'macOS',
  'Containers',
  'ESXi',
  'IaaS',
  'Identity Provider',
  'Network Devices',
  'Office Suite',
  'Office 365',
  'PRE',
  'SaaS',
];

// Heuristic synonym map: customer CSVs will say "Windows", "WinEventLog", "AWS", "O365", etc.
// rather than ATT&CK's exact platform strings, so normalize on best-effort substring match.
const SYNONYMS = [
  { canonical: 'Windows', patterns: [/windows/i, /\bwin\b/i, /wineventlog/i, /sysmon/i, /\betw\b/i] },
  { canonical: 'Linux', patterns: [/linux/i, /auditd/i, /\bsyslog\b/i] },
  { canonical: 'macOS', patterns: [/mac\s*os/i, /\bosx\b/i, /darwin/i, /unifiedlog/i] },
  { canonical: 'Containers', patterns: [/container/i, /docker/i, /kubernetes/i, /\bk8s\b/i, /\bpod\b/i] },
  { canonical: 'ESXi', patterns: [/esxi/i, /vmware/i, /vsphere/i] },
  { canonical: 'IaaS', patterns: [/\baws\b/i, /\bazure\b/i, /\bgcp\b/i, /\biaas\b/i, /cloudtrail/i, /\bec2\b/i] },
  { canonical: 'Identity Provider', patterns: [/identity provider/i, /\bidp\b/i, /\bokta\b/i, /entra/i, /azuread/i, /active directory/i, /\bad\b/i] },
  { canonical: 'Network Devices', patterns: [/network device/i, /firewall/i, /\brouter\b/i, /\bswitch\b/i, /netflow/i] },
  { canonical: 'Office Suite', patterns: [/office\s*365/i, /\bo365\b/i, /\bm365\b/i, /microsoft\s*365/i, /google workspace/i, /gsuite/i, /office suite/i] },
  { canonical: 'SaaS', patterns: [/\bsaas\b/i] },
];

function normalizePlatforms(raw) {
  if (!raw) return [];
  const parts = String(raw)
    .split(/[,;/|]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const result = new Set();
  for (const part of parts) {
    let matched = false;
    for (const syn of SYNONYMS) {
      if (syn.patterns.some((re) => re.test(part))) {
        result.add(syn.canonical);
        matched = true;
        break;
      }
    }
    if (!matched) {
      const exact = CANONICAL_PLATFORMS.find((c) => c.toLowerCase() === part.toLowerCase());
      if (exact) result.add(exact);
    }
  }
  return [...result];
}

module.exports = { CANONICAL_PLATFORMS, normalizePlatforms };
