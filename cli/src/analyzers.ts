/**
 * TypeScript implementation of all analyzers — mirrors the Rust scanner-core.
 */

import type { Finding, ParsedSkill, Severity } from './types.js';

interface PatternRule {
  id: string;
  title: string;
  severity: Severity;
  sectionFilter?: RegExp;
  contentPattern: RegExp;
  description: string;
  remediation: string;
  references: string[];
}

const PATTERN_RULES: PatternRule[] = [
  {
    id: 'SC-001',
    title: 'Fake prerequisite installer detected',
    severity: 'Critical',
    sectionFilter: /(?:prerequisites?|requirements?|before\s+you\s+(?:start|begin)|setup|install(?:ation)?)/i,
    contentPattern: /(?:download|install|run|execute)\s+.*\b(?:curl|wget|git\s+clone)\b.*\b(?:github|githubusercontent|raw\.github)/i,
    description:
      'Skill instructs users to download and install software from GitHub as a "prerequisite". This is the primary ClawHavoc attack vector.',
    remediation:
      'Legitimate skills should use declared package managers (brew, npm, pip) in frontmatter install specs, not manual download instructions.',
    references: [
      'https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html',
    ],
  },
  {
    id: 'CE-001',
    title: 'Pipe-to-interpreter pattern detected',
    severity: 'Critical',
    contentPattern: /(curl|wget)\s+[^\n]*\|\s*(bash|sh|zsh|python[23]?|ruby|node|perl)/,
    description:
      'Content is downloaded and directly piped to a script interpreter. This allows arbitrary code execution without inspection.',
    remediation: 'Download the script to a file first, inspect it, then execute.',
    references: [],
  },
  {
    id: 'CE-002',
    title: 'Reverse shell pattern detected',
    severity: 'Critical',
    contentPattern:
      /(?:bash\s+-i\s+>&\s*\/dev\/tcp|nc\s+(?:-e|--exec)\s+\/bin|python[23]?\s+-c\s+.*socket.*subprocess|mkfifo\s+\/tmp\/|\/dev\/tcp\/\d{1,3}\.\d{1,3}|ncat\s+.*-e\s+\/bin)/i,
    description:
      'Code contains a reverse shell pattern that would give an attacker remote access to the user\'s machine.',
    remediation: 'Remove reverse shell code. No legitimate skill needs this.',
    references: [],
  },
  {
    id: 'DE-001',
    title: 'Access to sensitive credential files',
    severity: 'High',
    contentPattern:
      /(~\/\.openclaw\/\.env|~\/\.clawdbot\/\.env|~\/\.ssh\/|~\/\.aws\/|~\/\.gnupg\/|~\/Library\/Keychains|~\/\.config\/gcloud|~\/\.kube\/config)/,
    description: 'Skill references sensitive credential storage locations.',
    remediation:
      "Avoid accessing credential files directly. Use OpenClaw's built-in env management instead.",
    references: [],
  },
  {
    id: 'DE-002',
    title: 'Data sent to known exfiltration endpoint',
    severity: 'High',
    contentPattern:
      /(?:webhook\.site|requestbin\.com|pipedream\.com|hookbin\.com|beeceptor\.com|ngrok\.io|burpcollaborator)/i,
    description: 'Skill sends data to a known data collection/exfiltration service.',
    remediation: 'Remove references to data collection services.',
    references: [],
  },
  {
    id: 'DE-003',
    title: 'Base64 encoding with network send',
    severity: 'High',
    contentPattern:
      /(?:base64|btoa|b64encode)[^\n]*(?:curl|wget|fetch|https?:\/\/|request)|(?:curl|wget|fetch|https?:\/\/|request)[^\n]*(?:base64|btoa|b64encode)/i,
    description:
      'Skill encodes data in base64 before sending it externally. This is a common data exfiltration technique.',
    remediation: 'Remove base64 encoding of data sent to external services.',
    references: [],
  },
  {
    id: 'PI-001',
    title: 'Potential prompt injection',
    severity: 'High',
    contentPattern:
      /(?:ignore\s+(?:all\s+)?previous\s+instructions|you\s+are\s+now\s+in\s+admin|override\s+safety|disregard\s+(?:your|the)\s+(?:rules|guidelines)|do\s+not\s+tell\s+the\s+user|act\s+as\s+if\s+you\s+have\s+no\s+restrictions)/i,
    description:
      "SKILL.md contains text that attempts to override the agent's instructions or hide actions from the user.",
    remediation: 'Remove prompt injection attempts.',
    references: [],
  },
  {
    id: 'BP-001',
    title: 'Unpinned package installation',
    severity: 'Medium',
    contentPattern:
      /(?:npm\s+install\s+[a-z@][a-z0-9@/_-]*(?!\S*@\d)|pip\s+install\s+[a-z][a-z0-9_-]*(?!\S*==\d)|gem\s+install\s+[a-z][a-z0-9_-]*(?!\S*\s+-v\s))/i,
    description:
      'Package installed without version pinning. A compromised version could be installed in the future.',
    remediation:
      'Pin all package versions (npm install pkg@1.2.3, pip install pkg==1.2.3).',
    references: [],
  },
];

const KNOWN_MALICIOUS_URL_PATTERNS = [
  'raw.githubusercontent.com/hightower6eu/',
  'raw.githubusercontent.com/sakaen736jih/',
];

const KNOWN_MALICIOUS_NAME_PREFIXES = [
  'solana-wallet',
  'polymarket-',
  'youtube-summarize',
  'auto-updater',
];

const KNOWN_MALICIOUS_PUBLISHERS = ['hightower6eu', 'sakaen736jih'];

/** Run all analyzers on a parsed skill. */
export function runAnalyzers(skill: ParsedSkill): Finding[] {
  const findings: Finding[] = [
    ...runPatternAnalyzer(skill),
    ...runMetadataAnalyzer(skill),
    ...runBehavioralAnalyzer(skill),
    ...runSignatureAnalyzer(skill),
  ];

  // Deduplicate by rule_id + line
  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = `${f.rule_id}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort by severity (critical first)
  const order: Record<string, number> = {
    Critical: 0,
    High: 1,
    Medium: 2,
    Low: 3,
    Info: 4,
  };
  deduped.sort((a, b) => order[a.severity] - order[b.severity]);

  return deduped;
}

function runPatternAnalyzer(skill: ParsedSkill): Finding[] {
  const findings: Finding[] = [];

  for (const rule of PATTERN_RULES) {
    if (rule.sectionFilter) {
      for (const section of skill.sections) {
        if (!rule.sectionFilter.test(section.title)) continue;
        const m = rule.contentPattern.exec(section.content);
        if (m) {
          const lineInSection = section.content.slice(0, m.index).split('\n').length;
          findings.push(makeFinding(rule, m[0], section.lineStart + lineInSection));
        }
      }
    } else {
      const m = rule.contentPattern.exec(skill.rawText);
      if (m) {
        const line = skill.rawText.slice(0, m.index).split('\n').length;
        findings.push(makeFinding(rule, m[0], line));
      }
    }

    // Scan code blocks (skip section-filtered rules)
    if (!rule.sectionFilter) {
      for (const block of skill.codeBlocks) {
        const m = rule.contentPattern.exec(block.content);
        if (m) {
          const alreadyFound = findings.some((f) => f.rule_id === rule.id);
          if (!alreadyFound) {
            findings.push(makeFinding(rule, m[0], block.lineStart));
          }
        }
      }
    }
  }

  return findings;
}

function runMetadataAnalyzer(skill: ParsedSkill): Finding[] {
  const findings: Finding[] = [];
  const fm = skill.frontmatter;

  if (!fm.name) {
    findings.push({
      rule_id: 'SM-003',
      title: 'Missing skill name in frontmatter',
      severity: 'Medium',
      description: 'SKILL.md frontmatter does not have a name field.',
      evidence: '',
      line: 1,
      remediation: "Add a 'name' field to the YAML frontmatter.",
      references: [],
    });
  }

  if (!fm.description) {
    findings.push({
      rule_id: 'SM-004',
      title: 'Missing skill description',
      severity: 'Low',
      description: 'SKILL.md has no description. Legitimate skills typically describe their purpose.',
      evidence: '',
      line: 1,
      remediation: "Add a 'description' field to the YAML frontmatter.",
      references: [],
    });
  }

  const ocMeta = fm.metadata?.openclaw ?? fm.metadata?.clawdbot ?? fm.metadata?.clawdi;
  if (ocMeta?.always === true) {
    findings.push({
      rule_id: 'SM-007',
      title: 'Skill runs on every prompt (always: true)',
      severity: 'Medium',
      description:
        'Skill is set to always run, meaning it executes on every user prompt.',
      evidence: 'always: true',
      line: null,
      remediation: 'Only set always: true if the skill genuinely needs to run on every prompt.',
      references: [],
    });
  }

  return findings;
}

function runBehavioralAnalyzer(skill: ParsedSkill): Finding[] {
  const findings: Finding[] = [];
  const desc = (skill.frontmatter.description ?? '').toLowerCase();
  const name = skill.frontmatter.name.toLowerCase();

  const isSecurityRelated =
    desc.includes('security') ||
    desc.includes('ssh') ||
    desc.includes('credential') ||
    name.includes('ssh') ||
    name.includes('gpg') ||
    name.includes('aws') ||
    name.includes('key') ||
    name.includes('cloud');

  if (!isSecurityRelated) {
    const sensitiveAccess = skill.filePaths.filter(
      (p) =>
        p.includes('.ssh') ||
        p.includes('.aws') ||
        p.includes('.gnupg') ||
        p.includes('Keychains') ||
        p.includes('.kube') ||
        p.includes('.config/gcloud')
    );

    if (sensitiveAccess.length > 0) {
      findings.push({
        rule_id: 'BA-001',
        title: 'Credential access inconsistent with stated purpose',
        severity: 'High',
        description: `Skill '${skill.frontmatter.name}' accesses sensitive credential paths but its description does not indicate a need for such access.`,
        evidence: sensitiveAccess.join(', '),
        line: null,
        remediation:
          'Remove access to credential files or update the skill description to explain the need.',
        references: [],
      });
    }
  }

  return findings;
}

function runSignatureAnalyzer(skill: ParsedSkill): Finding[] {
  const findings: Finding[] = [];
  const nameLower = skill.frontmatter.name.toLowerCase();

  for (const prefix of KNOWN_MALICIOUS_NAME_PREFIXES) {
    if (nameLower.startsWith(prefix)) {
      findings.push({
        rule_id: 'SIG-001',
        title: 'Skill name matches known malware campaign pattern',
        severity: 'High',
        description: `Skill name '${skill.frontmatter.name}' matches the pattern '${prefix}*' associated with the ClawHavoc malware campaign.`,
        evidence: skill.frontmatter.name,
        line: null,
        remediation: 'Verify the skill publisher and contents carefully before installing.',
        references: [
          'https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html',
        ],
      });
      break;
    }
  }

  for (const url of skill.urls) {
    for (const pattern of KNOWN_MALICIOUS_URL_PATTERNS) {
      if (url.url.includes(pattern)) {
        findings.push({
          rule_id: 'SIG-002',
          title: 'URL matches known malware distribution source',
          severity: 'Critical',
          description: `URL '${url.url}' matches a known malicious distribution source.`,
          evidence: url.url,
          line: url.line,
          remediation: 'Do not download or execute anything from this URL.',
          references: [
            'https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html',
          ],
        });
        break;
      }
    }
  }

  const rawLower = skill.rawText.toLowerCase();
  for (const publisher of KNOWN_MALICIOUS_PUBLISHERS) {
    if (rawLower.includes(publisher)) {
      const alreadyFlagged = findings.some((f) => f.rule_id === 'SIG-002');
      if (!alreadyFlagged) {
        findings.push({
          rule_id: 'SIG-003',
          title: 'References known malicious publisher account',
          severity: 'High',
          description: `Skill references the account '${publisher}' associated with the ClawHavoc campaign.`,
          evidence: publisher,
          line: null,
          remediation: 'Do not use skills from this publisher.',
          references: [
            'https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html',
          ],
        });
      }
      break;
    }
  }

  return findings;
}

function makeFinding(rule: PatternRule, evidence: string, line: number): Finding {
  return {
    rule_id: rule.id,
    title: rule.title,
    severity: rule.severity,
    description: rule.description,
    evidence,
    line,
    remediation: rule.remediation,
    references: [...rule.references],
  };
}
