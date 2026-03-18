/** Severity levels for findings. */
export type Severity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';

/** A single security finding. */
export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  description: string;
  evidence: string;
  line: number | null;
  remediation: string;
  references: string[];
}

/** Risk level categories. */
export type RiskLevel = 'Clean' | 'Low' | 'Medium' | 'High' | 'Critical';

/** Score breakdown by severity. */
export interface ScoreBreakdown {
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
}

/** Complete scan report. */
export interface ScanReport {
  skill_name: string;
  score: number;
  risk_level: RiskLevel;
  findings: Finding[];
  breakdown: ScoreBreakdown;
}

/** YAML frontmatter from SKILL.md. */
export interface SkillFrontmatter {
  name: string;
  description?: string;
  version?: string;
  metadata?: {
    openclaw?: OpenClawMeta;
    clawdbot?: OpenClawMeta;
    clawdi?: OpenClawMeta;
  };
}

export interface OpenClawMeta {
  requires?: {
    env?: string[];
    bins?: string[];
    anyBins?: string[];
    config?: string[];
    os?: string[];
  };
  primaryEnv?: string;
  always?: boolean;
  emoji?: string;
  install?: InstallSpec[];
}

export interface InstallSpec {
  id?: string;
  kind?: string;
  formula?: string;
  package?: string;
  bins?: string[];
  label?: string;
}

/** Parsed SKILL.md structure. */
export interface ParsedSkill {
  frontmatter: SkillFrontmatter;
  body: string;
  sections: {
    title: string;
    level: number;
    content: string;
    lineStart: number;
    lineEnd: number;
  }[];
  codeBlocks: {
    language?: string;
    content: string;
    lineStart: number;
  }[];
  urls: {
    url: string;
    domain: string;
    line: number;
    context: string;
  }[];
  filePaths: string[];
  rawText: string;
  files: { path: string; content: string }[];
}
