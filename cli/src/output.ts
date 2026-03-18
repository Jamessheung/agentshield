/**
 * Terminal output formatting for scan reports.
 */

import type { ScanReport, Severity } from './types.js';

/** Format a scan report for display. */
export function formatReport(report: ScanReport, format: string): string {
  switch (format) {
    case 'json':
      return JSON.stringify(report, null, 2);
    case 'sarif':
      return formatSarif(report);
    case 'terminal':
    default:
      return formatTerminal(report);
  }
}

function formatTerminal(report: ScanReport): string {
  const lines: string[] = [];

  lines.push('');
  lines.push('  AgentShield Scan Report');
  lines.push('  ───────────────────────────────────────');
  lines.push(`  Skill:       ${report.skill_name}`);
  lines.push(`  Risk Score:  ${report.score}/100 (${report.risk_level})`);
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('  ✅ No security issues found.');
  } else {
    for (const f of report.findings) {
      const icon = severityIcon(f.severity);
      lines.push(`  ${icon} ${f.title}`);
      if (f.line != null) {
        lines.push(`             Line ${f.line}: ${f.evidence}`);
      } else if (f.evidence) {
        lines.push(`             ${f.evidence}`);
      }
      lines.push('');
    }
  }

  lines.push('  ───────────────────────────────────────');
  lines.push(`  Verdict: ${verdict(report.risk_level)}`);
  lines.push('');

  return lines.join('\n');
}

function severityIcon(severity: Severity): string {
  switch (severity) {
    case 'Critical':
      return '⛔ CRITICAL';
    case 'High':
      return '⚠  HIGH    ';
    case 'Medium':
      return '⚠  MEDIUM  ';
    case 'Low':
      return 'ℹ  LOW     ';
    case 'Info':
      return 'ℹ  INFO    ';
  }
}

function verdict(risk: string): string {
  switch (risk) {
    case 'Clean':
      return 'SAFE — No issues detected.';
    case 'Low':
      return 'LOW RISK — Minor issues found, review recommended.';
    case 'Medium':
      return 'MEDIUM RISK — Review before installing.';
    case 'High':
      return 'HIGH RISK — Do not install without careful review.';
    case 'Critical':
      return 'DO NOT INSTALL — Likely malicious.';
    default:
      return risk;
  }
}

function formatSarif(report: ScanReport): string {
  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'AgentShield',
            version: '0.1.0',
            rules: report.findings.map((f) => ({
              id: f.rule_id,
              name: f.title,
              shortDescription: { text: f.description },
              defaultConfiguration: {
                level: f.severity === 'Critical' || f.severity === 'High' ? 'error' : 'warning',
              },
            })),
          },
        },
        results: report.findings.map((f) => {
          const result: Record<string, unknown> = {
            ruleId: f.rule_id,
            message: { text: f.description },
            level: f.severity === 'Critical' || f.severity === 'High' ? 'error' : 'warning',
          };
          if (f.line != null) {
            result.locations = [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'SKILL.md' },
                  region: { startLine: f.line },
                },
              },
            ];
          }
          return result;
        }),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
