/**
 * Full ClawHub registry audit with concurrency control.
 */

import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { listAllSlugs, fetchSkill } from './clawhub.js';
import { scanContent } from './scan-local.js';
import type { ScanReport } from './types.js';

/** Run a full audit of all ClawHub skills. */
export async function bulkScan(options: {
  output: string;
  concurrency: string;
}): Promise<void> {
  const concurrency = parseInt(options.concurrency, 10) || 10;
  const outputDir = options.output;
  await mkdir(outputDir, { recursive: true });

  console.log('Fetching skill registry...');
  const slugs = await listAllSlugs();
  console.log(`Found ${slugs.length} skills. Starting scan...\n`);

  const results = {
    total_scanned: 0,
    clean: 0,
    low_risk: 0,
    medium_risk: 0,
    high_risk: 0,
    critical_risk: 0,
    malicious_skills: [] as {
      slug: string;
      name: string;
      score: number;
      findings: { rule_id: string; title: string; severity: string }[];
    }[],
    top_findings: {} as Record<string, number>,
    scan_date: new Date().toISOString(),
  };

  // Process in batches for concurrency control
  for (let i = 0; i < slugs.length; i += concurrency) {
    const batch = slugs.slice(i, i + concurrency);
    const promises = batch.map(async (slug) => {
      try {
        const skill = await fetchSkill(slug);
        const report: ScanReport = await scanContent(skill.name, skill.files);

        results.total_scanned++;

        if (report.score === 0) results.clean++;
        else if (report.score <= 25) results.low_risk++;
        else if (report.score <= 50) results.medium_risk++;
        else if (report.score <= 75) results.high_risk++;
        else {
          results.critical_risk++;
          results.malicious_skills.push({
            slug,
            name: skill.name,
            score: report.score,
            findings: report.findings.map((f) => ({
              rule_id: f.rule_id,
              title: f.title,
              severity: f.severity,
            })),
          });
        }

        for (const f of report.findings) {
          results.top_findings[f.rule_id] = (results.top_findings[f.rule_id] || 0) + 1;
        }

        await writeFile(
          join(outputDir, `${slug}.json`),
          JSON.stringify(report, null, 2)
        );
      } catch (err) {
        console.error(`  Error scanning ${slug}: ${err}`);
      }
    });

    await Promise.all(promises);

    if (results.total_scanned % 100 === 0 && results.total_scanned > 0) {
      console.log(`  Scanned ${results.total_scanned}/${slugs.length}...`);
    }
  }

  // Write summary
  const maliciousPct =
    results.total_scanned > 0
      ? ((results.critical_risk / results.total_scanned) * 100).toFixed(1)
      : '0.0';

  const summary = { ...results, malicious_percentage: maliciousPct };

  await writeFile(join(outputDir, 'SUMMARY.json'), JSON.stringify(summary, null, 2));

  console.log('\n═══════════════════════════════════════════');
  console.log('  AgentShield ClawHub Security Audit');
  console.log('═══════════════════════════════════════════');
  console.log(`  Date:      ${summary.scan_date}`);
  console.log(`  Scanned:   ${summary.total_scanned} skills`);
  console.log(`  Clean:     ${summary.clean}`);
  console.log(`  Low risk:  ${summary.low_risk}`);
  console.log(`  Medium:    ${summary.medium_risk}`);
  console.log(`  High:      ${summary.high_risk}`);
  console.log(`  Critical:  ${summary.critical_risk} (${summary.malicious_percentage}%)`);
  console.log('═══════════════════════════════════════════\n');
}
