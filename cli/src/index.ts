#!/usr/bin/env node

/**
 * AgentShield CLI — Security scanner for OpenClaw skills.
 *
 * Usage:
 *   agentshield scan ./my-skill/       Scan a local skill directory
 *   agentshield check <slug>           Scan a skill from ClawHub by slug
 *   agentshield audit                  Audit all skills on ClawHub
 */

import { program } from 'commander';
import { scanLocal } from './scan-local.js';
import { formatReport } from './output.js';

program
  .name('agentshield')
  .description('Security scanner for AI agent skills')
  .version('0.1.0');

program
  .command('scan <path>')
  .description('Scan a local skill directory for security issues')
  .option('-f, --format <type>', 'Output format: terminal|json|sarif', 'terminal')
  .option('--no-color', 'Disable colored output')
  .action(async (path: string, options: { format: string }) => {
    try {
      const report = await scanLocal(path);
      console.log(formatReport(report, options.format));
      process.exit(report.score > 50 ? 1 : 0);
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }
  });

program
  .command('check <slug>')
  .description('Scan a skill from ClawHub by slug or URL')
  .option('-f, --format <type>', 'Output format: terminal|json|sarif', 'terminal')
  .action(async (slug: string, options: { format: string }) => {
    try {
      const { fetchSkill } = await import('./clawhub.js');
      const skill = await fetchSkill(slug);
      // For remote skills, we scan the SKILL.md content directly
      const { scanContent } = await import('./scan-local.js');
      const report = await scanContent(skill.name, skill.files);
      console.log(formatReport(report, options.format));
      process.exit(report.score > 50 ? 1 : 0);
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }
  });

program
  .command('audit')
  .description('Audit all skills on ClawHub (requires API token)')
  .option('--output <path>', 'Output directory for reports', './audit-results')
  .option('--concurrency <n>', 'Parallel scan workers', '10')
  .action(async (options: { output: string; concurrency: string }) => {
    try {
      const { bulkScan } = await import('./bulk-scan.js');
      await bulkScan(options);
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(2);
    }
  });

program.parse();
