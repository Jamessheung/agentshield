/**
 * Local skill scanning — reads a skill directory and runs all analyzers.
 *
 * This is a pure TypeScript implementation of the scanner for the CLI.
 * It mirrors the Rust scanner-core logic for portability.
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, resolve } from 'path';
import { runAnalyzers } from './analyzers.js';
import { calculateScore } from './scoring.js';
import type { ScanReport, ParsedSkill, SkillFrontmatter } from './types.js';
import { parse as parseYaml } from './yaml-parser.js';

/** Scan a local skill directory. */
export async function scanLocal(skillPath: string): Promise<ScanReport> {
  const absPath = resolve(skillPath);
  const skillMdPath = join(absPath, 'SKILL.md');

  if (!existsSync(skillMdPath)) {
    throw new Error(`No SKILL.md found in ${absPath}`);
  }

  const rawText = readFileSync(skillMdPath, 'utf-8');

  // Collect other files
  const otherFiles: { path: string; content: string }[] = [];
  try {
    for (const entry of readdirSync(absPath)) {
      if (entry === 'SKILL.md') continue;
      const fullPath = join(absPath, entry);
      const stat = statSync(fullPath);
      if (stat.isFile() && stat.size < 1_048_576) {
        try {
          otherFiles.push({ path: entry, content: readFileSync(fullPath, 'utf-8') });
        } catch {
          // Skip binary files
        }
      }
    }
  } catch {
    // Directory read failed, continue without other files
  }

  return scanRawContent(rawText, otherFiles);
}

/** Scan from raw content and file list (for remote skills). */
export async function scanContent(
  name: string,
  files: { path: string; content: string }[]
): Promise<ScanReport> {
  const skillMd = files.find(f => f.path === 'SKILL.md' || f.path.endsWith('/SKILL.md'));
  if (!skillMd) {
    throw new Error('No SKILL.md found in skill files');
  }
  const otherFiles = files.filter(f => f !== skillMd);
  return scanRawContent(skillMd.content, otherFiles);
}

function scanRawContent(
  rawText: string,
  otherFiles: { path: string; content: string }[]
): ScanReport {
  const skill = parseSkillContent(rawText, otherFiles);
  const findings = runAnalyzers(skill);
  const score = calculateScore(findings);

  return {
    skill_name: skill.frontmatter.name || 'unknown',
    score: score.total,
    risk_level: score.category,
    findings,
    breakdown: score.breakdown,
  };
}

function parseSkillContent(
  rawText: string,
  otherFiles: { path: string; content: string }[]
): ParsedSkill {
  const { frontmatterStr, body } = splitFrontmatter(rawText);
  let frontmatter: SkillFrontmatter;
  try {
    frontmatter = parseYaml(frontmatterStr);
  } catch {
    frontmatter = { name: '', description: '', version: '' };
  }

  const sections = parseSections(body);
  const codeBlocks = extractCodeBlocks(body);
  const urls = extractUrls(rawText);
  const filePaths = extractFilePaths(rawText);

  return {
    frontmatter,
    body,
    sections,
    codeBlocks,
    urls,
    filePaths,
    rawText,
    files: otherFiles,
  };
}

function splitFrontmatter(raw: string): { frontmatterStr: string; body: string } {
  const trimmed = raw.trimStart();
  if (!trimmed.startsWith('---')) {
    return { frontmatterStr: '', body: raw };
  }

  const afterFirst = trimmed.slice(3);
  const endPos = afterFirst.indexOf('\n---');
  if (endPos === -1) {
    return { frontmatterStr: '', body: raw };
  }

  const frontmatterStr = afterFirst.slice(0, endPos).trim();
  const body = afterFirst.slice(endPos + 4).replace(/^\n+/, '');
  return { frontmatterStr, body };
}

function parseSections(body: string): ParsedSkill['sections'] {
  const lines = body.split('\n');
  const sections: ParsedSkill['sections'] = [];

  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/^(#{1,6})\s+(.+)/);
    if (!match) continue;

    const level = match[1].length;
    const title = match[2];
    const lineStart = i + 1;

    const contentLines: string[] = [];
    let j = i + 1;
    while (j < lines.length) {
      const nextMatch = lines[j].match(/^(#{1,6})\s+/);
      if (nextMatch && nextMatch[1].length <= level) break;
      contentLines.push(lines[j]);
      j++;
    }

    sections.push({
      title,
      level,
      content: contentLines.join('\n'),
      lineStart,
      lineEnd: j,
    });
  }

  return sections;
}

function extractCodeBlocks(body: string): ParsedSkill['codeBlocks'] {
  const blocks: ParsedSkill['codeBlocks'] = [];
  const lines = body.split('\n');
  let i = 0;

  while (i < lines.length) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith('```')) {
      const lang = trimmed.slice(3).trim() || undefined;
      const lineStart = i + 1;
      const contentLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        contentLines.push(lines[i]);
        i++;
      }
      blocks.push({ language: lang, content: contentLines.join('\n'), lineStart });
    }
    i++;
  }

  return blocks;
}

function extractUrls(text: string): ParsedSkill['urls'] {
  const urlRe = /https?:\/\/[^\s)\]>"'`]+/g;
  const urls: ParsedSkill['urls'] = [];

  for (const [lineIdx, line] of text.split('\n').entries()) {
    let m;
    while ((m = urlRe.exec(line)) !== null) {
      const url = m[0].replace(/[.,]+$/, '');
      const domain = extractDomain(url);
      urls.push({ url, domain, line: lineIdx + 1, context: line });
    }
  }

  return urls;
}

function extractDomain(url: string): string {
  try {
    const withoutScheme = url.replace(/^https?:\/\//, '');
    return withoutScheme.split('/')[0].split(':')[0];
  } catch {
    return '';
  }
}

function extractFilePaths(text: string): string[] {
  const pathRe = /(?:~\/|\/etc\/|\/tmp\/|\/var\/|\/usr\/)[\w./-]+/g;
  const paths = new Set<string>();
  let m;
  while ((m = pathRe.exec(text)) !== null) {
    paths.add(m[0]);
  }
  return [...paths].sort();
}
