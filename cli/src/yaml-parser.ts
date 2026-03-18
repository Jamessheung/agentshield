/**
 * Minimal YAML parser for SKILL.md frontmatter.
 * Handles the subset of YAML used in skill frontmatter without external deps.
 */

import type { SkillFrontmatter } from './types.js';

/** Parse YAML frontmatter string into SkillFrontmatter. */
export function parse(yamlStr: string): SkillFrontmatter {
  if (!yamlStr.trim()) {
    return { name: '', description: '', version: '' };
  }

  const result: Record<string, unknown> = {};
  const lines = yamlStr.split('\n');
  const stack: { indent: number; obj: Record<string, unknown> }[] = [
    { indent: -1, obj: result },
  ];

  for (const line of lines) {
    // Skip comments and empty lines
    if (line.trim().startsWith('#') || line.trim() === '' || line.trim() === '---') {
      continue;
    }

    const indent = line.search(/\S/);
    const content = line.trim();

    // Array item
    if (content.startsWith('- ')) {
      const value = content.slice(2).trim();
      // Find parent
      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
        stack.pop();
      }
      const parent = stack[stack.length - 1].obj;
      const lastKey = Object.keys(parent).pop();
      if (lastKey) {
        if (!Array.isArray(parent[lastKey])) {
          parent[lastKey] = [];
        }
        (parent[lastKey] as unknown[]).push(parseValue(value));
      }
      continue;
    }

    // Key: value
    const colonIdx = content.indexOf(':');
    if (colonIdx === -1) continue;

    const key = content.slice(0, colonIdx).trim();
    const rawValue = content.slice(colonIdx + 1).trim();

    // Pop stack to find correct parent
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    const parent = stack[stack.length - 1].obj;

    if (rawValue === '' || rawValue === '|' || rawValue === '>') {
      // Nested object or block scalar
      const nested: Record<string, unknown> = {};
      parent[key] = nested;
      stack.push({ indent, obj: nested });
    } else {
      parent[key] = parseValue(rawValue);
    }
  }

  return {
    name: String(result.name || ''),
    description: result.description ? String(result.description) : undefined,
    version: result.version ? String(result.version) : undefined,
    metadata: result.metadata as SkillFrontmatter['metadata'],
  };
}

function parseValue(raw: string): unknown {
  // Remove quotes
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1);
  }
  // Booleans
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  // Numbers
  if (/^\d+$/.test(raw)) return parseInt(raw, 10);
  if (/^\d+\.\d+$/.test(raw)) return parseFloat(raw);
  // Null
  if (raw === 'null' || raw === '~') return null;
  return raw;
}
