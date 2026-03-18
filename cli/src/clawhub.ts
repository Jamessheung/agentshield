/**
 * ClawHub HTTP API client for fetching skills from the registry.
 */

const CLAWHUB_API = 'https://clawhub.com/api';

export interface ClawHubSkill {
  slug: string;
  name: string;
  description: string;
  version: string;
  publisher: {
    username: string;
    github_id: string;
    created_at: string;
  };
  install_count: number;
  files: { path: string; content: string }[];
  created_at: string;
  updated_at: string;
}

/** Fetch a single skill by slug from ClawHub. */
export async function fetchSkill(slug: string): Promise<ClawHubSkill> {
  const url = `${CLAWHUB_API}/skills/${encodeURIComponent(slug)}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Skill not found: ${slug} (HTTP ${res.status})`);
  }
  return res.json() as Promise<ClawHubSkill>;
}

/** List all skill slugs from ClawHub (paginated). */
export async function listAllSlugs(): Promise<string[]> {
  const slugs: string[] = [];
  let cursor: string | null = null;

  while (true) {
    const url = cursor
      ? `${CLAWHUB_API}/skills?limit=100&cursor=${encodeURIComponent(cursor)}`
      : `${CLAWHUB_API}/skills?limit=100`;

    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to list skills (HTTP ${res.status})`);
    }

    const data = (await res.json()) as {
      skills: { slug: string }[];
      next_cursor: string | null;
    };
    slugs.push(...data.skills.map((s) => s.slug));
    cursor = data.next_cursor;
    if (!cursor) break;
  }

  return slugs;
}
