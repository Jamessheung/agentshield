/**
 * ClawHub HTTP API client for fetching skills from the registry.
 */

const CLAWHUB_API = 'https://clawhub.com/api';

/** Default request timeout in milliseconds. */
const DEFAULT_TIMEOUT_MS = 15_000;

/** Maximum retry attempts for transient failures. */
const MAX_RETRIES = 3;

/** Base delay for exponential backoff (ms). */
const BASE_DELAY_MS = 1000;

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

/** Determines if an HTTP status code is retryable. */
function isRetryable(status: number): boolean {
  return status === 429 || status >= 500;
}

/** Sleep for the given number of milliseconds. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Fetch with timeout and exponential-backoff retry for transient errors. */
async function fetchWithRetry(
  url: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
      await sleep(delay);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);

      if (res.ok) {
        return res;
      }

      // Non-retryable error — fail immediately
      if (!isRetryable(res.status)) {
        throw new Error(`HTTP ${res.status}`);
      }

      lastError = new Error(`HTTP ${res.status}`);
    } catch (err: unknown) {
      clearTimeout(timer);
      if (err instanceof Error && err.name === 'AbortError') {
        lastError = new Error(`Request timed out after ${timeoutMs}ms`);
      } else if (err instanceof Error) {
        lastError = err;
      } else {
        lastError = new Error(String(err));
      }
    }
  }

  throw new Error(
    `Failed after ${MAX_RETRIES + 1} attempts: ${lastError?.message}`,
  );
}

/** Fetch a single skill by slug from ClawHub. */
export async function fetchSkill(slug: string): Promise<ClawHubSkill> {
  const url = `${CLAWHUB_API}/skills/${encodeURIComponent(slug)}`;
  try {
    const res = await fetchWithRetry(url);
    return (await res.json()) as ClawHubSkill;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Skill not found: ${slug} (${msg})`);
  }
}

/** List all skill slugs from ClawHub (paginated). */
export async function listAllSlugs(): Promise<string[]> {
  const slugs: string[] = [];
  let cursor: string | null = null;

  while (true) {
    const url = cursor
      ? `${CLAWHUB_API}/skills?limit=100&cursor=${encodeURIComponent(cursor)}`
      : `${CLAWHUB_API}/skills?limit=100`;

    try {
      const res = await fetchWithRetry(url);
      const data = (await res.json()) as {
        skills: { slug: string }[];
        next_cursor: string | null;
      };
      slugs.push(...data.skills.map((s) => s.slug));
      cursor = data.next_cursor;
      if (!cursor) break;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to list skills (${msg})`);
    }
  }

  return slugs;
}
