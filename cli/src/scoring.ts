/**
 * Risk score calculation — aggregates findings into a 0-100 risk score.
 */

import type { Finding, RiskLevel, ScoreBreakdown } from './types.js';

export interface ScanScore {
  total: number;
  category: RiskLevel;
  breakdown: ScoreBreakdown;
}

/** Calculate risk score from findings. */
export function calculateScore(findings: Finding[]): ScanScore {
  let score = 0;
  let critical_count = 0;
  let high_count = 0;
  let medium_count = 0;
  let low_count = 0;
  let info_count = 0;

  for (const f of findings) {
    switch (f.severity) {
      case 'Critical':
        score += 30;
        critical_count++;
        break;
      case 'High':
        score += 15;
        high_count++;
        break;
      case 'Medium':
        score += 5;
        medium_count++;
        break;
      case 'Low':
        score += 2;
        low_count++;
        break;
      case 'Info':
        info_count++;
        break;
    }
  }

  score = Math.min(score, 100);

  let category: RiskLevel;
  if (score === 0) category = 'Clean';
  else if (score <= 25) category = 'Low';
  else if (score <= 50) category = 'Medium';
  else if (score <= 75) category = 'High';
  else category = 'Critical';

  return {
    total: score,
    category,
    breakdown: { critical_count, high_count, medium_count, low_count, info_count },
  };
}
