/**
 * First-match firewall policy auditor.
 *
 * For an ordered rule list [r0, r1, ...] the decision for an address is
 * determined by the first rule whose CIDR contains it; with no match the
 * default decision is "deny".
 *
 * Rather than enumerate the IPv4 space, address sets are tracked as sorted
 * disjoint interval lists (see intervals.ts). This makes per-rule residual
 * coverage and adjacent-swap impact cheap and exact.
 */

import {
  cidrRange,
  cidrSize,
  formatIp,
  parseCidr,
  parseIp,
  type Cidr,
} from "./ip.js";
import {
  addRange,
  countAddresses,
  minimumAddress,
  subtract,
  EMPTY,
  type IntervalSet,
} from "./intervals.js";

export type Action = "allow" | "deny";

export type RuleStatus = "active" | "partial" | "shadowed";

export interface CoverageStep {
  /** Earlier rule selected at this step. */
  ruleId: string;
  ruleIndex: number;
  /**
   * Closed interval of target addresses newly covered at this step,
   * dotted-quad, inclusive on both ends.
   */
  lo: string;
  hi: string;
}

/**
 * Certificate that the rules before a shadowed rule already cover its whole
 * CIDR: the selected rule ids plus, per step, the closed interval of target
 * addresses that step newly covers. The step intervals are disjoint and
 * their union is exactly the target CIDR.
 */
export interface CoverageProof {
  /** Ids of the selected earlier rules, in selection order. */
  ruleIds: string[];
  steps: CoverageStep[];
}

export interface RuleInput {
  id: string;
  action: Action;
  cidr: string;
}

export interface RuleAudit {
  id: string;
  action: Action;
  cidr: string;
  index: number;
  /** Addresses of this CIDR matched by no earlier rule. */
  exposedAddresses: number;
  /** Total addresses in this CIDR. */
  totalAddresses: number;
  /** Smallest address the rule still decides (null when fully shadowed). */
  witness: string | null;
  status: RuleStatus;
  /**
   * Shadowed rules only: a minimal-count certificate that earlier rules
   * already cover this whole CIDR. Null for active/partial rules.
   */
  coverageProof: CoverageProof | null;
}

export interface SwapAudit {
  /** Rule indices whose order is swapped (adjacent pair). */
  indices: [number, number];
  ids: [string, string];
  actions: [Action, Action];
  /**
   * Addresses whose allow/deny decision changes after swapping the two
   * adjacent rules. Rules before/after the pair keep their priority, so only
   * addresses both rules cover and no earlier rule covers can be affected.
   */
  changedAddresses: number;
  /** Smallest affected address (null when nothing changes). */
  witness: string | null;
}

export interface QueryResult {
  query: string;
  /** First matching rule, or null when nothing matches (default deny). */
  ruleId: string | null;
  action: Action; // "deny" when ruleId is null
  index: number | null;
}

export interface AuditReport {
  rules: RuleAudit[];
  swaps: SwapAudit[];
  queries: QueryResult[];
  summary: {
    ruleCount: number;
    queryCount: number;
    shadowedCount: number;
    defaultAction: Action;
  };
}

/** Validation failure carrying a JSON-pointer-ish path for the CLI/server. */
export class ValidationError extends Error {
  readonly path: string;
  constructor(message: string, path = "$") {
    super(`${path}: ${message}`);
    this.name = "ValidationError";
    this.path = path;
  }
}

const ROOT_FIELDS = new Set(["rules", "queries"]);
const RULE_FIELDS = new Set(["id", "action", "cidr"]);
const MAX_RULES = 300;
const MAX_QUERIES = 100;

const knownObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function rejectUnknownFields(
  obj: Record<string, unknown>,
  known: Set<string>,
  path: string,
): void {
  for (const key of Object.keys(obj)) {
    if (!known.has(key)) {
      throw new ValidationError(`unknown field "${key}"`, path);
    }
  }
}

interface ParsedRule {
  input: RuleInput;
  cidr: Cidr;
}

function parseRules(value: unknown): ParsedRule[] {
  if (!Array.isArray(value)) {
    throw new ValidationError("rules must be an array", "$.rules");
  }
  if (value.length < 1) {
    throw new ValidationError("at least one rule is required", "$.rules");
  }
  if (value.length > MAX_RULES) {
    throw new ValidationError(
      `too many rules: ${value.length} > ${MAX_RULES}`,
      "$.rules",
    );
  }

  const rules: ParsedRule[] = [];
  const seenIds = new Set<string>();
  value.forEach((raw, i) => {
    const path = `$.rules[${i}]`;
    if (!knownObject(raw)) {
      throw new ValidationError("rule must be an object", path);
    }
    rejectUnknownFields(raw, RULE_FIELDS, path);

    const { id, action, cidr } = raw;
    if (typeof id !== "string" || id.length === 0) {
      throw new ValidationError("id must be a non-empty string", `${path}.id`);
    }
    if (seenIds.has(id)) {
      throw new ValidationError(`duplicate rule id "${id}"`, `${path}.id`);
    }
    if (action !== "allow" && action !== "deny") {
      throw new ValidationError(
        'action must be "allow" or "deny"',
        `${path}.action`,
      );
    }
    if (typeof cidr !== "string") {
      throw new ValidationError("cidr must be a string", `${path}.cidr`);
    }

    let parsedCidr: Cidr;
    try {
      parsedCidr = parseCidr(cidr);
    } catch (err) {
      throw new ValidationError((err as Error).message, `${path}.cidr`);
    }

    seenIds.add(id);
    rules.push({ input: { id, action, cidr }, cidr: parsedCidr });
  });
  return rules;
}

function parseQueries(value: unknown): number[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ValidationError("queries must be an array", "$.queries");
  }
  if (value.length > MAX_QUERIES) {
    throw new ValidationError(
      `too many queries: ${value.length} > ${MAX_QUERIES}`,
      "$.queries",
    );
  }
  return value.map((raw, i) => {
    const path = `$.queries[${i}]`;
    try {
      return parseIp(raw);
    } catch (err) {
      throw new ValidationError((err as Error).message, path);
    }
  });
}

/** Parse and validate the raw JSON request body. */
export function parseRequest(raw: unknown): {
  rules: ParsedRule[];
  queries: number[];
  rawQueries: unknown[];
} {
  if (!knownObject(raw)) {
    throw new ValidationError("request body must be a JSON object");
  }
  rejectUnknownFields(raw, ROOT_FIELDS, "$");
  if (!("rules" in raw)) {
    throw new ValidationError("missing required field rules", "$.rules");
  }
  const rules = parseRules(raw.rules);
  const queryIps = parseQueries(raw.queries);
  return {
    rules,
    queries: queryIps,
    rawQueries: raw.queries === undefined ? [] : (raw.queries as unknown[]),
  };
}

const statusFor = (
  exposed: IntervalSet,
  totalAddresses: number,
): RuleStatus => {
  if (exposed.length === 0) return "shadowed";
  if (countAddresses(exposed) === totalAddresses) return "active";
  return "partial";
};

/**
 * Minimal-count certificate that the rules before a shadowed rule already
 * cover its entire CIDR.
 *
 * Each earlier CIDR is intersected with the target range; the classic
 * interval-cover greedy then repeatedly takes, among the spans covering the
 * smallest still-uncovered target address, the one reaching farthest right
 * (ties go to the earlier rule index). That greedy choice is optimal for
 * covering a contiguous range, so the number of steps is the smallest
 * possible. All arithmetic runs on unsigned 32-bit addresses held in
 * doubles (2^32 stays exact) — no per-address iteration.
 */
function buildCoverageProof(
  rules: ParsedRule[],
  targetIndex: number,
): CoverageProof {
  const target = rules[targetIndex]!.cidr;

  // Intersect every earlier CIDR with the target range.
  const spans: Array<{ index: number; id: string; lo: number; hi: number }> =
    [];
  for (let j = 0; j < targetIndex; j++) {
    const earlier = rules[j]!;
    const lo = Math.max(earlier.cidr.lo, target.lo);
    const hi = Math.min(earlier.cidr.hi, target.hi);
    if (lo <= hi) spans.push({ index: j, id: earlier.input.id, lo, hi });
  }

  const ruleIds: string[] = [];
  const steps: CoverageStep[] = [];
  let current = target.lo;
  while (current <= target.hi) {
    // Spans are scanned in rule order and only a strictly farther right
    // endpoint replaces the pick, so ties keep the earliest rule index.
    let best: (typeof spans)[number] | undefined;
    for (const span of spans) {
      if (span.lo > current || span.hi < current) continue;
      if (best === undefined || span.hi > best.hi) best = span;
    }
    if (best === undefined) {
      // Unreachable: the rule was verified shadowed, so earlier rules cover it.
      throw new Error(
        `internal error: shadowed rule at index ${targetIndex} not covered by earlier rules`,
      );
    }
    ruleIds.push(best.id);
    steps.push({
      ruleId: best.id,
      ruleIndex: best.index,
      lo: formatIp(current),
      hi: formatIp(best.hi),
    });
    // May become 2^32 for a target reaching 255.255.255.255; still exact.
    current = best.hi + 1;
  }
  return { ruleIds, steps };
}

/** Run the full audit over parsed input. */
export function audit(raw: unknown): AuditReport {
  const { rules, queries, rawQueries } = parseRequest(raw);

  // Per-rule residual analysis. `covered` = addresses decided by rules 0..i-1.
  const coveredBefore: IntervalSet[] = [];
  const exposedSets: IntervalSet[] = [];
  let covered: IntervalSet = EMPTY;

  const ruleReports: RuleAudit[] = rules.map(({ input, cidr }, i) => {
    coveredBefore.push(covered);
    const total = cidrSize(cidr.prefix);
    const exposed = subtract([cidrRange(cidr)], covered);
    exposedSets.push(exposed);
    const exposedCount = countAddresses(exposed);
    const witnessIp = minimumAddress(exposed);
    covered = addRange(covered, cidrRange(cidr));
    const status = statusFor(exposed, total);

    return {
      id: input.id,
      action: input.action,
      cidr: input.cidr,
      index: i,
      exposedAddresses: exposedCount,
      totalAddresses: total,
      witness: witnessIp === null ? null : formatIp(witnessIp),
      status,
      coverageProof:
        status === "shadowed" ? buildCoverageProof(rules, i) : null,
    };
  });

  // Adjacent swap analysis.
  const swapReports: SwapAudit[] = [];
  for (let i = 0; i + 1 < rules.length; i++) {
    const a = rules[i]!;
    const b = rules[i + 1]!;
    const beforeSet = coveredBefore[i]!;

    // After a swap, addresses covered by exactly one of the pair are still
    // decided by that same rule — only the mutual intersection can flip, and
    // only when the actions differ. Earlier rules shadow the pair there too.
    let changed: IntervalSet = EMPTY;
    if (a.input.action !== b.input.action) {
      const lo = Math.max(a.cidr.lo, b.cidr.lo);
      const hi = Math.min(a.cidr.hi, b.cidr.hi);
      const intersection: IntervalSet = lo <= hi ? [{ lo, hi }] : EMPTY;
      changed = subtract(intersection, beforeSet);
    }

    const witnessIp = minimumAddress(changed);
    swapReports.push({
      indices: [i, i + 1],
      ids: [a.input.id, b.input.id],
      actions: [a.input.action, b.input.action],
      changedAddresses: countAddresses(changed),
      witness: witnessIp === null ? null : formatIp(witnessIp),
    });
  }

  // Query resolution: first matching rule wins, otherwise default deny.
  const queryReports: QueryResult[] = queries.map((ip, i) => {
    for (let r = 0; r < rules.length; r++) {
      const { cidr, input } = rules[r]!;
      if (ip >= cidr.lo && ip <= cidr.hi) {
        return {
          query: String(rawQueries[i]),
          ruleId: input.id,
          action: input.action,
          index: r,
        };
      }
    }
    return {
      query: String(rawQueries[i]),
      action: "deny" as Action,
      ruleId: null,
      index: null,
    };
  });

  return {
    rules: ruleReports,
    swaps: swapReports,
    queries: queryReports,
    summary: {
      ruleCount: rules.length,
      queryCount: queries.length,
      shadowedCount: ruleReports.filter((r) => r.status === "shadowed").length,
      defaultAction: "deny",
    },
  };
}
