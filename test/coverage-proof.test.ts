import { describe, expect, it } from "vitest";
import {
  audit,
  type Action,
  type AuditReport,
  type CoverageProof,
} from "../src/audit.js";
import { formatIp, parseIp } from "../src/ip.js";
import { runAudit } from "../src/runtime.js";
import { createPolicyServer } from "../src/server.js";

const rule = (id: string, action: Action, cidr: string) => ({ id, action, cidr });
type R = ReturnType<typeof rule>;

const run = (rules: R[], queries: string[] = []) => audit({ rules, queries });

const proofOf = (report: AuditReport, index: number): CoverageProof => {
  const proof = report.rules[index]!.coverageProof;
  expect(proof, `rule ${index} must carry a coverage proof`).not.toBeNull();
  return proof!;
};

describe("shadowed-rule coverage proof (hand-computed)", () => {
  it("covers a /24 with the two half-blocks that shadow it", () => {
    const rep = run([
      rule("lo", "allow", "10.0.0.0/25"),
      rule("hi", "deny", "10.0.0.128/25"),
      rule("all", "allow", "10.0.0.0/24"),
    ]);
    expect(rep.rules[2]!.status).toBe("shadowed");
    expect(proofOf(rep, 2)).toEqual({
      ruleIds: ["lo", "hi"],
      steps: [
        { ruleId: "lo", ruleIndex: 0, lo: "10.0.0.0", hi: "10.0.0.127" },
        { ruleId: "hi", ruleIndex: 1, lo: "10.0.0.128", hi: "10.0.0.255" },
      ],
    });
  });

  it("prefers the span reaching farthest right over a shorter earlier one", () => {
    const rep = run([
      rule("short", "allow", "10.0.0.0/26"), // .0..63
      rule("long", "deny", "10.0.0.0/25"), // .0..127 — same start, farther right
      rule("tail", "allow", "10.0.0.128/25"),
      rule("all", "deny", "10.0.0.0/24"),
    ]);
    const proof = proofOf(rep, 3);
    expect(proof.ruleIds).toEqual(["long", "tail"]);
    expect(proof.steps[0]).toMatchObject({ lo: "10.0.0.0", hi: "10.0.0.127" });
  });

  it("breaks right-endpoint ties by the earlier rule index", () => {
    const rep = run([
      rule("first", "allow", "10.0.0.0/25"),
      rule("second", "deny", "10.0.0.0/25"), // identical span, later index
      rule("tail", "allow", "10.0.0.128/25"),
      rule("all", "deny", "10.0.0.0/24"),
    ]);
    expect(proofOf(rep, 3).ruleIds).toEqual(["first", "tail"]);
  });

  it("clamps an earlier /0 to the target range", () => {
    const rep = run([
      rule("any", "deny", "0.0.0.0/0"),
      rule("net", "allow", "10.0.0.0/8"),
    ]);
    expect(proofOf(rep, 1)).toEqual({
      ruleIds: ["any"],
      steps: [{ ruleId: "any", ruleIndex: 0, lo: "10.0.0.0", hi: "10.255.255.255" }],
    });
  });

  it("covers a shadowed /0 across the unsigned 32-bit boundaries", () => {
    const rep = run([
      rule("low-half", "allow", "0.0.0.0/1"),
      rule("high-half", "deny", "128.0.0.0/1"),
      rule("everything", "allow", "0.0.0.0/0"),
    ]);
    expect(rep.rules[2]).toMatchObject({ status: "shadowed", exposedAddresses: 0 });
    expect(proofOf(rep, 2)).toEqual({
      ruleIds: ["low-half", "high-half"],
      steps: [
        { ruleId: "low-half", ruleIndex: 0, lo: "0.0.0.0", hi: "127.255.255.255" },
        { ruleId: "high-half", ruleIndex: 1, lo: "128.0.0.0", hi: "255.255.255.255" },
      ],
    });
  });

  it("covers a shadowed /0 with a single earlier /0", () => {
    const rep = run([
      rule("any", "deny", "0.0.0.0/0"),
      rule("also-any", "allow", "0.0.0.0/0"),
    ]);
    expect(proofOf(rep, 1).steps).toEqual([
      { ruleId: "any", ruleIndex: 0, lo: "0.0.0.0", hi: "255.255.255.255" },
    ]);
  });

  it("certifies the very last address 255.255.255.255/32", () => {
    const rep = run([
      rule("any", "allow", "0.0.0.0/0"),
      rule("last", "deny", "255.255.255.255/32"),
    ]);
    expect(proofOf(rep, 1).steps).toEqual([
      { ruleId: "any", ruleIndex: 0, lo: "255.255.255.255", hi: "255.255.255.255" },
    ]);
  });

  it("attaches no certificate to active or partial rules", () => {
    const rep = run([
      rule("mid", "deny", "10.0.0.64/26"),
      rule("whole", "allow", "10.0.0.0/24"),
    ]);
    expect(rep.rules[0]).toMatchObject({ status: "active", coverageProof: null });
    expect(rep.rules[1]).toMatchObject({ status: "partial", coverageProof: null });
  });

  it("leaves the pre-existing rule fields untouched", () => {
    const rep = run([
      rule("a", "allow", "10.0.0.0/24"),
      rule("b", "deny", "10.0.0.0/25"),
    ]);
    expect(rep.rules[1]).toMatchObject({
      id: "b",
      action: "deny",
      cidr: "10.0.0.0/25",
      index: 1,
      exposedAddresses: 0,
      totalAddresses: 128,
      witness: null,
      status: "shadowed",
    });
    expect(rep.summary.shadowedCount).toBe(1);
  });
});

/**
 * Minimality and correctness of the certificate, checked against subset
 * enumeration inside a tiny subnet. The oracle may walk addresses; the
 * implementation under test works on intervals only.
 */
describe("coverage proof vs brute-force subset enumeration in 10.13.0.0/28", () => {
  const BASE = parseIp("10.13.0.0");
  const PREFIX = 28;
  const SUBNET_SIZE = 2 ** (32 - PREFIX); // 16 addresses

  interface GenRule {
    id: string;
    action: Action;
    lo: number;
    hi: number;
    cidrText: string;
  }

  function mulberry32(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function randomRules(rand: () => number, count: number): GenRule[] {
    const rules: GenRule[] = [];
    const used = new Set<string>();
    let guard = 0;
    while (rules.length < count && guard < count * 50) {
      guard++;
      const hostBits = Math.floor(rand() * (32 - PREFIX + 1));
      const block = 2 ** hostBits;
      const offset = Math.floor(rand() * (SUBNET_SIZE / block)) * block;
      const p = 32 - hostBits;
      const lo = (BASE + offset) >>> 0;
      const key = `${lo}/${p}`;
      if (used.has(key)) continue;
      used.add(key);
      rules.push({
        id: `r${rules.length}`,
        action: rand() < 0.5 ? "allow" : "deny",
        lo,
        hi: (lo + block - 1) >>> 0,
        cidrText: `${formatIp(lo)}/${p}`,
      });
    }
    return rules;
  }

  /** Smallest number of earlier rules whose CIDRs jointly cover [lo, hi]. */
  function minCoverCount(earlier: GenRule[], lo: number, hi: number): number {
    const covers = (mask: number): boolean => {
      for (let a = lo; a <= hi; a++) {
        let hit = false;
        for (let j = 0; j < earlier.length; j++) {
          if ((mask & (1 << j)) !== 0 && a >= earlier[j]!.lo && a <= earlier[j]!.hi) {
            hit = true;
            break;
          }
        }
        if (!hit) return false;
      }
      return true;
    };
    let best = Number.POSITIVE_INFINITY;
    for (let mask = 1; mask < 1 << earlier.length; mask++) {
      let pop = 0;
      for (let m = mask; m !== 0; m &= m - 1) pop++;
      if (pop < best && covers(mask)) best = pop;
    }
    return best;
  }

  function checkProof(rules: GenRule[], report: AuditReport, i: number, label: string): void {
    const target = rules[i]!;
    const earlier = rules.slice(0, i);
    const proof = report.rules[i]!.coverageProof;
    expect(proof, `${label} rule ${i} proof`).not.toBeNull();
    const { ruleIds, steps } = proof!;
    expect(steps.length, `${label} rule ${i} step count`).toBe(ruleIds.length);

    // Minimality: no smaller subset of the earlier rules covers the target.
    expect(ruleIds.length, `${label} rule ${i} minimal`).toBe(
      minCoverCount(earlier, target.lo, target.hi),
    );

    const seenIndices = new Set<number>();
    let expectedLo = target.lo;
    steps.forEach((step, k) => {
      const stepLo = parseIp(step.lo);
      const stepHi = parseIp(step.hi);

      // The step names a distinct earlier rule, consistently in both views.
      expect(step.ruleIndex, `${label} step ${k} is an earlier rule`).toBeLessThan(i);
      expect(rules[step.ruleIndex]!.id).toBe(step.ruleId);
      expect(ruleIds[k]).toBe(step.ruleId);
      expect(seenIndices.has(step.ruleIndex)).toBe(false);
      seenIndices.add(step.ruleIndex);

      // The segment starts exactly at the smallest still-uncovered address
      // and stays inside the target.
      expect(stepLo, `${label} step ${k} starts at first gap`).toBe(expectedLo);
      expect(stepHi).toBeGreaterThanOrEqual(stepLo);
      expect(stepHi).toBeLessThanOrEqual(target.hi);

      // The segment is genuinely covered by the rule it names.
      expect(stepLo, `${label} step ${k} within its rule`).toBeGreaterThanOrEqual(
        rules[step.ruleIndex]!.lo,
      );
      expect(stepHi, `${label} step ${k} within its rule`).toBeLessThanOrEqual(
        rules[step.ruleIndex]!.hi,
      );

      // Greedy choice: farthest right endpoint among the intersected spans
      // covering stepLo; ties resolved towards the earlier rule index.
      let farthest = -1;
      for (const e of earlier) {
        const sLo = Math.max(e.lo, target.lo);
        const sHi = Math.min(e.hi, target.hi);
        if (sLo <= stepLo && stepLo <= sHi) farthest = Math.max(farthest, sHi);
      }
      expect(stepHi, `${label} step ${k} farthest right`).toBe(farthest);
      for (let j = 0; j < step.ruleIndex; j++) {
        const sLo = Math.max(earlier[j]!.lo, target.lo);
        const sHi = Math.min(earlier[j]!.hi, target.hi);
        expect(
          sLo <= stepLo && stepLo <= sHi && sHi === stepHi,
          `${label} step ${k} earlier tie-break`,
        ).toBe(false);
      }

      expectedLo = stepHi + 1;
    });

    // Contiguous disjoint steps from target.lo to target.hi, each inside the
    // target: the union of the certificate intervals is exactly the target.
    expect(expectedLo, `${label} rule ${i} exact union`).toBe(target.hi + 1);
  }

  for (let seed = 1; seed <= 250; seed++) {
    it(`random policy #${seed}: proofs are minimal, exact and deterministic`, () => {
      const rand = mulberry32(seed * 7919 + 13);
      const count = 1 + Math.floor(rand() * 8);
      const rules = randomRules(rand, count);
      const input = {
        rules: rules.map((r) => ({ id: r.id, action: r.action, cidr: r.cidrText })),
      };
      const label = `seed-${seed}`;
      const report = audit(input);

      report.rules.forEach((r, i) => {
        if (r.status === "shadowed") {
          checkProof(rules, report, i, label);
        } else {
          expect(r.coverageProof, `${label} rule ${i} has no proof`).toBeNull();
        }
      });

      // Repeated runs over the same policy agree exactly.
      expect(audit(input), `${label} repeat run`).toEqual(report);
      // Reordering JSON keys (not rules) must not change anything either.
      const reshuffled = {
        rules: rules.map((r) => ({ cidr: r.cidrText, id: r.id, action: r.action })),
      };
      expect(audit(reshuffled), `${label} key order`).toEqual(report);
    });
  }
});

describe("CLI and HTTP share the same certificate", () => {
  const policy = {
    rules: [
      rule("edge", "allow", "10.0.0.0/25"),
      rule("edge2", "deny", "10.0.0.128/25"),
      rule("lan", "allow", "10.0.0.0/24"),
      rule("any", "deny", "0.0.0.0/0"),
      rule("late", "allow", "192.168.0.0/16"),
    ],
    queries: ["10.0.0.5", "8.8.8.8"],
  };

  it("runAudit (the CLI path) emits the coverage proof", () => {
    const report = runAudit(JSON.stringify(policy)) as AuditReport;
    expect(report.rules[2]!.coverageProof).toEqual({
      ruleIds: ["edge", "edge2"],
      steps: [
        { ruleId: "edge", ruleIndex: 0, lo: "10.0.0.0", hi: "10.0.0.127" },
        { ruleId: "edge2", ruleIndex: 1, lo: "10.0.0.128", hi: "10.0.0.255" },
      ],
    });
    expect(report.rules[4]!.coverageProof).toEqual({
      ruleIds: ["any"],
      steps: [{ ruleId: "any", ruleIndex: 3, lo: "192.168.0.0", hi: "192.168.255.255" }],
    });
  });

  it("POST /audit returns a byte-identical report to the CLI path", async () => {
    const server = createPolicyServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("server did not bind a TCP port");
      }
      const body = JSON.stringify(policy);
      const res = await fetch(`http://127.0.0.1:${address.port}/audit`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      expect(res.status).toBe(200);
      // The HTTP response and the CLI's runAudit output are the same report,
      // coverage proofs included.
      expect(await res.json()).toEqual(runAudit(body));
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});
