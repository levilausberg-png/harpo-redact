# Security policy

Harpo is a privacy control: a way to make it send something it should not have sent is a security bug,
even when it looks like a detection gap. Report it privately, never in a public GitHub issue.

## How to report

1. **Preferred:** GitHub's private vulnerability reporting. On the repository's **Security** tab, choose **Report a
   vulnerability** (https://github.com/levilausberg-png/harpo-redact/security/advisories/new). The report stays private
   between you and the maintainers.
2. **Fallback:** email Security.Harpo@gmail.com.

Include a minimal request that reproduces it, with invented values, and the Harpo version and configuration you used.
Reports are reviewed as promptly as practical.

## What to report privately

In order of severity:

1. Sensitive data crosses a boundary it should not: a forwarded body contains a value the policy says must not leave
   (breaks INV-01, docs/INVARIANTS.md).
2. A way past egress verification.
3. A way past a policy or override control: an override restoring a raw value, a block that does not hold.
4. Raw request content or sensitive values in logs, metrics, error responses or audit lines.
5. An unchecked request surface: an unknown field or content part forwarded without inspection.
6. A document released without the verification it requires.
7. Denial of service with a security impact: a small request that costs a lot, below the configured budgets.

## What can be a public issue

A plain detection miss, a kind of value Harpo does not catch yet, can go in a public *Detection miss* issue, with
invented or synthetic values only and never real private data. If you are unsure whether it is a miss or a way past a
protection that should have held, report it privately.

Every reproducible detection failure becomes a permanent regression test and, where it fits, a LeakBench case
(bench/leakbench.py), so the fix stays fixed. Known limitations are listed in the README and in the threat model
(docs/THREAT_MODEL.md); reports about them are still useful when they come with data.
