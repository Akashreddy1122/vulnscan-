# Detection design, scoring and limits

## Principle

No single signal decides a verdict. Every contributing factor is recorded with a weight and a plain-language description, so an analyst can see *why* a file or event was flagged and dispute it. Probabilistic detection is the only honest model: the platform reduces risk and workload, it does not guarantee detection.

## File verdicts

`engine/scanner.py` runs these stages on the raw bytes:

| Stage | Source | Contribution |
|---|---|---|
| IOC hash match | `engine/rules/iocs.json` + operator IOCs in DB | Confidence-weighted, counted once per logical indicator |
| IOC content match | domains, IPs, URLs, regexes | Confidence-weighted |
| YARA-subset rules | `engine/rules/yara/*.yrl` + `data/rules/yara` (custom) | Weight from `severity` meta; a `critical` hit floors the verdict to at least *malicious/high* |
| Static heuristics | `engine/static_analysis.py` | Entropy, PE structure (malformed, W+X sections, packer names, overlay, few imports), script webshell shape, double extensions, ~70 suspicious string patterns |
| Explainable ML | `engine/ml_model.py`, weights in `engine/model/weights.json` | Only pushes the score up, scaled by probability above 0.5 |
| History | prior scans with the same SHA-256 | Small weight |

The total is capped to 0–100. Bands: ≥85 *malicious/critical*, ≥65 *malicious/high*, ≥40 *suspicious/medium*, ≥20 *suspicious/low*, else *clean/info*.

The EICAR standard test string is a special case: every AV product flags it, so it is reported as *malicious* with *info* severity and is labelled as a test file.

### The ML model

- Algorithm: L2-regularised logistic regression, implemented from scratch in `scripts/train_model.py`.
- Features: 22 static features (size, entropy, structure, indicator counts, filename patterns).
- Training data: **generated** benign and malicious-*shaped* inert samples (text, JSON, CSV, real ELF binaries from the host, and synthetic PE files). No real malware is used or shipped.
- Measured: training accuracy on that generated set only. **Real-world precision and recall are unknown.** Retrain on your own labelled corpus before trusting it for anything beyond triage prioritisation.

### YARA-subset, precisely

`engine/yara_lite.py` is a pure-Python implementation of a subset of the YARA language:

- Strings: `"text"` (with `nocase`, `wide`, `fullword`), hex with `??` nibble wildcards (`[n-m]` jumps are removed, which is conservative), `/regex/` with `i`/`s` flags.
- Conditions: `any of them`, `all of them`, `N of them`, `any of ($a*, $b)`, `all of ($x*)`, `$id`, `and`/`or`/`not`, parentheses, `filesize` comparisons with `KB`/`MB`.
- Anything else is a **syntax error**: unknown tokens in conditions, rule references and modules are rejected rather than silently treated as true. Tests in `backend/tests/test_yara_lite.py` pin this.

It is not `libyara`. Rules written for real YARA may need changes; the `yara-validate` endpoint and the UI rule workbench report exactly what does not compile.

## Log and process rules

- `engine/rules/log_rules.json`: regex per line, `threshold` within `window_seconds`, and an optional `escalate` block (e.g. ≥10 SSH failures from one source becomes *SSH brute-force attempt*, high).
- `engine/rules/process_rules.json`: regex against `name`, `cmdline`, `exe`, `username`, with an optional `exclude_exe` location allow-list.

## False-positive reduction (what is actually implemented)

- Deduplication by `alert_key`; repeats increment `count` and refresh evidence instead of creating new alerts.
- Thresholds and time windows per rule.
- Analyst false-positive workflow requiring a reason. Optional suppression by alert-key pattern with expiry; suppressions are audited and reversible.
- Alerts that were *resolved* reopen on recurrence; *false-positive* alerts stay closed unless the suppression is removed.

Tuning examples from development, both fixed and covered by regression tests:

- `proc.masquerade_name` flagged `python` running from a virtualenv. The rule now matches only core daemon names, and the location allow-list applies to any field.
- The IOC pack listed one EICAR file under three hashes, so it was counted three times. Indicators are now counted once.

## Known gaps

- No kernel-level behavioural engine. "Ransomware" coverage is the rule set (shadow-copy deletion, ransom-note language) plus FIM volume; mass-encryption detection by entropy-delta over file writes is not implemented.
- Network detection uses connection metadata only. No packet capture, no TLS inspection, no protocol decoding beyond EVE-JSON import.
- The CVE knowledge base is a curated subset (about 40 entries) with version-range matching. It will miss vulnerabilities and can mis-classify packages whose versioning differs from upstream.
- SCA probes are Linux-first. Windows and macOS checks are limited to what the probes support.
- The MITRE ATT&CK set is a curated subset of techniques, not the full matrix.
- Explanations describe the factors that fired. They do not prove causation.
