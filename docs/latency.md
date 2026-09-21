# SIR gate latency

This report measures `validate_sir()` only. It excludes the benchmark runner,
provider calls, and ledger writes. All latency values are **microseconds (µs)**,
and every result is a distribution rather than a mean. The committed JSON is
the machine-readable measurement record; `tools/latency_report.py` generated
all tables below from that record.

## Reproduce

```bash
PYTHONPATH=src python tools/latency_report.py --measure \
  --results docs/latency-results.json --markdown-out docs/latency.md
```

Re-measurement will naturally produce different values. The drift test instead
renders the committed measurement record and requires the published generated
region to match byte-for-byte. This prevents hand-copying while avoiding a
noisy performance threshold in CI.

## Methodology and boundary

Measurements were made on a 3-vCPU KVM machine with an Intel Xeon Platinum
8370C CPU at 2.80 GHz, Linux x86-64, and CPython 3.14.4. The process made 25
untimed warm-up calls, then made 500 sequential warm calls per normal case and
100 per pathological probe. The baseline ISC policy load was therefore
amortised; the domain policy-pack JSON load remains part of every
`validate_sir()` call because that is current function behaviour. Inputs and
checksums were built before timing. The monotonic, highest-available-resolution
`time.perf_counter_ns()` clock surrounded each individual function call.
Samples were not batched, trimmed, winsorised, or otherwise rejected: all
outliers are retained. Percentiles use linear interpolation between adjacent
ordered observations; standard deviation is the sample standard deviation.
No network was used.

“Terminating path” names the final decision precedence, not short-circuit work:
the current `_check_jailbreak()` implementation computes high-risk,
danger/safety, structural, deterministic-rule and obfuscation signals before
applying that precedence. Decode rows isolate one supported encoding at a time.
The inputs and construction recipes are committed in the generator.

<!-- BEGIN GENERATED LATENCY TABLES -->

### Terminating decision paths

| Case | Input chars | n | p50 (µs) | p95 (µs) | p99 (µs) | max (µs) | stdev (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|
| high-risk keyword | 25 | 500 | 321.7 | 468.5 | 806.3 | 6678.9 | 363.0 |
| danger + safety phrase | 27 | 500 | 355.2 | 487.4 | 2546.7 | 6072.9 | 440.6 |
| structural override exposure | 72 | 500 | 421.4 | 602.2 | 1402.0 | 4693.9 | 306.9 |
| deterministic rule match | 26 | 500 | 321.5 | 494.4 | 745.5 | 1242.2 | 94.6 |
| pass | 39 | 500 | 355.3 | 464.9 | 608.4 | 913.8 | 55.2 |

### Decode paths

| Case | Input chars | n | p50 (µs) | p95 (µs) | p99 (µs) | max (µs) | stdev (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|
| decode: Base64 | 52 | 500 | 311.1 | 388.0 | 514.2 | 764.3 | 43.8 |
| decode: ROT13 | 35 | 500 | 378.5 | 464.7 | 613.1 | 1176.4 | 61.4 |
| decode: hex | 61 | 500 | 401.4 | 515.6 | 654.2 | 3823.2 | 161.8 |
| decode: hex-escape | 112 | 500 | 387.7 | 487.0 | 630.1 | 3757.2 | 160.2 |

### Input-length sweep

| Case | Input chars | n | p50 (µs) | p95 (µs) | p99 (µs) | max (µs) | stdev (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|
| 64 chars | 64 | 500 | 398.1 | 549.2 | 717.1 | 17243.2 | 759.5 |
| 256 chars | 256 | 500 | 610.2 | 800.8 | 960.0 | 3420.4 | 144.1 |
| 1024 chars | 1024 | 500 | 1468.0 | 1812.5 | 2130.1 | 3949.0 | 203.4 |
| 4096 chars | 4096 | 500 | 4686.1 | 5287.5 | 6883.9 | 9462.7 | 412.9 |
| 8000 chars | 8000 | 500 | 8989.4 | 9947.8 | 13796.2 | 18029.2 | 1024.1 |

Least-squares fit over the measured p50 values: **1.0789 µs/character** with intercept **330.4 µs** (R² = **0.999889**).

#### Fit residuals

| Input chars | Observed p50 (µs) | Fitted p50 (µs) | Residual (µs) |
|---:|---:|---:|---:|
| 64 | 398.1 | 399.4 | -1.3 |
| 256 | 610.2 | 606.6 | +3.6 |
| 1024 | 1468.0 | 1435.1 | +32.9 |
| 4096 | 4686.1 | 4749.4 | -63.3 |
| 8000 | 8989.4 | 8961.3 | +28.1 |

### Pathological probes

| Case | Input chars | n | p50 (µs) | p95 (µs) | p99 (µs) | max (µs) | stdev (µs) |
|---|---:|---:|---:|---:|---:|---:|---:|
| all decoder markers | 193 | 100 | 532.4 | 595.9 | 608.3 | 921.2 | 46.3 |
| nested/repeated Base64 | 1068 | 100 | 1370.5 | 1509.5 | 3180.5 | 3401.8 | 275.1 |
| regex near-match repetition | 5877 | 100 | 7988.9 | 8427.5 | 16630.7 | 19259.7 | 1422.9 |
| many rule matches | 6900 | 100 | 8317.9 | 8764.3 | 8946.8 | 9266.2 | 198.7 |
| at size limit (8,000 chars) | 8000 | 100 | 8592.2 | 9077.7 | 12482.1 | 12548.4 | 622.7 |
| beyond size limit (8,001 chars) | 8001 | 100 | 179.8 | 223.7 | 252.9 | 263.5 | 18.6 |
| very long (100,000 chars) | 100000 | 100 | 179.8 | 222.6 | 254.3 | 326.9 | 22.5 |

The slowest p50 class found was **at size limit (8,000 chars)**, at **24.18×** the typical safe-pass p50.

### Typical safe-pass p50 decomposition (instrumented)

| Component | p50 (µs) | Share of instrumented total p50 |
|---|---:|---:|
| normalisation | 32.0 | 8.3% |
| rule evaluation after normalisation | 45.6 | 11.8% |
| ITGL construction and hashing | 117.2 | 30.3% |
| template and policy lookup | 127.6 | 33.0% |
| ISC envelope handling | 17.1 | 4.4% |
| result construction and orchestration | 13.5 | 3.5% |
| instrumentation overhead | 34.0 | 8.8% |

Instrumented n = 500; instrumented total p50 = **386.9 µs**, versus **352.9 µs** for the adjacent uninstrumented reference. Component p50 values need not sum exactly because each is the median of its own paired sample distribution.

### Effective input-character limits

| Enforcement pack | Template | `max_tokens` | Effective input ceiling (characters) |
|---|---|---:|---:|
| `data_exfiltration_pressure` | `HIPAA-ISC-v1` | 1500 | 6000 |
| `data_exfiltration_pressure` | `EU-AI-Act-ISC-v1` | 2000 | 8000 |
| `data_exfiltration_pressure` | `PCI-DSS-ISC-v1` | 1200 | 4800 |
| `eu_ai_act_compliance_pressure` | `HIPAA-ISC-v1` | 1500 | 6000 |
| `eu_ai_act_compliance_pressure` | `EU-AI-Act-ISC-v1` | 2000 | 8000 |
| `eu_ai_act_compliance_pressure` | `PCI-DSS-ISC-v1` | 1200 | 4800 |
| `generic_safety` | `HIPAA-ISC-v1` | 1500 | 6000 |
| `generic_safety` | `EU-AI-Act-ISC-v1` | 2000 | 8000 |
| `generic_safety` | `PCI-DSS-ISC-v1` | 1200 | 4800 |
| `hipaa_mental_health` | `HIPAA-ISC-v1` | 1200 | 4800 |
| `hipaa_mental_health` | `EU-AI-Act-ISC-v1` | 1800 | 7200 |
| `hipaa_mental_health` | `PCI-DSS-ISC-v1` | 1000 | 4000 |
| `pci_payments` | `PCI-DSS-ISC-v1` | 900 | 3600 |
| `pci_payments` | `EU-AI-Act-ISC-v1` | 1600 | 6400 |
| `pci_payments` | `HIPAA-ISC-v1` | 1200 | 4800 |
| `support_operator_override` | `HIPAA-ISC-v1` | 1500 | 6000 |
| `support_operator_override` | `EU-AI-Act-ISC-v1` | 2000 | 8000 |
| `support_operator_override` | `PCI-DSS-ISC-v1` | 1200 | 4800 |

<!-- END GENERATED LATENCY TABLES -->

## Length result

The coefficient and R² above describe only the five measured safe inputs from
64 through 8,000 characters on the selected template. The fit is excellent at
large sizes, but it does **not** imply microsecond-level per-call predictability,
especially for small inputs where fixed costs and runtime noise are a large
share of total latency. It is not a claim about arbitrary inputs or lengths
beyond the selected template's boundary. The residual table is published so
the pointwise errors remain visible rather than being hidden by a near-one R².

The decomposition uses timed wrappers around the actual normaliser, jailbreak
decision, ITGL append/hash function, policy loaders, and ISC envelope checks
during 500 additional safe-pass evaluations. Nothing is stubbed out. An
adjacent 500-call uninstrumented run measures wrapper overhead separately: the
instrumented p50 is 386.9 µs versus 352.9 µs uninstrumented, a 34.0 µs
instrumentation delta. After separating that overhead, the former unnamed
residual resolves into normalisation (32.0 µs), post-normalisation rule
evaluation (45.6 µs), ITGL construction/hashing (117.2 µs), template and policy
lookup (127.6 µs), ISC envelope handling (17.1 µs), and result construction and
orchestration (13.5 µs). **Policy/template lookup is the largest measured real
component, and evidence generation still costs substantially more than rule
evaluation.** Component medians are descriptive and need not add exactly.

## Pathological-input probe and security finding check

The probe deliberately includes every decoder marker in one input, repeated or
nested Base64, a structural-regex near match with hundreds of assignments,
many simultaneous rule matches, the measured template's exact 8,000-character
gate limit, one byte beyond it, and a 100,000-character input. Inputs above
8,000 characters on that template are
rejected by `_check_payload_size()` **before** `_check_jailbreak()` and its
decode paths run. Thus an input-size limit is enforced before decoding on this
measured `EU-AI-Act-ISC-v1` route. The Base64 decoder also independently caps a
candidate at 2,000 characters.

Functionally, an 8,001-character direct ISC string is **not truncated and not
evaluated for content**. It returns `status=BLOCKED` with reason
`friction_limit_exceeded`; `_check_jailbreak()` is never called. This is a hard
integration constraint, not merely a security property: prompts containing
retrieved context can routinely exceed it and will be rejected in full. The
limit is configurable per domain pack and template as `max_tokens`; the early
character boundary is `max_tokens * 4`. `EU-AI-Act-ISC-v1` in the measured
pack has `max_tokens=2000`, hence 8,000 characters. The common size check runs
after direct ISC, structured-request, or tool-result ingress has been converted
to an ISC payload, so it applies to all three modes. Structured and tool-result
schemas additionally reject their own content fields above 4,000 characters
before reaching this common check.

The generated table lists all 18 pack/template combinations across the six
installed enforcement packs. There is no global 8,000-character limit: current
effective ceilings range from 3,600 to 8,000 characters. Four packs share
6,000/8,000/4,800-character HIPAA/EU/PCI limits; `hipaa_mental_health` uses
4,800/7,200/4,000, while `pci_payments` uses 4,800/6,400/3,600 (shown in each
pack's declared template order above).

Despite its name, policy-pack `max_tokens` has **no effect on model output**.
Provider output budgets are configured separately by the runner. Here the field
only governs input admission: `_check_payload_size()` imposes the early
`max_tokens * 4` character ceiling, while `_check_friction()` compares the same
value with the larger of word count and `ceil(characters / 4)`. An operator who
changes `max_tokens` believing it controls output cost will inadvertently widen
or narrow which inputs the firewall accepts.

The four-characters-per-token arithmetic is visible in implementation-oriented
size-limit documentation, and the CJK undercount is recorded in the backlog,
but the field's misleading output-budget-like semantics and the English-text
heuristic are not documented as an operator contract. Four characters per
token is only a rough English-text heuristic; it does not hold reliably for
CJK and other scripts, and word count does not repair that mismatch.

**Recommendation (not implemented here):** add a separate explicit
`max_input_chars` field and retain `max_tokens` only as a deprecated
compatibility alias during migration. A rename alone would preserve the
conflation between a hard character cap and the later word/character estimate;
documentation alone leaves a high-risk industry-standard naming trap in place.
An explicit input field makes enforcement units unambiguous, allows a future
tokenizer-aware input budget to be separate, and avoids suggesting any control
over provider output. This report makes no configuration or runtime change.

No measured probe showed non-linear blowup, catastrophic regular-expression
backtracking, or unbounded decoder memory growth. This is a bounded empirical
statement about the committed cases and measured sizes, not proof for every
possible input. Had such behaviour appeared, publication would stop and it
would be reported as a security finding rather than hidden in a table.

The slowest class and its measured p50 multiple relative to the typical safe
`pass` input are recorded in `docs/latency-results.json` and discussed alongside
the generated pathological table; maxima and tail percentiles are retained so
the comparison is not presented as a mean-only claim.

## Provider-call context (separate from the published latency tables)

For the archived 2026-09-21 `eu_ai_act_compliance_pressure` pair, elapsed wall
time is calculated as certificate timestamp minus the `Date` header in that
half's attempts log. The baseline starts at `2026-09-21T13:47:07Z`, ends at
`13:50:13Z`, and records 150 provider calls: **186 s**, or **1.240 s/call**.
The gated half starts at `13:50:18Z`, ends at `13:51:40Z`, and records 76
provider calls: **82 s**, or **1.079 s/call**. These per-call values are derived
wall-clock averages, not isolated provider measurements: they include serial
runner and evidence overhead and are therefore upper bounds on average
provider-call duration (and concurrency, if introduced, would invalidate the
simple division).

Using the measured typical safe-pass p50 of 355.3 µs as a deliberately simple
cost for each of the 150 gate evaluations gives total gate cost `150 × 355.3
µs = 53,295 µs`, or **0.053295 s**. That is **0.0287%** of the 186 s baseline
wall time. Observed pair wall time fell by **104 s** (`186 − 82`), while the
gate itself adds about 0.053 s under this p50 calculation. The difference is
primarily associated with 74 avoided provider calls, but it must not be read as
a controlled provider-latency effect: provider durations and runner overhead
differ between the two halves. The archive sources are the baseline and gated
attempt logs plus their corresponding `audit.json` certificates under
`docs/runs/20260921-134707-359329-gh35607761858-a8a5ade8f6ed/` and
`docs/runs/20260921-135018-029319-gh35607761858-f3dd66376a01/`.

## Scope cautions

These figures describe this machine, revision, policy pack, inputs, and warm
measurement procedure. They do not establish a latency SLA, CI threshold, or a
claim about all inputs. No latency field is added to a signed certificate and
nothing under `proofs/` is modified by the generator.
