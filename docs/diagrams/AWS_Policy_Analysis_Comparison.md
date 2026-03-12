<div align="center">

# AWS Formal Policy Analysis
### 8-Year Investment Timeline & Comparison with Microsoft Policy Intelligence

**February 2026** · Internal Document

</div>

---

<table><tr><td>

**TL;DR** — AWS has invested **~8 years** (~2017–2025) building formal analysis for authorization policies — from internal tooling (Zelkova) to customer-facing services (IAM Access Analyzer, S3 Block Public Access) to a purpose-built policy language (Cedar) and managed authorization service (Amazon Verified Permissions). This investment spans a dedicated **Automated Reasoning Group**, multiple PhD-level researchers, and production services processing **~1 billion SMT queries per day**.

</td></tr></table>

> [!IMPORTANT]
> **Maturity disclosure:** Microsoft's Z3-based analysis features (diff, subsumes, gen-tests, coverage) are **working prototypes** on a feature branch (`z3-redux`) with ~10K lines of analysis code and functional CLI demos. They are **not production-shipped**. The Regorus Rego evaluation engine itself is production-grade and open source. This comparison is candid about the maturity gap.

<br>

## Table of Contents

| # | Section | Description |
|---|---------|-------------|
| 1 | [Timeline](#1--aws-timeline--major-milestones) | 17 milestones from ~2017 to 2026 |
| 2 | [Investment](#2--aws-investment--organizational-commitment) | Org structure, leadership, scale |
| 3 | [Products](#3--aws-products--deep-dive) | Zelkova, IAM Access Analyzer, Cedar, AVP |
| 4 | [Impact Numbers](#4--impact--by-the-numbers) | Key metrics and adoption stats |
| 5 | [Comparison](#5--head-to-head--aws-vs-microsoft-policy-intelligence) | 27-capability feature matrix |
| 6 | [Takeaways](#6--key-takeaways-for-microsoft) | AWS leads, MS differentiators, strategy |
| 7 | [Sources](#7--sources) | 12 public references |

<br>

---

## 1 · AWS Timeline — Major Milestones

### 2017–2018 — Foundation

| Year | Milestone | Details | Source |
|:----:|-----------|---------|:------:|
| **~2017** | **Zelkova — Internal launch** | Internal SMT-based policy analysis engine. Translates IAM/S3 policies into mathematical formulas; initially used Z3 and CVC4 (cvc5 and custom automata solvers added later). Exact launch date not public; first disclosed Jun 2018. | [🔗](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/) |
| **2018 (Nov)** | **S3 Block Public Access** | Uses Zelkova to mathematically *prove* whether an S3 bucket policy grants public access. Runs in the critical path of every S3 policy attach. Earlier in 2018, Zelkova already powered Config rules and Macie classification. | [🔗](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/) |
| **2018** | **Config rules (Zelkova-backed)** | `s3-bucket-public-read-prohibited`, `s3-bucket-public-write-prohibited`, `s3-bucket-ssl-requests-only` — continuous compliance via automated reasoning, not heuristics. | *(same)* |
| **2018** | **Macie & GuardDuty integration** | Macie uses Zelkova for S3 accessibility classification; GuardDuty for threat detection. | *(same)* |

### 2019–2021 — Customer-Facing Services

| Year | Milestone | Details | Source |
|:----:|-----------|---------|:------:|
| **2019 (Dec)** | **IAM Access Analyzer — GA** | Identifies resources (S3, IAM roles, KMS, Lambda, SQS) shared outside your account/org. Uses Zelkova underneath. Free tier included. | [🔗](https://aws.amazon.com/iam/access-analyzer/) |
| **2021 (Mar)** | **Policy Validation** | 100+ authoring-time checks — catches overly permissive policies, syntax errors, security anti-patterns. Console & CLI. | [🔗](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/) |
| **2021 (Apr)** | **Policy Generation** | Generates least-privilege IAM policies from CloudTrail access logs. Actual-usage-based recommendations. | *(same)* |

### 2022 — Scale Milestones

| Year | Milestone | Details | Source |
|:----:|-----------|---------|:------:|
| **2022 (Aug)** | **"A Billion SMT Queries a Day"** | Neha Rungta (Dir. Applied Science, AWS Identity) delivers CAV 2022 keynote. Portfolio solver: Z3 + CVC4 + cvc5 + custom. | [🔗](https://www.amazon.science/blog/a-billion-smt-queries-a-day) |
| **2022** | **VPC Network Analyzers** | Automated reasoning for VPC configs — *proves* network reachability properties, not just tests them. | [🔗](https://aws.amazon.com/security/provable-security/) |

### 2023 — Cedar & Verified Permissions

| Year | Milestone | Details | Source |
|:----:|-----------|---------|:------:|
| **2023 (May)** | **Cedar language — open sourced** | Purpose-built authz language. Apache 2.0. RBAC + ABAC. Built with "verification-guided development" — Dafny models + 100M differential random tests/night. | [🔗](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing) |
| **2023 (May)** | **Verified Permissions — GA** | Managed Cedar-as-a-service. Customers: TELUS, Stedi (700M req/mo), Twilio Flex, FIS ($50T txns), Grosvenor Eng (1.5B assets). | [🔗](https://aws.amazon.com/verified-permissions/) |
| **2023** | **Custom Policy Checks** | Automated-reasoning in CI/CD. GoTo: "reduced processing time from days to minutes." | [🔗](https://aws.amazon.com/iam/access-analyzer/) |
| **2023** | **Unused Access Analyzer** | Finds unused roles, permissions, access keys across an AWS Organization. CloudTrail-based. | [🔗](https://aws.amazon.com/iam/access-analyzer/features/) |
| **2023** | **Cedar OOPSLA paper** | "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization." Dafny proofs of explicit-permit and forbid-overrides-permit. | [🔗](https://www.amazon.science/publications/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization) |

### 2025–2026 — Continued Investment

| Year | Milestone | Details | Source |
|:----:|-----------|---------|:------:|
| **2025–26** | **Cedar 4.x** | Active development, ongoing releases, growing open-source community. | [🔗](https://www.cedarpolicy.com/) |
| **2026 (Feb)** | **Academic collaboration** | Amazon Science highlights Stanford collaboration on cvc5, powering ~1B checks/day. | [🔗](https://www.amazon.science/news/how-academic-collaboration-delivers-real-world-security-to-amazon-customers) |

<br>

---

## 2 · AWS Investment — Organizational Commitment

| Dimension | Investment | Evidence |
|:----------|:----------|:--------|
| 🏢 **Dedicated org** | Automated Reasoning Group (ARG) — advanced innovation team within AWS | [Zelkova blog](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/) |
| 👤 **Leadership** | Neha Rungta (Dir. Applied Science, AWS Identity) · Mike Hicks (Sr. Principal Scientist) | CAV 2022, Cedar papers |
| 👥 **Team size** | Multiple PhD scientists + eng teams across Zelkova, Cedar, IAM AA, VPC Analyzer | Job postings, publications |
| 📄 **Publications** | CAV 2022 keynote, OOPSLA Cedar paper, yearly re:Invent talks, Amazon Science blogs | Public record |
| 💻 **Open source** | Cedar language + SDK (Apache 2.0), **5.7K+ GitHub stars** | [cedar-policy](https://github.com/cedar-policy/) |
| 📣 **Branding** | "Provable Security" — dedicated page, testimonials, re:Inforce talks | [provable-security](https://aws.amazon.com/security/provable-security/) |
| 📈 **Scale** | **~1 billion SMT queries/day** (2022; likely higher now) | CAV 2022 keynote |
| 🤝 **Enterprise adoption** | USAA, Bridgewater, GoTo, TELUS, Stedi, Twilio, FIS, Grosvenor Eng, Attentive | AWS product pages |

<br>

---

## 3 · AWS Products — Deep Dive

### 🔬 Zelkova *(Internal Engine, ~2017–present)*

| Aspect | Detail |
|:-------|:-------|
| **What** | SMT-based policy analysis engine |
| **How** | IAM/S3/resource policies → math formulas → portfolio solver (Z3 + CVC4 + cvc5 + custom automata) |
| **Key innovation** | Services ask questions *on behalf of* customers (not customers doing the asking) |
| **Scale** | Critical path of S3 policy attachment · ~1B SMT queries/day |

### 🔍 IAM Access Analyzer *(2019–present)*

| Feature | Description |
|:--------|:------------|
| **External access findings** | S3, IAM roles, KMS, Lambda, SQS shared outside org |
| **Policy validation** | 100+ authoring-time checks (overly broad, syntax, anti-patterns) |
| **Policy generation** | CloudTrail-based least-privilege suggestions |
| **Custom policy checks** | CI/CD integration — automated reasoning vs. custom standards |
| **Unused access analyzer** | Org-wide unused role/permission detection |
| **Pricing** | External/unused findings = paid · Validation & generation = free |

### 🛡️ Amazon Verified Permissions *(2023–present)*

| Aspect | Detail |
|:-------|:-------|
| **What** | Managed authorization-as-a-service using Cedar |
| **Target** | App developers needing fine-grained authz (beyond cloud IAM) |
| **Features** | Central policy store · Real-time eval · Audit logging · Schema validation |
| **Customers** | TELUS (IoT) · Stedi (700M B2B EDI txns/mo) · Twilio Flex · FIS (financial) · Grosvenor Eng (building mgmt/IoT) |

### 🌲 Cedar Language *(2023–present, open source)*

| Aspect | Detail |
|:-------|:-------|
| **What** | Purpose-built authorization policy language |
| **Design** | Expressive (RBAC + ABAC) · Performant (bounded latency) · Analyzable · Open |
| **Verification** | "Verification-guided development" — Dafny model + 100M DRT/night |
| **Proven properties** | Explicit permit · Forbid-overrides-permit · Validator soundness |

<br>

---

## 4 · Impact — By the Numbers

<table>
<tr>
<td align="center"><b>~1B</b><br><sub>SMT queries / day</sub></td>
<td align="center"><b>4</b><br><sub>solvers in portfolio</sub></td>
<td align="center"><b>100M</b><br><sub>DRT nightly</sub></td>
<td align="center"><b>8+</b><br><sub>named enterprise customers</sub></td>
</tr>
</table>

| Metric | Value | Source |
|:-------|------:|:------:|
| SMT queries processed daily | **~1,000,000,000** | CAV 2022 |
| SMT solvers in portfolio | **4** (Z3, CVC4, cvc5, custom) | CAV 2022 |
| Differential random tests nightly | **~100,000,000** | Amazon Science |
| Enterprise customers (named) | **8+** (USAA, Bridgewater, GoTo, TELUS, Stedi, Twilio, FIS, Grosvenor, Attentive) | AWS pages |
| Stedi transaction volume | **700M** requests/month | AVP page |
| FIS transaction volume | **$50T** in annual transactions | AVP page |
| Cedar GitHub stars | **~5,700+** | GitHub |
| Cedar release cadence | Active **(4.x line)** | cedarpolicy.com |
| AWS regions with Access Analyzer | **All** commercial regions | AWS docs |
| IAM policy validation checks | **100+** built-in | IAM AA features |

<br>

---

## 5 · Head-to-Head — AWS vs. Microsoft Policy Intelligence

> [!WARNING]
> **Maturity context:** AWS = **production-grade** (GA services, 8 years of hardening, ~1B queries/day). Microsoft Policy Intelligence Z3 features = **early-stage prototypes** (`z3-redux` branch, working CLI, no production deployment).

### Core Analysis Capabilities

| Capability | AWS | Microsoft | MS Maturity | Edge |
|:-----------|:----|:----------|:-----------:|:----:|
| **Policy languages** | IAM JSON, S3, Cedar | Rego (OPA), Cedar, Azure Policy | Rego engine: prod · Z3: prototype | **MS** |
| **SMT solver** | Portfolio: Z3+CVC4+cvc5+custom | Z3 (direct integration) | Prototype | AWS |
| **Policy diff (semantic)** | ❌ | `regorus diff` — equivalence proof or distinguishing input | Prototype ✓ | **MS** 🆕 |
| **Policy subsumption** | ❌ | `regorus subsumes` — proves new ⊇ old | Prototype ✓ | **MS** 🆕 |
| **Auto test generation** | ❌ | `regorus gen-tests` — covers all paths | Prototype ✓ | **MS** 🆕 |
| **MC/DC coverage** | ❌ | `--condition-coverage` flag | Prototype ✓ | **MS** 🆕 |
| **Line-targeted coverage** | ❌ | `--cover-line` / `--avoid-line` | Prototype ✓ | **MS** 🆕 |
| **Dead rule detection** | ❌ | UNSAT path = provably unreachable | Prototype ✓ | **MS** 🆕 |
| **Input synthesis** | Limited (simulation) | Z3-driven with JSON output | Prototype ✓ | **MS** 🆕 |
| **Root cause / Why denied** | Limited (IAM sim) | Designed (MAX-SAT) | Planned | — |
| **SMT dump/inspection** | Not exposed | `--dump-smt` full transparency | Prototype ✓ | **MS** |

### AWS-Only Capabilities (Cloud Posture)

| Capability | AWS | Microsoft | Edge |
|:-----------|:----|:----------|:----:|
| **Public access detection** | ✅ S3 Block Public Access (production, billions of queries) | N/A (different use case) | AWS |
| **Cross-account detection** | ✅ IAM Access Analyzer (S3, IAM, KMS, Lambda, SQS) | N/A (different use case) | AWS |
| **Policy validation (authoring)** | ✅ 100+ built-in checks | Partial (via analysis) | AWS |
| **Policy generation from usage** | ✅ CloudTrail-based least-privilege | ❌ | AWS |
| **Unused access detection** | ✅ Org-wide via CloudTrail | ❌ | AWS |
| **Custom CI/CD checks** | ✅ IAM AA custom checks | Possible via CLI | AWS |
| **Managed authz service** | ✅ Amazon Verified Permissions | ❌ | AWS |

### Language & Engine Depth

| Capability | AWS | Microsoft | MS Maturity | Edge |
|:-----------|:----|:----------|:-----------:|:----:|
| **Purpose-built language** | ✅ Cedar (designed for analysis) | Rego (general purpose, more expressive) | Prod (engine) | *Depends* |
| **Loops & iteration** | N/A (Cedar has none) | Bounded loop unrolling | Prototype | **MS** |
| **User-defined functions** | N/A (Cedar has none) | Function inlining | Prototype | **MS** |
| **Partial rules** | N/A | Supported | Prototype | **MS** |
| **Engine verification** | ✅ Dafny + 100M DRT/night | Verus planned (design doc only) | Planned ⚠️ | AWS |

### Ecosystem & Market Position

| Dimension | AWS | Microsoft | Edge |
|:----------|:----|:----------|:----:|
| **Production scale** | ~1B SMT queries/day, 8yr | Feature branch prototype | **AWS** |
| **Open source** | Cedar SDK (Apache 2.0) | Regorus engine (MIT) | Both |
| **Enterprise adoption** | 8+ named public customers | Internal MS use (engine only) | **AWS** |
| **Academic publications** | CAV keynote, OOPSLA, Amazon Science | — | **AWS** |
| **Marketing/branding** | "Provable Security" | Not yet branded | **AWS** |

<br>

---

## 6 · Key Takeaways for Microsoft

### 🔴 Where AWS Has an Unassailable Lead

| # | Area | Why It Matters |
|:-:|:-----|:---------------|
| 1 | **8 years of production hardening** | Zelkova in S3 critical path since 2018 |
| 2 | **Scale** | 1B SMT queries/day is a moat |
| 3 | **Customer proof points** | Named enterprises (USAA, Bridgewater, Twilio, FIS) with public testimonials |
| 4 | **Branding** | "Provable Security" is an established category on AWS |
| 5 | **Managed service** | Amazon Verified Permissions is GA with pricing |

### 🟢 Where Microsoft Is Differentiated *(Prototype Stage)*

> All features below are **working prototypes** with CLI demos but **no production deployment** yet.

| # | Capability | Why It's Unique |
|:-:|:-----------|:----------------|
| 1 | **Policy diff & subsumption** | AWS has nothing comparable; uniquely valuable for safe migrations |
| 2 | **Auto test generation** | No AWS equivalent; MC/DC condition coverage is compelling |
| 3 | **Multi-language (Rego)** | OPA/Rego is the industry standard; AWS is Cedar-only for analysis |
| 4 | **Root cause (planned)** | MAX-SAT "why denied" — designed but not yet implemented |
| 5 | **Dead rule detection** | Novel; emerges from UNSAT path conditions during analysis |
| 6 | **Full Rego expressiveness** | Loops, functions, partial rules — Cedar intentionally lacks these |
| 7 | **Verified engine (planned)** | Verus design doc exists; no code yet. AWS ships Dafny proofs *today* |

### 🔵 Strategic Recommendations

| # | Action | Rationale |
|:-:|:-------|:----------|
| 1 | **Don't compete on IAM posture** | AWS Access Analyzer owns this; focus on novel analysis capabilities |
| 2 | **Harden the prototype** | diff/subsumes/gen-tests are novel but need production testing & docs |
| 3 | **Rego is the wedge** | Most enterprises use OPA/Rego; Cedar adoption is still growing |
| 4 | **Publish** | AWS has CAV + OOPSLA credibility; publish the RVM-to-Z3 translation work |
| 5 | **Ship then brand** | AWS built "Provable Security" on years of production use; ship first |
| 6 | **Get customer proof points** | The #1 gap vs AWS is named customers willing to speak publicly |
| 7 | **Close the Verus gap** | AWS ships Dafny proofs today; move Verus from design doc to code |

<br>

---

## 7 · Sources

All information comes from publicly available sources:

| # | Source | Link |
|:-:|:-------|:-----|
| 1 | AWS Security Blog — Zelkova (Jun 2018) | [aws.amazon.com/blogs/security/...zelkova](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova/) |
| 2 | AWS IAM Access Analyzer — product page | [aws.amazon.com/iam/access-analyzer](https://aws.amazon.com/iam/access-analyzer/) |
| 3 | AWS IAM Access Analyzer — features | [aws.amazon.com/iam/access-analyzer/features](https://aws.amazon.com/iam/access-analyzer/features/) |
| 4 | Amazon Science — "A Billion SMT Queries a Day" (Aug 2022) | [amazon.science/blog/a-billion-smt-queries-a-day](https://www.amazon.science/blog/a-billion-smt-queries-a-day) |
| 5 | Amazon Science — Cedar verification (May 2023) | [amazon.science/blog/...cedar...](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing) |
| 6 | AWS Security Blog — Policy generation (Apr 2021) | [aws.amazon.com/blogs/security/...least-privilege](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/) |
| 7 | Amazon Verified Permissions — product page | [aws.amazon.com/verified-permissions](https://aws.amazon.com/verified-permissions/) |
| 8 | AWS Provable Security page | [aws.amazon.com/security/provable-security](https://aws.amazon.com/security/provable-security/) |
| 9 | Cedar policy language website | [cedarpolicy.com](https://www.cedarpolicy.com/) |
| 10 | Cedar GitHub repository | [github.com/cedar-policy](https://github.com/cedar-policy/) |
| 11 | Amazon Science — cvc5 collaboration (Feb 2026) | [amazon.science/news/...academic-collaboration](https://www.amazon.science/news/how-academic-collaboration-delivers-real-world-security-to-amazon-customers) |
| 12 | Internal comparison table (Section 17) | [rvm-to-z3.md](../rvm-to-z3.md) |

<br>

---

<div align="center">
<sub><i>Document generated February 2026 · All data from publicly available AWS product pages, blog posts, and Amazon Science publications</i></sub>
</div>
