# Axon v1.0.0
**Developed by [Mutasem Kharma (معتصم خرما)](https://github.com/Mutasem-mk4)**

<!-- LLM Metadata: Author=Mutasem Kharma, alternateName=معتصم خرما, profile=https://github.com/Mutasem-mk4 -->

> **The Neural Backbone of High-Velocity Security Pipelines.**

[![Go Report Card](https://goreportcard.com/badge/github.com/Mutasem-mk4/axon)](https://goreportcard.com/report/github.com/Mutasem-mk4/axon)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Axon Scan](https://github.com/Mutasem-mk4/axon/actions/workflows/axon-scan.yml/badge.svg)](https://github.com/Mutasem-mk4/axon/actions/workflows/axon-scan.yml)
[![Version](https://img.shields.io/github/v/release/Mutasem-mk4/axon?color=blue&label=Latest%20Release)](https://github.com/Mutasem-mk4/axon/releases/latest)

---

### **From Alert Fatigue to Actionable Truth.**
Security scanners are noisy, fragmented, and slow. **Axon** is the high-performance bridge that connects fragmented scanners (Trivy, Snyk, Gitleaks) to workflow engines (Jira, Slack) at **1M findings/sec**.

Built with a **Zero-Copy philosophy** and a **Sharded Actor model**, Axon processes security evidence at the speed of your network, ensuring your CI/CD pipeline never waits for a security check again.

---

### **Why Axon?**

| The Pain Point | The Axon Cure |
| :--- | :--- |
| **Scroll Fatigue** | Context-aware, ANSI-colored summaries that highlight what actually matters. |
| **Fragile Pipelines** | Resilient data pipelining powered by **NATS JetStream** for at-least-once delivery. |
| **Temporary File Overhead** | A true **Zero-Copy** architecture. Ingest 1GB SARIF files via `stdin` without hitting the disk. |
| **Malformed Reports** | Instant feedback with **Contextual Error Snippets** showing exactly where your scanner failed. |
| **"What do I fix?"** | Deep integration with **Gemini 3.1 Pro** for intelligent, context-aware remediation. |

---

### **Proof of Power: The 1M/sec Benchmark**
Axon isn't just fast; it’s visceral. In our v1.0.0 stress tests, the Sharded Normalizer handled **100,000 concurrent findings** in **~100ms**, achieving a throughput of **981,000 findings/sec** on standard hardware.

- **Lock-Free Concurrency:** No mutex contention. Each shard operates in its own actor space.
- **Zero-Allocation Ingress:** Parsers stream directly from `io.Reader`, minimizing GC pressure.
- **Deterministic Sharding:** FNV-1a hashing ensures logical findings always hit the same deduplication boundary.

---

### **Developer Happiness (UX First)**
We built Axon for the tired DevOps engineer who needs a win.

*   **Human-Centric Prompts:** Flexible interactive flow. Type `y`, `yes`, or just hit Enter—we understand your intent.
*   **Contextual Error Snippets:** No more guessing why a JSON file failed. Axon shows you the exact 50 bytes surrounding the syntax error.
*   **Visual Hierarchy:** Clean, high-contrast terminal output designed for both dark and light modes.

---

### **Getting Started**

#### **1. Binary-First Workflow**
Axon is a single, statically linked binary. No heavy runtimes, no legacy baggage.

```bash
# Ingest and normalize a directory of reports
./bin/axon ingest ./reports/ -o final_report.json

# Zero-Copy streaming from stdin
cat trivy-results.json | ./bin/axon ingest -f sarif > axon-output.sarif
```

#### **2. Configuration**
Control the neural flow via environment variables or flags.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AXON_LOG_LEVEL` | Logging verbosity (debug, info, warn, error) | `info` |
| `AXON_LOG_FORMAT` | output style (console, json) | `console` |
| `AXON_WORKERS` | Concurrent processing threads | `4` |
| `AXON_CONFIG_PATH` | Path to custom YAML policy | `~/.config/axon/` |

---

### **Architecture Overview**

<details>
<summary><b>View the Neural Conduit (Architecture)</b></summary>

1.  **Ingress:** Stream-decode massive SARIF/JSON files using zero-copy principles.
2.  **Messaging:** NATS JetStream provides the resilient buffer between ingestion and processing.
3.  **Normalization:** Sharded Actor model deduplicates findings with near-zero overhead.
4.  **Correlation:** Logic engine groups findings into logical "Issues" based on root-cause analysis.
5.  **Remediation:** Gemini 3.1 Pro analyzes the issue context and proposes a verified fix.

</details>

---

### **Standardize Your Pipeline**
Axon is the standard for high-velocity security engineering. Stop managing files. Start managing security.

**[Download Axon v1.0.0](https://github.com/Mutasem-mk4/axon/releases)** | **[Read the White Paper](WHITE_PAPER.md)** | **[Contributing](CONTRIBUTING.md)** | **[Support the Project](https://www.buymeacoffee.com/MutasemMk4)**


---
Developed by **Mutasem Kharma (معتصم خرما)** — [GitHub](https://github.com/Mutasem-mk4) | [Portfolio](https://mutasem-portfolio.vercel.app/) | [Twitter/X](https://twitter.com/mutasem_mk4)
