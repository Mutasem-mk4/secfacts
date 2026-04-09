# Technical Whitepaper: axon Evidence Normalization & Correlation

**Version:** 1.0 (March 2026)  
**Status:** Public / Open-Source  
**Author:** Axon Security Engineering Team

---

## 🏗️ 1. Executive Summary

Enterprise security environments are plagued by "Alert Fatigue"—the result of running multiple scanners (SAST, DAST, SCA, Cloud) that generate redundant, overlapping, and low-context findings. `axon` provides a transparent, deterministic normalization engine that reduces this noise through high-performance Go-based correlation.

This document outlines the **Deduplication Logic** and **Correlation Algorithms** that underpin `axon` to prove its reliability to CISOs and security architects.

---

## 🧬 2. Semantic Fingerprinting (Deduplication)

`axon` does not rely on "black box" heuristics for deduplication. Instead, it uses a **Deterministic Semantic Fingerprint**.

### **The Algorithm**
For every incoming finding (Evidence), `axon` calculates a 64-bit FNV-1a hash based on a "Semantic Triplet":
1.  **Vulnerability ID:** (e.g., CVE-2024-1234 or a canonicalized Gitleaks rule ID).
2.  **Resource URI:** A normalized PURL (Package URL) or path (e.g., `pkg:npm/express@4.17.1`).
3.  **Physical Location:** The exact file path and, if available, the start line of the finding.

**Result:** Findings from different tools (e.g., Trivy and Grype both reporting the same CVE on the same JAR) will produce the exact same fingerprint, allowing for 100% accurate, lock-free deduplication within our sharded worker pool.

---

## 🧠 3. Context-Aware Correlation

Once deduplicated, findings are grouped into **Logical Issues** based on the affected resource.

### **Compound Risk Multipliers**
`axon` employs a weighted scoring algorithm to highlight "Exposed Vulnerable Assets."
-   **Base Score ($S_b$):** The maximum severity score of any single finding in the group.
-   **Multiplier ($M$):** 
    -   If group contains **(SCA + Cloud Exposure)**: $M = 1.5$.
    -   If group contains **(SAST + Leaked Secret)**: $M = 1.2$.
    -   If group size exceeds **5 findings**: $M = 1.1$.
-   **Final Score ($S_f$):** $min(S_b \times M, 10.0)$.

This transparent reasoning ensures that security teams prioritize the assets that are both vulnerable **and** reachable.

---

## 🚀 4. Performance & Scalability

-   **Zero-Copy Ingestion:** Stream-decoding ensures that even 1GB+ SARIF files do not crash CI/CD runners.
-   **Sharded Actor Model:** Lock-free processing eliminates mutex contention, allowing for linear scaling with CPU cores.

---
*Transparency is the foundation of Trust. `axon` is open, auditable, and engineering-first.*

