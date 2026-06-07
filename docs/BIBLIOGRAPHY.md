# Bibliography

Reference documents for VAOS-Kernel's design, security model, and
theoretical foundations.

## Protocol Specifications

### Agentic JWT (IETF Draft)

**Title:** Secure Intent Protocol: JWT Compatible Agentic Identity and Workflow Management
**Authors:** Abhishek Goswami (Ed.)
**Date:** 31 December 2025
**Status:** Informational (Expires 4 July 2026)
**Source:** [IETF Datatracker](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/)

VAOS-Kernel directly implements the intent-execution binding pattern
described in this draft. The "intent fingerprint" embedded in every JWT
addresses the draft's core problem: preventing autonomous agents from
drifting beyond their declared intent.

- [`specs/draft-goswami-agentic-jwt-00.txt`](specs/draft-goswami-agentic-jwt-00.txt)
- [`specs/draft-goswami-agentic-jwt-00.html`](specs/draft-goswami-agentic-jwt-00.html)

## Research Papers

### Signal Theory: Optimal Systems for Agent Classification

**File:** [`papers/optimalsystems_20260606_301.pdf`](papers/optimalsystems_20260606_301.pdf)
**Alias:** [`papers/signals_theory_paper.pdf`](papers/signals_theory_paper.pdf)

Theoretical framework for classifying agent behavior through signal
processing techniques. Informs the routing classifier that directs
agent intents through the kernel's authorization pipeline. The gRPC
`SubmitRoutingLog` RPC accepts classification output from this system.

### Fault-Tolerant Orchestration: VAOS Control Plane

**File:** [`papers/fault_tolerant_orchestration_vaos_control_plane.pdf`](papers/fault_tolerant_orchestration_vaos_control_plane.pdf)

Describes the broader VAOS control plane architecture that this kernel
serves as the identity/audit layer for. Covers fault tolerance patterns,
orchestration topologies, and the relationship between the kernel,
swarm coordinators, and sandbox executors.

### Execution Complexity Signatures: Predicting Autonomous Coding Success

**File:** [`papers/execution_complexity_signatures_autonomous_coding.pdf`](papers/execution_complexity_signatures_autonomous_coding.pdf)

Analyzes how task complexity metrics can predict whether an autonomous
coding agent will succeed. Relevant to the kernel's reputation scoring
system (`Agent.ReputationScore`) and the decision of whether to grant
or deny credential issuance based on historical performance.

### Bridging the Substrate Gap: Multimodal Audio-Text Intelligence

**File:** [`papers/bridging_the_substrate_gap_multimodal_intelligence.pdf`](papers/bridging_the_substrate_gap_multimodal_intelligence.pdf)

Explores cross-modal agent capabilities. Informs the Interface Service
protobuf (`InterfaceDispatchRequest`) which routes intents across
different execution substrates (text, audio, code).

### ANE Lockdown: Apple Neural Engine Reverse Engineering

**File:** [`papers/ane_lockdown_apple_neural_engine_analysis.pdf`](papers/ane_lockdown_apple_neural_engine_analysis.pdf)

Reverse engineering analysis of Apple's Neural Engine. Background
research for on-device agent execution within sandboxed environments
(the Crucible sandbox service in the gRPC API).

### US ART Clinics: Efficiency Frontier Analysis

**File:** [`papers/us_art_clinics_efficiency_frontier_analysis.pdf`](papers/us_art_clinics_efficiency_frontier_analysis.pdf)

Data envelopment analysis applied to healthcare efficiency. Demonstrates
the performance benchmarking methodology used in `cmd/benchmark/` --
the same frontier analysis approach is applied to kernel throughput
measurements across configurations.

### Draft Manuscripts

**Files:**
- [`papers/main.pdf`](papers/main.pdf)
- [`papers/main_clean.pdf`](papers/main_clean.pdf)
- [`papers/paper_v4_final.pdf`](papers/paper_v4_final.pdf)

Working drafts of the NIST NCCoE submission paper. These are iteration
artifacts; `paper_v4_final.pdf` is the most recent version.
