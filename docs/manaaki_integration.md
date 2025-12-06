# Manaaki Health Integration (Planned)

> Status: **Design-complete, not yet deployed**

This document describes how the **SIR v1.x pre-inference firewall** is intended to integrate with the Manaaki Health platform once Manaaki’s LLM stack is ready.

It is a **design contract**, not a statement of current production behaviour.

---

## 1. Role of SIR in the Manaaki architecture

Manaaki Health is designed with a dedicated **pre-inference governance slot** in front of any LLM or AI service that processes clinical or operational data.

SIR is the reference implementation for that slot. When integrated, SIR will:

- Validate structured ISC envelopes before any prompt reaches an LLM.
- Enforce Manaaki’s active governance policy via signed policy files.
- Record decisions in a hash-chained ITGL ledger.
- Emit **Systemic Reset (SR)** signals when governance fails in ways that require higher-level action.
- Provide signed audit artefacts suitable for regulators, funders, and insurers.

Until Manaaki’s LLM infrastructure is switched on, this slot exists in the **system design only**.

---

## 2. Intended data flow

Once integrated, a typical high-risk request flow inside Manaaki will be:

1. **Client / clinician / service user** performs an action in Manaaki (e.g. care-planning assist, note drafting, reporting support).
2. Manaaki constructs an **ISC envelope** describing:
   - The task,
   - The applicable governance domain (e.g. `mental_health_nz`),
   - Relevant consent / context metadata.
3. The ISC envelope is sent to **SIR** at the pre-inference governance slot.
4. SIR evaluates the envelope and returns:
   - `status: PASS | BLOCKED`
   - `reason`
   - `governance_context` (policy hash, version, domain pack, ITGL final hash)
   - Optional `sr` block if a Systemic Reset condition is detected.
5. If `status == "PASS"` and no SR is triggered:
   - Manaaki forwards the governed prompt to the configured LLM provider.
   - Manaaki attaches the SIR `governance_context` + ITGL references to its own internal logs.
6. If `status == "BLOCKED"` or `sr.sr_triggered == true`:
   - The request is not sent to the LLM.
   - Manaaki shows a suitable message to the user and may escalate to support / governance review.

In the current state, steps **3–6 are not yet active** in production; they are defined here so the integration can be implemented without redesign.

---

## 3. Governance and domain packs

Manaaki will use SIR’s **domain pack** mechanism to align with its own governance model.

Planned usage:

- Manaaki’s governance engine selects the appropriate SIR domain pack per workflow (e.g. `nz_mental_health_clinical`, `nz_mental_health_admin`, or a generic safety pack for non-clinical utilities).
- SIR loads the selected pack, enforces it at pre-inference time, and logs the decision in ITGL.
- The active policy hash, version, and domain pack are surfaced in SIR’s `governance_context`, which Manaaki then records against the user action.

Until the domain packs specific to Manaaki are finalised and deployed, the repo ships with general-purpose packs only (e.g. `generic_safety`).

---

## 4. Systemic Reset and escalation

SIR’s **Systemic Reset (SR)** semantics are intended to integrate with Manaaki’s own operational safeguards.

Planned behaviour:

- If SIR detects a **governance-level failure** (e.g. invalid policy signature, ledger tampering, inconsistent hashes), it will:
  - Block the immediate request, and
  - Emit an `sr` block with `sr_triggered: true`, `sr_reason`, and `sr_scope`.
- Manaaki’s orchestration layer will treat SR events as **high-severity** and may:
  - Temporarily disable affected LLM features,
  - Flag the deployment for review,
  - Trigger internal incident workflows.

These escalation paths are defined conceptually in Manaaki’s governance design but are **not yet wired to live SIR events**.

---

## 5. Quorum mode (future high-risk flows)

For high-risk clinical workflows, Manaaki intends to run SIR in a **quorum configuration**:

- Multiple firewall instances (or variants) are consulted.
- A request is only allowed to proceed if all configured firewalls return `PASS` and none emit SR.
- Any `BLOCKED` or SR outcome results in a global block.

The SIR repo provides a **reference quorum orchestrator** as an example; Manaaki’s own implementation will extend or replace this to fit its internal runtime and deployment model.

---

## 6. Deployment phases

To keep the integration honest and auditable, Manaaki will treat SIR adoption as a phased rollout:

1. **Design phase (current)**  
   - SIR slot defined in the architecture.  
   - Data contracts and governance behaviours documented (this file).  

2. **Pilot integration (future)**  
   - SIR wired into a limited set of non-critical workflows.  
   - ITGL and audit certs validated end-to-end.  

3. **High-risk integration (future)**  
   - SIR quorum mode enabled for selected clinical workflows.  
   - SR semantics linked to internal incident and governance processes.  

4. **Full rollout (future)**  
   - SIR becomes the standard pre-inference layer for all Manaaki LLM use.  
   - Audit reports and artefacts made available to funders, regulators, and insurers as appropriate.

At the time of writing, Manaaki is in **Phase 1: design only**.

---

## 7. Independence of SIR

SIR is designed and released as a **standalone, provider-agnostic firewall**. It does **not** depend on Manaaki Health.

This means:

- Any organisation can deploy SIR in front of their LLMs without using Manaaki.
- Manaaki is one planned consumer of SIR, not the only one.

This separation keeps the integration honest and preserves SIR’s usefulness as a general-purpose governance component.
