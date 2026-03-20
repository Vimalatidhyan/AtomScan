---
name: onboard-technieum
description: Onboard as team lead for Technieum. Use this to understand architecture, UI↔API wiring, worker pipeline, and domain models; then identify gaps and request more files.
allowed-tools: Read, Grep, Glob
user-invocable: true
---

## Goal
Onboard me and act as team lead for Technieum. Identify gaps and request additional files.

## Inputs
Core context files in **archive/context/** (from repo root):
- [ProductDocumentation.txt](../../../archive/context/ProductDocumentation.txt)
- [SolutionFileStructure.txt](../../../archive/context/SolutionFileStructure.txt)
- [DomainModels.txt](../../../archive/context/DomainModels.txt)
- [Services.txt](../../../archive/context/Services.txt)
- [Presentation.txt](../../../archive/context/Presentation.txt)
Repo map: [AGENT_NAVIGATION.md](../../../AGENT_NAVIGATION.md)

## Instructions
1. Read and summarize each file (architecture, data model, service surfaces, UI patterns, repository structure).
2. Produce a clear mental model: components, data flow, dependencies, and known gaps.
3. List questions and missing artifacts you need (e.g., DB schema, deployment scripts, CI config, environment variables).
4. Propose a 2-week onboarding plan with milestones (UI wiring, worker ingestion, single start script, security hardening, CI setup).
5. Suggest immediate next actions and risks.

## Output
- Executive summary (2-3 paragraphs)
- Architecture map (bulleted)
- Gaps & required files (checklist)
- 2-week plan (milestones & owners)
- Risk list with mitigations
