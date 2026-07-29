---
target: frontend/src/components/TargetSetup.tsx
total_score: 28
p0_count: 0
p1_count: 1
timestamp: 2026-07-16T15-33-16Z
slug: frontend-src-components-targetsetup-tsx
---
Method: dual-agent (A: `/root/impeccable_official_critique/assessment_a_design` · B: `/root/impeccable_official_critique/assessment_b_final_stable`)

# ScopeHarbor TargetSetup Design Critique

Target: `frontend/src/components/TargetSetup.tsx`, including its current imported dashboard surface and shared application styling.

This corrected synthesis incorporates the final refinement state: authorization remains complete after launch; successful, interrupted, failed, cancelled, and clean-result outcomes are distinguished correctly; unavailable profiles are disabled; readiness and reduced-motion behavior are aligned; scan/history context includes target, profile, and date; credential creation and rotation use separate secrets; evidence lists are bounded; and the line-led product language extends across tabs.

## Design Health Score

| # | Heuristic | Score | Key Issue |
|---|-----------|------:|-----------|
| 1 | Visibility of System Status | 3 | Outcome states are now explicit and clean scans complete correctly; the remaining gap is that a fresh session opens on Profile rather than the first unmet phase. |
| 2 | Match Between System and Real World | 3 | Safety language is unusually clear, but terms such as allowlist, ZAP, normalized evidence, CWE, and OWASP still assume scanner literacy. |
| 3 | User Control and Freedom | 3 | Direct phase navigation, cancellation, filters, and safe confirmation dialogs are strong; returning from Credentials to the interrupted audit and undoing management changes are weak. |
| 4 | Consistency and Standards | 3 | The line-led system and status vocabulary are coherent; overlapping Review, Findings, and Intelligence responsibilities remain the main standards gap. |
| 5 | Error Prevention | 3 | Unavailable profiles are correctly disabled and safety guardrails are visible; shared draft/historical selection can still create a context error. |
| 6 | Recognition Rather Than Recall | 3 | Target, profile, and date labels now strengthen recognition, though draft configuration and the selected historical scan still share one workspace. |
| 7 | Flexibility and Efficiency of Use | 2 | Search, filters, keyboard phase navigation, and direct tabs exist; there are no shortcuts, quick rerun, presets, or bulk finding actions. |
| 8 | Aesthetic and Minimalist Design | 3 | Restrained orange, line-led sections, and bounded disclosure are coherent; the persistent WebGL shield and repeated four-metric rails still add category-default weight. |
| 9 | Error Recognition and Recovery | 3 | Interrupted, failed, and cancelled audits are now labelled explicitly and work is preserved; some recovery messages still lack a direct corrective action. |
| 10 | Help and Documentation | 2 | Inline safety explanation is excellent; contextual terminology help and a visible task-focused help destination are absent. |
| **Total** |  | **28/40** | **Good — cohesive foundation with one major context-model issue** |

## Anti-Patterns Verdict

### LLM assessment

**Moderate product-slop risk, materially improved by the current refinement pass.**

The application no longer reads as two design generations stitched together. Current shared styles flatten product panels, remove card shadows, use line-separated groups, bound evidence, and keep orange as the active identity (`frontend/src/app/globals.css:3267-3759`). The WebGL fallback is also orange rather than violet (`frontend/src/app/globals.css:505-515`), and Credentials now has a deliberate two-column, line-led layout with separate create and rotation secrets (`frontend/src/components/dashboard/AuthProfilesPanel.tsx:68-168`).

The remaining category reflexes are structural:

- The 286px shield-and-network hero remains present above every task surface (`frontend/src/components/AppShell.tsx:68-79`; `frontend/src/app/globals.css:349-503`). It is polished, but “3D shield over a cyber network” is the most predictable AppSec visual metaphor.
- Workspace and Intelligence still lead with four equal big-number cells. Their current line treatment is cleaner, but the repeated metric-rail grammar remains generic (`frontend/src/components/dashboard/WorkspaceOverview.tsx:24-29`; `frontend/src/components/dashboard/RiskDashboardPanel.tsx:45-50`).
- Audit Review, Findings, and Intelligence still duplicate downstream capabilities, which makes the interface feel component-composed rather than role-composed.

ScopeHarbor does not look cheaply AI-generated. Its exact-scope language, restrained orange palette, and strong safety boundaries give it a real point of view. The next leap is to make the workflow model as authored as the visual system.

### Deterministic scan

The stable-source detector command was:

`node .agents/skills/impeccable/scripts/detect.mjs --json frontend/src/components frontend/src/app`

It returned exit code `0` and exact JSON `[]`: **0 findings**, no rule counts, messages, or locations, and no false positives to resolve.

This clean result means the detector found none of its encoded markup anti-patterns across the current component/app surface. It does not validate computed contrast, responsive composition, focus order, WebGL behavior, async state combinations, or the semantic correctness of the audit state model.

### Visual overlays

No reliable user-visible overlay is available. Browser control requires `mcp__node_repl__js`, which was not exposed in this environment, so mutable injection was not attempted, no live server was started, and no browser-console or screenshot evidence exists. The fallback evidence is the deterministic CLI scan plus read-only source/CSS inspection.

## Overall Impression

ScopeHarbor now has a credible visual foundation: calm, orange-led, precise, and substantially more cohesive than a conventional security dashboard. The single biggest opportunity is not another styling pass. It is making “what audit am I configuring, what audit am I viewing, and what state is it in?” unambiguous at every moment.

## Cognitive Load and Emotional Journey

### Cognitive load

**5 of 8 checklist failures: high cognitive load in the core audit flow.**

- **Single focus — fail:** Even with clear target/profile/date labels, Profile can show a historical scan preview while Run combines draft launch settings, monitoring, and history.
- **Chunking — fail:** expanded Findings groups expose seven management or evidence controls at once.
- **Grouping — pass:** related controls and evidence are generally grouped well, especially after the line-led refinement.
- **Visual hierarchy — pass:** within each phase, headings, context, primary actions, and supporting boundaries are clear.
- **One thing at a time — fail:** proposed configuration and historical evidence coexist.
- **Minimal choices — fail:** six top-level tabs, six audit phases, six severity choices, and seven-control advanced groups exceed the four-item working-memory guideline.
- **Working memory — fail:** the Credentials excursion has no explicit “return to authorization” handoff; historical context is now labelled, but it still shares the draft workspace.
- **Progressive disclosure — pass:** advanced filters, comparisons, activity, reports, AI details, and scanner receipts are bounded or disclosed progressively.

### Emotional journey

- **Arrival:** polished and reassuring, though the large shield delays access to the working surface.
- **Orientation valley:** the app initializes on Profile, visibly step three (`frontend/src/components/TargetSetup.tsx:85`), even though Preflight and Scope precede it.
- **Reassurance peak:** Authorization is the strongest moment. It names the exact target and profile, records explicit acknowledgements, and states that permission never broadens backend policy (`frontend/src/components/dashboard/ScanControls.tsx:164-209`).
- **Launch valley:** the draft launch review can still sit beside a selected historical scan. Target-aware progress and target/profile/date labels reduce the risk without removing the mixed context.
- **Execution recovery:** progress, cancellation, bounded scanner receipts, explicit Interrupted/Failed/Cancelled states, and status text restore control.
- **End state:** successful scans, including clean zero-finding scans, now close the Review phase correctly.

The remaining peak-end opportunity is to pair each explicit outcome with one context-preserving next action: review results, adjust and rerun, or return to the selected target.

## What’s Working

1. **Safety and authorization language are excellent.** Exact destinations, credential boundaries, redirect revalidation, sanitized output, and local ownership are explained at the decision point rather than hidden in documentation.

2. **The current visual-system reconciliation is real.** Non-Audit product pages now use the same line-led, restrained vocabulary as Audits; the orange fallback is consistent; Credentials has an aligned two-column structure; and card shadows/rounding are suppressed where the product language calls for flatter sections.

3. **State, accessibility, and high-stakes action fixes materially improve trust.** Clean scans complete Review, failed/cancelled runs are labelled honestly, authorization persists after launch, unavailable profiles are disabled, the readiness dot uses an amber checking state, navigation respects reduced motion, scan/history context is richer, evidence is bounded, and credential creation and rotation use separate secret inputs.

## Priority Issues

### [P1] Draft audit configuration and historical scan evidence are interleaved

**What:** `selectedScanId` drives findings, reports, AI, progress, and previews while the user is configuring a new target/profile.

**Why it matters:** A user can mistake old evidence for the audit they are about to launch, which is a serious context error during authorization and remediation.

**Evidence:**

- Initial loading automatically selects the first historical scan (`frontend/src/components/TargetSetup.tsx:769-774`).
- Profile shows findings from that selected scan directly beneath the new profile decision (`frontend/src/components/TargetSetup.tsx:1236-1277`).
- Run places the current launch configuration beside the selected scan and global history (`frontend/src/components/TargetSetup.tsx:1297-1311`).
- Target-aware progress and target/profile/date labels now make the historical source recognizable, but the same selected-scan state still drives previews, progress, findings, reports, and AI while a new audit is being configured.

**Fix:** Separate `draftAudit` from `viewedScan`. Default Run to the newly launched audit or no monitor; label history as “Past audits”; scope it to the selected target; and use the existing target/profile/date context inside a persistent historical-view banner. Move the Profile preview into a clearly separate “Recent audit for this target” region or out of configuration entirely.

**Suggested command:** `$impeccable layout`

### [P2] The phase rail still begins from application state rather than the first unmet audit step

**What:** The rail now labels successful, interrupted, failed, and cancelled states correctly, but a fresh session still initializes on Profile and completion is assembled from current selections plus the viewed scan rather than one explicit audit journey.

**Why it matters:** The rail is trustworthy once an audit outcome exists, yet first-time orientation can still feel like entering a workflow at step three.

**Fix:** Start on the first unmet phase for a new audit, or explicitly frame the rail as non-linear navigation rather than progress. Longer term, bind the phase model to a named draft/launched audit instance so current, complete, and interrupted states survive navigation without depending on unrelated selected resources.

**Suggested command:** `$impeccable shape`

### [P2] Review, Findings, and Intelligence have overlapping ownership

**What:** Audit Review embeds the full findings workspace plus Reports and AI; Findings embeds the same triage surface; Intelligence embeds Reports and AI again.

**Why it matters:** Users must learn three destinations for the same tasks, and navigation becomes a matter of remembering implementation reuse rather than understanding product roles.

**Evidence:** `TargetSetup.tsx:1315-1328`, `1335-1350`, and `1352-1381` render overlapping capabilities.

**Fix:** Give each destination one job:

- **Audits → Review:** concise scan-specific outcome, deltas, and handoff.
- **Findings:** workspace-wide triage, lifecycle, suppression, and tags.
- **Intelligence:** cross-scan posture, comparisons, report library, and explanations.

Use context-preserving links such as “Open these findings in Findings” instead of embedding the full downstream workspace.

**Suggested command:** `$impeccable distill`

### [P2] The persistent shield and equal metric rails still lead with category convention

**What:** A 286px WebGL shield/network scene precedes every task, and Workspace/Intelligence repeat four equal large-number cells.

**Why it matters:** The visual system is now restrained, but these structures still consume attention without improving the operator’s next decision. They also push the strongest product differentiator—exact scope and current audit state—below decoration.

**Fix:** Compress the everyday masthead to roughly 96–120px, reserve the full shield for onboarding or empty Workspace states, and let the active target/audit state become the persistent hero. Convert equal metric rails into a compact status strip or prioritized summary where one metric earns emphasis and the rest become supporting data.

**Suggested command:** `$impeccable quieter`

## Persona Red Flags

### Jordan — Confused First-Timer

- Lands on Profile, step three, without understanding what happened to Preflight and Scope.
- Encounters allowlist, ZAP, canonical address, normalized evidence, CWE, and OWASP without lightweight definitions.
- Can see a clearly labelled historical findings preview while configuring a new audit; the labels help, but the coexistence still obscures why old evidence is part of the current decision.
- Has no explicit handoff back to Authorization after visiting Credentials.

### Sam — Accessibility-Dependent User

- Strong foundations: semantic tabs, Arrow/Home/End navigation, visible focus, labelled controls, disabled unavailable profiles with `aria-disabled`, keyboard-safe dialogs, text-backed statuses, amber checking state, touch sizing, and reduced-motion-aware navigation.
- Several async risk/report/AI messages are plain paragraphs rather than announced status regions.
- Browser control was unavailable, so rendered focus order, contrast, and announcements remain unverified.

### Alex — Impatient Power User

- The persistent hero consumes 286px before the task on every visit.
- No keyboard shortcut, quick rerun, saved audit preset, or bulk lifecycle action is visible.
- Six top-level destinations plus six phase tabs create avoidable navigation overhead.
- Historical scan selection is global rather than initially scoped to the target being configured.
- Duplicated Review/Findings/Intelligence surfaces slow learned workflows despite strong filters and direct phase access.

## Minor Observations

- The orange fallback, line-led product pages, bounded lists, separate create/rotation secrets, disabled unavailable profiles, accurate terminal-phase labels, clean Review completion, amber checking dot, reduced-motion scroll, target-aware progress, and dated recent findings are confirmed fixes and should not reappear as backlog items.
- The Profile-to-recent-findings transition remains visually compact; temporal context is now present, so any further work should emphasize separation between “configuration” and “recent audit,” not add more card decoration.
- `onHeroStateChange` collapses every non-healthy platform state into “validating,” so the shell cannot distinguish loading from degraded (`frontend/src/components/TargetSetup.tsx:224-231`).
- Scan failures append a raw code after the message; keep the code available for support, but lead with a plain-language recovery action.
- The deterministic detector is clean, but runtime contrast, keyboard order, responsive tables, canvas behavior, and state transitions remain unverified without browser control.

## Questions to Consider

1. Is the phase rail progress for one audit instance, or navigation among reusable tools? What disappears if it commits to only one model?
2. If a historical scan is selected, what persistent signal would make it impossible to confuse with the draft audit?
3. If Findings owns triage and Intelligence owns decisions, what is the smallest useful Review phase?
4. Is the shield earning 286px on every task screen, or should exact scope and current audit state become the product’s signature visual?
