---
name: ScopeHarbor
description: A focused, visually clear, and trustworthy interface for authorized local application-security audits.
colors:
  harbor-abyss: "oklch(10.5% 0.025 252)"
  harbor-band: "oklch(13.2% 0.026 252)"
  harbor-surface: "oklch(15.5% 0.027 252)"
  harbor-raised: "oklch(19.5% 0.03 252)"
  harbor-input: "oklch(11.8% 0.026 252)"
  ink: "oklch(96% 0.008 250)"
  ink-soft: "oklch(82% 0.018 250)"
  ink-muted: "oklch(68% 0.02 250)"
  divider: "oklch(72% 0.035 248 / 0.18)"
  soft-fill: "oklch(92% 0.02 250 / 0.045)"
  signal-orange: "oklch(64% 0.205 37)"
  signal-orange-light: "oklch(73% 0.19 42)"
  signal-orange-deep: "oklch(51% 0.19 34)"
  action-orange: "oklch(73% 0.19 42)"
  action-orange-end: "oklch(68% 0.22 35)"
  on-action: "oklch(18% 0.035 45)"
  signal-blue: "oklch(72% 0.14 251)"
  signal-amber: "oklch(80% 0.15 78)"
  danger-coral: "oklch(70% 0.18 25)"
  success-mint: "oklch(76% 0.12 157)"
typography:
  display:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI Variable, Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 700
    lineHeight: 1.15
    letterSpacing: "-0.028em"
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI Variable, Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.018em"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI Variable, Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.018em"
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI Variable, Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: "normal"
  meta:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI Variable, Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI Variable, Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "0.025em"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.45
    letterSpacing: "normal"
rounded:
  none: "0"
  sm: "8px"
  field: "9px"
  md: "12px"
  lg: "16px"
  pill: "999px"
spacing:
  2xs: "4px"
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  2xl: "48px"
  3xl: "64px"
components:
  button-primary:
    backgroundColor: "{colors.action-orange}"
    textColor: "{colors.on-action}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "8px 14px"
    height: "39px"
  button-secondary:
    backgroundColor: "{colors.soft-fill}"
    textColor: "{colors.ink-soft}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "8px 14px"
    height: "39px"
  field:
    backgroundColor: "{colors.harbor-input}"
    textColor: "{colors.ink}"
    typography: "{typography.meta}"
    rounded: "{rounded.field}"
    padding: "8px 10px"
    height: "39px"
  status-chip:
    backgroundColor: "{colors.soft-fill}"
    textColor: "{colors.ink-muted}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "5px 9px"
  structural-panel:
    backgroundColor: "{colors.harbor-band}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "16px"
---

# Design System: ScopeHarbor

## 1. Overview

**Creative North Star: "The Illuminated Audit Path"**

ScopeHarbor should feel like a calm security workspace in a dim office or home environment: focused enough for meaningful AppSec work, clear enough for a solo developer to use without specialist coaching, and polished enough that dense evidence feels ordered. A restrained orange signal traces the authorized path from scope to profile, scan, finding, and remediation. It is a guide through the work, not decoration around it.

The canvas is a near-black, blue-tinted neutral field with one continuous structural surface for each major product band. Fine dividers organize related content; nested navy cards do not. The interface becomes dense only when evidence earns that density. Before data exists, loading and empty states explain the prerequisite and the next useful action.

The system explicitly rejects the look and behavior of a hacker-themed terminal, an intimidating expert-only scanner, and security theater that hides the workflow. Familiar controls, direct language, restrained motion, and visible safety boundaries create trust.

**Key Characteristics:**

- A dark ambient canvas with restrained orange used as a navigational signal.
- Continuous surfaces divided by fine lines instead of stacks of bubbly cards.
- Sleek system typography with compact, readable hierarchy and bounded prose.
- Explicit audit phases, prerequisites, status feedback, and next actions.
- A secure-network WebGL hero that supports the workflow without controlling it.
- Progressive disclosure for findings, activity, comparisons, reports, and explanations.

## 2. Colors

The palette is a dark maritime neutral system illuminated by one warm audit signal, with blue and amber reserved for small data-bearing moments.

### Primary

- **Signal Orange** (`colors.signal-orange`): active audit phases, selected profiles, primary progress, hero network links, and the three product-promise icons.
- **Action Orange** (`colors.action-orange` through `colors.action-orange-end`): primary buttons and irreversible forward movement. It is intentionally lighter than the hero's deeper orange.
- **Deep Signal Orange** (`colors.signal-orange-deep`): borders and pressed depth around orange actions, never a large background field.

### Secondary

- **Signal Blue** (`colors.signal-blue`): small progress, informational, and comparison details only.
- **Signal Amber** (`colors.signal-amber`): waiting, checking, warning, and attention states only.
- **Success Mint** (`colors.success-mint`): healthy services and completed workflow markers.
- **Danger Coral** (`colors.danger-coral`): destructive actions, failures, and critical status. It is never decorative.

### Neutral

- **Harbor Abyss** (`colors.harbor-abyss`): the application canvas.
- **Harbor Band** (`colors.harbor-band`): major continuous page and workflow surfaces.
- **Harbor Surface** and **Harbor Raised** (`colors.harbor-surface`, `colors.harbor-raised`): controls or genuinely elevated content, used sparingly.
- **Harbor Input** (`colors.harbor-input`): form fields and select controls.
- **Primary, Soft, and Muted Ink** (`colors.ink`, `colors.ink-soft`, `colors.ink-muted`): headings, supporting text, metadata, and inactive controls in descending emphasis.
- **Divider** and **Soft Fill** (`colors.divider`, `colors.soft-fill`): one-pixel structure, hover states, selected rows, and compact chips.

**The Orange Thread Rule.** Orange must remain a scarce directional signal. Use it for the current step, the primary action, selected state, and hero network—not for headings, decorative illustrations, or whole dashboard sections.

**The Signal Sprinkle Rule.** Blue and amber may appear in progress bars, comparison details, and live state indicators. They must not recolor section titles, navigation icons, or general imagery.

**The Structural Navy Rule.** One navy-tinted band may contain several related sections. Separate them with one-pixel dividers; never place every subdivision inside another navy card.

The light theme must preserve these semantic roles through the existing role-based CSS overrides. Do not invent a separate hue strategy for light mode.

## 3. Typography

**Display Font:** System interface sans (with Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif)

**Body Font:** System interface sans (with Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif)

**Label/Mono Font:** System interface sans for labels and UI; system monospace only for IDs, paths, model versions, and other literal technical values.

**Character:** Straight, sleek, and quietly technical. The single-family system stack feels familiar and trustworthy, while weight and spacing—not bubbly geometry or novelty type—create hierarchy.

### Hierarchy

- **Display** (`typography.display`): the ScopeHarbor hero title and rare page-level emphasis.
- **Headline** (`typography.headline`): page introductions and primary task headings.
- **Title** (`typography.title`): panel titles, audit decisions, and major subsection headings.
- **Body** (`typography.body`): primary explanations; prose is capped around 64–70 characters per line.
- **Meta** (`typography.meta`): descriptions, field help, evidence context, and status explanations.
- **Label** (`typography.label`): tabs, buttons, chips, table headings, and compact control labels.
- **Mono** (`typography.mono`): exact values only. It never becomes the overall product voice.

**The Sleek Utility Rule.** Use one interface sans family across the product. Bubbly display faces, pseudo-terminal typography, and decorative font pairings are prohibited.

**The Read-It-Once Rule.** A section gets a title and one concise explanatory sentence when its purpose or prerequisite is not obvious. Explanations must not compete with the task or repeat nearby labels.

## 4. Elevation

ScopeHarbor uses tonal layering and dividers as its primary depth system. Most surfaces remain visually flat and connected. Compact ambient shadows exist only to separate a true panel from the canvas; the confirmation dialog earns the strongest elevation because it interrupts the workflow. Hover elevation is limited to a one-pixel translation on actionable controls.

### Shadow Vocabulary

- **Ambient Soft** (`0 2px 6px oklch(2% 0.02 250 / 0.26)`): the subtle shadow used by standalone panels and metric surfaces. It must remain close to the surface.
- **Ambient Panel** (`0 4px 8px oklch(2% 0.02 250 / 0.34)`): the slightly stronger panel shadow used only where tonal separation is insufficient.
- **Dialog Lift** (`0 6px 8px oklch(0% 0 0 / 0.38)`): a short, defined shadow under confirmation dialogs, combined with a dark scrim and restrained backdrop blur.
- **Signal Glow** (`0 0 18px oklch(76% 0.12 157)`): a colored halo reserved for the hero object and tiny live-status dots; it is not a card treatment.

**The Flat-by-Default Rule.** Depth begins with tone and a one-pixel divider. If a section reads clearly without a shadow, the shadow is forbidden.

**The No Ghost-Card Rule.** Never pair a one-pixel border with a broad decorative shadow. Panels use compact structural depth; internal panes use dividers and no shadow.

## 5. Components

Components should feel precise, familiar, and task-oriented. Every interactive component requires default, hover, focus, disabled, loading, error, and selected states where applicable.

### Buttons

- **Shape:** compact gently curved rectangle (`rounded.sm`) with a minimum 39px height and 44px on coarse pointers.
- **Primary:** warm action gradient using `button-primary`; use for the single forward action in a decision area.
- **Hover / Focus:** one-pixel upward motion, brighter gradient endpoint, and a visible three-pixel orange focus outline. Reduced motion collapses transitions to near-instant.
- **Secondary:** translucent neutral fill using `button-secondary`; use for refresh, disclosure, navigation, and reversible actions.
- **Danger:** solid danger color with explicit confirmation for destructive operations.
- **Text:** borderless and reserved for low-emphasis navigation inside an already clear context.

### Chips

- **Style:** compact pill (`status-chip`) with a one-pixel divider-colored border and neutral fill.
- **State:** semantic color may change the text/border for severity, health, or lifecycle. Chips never become large call-to-action buttons.

### Cards / Containers

- **Corner Style:** modest 12px corners for standalone panels; internal panes and audit bands use square shared edges.
- **Background:** major structure uses `structural-panel`; children remain transparent unless they represent a distinct interactive object.
- **Shadow Strategy:** ambient shadow on the outer container only. Nested sections use dividers.
- **Border:** one-pixel divider for structure, never a colored side stripe.
- **Internal Padding:** 16px for regular panels, 24px for major guide and credential sections.

### Inputs / Fields

- **Style:** dark recessed field (`field`) with a one-pixel neutral border and 9px corners.
- **Focus:** orange-tinted border plus a compact three-pixel focus halo; never remove the keyboard outline without an equivalent.
- **Error / Disabled:** errors use danger text and a bounded message; disabled controls retain their label and reduce opacity without disappearing.
- **Secrets:** credential fields use password treatment, disable browser assistance, explain what value belongs there, and clear after a successful save.

### Navigation

- **Primary navigation:** neutral labels, transparent default state, and a two-pixel orange underline for the current page. The seven-tab row wraps into a horizontally scrollable second line before collision.
- **Audit phases:** a six-column divider-led band with numbered or completed markers, concise state text, and an orange underline on the current phase. On smaller screens it becomes a keyboard-accessible horizontal rail.
- **Guide navigation:** a quiet contents rail on wide screens and a single ordered flow on narrow screens.

### Tables and Evidence Lists

- Use tables for comparable fields and lists for narrative evidence.
- Keep table rows divided by one-pixel lines; do not wrap every row in a card.
- Paginate, filter, or progressively disclose when a result set exceeds the useful first view.
- AI explanations, activity, and comparison groups show a bounded preview with explicit “show more” controls.

### Loading and Empty States

- Loading is a compact structural band that names what the application is checking.
- Empty states explain whether the user must select, configure, run, or wait; they never render as unexplained grey rectangles.
- Loaded-empty, loading, failure, and unavailable are distinct states with distinct copy.

### Secure Network Hero

- The hero combines a restrained orange node path with a faceted shield aligned to the site's palette.
- WebGL is progressive enhancement. A polished shield fallback remains visible when WebGL is unavailable.
- Animation is ambient and state-responsive, never a prerequisite for understanding scope, readiness, or results.

## 6. Do's and Don'ts

### Do:

- **Do** make authorized scope, active profile, workflow status, and the next action visible at every audit phase.
- **Do** use Signal Orange for the current path and primary action, while keeping most of the screen neutral.
- **Do** use one continuous Harbor Band with internal one-pixel dividers for related content.
- **Do** add one concise description wherever a prerequisite, consequence, or unfamiliar security concept would otherwise force the user to guess.
- **Do** use purposeful loading and empty states that teach the next step.
- **Do** bound long findings, comparisons, activity, reports, and explanations with sorting, pagination, or progressive disclosure.
- **Do** preserve visible focus, keyboard operation, WCAG 2.2 AA contrast, non-color status cues, and reduced-motion behavior.
- **Do** keep the secure-network hero polished, orange-led, and subordinate to the audit workflow.
- **Do** preserve semantic light-theme mappings whenever a dark-theme token changes.

### Don't:

- **Don't** make ScopeHarbor resemble a **hacker-themed terminal** or an **intimidating expert-only scanner**.
- **Don't** hide the workflow behind **security theater**, unexplained specialist knowledge, raw scanner noise, or uncertain next steps.
- **Don't** color headings, general header icons, or large illustrations blue, amber, or orange; color belongs to actions and data-bearing features.
- **Don't** create a patchwork of navy cards. If every subdivision has its own filled rectangle, the hierarchy is wrong.
- **Don't** use bubbly containers, oversized radii, pill-shaped sections, or bubble separators. Prefer straight edges, modest corners, and lines.
- **Don't** use nested cards, identical icon-card grids, colored side-stripe borders, gradient text, decorative glassmorphism, or decorative grid backgrounds.
- **Don't** use mono typography as the product voice, add fake command prompts, or expose raw tool output for atmosphere.
- **Don't** show every result or explanation at once when a bounded preview communicates the set.
- **Don't** let text overflow, truncate essential security meaning, or shrink body text to solve a layout problem.
- **Don't** rely on motion, WebGL, or color alone to communicate readiness, severity, completion, or permission.
