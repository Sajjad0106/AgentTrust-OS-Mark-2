---
version: alpha
name: "Frequency-Based Extraction"
description: "Design tokens extracted from frequency analysis without LLM interpretation."
colors:
  surface: "#050505"
  text: "#ffffff"
  text-2: "#39ff14"
  text-3: "#bf00ff"
  text-4: "#ffd700"
  text-5: "#00ff9d"
  text-6: "#00e5ff"
  local-accent: "#e5e7eb"
  local-accent-2: "#d4af37"
typography:
  type-1:
    fontFamily: "ui-sans-serif"
    fontSize: "16px"
    fontWeight: "400"
    lineHeight: "24px"
  type-2:
    fontFamily: "ui-monospace"
    fontSize: "10px"
    fontWeight: "700"
    lineHeight: "15px"
  type-3:
    fontFamily: "ui-monospace"
    fontSize: "10.5px"
    fontWeight: "400"
    lineHeight: "17.0625px"
  type-4:
    fontFamily: "ui-monospace"
    fontSize: "9px"
    fontWeight: "400"
    lineHeight: "13.5px"
  type-5:
    fontFamily: "ui-monospace"
    fontSize: "10px"
    fontWeight: "400"
    lineHeight: "15px"
rounded:
  radius-1: "9999px"
  radius-2: "24px"
  radius-3: "12px"
  radius-4: "4px"
  radius-5: "8px"
spacing:
  space-1: "8px"
  space-2: "16px"
  space-3: "4px"
  space-4: "12px"
  space-5: "14px"
  space-6: "2px"
  space-7: "24px"
  space-8: "6px"
  space-9: "20px"
  space-10: "32px"
---

## Overview

Design tokens extracted from frequency analysis without LLM interpretation.

**Signature traits:**
- Evidence was insufficient to extract distinctive signature traits for this system.

## Colors

The palette uses 9 validated color tokens across 1 theme profile. Semantic roles stay attached to observed usage so generation agents can choose accents without inventing new color meaning.

### Text Scale
- **Text** (#ffffff): Frequency rank #1 (150 occurrences); token importance textCandidate: repeated text-role usage (150 hits). Role: text. {authored: rgb(255, 255, 255), space: rgb, alpha: 0.024}
- **Text-2** (#39ff14): Frequency rank #4 (11 occurrences); token importance textCandidate: repeated text-role usage (11 hits). Role: text. {authored: rgb(57, 255, 20), space: rgb}
- **Text-3** (#bf00ff): Frequency rank #5 (10 occurrences); token importance textCandidate: repeated text-role usage (10 hits). Role: text. {authored: rgb(191, 0, 255), space: rgb}
- **Text-4** (#ffd700): Frequency rank #7 (5 occurrences); token importance textCandidate: repeated text-role usage (5 hits). Role: text. {authored: rgb(255, 215, 0), space: rgb}
- **Text-5** (#00ff9d): Frequency rank #8 (5 occurrences); token importance textCandidate: repeated text-role usage (5 hits). Role: text. {authored: rgb(0, 255, 157), space: rgb, alpha: 0.3}
- **Text-6** (#00e5ff): Frequency rank #9 (5 occurrences); token importance textCandidate: repeated text-role usage (5 hits). Role: text. {authored: rgb(0, 229, 255), space: rgb}

### Interactive
- **Local-accent** (#e5e7eb): Frequency rank #2 (146 occurrences); token importance localAccent: localized usage with limited global footprint. Role: border. {authored: rgb(229, 231, 235), space: rgb}
- **Local-accent-2** (#d4af37): Frequency rank #3 (11 occurrences); token importance localAccent: localized usage with limited global footprint. Role: border. {authored: rgb(212, 175, 55), space: rgb, alpha: 0.05}

### Surface & Shadows
- **Surface** (#050505): Frequency rank #6 (5 occurrences); token importance surfaceCandidate: high surface coverage (27.6%). Role: background. {authored: rgb(5, 5, 5), space: rgb, alpha: 0.4}

## Typography

Typography uses ui-sans-serif, ui-monospace across extracted hierarchy roles. Keep hierarchy mapped to these token rows before adding decorative type styles.

Mixes ui-sans-serif and ui-monospace for visual contrast. Weight range spans regular, bold. Sizes range from 9px to 16px.

### Type Scale Evidence
| Role | Font | Size | Weight | Line Height | Letter Spacing | Stack / Features | Notes |
|------|------|------|--------|-------------|----------------|------------------|-------|
| Frequency rank #1 | ui-sans-serif | 16px | 400 | 24px | normal | ui-sans-serif, system-ui, sans-serif, Apple Color Emoji, Segoe UI Emoji, Segoe UI Symbol, Noto Color Emoji | Extracted token |
| Frequency rank #2 | ui-monospace | 10px | 700 | 15px | normal | ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace | Extracted token |
| Frequency rank #3 | ui-monospace | 10.5px | 400 | 17.0625px | normal | ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace | Extracted token |
| Frequency rank #4 | ui-monospace | 9px | 400 | 13.5px | normal | ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace | Extracted token |
| Frequency rank #5 | ui-monospace | 10px | 400 | 15px | normal | ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace | Extracted token |

## Layout

Layout rhythm is inferred from spacing tokens and responsive breakpoint evidence.

### Spacing System
| Token | Value | Px | Notes |
|------|-------|----|-------|
| space-6 | 2px | 2 | Extracted spacing token |
| space-3 | 4px | 4 | Extracted spacing token |
| space-8 | 6px | 6 | Extracted spacing token |
| space-1 | 8px | 8 | Extracted spacing token |
| space-4 | 12px | 12 | Extracted spacing token |
| space-5 | 14px | 14 | Extracted spacing token |
| space-2 | 16px | 16 | Extracted spacing token |
| space-9 | 20px | 20 | Extracted spacing token |
| space-7 | 24px | 24 | Extracted spacing token |
| space-10 | 32px | 32 | Extracted spacing token |

## Elevation & Depth

Keep depth flat unless validated shadow or interaction evidence appears in the extraction payload. Do not invent shadows beyond this evidence boundary.

### Shadow Evidence
| Shadow Token | Layers | Details |
|--------------|--------|---------|
| n/a | 0 | No validated shadow payload |

### Interaction Signals
| Theme | Signal | Evidence |
|-------|--------|----------|
| Light | backdrop-filter | blur(25px) |
| Light | outline-color | rgb(255, 255, 255) ; rgba(255, 255, 255, 0.3) ; rgb(57, 255, 20) |
| Light | outline-width | 3px |
| Light | outline-offset | 0px |
| Light | transform | matrix(1, 0, 0, 1, 0, -1.43739) ; matrix(0.912692, -0.408649, 0.408649, 0.912692, 0, 0) ; matrix(1, 0, 0, 1, 0, -0.677414) |

## Shapes

Shape language maps directly to rounded tokens. Keep component corners consistent with the role mapping below before introducing bespoke geometry.

### Radius Roles
| Token | Value | Px | Role Mapping |
|------|-------|----|--------------|
| radius-4 | 4px | 4 | Subtle corner |
| radius-5 | 8px | 8 | Control corner |
| radius-3 | 12px | 12 | Control corner |
| radius-2 | 24px | 24 | Large surface corner |
| radius-1 | 9999px | 9999 | Large surface corner |

### Geometry Evidence
| Radius Token | Shape | Units |
|--------------|-------|-------|
| radius-1 | 9999px | px |
| radius-2 | 24px | px |
| radius-3 | 12px | px |
| radius-4 | 4px | px |
| radius-5 | 8px | px |

## Components

(none detected)

## Do's and Don'ts

Guardrails tie generation choices back to validated tokens, component patterns, and evidence-backed hierarchy.

| Do | Don't |
|----|---------|
| Do maintain consistent spacing using the base grid | Don't make unsupported claims about absent visual features |
| Do maintain WCAG AA contrast ratios (4.5:1 for normal text) | Don't mix rounded and sharp corners in the same view |
| Do use the primary color only for the single most important action per screen |  |
| Do verify evidence before writing new design-system guidance |  |

## Responsive Evidence

### Breakpoints
| Name | Width | Key Changes |
|------|-------|-------------|
| Mobile | >= 640px | (min-width: 640px) |
| Tablet | >= 768px | (min-width: 768px) |
| Desktop | >= 1024px | (min-width: 1024px) |
| Desktop | >= 1280px | (min-width: 1280px) |
| Desktop | >= 1536px | (min-width: 1536px) |

## Agent Prompt Guide

### Example Component Prompts
- Create button component using validated primary color role and spacing tokens.
- Create card component with mapped radius role and evidence-backed elevation.
- Create form input component using inferred typography hierarchy and border roles.

### Iteration Guide
1. Start with extracted palette and typography roles only.
2. Map spacing and radius directly from token tables before visual polish.
3. Apply component patterns one section at a time and compare against source intent.
4. Keep elevation claims tied to explicit evidence in output.
5. Iterate with smallest diffs and re-check section hierarchy after each change.
