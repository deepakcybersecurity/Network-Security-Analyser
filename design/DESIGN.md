---
name: Aegis Scanner
colors:
  surface: '#10131a'
  surface-dim: '#10131a'
  surface-bright: '#363941'
  surface-container-lowest: '#0b0e15'
  surface-container-low: '#181c23'
  surface-container: '#1d2027'
  surface-container-high: '#272a31'
  surface-container-highest: '#32353c'
  on-surface: '#e0e2ec'
  on-surface-variant: '#c1c6d6'
  inverse-surface: '#e0e2ec'
  inverse-on-surface: '#2d3038'
  outline: '#8b909f'
  outline-variant: '#414754'
  surface-tint: '#acc7ff'
  primary: '#acc7ff'
  on-primary: '#002f68'
  primary-container: '#498fff'
  on-primary-container: '#00285b'
  inverse-primary: '#005bbf'
  secondary: '#bac8da'
  on-secondary: '#25313f'
  secondary-container: '#3b4857'
  on-secondary-container: '#a9b6c8'
  tertiary: '#ffb68b'
  on-tertiary: '#522300'
  tertiary-container: '#e47014'
  on-tertiary-container: '#481e00'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#d7e2ff'
  primary-fixed-dim: '#acc7ff'
  on-primary-fixed: '#001a40'
  on-primary-fixed-variant: '#004492'
  secondary-fixed: '#d6e4f6'
  secondary-fixed-dim: '#bac8da'
  on-secondary-fixed: '#101d2a'
  on-secondary-fixed-variant: '#3b4857'
  tertiary-fixed: '#ffdbc8'
  tertiary-fixed-dim: '#ffb68b'
  on-tertiary-fixed: '#321300'
  on-tertiary-fixed-variant: '#753400'
  background: '#10131a'
  on-background: '#e0e2ec'
  surface-variant: '#32353c'
typography:
  headline-sm:
    fontFamily: Hanken Grotesk
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-md:
    fontFamily: Hanken Grotesk
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Hanken Grotesk
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.02em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 14px
    letterSpacing: 0.02em
  code:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  gutter: 12px
  margin-page: 24px
  panel-padding: 16px
  table-cell-padding: 8px 12px
---

## Brand & Style
The design system is engineered for professional network security analysis, prioritizing technical precision over marketing aesthetics. The visual narrative is "The Command Center"—an environment that feels like a high-end security workstation. It is intentionally dense, structured, and pragmatic.

The style is **Professional / Technical**, drawing from terminal-inspired efficiency and enterprise-grade IDEs. It avoids decorative fluff like gradients, blurs, or excessive whitespace. Instead, it utilizes structural clarity, 1px borders, and a strict color hierarchy to guide the user through complex diagnostic data. The goal is to evoke a sense of absolute control, reliability, and speed for security engineers.

## Colors
This design system operates exclusively in a dark, high-performance color mode. The palette is functional, not decorative.

- **Foundations**: The background uses a deep charcoal-navy to reduce eye strain during long-form analysis. Surfaces and panels are differentiated by subtle luminosity shifts rather than shadows.
- **Accents**: The Primary Accent (#2F81F7) is reserved for active states, primary actions, and focused data points.
- **Semantic Logic**: Risk levels are strictly enforced using High (Red), Medium (Amber), and Low (Green) to allow for instant scanning of vulnerabilities.
- **Text**: Primary text uses high-contrast off-white, while secondary text is muted to create a clear information hierarchy in data-heavy views.

## Typography
Typography is compact and optimized for readability in dense layouts.

- **Primary Type**: Hanken Grotesk provides a clean, modern sans-serif feel that remains legible at small scales. 
- **Data Type**: JetBrains Mono is utilized for labels, metadata, status indicators, and technical values to provide a "terminal" feel and ensure character distinction (e.g., distinguishing 0 from O).
- **Scale**: Headings are kept small to maximize vertical screen real estate. The largest heading should rarely exceed 20px. 
- **Density**: Use `body-sm` as the standard for data tables and property panels to ensure high information density.

## Layout & Spacing
The layout follows a **Fixed Sidebar + Fluid Content** model, typical of professional IDEs. 

- **Grid**: A technical 4px baseline grid ensures tight alignment. 
- **Structure**: Content is organized into "Panels." Instead of large cards with generous padding, panels are separated by 1px borders (#202938) and minimal 12px gutters.
- **Adaptation**: On smaller screens, the sidebar collapses into an icon-only rail rather than hiding behind a hamburger menu, maintaining access to core tools. 
- **Density**: Vertical rhythm is tight. Group related inputs and data points closely to allow more information to be visible above the fold.

## Elevation & Depth
This design system rejects ambient shadows and blurs. Depth is communicated strictly through **Tonal Layering** and **Borders**.

- **Level 0 (Background)**: #080B12 - The base canvas.
- **Level 1 (Sidebar)**: #0D111A - Directly adjacent to the background.
- **Level 2 (Panels)**: #111722 - Content areas, differentiated by a 1px solid border (#202938).
- **Active State**: Use a 1px primary-colored border or a subtle vertical highlight bar to indicate selection or focus.

Interactive elements do not "float" via shadows; they are "etched" into the UI with borders or distinct background fills.

## Shapes
The shape language is rigid and industrial. 

- **Radius**: A standard 4px radius (`rounded-md`) is used for buttons, inputs, and panels. 
- **Exceptions**: Smaller components like tags or status indicators may use 2px. 
- **Prohibition**: No circular/pill-shaped buttons or extremely rounded corners. The intent is to maintain a sharp, technical profile that aligns with the 1px border aesthetic.

## Components

- **Buttons**: Square-ish with 4px radius. Use a solid fill for primary actions and a 1px border (#202938) for secondary actions. Use a "pressed" state that shifts the background color slightly darker.
- **Data Tables**: The core of the system. Use 1px horizontal separators. Header row should have a slightly darker background (#0D111A) and use `label-sm` in all caps.
- **Metrics**: Displayed as horizontal blocks with a label on the left and value on the right, or a "Status Bar" style. No oversized "hero" cards for metrics.
- **Input Fields**: Inset look using #080B12 background and #202938 border. Focus state should use a 1px #2F81F7 border. Use monospaced font for technical inputs (IP addresses, hashes).
- **Chips/Tags**: Rectangular with 2px radius. Use semantic background tints (e.g., #F04444 at 10% opacity for High Risk) with a 1px border of the same color.
- **Icons**: 16px or 20px Lucide-style line icons. Maintain a consistent stroke width (1.5px). Never use multi-color icons or emojis.
- **Activity Feed**: A vertical timeline of condensed log entries using monospaced text, color-coded by severity level.