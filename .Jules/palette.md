## Initializing Palette Journal
## 2026-05-04 - Fix ANSI color tabwriter column alignment
**Learning:** Adding ANSI escape codes (colors/bold) inside a `tabwriter` completely breaks column alignment because `tabwriter` counts the hidden escape codes as visible characters.
**Action:** When printing colored text in a `tabwriter`, always initialize it with `tabwriter.StripEscape` and wrap the ANSI codes in `\xff` bytes so the tabwriter ignores their length.
