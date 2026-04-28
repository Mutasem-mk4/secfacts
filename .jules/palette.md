## 2025-05-01 - Fix Terminal Tabular Output Misalignment with ANSI Colors
**Learning:** When building terminal-based tools in Go that use both `text/tabwriter` for column alignment and ANSI color escape sequences, the layout breaks if the escape codes are not stripped out by the tabwriter.
**Action:** Always initialize `text/tabwriter` with the `tabwriter.StripEscape` flag and wrap any ANSI color sequences passed into it using the `\xff` byte. This allows the tabwriter to calculate accurate visual widths while maintaining color output correctly.
