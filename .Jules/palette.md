## 2025-05-18 - Fix Terminal Column Misalignment with Go's tabwriter
**Learning:** When using ANSI color codes within Go's `text/tabwriter`, the escape sequences are counted towards the column width, leading to misaligned columns in the terminal output.
**Action:** Always use the `tabwriter.StripEscape` flag and wrap ANSI escape sequences in `\xff` when formatting terminal output using `text/tabwriter` to ensure correct visual alignment.
