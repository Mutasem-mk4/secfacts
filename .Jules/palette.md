## 2024-05-17 - Tabwriter Column Alignment with ANSI Colors
**Learning:** Go's `text/tabwriter` miscalculates column widths when text includes ANSI escape sequences, breaking table alignment.
**Action:** Unconditionally enable the `tabwriter.StripEscape` flag and wrap only the ANSI escape sequences themselves (e.g., `\x1b[31m`) in `\xff` characters (e.g., `\xff\x1b[31m\xff`). Do not wrap the visible text, as it will cause `tabwriter` to compute the text's width as 0.
