## 2024-05-19 - Tabwriter and ANSI Color Sequences
**Learning:** When using `text/tabwriter` to format tabular data in the terminal with ANSI color sequences, the tabwriter will miscalculate string lengths and misalign columns.
**Action:** When printing colored text in a `tabwriter`, use `tabwriter.StripEscape` as a flag when initializing the writer, and wrap the ANSI sequences in `\xff` characters (e.g. `"\xff" + colorRed + "\xff" + text + "\xff" + colorReset + "\xff"`). This ensures `tabwriter` ignores the escape sequence lengths and computes column sizes accurately.
