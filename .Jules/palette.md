## 2026-05-11 - Fix Terminal Tabular Alignment
**Learning:** Tabwriter alignment breaks when ANSI color escape codes are written because it counts escape sequence characters towards column width. Setting `tabwriter.StripEscape` and wrapping ANSI sequences conditionally in `\xff` fixes layout misalignment while maintaining colors.
**Action:** Always unconditionally use `tabwriter.StripEscape` and conditionally wrap ANSI color code sequences in `\xff` when using `text/tabwriter` for terminal output.
