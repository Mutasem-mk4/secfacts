## 2026-05-01 - Terminal Alignment with ANSI Codes
**Learning:** In CLI applications utilizing `text/tabwriter`, appending ANSI color codes directly will cause tab column misalignment since tabwriter counts the invisible escape characters as part of the string length.
**Action:** When implementing colored terminal output, initialize `tabwriter` with the `tabwriter.StripEscape` flag and wrap ANSI color codes with the `\xff` byte so tabwriter properly excludes them from its column width calculations.
