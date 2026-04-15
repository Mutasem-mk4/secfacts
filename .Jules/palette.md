## 2024-05-14 - Tabwriter Misalignment with ANSI Colors
**Learning:** When using Go's `text/tabwriter` along with ANSI color escape codes (e.g. `\x1b[31m` or `\033[31m`), the escape sequence characters are incorrectly counted as visible characters, causing column misalignment in terminal output.
**Action:** Use the `tabwriter.StripEscape` flag when instantiating the `tabwriter.Writer` and wrap all ANSI escape sequences with the `\xff` byte so that `tabwriter` correctly strips them during width calculation and restores them on output.
